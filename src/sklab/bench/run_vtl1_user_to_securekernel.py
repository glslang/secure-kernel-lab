"""Causal proof: a VTL1 user breakpoint enters and resumes through Secure Kernel.

The script uses only the allowlisted disposable K3 VM.  It creates a fresh
differencing disk, installs a guest-side one-shot trigger watcher, arms
securekernel!KiBreakpointTrap through the MCP live-control tools, and then proves
the saved VTL1 user frame, one-instruction step, resume, and enclave SEH result.
Evidence goes to the run directory and the differencing disk below the target's
configured `work_disk_root`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import struct
import sys
import time
import uuid
from typing import Any


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
ASSETS = HERE / "enclave-guest-assets"
RUN_ROOT = HERE / "vtl1-user-experiment"
PLAN = HERE / "vtl1-user-to-securekernel-experiment-plan.md"

sys.path.insert(0, str(HERE))

import run_k4_stop_step as k4  # noqa: E402
from h3_vtl1_debug_control import Probe, low_value, snapshot  # noqa: E402
from inject_provider_death_mcp import Mcp, structured  # noqa: E402
from guest_physical import GuestVirtual, find_secure_kernel_base, vtl1_identity  # noqa: E402
from vtl0_find_matching_image import Guest  # noqa: E402


VM_ID = k4.VM_ID
VM_NAME = k4.VM_NAME
EXPECTED_CR3 = k4.EXPECTED_CR3
SK_IMAGE = HERE / "guest-positive-securekernel.exe"
SK_RVA = 0xEB380
SK_BYTES = bytes.fromhex("4883ec08")
SK_STEP_RIP_DELTA = 4
ENCLAVE_RAISE_BP_RVA = 0x1130
ENCLAVE_RETURN_RIP_RVA = 0x100E
EXPECTED_IMAGE_SHA256 = k4.IMAGE_SHA256
EXPECTED_HOST_SHA256 = "1EDD7F2E9F647D6C1DAFE7A1692A704E78125FE0CEFC1E50566EFF65E70D237A"
EXPECTED_ENCLAVE_SHA256 = "7B1A05FBA8AFFA7E5B83DE3C7E6A0CD072AD0302E07161C3F298508B747A81F6"
EXPECTED_SERVICE_SHA256 = "DF7F0BFAD0994F7E03B2EA8CC70ED741AFA890E8DCC0D6913F94FF939608B750"
# Set from targets.<name>.work_disk_root and parent_disk by bench_bridge.configure.
PRIVATE_DISK_ROOT: pathlib.Path | None = None
PARENT_DISK: pathlib.Path | None = None
PROFILE = HERE / "vmwp-dispatcher-profiles"
DEBUG_REGISTERS = ("dr0", "dr1", "dr2", "dr3", "dr6", "dr7")


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def save(path: pathlib.Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def ok(response: dict[str, object], operation: str) -> dict[str, object]:
    data = structured(response)
    if (
        response.get("result", {}).get("isError")
        or not isinstance(data, dict)
        or data.get("status") != "ok"
    ):
        raise k4.GateFailure(f"{operation} failed: {response}")
    return data


def register_map(stop: dict[str, Any]) -> dict[str, int]:
    rows = stop["registers"]["values"]
    result: dict[str, int] = {}
    for row in rows:
        if int(row["status"]) != 0:
            raise k4.GateFailure(f"register {row['name']} failed: {row}")
        result[str(row["name"])] = int(str(row["low"]), 0)
    return result


def readable_hex(response: dict[str, Any]) -> bytes:
    data = str(response["data"])
    try:
        return bytes.fromhex(data)
    except ValueError as error:
        raise k4.GateFailure(f"live read returned malformed hex: {data!r}") from error


def is_canonical_user(address: int) -> bool:
    return 0 < address <= 0x00007FFFFFFFFFFF


def ps_quote(value: os.PathLike[str] | str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def vm_configuration() -> dict[str, Any]:
    raw = k4.ps(
        f"$v=Get-VM -Id '{VM_ID}' -ErrorAction Stop; "
        "$d=@(Get-VMHardDiskDrive -VM $v); if($d.Count -ne 1){throw 'expected one VM disk'}; "
        "$g=Get-VMIntegrationService -VM $v -Name 'Guest Service Interface'; "
        "[pscustomobject]@{"
        "VMId=$v.VMId.Guid;Name=$v.Name;State=$v.State.ToString();"
        "ProcessorCount=$v.ProcessorCount;DiskPath=$d[0].Path;"
        "ControllerType=$d[0].ControllerType.ToString();"
        "ControllerNumber=$d[0].ControllerNumber;ControllerLocation=$d[0].ControllerLocation;"
        "GuestServiceEnabled=$g.Enabled"
        "}|ConvertTo-Json -Compress"
    )
    return json.loads(raw)


def prepare_child(run_dir: pathlib.Path, nonce: str, mode: str = "BP1") -> dict[str, Any]:
    before = vm_configuration()
    if before["VMId"].lower() != VM_ID.lower() or before["Name"] != VM_NAME:
        raise k4.GateFailure(f"allowlisted VM identity mismatch: {before}")
    if before["State"] != "Off":
        raise k4.GateFailure(f"disk preparation requires the VM Off, got {before['State']}")
    if PARENT_DISK is None or PRIVATE_DISK_ROOT is None:
        raise k4.GateFailure("disk preparation requires targets.<name>.parent_disk and work_disk_root")
    if not PARENT_DISK.is_file():
        raise k4.GateFailure(f"missing immutable enclave parent {PARENT_DISK}")

    child = PRIVATE_DISK_ROOT / f"enclave-{nonce}.vhdx"
    if child.exists():
        raise k4.GateFailure(f"refusing to replace existing child {child}")
    state = {
        "schema": "windbg-mcp.private.vtl1-user-vm-state.v1",
        "before": before,
        "parent_disk": str(PARENT_DISK),
        "child_disk": str(child),
        "restored": False,
    }
    save(run_dir / "vm-state.json", state)

    service = ASSETS / "vtl1-user-experiment-service.exe"
    if not service.is_file():
        raise k4.GateFailure(f"missing private boot service {service}")
    script = f"""
$ErrorActionPreference='Stop'
$vm=Get-VM -Id '{VM_ID}' -ErrorAction Stop
if($vm.Name -ne {ps_quote(VM_NAME)} -or $vm.State.ToString() -ne 'Off'){{throw 'allowlisted VM is not Off'}}
$root={ps_quote(PRIVATE_DISK_ROOT)}
$parent={ps_quote(PARENT_DISK)}
$child={ps_quote(child)}
New-Item -ItemType Directory -Path $root -Force | Out-Null
New-VHD -Path $child -ParentPath $parent -Differencing -ErrorAction Stop | Out-Null
$mounted=$false
try {{
  $disk=Mount-VHD -Path $child -Passthru -ErrorAction Stop
  $mounted=$true
  $windows=$null
  foreach($partition in @($disk | Get-Partition -ErrorAction SilentlyContinue)) {{
    foreach($access in @($partition.AccessPaths)) {{
      if($access -and (Test-Path -LiteralPath (Join-Path $access 'Windows\\System32'))) {{$windows=$access;break}}
    }}
    if($windows){{break}}
  }}
  if(-not $windows){{throw 'mounted child has no accessible Windows volume'}}
  $encl=Join-Path $windows 'encl'
  if(-not (Test-Path -LiteralPath (Join-Path $encl 'spin_host.exe'))){{throw 'parent omitted spin_host.exe'}}
  if(-not (Test-Path -LiteralPath (Join-Path $encl 'spin_enclave.dll'))){{throw 'parent omitted spin_enclave.dll'}}
  Copy-Item -LiteralPath {ps_quote(service)} -Destination (Join-Path $encl 'vtl1-user-experiment-service.exe') -Force
  $experiment=Join-Path $encl 'vtl1-user-experiment'
  foreach($name in @('inbox','running','processed','results')){{New-Item -ItemType Directory -Path (Join-Path $experiment $name) -Force|Out-Null}}
  @('nonce={nonce}','mode={mode}','rounds=1') | Set-Content -LiteralPath (Join-Path $experiment 'request.txt') -Encoding Ascii
  $hiveName='WindbgMcpVtl1ExperimentSystem'
  $hivePath=Join-Path $windows 'Windows\\System32\\config\\SYSTEM'
  if(Test-Path -LiteralPath ('Registry::HKEY_LOCAL_MACHINE\\'+$hiveName)){{throw 'temporary guest SYSTEM hive name is already loaded'}}
  & reg.exe load ('HKLM\\'+$hiveName) $hivePath | Out-Null
  if($LASTEXITCODE -ne 0){{throw 'could not load guest SYSTEM hive'}}
  try {{
    $select=Get-ItemProperty -LiteralPath ('Registry::HKEY_LOCAL_MACHINE\\'+$hiveName+'\\Select')
    $controlSet='ControlSet{{0:D3}}' -f [int]$select.Current
    $serviceKey='Registry::HKEY_LOCAL_MACHINE\\'+$hiveName+'\\'+$controlSet+'\\Services\\WindbgMcpVtl1Experiment'
    New-Item -Path $serviceKey -Force | Out-Null
    New-ItemProperty -LiteralPath $serviceKey -Name Type -PropertyType DWord -Value 16 -Force | Out-Null
    New-ItemProperty -LiteralPath $serviceKey -Name Start -PropertyType DWord -Value 2 -Force | Out-Null
    New-ItemProperty -LiteralPath $serviceKey -Name ErrorControl -PropertyType DWord -Value 1 -Force | Out-Null
    New-ItemProperty -LiteralPath $serviceKey -Name ImagePath -PropertyType ExpandString -Value 'C:\\encl\\vtl1-user-experiment-service.exe' -Force | Out-Null
    New-ItemProperty -LiteralPath $serviceKey -Name DisplayName -PropertyType String -Value 'WinDbg MCP VTL1 experiment' -Force | Out-Null
    New-ItemProperty -LiteralPath $serviceKey -Name ObjectName -PropertyType String -Value 'LocalSystem' -Force | Out-Null
  }} finally {{
    [gc]::Collect(); [gc]::WaitForPendingFinalizers()
    & reg.exe unload ('HKLM\\'+$hiveName) | Out-Null
    if($LASTEXITCODE -ne 0){{throw 'could not unload guest SYSTEM hive'}}
  }}
}} finally {{
  if($mounted){{Dismount-VHD -Path $child -ErrorAction Stop}}
}}
$drive=Get-VMHardDiskDrive -VM $vm
Set-VMHardDiskDrive -VMHardDiskDrive $drive -Path $child -ErrorAction Stop
Set-VMProcessor -VM $vm -Count 1 -ErrorAction Stop
"""
    k4.ps(script, timeout=120)
    state["prepared"] = vm_configuration()
    save(run_dir / "vm-state.json", state)
    return state


def restore_vm(run_dir: pathlib.Path, state: dict[str, Any]) -> dict[str, Any]:
    before = state["before"]
    if k4.vm_state() != "Off":
        raise k4.GateFailure("refusing to restore VM configuration while it is not Off")
    service_command = (
        "Enable-VMIntegrationService"
        if before["GuestServiceEnabled"]
        else "Disable-VMIntegrationService"
    )
    script = f"""
$ErrorActionPreference='Stop'
$vm=Get-VM -Id '{VM_ID}' -ErrorAction Stop
if($vm.Name -ne {ps_quote(VM_NAME)} -or $vm.State.ToString() -ne 'Off'){{throw 'allowlisted VM is not Off'}}
$drive=Get-VMHardDiskDrive -VM $vm
if(@($drive).Count -ne 1){{throw 'expected one VM disk'}}
Set-VMHardDiskDrive -VMHardDiskDrive $drive -Path {ps_quote(before['DiskPath'])} -ErrorAction Stop
Set-VMProcessor -VM $vm -Count {int(before['ProcessorCount'])} -ErrorAction Stop
{service_command} -VM $vm -Name 'Guest Service Interface' -ErrorAction Stop
"""
    k4.ps(script, timeout=90)
    state["restored"] = True
    state["after_restore"] = vm_configuration()
    save(run_dir / "vm-state.json", state)
    return state["after_restore"]


def live_target(partition: int, path: pathlib.Path) -> dict[str, Any]:
    source = k4.h3_source(partition)
    try:
        identity = vtl1_identity(partition, 0)
        base, _evidence = find_secure_kernel_base(
            GuestVirtual(source, identity["cr3"]),
            identity["idtr_base"],
            identity["idtr_limit"],
            SK_IMAGE,
        )
        address = base + SK_RVA
        guest = Guest(source, EXPECTED_CR3)
        first = guest.virtual(address, 64)
        guest.pages.clear()
        second = guest.virtual(address, 64)
        result = {
            "partition_id": f"0x{partition:x}",
            "expected_cr3": f"0x{EXPECTED_CR3:x}",
            "securekernel_base": f"0x{base:016x}",
            "target_symbol": "KiBreakpointTrap",
            "target_rva": f"0x{SK_RVA:x}",
            "target_va": f"0x{address:016x}",
            "guard": SK_BYTES.hex(),
            "text": first.hex(),
            "stable": first == second,
        }
        if not result["stable"] or not first.startswith(SK_BYTES):
            raise k4.GateFailure(f"live KiBreakpointTrap guard mismatch: {result}")
        save(path, result)
        return result
    finally:
        source.close()


def extract_guest_evidence(child: pathlib.Path, nonce: str, run_dir: pathlib.Path) -> dict[str, Any]:
    output = run_dir / "guest-result.txt"
    ready = run_dir / "guest-ready.txt"
    script = f"""
$ErrorActionPreference='Stop'
$child={ps_quote(child)}
$mounted=$false
try {{
  $disk=Mount-VHD -Path $child -ReadOnly -Passthru -ErrorAction Stop
  $mounted=$true
  $windows=$null
  foreach($partition in @($disk | Get-Partition -ErrorAction SilentlyContinue)) {{
    foreach($access in @($partition.AccessPaths)) {{
      if($access -and (Test-Path -LiteralPath (Join-Path $access 'Windows\\System32'))) {{$windows=$access;break}}
    }}
    if($windows){{break}}
  }}
  if(-not $windows){{throw 'mounted child has no accessible Windows volume'}}
  $root=Join-Path $windows 'encl\\vtl1-user-experiment'
  Copy-Item -LiteralPath (Join-Path $root 'ready.txt') -Destination {ps_quote(ready)} -Force -ErrorAction Stop
  Copy-Item -LiteralPath (Join-Path $root 'results\\result.txt') -Destination {ps_quote(output)} -Force -ErrorAction Stop
}} finally {{
  if($mounted){{Dismount-VHD -Path $child -ErrorAction Stop}}
}}
"""
    k4.ps(script, timeout=90)
    transcript = output.read_text(encoding="ascii", errors="replace")
    ready_text = ready.read_text(encoding="ascii", errors="replace")
    match = re.search(r"RaiseBp at\s+(?:0x)?([0-9A-Fa-f]+)", transcript)
    return {
        "ready": ready_text.splitlines(),
        "transcript": transcript.splitlines(),
        "raise_bp": f"0x{int(match.group(1), 16):016x}" if match else None,
        "seh_success": bool(
            re.search(
                r"S5H_RESULT\s+arm=VTL1\s+rounds=1\s+handled=1\s+code=0x(?:00000000)?80000003\b",
                transcript,
                re.IGNORECASE,
            )
        ),
        "exit_success": bool(re.search(r"^exit_code=0\s*$", transcript, re.MULTILINE)),
    }


def verify_inputs() -> dict[str, Any]:
    inputs = {
        "plan": str(PLAN),
        "securekernel": {"path": str(SK_IMAGE), "sha256": sha256(SK_IMAGE)},
        "host": {"path": str(ASSETS / "spin_host.exe"), "sha256": sha256(ASSETS / "spin_host.exe")},
        "enclave": {"path": str(ASSETS / "spin_enclave.dll"), "sha256": sha256(ASSETS / "spin_enclave.dll")},
        "boot_service": {"path": str(ASSETS / "vtl1-user-experiment-service.exe"), "sha256": sha256(ASSETS / "vtl1-user-experiment-service.exe")},
    }
    expected = (
        (inputs["securekernel"]["sha256"], EXPECTED_IMAGE_SHA256, "securekernel.exe"),
        (inputs["host"]["sha256"], EXPECTED_HOST_SHA256, "spin_host.exe"),
        (inputs["enclave"]["sha256"], EXPECTED_ENCLAVE_SHA256, "spin_enclave.dll"),
        (inputs["boot_service"]["sha256"], EXPECTED_SERVICE_SHA256, "vtl1-user-experiment-service.exe"),
    )
    for observed, wanted, name in expected:
        if observed != wanted:
            raise k4.GateFailure(f"{name} SHA-256 mismatch: {observed} != {wanted}")
    if not PLAN.is_file() or not PROFILE.is_dir():
        raise k4.GateFailure("private plan or exact vmwp profile catalog is missing")
    return inputs


def run_positive(run_dir: pathlib.Path, nonce: str, state: dict[str, Any]) -> dict[str, Any]:
    trigger = run_dir / f"{nonce}.txt"
    trigger.write_text(f"nonce={nonce}\nmode=BP1\nrounds=1\n", encoding="ascii")
    result: dict[str, Any] = {
        "schema": "windbg-mcp.private.vtl1-user-to-securekernel.v1",
        "result": "running",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "nonce": nonce,
        "vm_id": VM_ID,
        "vm_name": VM_NAME,
        "trigger": trigger.read_text(encoding="ascii").splitlines(),
        "inputs": verify_inputs(),
        "vm_preparation": state,
    }
    manifest = run_dir / "manifest.json"
    save(manifest, result)

    client: Mcp | None = None
    session: str | None = None
    ended = False
    bench_started = False
    safely_released = False
    partition: int | None = None
    baseline: dict[str, Any] | None = None
    try:
        pid, uptime = k4.start_bench()
        bench_started = True
        result["boot"] = {"vmwp_pid": pid, "uptime_seconds": uptime, "vm": k4.vm_json()}
        vnd, handle, partition = k4.discover_identity(pid, f"vtl1-user-{nonce}")
        result["identity"] = {
            "dispatcher_vnd": f"0x{vnd:016x}",
            "partition_handle": f"0x{handle:016x}",
            "partition_id": f"0x{partition:x}",
            "expected_cr3": f"0x{EXPECTED_CR3:x}",
        }
        k4.pause_vm()
        probe = Probe()
        try:
            baseline = snapshot(probe, partition, 0)
        finally:
            probe.close()
        baseline_regs = baseline["registers"]
        if low_value(baseline_regs["cr3"]) != EXPECTED_CR3:
            raise k4.GateFailure("the paused VTL1 CR3 does not identify the expected runtime")
        if low_value(baseline_regs["dr7"]) & 0xFF:
            raise k4.GateFailure("the guest already has an enabled debug-register breakpoint")
        if low_value(baseline_regs["rflags"]) & ((1 << 8) | (1 << 16)):
            raise k4.GateFailure("the guest entered the experiment with TF or RF set")
        result["baseline"] = baseline
        target = live_target(partition, run_dir / "securekernel-before.json")
        result["target"] = target
        address = int(target["target_va"], 0)
        save(manifest, result)

        control_transport = (
            f"python {HERE / 'k4_control_provider.py'} --vm-id {VM_ID} "
            f"--partition-id 0x{partition:x} --expected-cr3 0x{EXPECTED_CR3:x} "
            "--allow-transition-cr3 --vp {vp}"
        )
        vmwp, handle = k4.discovered(partition)
        live_transport = (
            f"python {HERE / 'gpa_server.py'} --vmwp-pid {vmwp} --partition-handle 0x{handle:x} "
            f"--partition-id 0x{partition:x} --expected-cr3 0x{EXPECTED_CR3:x}"
        )
        client = Mcp()
        initialized = client.request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "vtl1-user-securekernel-gate", "version": "1"},
            },
            15,
        )
        if initialized.get("error") is not None:
            raise k4.GateFailure(f"initialize failed: {initialized}")
        client.notify("notifications/initialized", {})
        opened = ok(
            client.tool(
                "open_sk_live_control",
                {
                    "profile": str(PROFILE),
                    "control_transport": control_transport,
                    "live_transport": live_transport,
                    "vmwp_pid": pid,
                    "dispatcher_vnd": f"0x{vnd:016x}",
                    "vm_id": VM_ID,
                    "partition_id": f"0x{partition:x}",
                    "vp": 0,
                    "expected_cr3": f"0x{EXPECTED_CR3:x}",
                    "allow_transition_cr3": True,
                },
                30,
            ),
            "open_sk_live_control",
        )
        session = str(opened["session_id"])
        result["open"] = opened
        armed = ok(
            client.tool(
                "sk_live_arm",
                {
                    "session_id": session,
                    "address": f"0x{address:016x}",
                    "bytes": SK_BYTES.hex(),
                    "slot": 0,
                    "mode": "natural",
                },
                90,
            ),
            "sk_live_arm",
        )
        result["arm"] = armed
        result["trigger"] = {
            "request": trigger.read_text(encoding="ascii").splitlines(),
            "delivery": "offline child before boot",
            "service_release_delay_ms": 90000,
            "armed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        save(manifest, result)

        hardware = ok(
            client.tool("sk_live_wait", {"session_id": session}, 180),
            "hardware sk_live_wait",
        )
        event = hardware["event"]
        if event.get("reason") != {"reason": "hardware_breakpoint", "slot": 0}:
            raise k4.GateFailure(f"wrong stop reason: {event.get('reason')}")
        if (event.get("vtl"), event.get("cpl"), event.get("vp")) != (1, 0, 0):
            raise k4.GateFailure(f"stop identity is not VTL1 CPL0 VP0: {event}")
        if int(hardware["instruction"]["address"], 0) != address:
            raise k4.GateFailure("hardware stop did not occur at KiBreakpointTrap")
        registers = register_map(hardware)
        result["hardware_stop"] = hardware
        save(manifest, result)
        if registers["rip"] != address:
            raise k4.GateFailure("hardware-stop registers do not identify KiBreakpointTrap")
        if registers["cr3"] == EXPECTED_CR3 or registers["cr3"] == 0 or registers["cr3"] & 0xFFF:
            raise k4.GateFailure(
                "hardware stop did not carry a distinct, page-aligned VTL1 user transition CR3"
            )

        stack = ok(
            client.tool(
                "sk_live_read_memory",
                {"session_id": session, "address": f"0x{registers['rsp']:016x}", "size": 40},
                30,
            ),
            "read saved VTL1 user frame",
        )
        frame_bytes = readable_hex(stack)
        if len(frame_bytes) != 40:
            raise k4.GateFailure(f"saved user frame returned {len(frame_bytes)} bytes")
        words = struct.unpack("<5Q", frame_bytes)
        saved_rip, saved_cs, saved_rflags, saved_rsp, saved_ss = words
        if saved_cs != 0x33 or saved_ss != 0x2B:
            raise k4.GateFailure(
                f"trap frame is not VTL1 user mode: CS=0x{saved_cs:X}, SS=0x{saved_ss:X}"
            )
        if not is_canonical_user(saved_rip) or not is_canonical_user(saved_rsp):
            raise k4.GateFailure("trap frame does not contain canonical VTL1 user addresses")
        if saved_rip < ENCLAVE_RETURN_RIP_RVA:
            raise k4.GateFailure("saved VTL1 user RIP is below the known enclave return RVA")
        module_base = saved_rip - ENCLAVE_RETURN_RIP_RVA
        module = ok(
            client.tool(
                "sk_live_read_memory",
                {"session_id": session, "address": f"0x{module_base:016x}", "size": 64},
                30,
            ),
            "read enclave image header",
        )
        if not readable_hex(module).startswith(b"MZ"):
            raise k4.GateFailure("saved user RIP does not lead back to an enclave PE image")
        result["saved_user_frame"] = {
            "raw": frame_bytes.hex(),
            "rip": f"0x{saved_rip:016x}",
            "cs": f"0x{saved_cs:x}",
            "rflags": f"0x{saved_rflags:016x}",
            "rsp": f"0x{saved_rsp:016x}",
            "ss": f"0x{saved_ss:x}",
            "enclave_base": f"0x{module_base:016x}",
            "expected_int3": f"0x{saved_rip - 1:016x}",
            "image_header": module,
        }
        save(manifest, result)

        stepping = ok(
            client.tool(
                "sk_live_step",
                {
                    "session_id": session,
                    "epoch": hardware["epoch"],
                    "address": f"0x{address:016x}",
                    "bytes": SK_BYTES.hex(),
                    "expected_rips": [f"0x{address + SK_STEP_RIP_DELTA:016x}"],
                },
                90,
            ),
            "sk_live_step",
        )
        result["step"] = stepping
        stepped = ok(
            client.tool("sk_live_wait", {"session_id": session}, 120),
            "single-step sk_live_wait",
        )
        step_regs = register_map(stepped)
        if stepped["event"].get("reason") != {"reason": "single_step"}:
            raise k4.GateFailure("the Secure Kernel instruction did not complete as a single step")
        if step_regs["rip"] != address + SK_STEP_RIP_DELTA:
            raise k4.GateFailure("single-step RIP did not reach KiBreakpointTrap+4")
        if step_regs["rsp"] != registers["rsp"] - 8:
            raise k4.GateFailure("single-step RSP did not reflect sub rsp,8")
        if step_regs["cr3"] != registers["cr3"]:
            raise k4.GateFailure("single-step changed the proved VTL1 user transition CR3")
        result["single_step_stop"] = stepped

        resumed = ok(
            client.tool(
                "sk_live_continue",
                {"session_id": session, "epoch": stepped["epoch"]},
                90,
            ),
            "sk_live_continue",
        )
        result["continue"] = resumed
        ended_response = ok(
            client.tool("end_session", {"session_id": session}, 120),
            "end_session",
        )
        if ended_response.get("released") is not True or ended_response.get("target_left_running") is not True:
            raise k4.GateFailure(f"end_session did not release a running target: {ended_response}")
        result["end"] = ended_response
        ended = True
        session = None
        safely_released = True
        result["server_stderr"] = "".join(client.errors)
        client.shutdown()
        client = None

        result["health"] = [k4.health(pid, "immediate")]
        save(manifest, result)
        time.sleep(30)
        result["health"].append(k4.health(pid, "30s"))
        save(manifest, result)
        time.sleep(30)
        result["health"].append(k4.health(pid, "60s"))

        k4.pause_vm()
        probe = Probe()
        try:
            after = snapshot(probe, partition, 0)
        finally:
            probe.close()
        for name in DEBUG_REGISTERS:
            if after["registers"][name] != baseline["registers"][name]:
                raise k4.GateFailure(f"VP0 debug-register baseline mismatch for {name}")
        flags = low_value(after["registers"]["rflags"])
        if flags & ((1 << 8) | (1 << 16)):
            raise k4.GateFailure("VP0 retained TF or RF after continue")
        after_target = live_target(partition, run_dir / "securekernel-after.json")
        if after_target["text"] != target["text"]:
            raise k4.GateFailure("Secure Kernel text changed during the experiment")
        result["post_resume_audit"] = {
            "debug_baseline_restored": True,
            "tf_rf_clear": True,
            "securekernel_text_unchanged": True,
            "registers": after,
            "target": after_target,
        }
        k4.resume_vm()
        result["bench_cleanup"] = k4.stop_bench()
        bench_started = False

        guest = extract_guest_evidence(pathlib.Path(state["child_disk"]), nonce, run_dir)
        result["guest"] = guest
        if not guest["seh_success"] or not guest["exit_success"]:
            raise k4.GateFailure(f"enclave SEH did not complete successfully: {guest}")
        if guest["raise_bp"] is None:
            raise k4.GateFailure("guest transcript omitted the RaiseBp address")
        raise_bp = int(guest["raise_bp"], 0)
        if raise_bp - ENCLAVE_RAISE_BP_RVA != module_base:
            raise k4.GateFailure(
                "guest RaiseBp address and saved VTL1 user return frame name different enclave images"
            )
        result["causal_proof"] = {
            "guest_raise_bp": f"0x{raise_bp:016x}",
            "expected_int3": f"0x{raise_bp - (ENCLAVE_RAISE_BP_RVA - ENCLAVE_RETURN_RIP_RVA) - 1:016x}",
            "saved_return_rip": f"0x{saved_rip:016x}",
            "same_enclave_image": True,
            "securekernel_entry_stopped": True,
            "securekernel_prologue_stepped": True,
            "enclave_seh_resumed": True,
        }
        result["result"] = "pass"
        return result
    except Exception as error:
        result["result"] = "fail"
        result["error"] = str(error)
        if client is not None and session is not None and not ended:
            try:
                result["failure_end"] = client.tool("end_session", {"session_id": session}, 120)
                data = structured(result["failure_end"])
                if isinstance(data, dict) and data.get("status") == "ok" and data.get("target_left_running") is True:
                    safely_released = True
            except Exception as cleanup_error:
                result["failure_end_error"] = str(cleanup_error)
        raise
    finally:
        if client is not None:
            try:
                result["server_stderr"] = "".join(client.errors)
                client.shutdown()
            except Exception as cleanup_error:
                result["client_cleanup_error"] = str(cleanup_error)
        if bench_started:
            if safely_released:
                try:
                    result["bench_cleanup"] = k4.stop_bench()
                    bench_started = False
                except Exception as cleanup_error:
                    result["bench_cleanup_error"] = str(cleanup_error)
            else:
                try:
                    k4.fail_closed_pause()
                    result["failure_vm"] = k4.vm_json()
                except Exception as cleanup_error:
                    result["failure_pause_error"] = str(cleanup_error)
        result["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        save(manifest, result)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nonce", help="bounded evidence name; defaults to a fresh value")
    args = parser.parse_args()
    nonce = args.nonce or (time.strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8])
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", nonce):
        raise k4.GateFailure("nonce must contain only letters, digits, underscore, or hyphen")
    run_dir = RUN_ROOT / nonce
    run_dir.mkdir(parents=True, exist_ok=False)
    state: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    try:
        state = prepare_child(run_dir, nonce, "BP1")
        result = run_positive(run_dir, nonce, state)
        return 0
    finally:
        if state is not None and k4.vm_state() == "Off":
            try:
                restored = restore_vm(run_dir, state)
                if result is not None:
                    result["vm_restore"] = restored
                    save(run_dir / "manifest.json", result)
            except Exception as restore_error:
                if result is not None:
                    result["vm_restore_error"] = str(restore_error)
                    result["result"] = "fail"
                    save(run_dir / "manifest.json", result)
                raise
        print(
            json.dumps(
                {
                    "run": nonce,
                    "result": None if result is None else result.get("result"),
                    "evidence": str(run_dir),
                    "vm_state": k4.vm_state(),
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    raise SystemExit(main())
