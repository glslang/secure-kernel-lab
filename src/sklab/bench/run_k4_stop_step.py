"""One-command K4 VTL1 hardware-stop/single-step gate.

This is exact-build bench automation. It targets one allowlisted disposable VM,
never consumes a VID queue, and leaves a failed run paused rather than guessing
how to continue it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import queue
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Any


HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PROVIDER = HERE / "k4_control_provider.py"
CDB = pathlib.Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe")
# The windbg-mcp build whose `--sk-discover-identity` discovers this boot's identity;
# sklab.bench_bridge points it at the configured executable.
MCP_EXE = ROOT / "target" / "debug" / "windbg-mcp.exe"
# Discovery takes about two seconds. Its own bounds (the VM pause, the entry wait and the
# partition call) total under four minutes, so a run past this is held, not slow.
DISCOVERY_TIMEOUT = 300
VM_NAME = "windbg-mcp K3 Managed VTL1"
VM_ID = "6b1ed0f6-137e-469f-aeab-a3f4cfee398d"
IMAGE = HERE / "guest-positive-securekernel.exe"
IMAGE_SHA256 = "A9CDE82E39794FB2910BD53A7DDA3DF750C443222F898C49092D5E51F8B2095E"
EXPECTED_CR3 = 0x1201000
TARGET_RVA = 0xB12B
# The boot's discovery record: sklab.bench_bridge points this at the same file the workflows write.
DISCOVERY_CACHE: pathlib.Path | None = None
TARGET_BYTES = bytes.fromhex("0f1f440000")
VMWP_SHA256 = "AD1D4D5380F81DBD95CECDE55D5F1BC19FC1EBA60AE530141C8597562200909F"
VID_DLL_SHA256 = "9B538C07FA65C09D406956371EF3C68F4BCE4E1FA9F694E4CCB727409366FA26"
VID_SYS_SHA256 = "6611BCD768EFCFF90C13D39C4D9770315269C43201B3A58B638977486AB06697"
PROFILE = HERE.parents[2] / "profiles" / "vmwp-dispatcher-profile-26100.9711.json"

sys.path.insert(0, str(HERE))
from h3_vtl1_debug_control import (  # noqa: E402
    SNAPSHOT_NAMES,
    low_value,
)


class GateFailure(RuntimeError):
    pass


def cdb_marker_line(line: str) -> str:
    return re.sub(r"^(?:\d+:[^>]+>\s*)+", "", line.strip())


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def profile_rva(name: str) -> int:
    """Read an RVA from the configured exact-build vmwp profile."""
    value: Any = json.loads(PROFILE.read_text(encoding="utf-8"))
    for part in name.split("."):
        value = value[part]
    if isinstance(value, dict):
        value = value["rva"]
    return int(str(value), 0)


def ps(script: str, timeout: float = 60) -> str:
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    if completed.returncode:
        raise GateFailure(
            f"PowerShell failed ({completed.returncode}): {script}\n"
            f"stdout: {completed.stdout}\nstderr: {completed.stderr}"
        )
    return completed.stdout.strip()


def vm_json() -> dict[str, Any]:
    raw = ps(
        f"Get-VM -Name '{VM_NAME}' | Select-Object Name,"
        "@{n='State';e={$_.State.ToString()}},"
        "@{n='UptimeSeconds';e={$_.Uptime.TotalSeconds}},"
        "@{n='Heartbeat';e={(Get-VMIntegrationService -VM $_ -Name Heartbeat).PrimaryStatusDescription}},"
        "Status,VMId "
        "| ConvertTo-Json -Compress"
    )
    return json.loads(raw)


def vm_state() -> str:
    return ps(
        f"(Get-VM -Name '{VM_NAME}' -ErrorAction Stop).State.ToString()"
    )


def vmwp_pid() -> int:
    raw = ps(
        "$p=Get-CimInstance Win32_Process -Filter \"Name='vmwp.exe'\" | "
        f"Where-Object {{$_.CommandLine -match '{VM_ID}'}}; "
        "if(@($p).Count -ne 1){throw \"expected one target vmwp, got $(@($p).Count)\"}; "
        "$p.ProcessId"
    )
    return int(raw)


def pause_vm() -> None:
    state = vm_state()
    if state == "Paused":
        return
    if state != "Running":
        raise GateFailure(f"cannot pause VM from state {state}")
    ps(f"Suspend-VM -Name '{VM_NAME}' -ErrorAction Stop")
    if vm_state() != "Paused":
        raise GateFailure("VM did not enter Paused state")


def resume_vm() -> None:
    state = vm_state()
    if state == "Running":
        return
    if state != "Paused":
        raise GateFailure(f"cannot resume VM from state {state}")
    ps(f"Resume-VM -Name '{VM_NAME}' -ErrorAction Stop")


def start_pause_request() -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"Suspend-VM -Name '{VM_NAME}' -ErrorAction Stop",
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def finish_pause_request(request: subprocess.Popen[str]) -> None:
    try:
        stdout, stderr = request.communicate(timeout=60)
    except subprocess.TimeoutExpired as error:
        request.kill()
        request.communicate(timeout=5)
        raise GateFailure("asynchronous Suspend-VM did not complete") from error
    if request.returncode:
        raise GateFailure(
            f"asynchronous Suspend-VM failed ({request.returncode}): "
            f"stdout={stdout!r}, stderr={stderr!r}"
        )
    if vm_state() != "Paused":
        raise GateFailure("asynchronous Suspend-VM completed outside Paused state")
    ps(f"Resume-VM -Name '{VM_NAME}' -ErrorAction Stop")
    if vm_state() != "Running":
        raise GateFailure("VM did not resume after asynchronous completion kick")


def start_bench() -> tuple[int, float]:
    state = vm_json()["State"]
    if state != "Off":
        raise GateFailure(f"expected allowlisted disposable VM Off, got state {state}")
    unexpected = ps(
        f"$v=Get-VM | Where-Object {{$_.State -ne 'Off' -and $_.VMId -ne '{VM_ID}'}}; "
        "@($v).Count"
    )
    if int(unexpected or "0"):
        raise GateFailure(f"refusing to start beside {unexpected} non-Off VM(s)")
    ps(
        "foreach($n in @('h3probe')){$s=Get-Service -Name $n -ErrorAction Stop;"
        "if($s.Status -ne 'Running'){Start-Service -Name $n -ErrorAction Stop;"
        "$s.WaitForStatus('Running',[TimeSpan]::FromSeconds(15))}}"
    )
    ps(f"Start-VM -Name '{VM_NAME}' -ErrorAction Stop | Out-Null")
    deadline = time.monotonic() + 150
    while time.monotonic() < deadline:
        vm = vm_json()
        if vm["State"] == "Running" and vm.get("Heartbeat") == "OK":
            if float(vm["UptimeSeconds"]) >= 60:
                return vmwp_pid(), float(vm["UptimeSeconds"])
        time.sleep(5)
    raise GateFailure("VM did not reach a 60-second healthy boot")


def stop_bench() -> dict[str, Any]:
    state = vm_state()
    if state == "Paused":
        resume_vm()
        time.sleep(2)
    before = vm_json()
    if before["State"] == "Running":
        ps(f"Stop-VM -Name '{VM_NAME}' -ErrorAction Stop", timeout=60)
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline and vm_state() != "Off":
        time.sleep(2)
    if vm_state() != "Off":
        raise GateFailure("VM did not reach Off during final cleanup")
    ps(
        "foreach($n in @('h3probe')){$s=Get-Service -Name $n -ErrorAction SilentlyContinue;"
        "if($s -and $s.Status -ne 'Stopped'){Stop-Service -Name $n -ErrorAction Stop;"
        "$s.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(15))}}"
    )
    return {"before": before, "after": vm_json()}


def fail_closed_pause() -> bool:
    try:
        state = vm_state()
        if state == "Running":
            pause_vm()
        return vm_state() == "Paused"
    except Exception as error:  # best effort after the primary failure
        print(f"recovery: could not pause target: {error}", file=sys.stderr)
        return False


@dataclass
class CdbSession:
    pid: int
    name: str
    commands: str

    def __post_init__(self) -> None:
        self.command_path = HERE / f"{self.name}.cdb.txt"
        self.log_path = HERE / f"{self.name}.log"
        self.command_path.write_text(self.commands, encoding="ascii", newline="\n")
        self.process = subprocess.Popen(
            [
                str(CDB), "-pd", "-p", str(self.pid), "-cf", str(self.command_path),
                "-logo", str(self.log_path),
            ],
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self.lines: queue.Queue[str] = queue.Queue()
        self.all_lines: list[str] = []
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            self.all_lines.append(line)
            self.lines.put(line)

    def wait(self, marker: str, timeout: float = 60) -> str:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None and self.lines.empty():
                break
            try:
                line = self.lines.get(timeout=min(0.25, max(0.01, deadline - time.monotonic())))
            except queue.Empty:
                continue
            clean = line.strip()
            # CDB can prefix output produced at a prompt with `system:thread>`.
            # Strip that prompt only; echoed commands still begin with their
            # command verb and therefore cannot satisfy a marker.
            marker_line = cdb_marker_line(clean)
            # CDB echoes command-file input.  Accept only debugger output whose
            # line begins with the marker, never an echoed .echo/bp command.
            if marker.endswith("="):
                matched = marker_line.startswith(marker)
            else:
                matched = (
                    marker_line == marker
                    or marker_line.startswith(marker + " ")
                    or marker_line.startswith(marker + "=")
                )
            if matched:
                return marker_line
        tail = "".join(self.all_lines[-30:])
        raise GateFailure(f"CDB {self.name} did not report {marker!r}; tail:\n{tail}")

    def wait_optional(self, marker: str, timeout: float) -> str | None:
        try:
            return self.wait(marker, timeout)
        except GateFailure:
            if self.process.poll() is not None:
                raise
            return None

    def send(self, commands: str) -> None:
        if self.process.poll() is not None:
            raise GateFailure(f"CDB {self.name} exited before command")
        assert self.process.stdin is not None
        self.process.stdin.write(commands.rstrip() + "\n")
        self.process.stdin.flush()

    def finish(self, timeout: float = 30) -> str:
        try:
            code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise GateFailure(f"CDB {self.name} did not exit") from error
        self.reader.join(timeout=2)
        if code:
            raise GateFailure(f"CDB {self.name} exited {code}")
        return "".join(self.all_lines)

    def detach(self) -> None:
        if self.process.poll() is None:
            self.send("bc *\nbl\n.detach /h\nq")
            self.finish()


class ControlClient:
    """Client for the repository's windbg-mcp-sk-control/2 contract."""

    def __init__(self, partition: int) -> None:
        self.target = {
            "vm_id": VM_ID,
            "partition_id": f"0x{partition:016x}",
            "vp": 0,
            "vtl": 1,
            "expected_cr3": f"0x{EXPECTED_CR3:016x}",
        }
        self.partition = partition
        self.process = subprocess.Popen(
            [
                sys.executable,
                str(PROVIDER),
                "--vm-id",
                VM_ID,
                "--partition-id",
                hex(partition),
                "--expected-cr3",
                hex(EXPECTED_CR3),
            ],
            cwd=PROVIDER.parent,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            text=True,
            bufsize=1,
        )
        self.lines: queue.Queue[str] = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        for _ in range(64):
            if self._line(20) == "windbg-mcp-sk-control/2":
                break
        else:
            raise GateFailure("control provider omitted its readiness sentinel")
        hello = json.loads(self._line(20))
        if hello.get("protocol") != 2 or hello.get("target") != self.target:
            raise GateFailure(f"control provider hello mismatch: {hello}")
        self.epoch = str(hello["epoch"])
        self.next_id = 1
        self.phase = "running"
        capabilities = self.request("capabilities")
        expected = {
            "begin_arm", "finish_arm", "publish_stop", "held_event",
            "read_registers", "write_registers", "release",
        }
        advertised = set(capabilities["value"]["capabilities"])
        if capabilities.get("kind") != "capabilities" or not expected <= advertised:
            raise GateFailure(f"control provider capabilities mismatch: {capabilities}")
        if (
            capabilities["value"].get("requires_stop_epoch") is not True
            or capabilities["value"].get("writes_while_running") is not False
        ):
            raise GateFailure("control provider does not enforce stopped epochs")

    def _read(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            self.lines.put(line.rstrip("\r\n"))

    def _line(self, timeout: float) -> str:
        try:
            return self.lines.get(timeout=timeout)
        except queue.Empty as error:
            code = self.process.poll()
            raise GateFailure(f"control provider response timed out (exit={code})") from error

    def request(self, op: str, **fields: object) -> dict[str, Any]:
        if self.process.poll() is not None:
            raise GateFailure(f"control provider exited {self.process.returncode}")
        request_id = self.next_id
        self.next_id += 1
        request = {
            "protocol": 2,
            "id": request_id,
            "target": self.target,
            "epoch": self.epoch,
            "operation": {"op": op, **fields},
        }
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(request, separators=(",", ":")) + "\n")
        self.process.stdin.flush()
        response = json.loads(self._line(30))
        if (
            response.get("protocol") != 2
            or response.get("id") != request_id
            or response.get("target") != self.target
        ):
            raise GateFailure(f"control response identity mismatch: {response}")
        outcome = response.get("outcome", {})
        if outcome.get("status") == "error":
            error = outcome.get("error", {})
            if response.get("epoch") != self.epoch:
                raise GateFailure(f"control error changed epoch: {response}")
            raise GateFailure(f"control provider refused {error.get('code')}: {error.get('detail')}")
        if outcome.get("status") != "ok":
            raise GateFailure(f"invalid control outcome: {response}")
        next_epoch = str(response.get("epoch"))
        transition = op in {"begin_arm", "finish_arm", "publish_stop", "release"}
        if transition == (next_epoch == self.epoch):
            raise GateFailure(f"control epoch rotation mismatch for {op}: {response}")
        self.epoch = next_epoch
        return outcome["value"]

    def begin_arm(self) -> None:
        if self.phase != "running" or self.request("begin_arm").get("kind") != "arm_begun":
            raise GateFailure("control provider did not begin arming")
        self.phase = "arming"

    def finish_arm(self) -> None:
        if self.phase != "arming" or self.request("finish_arm").get("kind") != "arm_finished":
            raise GateFailure("control provider did not finish arming")
        self.phase = "running"

    def publish_stop(self, context: int, reason: dict[str, object]) -> dict[str, Any]:
        event = {
            "message_type": "0x0000000001000002",
            "vector": 1,
            "vp": 0,
            "vtl": 1,
            "cpl": 0,
            "dispatcher_context": f"0x{context:016x}",
            "advance_instruction_pointer": False,
            "reason": reason,
        }
        value = self.request("publish_stop", event=event)
        if value.get("kind") != "stop_published" or value.get("event") != event:
            raise GateFailure(f"control provider changed held event: {value}")
        self.phase = "stopped"
        echoed = self.request("held_event")
        if echoed.get("kind") != "held_event" or echoed.get("event") != event:
            raise GateFailure(f"control provider held-event mismatch: {echoed}")
        return event

    def release(self) -> None:
        if self.phase != "stopped" or self.request("release").get("kind") != "released":
            raise GateFailure("control provider did not release held epoch")
        self.phase = "running"

    def snapshot(self) -> dict[str, Any]:
        names = [*SNAPSHOT_NAMES, "vsm_vp_status"]
        value = self.request("read_registers", registers=names)
        if value.get("kind") != "registers":
            raise GateFailure(f"control provider returned wrong snapshot kind: {value}")
        rows = value["values"]
        if [row.get("name") for row in rows] != names:
            raise GateFailure(f"control provider reordered snapshot: {rows}")
        registers = {
            row["name"]: {"status": row["status"], "low": row["low"], "high": row["high"]}
            for row in rows
        }
        return {
            "partition_id": f"0x{self.partition:x}",
            "vp": 0,
            "vtl": 1,
            "epoch": self.epoch,
            "phase": self.phase,
            "registers": registers,
        }

    def write(self, name: str, expected: int, value: int) -> dict[str, Any]:
        response = self.request(
            "write_registers",
            writes=[{
                "name": name,
                "expected": f"0x{expected:016x}",
                "value": f"0x{value:016x}",
            }],
        )
        if response.get("kind") != "registers_written" or len(response.get("values", [])) != 1:
            raise GateFailure(f"control provider returned wrong write result: {response}")
        row = response["values"][0]
        if row.get("name") != name or low_value(row) != value:
            raise GateFailure(f"control provider write verification mismatch: {row}")
        return {"status": row["status"], "low": row["low"], "high": row["high"]}

    def close(self) -> None:
        if self.process.poll() is None and self.process.stdin is not None:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        self.reader.join(timeout=2)
        if self.process.returncode:
            raise GateFailure(f"control provider exited {self.process.returncode}")


def parse_address(text: str, field: str) -> int:
    match = re.search(rf"(?:^|\s){re.escape(field)}=([0-9a-fA-F`]+)", text)
    if not match:
        raise GateFailure(f"missing {field}= address in {text!r}")
    return int(match.group(1).replace("`", ""), 16)


def cdb_output_has_marker(output: str, marker: str) -> bool:
    """Return whether CDB emitted marker, excluding echoed command input."""
    return any(cdb_marker_line(line) == marker for line in output.splitlines())


def require_breakpoint_restored(output: str, marker: str, label: str) -> None:
    if not cdb_output_has_marker(output, marker):
        raise GateFailure(f"{label} breakpoint bytes were not restored")


def discover_identity(pid: int, run: str) -> tuple[int, int, int]:
    """This boot's dispatcher VND, VID partition handle and partition id, from windbg-mcp.

    `--sk-discover-identity` is the discovery a live-control session runs on its own engine
    thread, run alone: pause, attach, sample the dispatcher entry, call `VidGetHvPartitionId` on
    a hijacked thread with the others frozen, free its scratch and detach handled. It replaced a
    cdb sample after whose `.detach /h` vmwp crashed with `0x80000003` at the entry in about one
    run in eight, and a second cdb attach for the call.

    Output goes to files, not pipes. A discovery that cannot restore its partition call holds
    vmwp contained and never exits, and ending that process ends vmwp, so a run past the timeout
    is reported and left running for exact-PID recovery.
    """
    answer = HERE / f"k4-auto-{run}-identity.json"
    log = HERE / f"k4-auto-{run}-identity.log"
    command = [
        str(MCP_EXE), "--sk-discover-identity", "--profile", str(PROFILE),
        "--vm-id", VM_ID, "--vmwp-pid", str(pid),
    ]
    with answer.open("w", encoding="utf-8") as stdout, log.open("w", encoding="utf-8") as stderr:
        process = subprocess.Popen(
            command, cwd=ROOT, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
        )
        try:
            code = process.wait(timeout=DISCOVERY_TIMEOUT)
        except subprocess.TimeoutExpired as error:
            raise GateFailure(
                f"windbg-mcp discovery did not finish within {DISCOVERY_TIMEOUT}s; process "
                f"{process.pid} may hold vmwp contained and was left running (see {log})"
            ) from error
    if code:
        lines = log.read_text(encoding="utf-8", errors="replace").strip().splitlines()
        reason = next((line for line in reversed(lines) if line.startswith("Error:")), "")
        raise GateFailure(f"windbg-mcp discovery exited {code}: {reason or log}")
    data = json.loads(answer.read_text(encoding="utf-8"))
    if (
        data.get("schema") != "windbg-mcp.sk-identity.v1"
        or str(data.get("vm_id", "")).lower() != VM_ID.lower()
        or data.get("vmwp_pid") != pid
    ):
        raise GateFailure(f"windbg-mcp discovery answered for another target: {data}")
    return (
        int(data["dispatcher_vnd"], 16),
        int(data["partition_handle"], 16),
        int(data["partition_id"], 16),
    )


def save_json(path: pathlib.Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def register_snapshot(control: ControlClient, path: pathlib.Path) -> dict[str, Any]:
    value = control.snapshot()
    save_json(path, value)
    return value


def write_sequence(
    control: ControlClient,
    writes: tuple[tuple[str, int], ...],
    path: pathlib.Path,
) -> dict[str, Any]:
    before = control.snapshot()
    current = {
        name: low_value(row) for name, row in before["registers"].items()
    }
    rows: list[dict[str, Any]] = []
    for name, value in writes:
        readback = control.write(name, current[name], value)
        current[name] = value
        rows.append({"name": name, "value": f"0x{value:016x}", "readback": readback})
    result = {"before": before, "writes": rows, "after": control.snapshot()}
    save_json(path, result)
    return result


def roundtrip_debug(control: ControlClient, run: str) -> dict[str, Any]:
    before = control.snapshot()
    writes = tuple((name, low_value(before["registers"][name])) for name in (
        "dr0", "dr1", "dr2", "dr3", "dr6", "dr7"
    ))
    return write_sequence(control, writes, HERE / f"k4-auto-{run}-debug-roundtrip.json")


def discovered(partition: int) -> tuple[int, int]:
    """This boot's vmwp PID and its partition handle, from the discovery already run for it.

    A record for another boot, VM or partition is refused rather than used: the handle value is
    meaningful only inside the vmwp that discovery attached to.
    """
    cache = DISCOVERY_CACHE or HERE / "discovery-cache.json"
    try:
        data = json.loads(cache.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise GateFailure(f"no discovery record at {cache}: {error}") from error
    pid = vmwp_pid()
    if (
        data.get("vm_id") != VM_ID
        or int(data.get("vmwp_pid", 0)) != pid
        or int(str(data.get("partition_id", "0")), 0) != partition
    ):
        raise GateFailure(f"{cache} is not this boot's: vmwp {pid}, partition 0x{partition:x}")
    return pid, int(str(data["partition_handle"]), 0)


def h3_source(partition: int) -> Any:
    """h3probe's memory operation for this boot's vmwp and partition."""
    from guest_physical import H3Source

    pid, handle = discovered(partition)
    return H3Source(pid, handle, partition)


def live_target(
    partition: int, path: pathlib.Path, cr3: int = EXPECTED_CR3
) -> dict[str, Any]:
    from guest_physical import GuestVirtual, find_secure_kernel_base, vtl1_identity
    from vtl0_find_matching_image import Guest

    source = h3_source(partition)
    try:
        identity = vtl1_identity(partition, 0)
        base, _evidence = find_secure_kernel_base(
            GuestVirtual(source, identity["cr3"]),
            identity["idtr_base"],
            identity["idtr_limit"],
            IMAGE,
        )
        target = base + TARGET_RVA
        guest = Guest(source, cr3)
        first = guest.virtual(target, 16)
        guest.pages.clear()
        second = guest.virtual(target, 16)
        result = {
            "partition_id": f"0x{partition:x}",
            "cr3": f"0x{cr3:x}",
            "securekernel_base": f"0x{base:016x}",
            "target_rva": f"0x{TARGET_RVA:x}",
            "target_va": f"0x{target:016x}",
            "instruction_bytes": TARGET_BYTES.hex(),
            "instruction_length": len(TARGET_BYTES),
            "live_read_1": first.hex(),
            "live_read_2": second.hex(),
            "valid": first == second and first.startswith(TARGET_BYTES),
        }
        if not result["valid"]:
            raise GateFailure(f"live Secure Kernel target mismatch: {result}")
        save_json(path, result)
        return result
    finally:
        source.close()


def handler_commands(vnd: int) -> str:
    callback_stub = profile_rva("callback_stub_rva")
    event_held = profile_rva("event_held")
    return f'''sxd 6ba
sxd e06d7363
.echo K4AUTO_VECTOR1_BEGIN
r @$t5=0
r @$t6={vnd:016x}
r @$t7=0000020000000000
.dvalloc /b 0000020000000000 1000
eq @$t7 0
r @$t8=@$t7+100
r @$t9=@$t7+200
eq @$t8 @$t9
eq @$t9 vmwp+{callback_stub:x}
eq @$t9+30 vmwp+{callback_stub:x}
bp vmwp+{event_held:x} ".if (poi(@r14+8)==@$t5) {{ .echo K4AUTO_HARDWARE_EVENT_HELD; r rcx; r r14; dd @r14 L20; db @r14+148 L1 }} .else {{ gc }}"
~* f
~# u
r @$t0=poi(@rsp)
r @$t1=poi(@rsp+28)
r @$t2=poi(@rsp+30)
r @$t3=@rsp+28
r @$t4=@rsp+30
bp /1 @$t0 ".echo K4AUTO_VECTOR1_REGISTER_RETURN; r rax; r @$t5=poi(@$t7); .echo K4AUTO_VECTOR1_REGISTERED; r @$t5; dq @$t5 L20; eq @$t3 @$t1; eq @$t4 @$t2; ~* u"
r rcx=@$t6
r rdx=1
r r8=0
r r9=4b344155544f5354
eq @$t3 @$t8
eq @$t4 @$t7
r rip=vmwp!VidNotificationDispatcher::RegisterExceptionHandler
g
'''


def release_event(
    cdb: CdbSession,
    label: str,
    context: int,
    next_marker: str | None,
) -> dict[str, int | bool]:
    prefix = f"K4AUTO_{label}"
    event_held = profile_rva("event_held")
    callback_entry = profile_rva("callback_entry")
    handle_return = profile_rva("handle_return")
    callback_resume = profile_rva("callback_resume_rva")
    native_return = profile_rva("native_return")
    cdb.send(
        f".echo {prefix}_RELEASE_BEGIN\n"
        "bc *\n"
        f"db vmwp+{event_held:x} L8\n"
        f"bp vmwp+{callback_entry:x} \".echo {prefix}_CALLBACK_ENTRY\"\n"
        "g"
    )
    cdb.wait(f"{prefix}_CALLBACK_ENTRY", 30)
    cdb.send(
        f'.printf "{prefix}_CALLBACK_RESULT type=%p context=%p callback=%p\\n", @rcx, @rbx, poi(@rbx+80)\n'
        "bc *\n"
        f"db vmwp+{callback_entry:x} L8\n"
        f"bp vmwp+{handle_return:x} \".echo {prefix}_HANDLE_RETURN\"\n"
        f"r rip=vmwp+{callback_resume:x}\n"
        "g"
    )
    cdb.wait(f"{prefix}_HANDLE_RETURN", 30)
    cdb.send(
        f'.printf "{prefix}_HANDLE_RESULT rax=%p\\n", @rax\n'
        "bc *\n"
        f"db vmwp+{handle_return:x} L8\n"
        f"bp vmwp+{native_return:x} \".echo {prefix}_NATIVE_RETURN\"\n"
        "g"
    )
    pause_request: subprocess.Popen[str] | None = None
    marker = cdb.wait_optional(f"{prefix}_NATIVE_RETURN", 12)
    if marker is None:
        # A pause request makes the completion thread leave its VID wait, but
        # waiting synchronously for Suspend-VM deadlocks when CDB stops that
        # same vmwp at the native-return breakpoint.  Observe the breakpoint,
        # continue or detach it as handled, and only then join the request.
        pause_request = start_pause_request()
        cdb.wait(f"{prefix}_NATIVE_RETURN", 30)
    cdb.send(
        f'.printf "{prefix}_NATIVE_RESULT rax=%p\\n", @rax\n'
        "bc *\n"
        f"db vmwp+{native_return:x} L8"
    )
    native_line = cdb.wait(f"{prefix}_NATIVE_RESULT", 10)
    if parse_address(native_line, "rax") != 1:
        raise GateFailure(f"{label} native completion failed: {native_line}")
    if next_marker:
        cdb.send(
            f'bp vmwp+{event_held:x} ".if (poi(@r14+8)=={context:016x}) {{ .echo {next_marker}; '
            'r rcx; r r14; dd @r14 L20; db @r14+148 L1 } .else { gc }"\n'
            "g"
        )
    else:
        cdb.send("bl\n.detach /h\nq")
        output = cdb.finish()
        if "85 c0 0f 84 d8 00 00 00" not in output:
            raise GateFailure("final detach did not verify restored native-return bytes")
    if pause_request is not None:
        finish_pause_request(pause_request)
    if next_marker:
        cdb.wait(next_marker, 30)
    return {"native_return": 1, "cdb_detached": next_marker is None}


def cleanup_handler(pid: int, vnd: int, context: int, run: str) -> dict[str, Any]:
    # The unregister return also lands in host ntdll; retain the bytes observed
    # for every breakpoint so cleanup proves restoration across host builds.
    unregister = profile_rva("unregister_handler_rva")
    deferred_cleanup = profile_rva("deferred_cleanup")
    commands = f'''sxd 6ba
sxd e06d7363
dq 0000020000000100 L2
dq 0000020000000200 L8
~* f
~# u
r @$t0=poi(@rsp)
r @$t1=@$t0
r @$t3=poi(@$t0)
bp @$t0
r rcx={vnd:016x}
r rdx={context:016x}
r rip=vmwp+{unregister:x}
g
.printf "K4AUTO_UNREGISTER_RESULT rax=%p\\n", @rax
bc *
.if (poi(@$t1)==@$t3) {{ .echo K4AUTO_UNREGISTER_BREAKPOINT_RESTORED }} .else {{ .echo K4AUTO_UNREGISTER_BREAKPOINT_MISMATCH; r @$t3; db @$t1 L8 }}
r @$t4=poi(vmwp+{deferred_cleanup:x})
bp vmwp+{deferred_cleanup:x} ".if (@rcx == {context:016x}) {{ .echo K4AUTO_DEFERRED_CLEANUP_HIT; dq @rcx+70 L8; dq poi(@rcx+80) L8 }} .else {{ gc }}"
~* u
g
r @$t2=poi(@rsp)
bc *
.if (poi(vmwp+{deferred_cleanup:x})==@$t4) {{ .echo K4AUTO_CLEANUP_ENTRY_BREAKPOINT_RESTORED }} .else {{ .echo K4AUTO_CLEANUP_ENTRY_BREAKPOINT_MISMATCH; r @$t4; db vmwp+{deferred_cleanup:x} L8 }}
r @$t5=poi(@$t2)
bp @$t2
g
.echo K4AUTO_DEFERRED_CLEANUP_RETURN
bc *
.if (poi(@$t2)==@$t5) {{ .echo K4AUTO_CLEANUP_RETURN_BREAKPOINT_RESTORED }} .else {{ .echo K4AUTO_CLEANUP_RETURN_BREAKPOINT_MISMATCH; r @$t5; db @$t2 L8 }}
.detach /h
q
'''
    cdb = CdbSession(pid, f"k4-auto-{run}-cleanup", commands)
    unregister = cdb.wait("K4AUTO_UNREGISTER_RESULT", 30)
    cdb.wait("K4AUTO_DEFERRED_CLEANUP_HIT", 30)
    cdb.wait("K4AUTO_DEFERRED_CLEANUP_RETURN", 30)
    output = cdb.finish()
    if parse_address(unregister, "rax") != 1:
        raise GateFailure(f"handler unregister failed: {unregister}")
    for marker, label in (
        ("K4AUTO_UNREGISTER_BREAKPOINT_RESTORED", "handler unregister return"),
        ("K4AUTO_CLEANUP_ENTRY_BREAKPOINT_RESTORED", "deferred cleanup entry"),
        ("K4AUTO_CLEANUP_RETURN_BREAKPOINT_RESTORED", "deferred cleanup return"),
    ):
        require_breakpoint_restored(output, marker, label)
    time.sleep(5)
    free_commands = f'''sxd 6ba
sxd e06d7363
.printf "K4AUTO_OLD_CALLBACK_FIELDS callback=%p flags=%p\\n", poi({context + 0x80:016x}), poi({context + 0x88:016x})
dq 0000020000000000 L8
.dvfree 0000020000000000 0
.echo K4AUTO_SCRATCH_FREED
dq 0000020000000000 L2
bl
.detach /h
q
'''
    free = CdbSession(pid, f"k4-auto-{run}-free", free_commands)
    stale = free.wait("K4AUTO_OLD_CALLBACK_FIELDS", 30)
    free.wait("K4AUTO_SCRATCH_FREED", 30)
    free_output = free.finish()
    if "????????`????????" not in free_output:
        raise GateFailure("callback allocation was not verified inaccessible after free")
    return {
        "unregister_return": 1,
        "deferred_cleanup_hit": True,
        "deferred_cleanup_returned": True,
        "old_callback_line": stale,
        "scratch_freed": True,
    }


def health(pid: int, label: str) -> dict[str, Any]:
    vm = vm_json()
    current_pid = vmwp_pid()
    if current_pid != pid:
        raise GateFailure(f"vmwp PID changed from {pid} to {current_pid}")
    raw = ps(
        f"$pidHex='{pid:X}'; $started=(Get-Process -Id {pid} -ErrorAction Stop).StartTime; "
        "$e=Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$started;Level=2} "
        "-ErrorAction SilentlyContinue | Where-Object {$_.ProviderName -in @('Application Error','Windows Error Reporting') "
        "-and $_.Message -match 'vmwp.exe' -and $_.Message -match "
        "('(?im)^Faulting process id:\\s*0x' + $pidHex + '\\s*$')}; @($e).Count"
    )
    errors = int(raw or "0")
    if errors:
        raise GateFailure(f"{errors} recent vmwp crash records")
    if vm["State"] != "Running" or vm.get("Heartbeat") != "OK":
        raise GateFailure(f"unhealthy VM at {label}: {vm}")
    return {
        "label": label,
        "pid": current_pid,
        "uptime_seconds": float(vm["UptimeSeconds"]),
        "heartbeat": vm["Heartbeat"],
        "status": vm["Status"],
        "recent_vmwp_errors": errors,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default="run1")
    args = ap.parse_args()
    run = re.sub(r"[^a-zA-Z0-9_-]", "_", args.run)
    result_path = HERE / f"k4-auto-{run}-result.json"
    result: dict[str, Any] = {
        "schema": "windbg-mcp.private.k4-automated-stop-step.v1",
        "run": run,
        "vm_name": VM_NAME,
        "vm_id": VM_ID,
        "result": "running",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    handler: CdbSession | None = None
    control: ControlClient | None = None
    original: dict[str, Any] | None = None
    pid: int | None = None
    vnd: int | None = None
    partition: int | None = None
    context: int | None = None
    state_mutated = False
    handler_registered = False
    event_held = False
    release_in_progress = False
    cleanup_in_progress = False
    handler_continuing = False
    try:
        guards = {
            "vmwp.exe": sha256(pathlib.Path(r"C:\Windows\System32\vmwp.exe")),
            "vid.dll": sha256(pathlib.Path(r"C:\Windows\System32\vid.dll")),
            "Vid.sys": sha256(pathlib.Path(r"C:\Windows\System32\drivers\Vid.sys")),
            "securekernel.exe": sha256(IMAGE),
        }
        expected = {
            "vmwp.exe": VMWP_SHA256,
            "vid.dll": VID_DLL_SHA256,
            "Vid.sys": VID_SYS_SHA256,
            "securekernel.exe": IMAGE_SHA256,
        }
        if guards != expected:
            raise GateFailure(f"binary identity mismatch: observed={guards}, expected={expected}")
        result["binary_sha256"] = guards

        pid, boot_uptime = start_bench()
        result["vmwp_pid"] = pid
        result["boot_uptime_seconds"] = boot_uptime
        vnd, source_handle, partition = discover_identity(pid, run)
        result["identity"] = {
            "dispatcher_vnd": f"0x{vnd:016x}",
            "source_vid_handle": f"0x{source_handle:x}",
            "partition_id": f"0x{partition:x}",
        }

        pause_vm()
        target_record = live_target(
            partition, HERE / f"k4-auto-{run}-target-before.json"
        )
        target = int(target_record["target_va"], 0)
        result["target"] = target_record

        control = ControlClient(partition)
        control.begin_arm()
        original = register_snapshot(
            control, HERE / f"k4-auto-{run}-original-state.json"
        )
        roundtrip = roundtrip_debug(control, run)
        if roundtrip["before"]["registers"] != roundtrip["after"]["registers"]:
            raise GateFailure("debug-register round trip changed VTL1 state")
        result["debug_roundtrip"] = True

        handler = CdbSession(pid, f"k4-auto-{run}-handler", handler_commands(vnd))
        handler.wait("K4AUTO_VECTOR1_REGISTER_RETURN", 30)
        register_return = handler.wait("rax=", 10)
        if parse_address(register_return, "rax") != 0:
            raise GateFailure(f"vector-1 handler registration failed: {register_return}")
        handler.wait("K4AUTO_VECTOR1_REGISTERED", 10)
        context_line = handler.wait("$t5=", 10)
        context = parse_address(context_line, "$t5")
        handler_registered = True
        result["handler_context"] = f"0x{context:016x}"

        regs = original["registers"]
        original_dr7 = low_value(regs["dr7"])
        original_dr6 = low_value(regs["dr6"])
        original_flags = low_value(regs["rflags"])
        if original_dr7 & 0xFF:
            raise GateFailure(f"guest already has active debug breakpoints: DR7=0x{original_dr7:X}")
        state_mutated = True
        write_sequence(
            control,
            (
                ("dr7", original_dr7 & ~0xFF),
                ("dr0", target),
                ("dr6", original_dr6 & ~0xE00F),
                ("rip", target),
                ("rflags", original_flags & ~(0x100 | 0x10000)),
                ("dr7", 0x401),
            ),
            HERE / f"k4-auto-{run}-hardware-arm.json",
        )
        control.finish_arm()
        control.close()
        control = None
        handler.send(".echo K4AUTO_HANDLER_ARMED")
        handler.wait("K4AUTO_HANDLER_ARMED", 30)
        handler_continuing = True
        handler.send("g")
        time.sleep(0.5)
        resume_vm()
        handler.wait("K4AUTO_HARDWARE_EVENT_HELD", 30)
        handler_continuing = False
        event_held = True
        control = ControlClient(partition)
        result["hardware_event"] = control.publish_stop(
            context, {"reason": "hardware_breakpoint", "slot": 0}
        )
        hw1 = register_snapshot(control, HERE / f"k4-auto-{run}-hardware-stop-1.json")
        time.sleep(0.3)
        hw2 = register_snapshot(control, HERE / f"k4-auto-{run}-hardware-stop-2.json")
        if hw1["registers"] != hw2["registers"]:
            raise GateFailure("hardware stop state changed during hold")
        hw_regs = hw1["registers"]
        if low_value(hw_regs["rip"]) != target or not (low_value(hw_regs["dr6"]) & 1):
            raise GateFailure(f"hardware stop was not DR0 at target: {hw_regs}")
        result["hardware_stop"] = {
            "rip": hw_regs["rip"]["low"],
            "dr6": hw_regs["dr6"]["low"],
            "dr7": hw_regs["dr7"]["low"],
            "two_reads_agree": True,
        }

        current_dr6 = low_value(hw_regs["dr6"])
        current_flags = low_value(hw_regs["rflags"])
        write_sequence(
            control,
            (
                ("dr7", original_dr7 & ~0xFF),
                ("dr0", low_value(regs["dr0"])),
                ("dr6", current_dr6 & ~0xE00F),
                ("rip", target),
                ("rflags", (current_flags | 0x100) & ~0x10000),
            ),
            HERE / f"k4-auto-{run}-step-arm.json",
        )
        control.release()
        control.close()
        control = None
        release_in_progress = True
        release_event(handler, "HARDWARE", context, "K4AUTO_SINGLE_STEP_EVENT_HELD")
        release_in_progress = False
        control = ControlClient(partition)
        result["single_step_event"] = control.publish_stop(
            context, {"reason": "single_step"}
        )

        step1 = register_snapshot(control, HERE / f"k4-auto-{run}-step-stop-1.json")
        time.sleep(0.3)
        step2 = register_snapshot(control, HERE / f"k4-auto-{run}-step-stop-2.json")
        if step1["registers"] != step2["registers"]:
            raise GateFailure("single-step state changed during hold")
        step_regs = step1["registers"]
        expected_next = target + len(TARGET_BYTES)
        if low_value(step_regs["rip"]) != expected_next or not (low_value(step_regs["dr6"]) & (1 << 14)):
            raise GateFailure(f"single step did not stop at decoded successor: {step_regs}")
        result["single_step"] = {
            "rip": step_regs["rip"]["low"],
            "expected_rip": f"0x{expected_next:016x}",
            "dr6": step_regs["dr6"]["low"],
            "two_reads_agree": True,
        }

        original_values = {name: low_value(regs[name]) for name in SNAPSHOT_NAMES}
        restore = write_sequence(
            control,
            (
                ("dr7", original_values["dr7"] & ~0xFF),
                ("rflags", original_values["rflags"]),
                ("rip", original_values["rip"]),
                ("dr0", original_values["dr0"]),
                ("dr1", original_values["dr1"]),
                ("dr2", original_values["dr2"]),
                ("dr3", original_values["dr3"]),
                ("dr6", original_values["dr6"]),
                ("dr7", original_values["dr7"]),
            ),
            HERE / f"k4-auto-{run}-restore.json",
        )
        for name in ("rip", "rsp", "rflags", "cr3", "dr0", "dr1", "dr2", "dr3", "dr6", "dr7"):
            if restore["after"]["registers"][name] != original["registers"][name]:
                raise GateFailure(f"restore mismatch for {name}")
        state_mutated = False
        control.release()
        control.close()
        control = None
        release_in_progress = True
        final_release = release_event(handler, "STEP", context, None)
        release_in_progress = False
        event_held = False
        if final_release.get("cdb_detached") is not True:
            raise GateFailure("final release did not detach the event controller")
        if "49 8b 5e 08 48 8b 43 78" not in "".join(handler.all_lines):
            raise GateFailure("handler detach did not verify the restored dispatcher bytes")
        handler = None

        cleanup_in_progress = True
        result["handler_cleanup"] = cleanup_handler(pid, vnd, context, run)
        cleanup_in_progress = False
        handler_registered = False
        immediate = health(pid, "immediate")
        time.sleep(30)
        after_30 = health(pid, "30s")
        time.sleep(30)
        after_60 = health(pid, "60s")
        result["survival"] = [immediate, after_30, after_60]

        pause_vm()
        control = ControlClient(partition)
        control.begin_arm()
        final_state = register_snapshot(
            control, HERE / f"k4-auto-{run}-final-state.json"
        )
        for name in ("rflags", "dr0", "dr1", "dr2", "dr3", "dr6", "dr7"):
            if final_state["registers"][name] != original["registers"][name]:
                raise GateFailure(f"final debug-state audit mismatch for {name}")
        control.finish_arm()
        control.close()
        control = None
        final_target = live_target(partition, HERE / f"k4-auto-{run}-target-after.json")
        result["final_audit"] = {
            "debug_state_baseline": True,
            "target_text_unchanged": final_target["valid"],
        }
        result["bench_cleanup"] = stop_bench()
        result["result"] = "pass"
        result["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        save_json(result_path, result)
        print(json.dumps(result, indent=2))
        return 0
    except Exception as error:
        result["result"] = "fail"
        result["error"] = str(error)
        result["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        save_json(result_path, result)
        if control is not None:
            closing = control
            control = None
            try:
                closing.close()
            except Exception as control_error:
                result["control_close_error"] = str(control_error)
                save_json(result_path, result)
        if (
            handler_continuing
            and handler is not None
            and not event_held
            and not release_in_progress
        ):
            try:
                if vm_state() == "Paused":
                    resume_vm()
                handler.wait("K4AUTO_HARDWARE_EVENT_HELD", 30)
                handler_continuing = False
                event_held = True
                result["recovery_hardware_event_held"] = True
                save_json(result_path, result)
            except Exception as event_error:
                result["recovery_event_wait_error"] = str(event_error)
                save_json(result_path, result)
        if (
            handler is not None
            and not release_in_progress
            and not event_held
            and not handler_continuing
        ):
            try:
                handler.detach()
                handler = None
            except Exception as detach_error:
                result["detach_before_pause_error"] = str(detach_error)
                save_json(result_path, result)
        recovery_stable = event_held or fail_closed_pause()
        if original is not None and state_mutated and recovery_stable:
            try:
                if partition is None:
                    raise GateFailure("partition identity unavailable for recovery restore")
                control = ControlClient(partition)
                if control.phase == "running":
                    control.begin_arm()
                regs = original["registers"]
                values = {name: low_value(regs[name]) for name in SNAPSHOT_NAMES}
                write_sequence(
                    control,
                    (
                        ("dr7", values["dr7"] & ~0xFF),
                        ("rflags", values["rflags"]),
                        ("rip", values["rip"]),
                        ("dr0", values["dr0"]),
                        ("dr1", values["dr1"]),
                        ("dr2", values["dr2"]),
                        ("dr3", values["dr3"]),
                        ("dr6", values["dr6"]),
                        ("dr7", values["dr7"]),
                    ),
                    HERE / f"k4-auto-{run}-failure-restore.json",
                )
                state_mutated = False
                if control.phase == "arming":
                    control.finish_arm()
            except Exception as restore_error:
                result["restore_error"] = str(restore_error)
                save_json(result_path, result)
            finally:
                if control is not None:
                    closing = control
                    control = None
                    try:
                        closing.close()
                    except Exception as control_error:
                        result["recovery_control_close_error"] = str(control_error)
                        save_json(result_path, result)
        if (
            event_held
            and not release_in_progress
            and handler is not None
            and context is not None
        ):
            try:
                release_event(handler, "RECOVERY", context, None)
                event_held = False
                handler_continuing = False
                if control is not None and control.phase == "stopped":
                    control.release()
                result["recovery_event_released"] = True
            except Exception as release_error:
                result["recovery_release_error"] = str(release_error)
                save_json(result_path, result)
        if (
            handler is not None
            and not release_in_progress
            and not event_held
            and not handler_continuing
        ):
            try:
                handler.detach()
                handler = None
            except Exception as detach_error:
                result["detach_error"] = str(detach_error)
                save_json(result_path, result)
        if (
            handler_registered
            and not cleanup_in_progress
            and handler is None
            and context is not None
            and pid is not None
            and vnd is not None
        ):
            try:
                result["recovery_handler_cleanup"] = cleanup_handler(
                    pid, vnd, context, f"{run}-recovery"
                )
                handler_registered = False
            except Exception as cleanup_error:
                result["recovery_cleanup_error"] = str(cleanup_error)
                save_json(result_path, result)
        fail_closed_pause()
        try:
            result["failure_final_vm"] = vm_json()
        except Exception as final_state_error:
            result["failure_final_vm_error"] = str(final_state_error)
        save_json(result_path, result)
        print(json.dumps(result, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
