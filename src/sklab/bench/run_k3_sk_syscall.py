"""Break a VTL1 **user-mode trustlet** entering the Secure Kernel, read its protected memory, resume.

This is the test the whole exercise is for, and it differs from `run_k3_sk_live.py` in one way that
matters: the stop is a **transition**. A trustlet executes `syscall`, the CPU raises to CPL0 inside
VTL1, and the breakpoint fires on the Secure Kernel's first instruction *before anything has been
switched* -- so at the stop the trustlet's address space and the trustlet's stack are both still
live. That is what makes the evidence irrefutable rather than circumstantial:

  * `rip` is the Secure Kernel's own syscall entry, at `sk_base + rva` computed from the pinned
    build, and `dr0`/`dr1` read back from the VP hold that address with `dr7` enabling the slot.
  * the event says `vtl 1, cpl 0` -- VTL1 **kernel** mode.
  * `cr3` is **not** the root this session discovered for the idle Secure Kernel. It is the
    caller's. That is the transition, and the policy must admit it (see below).
  * `rsp` is a canonical **user** address, because `syscall` does not switch stacks and the Secure
    Kernel has not yet done so by hand. A kernel-mode stop whose stack pointer is a user address
    can only have come from user mode.
  * reading at that `rsp` reads the trustlet's own stack -- VTL1 user memory that VTL0 cannot see.

Both syscall entries are armed, because which one executes depends on whether KVA shadowing is on
in VTL1 and that is not something to guess. Disassembled from the pinned image 2026-10-10:

    KiSystemCall64        rva 0xeeec0  swapgs ...  and NO cr3 write in 14 instructions
    KiSystemCall64Shadow  rva 0xf7240  swapgs ...  `mov cr3,rsp` at 0xf7255, the 4th instruction

Ordinary single steps must retain the address-space root. The shadow path's fourth instruction is
the deliberate exception: `sk_live_step` must classify `mov cr3,rsp` as `step_over`, bind the new
root named by that reason, and continue from its linear successor. The cap is applied from
whichever entry actually fired, not chosen in advance.

Stepping the non-shadow prologue is also worth doing for its own sake: it *builds* a user trap
frame -- `push 2Bh` (user SS), the saved user RSP, `push r11` (user RFLAGS), `push 33h` (user CS),
`push rcx` (user return RIP) -- so after eight steps the Secure Kernel's own code has written the
proof of user origin onto its stack, where it can be read back.

    uv run sklab --target <name> run live.transition --set steps=8 --yes

sklab writes the run's policy and sets `WINDBG_MCP_SK_LIVE_POLICY` and `WINDBG_MCP_TRANSCRIPT`
(`bench_bridge.runner_environment`). The policy must admit the control transport **with**
`--allow-transition-cr3`; without it `k4_control_provider.py` refuses any stop whose CR3 differs
from the baseline, which is every transition stop there is.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import pathlib
import struct
import sys
import time
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run_k4_stop_step as k4  # noqa: E402
import run_vtl1_user_to_securekernel as exp  # noqa: E402
from h3_vtl1_debug_control import REGISTERS, Probe, low_value, snapshot  # noqa: E402
from guest_physical import (  # noqa: E402
    GuestVirtual,
    H3Source,
    find_secure_kernel_base,
    vtl1_identity,
)
from inject_provider_death_mcp import Mcp  # noqa: E402
from guest_credentials import powershell_credential  # noqa: E402

VM_NAME = "windbg-mcp K3 Managed VTL1"
VM_ID = "6b1ed0f6-137e-469f-aeab-a3f4cfee398d"
PROFILE = HERE / "vmwp-dispatcher-profile.json"
IMAGE = HERE / "guest-positive-securekernel.exe"
RUN_ROOT = HERE / "k3-sk-syscall"
DISCOVERY_CACHE = RUN_ROOT / "discovery-cache.json"

# Both Secure Kernel syscall entries, with the step budget each one allows. The shadow entry's
# fourth instruction is `mov cr3,rsp`; item 123 makes that a bounded hardware step-over rather
# than a reason to truncate the walk.
ENTRIES = (
    # The exception path, and the one this bench can actually drive. `spin_host.exe BP1 <n>` raises
    # `#BP` inside the enclave in VTL1 user mode, which enters the Secure Kernel here — the same
    # entry the 2026-10-04 LsaIso run armed, reached by a trustlet we can start on demand instead
    # of one that needs a Credential Guard licence. `kind` selects how user origin is proved: an
    # exception entry has already switched to the kernel stack and pushed a trap frame, so the
    # caller's CS and SS are read back out of memory at RSP.
    {
        "symbol": "KiBreakpointTrap",
        "rva": 0xEB380,
        "bytes": "4883ec08",
        "slot": 0,
        "max_steps": 13,
        "kind": "exception",
    },
    # The syscall path. Kept armed because it costs a slot and nothing else, but note the spin
    # enclave makes **no syscalls at all** — `Spin` is a pure arithmetic loop and vertdll is a
    # restricted surface — so this fires only if some other trustlet calls a secure service.
    {
        "symbol": "KiSystemCall64",
        "rva": 0xEEEC0,
        "bytes": "0f01f8",
        "slot": 1,
        "max_steps": 13,
        "kind": "syscall",
    },
    {
        "symbol": "KiSystemCall64Shadow",
        "rva": 0xF7240,
        "bytes": "0f01f8",
        "slot": 2,
        "max_steps": 13,
        "kind": "syscall",
    },
)

# The in-guest VTL1 workload. `spin_host.exe` is staged at this path and loads a test-signed
# enclave, so the guest needs `testsigning on` — enabling Secure Boot clears it and
# `LoadEnclaveImage` then fails 577. Verified working 2026-10-10 after restoring it.
SPIN_HOST = r"C:\encl\spin_host.exe"

# A canonical user-mode address has bits 63..47 clear. Kernel addresses are the sign-extended half.
USER_ADDRESS_LIMIT = 0x0000_8000_0000_0000
LSTAR_REGISTER = 0x00080009

PYTHON = sys.executable
# The transition-permitting template. It must match `sk-live-policy.json` word for word.
CONTROL_TRANSPORT = (
    f'"{PYTHON}" "{HERE / "k4_control_provider.py"}" '
    f"--vm-id {VM_ID} --partition-id {{partition_id}} --allow-transition-cr3"
)
LIVE_TRANSPORT = (
    f'"{PYTHON}" "{HERE / "gpa_server.py"}" '
    "--vmwp-pid {vmwp_pid} --partition-handle {partition_handle} "
    f'--partition-id {{partition_id}} --vp {{vp}} --image "{IMAGE}" --writes'
)


def signed64(value: int) -> int:
    """
    A register difference as a signed 64-bit quantity.

    `mov rsp, gs:[1070h]` switches from the trustlet's user stack to the Secure Kernel's, so the
    delta is a large negative number; subtracting unsigned reported it as 18446664688968830728,
    which reads as a 16-exabyte push rather than a stack switch.
    """
    value &= (1 << 64) - 1
    return value - (1 << 64) if value >= 1 << 63 else value


def module_loaded(name: str) -> bool:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetModuleHandleW.restype = ctypes.c_void_p
    kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    return bool(kernel32.GetModuleHandleW(name))


def save(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def vm_state() -> str:
    return k4.ps(f"(Get-VM -Id '{VM_ID}' -ErrorAction Stop).State.ToString()")


def discovery(pid: int) -> tuple[int, int, int, str]:
    """Per-boot; cached on the vmwp pid so a boot is attached to and hijacked once."""
    if DISCOVERY_CACHE.is_file():
        try:
            data = json.loads(DISCOVERY_CACHE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        if (
            data.get("vm_id") == VM_ID
            and data.get("vmwp_pid") == pid
            and int(str(data.get("partition_handle", "0")), 0) != 0
        ):
            return (
                int(str(data["dispatcher_vnd"]), 0),
                int(str(data["partition_handle"]), 0),
                int(str(data["partition_id"]), 0),
                "reused from this boot's cache; nothing was attached to vmwp",
            )
    vnd, handle, partition = k4.discover_identity(pid, "k3-sk-syscall")
    save(
        DISCOVERY_CACHE,
        {
            "vm_id": VM_ID,
            "vmwp_pid": pid,
            "dispatcher_vnd": f"0x{vnd:016x}",
            "partition_handle": f"0x{handle:x}",
            "partition_id": f"0x{partition:x}",
        },
    )
    return vnd, handle, partition, "fresh; windbg-mcp discovery attached to vmwp"


def guest(script: str, timeout: float = 60) -> str:
    """PowerShell Direct into the configured disposable guest over VMBus."""
    return k4.ps(
        powershell_credential()
        + f"Invoke-Command -VMName '{VM_NAME}' -Credential $c -ScriptBlock {{ {script} }}",
        timeout=timeout,
    )


def start_vtl1_workload(delay: int, seconds: int, rounds: int) -> str:
    """
    Start a detached loop in the guest that keeps raising `#BP` inside the enclave, in VTL1.

    This is a **workload**, not a trigger for one event, and the distinction is what makes it
    usable here. The Secure Kernel is not continuously executing on an HVCI-only guest -- four
    ambient interrupt entries armed at once produced no stop in 60s -- so something has to be
    running in VTL1 for a breakpoint there to be reached at all. An enclave raising `#BP` in a loop
    both keeps VTL1 executing and crosses into the Secure Kernel on every exception, so it does not
    run out the way a per-image HVCI validation does.

    Detached, and timed in **guest** seconds, for the same two reasons the HVCI trigger taught:
    the guest is unreachable between `sk_live_arm` and `sk_live_wait` because the dispatcher pauses
    the whole VM, and a host-side clock would burn down during that pause while a guest-side one
    stops with it. A synchronous call would deadlock against the stop it causes.
    """
    # Pinned to CPU 0, because **debug registers are per-VP** and the session arms VP 0 only. K3 has
    # two virtual processors, so an unpinned enclave thread can raise every one of its `#BP`s on
    # VP 1 where nothing is armed — which looks exactly like a target that never crossed. Affinity
    # is inherited by child processes, so pinning the loop's own process pins every `spin_host` it
    # starts. Bit 0 of the mask is CPU 0.
    # The delay is **required**, and not for the reason a delay is usually needed here. Opening and
    # arming the session needs VTL1 *quiet*: `allow_transition_cr3`'s own documentation says "the
    # initial paused baseline and live-memory source must still match `expected_cr3` exactly", and
    # with the enclave already raising `#BP` the register provider and the live-memory provider
    # sample the VP's CR3 at different instants and disagree. Measured 2026-10-10 as
    # `live-memory source CR3 Some(...) does not match the bound CR3 0xab0000` at `sk_live_arm`.
    # So the workload must begin *after* the arm — and since the guest is unreachable from then
    # until `sk_live_wait`, the wait has to be built into the guest. It is in **guest** seconds, so
    # the dispatcher's pause of the whole VM during the arm does not consume it.
    #
    # The transition this session exists to catch is permitted at a *stop*, not while establishing
    # the session; quiet-then-busy is the only ordering that satisfies both.
    inner = (
        "$p=[Diagnostics.Process]::GetCurrentProcess(); $p.ProcessorAffinity=1; "
        f"Start-Sleep -Seconds {delay}; "
        f"$end=(Get-Date).AddSeconds({seconds}); "
        f"while((Get-Date) -lt $end){{ & {SPIN_HOST} BP1 {rounds} | Out-Null }}"
    )
    return guest(
        "Start-Process powershell -WindowStyle Hidden -ArgumentList "
        f"'-NoProfile','-NonInteractive','-Command','{inner}'; 'started'",
        timeout=60,
    )


def stop_vtl1_workload() -> str:
    """
    Stop the detached enclave loop, however the run ended.

    Not optional housekeeping: the loop outlives a failed run by design (it is timed in guest
    seconds, not tied to this process), and a loop still raising `#BP` makes the *next* run's
    `sk_live_arm` fail with a CR3 disagreement between its two providers — which is exactly how
    2026-10-10's first attempt at this harness was poisoned by its own previous attempt. The
    detached loop pinned itself to CPU 0, so affinity 1 distinguishes it from the remoting host.
    """
    # **The parent first, then the children, then verify.** Killing `spin_host` first leaves the
    # loop alive to start another one within ~26ms, which is how a previous teardown reported
    # "stopped 1 remaining" and left a straggler able to poison the next run's arm. The loop is the
    # PowerShell pinned to CPU 0; the remoting host is unpinned, so affinity 1 separates them.
    return guest(
        "Get-Process powershell -ErrorAction SilentlyContinue | "
        "Where-Object { [int]$_.ProcessorAffinity -eq 1 } | "
        "Stop-Process -Force -ErrorAction SilentlyContinue; "
        "for ($i = 0; $i -lt 10; $i++) { "
        "  $left = @(Get-Process spin_host -ErrorAction SilentlyContinue); "
        "  if ($left.Count -eq 0) { break }; "
        "  $left | Stop-Process -Force -ErrorAction SilentlyContinue; "
        "  Start-Sleep -Milliseconds 200 }; "
        "$loops = @(Get-Process powershell -ErrorAction SilentlyContinue | "
        "  Where-Object { [int]$_.ProcessorAffinity -eq 1 }).Count; "
        "$hosts = @(Get-Process spin_host -ErrorAction SilentlyContinue).Count; "
        "if ($loops -eq 0 -and $hosts -eq 0) { 'stopped clean' } "
        "else { 'STILL RUNNING loops=' + $loops + ' spin_host=' + $hosts }",
        timeout=60,
    )


def raw_command(client: Mcp, session_id: str, command: str) -> str:
    """`execute` returns debugger text and no `structuredContent`, so `exp.ok` would reject it."""
    response = client.tool("execute", {"session_id": session_id, "command": command}, 90)
    if response.get("error") is not None:
        raise k4.GateFailure(f"{command!r} failed: {response}")
    result = response.get("result") or {}
    if result.get("isError"):
        raise k4.GateFailure(f"{command!r} reported an error: {response}")
    return "".join(b.get("text", "") for b in (result.get("content") or []) if isinstance(b, dict))


def step_plans(
    count: int, entries: tuple[dict[str, Any], ...]
) -> dict[int, list[dict[str, Any]]]:
    """
    Disassemble both entries' prologues, keyed by RVA, in a server of their own.

    **Deliberately a separate server with the transcript suppressed.** The plan needs a
    disassembler and this server has one, but opening the image as a target puts a second session
    in the recording — reported as `kind: crash dump` with DbgEng's placeholder
    "Windows XP Version 2600" banner, because a bare PE carries no OS version. In a recording of a
    live Secure Kernel run that reads as though the whole thing were a dump. The transcript should
    hold the live session and nothing else, so this spawns its own server with
    `WINDBG_MCP_TRANSCRIPT` removed from the environment it inherits.
    """
    saved = {
        name: os.environ.pop(name)
        for name in ("WINDBG_MCP_TRANSCRIPT", "WINDBG_MCP_TRANSCRIPT_MAX_FIELD")
        if name in os.environ
    }
    try:
        client = Mcp(("--tools", "all"))
    finally:
        os.environ.update(saved)
    try:
        client.request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "k3-sk-syscall-plan", "version": "1"},
            },
            15,
        )
        client.notify("notifications/initialized", {})
        opened = exp.ok(client.tool("open_dump", {"path": str(IMAGE)}, 90), "open_dump of the image")
        sid = str(opened["session_id"])
        base = int(str(opened["summary"]["primary_module"]["start"]), 0)
        raw_command(client, sid, ".reload /f")
        plans: dict[int, list[dict[str, Any]]] = {}
        for entry in entries:
            want = min(count, entry["max_steps"]) + 1
            dis = exp.ok(
                client.tool(
                    "disassemble",
                    {"session_id": sid, "address": f"0x{base + entry['rva']:x}", "count": want},
                    90,
                ),
                f"disassemble {entry['symbol']}",
            )
            rows = [
                {
                    "rva": int(str(r["rva"]), 0),
                    "bytes": str(r["bytes"]).replace(" ", "").lower(),
                    "text": str(r["text"]),
                }
                for r in dis["instructions"]
            ]
            if not rows or rows[0]["rva"] != entry["rva"]:
                raise k4.GateFailure(f"{entry['symbol']}: disassembly did not start at its RVA")
            if rows[0]["bytes"] != entry["bytes"]:
                raise k4.GateFailure(
                    f"{entry['symbol']}: image bytes {rows[0]['bytes']} != guard {entry['bytes']}"
                )
            # Mark CR3 writes from the exact disassembly. The server derives this itself from the
            # guarded bytes; the marker is only the harness oracle for the returned stop reason.
            for row in rows[: min(count, entry["max_steps"])]:
                if "cr3" in row["text"].replace(" ", "").lower().split(",")[0]:
                    row["reason"] = "step_over"
                else:
                    row["reason"] = "single_step"
            plans[entry["rva"]] = rows
        exp.ok(client.tool("end_session", {"session_id": sid}, 60), "end_session")
        return plans
    finally:
        client.shutdown()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--steps", type=int, default=8)
    parser.add_argument("--stack-bytes", type=int, default=64)
    parser.add_argument(
        "--entry",
        choices=tuple(entry["symbol"] for entry in ENTRIES),
        help="arm only one entry; item 123 uses KiSystemCall64Shadow",
    )
    parser.add_argument(
        "--force-shadow-lstar",
        action="store_true",
        help="temporarily route VP0 VTL1 syscalls to KiSystemCall64Shadow; restore LSTAR on exit",
    )
    parser.add_argument(
        "--inject-shadow-cr3",
        action="store_true",
        help="at mov cr3,rsp, supply the discovered Secure Kernel root as the held RSP operand",
    )
    parser.add_argument(
        "--workload-seconds",
        type=int,
        default=150,
        help="guest seconds to keep raising #BP inside the enclave; must outlast the open, the "
        "arm and the ~60s sk_live_wait deadline, and only advances while the VM runs",
    )
    parser.add_argument(
        "--rounds", type=int, default=2000, help="#BP raises per spin_host invocation"
    )
    parser.add_argument(
        "--workload-delay",
        type=int,
        default=25,
        help="guest seconds to stay QUIET before raising anything, so the open and the arm see "
        "a stable VTL1 CR3; must be under the ~60s sk_live_wait deadline",
    )
    parser.add_argument(
        "--no-workload",
        action="store_true",
        help="arm without starting the enclave; use to show that nothing crosses on its own",
    )
    args = parser.parse_args()
    entries = tuple(entry for entry in ENTRIES if args.entry in (None, entry["symbol"]))
    if args.inject_shadow_cr3 and not args.force_shadow_lstar:
        parser.error("--inject-shadow-cr3 requires --force-shadow-lstar")

    state = vm_state()
    if state != "Running":
        raise k4.GateFailure(
            f"{VM_NAME} is {state}, not Running. "
            + ("Resume it (`Resume-VM`)." if state == "Paused" else "Start it; this prepares no VM.")
        )

    run_dir = RUN_ROOT / time.strftime("%Y%m%dT%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=False)
    manifest = run_dir / "manifest.json"
    record: dict[str, Any] = {
        "schema": "windbg-mcp.private.k3-sk-syscall.v1",
        "result": "running",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "vm_id": VM_ID,
        "vm_name": VM_NAME,
        "claim": "a VTL1 user-mode trustlet entered the Secure Kernel; we stopped on its first "
        "instruction, read the trustlet's own stack, and resumed",
        "entries_armed": [
            {k: (f"0x{v:x}" if k == "rva" else v) for k, v in e.items()} for e in entries
        ],
        "hvlib_loaded_before": module_loaded("hvlib.dll"),
    }
    if record["hvlib_loaded_before"]:
        raise k4.GateFailure("hvlib.dll was already loaded before transition preparation")
    save(manifest, record)

    client: Mcp | None = None
    session: str | None = None
    workload_running = False
    lstar_restore: tuple[int, int, int] | None = None
    try:
        plans = step_plans(args.steps, entries)
        record["step_plans"] = {f"0x{rva:x}": rows for rva, rows in plans.items()}
        save(manifest, record)

        pid = k4.vmwp_pid()
        vnd, source_handle, partition, how = discovery(pid)
        record["identity"] = {
            "vmwp_pid": pid,
            "dispatcher_vnd": f"0x{vnd:016x}",
            "partition_handle": f"0x{source_handle:x}",
            "partition_id": f"0x{partition:x}",
            "discovery": how,
        }

        source: H3Source | None = None
        k4.pause_vm()
        try:
            probe = Probe()
            try:
                baseline = snapshot(probe, partition, 0)
            finally:
                probe.close()
            registers = vtl1_identity(partition, 0)
            sampled_cr3 = low_value(baseline["registers"]["cr3"])
            if registers["cr3"] != sampled_cr3:
                raise k4.GateFailure(
                    f"paused VTL1 CR3 changed from 0x{sampled_cr3:x} to "
                    f"0x{registers['cr3']:x} during identity discovery"
                )
            source = H3Source(pid, source_handle, partition)
            guest = GuestVirtual(source, registers["cr3"])
            sk_base, base_evidence = find_secure_kernel_base(
                guest,
                registers["idtr_base"],
                registers["idtr_limit"],
                IMAGE,
            )
        finally:
            if source is not None:
                source.close()
            if vm_state() == "Paused":
                k4.resume_vm()
        record["baseline"] = baseline
        record["identity"]["cr3_when_sampled"] = f"0x{low_value(baseline['registers']['cr3']):x}"
        record["identity"]["secure_cr3"] = f"0x{registers['cr3']:x}"
        record["identity"]["idtr_base"] = f"0x{registers['idtr_base']:016x}"
        record["identity"]["idtr_limit"] = f"0x{registers['idtr_limit']:x}"
        record["identity"]["base_discovery"] = base_evidence
        record["identity"]["securekernel_base"] = f"0x{sk_base:016x}"
        for entry in record["entries_armed"]:
            entry["address"] = f"0x{sk_base + int(entry['rva'], 0):016x}"
        if args.force_shadow_lstar:
            shadow = next(
                (entry for entry in entries if entry["symbol"] == "KiSystemCall64Shadow"),
                None,
            )
            if shadow is None or len(entries) != 1:
                raise k4.GateFailure(
                    "--force-shadow-lstar requires --entry KiSystemCall64Shadow"
                )
            forced_lstar = sk_base + shadow["rva"]
            k4.pause_vm()
            probe = Probe()
            try:
                status, original_low, original_high = probe.get(
                    partition, 1, LSTAR_REGISTER, 0
                )
                if status != 0:
                    raise k4.GateFailure(
                        f"read VTL1 LSTAR failed with HV status 0x{status:04x}"
                    )
                lstar_restore = (partition, original_low, original_high)
                record["lstar"] = {
                    "original": f"0x{original_low:016x}",
                    "forced": f"0x{forced_lstar:016x}",
                    "restored": False,
                }
                status = probe.set(partition, 1, LSTAR_REGISTER, forced_lstar, 0, 0)
                if status != 0:
                    raise k4.GateFailure(
                        f"write VTL1 LSTAR failed with HV status 0x{status:04x}"
                    )
                status, readback, readback_high = probe.get(
                    partition, 1, LSTAR_REGISTER, 0
                )
                if status != 0 or readback != forced_lstar or readback_high != 0:
                    raise k4.GateFailure(
                        f"VTL1 LSTAR readback did not hold 0x{forced_lstar:x}"
                    )
            finally:
                probe.close()
                k4.resume_vm()
        save(manifest, record)

        # Started here: after discovery (which pauses and resumes the VM itself) and before the
        # session exists, since the guest cannot be reached once armed.
        if args.no_workload:
            record["workload"] = {"started": False, "why": "--no-workload"}
        else:
            record["workload"] = {
                "started": True,
                "command": f"{SPIN_HOST} BP1 {args.rounds}",
                "guest_seconds": args.workload_seconds,
                "quiet_delay_s": args.workload_delay,
                "reply": start_vtl1_workload(
                    args.workload_delay, args.workload_seconds, args.rounds
                ),
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            }
            workload_started = time.monotonic()
            workload_running = True
        save(manifest, record)

        client = Mcp(("--tools", "all"))
        initialized = client.request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "k3-sk-syscall", "version": "1"},
            },
            15,
        )
        if initialized.get("error") is not None:
            raise k4.GateFailure(f"initialize failed: {initialized}")
        client.notify("notifications/initialized", {})

        opened = exp.ok(
            client.tool(
                "open_sk_live_control",
                {
                    "profile": str(PROFILE),
                    "control_transport": CONTROL_TRANSPORT,
                    "live_transport": LIVE_TRANSPORT,
                    "vmwp_pid": pid,
                    "dispatcher_vnd": f"0x{vnd:016x}",
                    "vm_id": VM_ID,
                    "partition_id": f"0x{partition:x}",
                    "vp": 0,
                    # The whole point: a trustlet entry stops with the caller's root loaded.
                    "allow_transition_cr3": True,
                },
                30,
            ),
            "open_sk_live_control",
        )
        session = str(opened["session_id"])
        record["open"] = opened

        primary, *extra = entries
        record["arm"] = exp.ok(
            client.tool(
                "sk_live_arm",
                {
                    "session_id": session,
                    "address": f"0x{sk_base + primary['rva']:016x}",
                    "bytes": primary["bytes"],
                    "slot": primary["slot"],
                    "mode": "natural",
                    "additional_breakpoints": [
                        {
                            "slot": e["slot"],
                            "address": f"0x{sk_base + e['rva']:016x}",
                            "bytes": e["bytes"],
                        }
                        for e in extra
                    ],
                },
                90,
            ),
            "sk_live_arm",
        )
        armed_at = time.monotonic()
        if not args.no_workload:
            elapsed = armed_at - workload_started
            record["workload"]["armed_after_s"] = round(elapsed, 1)
            record["workload"]["quiet_headroom_s"] = round(args.workload_delay - elapsed, 1)
        save(manifest, record)

        stop = exp.ok(client.tool("sk_live_wait", {"session_id": session}, 120), "sk_live_wait")
        record["stop"] = stop
        record["stopped_after_arm_s"] = round(time.monotonic() - armed_at, 1)
        regs = exp.register_map(stop)

        fired = next((e for e in entries if sk_base + e["rva"] == regs["rip"]), None)
        if fired is None:
            raise k4.GateFailure(
                f"stopped at 0x{regs['rip']:x}, which is neither syscall entry "
                + ", ".join(f"0x{sk_base + e['rva']:x}" for e in entries)
            )
        settled_cr3 = int(str(stop["target"]["expected_cr3"]), 0)
        event = stop["event"]
        evidence = {
            "entry": fired["symbol"],
            "rva": f"0x{fired['rva']:x}",
            "rip": f"0x{regs['rip']:016x}",
            "vtl": event["vtl"],
            "cpl": event["cpl"],
            "reason": event["reason"],
            "dr0": f"0x{regs['dr0']:016x}",
            "dr1": f"0x{regs['dr1']:016x}",
            "dr7": f"0x{regs['dr7']:x}",
            "cr3_at_stop": f"0x{regs['cr3']:016x}",
            "cr3_secure_kernel": f"0x{settled_cr3:016x}",
            "cr3_transitioned": regs["cr3"] != settled_cr3,
            "rsp_at_stop": f"0x{regs['rsp']:016x}",
            "kind": fired["kind"],
        }
        record["evidence"] = evidence
        save(manifest, record)

        if event["vtl"] != 1 or event["cpl"] != 0:
            raise k4.GateFailure(f"the stop is not VTL1 kernel mode: {event}")
        if not evidence["cr3_transitioned"]:
            raise k4.GateFailure(
                f"cr3 0x{regs['cr3']:x} equals the Secure Kernel's own root, so this stop is not a "
                f"transition from another address space"
            )

        # The protected read, and what proves the caller was user mode. The two entry kinds put the
        # evidence in different places, so neither check is applied to the wrong one:
        #
        #   syscall   -- `syscall` does not switch stacks and the Secure Kernel has not yet done so
        #                by hand, so RSP is still the trustlet's own stack: a canonical *user*
        #                address at a CPL0 stop, which can only have come from user mode.
        #   exception -- the processor has already switched to the kernel stack and pushed a trap
        #                frame, so RSP points at `rip, cs, rflags, rsp, ss` and the caller's
        #                `cs=0x33`/`ss=0x2b` are read back out of it. This is the shape the
        #                2026-10-04 LsaIso run recorded.
        #
        # Either way the read goes through the trustlet's address space, which VTL0 cannot see.
        read_size = max(args.stack_bytes, 40)
        record["trustlet_stack"] = exp.ok(
            client.tool(
                "sk_live_read_memory",
                {"session_id": session, "address": f"0x{regs['rsp']:016x}", "size": read_size},
                60,
            ),
            "sk_live_read_memory at the stopped RSP",
        )
        raw = bytes.fromhex(str(record["trustlet_stack"]["data"]))
        if fired["kind"] == "syscall":
            evidence["rsp_is_user_address"] = regs["rsp"] < USER_ADDRESS_LIMIT
            if not evidence["rsp_is_user_address"]:
                raise k4.GateFailure(
                    f"rsp 0x{regs['rsp']:x} is not a canonical user address, so this syscall stop "
                    f"is not holding the caller's stack"
                )
        else:
            saved_rip, saved_cs, saved_flags, saved_rsp, saved_ss = struct.unpack_from("<5Q", raw)
            evidence["trap_frame"] = {
                "rip": f"0x{saved_rip:016x}",
                "cs": f"0x{saved_cs:x}",
                "rflags": f"0x{saved_flags:x}",
                "rsp": f"0x{saved_rsp:016x}",
                "ss": f"0x{saved_ss:x}",
            }
            evidence["frame_is_user_mode"] = saved_cs == 0x33 and saved_ss == 0x2B
            evidence["frame_rip_is_user"] = saved_rip < USER_ADDRESS_LIMIT
            if not evidence["frame_is_user_mode"]:
                raise k4.GateFailure(
                    f"the trap frame at rsp says cs=0x{saved_cs:x} ss=0x{saved_ss:x}, not the "
                    f"0x33/0x2b of VTL1 user mode, so this exception did not come from a trustlet"
                )
            if not evidence["frame_rip_is_user"]:
                raise k4.GateFailure(
                    f"the trap frame's saved rip 0x{saved_rip:x} is not a user address"
                )
        record["evidence"] = evidence
        record["registers"] = exp.ok(
            client.tool("sk_live_registers", {"session_id": session}, 60), "sk_live_registers"
        )
        save(manifest, record)

        plan = plans[fired["rva"]]
        budget = min(args.steps, fired["max_steps"])
        record["step_budget"] = {
            "requested": args.steps,
            "allowed_by_entry": fired["max_steps"],
            "used": budget,
            "why": "a CR3 write is a bounded hardware step-over; other instructions use TF",
        }
        steps: list[dict[str, Any]] = []
        held = stop
        stop_cr3 = regs["cr3"]
        for index in range(budget):
            entry = plan[index]
            before = exp.register_map(held)
            want = sk_base + entry["rva"]
            if before["rip"] != want:
                raise k4.GateFailure(
                    f"step {index}: at 0x{before['rip']:x} but the plan expects "
                    f"{entry['text']!r} at 0x{want:x}"
                )
            if entry["reason"] == "step_over" and args.inject_shadow_cr3:
                if settled_cr3 == stop_cr3:
                    raise k4.GateFailure(
                        "the injected step-over fixture needs distinct caller and Secure Kernel roots"
                    )
                probe = Probe()
                try:
                    rip_status, actual_rip, _ = probe.get(
                        partition, 1, REGISTERS["rip"], 0
                    )
                    cr3_status, actual_cr3, _ = probe.get(
                        partition, 1, REGISTERS["cr3"], 0
                    )
                    if rip_status != 0 or actual_rip != want:
                        raise k4.GateFailure(
                            f"held VP RIP is 0x{actual_rip:x}, expected 0x{want:x}"
                        )
                    if cr3_status != 0 or actual_cr3 != stop_cr3:
                        raise k4.GateFailure(
                            f"held VP CR3 is 0x{actual_cr3:x}, expected 0x{stop_cr3:x}"
                        )
                    status = probe.set(
                        partition, 1, REGISTERS["rsp"], settled_cr3, 0, 0
                    )
                    read_status, readback, readback_high = probe.get(
                        partition, 1, REGISTERS["rsp"], 0
                    )
                    if (
                        status != 0
                        or read_status != 0
                        or readback != settled_cr3
                        or readback_high != 0
                    ):
                        raise k4.GateFailure(
                            "the held VP did not retain the injected CR3 operand in RSP"
                        )
                    record["shadow_cr3_fixture"] = {
                        "source_rip": f"0x{want:016x}",
                        "old_cr3": f"0x{stop_cr3:016x}",
                        "rsp_operand": f"0x{settled_cr3:016x}",
                    }
                    save(manifest, record)
                finally:
                    probe.close()
            exp.ok(
                client.tool(
                    "sk_live_step",
                    {
                        "session_id": session,
                        "epoch": held["epoch"],
                        "address": f"0x{want:016x}",
                        "bytes": entry["bytes"],
                    },
                    90,
                ),
                f"sk_live_step {index}",
            )
            held = exp.ok(
                client.tool("sk_live_wait", {"session_id": session}, 120), f"step stop {index}"
            )
            after = exp.register_map(held)
            reason = held["event"]["reason"]
            if entry["reason"] == "step_over":
                if reason.get("reason") != "step_over":
                    raise k4.GateFailure(
                        f"step {index} returned {reason!r}, not a CR3 step-over"
                    )
                new_cr3 = int(str(reason["new_cr3"]), 0)
                if new_cr3 != after["cr3"] or new_cr3 == stop_cr3:
                    raise k4.GateFailure(
                        f"step {index} reported new CR3 0x{new_cr3:x}, retained "
                        f"0x{after['cr3']:x}, previous 0x{stop_cr3:x}"
                    )
                stop_cr3 = new_cr3
            else:
                if reason != {"reason": "single_step"}:
                    raise k4.GateFailure(
                        f"step {index} returned {reason!r}, not a single step"
                    )
                if after["cr3"] != stop_cr3:
                    raise k4.GateFailure(
                        f"step {index} moved the address-space root from 0x{stop_cr3:x} to "
                        f"0x{after['cr3']:x}"
                    )
            steps.append(
                {
                    "index": index,
                    "rva": f"0x{entry['rva']:x}",
                    "text": entry["text"],
                    "bytes": entry["bytes"],
                    "from": f"0x{before['rip']:016x}",
                    "rip": f"0x{after['rip']:016x}",
                    "rsp": f"0x{after['rsp']:016x}",
                    "rsp_delta": signed64(after["rsp"] - before["rsp"]),
                    "reason": reason,
                    "cr3": f"0x{after['cr3']:016x}",
                }
            )
            record["steps"] = steps
            save(manifest, record)

        # The Secure Kernel builds a user trap frame as it goes; once `push 33h` has run, its own
        # code has written the caller's CS onto the stack where it can be read back.
        tail = exp.register_map(held)
        record["frame_after_steps"] = exp.ok(
            client.tool(
                "sk_live_read_memory",
                {"session_id": session, "address": f"0x{tail['rsp']:016x}", "size": 48},
                60,
            ),
            "sk_live_read_memory of the built frame",
        )

        record["continue"] = exp.ok(
            client.tool("sk_live_continue", {"session_id": session, "epoch": held["epoch"]}, 90),
            "sk_live_continue",
        )
        record["end"] = exp.ok(
            client.tool("end_session", {"session_id": session}, 120), "end_session"
        )
        session = None
        record["hvlib_loaded_after"] = module_loaded("hvlib.dll")
        if record["hvlib_loaded_after"]:
            raise k4.GateFailure("hvlib.dll was loaded during the transition workflow")
        record["result"] = "pass"
        return 0
    finally:
        if client is not None:
            if session is not None:
                try:
                    record["end"] = exp.ok(
                        client.tool("end_session", {"session_id": session}, 120), "end_session"
                    )
                except Exception as error:  # noqa: BLE001
                    record["end_error"] = repr(error)
            client.shutdown()
        if lstar_restore is not None:
            partition, original_low, original_high = lstar_restore
            try:
                k4.pause_vm()
                probe = Probe()
                try:
                    status = probe.set(
                        partition,
                        1,
                        LSTAR_REGISTER,
                        original_low,
                        original_high,
                        0,
                    )
                    read_status, readback, readback_high = probe.get(
                        partition, 1, LSTAR_REGISTER, 0
                    )
                    if (
                        status != 0
                        or read_status != 0
                        or readback != original_low
                        or readback_high != original_high
                    ):
                        raise k4.GateFailure("VTL1 LSTAR restoration did not verify")
                    record["lstar"]["restored"] = True
                finally:
                    probe.close()
                    k4.resume_vm()
            except Exception as error:  # noqa: BLE001
                record["lstar"]["restore_error"] = repr(error)
        # Only now: the guest is unreachable while a stop is held, and ending the session is what
        # lets it run again.
        if workload_running:
            try:
                record["workload"]["stopped"] = stop_vtl1_workload()
            except Exception as error:  # noqa: BLE001
                record["workload"]["stop_error"] = repr(error)
        if record.get("result") == "running":
            record["result"] = "fail"
        record["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        save(manifest, record)
        print(
            json.dumps(
                {
                    "result": record["result"],
                    "evidence": record.get("evidence"),
                    "steps": len(record.get("steps", [])),
                    "run_dir": str(run_dir),
                    "vm_state": vm_state(),
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    raise SystemExit(main())
