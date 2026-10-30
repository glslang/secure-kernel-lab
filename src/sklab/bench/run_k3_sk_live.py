"""K3 live Secure Kernel stop/step/resume on an ambient Secure Kernel code path. No trigger.

This supersedes `run_k3_hvci_trigger.py`, whose scaffolding had grown larger than the thing it was
testing. The lesson it cost: **the Secure Kernel is always executing**, so a stop does not need an
event to be provoked in the guest. Arming `KiTimerInterrupt` — which is what this bench's own
proven natural-flow config arms — produces a stop at once, as often as you like, with no in-guest
trigger, no image to keep fresh, and nothing racing `sk_live_wait`'s deadline.

What the trigger experiment cost and concluded, so nobody repeats it: HVCI validates a driver image
**once per boot**, so `fltmc load` is a one-shot per image (three clean observations); the guest is
unreachable between `sk_live_arm` and `sk_live_wait` because the dispatcher pauses the whole VM; a
synchronous in-guest trigger deadlocks against the stop it causes; and `sk_live_wait` faults at
**about 60 seconds**, measured, with no timeout argument reaching it. Every one of those is a
property of provoking an event, and none of them applies here.

Exercises all seven live tools in one run: `open_sk_live_control`, `sk_live_arm`, `sk_live_wait`,
`sk_live_registers`, `sk_live_read_memory`, `sk_live_step`, `sk_live_continue`, then `end_session`.

    uv run sklab --target <name> run live.ambient --set steps=8 --yes

sklab writes the run's policy and sets `WINDBG_MCP_SK_LIVE_POLICY` and `WINDBG_MCP_TRANSCRIPT`
(`bench_bridge.runner_environment`). `Mcp` spawns `target/debug/windbg-mcp.exe` with no `env=`,
so both transcript variables reach it.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time
from typing import Any

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run_k4_stop_step as k4  # noqa: E402
import run_vtl1_user_to_securekernel as exp  # noqa: E402
from h3_vtl1_debug_control import Probe, low_value, snapshot  # noqa: E402
from guest_physical import (  # noqa: E402
    GuestVirtual,
    H3Source,
    find_secure_kernel_base,
    vtl1_identity,
)
from inject_provider_death_mcp import Mcp  # noqa: E402

VM_NAME = "windbg-mcp K3 Managed VTL1"
VM_ID = "6b1ed0f6-137e-469f-aeab-a3f4cfee398d"
PROFILE = HERE / "vmwp-dispatcher-profile.json"
IMAGE = HERE / "guest-positive-securekernel.exe"
RUN_ROOT = HERE / "k3-sk-live"

# Four ambient Secure Kernel interrupt entries, armed at once across the four debug-register slots
# natural mode allows. One target was not enough, for two reasons measured on 2026-10-10:
#
#   * **`KiTimerInterrupt` is not continuous.** An idle VBS guest is tickless, so it fired after
#     **49.7s** on one run and not at all within the ~60s `sk_live_wait` deadline on the next. A
#     stop that depends on a rare event is a coin toss against that deadline.
#   * **Every entry has a KVA-shadow twin**, and which one executes is a property of the guest, not
#     a thing to guess: `KiTimerInterruptShadow`, `KiVinaInterruptShadow`, and so on. Arming only
#     the non-shadow entry would simply never fire on a guest that shadows.
#
# `KiVinaInterrupt` is the Virtual Interrupt Notification Assist — the Secure Kernel is notified
# when VTL0 has an interrupt pending while VTL1 is running — so it tracks ordinary guest activity
# rather than a timer, and should be the most frequent of these on a guest doing anything at all.
#
# `max_steps` is per entry because the prologues differ: the shadow timer's second instruction is a
# conditional `je`, and this harness omits `expected_rips` so the server defaults it to
# address-plus-length, which a taken branch would violate. One step there, the `test`, and no more.
ENTRIES = (
    {"symbol": "KiVinaInterrupt", "rva": 0xE7670, "bytes": "4883ec08", "slot": 0, "max_steps": 13},
    {"symbol": "KiTimerInterrupt", "rva": 0xE8F70, "bytes": "4883ec08", "slot": 1, "max_steps": 13},
    {"symbol": "KiCallbackInterrupt", "rva": 0xE8100, "bytes": "4883ec08", "slot": 2, "max_steps": 13},
    {"symbol": "KiTimerInterruptShadow", "rva": 0xF6CC0, "bytes": "f644240801", "slot": 3, "max_steps": 1},
)

# The exact templates `sk-live-policy.json` admits. Matching is word-by-word over a normalised
# vector after the program path is canonicalised, so the absolute interpreter, the quoting and the
# `{partition_id}` placeholder are all load-bearing: a near miss is a refusal, not a warning.
PYTHON = sys.executable
CONTROL_TRANSPORT = (
    f'"{PYTHON}" "{HERE / "k4_control_provider.py"}" '
    f"--vm-id {VM_ID} --partition-id {{partition_id}}"
)
LIVE_TRANSPORT = (
    f'"{PYTHON}" "{HERE / "gpa_server.py"}" '
    "--vmwp-pid {vmwp_pid} --partition-handle {partition_handle} "
    f'--partition-id {{partition_id}} --vp {{vp}} --image "{IMAGE}" --writes'
)

# Discovery (`windbg-mcp --sk-discover-identity`) attaches to the VM's worker process and hijacks
# one of its threads. Its values are per-boot constants and the vmwp pid identifies the boot
# exactly, so this is paid once per boot rather than once per run.
DISCOVERY_CACHE = RUN_ROOT / "discovery-cache.json"


def signed64(value: int) -> int:
    """
    A register difference as a signed 64-bit quantity.

    `mov rsp, gs:[1070h]` switches from the trustlet's user stack to the Secure Kernel's, so the
    delta is a large negative number; subtracting unsigned reported it as 18446664688968830728,
    which reads as a 16-exabyte push rather than a stack switch.
    """
    value &= (1 << 64) - 1
    return value - (1 << 64) if value >= 1 << 63 else value


def save(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def vm_state() -> str:
    return k4.ps(f"(Get-VM -Id '{VM_ID}' -ErrorAction Stop).State.ToString()")


def discovery(pid: int) -> tuple[int, int, int, str]:
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
    vnd, handle, partition = k4.discover_identity(pid, "k3-sk-live")
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


def raw_command(client: Mcp, session_id: str, command: str) -> str:
    """`execute` answers with debugger text and no `structuredContent`, so `exp.ok` rejects it."""
    response = client.tool("execute", {"session_id": session_id, "command": command}, 90)
    if response.get("error") is not None:
        raise k4.GateFailure(f"{command!r} failed: {response}")
    result = response.get("result") or {}
    if result.get("isError"):
        raise k4.GateFailure(f"{command!r} reported an error: {response}")
    return "".join(b.get("text", "") for b in (result.get("content") or []) if isinstance(b, dict))


def step_plans(client: Mcp, count: int) -> dict[int, list[dict[str, Any]]]:
    """
    The instruction sequence to be stepped, disassembled from the pinned image by this same server.

    A repeated `sk_live_step` must state the instruction at the *current* RIP, and a stop record
    cannot supply it — its `instruction` is the instruction just stepped. So the length of the next
    instruction has to come from somewhere, and the server disassembles. DbgEng takes a bare PE as a
    target at its preferred base, so only the RVA carries over to the guest; the live run then
    asserts each stopped RIP against `sk_base + rva`, checking image, base and plan against each
    other at every step. `.reload /f` immediately, or reads of that target fail `0x8007001E`.
    """
    opened = exp.ok(client.tool("open_dump", {"path": str(IMAGE)}, 90), "open_dump of the SK image")
    sid = str(opened["session_id"])
    try:
        base = int(str(opened["summary"]["primary_module"]["start"]), 0)
        raw_command(client, sid, ".reload /f")
        plans: dict[int, list[dict[str, Any]]] = {}
        for entry in ENTRIES:
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
            plans[entry["rva"]] = rows
        exp.ok(client.tool("end_session", {"session_id": sid}, 60), "end_session")
        return plans
    finally:
        try:
            client.tool("end_session", {"session_id": sid}, 60)
        except Exception:  # noqa: BLE001 - never mask the caller's outcome
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--steps", type=int, default=8)
    parser.add_argument("--read-size", type=int, default=32)
    parser.add_argument(
        "--only",
        help="arm a single entry by symbol instead of all four (e.g. KiTimerInterrupt)",
    )
    args = parser.parse_args()

    entries = list(ENTRIES)
    if args.only:
        entries = [e for e in ENTRIES if e["symbol"].lower() == args.only.lower()]
        if not entries:
            raise k4.GateFailure(
                f"--only {args.only!r} names no entry; known: "
                + ", ".join(e["symbol"] for e in ENTRIES)
            )

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
        "schema": "windbg-mcp.private.k3-sk-live.v1",
        "result": "running",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "vm_id": VM_ID,
        "vm_name": VM_NAME,
        "trigger": "none; these Secure Kernel interrupt entries are ambient",
        "entries_armed": [
            {k: (f"0x{v:x}" if k == "rva" else v) for k, v in e.items()} for e in entries
        ],
    }
    save(manifest, record)

    client: Mcp | None = None
    session: str | None = None
    try:
        pid = k4.vmwp_pid()
        vnd, source_handle, partition, how = discovery(pid)
        record["identity"] = {
            "vmwp_pid": pid,
            "dispatcher_vnd": f"0x{vnd:016x}",
            "partition_handle": f"0x{source_handle:x}",
            "partition_id": f"0x{partition:x}",
            "discovery": how,
        }

        # The source handle belongs to vmwp, and h3probe uses it there, after checking vmwp, the
        # handle's owner and the partition ID. Hold the VM while CR3, IDTR, page tables and the PE
        # identity are read as one state. The worker repeats the same guarded discovery and passes
        # its handle only to the allow-listed memory child when the live session arms.
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
        for shown in record["entries_armed"]:
            shown["address"] = f"0x{sk_base + int(shown['rva'], 0):016x}"
        save(manifest, record)

        # `securekernel` is the one tool group marked `extra`, so it is absent from the default
        # surface and can only be widened on the command line.
        client = Mcp(("--tools", "all"))
        initialized = client.request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "k3-sk-live", "version": "1"},
            },
            15,
        )
        if initialized.get("error") is not None:
            raise k4.GateFailure(f"initialize failed: {initialized}")
        client.notify("notifications/initialized", {})

        plans = step_plans(client, args.steps)
        record["step_plans"] = {f"0x{rva:x}": rows for rva, rows in plans.items()}
        save(manifest, record)

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
                },
                30,
            ),
            "open_sk_live_control",
        )
        session = str(opened["session_id"])
        record["open"] = opened

        # All of them at once, across the four slots natural mode allows: whichever ambient entry
        # the guest reaches first ends the wait, and which one it was identifies whether this guest
        # shadows.
        primary, *extra = entries
        armed = time.monotonic()
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
        save(manifest, record)

        stop = exp.ok(client.tool("sk_live_wait", {"session_id": session}, 120), "sk_live_wait")
        record["stop"] = stop
        record["stopped_after_arm_s"] = round(time.monotonic() - armed, 1)
        regs = exp.register_map(stop)
        # Which of the armed entries the guest actually reached. On a shadowing guest the non-shadow
        # entries never execute, so this also reports a fact about the guest rather than assuming it.
        fired = next((e for e in entries if sk_base + e["rva"] == regs["rip"]), None)
        if fired is None:
            raise k4.GateFailure(
                f"stopped at 0x{regs['rip']:x}, which is none of the armed entries: "
                + ", ".join(f"{e['symbol']}@0x{sk_base + e['rva']:x}" for e in entries)
            )
        record["fired"] = {"symbol": fired["symbol"], "rva": f"0x{fired['rva']:x}"}
        settled_cr3 = int(str(stop["target"]["expected_cr3"]), 0)
        record["identity"]["cr3_settled"] = f"0x{settled_cr3:x}"
        if regs["cr3"] != settled_cr3:
            raise k4.GateFailure(
                f"cr3 0x{regs['cr3']:x} is not the root this session discovered 0x{settled_cr3:x}"
            )
        record["same_address_space"] = True
        save(manifest, record)

        # The one live tool the trigger runs never reached.
        record["registers"] = exp.ok(
            client.tool("sk_live_registers", {"session_id": session}, 60), "sk_live_registers"
        )

        code = exp.ok(
            client.tool(
                "sk_live_read_memory",
                {
                    "session_id": session,
                    "address": f"0x{sk_base + fired['rva']:016x}",
                    "size": args.read_size,
                },
                60,
            ),
            "sk_live_read_memory",
        )
        record["code_at_stop"] = code
        if not str(code["data"]).lower().startswith(fired["bytes"]):
            raise k4.GateFailure("the bytes at the stop are not the guarded instruction")
        save(manifest, record)

        # Each mutating call consumes the held stop's epoch exactly once; a repeated step must also
        # state the instruction it is stepping. `expected_rips` is omitted so the server defaults it
        # to address-plus-length and a branch is refused rather than silently accepted.
        plan = plans[fired["rva"]]
        budget = min(args.steps, fired["max_steps"])
        record["step_budget"] = {
            "requested": args.steps,
            "allowed_by_entry": fired["max_steps"],
            "used": budget,
        }
        steps: list[dict[str, Any]] = []
        held = stop
        for index in range(budget):
            entry = plan[index]
            before = exp.register_map(held)
            want = sk_base + entry["rva"]
            if before["rip"] != want:
                raise k4.GateFailure(
                    f"step {index}: stopped at 0x{before['rip']:x} but the plan's next instruction "
                    f"is {entry['text']!r} at 0x{want:x}"
                )
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
            if after["cr3"] != settled_cr3:
                raise k4.GateFailure(
                    f"step {index} changed the address-space root to 0x{after['cr3']:x}"
                )
            steps.append(
                {
                    "index": index,
                    "from": f"0x{before['rip']:016x}",
                    "rva": f"0x{entry['rva']:x}",
                    "text": entry["text"],
                    "bytes": entry["bytes"],
                    "rip": f"0x{after['rip']:016x}",
                    "rsp_delta": signed64(after["rsp"] - before["rsp"]),
                    "reason": held["event"]["reason"],
                }
            )
            record["steps"] = steps
            save(manifest, record)

        record["continue"] = exp.ok(
            client.tool("sk_live_continue", {"session_id": session, "epoch": held["epoch"]}, 90),
            "sk_live_continue",
        )
        record["end"] = exp.ok(
            client.tool("end_session", {"session_id": session}, 120), "end_session"
        )
        session = None
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
        if record.get("result") == "running":
            record["result"] = "fail"
        record["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        save(manifest, record)
        print(
            json.dumps(
                {
                    "result": record["result"],
                    "tools_exercised": [
                        name
                        for name, key in (
                            ("open_sk_live_control", "open"),
                            ("sk_live_arm", "arm"),
                            ("sk_live_wait", "stop"),
                            ("sk_live_registers", "registers"),
                            ("sk_live_read_memory", "code_at_stop"),
                            ("sk_live_step", "steps"),
                            ("sk_live_continue", "continue"),
                            ("end_session", "end"),
                        )
                        if record.get(key)
                    ],
                    "evidence": str(run_dir),
                    "vm_state": vm_state(),
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    raise SystemExit(main())
