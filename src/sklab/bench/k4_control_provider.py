"""Private K4 register provider for windbg-mcp-sk-control/2.

The provider owns only the exact-partition H3 register handle.  The parent
runner owns Hyper-V state and the debugger-held vmwp event; it publishes that
event here so epochs bind register mutations to the same stop.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import secrets
import sys
import time
from typing import Any

from h3_vtl1_debug_control import (
    Probe,
    REGISTERS,
    SNAPSHOT_NAMES,
    guard,
    low_value,
    read_named,
    snapshot,
    write_checked,
)


PROTOCOL = 2
READY = "windbg-mcp-sk-control/2"
READABLE = (
    "rax", "rcx", "rdx", "rbx", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    *SNAPSHOT_NAMES,
    "ds", "es", "fs", "gs", "ss", "vsm_vp_status",
)
WRITABLE = ("rip", "rsp", "rflags", "dr0", "dr1", "dr2", "dr3", "dr6", "dr7")
CAPABILITIES = {
    "capabilities": [
        "begin_arm",
        "finish_arm",
        "publish_stop",
        "held_event",
        "read_registers",
        "write_registers",
        "release",
        # Vector-3 events from the worker's own guarded INT3 patches. The worker enables them only
        # under a policy with `allow_memory_writes`, so advertising this changes nothing elsewhere.
        "breakpoint_events",
    ],
    "readable_registers": list(READABLE),
    "writable_registers": list(WRITABLE),
    "max_registers_per_request": 32,
    "requires_stop_epoch": True,
    "writes_while_running": False,
}


def word(value: int) -> str:
    return f"0x{value:016x}"


def epoch(phase: str) -> str:
    return f"{phase}-{secrets.token_hex(16)}"


def validate_target(value: object, expected: dict[str, object]) -> bool:
    return value == expected


def register_value(probe: Probe, partition: int, vp: int, name: str) -> dict[str, object]:
    row = read_named(probe, partition, name, vp)
    return {"name": name, **row}


class Provider:
    def __init__(
        self,
        vm_id: str,
        partition: int,
        expected_cr3: int | None,
        vp: int = 0,
        allow_transition_cr3: bool = False,
        identity_change_signal: pathlib.Path | None = None,
    ) -> None:
        self.probe = Probe()
        if expected_cr3 is None:
            expected_cr3 = low_value(read_named(self.probe, partition, "cr3", vp))
        guard(self.probe, partition, expected_cr3, vp)
        self.partition = partition
        self.vp = vp
        self.allow_transition_cr3 = allow_transition_cr3
        self.identity_change_signal = identity_change_signal
        self.target = {
            "vm_id": vm_id.lower(),
            "partition_id": word(partition),
            "vp": vp,
            "vtl": 1,
            "expected_cr3": word(expected_cr3),
        }
        self.phase = "running"
        self.epoch = epoch(self.phase)
        self.event: dict[str, object] | None = None

    def close(self) -> None:
        self.probe.close()

    def response(self, request: dict[str, Any], value: dict[str, object]) -> dict[str, object]:
        return {
            "protocol": PROTOCOL,
            "id": request["id"],
            "target": self.target,
            "epoch": self.epoch,
            "outcome": {"status": "ok", "value": value},
        }

    def error(self, request: dict[str, Any], code: str, detail: str) -> dict[str, object]:
        return {
            "protocol": PROTOCOL,
            "id": request.get("id", 0),
            "target": self.target,
            "epoch": self.epoch,
            "outcome": {
                "status": "error",
                "error": {"code": code, "detail": detail},
            },
        }

    def handle(self, request: dict[str, Any]) -> dict[str, object]:
        if request.get("protocol") != PROTOCOL:
            return self.error(request, "provider", f"protocol must be {PROTOCOL}")
        if not validate_target(request.get("target"), self.target):
            return self.error(request, "wrong_target", "target identity mismatch")
        if request.get("epoch") != self.epoch:
            return self.error(request, "stale_epoch", "stop epoch mismatch")
        operation = request.get("operation")
        if not isinstance(operation, dict):
            return self.error(request, "provider", "operation must be an object")
        op = operation.get("op")

        if (
            self.identity_change_signal is not None
            and self.identity_change_signal.exists()
            and op in {"read_registers", "write_registers", "release"}
        ):
            return self.error(
                request,
                "wrong_target",
                "target identity changed after the independently observed VM reset",
            )

        if op == "capabilities":
            return self.response(request, {"kind": "capabilities", "value": CAPABILITIES})
        if op == "begin_arm":
            if self.phase != "running":
                return self.error(request, "running", "begin_arm requires running state")
            self.phase = "arming"
            self.epoch = epoch(self.phase)
            return self.response(request, {"kind": "arm_begun"})
        if op == "finish_arm":
            if self.phase != "arming":
                return self.error(request, "running", "finish_arm requires arming state")
            self.phase = "running"
            self.epoch = epoch(self.phase)
            return self.response(request, {"kind": "arm_finished"})
        if op == "publish_stop":
            if self.phase != "running":
                return self.error(request, "running", "publish_stop requires running state")
            event = operation.get("event")
            if not isinstance(event, dict):
                return self.error(request, "provider", "publish_stop omitted event")
            if (
                event.get("message_type") != word(0x01000002)
                or event.get("vector") not in {1, 3}
                or event.get("vp") != self.vp
                or event.get("vtl") != 1
                or event.get("cpl") != 0
                or event.get("dispatcher_context") == word(0)
                or event.get("advance_instruction_pointer") is not False
            ):
                return self.error(request, "provider", "held event identity is not VTL1 CPL0 vector 1 or 3")
            expected_reason = "debug_exception" if event.get("vector") == 1 else "breakpoint_exception"
            reason = event.get("reason")
            if not isinstance(reason, dict) or reason.get("reason") != expected_reason:
                return self.error(request, "provider", "stop reason does not match its raw vector")
            current = snapshot(self.probe, self.partition, self.vp)
            cr3 = low_value(current["registers"]["cr3"])
            if cr3 != int(self.target["expected_cr3"], 0) and not self.allow_transition_cr3:
                return self.error(request, "wrong_target", "CR3 changed before stop publication")
            if cr3 == 0 or cr3 & 0xFFF:
                return self.error(request, "wrong_target", "stop CR3 is zero or not page aligned")
            self.event = event
            self.phase = "stopped"
            self.epoch = epoch(self.phase)
            return self.response(request, {"kind": "stop_published", "event": event})
        if op == "held_event":
            if self.phase != "stopped" or self.event is None:
                return self.error(request, "not_stopped", "there is no held event")
            return self.response(request, {"kind": "held_event", "event": self.event})
        if op == "read_registers":
            if self.phase == "running":
                return self.error(request, "running", "register reads are refused while running")
            names = operation.get("registers")
            if (
                not isinstance(names, list)
                or not names
                or len(names) > CAPABILITIES["max_registers_per_request"]
                or len(set(names)) != len(names)
                or any(name not in READABLE for name in names)
            ):
                return self.error(request, "unsupported_register", "invalid register request")
            values = [register_value(self.probe, self.partition, self.vp, name) for name in names]
            return self.response(request, {"kind": "registers", "values": values})
        if op == "write_registers":
            if self.phase == "running":
                return self.error(request, "running", "register writes are refused while running")
            writes = operation.get("writes")
            if (
                not isinstance(writes, list)
                or not writes
                or len(writes) > CAPABILITIES["max_registers_per_request"]
                or any(not isinstance(item, dict) for item in writes)
            ):
                return self.error(request, "unsupported_register", "invalid register write request")
            names = [item.get("name") for item in writes]
            if len(set(names)) != len(names) or any(name not in WRITABLE for name in names):
                return self.error(request, "unsupported_register", "invalid or duplicate writable register")
            before: dict[str, int] = {}
            for item in writes:
                name = item["name"]
                current = low_value(read_named(self.probe, self.partition, name, self.vp))
                before[name] = current
                if item.get("expected") != word(current):
                    return self.error(request, "guard_mismatch", f"{name} changed before write")
            applied: list[str] = []
            try:
                for item in writes:
                    name = item["name"]
                    value = int(item["value"], 0)
                    write_checked(self.probe, self.partition, name, value, self.vp)
                    applied.append(name)
            except Exception:
                rollback_errors = []
                for name in reversed(applied):
                    try:
                        write_checked(self.probe, self.partition, name, before[name], self.vp)
                    except Exception as rollback_error:
                        rollback_errors.append(f"{name}: {rollback_error}")
                if rollback_errors:
                    raise RuntimeError("write failed and rollback failed: " + "; ".join(rollback_errors))
                raise
            values = [register_value(self.probe, self.partition, self.vp, name) for name in names]
            return self.response(request, {"kind": "registers_written", "values": values})
        if op == "release":
            if self.phase != "stopped":
                return self.error(request, "not_stopped", "release requires a held event")
            self.event = None
            self.phase = "running"
            self.epoch = epoch(self.phase)
            return self.response(request, {"kind": "released"})
        return self.error(request, "provider", f"unknown operation {op!r}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vm-id", required=True)
    ap.add_argument("--partition-id", required=True, type=lambda value: int(value, 0))
    ap.add_argument("--expected-cr3", type=lambda value: int(value, 0))
    ap.add_argument("--vp", type=int, default=0)
    ap.add_argument("--allow-transition-cr3", action="store_true")
    ap.add_argument("--exit-before-response")
    ap.add_argument("--identity-change-signal", type=pathlib.Path)
    args = ap.parse_args()
    provider = Provider(
        args.vm_id,
        args.partition_id,
        args.expected_cr3,
        args.vp,
        args.allow_transition_cr3,
        args.identity_change_signal,
    )
    try:
        print(READY)
        print(json.dumps({
            "protocol": PROTOCOL,
            "target": provider.target,
            "epoch": provider.epoch,
        }))
        sys.stdout.flush()
        for line in sys.stdin:
            started = time.monotonic()
            try:
                request = json.loads(line)
                operation = request.get("operation")
                op = operation.get("op") if isinstance(operation, dict) else None
                print(
                    f"provider vp={provider.vp} id={request.get('id')} op={op} begin",
                    file=sys.stderr,
                    flush=True,
                )
                response = provider.handle(request)
            except Exception as error:
                print(f"provider fatal: {error}", file=sys.stderr)
                return 1
            if (
                isinstance(operation, dict)
                and operation.get("op") == args.exit_before_response
            ):
                print(
                    f"injected provider exit before {args.exit_before_response} response",
                    file=sys.stderr,
                )
                return 86
            print(
                f"provider vp={provider.vp} id={request.get('id')} op={op} end "
                f"elapsed={time.monotonic() - started:.3f}s",
                file=sys.stderr,
                flush=True,
            )
            print(json.dumps(response, separators=(",", ":")))
            sys.stdout.flush()
        return 0
    finally:
        provider.close()


if __name__ == "__main__":
    raise SystemExit(main())
