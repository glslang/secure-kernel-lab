"""Inject debugger loss after live baseline restoration and audit containment."""

from __future__ import annotations

import json
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))

import run_k4_stop_step as k4
from h3_vtl1_debug_control import Probe, snapshot
from inject_provider_death_mcp import Mcp, processes, structured

RESULT = HERE / "live-debugger-loss-result.json"
DEBUG_REGISTERS = ("dr0", "dr1", "dr2", "dr3", "dr6", "dr7")


def save(result: dict[str, object]) -> None:
    RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def ok(response: dict[str, object], operation: str) -> dict[str, object]:
    value = structured(response)
    if (
        response.get("result", {}).get("isError")
        or not isinstance(value, dict)
        or value.get("status") != "ok"
    ):
        raise k4.GateFailure(f"{operation} failed: {response}")
    return value


def main() -> None:
    config = json.loads((HERE / "scheduler-selected-live-input.json").read_text())
    prep = json.loads((HERE / "scheduler-selected-prep-result.json").read_text())
    if config.get("disposable") is not True or config["vm_id"].lower() != k4.VM_ID.lower():
        raise k4.GateFailure("input does not name the allowlisted disposable K3 VM")

    before_ids = {int(row["ProcessId"]) for row in processes()}
    result: dict[str, object] = {
        "schema": "windbg-mcp.private.live-debugger-loss.v1",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "vm_id": config["vm_id"],
        "vmwp_pid": config["vmwp_pid"],
        "partition_id": config["partition_id"],
        "result": "running",
    }
    client = None
    session = None
    retained_workers: list[dict[str, object]] = []
    try:
        client = Mcp(args=("--tools", "all"))
        initialized = client.request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "live-debugger-loss-gate", "version": "1"},
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
                    "profile": config["profile"],
                    "control_transport": config["control_transport"],
                    "live_transport": config["live_transport"],
                    "vmwp_pid": config["vmwp_pid"],
                    "dispatcher_vnd": config["dispatcher_vnd"],
                    "vm_id": config["vm_id"],
                    "partition_id": config["partition_id"],
                    "vp": config["vp"],
                    "additional_vps": [],
                    "expected_cr3": None,
                },
                30,
            ),
            "open_sk_live_control",
        )
        session = opened["session_id"]
        result["session_id"] = session
        ok(
            client.tool(
                "sk_live_arm",
                {
                    "session_id": session,
                    "address": config["instruction_address"],
                    "bytes": config["instruction_bytes"],
                    "slot": config["slot"],
                    "mode": "natural",
                },
                90,
            ),
            "sk_live_arm",
        )
        stopped = ok(
            client.tool("sk_live_wait", {"session_id": session}, 240),
            "sk_live_wait",
        )
        result["stop"] = stopped

        faulted = client.tool(
            "sk_live_continue",
            {"session_id": session, "epoch": stopped["epoch"]},
            90,
        )
        result["fault_response"] = faulted
        fault_text = json.dumps(faulted)
        if not faulted.get("result", {}).get("isError"):
            raise k4.GateFailure("debugger-loss injection did not fault continue")
        if "debugger loss after provider baseline restoration" not in fault_text:
            raise k4.GateFailure("fault did not name the injected debugger loss")
        if "target_left_paused=true" not in fault_text:
            raise k4.GateFailure("fault did not report fail-closed containment")
        if "dispatcher recovery" not in fault_text:
            raise k4.GateFailure("fault did not record debugger recovery failure")

        ended = client.tool("end_session", {"session_id": session}, 60)
        result["end_response"] = ended
        end = structured(ended)
        if not isinstance(end, dict):
            raise k4.GateFailure(f"end_session returned no structured result: {ended}")
        if end.get("recovery_required") is not True or end.get("released") is not False:
            raise k4.GateFailure("end_session did not retain unresolved ownership")

        result["server_stderr"] = "".join(client.errors)
        client.shutdown()
        client = None
        session = None

        probe = Probe()
        try:
            contained = snapshot(
                probe, int(config["partition_id"], 0), int(config["vp"])
            )
        finally:
            probe.close()
        for name in DEBUG_REGISTERS:
            if contained["registers"][name] != prep["before"][0]["registers"][name]:
                raise k4.GateFailure(f"restored baseline mismatch for {name}")
        flags = int(contained["registers"]["rflags"]["low"], 0)
        if flags & ((1 << 8) | (1 << 16)):
            raise k4.GateFailure("restored baseline retained TF/RF")
        result["contained_vtl1_state"] = contained
        result["baseline_restored"] = True
        sentinel = k4.live_target(
            int(config["partition_id"], 0),
            HERE / "debugger-loss-sentinel.json",
            int(config["discovered_cr3"], 0),
        )
        result["sentinel_while_contained"] = sentinel
        if sentinel["live_read_1"] != prep["sentinel"]["live_read_1"]:
            raise k4.GateFailure("debugger-loss containment changed Secure Kernel text")

        retained_workers = [
            row
            for row in processes()
            if int(row["ProcessId"]) not in before_ids
            and "--engine-worker" in (row.get("CommandLine") or "")
        ]
        result["retained_workers"] = retained_workers
        if len(retained_workers) != 1:
            raise k4.GateFailure("expected exactly one retained engine worker")
        result["result"] = "pass"
    except Exception as error:
        result["result"] = "fail"
        result["error"] = str(error)
        raise
    finally:
        if client is not None:
            try:
                result["server_stderr"] = "".join(client.errors)
                client.shutdown()
            except Exception as error:
                result["client_cleanup_error"] = str(error)
        try:
            result["vm_before_disposal"] = k4.vm_json()
            for row in retained_workers:
                executable = pathlib.Path(row.get("ExecutablePath") or "")
                expected = ROOT / "target" / "debug" / "windbg-mcp.exe"
                if executable.resolve() != expected.resolve():
                    raise k4.GateFailure(
                        f"refusing to stop unexpected retained process {row['ProcessId']}"
                    )
                k4.ps(
                    f"Stop-Process -Id {int(row['ProcessId'])} -Force -ErrorAction Stop"
                )
            time.sleep(3)
            result["vm_after_worker_disposal"] = k4.vm_json()
            k4.ps(
                f"$v=Get-VM -Id '{k4.VM_ID}'; "
                "if($v.State -ne 'Off'){Stop-VM -VM $v -Force -ErrorAction Stop}"
            )
            result["vm_after_cleanup"] = k4.vm_json()
        except Exception as error:
            result["cleanup_error"] = str(error)
        try:
            k4.ps(
                "foreach($n in @('h3probe')){$s=Get-Service -Name $n "
                "-ErrorAction SilentlyContinue;if($s -and $s.Status -ne 'Stopped'){"
                "Stop-Service -Name $n -ErrorAction Stop;"
                "$s.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(15))}}"
            )
        except Exception as error:
            result["service_cleanup_error"] = str(error)
        result["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        save(result)
    print(
        json.dumps(
            {
                "result": result["result"],
                "baseline_restored": result.get("baseline_restored"),
                "retained_workers": len(result.get("retained_workers", [])),
                "vm_after_cleanup": result.get("vm_after_cleanup"),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
