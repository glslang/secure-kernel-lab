"""Reset the disposable VM under a held stop and audit identity containment."""

from __future__ import annotations

import json
import os
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SIGNAL = HERE / "identity-change.signal"
RESULT = HERE / "live-identity-change-result.json"
sys.path.insert(0, str(HERE))

import run_k4_stop_step as k4
from inject_provider_death_mcp import Mcp, processes, structured
from guest_credentials import powershell_credential


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


def guest_boot_identity(timeout: float = 60) -> str:
    raw = k4.ps(
        powershell_credential()
        + f"Invoke-Command -VMName '{k4.VM_NAME}' -Credential $c -ScriptBlock {{"
        "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')"
        "}",
        timeout=timeout,
    )
    value = raw.strip()
    if not value:
        raise k4.GateFailure("guest returned no boot identity")
    return value


def wait_for_new_boot(before: str) -> str:
    deadline = time.monotonic() + 240
    last_error = ""
    while time.monotonic() < deadline:
        try:
            vm = k4.vm_json()
            if vm["State"] == "Running" and vm.get("Heartbeat") == "OK":
                current = guest_boot_identity(20)
                if current != before:
                    return current
        except Exception as error:
            last_error = str(error)
        time.sleep(5)
    raise k4.GateFailure(f"VM did not expose a new boot identity: {last_error}")


def wait_for_vm_object() -> str:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        state = k4.ps(
            f"$v=Get-VM -Id '{k4.VM_ID}' -ErrorAction SilentlyContinue;"
            "if($v){$v.State.ToString()}"
        ).strip()
        if state:
            return state
        time.sleep(2)
    raise k4.GateFailure("VMMS did not restore the exact VM object after worker disposal")


def stop_retained_workers(rows: list[dict[str, object]]) -> None:
    expected = ROOT / "target" / "debug" / "windbg-mcp.exe"
    for row in rows:
        executable = pathlib.Path(row.get("ExecutablePath") or "")
        if executable.resolve() != expected.resolve():
            raise k4.GateFailure(
                f"refusing to stop unexpected retained process {row['ProcessId']}"
            )
        k4.ps(f"Stop-Process -Id {int(row['ProcessId'])} -Force -ErrorAction Stop")


def main() -> None:
    config = json.loads((HERE / "scheduler-selected-live-input.json").read_text())
    policy = json.loads((HERE / "sk-live-policy.json").read_text())
    if config.get("disposable") is not True or config["vm_id"].lower() != k4.VM_ID.lower():
        raise k4.GateFailure("input does not name the allowlisted disposable K3 VM")
    control_transport = next(
        command
        for command in policy["transport_commands"]
        if "--identity-change-signal" in command
    )
    SIGNAL.unlink(missing_ok=True)
    before_rows = processes()
    before_ids = {int(row["ProcessId"]) for row in before_rows}
    result: dict[str, object] = {
        "schema": "windbg-mcp.private.live-identity-change.v1",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "vm_id": config["vm_id"],
        "vmwp_pid_before": config["vmwp_pid"],
        "partition_id_before": config["partition_id"],
        "result": "running",
    }
    client = None
    session = None
    retained_workers: list[dict[str, object]] = []
    try:
        if k4.vm_json()["State"] == "Paused":
            k4.resume_vm()
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                vm = k4.vm_json()
                if vm["State"] == "Running" and vm.get("Heartbeat") == "OK":
                    break
                time.sleep(2)
            else:
                raise k4.GateFailure("VM did not become healthy for the pre-reset boot reading")
        result["boot_identity_before"] = guest_boot_identity()
        client = Mcp(args=("--tools", "all"))
        initialized = client.request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "live-identity-change-gate", "version": "1"},
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
                    "control_transport": control_transport,
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

        old_vmwp = int(config["vmwp_pid"])
        k4.ps(
            f"$p=Get-CimInstance Win32_Process -Filter \"ProcessId={old_vmwp}\" "
            "-ErrorAction Stop;"
            f"if($p.Name -ne 'vmwp.exe' -or $p.CommandLine -notmatch '{k4.VM_ID}'){{"
            "throw 'refusing to terminate a vmwp without the exact allowlisted VM identity'};"
            f"Stop-Process -Id {old_vmwp} -Force -ErrorAction Stop"
        )
        result["reset_method"] = "terminated the exact allowlisted VM's vmwp process"
        result["old_vmwp_termination_requested_while_stop_held"] = True
        SIGNAL.write_text(
            "termination was issued to the exact pre-reset vmwp\n", encoding="utf-8"
        )
        stderr_start = len(client.errors)

        faulted = client.tool(
            "sk_live_continue",
            {"session_id": session, "epoch": stopped["epoch"]},
            90,
        )
        result["fault_response"] = faulted
        fault_text = json.dumps(faulted)
        if not faulted.get("result", {}).get("isError"):
            raise k4.GateFailure("identity-change injection did not fault continue")
        if "target identity changed" not in fault_text:
            raise k4.GateFailure("fault did not name the changed target identity")
        if "target_left_paused=true" not in fault_text:
            raise k4.GateFailure("fault did not report fail-closed containment")
        time.sleep(1)
        after_change_stderr = "".join(client.errors[stderr_start:])
        result["provider_log_after_identity_change"] = after_change_stderr
        if "op=write_registers begin" in after_change_stderr:
            raise k4.GateFailure("provider attempted a register write after identity change")
        result["no_provider_write_after_identity_change"] = True

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
        retained_workers = [
            row
            for row in processes()
            if int(row["ProcessId"]) not in before_ids
            and "--engine-worker" in (row.get("CommandLine") or "")
        ]
        result["retained_workers"] = retained_workers
        if len(retained_workers) != 1:
            raise k4.GateFailure("expected exactly one retained engine worker")
        stop_retained_workers(retained_workers)
        retained_workers = []
        result["retained_worker_disposed_for_boot_audit"] = True
        state = wait_for_vm_object()
        if state != "Running":
            if state != "Off":
                k4.ps(
                    f"$v=Get-VM -Id '{k4.VM_ID}' -ErrorAction Stop;"
                    "Stop-VM -VM $v -Force -ErrorAction Stop"
                )
            k4.ps(f"Start-VM -Name '{k4.VM_NAME}' -ErrorAction Stop | Out-Null")
        after = wait_for_new_boot(str(result["boot_identity_before"]))
        result["boot_identity_after"] = after
        result["vm_after_reset"] = k4.vm_json()
        result["vmwp_pid_after"] = k4.vmwp_pid()
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
        if not retained_workers and not result.get("retained_worker_disposed_for_boot_audit"):
            try:
                retained_workers = [
                    row
                    for row in processes()
                    if int(row["ProcessId"]) not in before_ids
                    and "--engine-worker" in (row.get("CommandLine") or "")
                ]
                result["retained_workers"] = retained_workers
            except Exception as error:
                result["worker_scan_error"] = str(error)
        try:
            stop_retained_workers(retained_workers)
            time.sleep(5)
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
        SIGNAL.unlink(missing_ok=True)
        result["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        save(result)
    print(
        json.dumps(
            {
                "result": result["result"],
                "boot_changed": result.get("boot_identity_before")
                != result.get("boot_identity_after"),
                "no_provider_write": result.get("no_provider_write_after_identity_change"),
                "retained_workers": len(result.get("retained_workers", [])),
                "vm_after_cleanup": result.get("vm_after_cleanup"),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
