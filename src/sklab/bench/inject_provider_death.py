"""Kill the private provider at stop publication and prove the worker contains K3."""

import json
import os
import pathlib
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))

import run_k4_stop_step as k4
from h3_vtl1_debug_control import Probe, snapshot


def processes():
    raw = k4.ps(
        "@(Get-CimInstance Win32_Process | Where-Object {$_.Name -eq 'windbg-mcp.exe'} | "
        "Select-Object ProcessId,ExecutablePath,CommandLine) | ConvertTo-Json -Compress"
    )
    if not raw:
        return []
    value = json.loads(raw)
    return value if isinstance(value, list) else [value]


def main():
    config = json.loads((HERE / "natural-live-control-input.json").read_text())
    prep = json.loads((HERE / "natural-flow-prep-result.json").read_text())
    if config["vm_id"].lower() != k4.VM_ID.lower() or not config.get("disposable"):
        raise k4.GateFailure("input does not name the allowlisted disposable K3 VM")
    config["control_transport"] += " --exit-before-response publish_stop"
    injected = HERE / "provider-death-live-input.json"
    injected.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    before_processes = processes()
    before_ids = {int(row["ProcessId"]) for row in before_processes}
    result = {
        "schema": "windbg-mcp.private.live-provider-death.v1",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "vm_id": config["vm_id"],
        "vmwp_pid": config["vmwp_pid"],
        "partition_id": config["partition_id"],
        "processes_before": before_processes,
        "result": "running",
    }
    path = HERE / "live-provider-death-result.json"
    new_workers = []
    try:
        environment = os.environ.copy()
        environment["WINDBG_MCP_SMOKE_SK_LIVE"] = str(injected)
        command = [
            "cargo", "test", "--test", "mcp_smoke",
            "a_live_secure_kernel_session_stops_steps_inspects_resumes_and_closes",
            "--", "--ignored", "--nocapture",
        ]
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            timeout=240,
        )
        result["test_exit_code"] = completed.returncode
        result["test_stdout"] = completed.stdout
        result["test_stderr"] = completed.stderr
        if completed.returncode == 0:
            raise k4.GateFailure("provider-death injection unexpectedly completed")
        combined = completed.stdout + completed.stderr
        if "target_left_paused=true" not in combined:
            raise k4.GateFailure("provider death did not report fail-closed containment")

        if not k4.fail_closed_pause():
            raise k4.GateFailure("host could not put the contained VM in Hyper-V Paused state")
        result["contained_vm"] = k4.vm_json()
        result["same_vmwp_after_fault"] = k4.vmwp_pid() == int(config["vmwp_pid"])
        if not result["same_vmwp_after_fault"]:
            raise k4.GateFailure("provider death replaced vmwp before containment was recorded")

        probe = Probe()
        try:
            result["contained_vtl1_state"] = snapshot(
                probe, int(config["partition_id"], 0), int(config.get("vp", 0))
            )
        finally:
            probe.close()
        if int(result["contained_vtl1_state"]["registers"]["dr0"]["low"], 0) != int(
            config["instruction_address"], 0
        ):
            raise k4.GateFailure("contained state does not retain the owned DR0 stop")
        result["sentinel_while_contained"] = k4.live_target(
            int(config["partition_id"], 0), HERE / "provider-death-sentinel.json"
        )
        if result["sentinel_while_contained"]["live_read_1"] != prep["sentinel"]["live_read_1"]:
            raise k4.GateFailure("provider-death containment changed Secure Kernel text")

        after_processes = processes()
        result["processes_after_fault"] = after_processes
        new_workers = [
            row for row in after_processes if int(row["ProcessId"]) not in before_ids
        ]
        result["retained_workers"] = new_workers
        if not any("--engine-worker" in (row.get("CommandLine") or "") for row in new_workers):
            raise k4.GateFailure("no retained engine worker proves unresolved containment")
        result["result"] = "pass"
    except Exception as error:
        result["result"] = "fail"
        result["error"] = str(error)
        raise
    finally:
        try:
            for row in new_workers:
                pid = int(row["ProcessId"])
                command_line = row.get("CommandLine") or ""
                executable = pathlib.Path(row.get("ExecutablePath") or "")
                if "--engine-worker" not in command_line:
                    continue
                if executable.resolve() != (ROOT / "target" / "debug" / "windbg-mcp.exe").resolve():
                    raise k4.GateFailure(f"refusing to stop unexpected retained process {pid}")
                k4.ps(f"Stop-Process -Id {pid} -Force -ErrorAction Stop")
            result["retained_workers_stopped_for_disposal"] = True
        except Exception as worker_error:
            result["worker_cleanup_error"] = str(worker_error)
        try:
            # Releasing an unresolved DbgEng attachment can replace vmwp. This child is dedicated
            # to the destructive fault, so wait for Hyper-V to settle and then stop only this VM.
            time.sleep(3)
            result["vm_before_disposal"] = k4.vm_json()
            k4.ps(
                f"$v=Get-VM -Id '{k4.VM_ID}'; "
                "if($v.State -ne 'Off'){Stop-VM -VM $v -Force -ErrorAction Stop}"
            )
        except Exception as stop_error:
            result["stop_error"] = str(stop_error)
        try:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline and k4.vm_state() != "Off":
                time.sleep(1)
            result["vm_after_cleanup"] = k4.vm_json()
        except Exception as state_error:
            result["cleanup_state_error"] = str(state_error)
        try:
            k4.ps(
                "foreach($n in @('h3probe')){$s=Get-Service -Name $n "
                "-ErrorAction SilentlyContinue;if($s -and $s.Status -ne 'Stopped'){"
                "Stop-Service -Name $n -ErrorAction Stop;"
                "$s.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(15))}}"
            )
        except Exception as service_error:
            result["service_cleanup_error"] = str(service_error)
        result["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
