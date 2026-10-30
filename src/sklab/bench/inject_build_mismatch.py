"""Prove an exact-build mismatch refuses before VTL1 mutation, then leave K3 paused."""

import json
import pathlib
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))

import run_k4_stop_step as k4
from h3_vtl1_debug_control import Probe, snapshot


def main():
    prep = json.loads((HERE / "natural-flow-prep-result.json").read_text())
    config = json.loads((HERE / "natural-live-control-input.json").read_text())
    if config["vm_id"].lower() != k4.VM_ID.lower() or not config.get("disposable"):
        raise k4.GateFailure("input does not name the allowlisted disposable K3 VM")

    profile = json.loads(pathlib.Path(config["profile"]).read_text())
    original_hash = profile["vmwp_sha256"]
    profile["vmwp_sha256"] = "0" * 64
    if profile["vmwp_sha256"].lower() == original_hash.lower():
        raise k4.GateFailure("the mismatch profile accidentally matches the real profile")
    bad_profile = HERE / "vmwp-dispatcher-profile-mismatch.json"
    bad_profile.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")

    command = [
        str(ROOT / "target" / "debug" / "windbg-mcp.exe"),
        "--sk-live-control",
        "--profile", str(bad_profile),
        "--control-transport", config["control_transport"],
        "--live-transport", config["live_transport"],
        "--vmwp-pid", str(config["vmwp_pid"]),
        "--dispatcher-vnd", config["dispatcher_vnd"],
        "--vm-id", config["vm_id"],
        "--partition-id", config["partition_id"],
        "--expected-cr3", config["expected_cr3"],
        "--vp", str(config.get("vp", 0)),
        "--instruction-address", config["instruction_address"],
        "--instruction-bytes", config["instruction_bytes"],
        "--arm-mode", config.get("arm_mode", "redirect"),
    ]
    result = {
        "schema": "windbg-mcp.private.live-build-mismatch.v1",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "vm_id": config["vm_id"],
        "vmwp_pid": config["vmwp_pid"],
        "partition_id": config["partition_id"],
        "result": "running",
    }
    path = HERE / "live-build-mismatch-result.json"
    try:
        completed = subprocess.run(
            command, cwd=ROOT, text=True, capture_output=True, timeout=180
        )
        result["exit_code"] = completed.returncode
        result["stderr"] = completed.stderr
        if completed.returncode == 0:
            raise k4.GateFailure("mismatched profile was accepted")
        if "vmwp SHA-256 does not match" not in completed.stderr:
            raise k4.GateFailure("failure did not name the vmwp SHA-256 guard")

        result["health_after_refusal"] = k4.health(
            int(config["vmwp_pid"]), "after-build-mismatch"
        )
        k4.pause_vm()
        probe = Probe()
        try:
            after = snapshot(probe, int(config["partition_id"], 0), int(config.get("vp", 0)))
        finally:
            probe.close()
        before = prep["snapshot"]
        for name in ("dr0", "dr1", "dr2", "dr3", "dr6", "dr7"):
            if after["registers"][name] != before["registers"][name]:
                raise k4.GateFailure(f"build mismatch changed {name}")
        flags = int(after["registers"]["rflags"]["low"], 0)
        if flags & ((1 << 8) | (1 << 16)):
            raise k4.GateFailure("build mismatch left TF or RF set")
        result["state_after_refusal"] = after
        result["sentinel_after_refusal"] = k4.live_target(
            int(config["partition_id"], 0), HERE / "build-mismatch-sentinel-after.json"
        )
        if result["sentinel_after_refusal"]["live_read_1"] != prep["sentinel"]["live_read_1"]:
            raise k4.GateFailure("build mismatch changed guarded Secure Kernel text")
        result["vm_left_paused_for_next_gate"] = True
        result["result"] = "pass"
    except Exception as error:
        result["result"] = "fail"
        result["error"] = str(error)
        try:
            k4.stop_bench()
        except Exception as cleanup:
            result["cleanup_error"] = str(cleanup)
        raise
    finally:
        result["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
