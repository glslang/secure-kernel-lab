import argparse
import json
import pathlib
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run_k4_stop_step as k4


def low(row):
    return int(row["low"], 0)


parser = argparse.ArgumentParser()
parser.add_argument("--registers-text-only", action="store_true")
args = parser.parse_args()
prepared = json.loads((HERE / "rust-adapter-input.json").read_text())
k4.EXPECTED_CR3 = int(prepared["target"]["cr3"], 0)
k4.TARGET_RVA = int(prepared["target"]["target_va"], 0) - int(prepared["target"]["securekernel_base"], 0)
k4.TARGET_BYTES = bytes.fromhex(prepared["target"]["instruction_bytes"])
pid = int(prepared["pid"])
partition = int(prepared["partition"], 0)
result = {
    "schema": "windbg-mcp.private.managed-kd-post-audit.v1",
    "vmwp_pid": pid,
    "partition_id": prepared["partition"],
    "survival": [],
}
control = None
paused = False
try:
    if args.registers_text_only:
        previous = json.loads((HERE / "managed-kd-post-audit.json").read_text())
        result["survival"] = previous["survival"]
    else:
        result["survival"].append(k4.health(pid, "immediate"))
        time.sleep(30)
        result["survival"].append(k4.health(pid, "30s"))
        time.sleep(30)
        result["survival"].append(k4.health(pid, "60s"))
    k4.pause_vm()
    paused = True
    control = k4.ControlClient(partition)
    control.begin_arm()
    snapshot = control.snapshot()
    registers = snapshot["registers"]
    debug = {name: registers[name] for name in ("dr0", "dr1", "dr2", "dr3", "dr6", "dr7")}
    if low(registers["dr7"]) & 0xff:
        raise k4.GateFailure(f"active debug breakpoint remained after release: {debug}")
    if low(registers["rflags"]) & ((1 << 8) | (1 << 16)):
        raise k4.GateFailure(f"TF/RF remained set after release: {registers['rflags']}")
    result["debug_registers"] = debug
    result["rflags"] = registers["rflags"]
    control.finish_arm()
    control.close()
    control = None
    target = k4.live_target(partition, HERE / "managed-kd-target-after.json")
    if target["live_read_1"] != prepared["target"]["live_read_1"]:
        raise k4.GateFailure("guarded Secure Kernel text changed")
    result["target_after"] = target
    result["result"] = "pass"
finally:
    if control is not None:
        try:
            if control.phase == "arming":
                control.finish_arm()
            control.close()
        except Exception as error:
            result["control_cleanup_error"] = str(error)
    if paused:
        try:
            k4.resume_vm()
        except Exception as error:
            result["resume_error"] = str(error)
    (HERE / "managed-kd-post-audit.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
