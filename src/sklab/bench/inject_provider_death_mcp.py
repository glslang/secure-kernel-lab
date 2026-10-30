"""Drive provider death over MCP without the happy-path smoke test's panic cleanup."""

import json
import pathlib
import queue
import subprocess
import sys
import threading
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
MCP_EXE = ROOT / "target" / "debug" / "windbg-mcp.exe"
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


class Mcp:
    # `args` reaches the server's own command line. It defaults to none, so every existing caller
    # spawns exactly what it did before. It exists because the run's tool surface is `--tools` and
    # nothing else: the unnamed `WINDBG_MCP_TOOLS` is a *credential's* surface, read only on the
    # listener and service paths (`listen.rs`, `service.rs`), so a stdio server cannot be widened
    # through the environment. Without `--tools all`, `securekernel` -- the one `extra` group -- is
    # absent from the default surface and `open_sk_live_control` is refused `-32602`.
    def __init__(self, args=()):
        self.process = subprocess.Popen(
            [str(MCP_EXE), *args],
            cwd=ROOT,
            text=True,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1,
        )
        self.messages = queue.Queue()
        self.errors = []
        self.next_id = 1
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    def _read_stdout(self):
        assert self.process.stdout is not None
        for line in self.process.stdout:
            try:
                self.messages.put(json.loads(line))
            except Exception as error:
                self.messages.put({"reader_error": f"{error}: {line!r}"})

    def _read_stderr(self):
        assert self.process.stderr is not None
        for line in self.process.stderr:
            self.errors.append(line)

    def send(self, value):
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(value, separators=(",", ":")) + "\n")
        self.process.stdin.flush()

    def request(self, method, params, timeout):
        request_id = self.next_id
        self.next_id += 1
        self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None and self.messages.empty():
                raise k4.GateFailure(f"MCP server exited {self.process.returncode}")
            try:
                message = self.messages.get(timeout=min(0.25, deadline - time.monotonic()))
            except queue.Empty:
                continue
            if message.get("id") == request_id:
                return message
        raise k4.GateFailure(f"MCP {method} exceeded {timeout}s")

    def notify(self, method, params):
        self.send({"jsonrpc": "2.0", "method": method, "params": params})

    def tool(self, name, arguments, timeout=60):
        return self.request(
            "tools/call", {"name": name, "arguments": arguments}, timeout
        )

    def shutdown(self):
        if self.process.stdin is not None:
            self.process.stdin.close()
            self.process.stdin = None
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)


def structured(response):
    if response.get("error") is not None:
        raise k4.GateFailure(f"JSON-RPC error: {response['error']}")
    return response.get("result", {}).get("structuredContent")


def main():
    config = json.loads((HERE / "natural-live-control-input.json").read_text())
    prep = json.loads((HERE / "natural-flow-prep-result.json").read_text())
    if config["vm_id"].lower() != k4.VM_ID.lower() or not config.get("disposable"):
        raise k4.GateFailure("input does not name the allowlisted disposable K3 VM")
    config["control_transport"] += " --exit-before-response publish_stop"

    before_processes = processes()
    before_ids = {int(row["ProcessId"]) for row in before_processes}
    result = {
        "schema": "windbg-mcp.private.live-provider-death-mcp.v1",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "vm_id": config["vm_id"],
        "vmwp_pid": config["vmwp_pid"],
        "partition_id": config["partition_id"],
        "processes_before": before_processes,
        "result": "running",
    }
    path = HERE / "live-provider-death-result.json"
    client = None
    new_workers = []
    try:
        client = Mcp()
        initialized = client.request(
            "initialize",
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "provider-death-gate", "version": "1"},
            },
            15,
        )
        if initialized.get("error") is not None:
            raise k4.GateFailure(f"initialize failed: {initialized}")
        client.notify("notifications/initialized", {})
        opened = client.tool(
            "open_sk_live_control",
            {
                "profile": config["profile"],
                "control_transport": config["control_transport"],
                "live_transport": config["live_transport"],
                "vmwp_pid": config["vmwp_pid"],
                "dispatcher_vnd": config["dispatcher_vnd"],
                "vm_id": config["vm_id"],
                "partition_id": config["partition_id"],
                "vp": config.get("vp", 0),
                "expected_cr3": config["expected_cr3"],
            },
            30,
        )
        opened_data = structured(opened)
        if opened.get("result", {}).get("isError") or opened_data.get("status") != "ok":
            raise k4.GateFailure(f"live open failed: {opened}")
        session = opened_data["session_id"]
        result["session_id"] = session

        armed = client.tool(
            "sk_live_arm",
            {
                "session_id": session,
                "address": config["instruction_address"],
                "bytes": config["instruction_bytes"],
                "mode": config.get("arm_mode", "natural"),
            },
            60,
        )
        armed_data = structured(armed)
        if armed.get("result", {}).get("isError") or armed_data.get("status") != "ok":
            raise k4.GateFailure(f"live arm failed: {armed}")

        started = time.monotonic()
        stopped = client.tool("sk_live_wait", {"session_id": session}, 120)
        result["fault_latency_seconds"] = time.monotonic() - started
        result["wait_response"] = stopped
        if not stopped.get("result", {}).get("isError"):
            raise k4.GateFailure("provider death did not fail the wait")
        if "target_left_paused=true" not in json.dumps(stopped):
            raise k4.GateFailure("provider death did not report fail-closed containment")

        ended = client.tool("end_session", {"session_id": session}, 30)
        result["end_response"] = ended
        if not ended.get("result", {}).get("isError"):
            raise k4.GateFailure("contained session teardown unexpectedly claimed release")
        result["server_stderr"] = "".join(client.errors)
        client.shutdown()
        client = None

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
            row
            for row in after_processes
            if int(row["ProcessId"]) not in before_ids
            and "--engine-worker" in (row.get("CommandLine") or "")
        ]
        result["retained_workers"] = new_workers
        if not new_workers:
            raise k4.GateFailure("no retained engine worker proves unresolved containment")
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
            except Exception as client_error:
                result["client_cleanup_error"] = str(client_error)
        try:
            for row in new_workers:
                pid = int(row["ProcessId"])
                executable = pathlib.Path(row.get("ExecutablePath") or "")
                if executable.resolve() != (ROOT / "target" / "debug" / "windbg-mcp.exe").resolve():
                    raise k4.GateFailure(f"refusing to stop unexpected retained process {pid}")
                k4.ps(f"Stop-Process -Id {pid} -Force -ErrorAction Stop")
            result["retained_workers_stopped_for_disposal"] = True
        except Exception as worker_error:
            result["worker_cleanup_error"] = str(worker_error)
        try:
            time.sleep(3)
            result["vm_before_disposal"] = k4.vm_json()
            k4.ps(
                f"$v=Get-VM -Id '{k4.VM_ID}'; "
                "if($v.State -ne 'Off'){Stop-VM -VM $v -Force -ErrorAction Stop}"
            )
            result["vm_after_cleanup"] = k4.vm_json()
        except Exception as stop_error:
            result["stop_error"] = str(stop_error)
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
