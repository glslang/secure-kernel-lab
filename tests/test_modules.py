from __future__ import annotations

import io
import json
from dataclasses import replace
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from sklab.cli import parse_overrides, resolve_module
from sklab.errors import RecoveryRequired
from sklab.modules import ALL_MODULES
from sklab.modules import core
from sklab import m8
from sklab.config import load


class ModuleTests(unittest.TestCase):
    def test_core_catalog_is_present(self) -> None:
        expected = {
            "capture.inspect",
            "live.decode",
            "live.registers",
            "live.ambient",
            "live.transition",
            "kd.manual",
            "kd.external",
            "kd.debugger",
            "validate.m8",
        }
        self.assertTrue(expected.issubset(ALL_MODULES))

    def test_the_write_proof_is_in_the_advanced_catalog_under_its_provider_neutral_name(self) -> None:
        module = ALL_MODULES["validate.memory-write"]
        self.assertEqual(module.risk, "target-control")
        self.assertNotIn("validate.hvmm-write", ALL_MODULES)
        self.assertFalse([name for name in ALL_MODULES if "hvmm" in name])

    def test_numeric_and_named_module_selection_match(self) -> None:
        self.assertIs(resolve_module("1"), next(iter(ALL_MODULES.values())))
        self.assertIs(resolve_module("kd.manual"), ALL_MODULES["kd.manual"])

    def test_cli_overrides_are_typed(self) -> None:
        self.assertEqual(parse_overrides(["steps=0x10", "cross-check=false"]), {"steps": 16, "cross_check": False})

    def test_m8_open_arguments_are_discovered_and_transition_capable(self) -> None:
        config = load(Path(__file__).parents[1] / "config.example.toml")
        target = config.target("demo")
        opened = m8.open_arguments(config, target, arm_mode="redirect")

        self.assertEqual(opened["vm_id"], target.vm_id)
        self.assertEqual(opened["arm_mode"], "redirect")
        self.assertIn("--allow-transition-cr3", opened["control_transport"])
        self.assertIn("--vp {vp}", opened["control_transport"])
        for per_boot in ("vmwp_pid", "partition_id", "expected_cr3", "kernel_base"):
            self.assertNotIn(per_boot, opened)

    def test_kd_command_is_published_only_after_the_pipe_is_ready(self) -> None:
        context = mock.Mock()
        context.cancelled.return_value = False
        context.output.stream = io.StringIO()
        timeline: list[tuple[str, str]] = []
        context.manifest.add_event.side_effect = (
            lambda _event, *, phase: timeline.append(("phase", phase))
        )
        context.manifest.update.side_effect = (
            lambda *, debugger_command: timeline.append(("command", debugger_command))
        )
        client = mock.Mock()
        command = "windbg.exe -k com:pipe,port=ready"

        with (
            mock.patch.object(
                core,
                "_kd_phase",
                side_effect=["running", "waiting_for_peer", "released"],
            ),
            mock.patch.object(core.time, "sleep"),
        ):
            final_phase = core._monitor_kd(context, client, "session", command)

        self.assertEqual(final_phase, "released")
        self.assertEqual(
            timeline,
            [
                ("phase", "running"),
                ("phase", "waiting_for_peer"),
                ("command", command),
                ("phase", "released"),
            ],
        )
        output = context.output.stream.getvalue()
        self.assertEqual(output.count(command), 1)
        messages = [call.args[1] for call in context.output.event.call_args_list]
        self.assertTrue(any("ordinary g" in message for message in messages))
        self.assertTrue(any("guarded INT3" in message for message in messages))
        self.assertTrue(any("Ctrl+Break" in message and "M2" in message for message in messages))
        self.assertTrue(any("NT process/thread extensions" in message for message in messages))

    def test_m8_qualification_config_is_generated_from_the_lab(self) -> None:
        config = load(Path(__file__).parents[1] / "config.example.toml")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            classic = root / "windbg.exe"
            windbgx = root / "WinDbgX.exe"
            symbols = root / "symbols"
            classic.write_bytes(b"")
            windbgx.write_bytes(b"")
            symbols.mkdir()
            configured = replace(
                config,
                paths=replace(
                    config.paths,
                    classic_debugger_exe=classic,
                    windbgx_exe=windbgx,
                    symbol_path=symbols,
                ),
            )
            path = m8.write_qualification_config(
                configured,
                configured.target("demo"),
                root / "qualification",
            )
            value = json.loads(path.read_text(encoding="utf-8"))
            hardware = json.loads(Path(value["policies"]["hardware"]).read_text(encoding="utf-8"))
            int3 = json.loads(Path(value["policies"]["int3"]).read_text(encoding="utf-8"))

        self.assertEqual(value["schema"], m8.M8_SCHEMA)
        self.assertEqual(value["frontends"], {"classic": str(classic), "windbgx": str(windbgx)})
        self.assertEqual(value["trigger"][-1], "{count}")
        self.assertIn("sklab.m8_helper", value["boot_probe"])
        self.assertIn("sklab.m8_helper", value["post_release_audit"])
        self.assertNotIn("allow_memory_writes", hardware)
        self.assertIs(int3["allow_memory_writes"], True)
        self.assertEqual(value["open"]["connect_timeout_ms"], 60_000)
        self.assertEqual(value["open"]["idle_timeout_ms"], 60_000)

    def test_composite_debugger_uses_the_generic_m8_tool_sequence(self) -> None:
        calls: list[str] = []
        execution = 0

        class Client:
            stderr = (
                "KD go to 1 hardware breakpoint(s)\n"
                "KD restored the hit hardware-breakpoint handle\n"
                "KD go with no breakpoint\n"
                "KD break-in woke the running wait\n"
            )

            def initialize(self):
                return {"serverInfo": {"name": "test"}}

            def tool(self, name, arguments, _timeout=60):
                nonlocal execution
                calls.append(name)
                if name == "open_sk_debugger":
                    return {"session_id": "sk"}
                if name == "continue_async":
                    execution += 1
                    return {"running": True, "execution": f"run-{execution}"}
                if name == "wait_for_stop":
                    return {
                        "stop": {
                            "stopped_at": "0xfffff80000001000",
                            "interrupted": execution > 1,
                        }
                    }
                return {"status": "ok", "stopped_at": "0xfffff80000001001"}

            def tool_text(self, name, _arguments, _timeout=60):
                calls.append(name)
                return "symbols reloaded"

            def end_session(self, _session_id, _timeout=90):
                return {"status": "ok", "released": True, "target_left_running": True}

            def close(self, **_arguments):
                return None

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = SimpleNamespace(
                source=root / "config.toml",
                defaults=SimpleNamespace(
                    arm_mode="redirect",
                    connect_timeout_ms=120_000,
                    idle_timeout_ms=300_000,
                    max_pause_ms=600_000,
                ),
                paths=SimpleNamespace(
                    symbol_path=root,
                    windbg_mcp_exe=root / "windbg-mcp.exe",
                    windbg_mcp_repo=root,
                ),
            )
            target = SimpleNamespace(
                name="k3",
                vm_name="K3",
                profile=root / "profile.json",
                secure_kernel_image=root / "securekernel.exe",
                vm_id="00000000-0000-0000-0000-000000000001",
                vp=0,
                disposable=True,
            )
            context = SimpleNamespace(
                config=config,
                target=target,
                run_dir=root,
                require_disposable=mock.Mock(),
                confirm=mock.Mock(),
            )
            client = Client()
            with (
                mock.patch.object(core, "_require_checks"),
                mock.patch.object(core, "write_policy"),
                mock.patch.object(core, "McpClient", return_value=client),
                mock.patch.object(core.subprocess, "Popen", return_value=mock.Mock()),
                mock.patch.object(
                    core,
                    "_wait_trigger",
                    return_value={"exit_code": 0, "stdout": "{}", "stderr": ""},
                ),
                mock.patch.object(core, "_post_kd_audit", return_value={"result": "pass"}),
                mock.patch.object(core, "atomic_json"),
            ):
                result = core.kd_debugger(context, {"free_run_cycles": 1})

        for tool in (
            "open_sk_debugger",
            "set_symbol_path",
            "modules",
            "set_breakpoint",
            "continue_async",
            "wait_for_stop",
            "registers",
            "backtrace",
            "disassemble",
            "step_into",
            "clear_breakpoints",
            "break_in",
        ):
            self.assertIn(tool, calls)
        self.assertEqual(len(result["break_ins"]), 1)
        self.assertEqual(result["post_release_audit"], {"result": "pass"})

    def test_kd_command_is_not_published_when_readiness_fails(self) -> None:
        context = mock.Mock()
        context.cancelled.return_value = False
        context.output.stream = io.StringIO()
        client = mock.Mock()

        with (
            mock.patch.object(core, "_kd_phase", side_effect=["running", "failed"]),
            mock.patch.object(core.time, "sleep"),
            self.assertRaises(RecoveryRequired),
        ):
            core._monitor_kd(context, client, "session", "do-not-print")

        self.assertNotIn("do-not-print", context.output.stream.getvalue())
        messages = [call.args[1] for call in context.output.event.call_args_list]
        self.assertFalse(any("lm m securekernel" in message for message in messages))
        context.manifest.update.assert_not_called()

    def test_post_kd_audit_carries_the_checked_target_identity(self) -> None:
        identity = {"name": "Hyper-V target identity", "status": "ok", "detail": "target"}
        state = {"name": "Hyper-V target state", "status": "ok", "detail": "Running"}
        registers = {
            name: {"low": "0x0"}
            for name in ("dr0", "dr1", "dr2", "dr3", "dr6", "dr7", "rflags")
        }
        control = mock.Mock(phase="stopped")
        control.snapshot.return_value = {"registers": registers}
        k4 = SimpleNamespace(
            pause_vm=mock.Mock(),
            resume_vm=mock.Mock(),
            ControlClient=mock.Mock(return_value=control),
            health=mock.Mock(return_value={"status": "ok"}),
        )
        source = mock.Mock()
        guest = mock.Mock()
        guest.read.return_value = b"\x90" * 16
        memory = SimpleNamespace(
            vtl1_identity=mock.Mock(
                return_value={"cr3": 0x1201000, "idtr_base": 0x2000, "idtr_limit": 0x100}
            ),
            H3Source=mock.Mock(return_value=source),
            GuestVirtual=mock.Mock(return_value=guest),
            find_secure_kernel_base=mock.Mock(return_value=(0x1000, {"method": "test"})),
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / "profile.json"
            profile.write_text(
                '{"secure_kernel_kd":{"initial":{"rva":"0x10","original":[144]}}}',
                encoding="utf-8",
            )
            target = SimpleNamespace(profile=profile, secure_kernel_image=root / "securekernel.exe", vp=0)
            context = SimpleNamespace(
                target=target,
                config=mock.Mock(),
                run_dir=root,
            )
            with (
                mock.patch.object(core, "doctor", return_value=[identity, state]),
                mock.patch.object(core, "module_loaded", side_effect=[False, False]),
                mock.patch.object(
                    core.bench_bridge,
                    "discover",
                    return_value=(123, None, 0x44, 0x1B, {"source": "test"}),
                ),
                mock.patch.object(core.bench_bridge, "configure", return_value={"k4": k4}),
                mock.patch.object(core.bench_bridge, "_module", return_value=memory) as module,
                mock.patch.object(core, "atomic_json"),
                mock.patch.object(core.time, "sleep"),
            ):
                result = core._post_kd_audit(context, survival_seconds=60)

        self.assertIs(result["identity"], identity)
        self.assertEqual(len(result["survival"]), 3)
        self.assertEqual(
            [call.args[1] for call in k4.health.call_args_list],
            ["post-kd-release-0s", "post-kd-release-30s", "post-kd-release-60s"],
        )
        k4.resume_vm.assert_called_once_with()
        # The guarded text is read through h3probe's memory operation with the discovered
        # vmwp PID, its own handle and the partition ID, and nothing opens hvmm.
        module.assert_called_once_with("guest_physical")
        memory.H3Source.assert_called_once_with(123, 0x44, 0x1B)
        source.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
