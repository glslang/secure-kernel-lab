from __future__ import annotations

import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from sklab.cli import parse_overrides, resolve_module
from sklab.config import load
from sklab import m8
from sklab.modules import ALL_MODULES, core


class ModuleTests(unittest.TestCase):
    def test_catalog_contains_only_supported_client_workflows(self) -> None:
        self.assertEqual(
            set(ALL_MODULES),
            {
                "capture.inspect",
                "live.decode",
                "live.ambient",
                "kd.manual",
                "kd.external",
                "kd.debugger",
                "validate.kd-post-audit",
                "validate.live",
                "validate.kd",
                "validate.m8",
            },
        )
        self.assertIs(resolve_module("kd.manual"), ALL_MODULES["kd.manual"])
        self.assertEqual(
            parse_overrides(["free-run-cycles=0x10", "post-audit=false"]),
            {"free_run_cycles": 16, "post_audit": False},
        )

    def test_m8_open_arguments_select_the_builtin_for_both_roles(self) -> None:
        config = load(Path(__file__).parents[1] / "config.example.toml")
        opened = m8.open_arguments(config, config.target("demo"), arm_mode="redirect")
        self.assertEqual(opened["control_transport"], "builtin:h3probe")
        self.assertEqual(opened["live_transport"], "builtin:h3probe")

    def test_managed_kd_config_is_natural_and_builtin_only(self) -> None:
        config = mock.Mock()
        target = mock.Mock()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            kit = root / "kit"
            symbols = root / "symbols"
            kit.mkdir()
            symbols.mkdir()
            (kit / "kd.exe").touch()
            config.paths.cdb_exe = kit / "cdb.exe"
            config.paths.symbol_path = symbols
            config.defaults.connect_timeout_ms = 120_000
            config.defaults.idle_timeout_ms = 300_000
            config.defaults.arm_mode = "redirect"
            config.source = root / "config.toml"
            target.profile = root / "profile.json"
            target.profile.write_text(
                '{"secure_kernel_kd":{"initial":{"rva":"0xb12b","original":[15]}}}',
                encoding="utf-8",
            )
            target.vm_id = "vm-id"
            target.vp = 0
            target.name = "k3"
            destination = root / "managed-kd.json"
            m8.write_managed_kd_config(config, target, destination)
            value = json.loads(destination.read_text(encoding="utf-8"))
            profile = json.loads((root / "managed-kd-profile.json").read_text(encoding="utf-8"))

        self.assertEqual(value["arm_mode"], "natural")
        self.assertEqual(value["kd"], str(kit / "kd.exe"))
        self.assertEqual(value["control_transport"], "builtin:h3probe")
        self.assertEqual(value["live_transport"], "builtin:h3probe")
        self.assertEqual(value["trigger"][-2:], ["--count", "1"])
        self.assertEqual(value["post_release_audit"][-2:], ["--survival-seconds", "60"])
        self.assertEqual(profile["secure_kernel_kd"]["initial"]["rva"], m8.NATURAL_STOP_RVA)
        self.assertEqual(profile["secure_kernel_kd"]["initial"]["original"], [72, 131, 236, 8])

    def test_live_ambient_arms_the_four_measured_interrupt_entries(self) -> None:
        armed = core._ambient_breakpoints(0x10000000)
        self.assertEqual(armed["instruction_address"], "0x100e7670")
        self.assertEqual(armed["instruction_bytes"], "4883ec08")
        self.assertEqual(armed["slot"], 0)
        self.assertEqual(
            [(row["address"], row["slot"]) for row in armed["additional_breakpoints"]],
            [("0x100e8f70", 1), ("0x100e8100", 2), ("0x100f6cc0", 3)],
        )

    def test_live_ambient_allows_the_measured_transition_cr3(self) -> None:
        context = mock.Mock()
        context.run_dir = Path("run")
        context.target.profile = "measured"
        context.target.vp = 0
        context.target.vm_id = "vm-id"
        context.target.name = "k3"
        context.target.secure_kernel_image = Path("securekernel.exe")
        context.config.source = Path("config.toml")
        context.config.paths.windbg_mcp_exe = Path("windbg-mcp.exe")
        context.config.paths.windbg_mcp_repo = Path("windbg-mcp")
        written: dict[str, object] = {}
        shaped = mock.Mock(returncode=0, stdout="SHAPE cr3=0x2601000 kernel_base=0x10000000\n")
        with (
            mock.patch.object(core, "_require_checks"),
            mock.patch.object(core.bench_bridge, "discover", return_value=(42, 7, 9, 11, "test")),
            mock.patch.object(core.subprocess, "run", return_value=shaped),
            mock.patch.object(core, "atomic_json", side_effect=lambda _path, value: written.update(value)),
            mock.patch.object(core, "write_policy"),
        ):
            core.live_ambient(context, {})
        self.assertIs(written["allow_transition_cr3"], True)
        self.assertEqual(written["expected_cr3"], "0x2601000")
        self.assertEqual(written["trigger"][-2:], ["--count", "1"])

    def test_m8_trigger_waits_for_a_debugger_owned_pause_to_end(self) -> None:
        target = mock.Mock()
        target.vm_id = "00000000-0000-0000-0000-000000000000"
        target.vm_name = "test-vm"
        target.guest_spin_host = r"C:\host.exe"
        target.guest_enclave_image = r"C:\enclave.dll"
        with tempfile.TemporaryDirectory() as directory:
            credential = Path(directory) / "guest.json"
            credential.write_text("{}", encoding="utf-8")
            target.guest_credential_file = credential
            completed = mock.Mock(
                returncode=0,
                stdout='{"requested_count":1,"exit_code":0}',
                stderr="",
            )
            with mock.patch.object(m8.subprocess, "run", return_value=completed) as run:
                self.assertEqual(m8.trigger_enclave(target, 1)["exit_code"], 0)

        command = run.call_args.args[0][-1]
        self.assertIn("AddSeconds(30)", command)
        self.assertIn("$state -eq 'Paused'", command)
        self.assertIn("TotalMilliseconds -ge 500", command)
        self.assertNotIn("Resume-VM", command)

    def test_kd_command_is_published_only_after_the_pipe_is_ready(self) -> None:
        context = mock.Mock()
        context.cancelled.return_value = False
        context.output.stream = io.StringIO()
        client = mock.Mock()
        command = "windbg.exe -k com:pipe,port=ready"
        with (
            mock.patch.object(core, "_kd_phase", side_effect=["running", "waiting_for_peer", "released"]),
            mock.patch.object(core.time, "sleep"),
        ):
            self.assertEqual(core._monitor_kd(context, client, "session", command), "released")
        self.assertEqual(context.output.stream.getvalue().count(command), 1)


if __name__ == "__main__":
    unittest.main()
