from __future__ import annotations

from dataclasses import replace
import io
from pathlib import Path
import subprocess
import unittest
from unittest import mock

from sklab import vm_disk
from sklab.cli import _parser, run_vm
from sklab.config import load
from sklab.errors import PrerequisiteError, RecoveryRequired
from sklab.output import Output


EXAMPLE = Path(__file__).resolve().parents[1] / "config.example.toml"


def disk_status() -> dict[str, object]:
    return {
        "vm_name": "Disposable Secure Kernel demo VM",
        "vm_id": "00000000-0000-0000-0000-000000000000",
        "state": "Off",
        "disk_path": r"D:\lab\old.vhdx",
        "disk_type": "Differencing",
        "parent_path": r"D:\lab\parent.vhdx",
        "file_size_bytes": 20 * 1024**3,
        "logical_size_bytes": 64 * 1024**3,
    }


class VmDiskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load(EXAMPLE)
        self.target = replace(
            self.config.target("demo"),
            parent_disk=Path(r"D:\lab\parent.vhdx"),
        )

    def test_status_uses_exact_vm_identity_and_reports_the_attached_vhd(self) -> None:
        with mock.patch.object(vm_disk, "_invoke", return_value=disk_status()) as invoke:
            self.assertEqual(vm_disk.status(self.target)["state"], "Off")
        script = invoke.call_args.args[0]
        self.assertIn("Get-VM -Id '00000000-0000-0000-0000-000000000000'", script)
        self.assertIn("VM identity mismatch", script)
        self.assertIn("Get-VHD -Path $path", script)

    def test_reset_requires_a_disposable_target_and_configured_parent(self) -> None:
        with self.assertRaisesRegex(PrerequisiteError, "disposable"):
            vm_disk.reset(replace(self.target, disposable=False))
        with self.assertRaisesRegex(PrerequisiteError, "parent_disk"):
            vm_disk.reset(replace(self.target, parent_disk=None))

    def test_reset_script_guards_identity_references_parent_and_rollback(self) -> None:
        result = {
            "result": "reset",
            "reclaimed_bytes": 20 * 1024**3,
            "fresh_size_bytes": 2 * 1024**3,
        }
        with mock.patch.object(vm_disk, "_invoke", return_value=result) as invoke:
            self.assertEqual(vm_disk.reset(self.target), result)
        script = invoke.call_args.args[0]
        for expected in (
            "disk reset requires the VM Off",
            "parent disk is not read-only",
            "attached child has unexpected VM or checkpoint references",
            "fresh child did not sustain a healthy boot",
            "superseded child remains referenced",
            "Remove-Item -LiteralPath $old",
            "restored the original disk",
            "SKLAB_RECOVERY_REQUIRED",
        ):
            self.assertIn(expected, script)

    def test_timeout_is_recovery_required_because_attachment_state_is_unknown(self) -> None:
        with mock.patch.object(
            subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired("powershell", 1),
        ):
            with self.assertRaises(RecoveryRequired):
                vm_disk._invoke("ignored", timeout=1)

    def test_cli_has_status_and_confirmed_reset_forms(self) -> None:
        parser = _parser()
        status_args = parser.parse_args(["vm"])
        self.assertEqual(status_args.action, "status")
        reset_args = parser.parse_args(["--target", "demo", "vm", "reset", "--yes"])
        self.assertEqual(reset_args.action, "reset")
        self.assertTrue(reset_args.yes)

    def test_run_vm_does_not_mutate_when_confirmation_is_declined(self) -> None:
        stream = io.StringIO()
        with (
            mock.patch.object(vm_disk, "status", return_value=disk_status()),
            mock.patch.object(vm_disk, "reset") as reset,
        ):
            with self.assertRaisesRegex(PrerequisiteError, "declined"):
                run_vm(
                    self.config,
                    "demo",
                    "reset",
                    Output(stream=stream),
                    confirm=lambda _prompt: False,
                )
        reset.assert_not_called()
        self.assertIn("20.000", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
