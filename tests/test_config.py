from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from sklab.config import load
from sklab.errors import PrerequisiteError


class ConfigTests(unittest.TestCase):
    def test_example_configuration_loads_and_resolves_relative_paths(self) -> None:
        config = load(Path(__file__).resolve().parents[1] / "config.example.toml")
        target = config.target("demo")
        self.assertEqual(config.defaults.arm_mode, "redirect")
        self.assertEqual(target.vp, 0)
        self.assertTrue(str(target.profile).endswith("profiles\\vmwp-dispatcher-profile-26100.9711.json"))
        self.assertTrue(target.disposable)

    def test_omitted_arm_mode_defaults_to_redirect(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "defaults.toml"
            path.write_text(
                """
[paths]
windbg_mcp_repo='.'
windbg_mcp_exe='mcp.exe'
windows_kit_root='kit'
""",
                encoding="utf-8",
            )
            self.assertEqual(load(path).defaults.arm_mode, "redirect")

    def test_invalid_hash_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.toml"
            path.write_text(
                """
[paths]
windbg_mcp_repo='.'
windbg_mcp_exe='mcp.exe'
windows_kit_root='kit'
[targets.bad]
vm_id='id'
vm_name='name'
disposable=true
profile='profile.json'
secure_kernel_image='securekernel.exe'
expected_image_sha256='bad'
""",
                encoding="utf-8",
            )
            with self.assertRaises(PrerequisiteError):
                load(path)

    def test_invalid_driver_pin_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad-driver.toml"
            path.write_text(
                """
[paths]
windbg_mcp_repo='.'
windbg_mcp_exe='mcp.exe'
windows_kit_root='kit'
[drivers]
h3probe_sha256='not-a-hash'
""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(PrerequisiteError, "^drivers contains"):
                load(path)

    def test_a_configuration_still_naming_livecloudkd_is_refused(self) -> None:
        stale = {
            "paths.livecloudkd_root": "livecloudkd_root='live'\n",
            "drivers.hvmm_service": "[drivers]\nhvmm_service='hvmm'\n",
        }
        for key, line in stale.items():
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "stale.toml"
                path.write_text(
                    "[paths]\nwindbg_mcp_repo='.'\nwindbg_mcp_exe='mcp.exe'\nwindows_kit_root='kit'\n" + line,
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(PrerequisiteError, f"^{key} is no longer read"):
                    load(path)


if __name__ == "__main__":
    unittest.main()
