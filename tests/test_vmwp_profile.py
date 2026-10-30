from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import types
import unittest
from unittest import mock

from sklab.cli import main as cli_main
from sklab.config import load
from sklab.vmwp_profile import (
    ProfileError,
    default_report_path,
    generate,
    validate_existing_candidate,
    write_new,
)


SITES = {
    "discovery.entry": (0x1100, bytes.fromhex("1020304050607080")),
    "event_held": (0x1120, bytes.fromhex("1121314151617181")),
    "callback_entry": (0x1140, bytes.fromhex("1222324252627282")),
    "handle_return": (0x1160, bytes.fromhex("1323334353637383")),
    "native_return": (0x1180, bytes.fromhex("1424344454647484")),
    "deferred_cleanup": (0x11A0, bytes.fromhex("1525354555657585")),
}
FUNCTIONS = {
    "register_handler_rva": (0x1200, 0x1300, bytes.fromhex("a110213243546576")),
    "unregister_handler_rva": (0x1240, 0x1340, bytes.fromhex("a211223344556677")),
    "callback_stub_rva": (0x1280, 0x1380, bytes.fromhex("a312233445566778")),
}
RESUME = (0x11C0, bytes.fromhex("202122232425262728292a2b2c2d2e2f"))
EXAMPLE = Path(__file__).resolve().parents[1] / "config.example.toml"


def make_pe(path: Path, mappings: dict[int, bytes], *, timestamp: int, size_of_image: int) -> None:
    data = bytearray(b"\xCC" * 0x3200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, timestamp, 0, 0, 0xF0, 0x2022)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 56, size_of_image)
    section = optional + 0xF0
    struct.pack_into(
        "<8sIIIIIIHHI",
        data,
        section,
        b".text\0\0\0",
        0x3000,
        0x1000,
        0x3000,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    for rva, value in mappings.items():
        offset = 0x200 + rva - 0x1000
        data[offset : offset + len(value)] = value
    path.write_bytes(data)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest().upper()


class VmwpProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.old = self.root / "old-vmwp.exe"
        self.new = self.root / "new-vmwp.exe"
        self.vid = self.root / "vid.dll"
        old_mappings = {rva: value for rva, value in SITES.values()}
        old_mappings.update({old: value for old, _new, value in FUNCTIONS.values()})
        old_mappings[RESUME[0]] = RESUME[1]
        new_mappings = {rva: value for rva, value in SITES.values()}
        new_mappings.update({new: value for _old, new, value in FUNCTIONS.values()})
        new_mappings[RESUME[0]] = RESUME[1]
        make_pe(self.old, old_mappings, timestamp=1, size_of_image=0x4000)
        make_pe(self.new, new_mappings, timestamp=2, size_of_image=0x5000)
        make_pe(self.vid, {}, timestamp=3, size_of_image=0x3000)
        self.baseline = self.root / "baseline.json"
        self.baseline.write_text(json.dumps(self.profile()) + "\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def profile(self) -> dict:
        def site(name: str) -> dict:
            rva, value = SITES[name]
            return {"rva": f"0x{rva:016x}", "original": list(value)}

        return {
            "schema": "windbg-mcp.sk-live-dispatcher-profile.v1",
            "vmwp_image": r"C:\Windows\System32\vmwp.exe",
            "vmwp_sha256": sha256(self.old),
            "vmwp_size_of_image": 0x4000,
            "scratch_base": "0x0000020000000000",
            "scratch_size": 4096,
            "registration_tag": "0x4b344155544f5354",
            **{name: f"0x{old:016x}" for name, (old, _new, _value) in FUNCTIONS.items()},
            "callback_resume_rva": f"0x{RESUME[0]:016x}",
            "discovery": {
                "entry": site("discovery.entry"),
                "vid_image": r"C:\Windows\System32\vid.dll",
                "vid_sha256": "0" * 64,
                "vid_size_of_image": 1,
            },
            "secure_kernel_kd": {"build": 26100},
            **{name: site(name) for name in SITES if name != "discovery.entry"},
            "layout": {"returned_context": 0},
        }

    def generate(self):
        return generate(self.baseline, self.old, self.new, self.vid, prefix_bytes=8)

    def test_generation_moves_unique_functions_and_updates_both_images(self) -> None:
        result = self.generate()

        self.assertEqual(result.candidate["vmwp_sha256"], sha256(self.new))
        self.assertEqual(result.candidate["vmwp_size_of_image"], 0x5000)
        self.assertEqual(result.candidate["discovery"]["vid_sha256"], sha256(self.vid))
        self.assertEqual(result.candidate["discovery"]["vid_size_of_image"], 0x3000)
        for name, (_old, new, _value) in FUNCTIONS.items():
            self.assertEqual(result.candidate[name], f"0x{new:016x}")
            self.assertEqual(
                result.report["function_prefixes"][name]["selection"],
                "unique-prefix-match",
            )
        self.assertEqual(result.report["status"], "offline-pass")
        self.assertEqual(result.report["live_validation"]["status"], "not-run")
        self.assertTrue(result.report["candidate"]["review_required"])
        self.assertFalse(result.report["candidate"]["activated"])
        self.assertEqual(result.candidate["layout"], {"returned_context": 0})
        self.assertEqual(result.candidate["secure_kernel_kd"], {"build": 26100})

    def test_a_moved_guarded_site_is_selected_only_when_its_bytes_are_unique(self) -> None:
        moved = 0x1500
        mappings = {rva: value for name, (rva, value) in SITES.items() if name != "event_held"}
        mappings[moved] = SITES["event_held"][1]
        mappings.update({new: value for _old, new, value in FUNCTIONS.values()})
        mappings[RESUME[0]] = RESUME[1]
        make_pe(self.new, mappings, timestamp=2, size_of_image=0x5000)

        result = self.generate()

        self.assertEqual(result.candidate["event_held"]["rva"], f"0x{moved:016x}")
        self.assertEqual(
            result.report["guarded_sites"]["event_held"]["selection"],
            "unique-byte-match",
        )

    def test_an_ambiguous_function_prefix_requires_manual_derivation(self) -> None:
        data = bytearray(self.new.read_bytes())
        duplicate = 0x1400
        offset = 0x200 + duplicate - 0x1000
        data[offset : offset + 8] = FUNCTIONS["register_handler_rva"][2]
        self.new.write_bytes(data)

        with self.assertRaisesRegex(ProfileError, "register_handler_rva.*2 executable matches"):
            self.generate()

    def test_outputs_are_new_and_an_existing_candidate_is_never_overwritten(self) -> None:
        candidate = self.root / ".state" / "candidate.json"
        written_candidate, written_report = write_new(self.generate(), candidate)

        self.assertEqual(written_candidate, candidate.resolve())
        self.assertEqual(written_report, default_report_path(candidate).resolve())
        self.assertTrue(json.loads(candidate.read_text())["vmwp_sha256"])
        with self.assertRaisesRegex(ProfileError, "refusing to overwrite"):
            write_new(self.generate(), candidate)

    def test_existing_candidate_validation_uses_the_same_derivation(self) -> None:
        candidate = self.root / "candidate.json"
        candidate.write_text(json.dumps(self.generate().candidate), encoding="utf-8")

        report = validate_existing_candidate(
            self.baseline,
            candidate,
            self.old,
            self.new,
            self.vid,
            prefix_bytes=8,
        )

        self.assertTrue(report["candidate"]["validated"])

    def test_cli_runs_without_a_lab_configuration(self) -> None:
        candidate = self.root / "candidate.json"
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = cli_main(
                [
                    "--no-color",
                    "profile",
                    "vmwp",
                    "--baseline",
                    str(self.baseline),
                    "--old-image",
                    str(self.old),
                    "--new-image",
                    str(self.new),
                    "--vid-image",
                    str(self.vid),
                    "--prefix-bytes",
                    "8",
                    "--output",
                    str(candidate),
                ]
            )

        self.assertEqual(code, 0, stdout.getvalue())
        self.assertTrue(candidate.is_file())
        self.assertIn("was not activated", stdout.getvalue())

    def test_optional_live_validation_uses_an_ephemeral_target_profile(self) -> None:
        candidate = self.root / ".state" / "live-candidate.json"
        config = load(EXAMPLE)
        original_profile = config.target("demo").profile
        run_dir = self.root / "runs" / "live-validation"
        stdout = io.StringIO()
        with (
            redirect_stdout(stdout),
            mock.patch("sklab.cli._load", return_value=config),
            mock.patch(
                "sklab.cli.execute_module",
                return_value=types.SimpleNamespace(run_dir=run_dir),
            ) as execute,
        ):
            code = cli_main(
                [
                    "--no-color",
                    "--target",
                    "demo",
                    "profile",
                    "vmwp",
                    "--baseline",
                    str(self.baseline),
                    "--old-image",
                    str(self.old),
                    "--new-image",
                    str(self.new),
                    "--vid-image",
                    str(self.vid),
                    "--prefix-bytes",
                    "8",
                    "--output",
                    str(candidate),
                    "--live-validate",
                    "--live-steps",
                    "2",
                    "--yes",
                ]
            )

        self.assertEqual(code, 0, stdout.getvalue())
        configured = execute.call_args.args[0]
        selected = configured.target("demo")
        self.assertEqual(selected.profile, candidate.resolve())
        self.assertEqual(selected.expected_vmwp_sha256, sha256(self.new))
        self.assertEqual(config.target("demo").profile, original_profile)
        self.assertEqual(execute.call_args.kwargs["overrides"], {"steps": 2})
        live = json.loads((candidate.parent / "live-candidate.live.json").read_text())
        self.assertEqual(live["status"], "pass")
        self.assertFalse(live["config_changed"])
        self.assertEqual(live["run_dir"], str(run_dir))


if __name__ == "__main__":
    unittest.main()
