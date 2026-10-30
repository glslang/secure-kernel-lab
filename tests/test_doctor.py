from __future__ import annotations

import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock

from sklab import doctor
from sklab.config import load


EXAMPLE = Path(__file__).resolve().parents[1] / "config.example.toml"


class DoctorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load(EXAMPLE)
        self.target = self.config.target("demo")

    def vm_result(
        self,
        *,
        name: str | None = None,
        state: str = "Running",
    ) -> subprocess.CompletedProcess[str]:
        value = {
            "Name": name or self.target.vm_name,
            "State": state,
            "VMId": self.target.vm_id,
        }
        return subprocess.CompletedProcess([], 0, json.dumps(value), "")

    def test_vm_must_be_running_separately_from_matching_identity(self) -> None:
        with mock.patch.object(doctor.subprocess, "run", return_value=self.vm_result(state="Off")):
            identity, state, detail = doctor._vm(self.target)

        self.assertTrue(identity)
        self.assertEqual(state, "Off")
        self.assertIn("(Off)", detail)

    def test_running_vm_with_matching_identity_is_ready(self) -> None:
        with mock.patch.object(doctor.subprocess, "run", return_value=self.vm_result()):
            identity, state, detail = doctor._vm(self.target)

        self.assertTrue(identity)
        self.assertEqual(state, "Running")
        self.assertIn("(Running)", detail)

    def test_running_vm_with_wrong_name_still_fails_identity(self) -> None:
        with mock.patch.object(doctor.subprocess, "run", return_value=self.vm_result(name="wrong VM")):
            identity, state, _detail = doctor._vm(self.target)

        self.assertFalse(identity)
        self.assertEqual(state, "Running")

    def test_vm_query_failure_has_unknown_state(self) -> None:
        failed = subprocess.CompletedProcess([], 1, "", "access denied")
        with mock.patch.object(doctor.subprocess, "run", return_value=failed):
            identity, state, detail = doctor._vm(self.target)

        self.assertFalse(identity)
        self.assertIsNone(state)
        self.assertEqual(detail, "access denied")

    def test_required_running_state_fails_with_start_command(self) -> None:
        probe = mock.Mock(installed=False, service="h3probe")
        with (
            mock.patch.object(doctor, "_vm", return_value=(True, "Off", "demo (Off) id")),
            mock.patch.object(doctor, "driver_status", side_effect=[probe]),
            mock.patch.object(doctor, "load_manifest", return_value={}),
        ):
            checks = doctor.run(self.config, self.target, required={"running"})

        identity = next(row for row in checks if row["name"] == "Hyper-V target identity")
        state = next(row for row in checks if row["name"] == "Hyper-V target state")
        self.assertEqual(identity["status"], "ok")
        self.assertEqual(state["status"], "error")
        self.assertIn(f"Start-VM -Id '{self.target.vm_id}'", state["detail"])


    def memory_row(self, required: set[str] | None, served: bool = True) -> dict:
        # _drivers as run calls it: the memory row is required where every capability or it is.
        probe = mock.Mock(installed=True, running=True, service="h3probe", state="running", image=None)
        device = mock.Mock()
        with (
            mock.patch.object(doctor, "driver_status", return_value=probe),
            mock.patch.object(doctor, "open_device", return_value=(True, "opened")),
            mock.patch.object(doctor.h3_memory, "Device", return_value=device),
            mock.patch.object(doctor.h3_memory, "capability", return_value=(served, "ABI")),
        ):
            rows = doctor._drivers(self.config, True, required is None or "h3_memory" in required)
        device.close.assert_called_once_with()
        return next(row for row in rows if row["name"] == "h3 memory operation")

    def test_the_memory_operation_is_required_whenever_everything_or_it_is(self) -> None:
        for required in (None, {"h3_memory"}):
            with self.subTest(required=required):
                row = self.memory_row(required, served=False)
                self.assertEqual((row["required"], row["status"]), (True, "error"))
        row = self.memory_row({"h3probe"}, served=False)
        self.assertEqual((row["required"], row["status"]), (False, "warning"))

    def test_run_requires_the_memory_operation_when_nothing_narrows_it(self) -> None:
        with mock.patch.object(doctor, "_drivers", return_value=[]) as drivers,              mock.patch.object(doctor, "load_manifest", return_value={}):
            doctor.run(self.config, None)
            self.assertEqual(drivers.call_args.args[1:], (True, True))
            doctor.run(self.config, None, required={"h3probe"})
            self.assertEqual(drivers.call_args.args[1:], (True, False))

if __name__ == "__main__":
    unittest.main()
