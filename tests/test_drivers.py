from __future__ import annotations

from pathlib import Path
import unittest
from unittest import mock

from sklab.cli import _driver_services
from sklab.config import load
from sklab.context import RunContext
from sklab.errors import PrerequisiteError
from sklab.modules import core


EXAMPLE = Path(__file__).resolve().parents[1] / "config.example.toml"


class DriverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = load(EXAMPLE)

    def test_example_configures_one_driver_unpinned(self) -> None:
        self.assertEqual(self.config.drivers.h3probe_service, "h3probe")
        self.assertIsNone(self.config.drivers.h3probe_sha256)
        self.assertFalse(hasattr(self.config.drivers, "hvmm_service"))

    def test_only_h3probe_is_started_and_stopped(self) -> None:
        for action in ("start", "stop", "status"):
            self.assertEqual(_driver_services(self.config, action, None), ["h3probe"])
        self.assertEqual(_driver_services(self.config, "stop", "h3probe"), ["h3probe"])
        for unknown in ("hvmm", "beep"):
            with self.subTest(unknown=unknown), self.assertRaises(PrerequisiteError):
                _driver_services(self.config, "start", unknown)

    def required(self, checker, options: dict) -> set[str]:
        context = RunContext(self.config, mock.Mock(), mock.Mock(), self.config.target("demo"))
        with mock.patch.object(core, "doctor", return_value=[]) as doctor:
            checker(context, options)
        return set(doctor.call_args.kwargs["required"])

    def test_every_control_path_requires_h3probe(self) -> None:
        self.assertIn("h3probe", self.required(core._control_checks, {}))
        self.assertIn("h3probe", self.required(core._kd_checks, {}))
        self.assertIn("h3probe", self.required(core._transition_checks, {}))
        self.assertIn("h3probe", self.required(core._registers_checks, {}))

    def test_live_paths_require_a_running_target(self) -> None:
        self.assertIn("running", self.required(core._common_checks, {}))
        self.assertIn("running", self.required(core._control_checks, {}))
        self.assertIn("running", self.required(core._kd_checks, {}))
        self.assertIn("running", self.required(core._transition_checks, {}))
        self.assertIn("running", self.required(core._registers_checks, {"snapshot": True}))
        self.assertNotIn("running", self.required(core._registers_checks, {}))

    def test_transition_and_kd_audit_need_the_memory_operation_and_neither_external_provider(self) -> None:
        for checks in (core._transition_checks, core._kd_checks):
            required = self.required(checks, {})
            self.assertIn("h3_memory", required)
            self.assertNotIn("hvlib", required)

    def test_both_decode_modes_read_through_h3probe_alone(self) -> None:
        direct = self.required(core._common_checks, {"mode": "direct"})
        hypercall = self.required(core._common_checks, {"mode": "hypercall"})
        self.assertTrue({"h3probe", "h3_memory"} <= direct)
        self.assertIn("h3probe", hypercall)
        self.assertNotIn("h3_memory", hypercall)  # the refusing hypercall needs no memory operation
        self.assertFalse({"hvlib", "hvmm"} & (direct | hypercall))

    def test_the_gate_alone_does_not_need_the_target(self) -> None:
        self.assertEqual(self.required(core._registers_checks, {}), {"administrator", "h3probe"})
        self.assertIn("identity", self.required(core._registers_checks, {"snapshot": True}))

    def test_vps_accepts_console_forms(self) -> None:
        self.assertEqual(core._vps(None, 0, (1,)), [0, 1])
        self.assertEqual(core._vps(2, 0, (1,)), [2])
        self.assertEqual(core._vps("0,1", 0, ()), [0, 1])


if __name__ == "__main__":
    unittest.main()
