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

    def test_vm_identity_and_running_state_are_separate(self) -> None:
        answer = json.dumps(
            {"Name": self.target.vm_name, "State": "Off", "VMId": self.target.vm_id}
        )
        with mock.patch.object(
            doctor.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, answer, ""),
        ):
            identity, state, detail = doctor._vm(self.target)
        self.assertTrue(identity)
        self.assertEqual(state, "Off")
        self.assertIn("(Off)", detail)

    def test_provider_probe_runs_discovery_then_the_builtin_handshake(self) -> None:
        discovery = subprocess.CompletedProcess(
            [], 0, json.dumps({"partition_id": "0x85"}), ""
        )
        provider = subprocess.CompletedProcess([], 0, "capabilities {}", "")
        with mock.patch.object(doctor.subprocess, "run", side_effect=[discovery, provider]) as run:
            row = doctor._provider(self.config, self.target, True)
        self.assertEqual(row["status"], "ok")
        second = run.call_args_list[1].args[0]
        self.assertIn("--sk-control-probe", second)
        self.assertIn("builtin:h3probe", second)
        self.assertNotIn("--expected-cr3", second)


if __name__ == "__main__":
    unittest.main()
