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

    def test_sklab_keeps_only_service_lifecycle(self) -> None:
        for action in ("start", "stop", "status"):
            self.assertEqual(_driver_services(self.config, action, None), ["h3probe"])
        with self.assertRaises(PrerequisiteError):
            _driver_services(self.config, "start", "hvmm")

    def test_live_workflows_require_the_repository_owned_provider(self) -> None:
        context = RunContext(self.config, mock.Mock(), mock.Mock(), self.config.target("demo"))
        with mock.patch.object(core, "doctor", return_value=[]) as doctor:
            core._common_checks(context, {})
        required = set(doctor.call_args.kwargs["required"])
        self.assertIn("h3probe", required)
        self.assertIn("running", required)
        self.assertNotIn("h3_memory", required)


if __name__ == "__main__":
    unittest.main()
