from __future__ import annotations

from pathlib import Path
import unittest
from unittest import mock

from sklab.config import load
from sklab.context import RunContext
from sklab.errors import PrerequisiteError
from sklab.modules import core


EXAMPLE = Path(__file__).resolve().parents[1] / "config.example.toml"


class LiveDecodeCommandTests(unittest.TestCase):
    def command(self, mode: str = "direct") -> list[str]:
        config = load(EXAMPLE)
        context = RunContext(config, mock.Mock(), mock.Mock(), config.target("demo"))
        context.run_process = mock.Mock()  # type: ignore[method-assign]
        with (
            mock.patch.object(core, "_require_checks"),
            mock.patch.object(
                core.bench_bridge,
                "discover",
                return_value=(4242, 0x12340000, 0x2E0, 7, "repository role"),
            ),
        ):
            result = core.live_decode(context, {"mode": mode})
        self.assertEqual(result["provider"], "builtin:h3probe")
        return context.run_process.call_args.args[0]

    def test_direct_mode_passes_worker_discovered_memory_coordinates(self) -> None:
        command = self.command()
        self.assertEqual(command[command.index("--transport") + 1], "builtin:h3probe")
        self.assertEqual(command[command.index("--pages") + 1], "h3")
        self.assertEqual(command[command.index("--vmwp-pid") + 1], "4242")
        self.assertEqual(command[command.index("--partition-handle") + 1], "0x2e0")

    def test_hypercall_mode_selects_the_built_in_negative_control(self) -> None:
        command = self.command("hypercall")
        self.assertEqual(command[command.index("--pages") + 1], "hypercall")
        self.assertNotIn("--vmwp-pid", command)
        self.assertNotIn("--partition-handle", command)

    def test_unknown_mode_is_refused(self) -> None:
        with self.assertRaises(PrerequisiteError):
            self.command("other")


if __name__ == "__main__":
    unittest.main()
