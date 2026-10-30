from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from sklab.config import load
from sklab.policy import write_policy


class PolicyTests(unittest.TestCase):
    def test_policy_pins_target_commands_roots_and_pause(self) -> None:
        root = Path(__file__).resolve().parents[1]
        config = load(root / "config.example.toml")
        target = config.target("demo")
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "policy.json"
            write_policy(config, target, destination)
            policy = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(policy["disposable_vm_ids"], [target.vm_id])
        self.assertEqual(policy["max_pause_ms"], config.defaults.max_pause_ms)
        self.assertIn(str(target.profile.parent), policy["profile_roots"])
        live = next(command for command in policy["transport_commands"] if "gpa_server.py" in command)
        self.assertNotIn("hvmm", live)
        # The capability is served; whether a write is made is the policy's, which grants none here.
        self.assertTrue(live.endswith("--writes"))
        self.assertNotIn("allow_memory_writes", policy)
        self.assertFalse(any("hvmm" in command for command in policy["transport_commands"]))
        self.assertIn("--vmwp-pid {vmwp_pid}", live)
        self.assertIn("--partition-handle {partition_handle}", live)
        self.assertIn("--partition-id {partition_id}", live)
        self.assertIn("--vp {vp}", live)
        self.assertIn(str(target.secure_kernel_image), live)


if __name__ == "__main__":
    unittest.main()
