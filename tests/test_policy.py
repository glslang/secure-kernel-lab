from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from sklab.config import load
from sklab.policy import BUILTIN_H3PROBE, control_transport, live_transport, write_policy


class PolicyTests(unittest.TestCase):
    def test_policy_admits_only_the_repository_owned_provider(self) -> None:
        root = Path(__file__).resolve().parents[1]
        config = load(root / "config.example.toml")
        target = config.target("demo")
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "policy.json"
            write_policy(config, target, destination)
            policy = json.loads(destination.read_text(encoding="utf-8"))

        self.assertEqual(policy["disposable_vm_ids"], [target.vm_id])
        self.assertEqual(policy["builtin_transports"], [BUILTIN_H3PROBE])
        self.assertNotIn("transport_commands", policy)
        self.assertNotIn("allow_memory_writes", policy)
        self.assertEqual(control_transport(target, vp=True, transition=True), BUILTIN_H3PROBE)
        self.assertEqual(live_transport(target), BUILTIN_H3PROBE)


if __name__ == "__main__":
    unittest.main()
