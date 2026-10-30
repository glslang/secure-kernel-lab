from __future__ import annotations

import json
from pathlib import Path
import tempfile
import types
import unittest

from sklab import bench_bridge


class DiscoveryTests(unittest.TestCase):
    def test_cache_carries_the_vmwp_handle_and_reuses_it_only_for_the_same_process(self) -> None:
        for name in ("run_k3_sk_live", "run_k3_sk_syscall"):
            with self.subTest(runner=name):
                runner = bench_bridge._module(name)
                old_cache, old_k4, old_vm_id = runner.DISCOVERY_CACHE, runner.k4, runner.VM_ID
                calls: list[tuple] = []
                fake = types.SimpleNamespace(
                    discover_identity=lambda pid, run: calls.append(("identity", pid, run)) or (0x12340000, 0x2E0, 7),
                )
                try:
                    with tempfile.TemporaryDirectory() as directory:
                        runner.DISCOVERY_CACHE = Path(directory) / "discovery.json"
                        runner.k4 = fake
                        runner.VM_ID = "vm-id"
                        self.assertEqual(
                            runner.discovery(4242),
                            (0x12340000, 0x2E0, 7, "fresh; windbg-mcp discovery attached to vmwp"),
                        )
                        self.assertEqual(calls, [("identity", 4242, name.removeprefix("run_").replace("_", "-"))])
                        saved = json.loads(runner.DISCOVERY_CACHE.read_text(encoding="utf-8"))
                        self.assertEqual(
                            saved,
                            {
                                "vm_id": "vm-id",
                                "vmwp_pid": 4242,
                                "dispatcher_vnd": "0x0000000012340000",
                                "partition_handle": "0x2e0",
                                "partition_id": "0x7",
                            },
                        )
                        calls.clear()
                        reused = runner.discovery(4242)
                        self.assertEqual(reused[:3], (0x12340000, 0x2E0, 7))
                        self.assertIn("reused", reused[3])
                        self.assertEqual(calls, [])
                finally:
                    runner.DISCOVERY_CACHE, runner.k4, runner.VM_ID = old_cache, old_k4, old_vm_id

    def test_an_old_cache_without_a_handle_is_not_reused(self) -> None:
        for name in ("run_k3_sk_live", "run_k3_sk_syscall"):
            with self.subTest(runner=name):
                runner = bench_bridge._module(name)
                old_cache, old_k4, old_vm_id = runner.DISCOVERY_CACHE, runner.k4, runner.VM_ID
                calls: list[str] = []
                fake = types.SimpleNamespace(
                    discover_identity=lambda pid, run: calls.append("identity") or (0x12340000, 0x2E0, 7),
                )
                try:
                    with tempfile.TemporaryDirectory() as directory:
                        runner.DISCOVERY_CACHE = Path(directory) / "discovery.json"
                        runner.DISCOVERY_CACHE.write_text(
                            json.dumps(
                                {
                                    "vm_id": "vm-id",
                                    "vmwp_pid": 4242,
                                    "dispatcher_vnd": "0x12340000",
                                    "partition_id": "0x7",
                                }
                            ),
                            encoding="utf-8",
                        )
                        runner.k4 = fake
                        runner.VM_ID = "vm-id"
                        self.assertEqual(runner.discovery(4242)[:3], (0x12340000, 0x2E0, 7))
                        self.assertEqual(calls, ["identity"])
                finally:
                    runner.DISCOVERY_CACHE, runner.k4, runner.VM_ID = old_cache, old_k4, old_vm_id


if __name__ == "__main__":
    unittest.main()
