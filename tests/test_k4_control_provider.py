from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "sklab" / "bench"))
import k4_control_provider as provider  # noqa: E402


CR3 = 0x2601000


class HeldEventTests(unittest.TestCase):
    def setUp(self) -> None:
        # The constructor opens the driver; these tests need only the state it leaves behind.
        self.provider = provider.Provider.__new__(provider.Provider)
        self.provider.probe = mock.Mock()
        self.provider.partition = 0x10
        self.provider.vp = 0
        self.provider.allow_transition_cr3 = False
        self.provider.identity_change_signal = None
        self.provider.target = {
            "vm_id": "6b1ed0f6-137e-469f-aeab-a3f4cfee398d",
            "partition_id": provider.word(0x10),
            "vp": 0,
            "vtl": 1,
            "expected_cr3": provider.word(CR3),
        }
        self.provider.phase = "running"
        self.provider.epoch = provider.epoch("running")
        self.provider.event = None
        snapshot = {"registers": {"cr3": {"low": provider.word(CR3), "high": provider.word(0), "status": 0}}}
        patcher = mock.patch.object(provider, "snapshot", return_value=snapshot)
        patcher.start()
        self.addCleanup(patcher.stop)

    def request(self, operation: dict[str, object]) -> dict[str, object]:
        return {
            "protocol": provider.PROTOCOL,
            "id": 7,
            "target": dict(self.provider.target),
            "epoch": self.provider.epoch,
            "operation": operation,
        }

    def event(self, vector: int, reason: str) -> dict[str, object]:
        return {
            "message_type": provider.word(0x01000002),
            "vector": vector,
            "vp": 0,
            "vtl": 1,
            "cpl": 0,
            "dispatcher_context": provider.word(0x25CCE3E1140),
            "advance_instruction_pointer": False,
            "reason": {"reason": reason},
        }

    def publish(self, vector: int, reason: str) -> dict[str, object]:
        return self.provider.handle(self.request({"op": "publish_stop", "event": self.event(vector, reason)}))

    def test_breakpoint_events_are_advertised(self) -> None:
        answer = self.provider.handle(self.request({"op": "capabilities"}))
        self.assertIn("breakpoint_events", answer["outcome"]["value"]["value"]["capabilities"])

    def test_each_vector_is_held_only_with_its_own_raw_reason(self) -> None:
        for vector, reason in ((1, "debug_exception"), (3, "breakpoint_exception")):
            with self.subTest(vector=vector):
                self.setUp()
                answer = self.publish(vector, reason)
                self.assertEqual(answer["outcome"]["status"], "ok", answer)
                self.assertEqual(answer["outcome"]["value"]["event"]["vector"], vector)
                self.assertEqual(self.provider.phase, "stopped")
        for vector, reason in ((1, "breakpoint_exception"), (3, "debug_exception")):
            with self.subTest(vector=vector, reason=reason):
                self.setUp()
                answer = self.publish(vector, reason)
                self.assertEqual(answer["outcome"]["error"]["detail"], "stop reason does not match its raw vector")
                self.assertEqual(self.provider.phase, "running")

    def test_other_vectors_are_still_refused(self) -> None:
        for vector in (0, 2, 6, 14):
            with self.subTest(vector=vector):
                self.setUp()
                answer = self.publish(vector, "debug_exception")
                self.assertEqual(answer["outcome"]["status"], "error")
                self.assertIn("vector 1 or 3", answer["outcome"]["error"]["detail"])


if __name__ == "__main__":
    unittest.main()
