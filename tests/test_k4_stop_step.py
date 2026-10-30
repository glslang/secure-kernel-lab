from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from sklab.bench import run_k4_stop_step as k4


class FakeDiscovery:
    """`windbg-mcp --sk-discover-identity`, answering with what the test gives it."""

    command: list[str] = []
    answer: dict[str, object] | None = None
    log = ""
    code = 0
    hangs = False
    killed = False

    def __init__(self, command: list[str], **kwargs: object) -> None:
        type(self).command = command
        self.pid = 9999
        if type(self).answer is not None:
            kwargs["stdout"].write(json.dumps(type(self).answer))  # type: ignore[attr-defined]
        kwargs["stderr"].write(type(self).log)  # type: ignore[attr-defined]

    def wait(self, timeout: float) -> int:
        if type(self).hangs:
            raise subprocess.TimeoutExpired("windbg-mcp", timeout)
        return type(self).code

    def kill(self) -> None:
        type(self).killed = True


def identity(**overrides: object) -> dict[str, object]:
    answer: dict[str, object] = {
        "schema": "windbg-mcp.sk-identity.v1",
        "vm_id": k4.VM_ID,
        "vmwp_pid": 4242,
        "dispatcher_vnd": "0x000002dec8446680",
        "partition_handle": "0x00000000000002e4",
        "partition_id": "0x0000000000000026",
        "late_entry_hits": 0,
    }
    answer.update(overrides)
    return answer


class FakeCleanupCdbSession:
    commands: list[str] = []

    def __init__(self, _pid: int, name: str, commands: str) -> None:
        self.name = name
        type(self).commands.append(commands)

    def wait(self, marker: str, _timeout: float) -> str:
        if marker == "K4AUTO_UNREGISTER_RESULT":
            return "K4AUTO_UNREGISTER_RESULT rax=00000000`00000001"
        if marker == "K4AUTO_OLD_CALLBACK_FIELDS":
            return "K4AUTO_OLD_CALLBACK_FIELDS callback=0 flags=0"
        return marker

    def finish(self) -> str:
        if self.name.endswith("-cleanup"):
            return "\n".join(
                (
                    "K4AUTO_UNREGISTER_BREAKPOINT_RESTORED",
                    "K4AUTO_CLEANUP_ENTRY_BREAKPOINT_RESTORED",
                    "K4AUTO_CLEANUP_RETURN_BREAKPOINT_RESTORED",
                )
            )
        return "????????`????????"


class K4StopStepTests(unittest.TestCase):
    def test_handler_commands_use_the_selected_profile(self) -> None:
        commands = k4.handler_commands(0x1000)

        self.assertIn("eq @$t9 vmwp+48bd0", commands)
        self.assertIn("bp vmwp+2c7b4", commands)
        self.assertNotIn("vmwp+494f0", commands)

    def discover(self, **fake: object) -> tuple[int, int, int]:
        defaults = {"answer": identity(), "log": "", "code": 0, "hangs": False, "killed": False}
        defaults.update(fake)
        for name, value in defaults.items():
            setattr(FakeDiscovery, name, value)
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(k4, "HERE", Path(directory)),
                patch.object(k4.subprocess, "Popen", FakeDiscovery),
            ):
                return k4.discover_identity(4242, "test")

    def test_discovery_is_windbg_mcps_own_and_returns_the_three_values(self) -> None:
        self.assertEqual(self.discover(), (0x2DEC8446680, 0x2E4, 0x26))
        command = FakeDiscovery.command
        self.assertEqual(command[0], str(k4.MCP_EXE))
        self.assertEqual(command[1], "--sk-discover-identity")
        self.assertEqual(command[command.index("--profile") + 1], str(k4.PROFILE))
        self.assertEqual(command[command.index("--vm-id") + 1], k4.VM_ID)
        self.assertEqual(command[command.index("--vmwp-pid") + 1], "4242")

    def test_an_answer_for_another_target_is_refused(self) -> None:
        for wrong in (
            {"vmwp_pid": 4243},
            {"vm_id": "00000000-0000-0000-0000-000000000000"},
            {"schema": "windbg-mcp.sk-identity.v0"},
        ):
            with self.subTest(wrong=wrong):
                with self.assertRaisesRegex(k4.GateFailure, "another target"):
                    self.discover(answer=identity(**wrong))

    def test_a_failed_discovery_reports_the_servers_error(self) -> None:
        log = "INFO dispatcher paused\nError: discovered Hyper-V partition 0x26 does not match\n"
        with self.assertRaisesRegex(k4.GateFailure, "exited 1: Error: discovered Hyper-V"):
            self.discover(answer=None, log=log, code=1)

    def test_a_discovery_past_its_timeout_is_left_running(self) -> None:
        # A held discovery is a contained vmwp, and ending its process ends vmwp.
        with self.assertRaisesRegex(k4.GateFailure, "process 9999 may hold vmwp contained"):
            self.discover(answer=None, hangs=True)
        self.assertFalse(FakeDiscovery.killed)

    def test_echoed_restore_marker_does_not_satisfy_check(self) -> None:
        echoed = (
            ".if (poi(@$t0)==@$t3) { "
            ".echo K4AUTO_UNREGISTER_BREAKPOINT_RESTORED }\n"
        )
        with self.assertRaisesRegex(k4.GateFailure, "bytes were not restored"):
            k4.require_breakpoint_restored(echoed, "K4AUTO_UNREGISTER_BREAKPOINT_RESTORED", "test")
        k4.require_breakpoint_restored(
            "0:001> K4AUTO_UNREGISTER_BREAKPOINT_RESTORED\n",
            "K4AUTO_UNREGISTER_BREAKPOINT_RESTORED",
            "test",
        )

    def test_cleanup_compares_each_breakpoint_with_its_captured_bytes(self) -> None:
        FakeCleanupCdbSession.commands = []
        with (
            patch.object(k4, "CdbSession", FakeCleanupCdbSession),
            patch.object(k4.time, "sleep"),
        ):
            result = k4.cleanup_handler(123, 0x1000, 0x2000, "test")

        self.assertTrue(result["scratch_freed"])
        cleanup_commands = FakeCleanupCdbSession.commands[0]
        for command in (
            "r @$t3=poi(@$t0)",
            "poi(@$t1)==@$t3",
            "r @$t4=poi(vmwp+19630)",
            "poi(vmwp+19630)==@$t4",
            "r @$t5=poi(@$t2)",
            "poi(@$t2)==@$t5",
            "r rip=vmwp+210fe0",
        ):
            self.assertIn(command, cleanup_commands)


if __name__ == "__main__":
    unittest.main()
