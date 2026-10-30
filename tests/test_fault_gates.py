from __future__ import annotations

import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from sklab.errors import ExecutionFailure, RecoveryRequired
from sklab.modules import advanced


REFUSAL = "sk_live_arm: loaded vmwp SHA-256 does not match the dispatcher profile"


class Client:
    """The server as `open_sk_live_control` reserves and the first arm validates."""

    def __init__(self, arm_error: Exception | None) -> None:
        self.arm_error = arm_error
        self.calls: list[str] = []
        self.arguments: dict[str, dict[str, object]] = {}
        self.stderr = ""

    def initialize(self) -> None:
        pass

    def tool(self, name: str, arguments: dict[str, object], _timeout: float) -> dict[str, object]:
        self.calls.append(name)
        self.arguments[name] = arguments
        if name == "open_sk_live_control":
            return {"session_id": "sess-1", "status": "ok"}
        if name == "sk_live_arm" and self.arm_error is not None:
            raise self.arm_error
        return {"status": "ok"}

    def end_session(self, session_id: str) -> dict[str, object]:
        self.calls.append("end_session")
        return {"session_id": session_id, "released": True, "status": "ok"}

    def session(self, _session_id: str) -> dict[str, object]:
        return {"session_id": "sess-1", "state": {"state": "closed"}}

    def close(self, **_options: object) -> None:
        pass


def make_context(root: Path, profile: Path, arm_mode: str = "redirect") -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(
            paths=SimpleNamespace(windbg_mcp_exe=root / "w.exe", windbg_mcp_repo=root),
            defaults=SimpleNamespace(arm_mode=arm_mode),
        ),
        target=SimpleNamespace(vm_name="K3", vm_id="vm", vp=0, profile=profile),
        run_dir=root,
        confirm=mock.Mock(),
    )


class BuildMismatchTests(unittest.TestCase):
    def run_gate(self, client: Client) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / "profile.json"
            profile.write_text(json.dumps({"vmwp_sha256": "A" * 64}), encoding="utf-8")
            context = make_context(root, profile)
            with (
                mock.patch.object(advanced, "_require"),
                mock.patch.object(advanced, "_resolve_guard", return_value=("0xfffff8040bd0d7f0", "0f1f44", {})),
                mock.patch.object(advanced, "write_policy", return_value={"profile_roots": []}),
                mock.patch.object(advanced, "control_transport", return_value="control"),
                mock.patch.object(advanced, "live_transport", return_value="live"),
                mock.patch.object(advanced, "McpClient", return_value=client),
            ):
                return advanced.build_mismatch(context, {})

    def test_the_first_arm_refuses_the_hash_and_the_session_ends_released(self) -> None:
        client = Client(ExecutionFailure(REFUSAL))
        result = self.run_gate(client)
        self.assertEqual((result["refused"], result["refused_at"]), (True, "arm"))
        self.assertEqual(client.calls, ["open_sk_live_control", "sk_live_arm", "end_session"])
        self.assertEqual(client.arguments["sk_live_arm"]["mode"], "redirect")

    def test_an_arm_that_succeeds_fails_the_gate(self) -> None:
        client = Client(None)
        with self.assertRaisesRegex(ExecutionFailure, "was armed"):
            self.run_gate(client)
        self.assertEqual(client.calls[-1], "end_session")

    def test_an_arm_refused_for_another_reason_is_not_this_proof(self) -> None:
        with self.assertRaisesRegex(ExecutionFailure, "CR3"):
            self.run_gate(Client(ExecutionFailure("sk_live_arm: live-memory source CR3 does not match")))


class ProviderDeath(Client):
    """A provider that exits at stop publication: the wait faults and ownership stays unresolved."""

    def tool(self, name: str, arguments: dict[str, object], timeout: float) -> dict[str, object]:
        if name == "sk_live_wait":
            self.calls.append(name)
            raise ExecutionFailure("sk_live_wait: live Secure Kernel control faulted; target_left_paused=true")
        return super().tool(name, arguments, timeout)

    def end_session(self, session_id: str) -> dict[str, object]:
        self.calls.append("end_session")
        raise RecoveryRequired("end_session: recovery_required")

    def session(self, _session_id: str) -> dict[str, object]:
        return {"session_id": "sess-1", "state": {"state": "live_control_unresolved"}}


class FaultSessionTests(unittest.TestCase):
    def run_fault(self, client: Client, options: dict[str, object], arm_mode: str) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = make_context(root, root / "profile.json", arm_mode)
            with (
                mock.patch.object(advanced, "_require"),
                mock.patch.object(advanced, "_resolve_guard", return_value=("0xfffff8040bd0512b", "0f1f44", {})),
                mock.patch.object(advanced, "write_policy", return_value={"transport_commands": []}),
                mock.patch.object(advanced, "control_transport", return_value="control"),
                mock.patch.object(advanced, "live_transport", return_value="live"),
                mock.patch.object(advanced, "atomic_json"),
                mock.patch.object(advanced, "McpClient", return_value=client),
            ):
                return advanced.provider_death(context, options)

    def test_the_fault_arm_takes_the_configured_mode_unless_the_run_names_one(self) -> None:
        # A natural arm waits for the guest to reach the guard by itself, which on K3 it does not
        # within the wait's budget, so the fault is never injected.
        for configured, options, expected in (("redirect", {}, "redirect"), ("redirect", {"arm_mode": "natural"}, "natural")):
            with self.subTest(configured=configured, options=options):
                client = ProviderDeath(None)
                result = self.run_fault(client, options, configured)
                self.assertEqual(client.arguments["sk_live_arm"]["mode"], expected)
                self.assertIn("target_left_paused=true", result["fault_result"])
                self.assertEqual(result["retained_session"]["state"]["state"], "live_control_unresolved")


if __name__ == "__main__":
    unittest.main()
