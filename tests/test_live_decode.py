from __future__ import annotations

from pathlib import Path
import struct
import unittest
from unittest import mock

from sklab import bench_bridge
from sklab.config import load
from sklab.context import RunContext
from sklab.errors import PrerequisiteError
from sklab.modules import core


EXAMPLE = Path(__file__).resolve().parents[1] / "config.example.toml"
physical = bench_bridge._module("guest_physical")


class Probe:
    """h3probe answering IOCTL_H3_READGPA from `answers`: GPA -> (HV status, access result, bytes)."""

    def __init__(self, answers: dict[int, tuple[int, int, bytes]]) -> None:
        self.answers = answers
        self.requests: list[tuple[int, int, int]] = []
        self.closed = False

    def ioctl(self, code: int, payload: bytes, out_size: int) -> bytes:
        partition, gpa, size, _ = struct.unpack("<QQII", payload)
        self.requests.append((partition, gpa, size))
        status, access, data = self.answers[gpa]
        return struct.pack("<IIQ", status, 0, access) + data.ljust(16, b"\0")

    def close(self) -> None:
        self.closed = True


class HypercallSourceTests(unittest.TestCase):
    """The negative control: what the hypervisor itself will read, and its refusal of VTL1."""

    def source(self, answers: dict[int, tuple[int, int, bytes]]) -> tuple[object, Probe]:
        probe = Probe(answers)
        with mock.patch.object(physical, "Probe", return_value=probe):
            return physical.HypercallSource(0x7), probe

    def test_an_accepted_read_is_the_hypervisors_bytes(self) -> None:
        source, probe = self.source({0x1000: (0, 0, b"0123456789abcdef")})
        self.assertEqual(source.read(0x1000, 16), (b"0123456789abcdef", None))
        self.assertEqual(probe.requests, [(0x7, 0x1000, 16)])

    def test_a_vtl1_page_is_refused_by_its_access_result_not_its_status(self) -> None:
        # H4: HV_STATUS_SUCCESS, a buffer of zeros, and ReadIntercept
        source, _ = self.source({0x13BB000: (0, 2, bytes(16))})
        self.assertEqual(source.read(0x13BB000, 16), (None, "REFUSED ReadIntercept(2)"))

    def test_a_failed_hypercall_and_an_oversized_read_are_errors(self) -> None:
        source, probe = self.source({0xFEE00000: (0x80, 0, b"")})
        self.assertEqual(source.read(0xFEE00000, 16), (None, "ERROR HV_STATUS 0x0080"))
        data, failure = source.read(0x1000, 17)
        self.assertIsNone(data)
        self.assertTrue((failure or "").startswith("ERROR"))
        self.assertEqual(len(probe.requests), 1)

    def test_a_closed_source_reads_nothing(self) -> None:
        source, probe = self.source({})
        source.close()
        self.assertTrue(probe.closed)
        self.assertEqual(source.read(0x1000, 8), (None, "ERROR hypercall source is closed"))


class GuestVirtualCacheTests(unittest.TestCase):
    """A raw source is uncached; one virtual walk caches its own pages and no other's."""

    class Source:
        def __init__(self) -> None:
            self.page = b"A" * 0x1000
            self.reads = 0

        def read(self, gpa: int, size: int) -> tuple[bytes, None]:
            self.reads += 1
            return self.page[:size], None

    def test_virtual_walk_cache_is_scoped_to_one_guest(self) -> None:
        source = self.Source()
        first = physical.GuestVirtual(source, 0x1000)
        self.assertEqual(first._page(0x2000), b"A" * 0x1000)
        source.page = b"B" * 0x1000
        self.assertEqual(first._page(0x2000), b"A" * 0x1000)
        second = physical.GuestVirtual(source, 0x1000)
        self.assertEqual(second._page(0x2000), b"B" * 0x1000)
        self.assertEqual(source.reads, 2)


class LiveDecodeCommandTests(unittest.TestCase):
    def transport_line(self, **options: object) -> str:
        config = load(EXAMPLE)
        context = RunContext(config, mock.Mock(), mock.Mock(), config.target("demo"))
        context.run_process = mock.Mock()  # type: ignore[method-assign]
        with mock.patch.object(core, "_require_checks"), \
             mock.patch.object(
                 core.bench_bridge,
                 "discover",
                 return_value=(4242, 0x12340000, 0x2E0, 7, "fresh"),
             ) as discover:
            self.result = core.live_decode(context, {"partition_id": 7, **options})
        self.discovered = discover.called
        command = context.run_process.call_args.args[0]
        return command[command.index("--transport") + 1]

    def test_only_the_direct_mode_requires_worker_discovery(self) -> None:
        self.transport_line(mode="hypercall")
        self.assertFalse(self.discovered)
        self.transport_line()
        self.assertTrue(self.discovered)

    def test_direct_mode_reads_through_the_h3_memory_operation(self) -> None:
        line = self.transport_line()
        self.assertIn("gpa_server.py", line)
        self.assertIn("--vmwp-pid 4242", line)
        self.assertIn("--partition-handle 0x2e0", line)
        self.assertIn("--partition-id 0x7", line)
        self.assertNotIn("--pages", line)
        self.assertNotIn("--writes", line)  # the decoder never writes
        for retired in ("hvmm", "hvlib", "s5w", "livecloudkd"):
            self.assertNotIn(retired, line.lower())

    def test_the_hypercall_mode_is_the_same_transport_reading_through_the_hypercall(self) -> None:
        line = self.transport_line(mode="hypercall")
        self.assertIn("gpa_server.py", line)
        self.assertIn("--pages hypercall", line)
        self.assertIn("--partition-id 0x7", line)
        self.assertNotIn("--vmwp-pid", line)
        self.assertEqual(self.result["pages"], "HvCallReadGpa, which refuses VTL1")

    def test_an_unknown_mode_is_refused(self) -> None:
        with self.assertRaises(PrerequisiteError):
            self.transport_line(mode="hvmm")

    def test_a_supplied_partition_must_match_handle_discovery(self) -> None:
        config = load(EXAMPLE)
        context = RunContext(config, mock.Mock(), mock.Mock(), config.target("demo"))
        with mock.patch.object(core, "_require_checks"), mock.patch.object(
            core.bench_bridge,
            "discover",
            return_value=(4242, 0x12340000, 0x2E0, 8, "fresh"),
        ):
            with self.assertRaises(core.ExecutionFailure):
                core.live_decode(context, {"partition_id": 7})


if __name__ == "__main__":
    unittest.main()
