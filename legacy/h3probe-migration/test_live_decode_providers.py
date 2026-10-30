from __future__ import annotations

from pathlib import Path
import ctypes
import types
import unittest
from unittest import mock

from sklab import bench_bridge, hvmm
from sklab.config import load
from sklab.context import RunContext
from sklab.errors import PrerequisiteError
from sklab.modules import core


EXAMPLE = Path(__file__).resolve().parents[1] / "config.example.toml"
transport = bench_bridge._module("s5w_gpa_server_pinned_vtl")
control = bench_bridge._module("h3_vtl1_debug_control")
hvmm_gpa = bench_bridge._module("hvmm_gpa")


class H3Probe:
    """h3probe answering IOCTL_H3_READGPA from `answers`: GPA -> (HV status, access result)."""

    def __init__(self) -> None:
        self.answers: dict[int, tuple[int, int]] = {}
        self.closed = False

    def ioctl(self, code: int, payload: bytes, out_size: int) -> bytes:
        status, access = self.answers[int.from_bytes(payload[8:16], "little")]
        return status.to_bytes(4, "little") + bytes(4) + access.to_bytes(8, "little") + bytes(16)

    def close(self) -> None:
        self.closed = True


class Device:
    """hvmm: pages it holds come back whole, `b""` entries empty, anything else as zeros, as the driver
    answers a GPA with no RAM behind it; `fail` makes the call itself fail."""

    def __init__(self) -> None:
        self.pages = {0x2601000: bytes(range(256)) * 16, 0x5000: b""}
        self.fail: OSError | None = None
        self.requests: list[bytes] = []
        self.closed = False

    def ioctl(self, code: int, payload: bytes, out_size: int) -> bytes:
        self.requests.append(payload)
        if self.fail is not None:
            raise self.fail
        return self.pages.get(int.from_bytes(payload[0x28:0x30], "little"), bytes(out_size))

    def close(self) -> None:
        self.closed = True


class MutablePhysicalMemory:
    """A DeviceIoControl double whose page can change while one source stays open."""

    def __init__(self, page: bytes) -> None:
        self.page = page
        self.reads = 0

    def DeviceIoControl(
        self,
        device: object,
        code: int,
        request: object,
        request_size: int,
        output: object,
        output_size: int,
        returned: object,
        overlapped: object,
    ) -> bool:
        del device, code, request, request_size, output_size, overlapped
        output[:] = self.page
        returned._obj.value = len(self.page)
        self.reads += 1
        return True


class LiveHvmmSourceTests(unittest.TestCase):
    def source(self, page: bytes) -> tuple[object, MutablePhysicalMemory]:
        kernel = MutablePhysicalMemory(page)
        source = object.__new__(hvmm_gpa.HvmmSource)
        source.k32 = kernel
        source.process = None
        source.partition = ctypes.c_void_p(2)
        source.device = ctypes.c_void_p(1)
        return source, kernel

    def test_raw_reads_do_not_reuse_an_old_physical_page(self) -> None:
        source, kernel = self.source(b"A" * hvmm_gpa.PAGE_SIZE)
        self.assertEqual(source.read(0x1234, 4), (b"AAAA", None))

        kernel.page = b"B" * hvmm_gpa.PAGE_SIZE

        self.assertEqual(source.read(0x1234, 4), (b"BBBB", None))
        self.assertEqual(kernel.reads, 2)

    def test_virtual_walk_cache_is_scoped_to_one_guest(self) -> None:
        source, kernel = self.source(b"A" * hvmm_gpa.PAGE_SIZE)
        first = hvmm_gpa.GuestVirtual(source, 0x1000)
        self.assertEqual(first._page(0x2000), b"A" * hvmm_gpa.PAGE_SIZE)

        kernel.page = b"B" * hvmm_gpa.PAGE_SIZE

        self.assertEqual(first._page(0x2000), b"A" * hvmm_gpa.PAGE_SIZE)
        second = hvmm_gpa.GuestVirtual(source, 0x1000)
        self.assertEqual(second._page(0x2000), b"B" * hvmm_gpa.PAGE_SIZE)
        self.assertEqual(kernel.reads, 2)


class HvmmDirectTests(unittest.TestCase):
    """The transport's direct mode with `--reader hvmm`: hvlib's open, hvmm's pages, the protocol's words."""

    def source(self, ram_runs: str | None = None, ask_hypervisor: bool = False) -> tuple[object, Device]:
        device = Device()
        # hvlib after it opened partition 7: InfoPartitionHandle (21) as K3 reported one on 2026-10-17
        direct = types.SimpleNamespace(
            pid=7, handle=1, max_read=0x1000, shape=lambda: "SHAPE cr3=0x27C6C000",
            dll=types.SimpleNamespace(SdkGetData2=lambda handle, info: {21: 0x28C}[info]),
        )
        self.probes: list[H3Probe] = []
        with mock.patch.object(hvmm, "Device", return_value=device), \
             mock.patch.object(control, "Probe", lambda: self.probes.append(H3Probe()) or self.probes[-1]):
            return transport.HvmmDirect(direct, ram_runs, ask_hypervisor), device

    def test_with_the_guests_ram_zeros_past_it_are_not_present(self) -> None:
        source, _ = self.source("0x1000-0xA0000,0x100000000-0x108000000")
        self.assertEqual(source.read(0x108000000, 8), (None, "NOTPRESENT"))
        self.assertEqual(source.read(0x2601000, 2), (bytes([0x00, 0x01]), None))  # outside, with data: kept
        self.assertEqual(source.reader.contradictions, [0x2601000])
        self.assertEqual(self.probes, [])  # nobody asked for the hypervisor

    def test_asked_the_hypervisor_serves_its_memory_and_refuses_the_rest(self) -> None:
        source, _ = self.source("0x1000-0xA0000,0x100000000-0x108000000", ask_hypervisor=True)
        (probe,) = self.probes
        probe.answers = {0x0: (0, 0), 0xFEE00000: (0x80, 0)}  # K3 2026-10-17: page 0 Accepted, APIC 0x0080
        self.assertEqual(source.read(0x0, 8), (bytes(8), None))
        self.assertEqual(source.read(0xFEE00000, 8), (None, "NOTPRESENT"))
        source.close()
        self.assertTrue(probe.closed)

    def test_without_ram_runs_the_hypervisor_is_not_asked(self) -> None:
        self.source(None, ask_hypervisor=True)
        self.assertEqual(self.probes, [])

    def test_a_page_hvmm_holds_is_read_through_hvlibs_handle(self) -> None:
        source, device = self.source()
        self.assertEqual(source.read(0x2601010, 4), (bytes([0x10, 0x11, 0x12, 0x13]), None))
        self.assertEqual(device.requests[0][0x00:0x10], bytes.fromhex("8c02000000000000" "0700000000000000"))

    def test_a_page_hvmm_answered_without_is_not_present(self) -> None:
        source, _ = self.source()
        self.assertEqual(source.read(0x5000, 8), (None, "NOTPRESENT"))

    def test_no_ram_behind_a_gpa_still_reads_as_zeros(self) -> None:
        # the limit, pinned: hvmm answered 0x108000000, past K3's RAM, with zeros on 2026-10-17
        source, _ = self.source()
        self.assertEqual(source.read(0x108000000, 8), (bytes(8), None))

    def test_a_failed_call_to_hvmm_is_an_error(self) -> None:
        source, device = self.source()
        device.fail = OSError("DeviceIoControl 0x2220C0: Win32 6")
        self.assertEqual(source.read(0x2601000, 8), (None, "ERROR hvmm: DeviceIoControl 0x2220C0: Win32 6"))

    def test_the_shape_is_the_one_hvlib_opened(self) -> None:
        source, device = self.source()
        self.assertEqual(source.shape(), "SHAPE cr3=0x27C6C000")
        self.assertEqual(source.max_read, 0x1000)
        source.close()
        self.assertTrue(device.closed)


class ProviderTests(unittest.TestCase):
    def test_the_transport_reads_through_hvlib_unless_told(self) -> None:
        # the bench's runners spawn it with --mode direct and nothing else, and keep hvlib's reads
        self.assertEqual(transport.arguments().parse_args(["--partition-id", "7"]).reader, "hvlib")

    def test_each_mode_and_reader_gets_its_source(self) -> None:
        bootstrap = types.SimpleNamespace(pid=7, cr3=0x27C6C000)
        with mock.patch.object(transport, "HvmmDirect") as direct, mock.patch.object(transport, "Hypercall") as hypercall:
            self.assertIs(transport.provider("direct", "hvlib", bootstrap), bootstrap)
            self.assertIs(transport.provider("direct", "hvmm", bootstrap), direct.return_value)
            self.assertIs(transport.provider("hypercall", "hvmm", bootstrap), hypercall.return_value)
        direct.assert_called_once_with(bootstrap, None, False)
        hypercall.assert_called_once_with(7, 0x27C6C000)

    def test_the_ram_runs_reach_the_hvmm_reader(self) -> None:
        bootstrap = types.SimpleNamespace(pid=7, cr3=0x27C6C000)
        with mock.patch.object(transport, "HvmmDirect") as direct:
            transport.provider("direct", "hvmm", bootstrap, "0x1000-0xA0000", True)
        direct.assert_called_once_with(bootstrap, "0x1000-0xA0000", True)
        args = transport.arguments().parse_args(["--partition-id", "7", "--ram-runs", "0x1000-0xA0000", "--ask-hypervisor"])
        self.assertEqual((args.ram_runs, args.ask_hypervisor), ("0x1000-0xA0000", True))
        self.assertFalse(transport.arguments().parse_args(["--partition-id", "7"]).ask_hypervisor)


RUNS = [(0x1000, 0xA0000), (0x100000000, 0x108000000)]
RAM = {"vp": "0", "kernel_base": "0xfffff80300000000", "pdb": "ntkrnlmp.pdb C29EBFB06B78B3C020DCA66D99713F9E1",
       "runs": RUNS, "pages": 0x809F}


class LiveDecodeCommandTests(unittest.TestCase):
    def transport_line(self, **options: object) -> str:
        config = load(EXAMPLE)
        context = RunContext(config, mock.Mock(), mock.Mock(), config.target("demo"))
        context.run_process = mock.Mock()  # type: ignore[method-assign]
        self.output = context.output
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

    def test_only_the_hvmm_reader_requires_worker_discovery(self) -> None:
        self.transport_line(reader="hvlib")
        self.assertFalse(self.discovered)
        self.transport_line(mode="hypercall")
        self.assertFalse(self.discovered)
        self.transport_line()
        self.assertTrue(self.discovered)

    def test_direct_mode_reads_through_the_h3_memory_operation_by_default(self) -> None:
        line = self.transport_line()
        self.assertIn("gpa_server.py", line)
        self.assertNotIn("hvmm", line)
        self.assertIn("--vmwp-pid 4242", line)
        self.assertIn("--partition-handle 0x2e0", line)
        self.assertIn("--partition-id 0x7", line)
        self.assertNotIn("hvlib", line)
        self.assertNotIn("--writes", line)
        self.assertIn("follows only mappings present", self.result["guest_ram"]["skipped"])

    def test_the_duplicated_handle_hvmm_reader_is_still_asked_for_by_name(self) -> None:
        line = self.transport_line(reader="hvmm")
        self.assertIn("hvmm_gpa_server.py", line)
        self.assertIn("--partition-handle 0x2e0", line)

    def test_reading_through_hvlib_is_still_asked_for_by_name(self) -> None:
        self.assertIn("--reader hvlib", self.transport_line(reader="hvlib"))

    def test_the_hypercall_mode_takes_no_reader(self) -> None:
        self.assertNotIn("--reader", self.transport_line(mode="hypercall"))

    def test_an_unknown_reader_is_refused(self) -> None:
        with self.assertRaises(PrerequisiteError):
            self.transport_line(reader="vid")

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
