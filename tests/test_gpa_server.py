from __future__ import annotations

import io
import struct
import unittest
from unittest.mock import patch

from sklab import bench_bridge

physical = bench_bridge._module("guest_physical")
server = bench_bridge._module("gpa_server")

MEMREAD = (0x22 << 16) | (0x812 << 2)
MEMWRITE = (0x22 << 16) | (0x813 << 2)


def answer(result: int, stage: int, length: int, gpn: int) -> bytes:
    return struct.pack("<6IQ", 1, result, stage, 0, length, 0, gpn)


class Driver:
    """Guest pages behind the memory operation: RAM, a page VID refuses, and nothing else."""

    def __init__(self) -> None:
        self.pages = {0x10: bytearray(b"\x11" * 0x1000)}
        self.refused = {0xFEE00}
        self.closed = False

    def ioctl(self, code: int, payload: bytes, out_size: int) -> bytes:
        _v, _pid, _handle, _partition, gpa, length, _r = struct.unpack_from("<IIQQQII", payload, 0)
        gpn, offset = gpa >> 12, gpa & 0xFFF
        if gpn in self.refused:
            head = answer(2, 8, 0, gpn)
        elif gpn not in self.pages:
            head = answer(1, 8, 0, gpn)
        elif code == MEMWRITE:
            self.pages[gpn][offset : offset + length] = payload[40:]
            return answer(0, 0, length, gpn)
        else:
            data = bytes(self.pages[gpn][offset : offset + length])
            return answer(0, 0, length, gpn) + data + bytes(0x1000 - length)
        return head + (bytes(0x1000) if code == MEMREAD else b"")

    def close(self) -> None:
        self.closed = True


def source(driver: Driver) -> object:
    with patch.object(physical.h3_memory, "Device", return_value=driver):
        return physical.H3Source(4242, 0x2E4, 3)


class H3SourceTests(unittest.TestCase):
    def test_absence_and_refusal_are_the_transport_words_not_zeros(self) -> None:
        h3 = source(Driver())
        self.assertEqual(h3.read(0x10FF0, 4), (b"\x11" * 4, None))
        self.assertEqual(h3.read(0xF8000000, 4), (None, "NOTPRESENT"))
        self.assertEqual(h3.read(0xFEE00000, 4), (None, "REFUSED translate"))

    def test_a_read_across_pages_stops_at_the_first_absent_one(self) -> None:
        self.assertEqual(source(Driver()).read(0x10FFE, 4), (None, "NOTPRESENT"))

    def test_a_write_lands_and_a_cross_page_write_is_refused_before_the_driver(self) -> None:
        driver = Driver()
        h3 = source(driver)
        self.assertIsNone(h3.write(0x10004, b"\xCC"))
        self.assertEqual(driver.pages[0x10][4], 0xCC)
        self.assertEqual(h3.write(0x10FFF, b"\xCC\xCC"), "ERROR write must remain within one physical page")

    def test_a_closed_source_reads_nothing(self) -> None:
        driver = Driver()
        h3 = source(driver)
        h3.close()
        self.assertTrue(driver.closed)
        self.assertEqual(h3.read(0x10000, 4), (None, "ERROR h3 source is closed"))


class ServeTests(unittest.TestCase):
    def serve(self, requests: bytes, *, writes: bool) -> tuple[list[bytes], Driver]:
        driver = Driver()
        out = io.BytesIO()
        with patch.object(server, "IN", io.BytesIO(requests)), patch.object(server, "OUT", out):
            self.assertEqual(server.serve(source(driver), 0x1000, 0xFFFFF80000000000, writes), 0)
        return out.getvalue().split(b"\n"), driver

    def test_shape_advertises_writes_only_when_served(self) -> None:
        lines, _ = self.serve(b"SHAPE\n", writes=False)
        self.assertNotIn(b"max_write", lines[0])
        self.assertIn(b"read_coherency=explicit_refresh", lines[0])
        lines, _ = self.serve(b"SHAPE\n", writes=True)
        self.assertIn(b"max_write=4096 write_coherency=instruction_coherent", lines[0])

    def test_reads_refresh_and_typed_failures(self) -> None:
        lines, _ = self.serve(b"REFRESH\nREAD 0x10000 2\nREAD 0x200000000 2\nREAD 0xFEE00000 2\n", writes=False)
        self.assertEqual(lines[0], b"OK 0")
        self.assertEqual(lines[1], b"OK 2")
        self.assertEqual(lines[2][:2], b"\x11\x11")
        self.assertEqual(lines[2][2:], b"NOTPRESENT")
        self.assertEqual(lines[3], b"REFUSED translate")

    def test_a_write_without_writes_consumes_its_payload_and_writes_nothing(self) -> None:
        lines, driver = self.serve(b"WRITE 0x10004 1\n\xccREAD 0x10004 1\n", writes=False)
        self.assertEqual(lines[0], b"ERROR this transport was started without --writes")
        self.assertEqual(lines[1], b"OK 1")
        self.assertEqual(driver.pages[0x10][4], 0x11)

    def test_a_served_write_is_read_back(self) -> None:
        lines, driver = self.serve(b"WRITE 0x10004 1\n\xccREAD 0x10004 1\n", writes=True)
        self.assertEqual(lines[0], b"OK 1")
        self.assertEqual(lines[1], b"OK 1")
        self.assertEqual(lines[2], b"\xcc")

    def test_a_write_beyond_max_write_ends_the_stream(self) -> None:
        lines, _ = self.serve(b"WRITE 0x10000 4097\n" + b"\0" * 4097 + b"SHAPE\n", writes=True)
        self.assertEqual(lines[0], b"ERROR 4097 is outside 1..4096")
        self.assertEqual(lines[1:], [b""])


    def test_the_hypercall_shape_names_no_kernel_base_and_reads_sixteen_bytes(self) -> None:
        line = server.shape(0x1201000, None, physical.HypercallSource.__new__(physical.HypercallSource), False)
        self.assertNotIn("kernel_base", line)
        self.assertIn("max_read=16", line)
        self.assertNotIn("max_write", line)

if __name__ == "__main__":
    unittest.main()
