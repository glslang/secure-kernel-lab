from __future__ import annotations

import struct
import unittest

from sklab import h3_memory


MEMREAD = (0x22 << 16) | (0x812 << 2)
MEMWRITE = (0x22 << 16) | (0x813 << 2)
RESULT = {"ok": 0, "not-present": 1, "refused": 2, "error": 3, "identity": 4}


def answer(result: str = "ok", *, stage: int = 0, status: int = 0, length: int = 0,
           gpn: int = 0, version: int = 1) -> bytes:
    """H3_MEM_ANSWER at its literal offsets in drivers/h3probe/h3probe.c."""
    raw = bytearray(32)
    struct.pack_into("<I", raw, 0, version)
    struct.pack_into("<I", raw, 4, RESULT.get(result, 9))
    struct.pack_into("<I", raw, 8, stage)
    struct.pack_into("<I", raw, 12, status)
    struct.pack_into("<I", raw, 16, length)
    struct.pack_into("<Q", raw, 24, gpn)
    return bytes(raw)


class Guest:
    """A fake device holding guest pages, answering the two memory controls as the driver does."""

    def __init__(self, pages: dict[int, bytes], *, absent: set[int] | None = None) -> None:
        self.pages = {gpn: bytearray(data) for gpn, data in pages.items()}
        self.absent = absent or set()
        self.calls: list[tuple[int, bytes, int]] = []

    def ioctl(self, code: int, payload: bytes, out_size: int) -> bytes:
        self.calls.append((code, payload, out_size))
        version, pid, handle, partition, gpa, length, reserved = struct.unpack_from("<IIQQQII", payload, 0)
        assert (version, reserved) == (1, 0) and pid and handle
        gpn, offset = gpa >> 12, gpa & 0xFFF
        assert 1 <= length <= 0x1000 - offset
        if gpn in self.absent or gpn not in self.pages:
            return answer("not-present", stage=8, gpn=gpn) + (bytes(0x1000) if code == MEMREAD else b"")
        if code == MEMREAD:
            data = bytes(self.pages[gpn][offset : offset + length])
            return answer(length=length, gpn=gpn) + data + bytes(0x1000 - length)
        assert code == MEMWRITE and len(payload) == 40 + length
        self.pages[gpn][offset : offset + length] = payload[40:]
        return answer(length=length, gpn=gpn)


class RequestTests(unittest.TestCase):
    def test_the_request_is_laid_out_as_the_driver_reads_it(self) -> None:
        raw = h3_memory.request(4242, 0x2E4, 3, 0x107FFF040, 16)
        self.assertEqual(len(raw), 40)
        self.assertEqual(struct.unpack_from("<I", raw, 0)[0], 1)
        self.assertEqual(struct.unpack_from("<I", raw, 4)[0], 4242)
        self.assertEqual(struct.unpack_from("<Q", raw, 8)[0], 0x2E4)
        self.assertEqual(struct.unpack_from("<Q", raw, 16)[0], 3)
        self.assertEqual(struct.unpack_from("<Q", raw, 24)[0], 0x107FFF040)
        self.assertEqual(struct.unpack_from("<I", raw, 32)[0], 16)
        self.assertEqual(struct.unpack_from("<I", raw, 36)[0], 0)

    def test_requests_the_driver_would_refuse_are_refused_first(self) -> None:
        bad = [
            (0, 0x2E4, 3, 0, 1),
            (1, 0, 3, 0, 1),
            (1, 0x2E4, -1, 0, 1),
            (1, 0x2E4, 3, -1, 1),
            (1, 0x2E4, 3, 0, 0),
            (1, 0x2E4, 3, 0, 0x1001),
            (1, 0x2E4, 3, 0xFFF, 2),
            (1 << 32, 0x2E4, 3, 0, 1),
        ]
        for args in bad:
            with self.subTest(args=args), self.assertRaises(ValueError):
                h3_memory.request(*args)

    def test_the_last_byte_of_a_page_is_one_request(self) -> None:
        self.assertEqual(len(h3_memory.request(1, 2, 3, 0xFFF, 1)), 40)


class AnswerTests(unittest.TestCase):
    def test_a_version_the_client_does_not_speak_is_refused(self) -> None:
        with self.assertRaisesRegex(OSError, "ABI version 2"):
            h3_memory.parse_answer(answer(version=2, length=4), 4)

    def test_ok_must_carry_exactly_the_bytes_asked_for(self) -> None:
        with self.assertRaisesRegex(OSError, "ok with 3 of 4"):
            h3_memory.parse_answer(answer(length=3), 4)

    def test_a_failure_must_carry_no_bytes(self) -> None:
        with self.assertRaisesRegex(OSError, "not-present with 4 bytes"):
            h3_memory.parse_answer(answer("not-present", stage=8, length=4), 4)

    def test_unknown_results_and_stages_are_refused(self) -> None:
        with self.assertRaisesRegex(OSError, "unknown result 9"):
            h3_memory.parse_answer(answer("nonsense"), 4)
        with self.assertRaisesRegex(OSError, "stage 99"):
            h3_memory.parse_answer(answer("error", stage=99), 4)

    def test_identity_is_distinct_from_every_gpa_result(self) -> None:
        parsed = h3_memory.parse_answer(answer("identity", stage=6, status=0xC0000024), 4)
        self.assertEqual((parsed.result, parsed.stage), ("identity", "partition"))
        self.assertIn("identity at partition (status 0xc0000024)", parsed.failure())


class CapabilityTests(unittest.TestCase):
    def test_an_empty_request_refused_at_request_is_the_abi(self) -> None:
        class Driver:
            def ioctl(self, code: int, payload: bytes, out_size: int) -> bytes:
                assert code == MEMREAD and struct.unpack_from("<I", payload, 32)[0] == 0
                return answer("error", stage=1, status=0xC000000D) + bytes(0x1000)

        self.assertEqual(h3_memory.capability(Driver()), (True, "memory operation ABI 1"))

    def test_a_driver_without_the_operation_is_not_the_abi(self) -> None:
        class OldDriver:
            def ioctl(self, code: int, payload: bytes, out_size: int) -> bytes:
                raise RuntimeError("DeviceIoControl 0x222048: Win32 1")

        ok, detail = h3_memory.capability(OldDriver())
        self.assertFalse(ok)
        self.assertIn("is not served", detail)

    def test_an_empty_request_served_as_anything_else_is_not_the_abi(self) -> None:
        class Odd:
            def ioctl(self, code: int, payload: bytes, out_size: int) -> bytes:
                return answer("identity", stage=3) + bytes(0x1000)

        self.assertFalse(h3_memory.capability(Odd())[0])


class ReaderTests(unittest.TestCase):
    def test_a_read_across_a_page_boundary_is_two_exact_requests(self) -> None:
        guest = Guest({0x10: bytes([0x11]) * 0x1000, 0x11: bytes([0x22]) * 0x1000})
        reader = h3_memory.Reader(guest, 4242, 0x2E4, 3)
        data, failure = reader.read(0x10FFE, 4)
        self.assertEqual((data, failure), (bytes([0x11, 0x11, 0x22, 0x22]), None))
        self.assertEqual([call[0] for call in guest.calls], [MEMREAD, MEMREAD])
        lengths = [struct.unpack_from("<I", call[1], 32)[0] for call in guest.calls]
        self.assertEqual(lengths, [2, 2])
        self.assertEqual({call[2] for call in guest.calls}, {32 + 0x1000})

    def test_a_read_above_four_gib_keeps_the_full_gpa(self) -> None:
        guest = Guest({0x107FFF: bytes([0xA5]) * 0x1000})
        data, failure = h3_memory.Reader(guest, 1, 2, 3).read(0x107FFF040, 4)
        self.assertEqual((data, failure), (bytes([0xA5]) * 4, None))
        self.assertEqual(struct.unpack_from("<Q", guest.calls[0][1], 24)[0], 0x107FFF040)

    def test_a_zero_page_that_is_ram_is_data_and_an_absent_page_is_not(self) -> None:
        guest = Guest({0: bytes(0x1000)}, absent={0xF8000})
        reader = h3_memory.Reader(guest, 1, 2, 3)
        self.assertEqual(reader.read(0, 8), (bytes(8), None))
        data, failure = reader.read(0xF8000000, 8)
        self.assertIsNone(data)
        self.assertIn("not-present at translate", failure or "")
        self.assertEqual(reader.results, {"ok": 1, "not-present": 1})
        self.assertEqual(reader.failed_calls, 0)

    def test_a_failed_call_is_counted_apart_from_a_typed_answer(self) -> None:
        class Gone:
            def ioctl(self, code: int, payload: bytes, out_size: int) -> bytes:
                raise OSError("DeviceIoControl 0x22204C: Win32 6")

        reader = h3_memory.Reader(Gone(), 1, 2, 3)
        data, failure = reader.read(0x1000, 8)
        self.assertIsNone(data)
        self.assertEqual(failure, "h3 memory: DeviceIoControl 0x22204C: Win32 6")
        self.assertEqual((reader.failed_calls, reader.results), (1, {}))

    def test_a_short_driver_answer_is_a_failure_not_a_page(self) -> None:
        class Short:
            def ioctl(self, code: int, payload: bytes, out_size: int) -> bytes:
                return answer(length=8)

        data, failure = h3_memory.Reader(Short(), 1, 2, 3).read(0x1000, 8)
        self.assertIsNone(data)
        self.assertIn("returned 32 of 4128 bytes", failure or "")

    def test_a_closed_device_reads_nothing(self) -> None:
        device = h3_memory.Device.__new__(h3_memory.Device)
        device.handle = None
        data, failure = h3_memory.Reader(device, 1, 2, 3).read(0x1000, 8)
        self.assertIsNone(data)
        self.assertIn("is closed", failure or "")

    def test_no_identity_is_refused_before_any_read(self) -> None:
        for args in ((0, 2, 3), (1, 0, 3)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                h3_memory.Reader(Guest({}), *args)


class WriterTests(unittest.TestCase):
    def test_a_write_across_a_page_boundary_is_two_requests_carrying_their_bytes(self) -> None:
        guest = Guest({0x5: bytes(0x1000), 0x6: bytes(0x1000)})
        writer = h3_memory.Writer(guest, 1, 2, 3)
        self.assertEqual(writer.write(0x5FFF, b"\xCC\x90"), (2, None))
        self.assertEqual([call[0] for call in guest.calls], [MEMWRITE, MEMWRITE])
        self.assertEqual([len(call[1]) for call in guest.calls], [41, 41])
        self.assertEqual({call[2] for call in guest.calls}, {32})
        self.assertEqual((guest.pages[0x5][0xFFF], guest.pages[0x6][0]), (0xCC, 0x90))

    def test_a_write_stops_at_the_first_page_that_fails(self) -> None:
        guest = Guest({0x5: bytes(0x1000)}, absent={0x6})
        writer = h3_memory.Writer(guest, 1, 2, 3)
        written, failure = writer.write(0x5FFF, b"\xCC\x90")
        self.assertEqual(written, 1)
        self.assertIn("not-present", failure or "")
        self.assertEqual(writer.calls, 2)

    def test_an_empty_write_sends_nothing(self) -> None:
        guest = Guest({})
        self.assertEqual(h3_memory.Writer(guest, 1, 2, 3).write(0x5000, b""), (0, None))
        self.assertEqual(guest.calls, [])


if __name__ == "__main__":
    unittest.main()
