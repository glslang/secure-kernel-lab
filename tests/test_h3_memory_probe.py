from __future__ import annotations

import struct
import unittest

from sklab import h3_memory_probe


# Byte offsets of H3_VIDTRANSLATE_OUT and H3_VIDREADPROBE_OUT in drivers/h3probe/h3probe.c,
# written out rather than taken from the module's own Struct so a layout drift in either
# file fails here instead of agreeing with itself.
TRANSLATE_SIZE = 112
READ_SIZE = 200 + 0x1000


def identity(raw: bytearray, base: int, *, owner_matched: int = 1) -> None:
    struct.pack_into("<8I2Q", raw, base, 0xD2E40B4A, 0xDC000, 0, 0, 1, 1, owner_matched, 0,
                     0xFFFF800012340000, 0xFFFF800012340000)


def translate_answer(fields: tuple[int, int, int, int], gpn: int = 0x107FFF) -> bytes:
    raw = bytearray(TRANSLATE_SIZE)
    struct.pack_into("<II", raw, 0, 2, 0)
    identity(raw, 8)
    struct.pack_into("<Q", raw, 56, gpn)
    struct.pack_into("<II", raw, 64, 0, 0)
    struct.pack_into("<Q", raw, 72, 32)
    struct.pack_into("<4Q", raw, 80, *fields)
    return bytes(raw)


def read_answer(
    result: int = 0,
    *,
    data: bytes = bytes([0xA5]) * 0x1000,
    length: int = 0x1000,
    version: int = 2,
) -> bytes:
    raw = bytearray(READ_SIZE)
    struct.pack_into("<II", raw, 0, version, result)
    identity(raw, 8)
    struct.pack_into("<Q", raw, 56, 0x107FFF)
    struct.pack_into("<II", raw, 64, 0, 0)
    struct.pack_into("<Q", raw, 72, 32)
    struct.pack_into("<4Q", raw, 80, 0, 0x265F2FB73C0, 0x7FFF, 0x11)
    struct.pack_into("<4I", raw, 112, 0, 9, 1, 0)
    struct.pack_into("<4Q", raw, 128, 3, 0x8000, 8, 0x1000)
    struct.pack_into("<II", raw, 160, 0, length)
    struct.pack_into("<4Q", raw, 168, 0, 0x265F2FB73C0, 0x7FFF, 0x11)
    raw[200:200 + len(data)] = data
    return bytes(raw)


class Device:
    def __init__(self, answer: bytes) -> None:
        self.answer = answer
        self.calls: list[tuple[int, bytes, int]] = []

    def ioctl(self, code: int, payload: bytes, out_size: int) -> bytes:
        self.calls.append((code, payload, out_size))
        return self.answer


class LayoutTests(unittest.TestCase):
    def test_struct_sizes_match_the_drivers_compile_time_assertions(self) -> None:
        self.assertEqual(h3_memory_probe.INPUT.size, 24)
        self.assertEqual(h3_memory_probe.IDENT.size, 48)
        self.assertEqual(h3_memory_probe.TRANSLATE_OUTPUT.size, TRANSLATE_SIZE)
        self.assertEqual(h3_memory_probe.READ_OUTPUT.size, READ_SIZE)


class TranslateTests(unittest.TestCase):
    def test_translate_sends_the_byte_address_and_reads_the_page_number_back(self) -> None:
        device = Device(translate_answer((0, 0x265F2FB73C0, 0x7FFF, 0x11)))
        result = h3_memory_probe.translate(device, 4242, 0x2E0, 0x107FFF000)
        self.assertTrue(result.succeeded)
        self.assertEqual(result.gpn, 0x107FFF)
        self.assertEqual(result.kind, "memory-block")
        code, payload, out_size = device.calls[0]
        self.assertEqual(code, (0x22 << 16) | (0x810 << 2))
        self.assertEqual(struct.unpack("<IIQQ", payload), (4242, 0, 0x2E0, 0x107FFF000))
        self.assertEqual(out_size, TRANSLATE_SIZE)

    def test_no_range_and_a_non_memory_range_are_different_kinds(self) -> None:
        none = h3_memory_probe.translate(Device(translate_answer((0, 0, 0, 0))), 1, 2, 0x108000000)
        mmio = h3_memory_probe.translate(Device(translate_answer((0x2A0, 0, 0, 0))), 1, 2, 0xFEE00000)
        self.assertEqual((none.kind, mmio.kind), ("none", "other-range"))

    def test_an_identity_mismatch_is_not_a_translation(self) -> None:
        raw = bytearray(translate_answer((0, 0, 0, 0)))
        identity(raw, 8, owner_matched=0)
        result = h3_memory_probe.translate(Device(bytes(raw)), 1, 2, 0)
        self.assertFalse(result.succeeded)
        self.assertEqual(result.kind, "unknown")

    def test_a_version_one_driver_is_refused(self) -> None:
        raw = bytearray(translate_answer((0, 0, 0, 0)))
        struct.pack_into("<I", raw, 0, 1)
        with self.assertRaisesRegex(OSError, "version 1"):
            h3_memory_probe.translate(Device(bytes(raw)), 1, 2, 0)

    def test_short_driver_output_is_not_accepted(self) -> None:
        with self.assertRaisesRegex(OSError, "returned 111 of 112"):
            h3_memory_probe.translate(Device(translate_answer((0, 0, 0, 0))[:-1]), 1, 2, 0)

    def test_invalid_identity_and_gpa_are_refused_before_the_call(self) -> None:
        for args in ((0, 2, 0), (1, 0, 0), (1, 2, -1), (1, 2, 1 << 64)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                h3_memory_probe.translate(Device(b""), *args)


class ReadProbeTests(unittest.TestCase):
    def test_an_ok_read_returns_exactly_one_page(self) -> None:
        device = Device(read_answer())
        result = h3_memory_probe.read_probe(device, 6508, 0x2E0, 0x107FFF000)
        self.assertTrue(result.succeeded)
        self.assertEqual(result.data, bytes([0xA5]) * 0x1000)
        self.assertEqual((result.memory_block_handle, result.memory_block_pages), (3, 0x8000))
        self.assertEqual(result.translate_fields[2], 0x7FFF)
        self.assertEqual(result.recheck_fields, result.translate_fields)
        self.assertEqual((result.table_count, result.table_matches), (9, 1))
        self.assertEqual(result.completion, 0x1000)
        self.assertEqual(device.calls[0][0], (0x22 << 16) | (0x811 << 2))
        self.assertEqual(device.calls[0][2], READ_SIZE)

    def test_a_zero_page_that_is_ram_is_ok_with_zero_data(self) -> None:
        result = h3_memory_probe.read_probe(Device(read_answer(data=bytes(0x1000))), 1, 2, 0)
        self.assertEqual(result.result, "ok")
        self.assertTrue(result.record()["all_zero"])

    def test_typed_failures_carry_no_data(self) -> None:
        for code, name in ((1, "not-present"), (2, "refused"), (3, "error"), (4, "identity")):
            with self.subTest(name=name):
                result = h3_memory_probe.read_probe(
                    Device(read_answer(code, data=bytes(0x1000), length=0)), 1, 2, 0x108000000
                )
                self.assertEqual(result.result, name)
                self.assertFalse(result.succeeded)
                self.assertEqual(result.data, b"")
                self.assertIsNone(result.record()["sha256"])

    def test_ok_with_a_short_page_is_rejected(self) -> None:
        with self.assertRaisesRegex(OSError, "ok with 2048 data bytes"):
            h3_memory_probe.read_probe(Device(read_answer(length=0x800)), 1, 2, 0)

    def test_a_failure_carrying_data_is_rejected(self) -> None:
        with self.assertRaisesRegex(OSError, "not-present with 4096 data bytes"):
            h3_memory_probe.read_probe(Device(read_answer(1)), 1, 2, 0)

    def test_an_unknown_result_code_is_rejected(self) -> None:
        with self.assertRaisesRegex(OSError, "unknown result 9"):
            h3_memory_probe.read_probe(Device(read_answer(9, length=0)), 1, 2, 0)

    def test_a_version_one_driver_is_refused(self) -> None:
        with self.assertRaisesRegex(OSError, "version 1"):
            h3_memory_probe.read_probe(Device(read_answer(version=1)), 1, 2, 0)

    def test_unaligned_gpa_is_refused_before_the_call(self) -> None:
        device = Device(b"")
        with self.assertRaisesRegex(ValueError, "page aligned"):
            h3_memory_probe.read_probe(device, 1, 2, 1)
        self.assertEqual(device.calls, [])


if __name__ == "__main__":
    unittest.main()
