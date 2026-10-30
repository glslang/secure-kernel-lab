from __future__ import annotations

import unittest

from sklab import guest_ram, hvmm


class Device:
    """hvmm as the reader sees it: one call per page, answering with what `pages` holds.

    A GPA it holds nothing for comes back as a page of zeros, which is what the driver does for one
    with no RAM behind it (K3 2026-10-17). An entry of `b""` is the driver answering with no bytes,
    which it does when it cannot use the handle or the partition type.
    """

    def __init__(self, pages: dict[int, bytes], fail: Exception | None = None) -> None:
        self.pages, self.fail = pages, fail
        self.calls: list[tuple[int, bytes, int]] = []

    def ioctl(self, code: int, payload: bytes, out_size: int) -> bytes:
        self.calls.append((code, payload, out_size))
        if self.fail is not None:
            raise self.fail
        gpa = int.from_bytes(payload[0x28:0x30], "little")
        if code == hvmm.WRITE_MEMORY:
            size = int.from_bytes(payload[0x30:0x38], "little")
            base, offset = gpa & ~(hvmm.PAGE - 1), gpa & (hvmm.PAGE - 1)
            page_data = bytearray(self.pages.get(base, bytes(hvmm.PAGE)))
            page_data[offset : offset + size] = payload[hvmm.REQUEST_SIZE :]
            self.pages[base] = bytes(page_data)
            return bytes(out_size)
        return self.pages.get(gpa, bytes(out_size))


def page(fill: int) -> bytes:
    return bytes([fill]) * 0x1000


class RequestTests(unittest.TestCase):
    def test_the_request_is_the_one_hvlib_sends(self) -> None:
        # traced from hvlib on K3 2026-10-17, less +0x10, which the driver's read path does not use
        self.assertEqual(
            hvmm.request(0x1F4, 7, 0x2601000),
            bytes.fromhex("f401000000000000" "0700000000000000") + bytes(0x18)
            + bytes.fromhex("0010600200000000" "0010000000000000") + bytes(0x18),
        )

    def test_the_address_is_cut_to_its_page(self) -> None:
        self.assertEqual(hvmm.request(1, 1, 0x2601ABC)[0x28:0x30], (0x2601000).to_bytes(8, "little"))

    def test_the_code_is_function_0x830_buffered(self) -> None:
        self.assertEqual(hvmm.READ_MEMORY, (0x22 << 16) | (0x830 << 2))

    def test_write_request_is_the_installed_drivers_header_plus_data(self) -> None:
        request = hvmm.write_request(0x1F4, 7, 0x2601ABC, b"\x12\x34")
        self.assertEqual(len(request), 0x52)
        self.assertEqual(request[0x00:0x08], (0x1F4).to_bytes(8, "little"))
        self.assertEqual(request[0x08:0x10], (7).to_bytes(8, "little"))
        self.assertEqual(request[0x28:0x30], (0x2601ABC).to_bytes(8, "little"))
        self.assertEqual(request[0x30:0x38], (2).to_bytes(8, "little"))
        self.assertEqual(request[0x50:], b"\x12\x34")

    def test_write_request_refuses_empty_cross_page_and_missing_handle(self) -> None:
        for arguments in (
            (0, 7, 0x1000, b"x"),
            (1, 7, 0x1000, b""),
            (1, 7, 0x1FFF, b"xx"),
            (1, 7, 0x1000, bytes(hvmm.PAGE + 1)),
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(ValueError):
                    hvmm.write_request(*arguments)

    def test_the_write_code_is_function_0x835_buffered(self) -> None:
        self.assertEqual(hvmm.WRITE_MEMORY, (0x22 << 16) | (0x835 << 2))


class DuplicatedHandleTests(unittest.TestCase):
    def test_zero_coordinates_are_refused_before_opening_a_process(self) -> None:
        with self.assertRaises(ValueError):
            hvmm.DuplicatedHandle(0, 0x2E0)
        with self.assertRaises(ValueError):
            hvmm.DuplicatedHandle(4242, 0)

    def test_duplication_uses_only_duplicate_handle_access(self) -> None:
        self.assertEqual(hvmm.PROCESS_DUP_HANDLE, 0x40)
        self.assertEqual(hvmm.DUPLICATE_SAME_ACCESS, 0x2)


class ReaderTests(unittest.TestCase):
    def test_a_read_within_a_page(self) -> None:
        device = Device({0x5000: bytes(range(256)) * 16})
        data, failure = hvmm.Reader(device, 0x1F4, 7).read(0x5010, 4)
        self.assertIsNone(failure)
        self.assertEqual(data, bytes([0x10, 0x11, 0x12, 0x13]))
        self.assertEqual([call[0] for call in device.calls], [0x2220C0])
        self.assertEqual(device.calls[0][2], 0x1000)

    def test_a_read_across_pages_takes_each(self) -> None:
        device = Device({0x5000: page(0x11), 0x6000: page(0x22)})
        data, failure = hvmm.Reader(device, 0x1F4, 7).read(0x5FFE, 4)
        self.assertIsNone(failure)
        self.assertEqual(data, bytes([0x11, 0x11, 0x22, 0x22]))
        self.assertEqual(len(device.calls), 2)

    def test_a_read_above_four_gib_keeps_the_full_gpa(self) -> None:
        high_gpa = 0x107FFF000
        device = Device({high_gpa: page(0xA5)})
        data, failure = hvmm.Reader(device, 0x1F4, 7).read(high_gpa + 0x40, 4)
        self.assertEqual((data, failure), (bytes([0xA5]) * 4, None))
        self.assertEqual(
            int.from_bytes(device.calls[0][1][0x28:0x30], "little"),
            high_gpa,
        )

    def test_a_short_answer_is_a_failure(self) -> None:
        reader = hvmm.Reader(Device({0x5000: b""}), 0x1F4, 7)
        data, failure = reader.read(0x5000, 8)
        self.assertIsNone(data)
        self.assertEqual(failure, "hvmm returned 0 of 4096 bytes")
        self.assertEqual(reader.failed_calls, 0)  # the driver answered; it had no page to give

    def test_a_page_with_no_ram_behind_it_reads_as_zeros(self) -> None:
        # Not a property anyone wants: the limit this reader has, pinned so a fix changes it on purpose.
        # On K3 2026-10-17, 0x108000000 is the first page past RAM and hvmm answered it with zeros.
        self.assertEqual(hvmm.Reader(Device({}), 0x1F4, 7).read(0x108000000, 8), (bytes(8), None))

    def test_zeros_outside_the_guests_ram_are_no_page(self) -> None:
        # K3's last run ends at 0x108000000, and hvmm answered that page with zeros on 2026-10-17
        reader = hvmm.Reader(Device({}), 0x1F4, 7, guest_ram.Ram([(0x100000000, 0x108000000)]))
        data, failure = reader.read(0x108000010, 8)
        self.assertIsNone(data)
        self.assertEqual(failure, "no RAM here by the guest's own map; hvmm answered with zeros, the hypervisor: not asked")
        self.assertEqual((reader.outside_zero, reader.outside_with_data, reader.failed_calls), (1, 0, 0))
        self.assertEqual(reader.refused, [0x108000000])

    def test_zeros_inside_the_guests_ram_are_a_page_of_zeros(self) -> None:
        reader = hvmm.Reader(Device({}), 0x1F4, 7, guest_ram.Ram([(0x100000000, 0x108000000)]))
        self.assertEqual(reader.read(0x107FFF000, 8), (bytes(8), None))
        self.assertEqual(reader.outside_zero, 0)

    def test_data_outside_the_guests_ram_is_kept_and_counted_against_the_map(self) -> None:
        reader = hvmm.Reader(Device({0x977000: page(0x5A)}), 0x1F4, 7, guest_ram.Ram([(0x100000, 0x977000)]))
        self.assertEqual(reader.read(0x977000, 2), (bytes([0x5A, 0x5A]), None))
        self.assertEqual((reader.outside_with_data, reader.contradictions), (1, [0x977000]))

    def ram_reader(self, answers: dict[int, tuple[bool | None, str]], pages: dict[int, bytes] | None = None):
        asked: list[int] = []

        class Hypervisor:
            def ask(self, gpa: int) -> tuple[bool | None, str]:
                asked.append(gpa)
                return answers[gpa]

        ram = guest_ram.Ram([(0x1000, 0xA0000), (0x100000000, 0x108000000)])
        return hvmm.Reader(Device(pages or {}), 0x1F4, 7, ram, Hypervisor()), asked

    def test_zeros_the_hypervisor_calls_memory_are_a_page_of_zeros(self) -> None:
        # page 0 on K3 2026-10-17: outside NT's runs, zeros through hvmm, Accepted by HvCallReadGpa
        reader, asked = self.ram_reader({0x0: (True, "Accepted")})
        self.assertEqual(reader.read(0x10, 8), (bytes(8), None))
        self.assertEqual((reader.outside_zero_backed, reader.outside_zero, reader.answers), (1, 0, {0x0: "Accepted"}))
        self.assertEqual(asked, [0x0])

    def test_zeros_the_hypervisor_does_not_call_memory_are_no_page(self) -> None:
        # the local APIC page on K3 2026-10-17: HvCallReadGpa failed with HV_STATUS 0x0080
        reader, _ = self.ram_reader({0xFEE00000: (False, "HV_STATUS 0x0080")})
        data, failure = reader.read(0xFEE00000, 8)
        self.assertIsNone(data)
        self.assertTrue(failure.endswith("the hypervisor: HV_STATUS 0x0080"))
        self.assertEqual((reader.outside_zero, reader.refused, reader.outside_zero_backed), (1, [0xFEE00000], 0))

    def test_an_unanswered_question_refuses_as_before(self) -> None:
        reader, _ = self.ram_reader({0x108000000: (None, "h3probe: DeviceIoControl 0x222004: Win32 6")})
        self.assertIsNone(reader.read(0x108000000, 8)[0])
        self.assertEqual(reader.outside_zero, 1)

    def test_only_zeros_outside_the_runs_are_asked_about(self) -> None:
        reader, asked = self.ram_reader({}, {0x977000: page(0x5A)})
        reader.read(0x5000, 8)  # zeros inside the runs
        reader.read(0x977000, 8)  # data outside them
        self.assertEqual(asked, [])

    def test_part_of_a_page_is_a_failure(self) -> None:
        data, failure = hvmm.Reader(Device({0x5000: bytes(0x800)}), 0x1F4, 7).read(0x5000, 8)
        self.assertIsNone(data)
        self.assertEqual(failure, "hvmm returned 2048 of 4096 bytes")

    def test_a_failed_call_is_a_failure(self) -> None:
        reader = hvmm.Reader(Device({}, OSError("DeviceIoControl 0x2220C0: Win32 6")), 0x1F4, 7)
        data, failure = reader.read(0, 8)
        self.assertIsNone(data)
        self.assertEqual(failure, "hvmm: DeviceIoControl 0x2220C0: Win32 6")
        self.assertEqual(reader.failed_calls, 1)

    def test_no_handle_is_refused_before_any_read(self) -> None:
        with self.assertRaises(ValueError):
            hvmm.Reader(Device({}), 0, 7)


class WriterTests(unittest.TestCase):
    def test_an_in_page_write_uses_the_write_ioctl(self) -> None:
        device = Device({0x5000: page(0x11)})
        written, failure = hvmm.Writer(device, 0x1F4, 7).write(0x5010, b"\x22\x33")
        self.assertEqual((written, failure), (2, None))
        self.assertEqual(device.pages[0x5000][0x10:0x12], b"\x22\x33")
        self.assertEqual([call[0] for call in device.calls], [hvmm.WRITE_MEMORY])
        self.assertEqual(device.calls[0][2], 1)

    def test_a_cross_page_write_is_split_at_the_boundary(self) -> None:
        device = Device({0x5000: page(0x11), 0x6000: page(0x22)})
        writer = hvmm.Writer(device, 0x1F4, 7)
        written, failure = writer.write(0x5FFE, b"abcd")
        self.assertEqual((written, failure), (4, None))
        self.assertEqual(device.pages[0x5000][-2:], b"ab")
        self.assertEqual(device.pages[0x6000][:2], b"cd")
        self.assertEqual(writer.calls, 2)

    def test_a_failed_second_page_reports_the_completed_prefix(self) -> None:
        class FailsSecond(Device):
            def ioctl(self, code: int, payload: bytes, out_size: int) -> bytes:
                if len(self.calls) == 1:
                    raise OSError("second page failed")
                return super().ioctl(code, payload, out_size)

        writer = hvmm.Writer(FailsSecond({0x5000: page(0)}), 0x1F4, 7)
        written, failure = writer.write(0x5FFF, b"ab")
        self.assertEqual(written, 1)
        self.assertEqual(failure, "hvmm: second page failed")
        self.assertEqual(writer.failed_calls, 1)

    def test_a_short_completion_is_a_failed_write(self) -> None:
        class ShortCompletion(Device):
            def ioctl(self, code: int, payload: bytes, out_size: int) -> bytes:
                self.calls.append((code, payload, out_size))
                return b""

        writer = hvmm.Writer(ShortCompletion({}), 0x1F4, 7)
        written, failure = writer.write(0x5000, b"x")
        self.assertEqual(written, 0)
        self.assertEqual(failure, "hvmm: hvmm write returned 0 of 1 completion bytes")
        self.assertEqual((writer.calls, writer.failed_calls), (1, 1))

    def test_no_handle_is_refused_before_any_write(self) -> None:
        with self.assertRaises(ValueError):
            hvmm.Writer(Device({}), 0, 7)


if __name__ == "__main__":
    unittest.main()
