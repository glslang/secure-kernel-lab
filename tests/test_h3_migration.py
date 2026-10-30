from __future__ import annotations

import unittest
from dataclasses import dataclass

from sklab import h3_migration


@dataclass(frozen=True)
class FakeTranslation:
    gpn: int
    kind: str
    fields: tuple[int, int, int, int]
    translate_status: int = 0


LOW, HIGH = 0x111, 0x222


def k3_like(gpn: int) -> FakeTranslation:
    """Low RAM in one block with a non-memory hole, a device gap, then high RAM in a second block."""
    if 0xA0 <= gpn < 0xC0:
        return FakeTranslation(gpn, "other-range", (0x99, 0, 0, 0x3))
    if gpn < 0xF8000:
        return FakeTranslation(gpn, "memory-block", (0, LOW, gpn, 0x11))
    if 0x100000 <= gpn < 0x108000:
        return FakeTranslation(gpn, "memory-block", (0, HIGH, gpn - 0x100000, 0x11))
    return FakeTranslation(gpn, "none", (0, 0, 0, 0))


class RangeMapTests(unittest.TestCase):
    def test_every_boundary_is_bisected_to_the_exact_page(self) -> None:
        asked: list[int] = []

        def ask(gpn: int) -> FakeTranslation:
            asked.append(gpn)
            return k3_like(gpn)

        runs = h3_migration.range_map(ask, 0x110000, 0x40)
        self.assertEqual(
            [(run["start"], run["end"], run["kind"]) for run in runs],
            [
                ("0x0", "0xa0000", "memory-block"),
                ("0xa0000", "0xc0000", "other-range"),
                ("0xc0000", "0xf8000000", "memory-block"),
                ("0xf8000000", "0x100000000", "none"),
                ("0x100000000", "0x108000000", "memory-block"),
                ("0x108000000", "0x110000000", "none"),
            ],
        )
        self.assertEqual(runs[2]["block_page"], "0xc0")
        self.assertEqual(runs[4]["block_page"], "0x0")
        self.assertEqual(sum(run["pages"] for run in runs), 0x110000)
        self.assertLess(len(set(asked)), 0x110000 // 0x40 + 0x100 + 100)

    def test_a_block_page_that_is_not_linear_starts_a_new_run(self) -> None:
        def ask(gpn: int) -> FakeTranslation:
            page = gpn if gpn < 0x80 else gpn + 7
            return FakeTranslation(gpn, "memory-block", (0, LOW, page, 0x11))

        runs = h3_migration.range_map(ask, 0x100, 0x40, dense_below=0)
        self.assertEqual([(run["start"], run["pages"]) for run in runs], [("0x0", 0x80), ("0x80000", 0x80)])

    def test_a_failed_translation_is_its_own_run_not_absence(self) -> None:
        def ask(gpn: int) -> FakeTranslation:
            if gpn == 0x50:
                return FakeTranslation(gpn, "unknown", (0, 0, 0, 0), 0xC0000022)
            return k3_like(gpn)

        runs = h3_migration.range_map(ask, 0x100, 0x10, dense_below=0)
        self.assertIn(("0x50000", 1, "unknown"), [(run["start"], run["pages"], run["kind"]) for run in runs])

    def test_a_hole_between_two_samples_of_one_run_is_not_seen_above_the_dense_region(self) -> None:
        def ask(gpn: int) -> FakeTranslation:
            if 0x2A0 <= gpn < 0x2C0:
                return FakeTranslation(gpn, "other-range", (0x99, 0, 0, 0x3))
            return FakeTranslation(gpn, "memory-block", (0, LOW, gpn, 0x11))

        sampled = h3_migration.range_map(ask, 0x400, 0x40)
        dense = h3_migration.range_map(ask, 0x400, 0x40, dense_below=0x400)
        self.assertEqual(len(sampled), 1)
        self.assertEqual([run["kind"] for run in dense], ["memory-block", "other-range", "memory-block"])


class SampleTests(unittest.TestCase):
    def runs(self) -> list[dict[str, object]]:
        return h3_migration.range_map(k3_like, 0x110000, 0x400)

    def test_samples_are_memory_block_pages_and_reproducible(self) -> None:
        first = h3_migration.sample_pages(self.runs(), 64, 7)
        self.assertEqual(first, h3_migration.sample_pages(self.runs(), 64, 7))
        self.assertEqual(len(set(first)), 64)
        for gpa in first:
            self.assertEqual(gpa & 0xFFF, 0)
            self.assertEqual(k3_like(gpa >> 12).kind, "memory-block")

    def test_high_ram_is_reachable_by_the_sample(self) -> None:
        pages = h3_migration.sample_pages(self.runs(), 4096, 1)
        self.assertTrue(any(gpa >= 0x100000000 for gpa in pages))


def comparison(result: str, *, agree: bool | None = True, zero: bool | None = False, backing: str = "Accepted") -> dict[str, object]:
    return {"h3": {"result": result, "all_zero": zero}, "hypervisor_bytes_agree": agree, "backing": backing}


def validated() -> dict[str, object]:
    registers = {name: {"low": "0x0"} for name in ("dr0", "dr1", "dr2", "dr3", "dr6", "dr7")}
    identity = {"machine": "0x8664", "timestamp": "0x12345678", "size_of_image": "0x1a4000"}
    return {
        "comparisons": {
            "mapped_code": comparison("ok", agree=None, backing="ReadIntercept"),
            "mapped_data": comparison("ok", agree=None, backing="ReadIntercept"),
            "mapped_zero": comparison("ok", zero=True),
            "ram_hole": comparison("ok", zero=True),
            "device_gap": comparison("not-present", agree=None, zero=None, backing="Unmapped"),
            "end_of_ram": comparison("not-present", agree=None, zero=None, backing="Unmapped"),
            "above_4gib": comparison("ok"),
        },
        "controls": {
            "vtl0_positive_control": comparison("ok"),
            "secure_kernel_header": {**comparison("ok", agree=None, backing="ReadIntercept"), "pe_identity": dict(identity)},
            "last_ram_page": comparison("ok"),
            "local_apic": comparison("not-present", agree=None, zero=None, backing="HV_STATUS 0x0080"),
            "far_above_ram": comparison("not-present", agree=None, zero=None, backing="Unmapped"),
        },
        "pinned_image": dict(identity),
        "sample": {"pages": 256, "read": 256, "hypervisor_checked": 250, "hypervisor_agreed": 250},
        "refusals": {"wrong_partition": {"passed": True}, "oversized": {"passed": True}},
        "leak": {"passed": True},
        "cancellation": {"passed": True},
        "unload": {"passed": True},
        "identity_change": {"passed": True},
        "hvlib_loaded_before": False,
        "hvlib_loaded_after": False,
        "state_before": {"registers": registers},
        "state_after": {"registers": dict(registers)},
        "vtl1_text": {"sha256_before": "ab", "sha256_after": "ab"},
        "same_boot": True,
    }


class ValidationVerdictTests(unittest.TestCase):
    def test_a_complete_validation_passes(self) -> None:
        verdict = h3_migration.validation_verdict(validated())
        self.assertTrue(verdict["passed"], verdict)

    def test_each_criterion_can_fail_the_gate(self) -> None:
        breaks = {
            "ram_reads": lambda r: r["comparisons"].update(ram_hole=comparison("error", agree=None)),
            "hypervisor_agrees": lambda r: r["controls"].update(vtl0_positive_control=comparison("ok", agree=False)),
            "protected_pages_read": lambda r: r["comparisons"]["mapped_data"].update(backing="Accepted"),
            "pinned_image_in_vtl1": lambda r: r["pinned_image"].update(timestamp="0x87654321"),
            "mapped_zero_is_data": lambda r: r["comparisons"]["mapped_zero"]["h3"].update(all_zero=False),
            "absence_is_typed": lambda r: r["controls"].update(local_apic=comparison("ok", agree=None, zero=True)),
            "sample_agreement": lambda r: r["sample"].update(hypervisor_agreed=249),
            "refusals": lambda r: r["refusals"]["oversized"].update(passed=False),
            "no_scratch_leak": lambda r: r["leak"].update(passed=False),
            "cancellation_contained": lambda r: r.pop("cancellation"),
            "unload_contained": lambda r: r["unload"].update(passed=False),
            "identity_change_refused": lambda r: r["identity_change"].update(passed=False),
            "no_hvlib": lambda r: r.update(hvlib_loaded_after=True),
            "debug_registers_unchanged": lambda r: r["state_after"]["registers"].update(dr7={"low": "0x1"}),
            "vtl1_text_unchanged": lambda r: r["vtl1_text"].update(sha256_after="cd"),
            "same_boot_health": lambda r: r.update(same_boot=None),
        }
        for name, mutate in breaks.items():
            with self.subTest(name=name):
                record = validated()
                mutate(record)
                verdict = h3_migration.validation_verdict(record)
                self.assertFalse(verdict["passed"])
                self.assertEqual([key for key, ok in verdict["criteria"].items() if not ok], [name])

    def test_a_page_the_hypervisor_never_answered_cannot_stand_for_agreement(self) -> None:
        record = validated()
        record["controls"]["vtl0_positive_control"]["hypervisor_bytes_agree"] = None
        self.assertFalse(h3_migration.validation_verdict(record)["criteria"]["hypervisor_agrees"])

    def test_a_sample_the_hypervisor_checked_none_of_does_not_pass(self) -> None:
        record = validated()
        record["sample"].update(hypervisor_checked=0, hypervisor_agreed=0)
        self.assertFalse(h3_migration.validation_verdict(record)["criteria"]["sample_agreement"])

    def test_no_refusals_recorded_is_not_a_pass(self) -> None:
        record = validated()
        record["refusals"] = {}
        self.assertFalse(h3_migration.validation_verdict(record)["criteria"]["refusals"])


if __name__ == "__main__":
    unittest.main()
