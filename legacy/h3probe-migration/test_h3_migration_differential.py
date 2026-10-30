from __future__ import annotations

import unittest
from dataclasses import dataclass

from sklab import h3_migration


class CorpusTests(unittest.TestCase):
    def corpus(self) -> dict[str, object]:
        samples = []
        for index, name in enumerate(h3_migration.SAMPLE_NAMES):
            if name in {"ram_hole", "device_gap", "end_of_ram"}:
                samples.append(h3_migration.page_record(name, index * 0x1000, None, "not present"))
            else:
                fill = 0 if name == "mapped_zero" else index + 1
                samples.append(h3_migration.page_record(name, index * 0x1000, bytes([fill]) * 0x1000, None))
        return {
            "schema": h3_migration.SCHEMA,
            "target": "synthetic",
            "boot_before": {},
            "identity_before": {},
            "state_before": {},
            "drivers": {},
            "samples": samples,
        }

    def test_the_synthetic_differential_corpus_is_complete(self) -> None:
        corpus = self.corpus()
        h3_migration.validate(corpus)
        self.assertTrue(corpus["samples"][2]["all_zero"])
        self.assertNotIn("data", corpus["samples"][0])

    def test_live_bytes_cannot_be_mistaken_for_metadata(self) -> None:
        record = h3_migration.page_record("mapped_code", 0x1000, b"A" * 0x1000, None)
        self.assertEqual(record["length"], 0x1000)
        self.assertIsInstance(record["sha256"], str)
        self.assertFalse(record["all_zero"])

    def test_a_partial_page_cannot_be_a_differential_oracle(self) -> None:
        corpus = self.corpus()
        corpus["samples"][0] = h3_migration.page_record("mapped_code", 0, b"short", None)
        with self.assertRaisesRegex(ValueError, "not one complete page"):
            h3_migration.validate(corpus)

    def test_mapped_zero_and_unmapped_are_distinct_records(self) -> None:
        mapped = h3_migration.page_record("mapped_zero", 0, bytes(0x1000), None, backing="Accepted")
        absent = h3_migration.page_record("end_of_ram", 0x108000000, None, "not present", backing="Unmapped")
        self.assertEqual((mapped["status"], mapped["all_zero"]), ("data", True))
        self.assertEqual((absent["status"], absent["all_zero"]), ("failure", None))


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


def comparison(result: str, *, matches: bool | None = True, zero: bool | None = False) -> dict[str, object]:
    return {"h3": {"result": result, "all_zero": zero}, "data_matches_hvmm": matches}


def measured() -> dict[str, object]:
    registers = {name: {"low": "0x0"} for name in ("dr0", "dr1", "dr2", "dr3", "dr6", "dr7")}
    return {
        "comparisons": {
            "mapped_code": comparison("ok"),
            "mapped_data": comparison("ok"),
            "mapped_zero": comparison("ok", zero=True),
            "ram_hole": comparison("ok"),
            "device_gap": comparison("not-present", matches=None, zero=None),
            "end_of_ram": comparison("not-present", matches=None, zero=None),
            "above_4gib": comparison("ok"),
        },
        "controls": {
            "vtl0_positive_control": comparison("ok"),
            "last_ram_page": comparison("ok"),
            "far_above_ram": comparison("not-present", matches=None, zero=None),
        },
        "sample": {"pages": 64, "agreed": 64},
        "hvlib_loaded_before": False,
        "hvlib_loaded_after": False,
        "state_before": {"registers": registers},
        "state_after": {"registers": dict(registers)},
        "same_boot": True,
    }


class Phase1VerdictTests(unittest.TestCase):
    def test_a_complete_measurement_passes(self) -> None:
        verdict = h3_migration.phase1_verdict(measured())
        self.assertTrue(verdict["passed"], verdict)

    def test_each_criterion_can_fail_the_gate(self) -> None:
        breaks = {
            "vtl0_positive_control": lambda r: r["controls"].update(vtl0_positive_control=comparison("ok", matches=False)),
            "vtl1_protected_pages": lambda r: r["comparisons"].update(mapped_code=comparison("refused", matches=None)),
            "high_ram": lambda r: r["comparisons"].update(above_4gib=comparison("not-present", matches=None)),
            "mapped_zero_is_typed_data": lambda r: r["comparisons"].update(mapped_zero=comparison("not-present", zero=None)),
            "ram_boundary_is_exact": lambda r: r["controls"].update(last_ram_page=comparison("not-present", matches=None)),
            "absence_is_typed": lambda r: r["comparisons"].update(device_gap=comparison("ok", zero=True)),
            "sample_agreement": lambda r: r["sample"].update(agreed=63),
            "no_hvlib": lambda r: r.update(hvlib_loaded_after=True),
            "debug_registers_unchanged": lambda r: r["state_after"]["registers"].update(dr7={"low": "0x1"}),
            "same_boot_health": lambda r: r.update(same_boot=False),
        }
        for name, mutate in breaks.items():
            with self.subTest(name=name):
                record = measured()
                mutate(record)
                verdict = h3_migration.phase1_verdict(record)
                self.assertFalse(verdict["passed"])
                self.assertEqual([key for key, ok in verdict["criteria"].items() if not ok], [name])

    def test_an_empty_sample_does_not_pass(self) -> None:
        record = measured()
        record["sample"] = {"pages": 0, "agreed": 0}
        self.assertFalse(h3_migration.phase1_verdict(record)["criteria"]["sample_agreement"])


def validated() -> dict[str, object]:
    record = measured()
    record["controls"]["local_apic"] = comparison("not-present", matches=None, zero=None)
    record["refusals"] = {"wrong_partition": {"passed": True}, "oversized": {"passed": True}}
    record["leak"] = {"passed": True}
    record["cancellation"] = {"passed": True}
    record["unload"] = {"passed": True}
    record["identity_change"] = {"passed": True}
    record["vtl1_text"] = {"sha256_before": "ab", "sha256_after": "ab"}
    return record


class Phase2VerdictTests(unittest.TestCase):
    def test_a_complete_validation_passes(self) -> None:
        verdict = h3_migration.phase2_verdict(validated())
        self.assertTrue(verdict["passed"], verdict)

    def test_each_criterion_can_fail_the_gate(self) -> None:
        breaks = {
            "ram_agrees_with_hvmm": lambda r: r["comparisons"].update(ram_hole=comparison("ok", matches=False)),
            "mapped_zero_is_data": lambda r: r["comparisons"]["mapped_zero"]["h3"].update(all_zero=False),
            "absence_is_typed": lambda r: r["controls"].update(local_apic=comparison("ok", zero=True)),
            "sample_agreement": lambda r: r["sample"].update(agreed=0),
            "refusals": lambda r: r["refusals"]["oversized"].update(passed=False),
            "no_scratch_leak": lambda r: r["leak"].update(passed=False),
            "cancellation_contained": lambda r: r.pop("cancellation"),
            "unload_contained": lambda r: r["unload"].update(passed=False),
            "identity_change_refused": lambda r: r["identity_change"].update(passed=False),
            "no_hvlib": lambda r: r.update(hvlib_loaded_before=None),
            "debug_registers_unchanged": lambda r: r["state_after"]["registers"].update(dr0={"low": "0x8"}),
            "vtl1_text_unchanged": lambda r: r["vtl1_text"].update(sha256_after="cd"),
            "same_boot_health": lambda r: r.update(same_boot=None),
        }
        for name, mutate in breaks.items():
            with self.subTest(name=name):
                record = validated()
                mutate(record)
                verdict = h3_migration.phase2_verdict(record)
                self.assertEqual([key for key, ok in verdict["criteria"].items() if not ok], [name])

    def test_no_refusals_recorded_is_not_a_pass(self) -> None:
        record = validated()
        record["refusals"] = {}
        self.assertFalse(h3_migration.phase2_verdict(record)["criteria"]["refusals"])


if __name__ == "__main__":
    unittest.main()
