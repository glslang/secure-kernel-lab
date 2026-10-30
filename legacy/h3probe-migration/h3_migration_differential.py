"""Versioned records for the hvmm-to-h3probe differential migration.

Live page bytes are intentionally never serialized.  A corpus record carries
only addresses, status, length, all-zero classification, and SHA-256 digests.
That is sufficient to compare providers without checking guest memory into Git.

The range map and sample below are the differential's address sources, and
``phase1_verdict`` is the plan's Phase 1 decision gate stated as data.
"""

from __future__ import annotations

import hashlib
import random
from typing import Any, Callable


SCHEMA = "secure-kernel-lab.h3-memory-corpus.v1"
SAMPLE_NAMES = (
    "mapped_code",
    "mapped_data",
    "mapped_zero",
    "ram_hole",
    "device_gap",
    "end_of_ram",
    "above_4gib",
)


def page_record(
    name: str,
    gpa: int,
    data: bytes | None,
    failure: str | None,
    *,
    backing: str | None = None,
) -> dict[str, Any]:
    """Describe one page result without retaining its contents."""
    if name not in SAMPLE_NAMES:
        raise ValueError(f"unknown corpus sample {name!r}")
    if gpa < 0 or gpa & 0xFFF:
        raise ValueError("corpus GPAs must be non-negative and page aligned")
    if data is not None and failure is not None:
        raise ValueError("a sample cannot contain both data and a failure")
    return {
        "name": name,
        "gpa": f"0x{gpa:x}",
        "status": "data" if data is not None else "failure",
        "length": len(data) if data is not None else 0,
        "all_zero": data == bytes(len(data)) if data is not None else None,
        "sha256": hashlib.sha256(data).hexdigest() if data is not None else None,
        "failure": failure,
        "backing": backing,
    }


def validate(record: dict[str, Any]) -> None:
    """Reject a corpus that cannot serve as the migration's differential oracle."""
    if record.get("schema") != SCHEMA:
        raise ValueError(f"unsupported corpus schema {record.get('schema')!r}")
    for field in ("target", "boot_before", "identity_before", "state_before", "drivers"):
        if field not in record:
            raise ValueError(f"corpus is missing {field}")
    samples = record.get("samples")
    if not isinstance(samples, list):
        raise ValueError("corpus samples must be a list")
    names = [sample.get("name") for sample in samples if isinstance(sample, dict)]
    if sorted(names) != sorted(SAMPLE_NAMES):
        raise ValueError(f"corpus samples are {names}, expected {list(SAMPLE_NAMES)}")
    for sample in samples:
        if sample["status"] == "data":
            if sample["length"] != 0x1000 or not sample["sha256"]:
                raise ValueError(f"data sample {sample['name']} is not one complete page")
        elif sample["status"] == "failure":
            if not sample["failure"]:
                raise ValueError(f"failed sample {sample['name']} has no reason")
        else:
            raise ValueError(f"sample {sample['name']} has invalid status {sample['status']!r}")


def _run_key(translation: Any) -> tuple[Any, ...]:
    """Two pages share a run when VID answers for them the same way, linearly."""
    kind = translation.kind
    fields = translation.fields
    if kind == "memory-block":
        return (kind, fields[1], fields[3], fields[2] - translation.gpn)
    if kind == "other-range":
        return (kind, fields[0], fields[3])
    if kind == "unknown":
        return (kind, translation.translate_status)
    return (kind,)


def range_map(
    ask: Callable[[int], Any], limit_gpn: int, step: int, dense_below: int = 0x100
) -> list[dict[str, Any]]:
    """VID's GPA ranges below ``limit_gpn``, from ``ask(gpn)`` translations.

    Every page below ``dense_below`` is asked (the first MiB by default, where the legacy holes
    are); above it pages are sampled every ``step``, and each change between two samples is
    bisected to the exact page, so every boundary reported is exact. A range shorter than ``step``
    lying wholly between two samples of one run is not seen there: that part is a sampled map, and
    its caller records the step for that reason.
    """
    if limit_gpn <= 0 or step <= 0 or dense_below < 0:
        raise ValueError("the range map needs a positive limit and step")
    cache: dict[int, tuple[tuple[Any, ...], Any]] = {}

    def key(gpn: int) -> tuple[Any, ...]:
        if gpn not in cache:
            translation = ask(gpn)
            cache[gpn] = (_run_key(translation), translation)
        return cache[gpn][0]

    runs: list[dict[str, Any]] = []

    def close(start: int, end: int) -> None:
        translation = cache[start][1]
        run: dict[str, Any] = {
            "start": f"0x{start << 12:x}",
            "end": f"0x{(end + 1) << 12:x}",
            "pages": end - start + 1,
            "kind": translation.kind,
        }
        if translation.kind == "memory-block":
            run.update(
                block=f"0x{translation.fields[1]:x}",
                block_page=f"0x{translation.fields[2]:x}",
                flags=f"0x{translation.fields[3]:x}",
            )
        elif translation.kind == "other-range":
            run.update(context=f"0x{translation.fields[0]:x}", flags=f"0x{translation.fields[3]:x}")
        runs.append(run)

    dense = min(dense_below, limit_gpn)
    points = list(range(1, dense)) + list(range(max(dense, step), limit_gpn, step))
    if not points or points[-1] != limit_gpn - 1:
        points.append(limit_gpn - 1)
    start = same = 0
    current = key(0)
    for point in points:
        while key(point) != current:
            low, high = same, point
            while high - low > 1:
                middle = (low + high) // 2
                if key(middle) == current:
                    low = middle
                else:
                    high = middle
            close(start, high - 1)
            start = same = high
            current = key(high)
        same = point
    close(start, limit_gpn - 1)
    return runs


def sample_pages(runs: list[dict[str, Any]], count: int, seed: int) -> list[int]:
    """``count`` distinct memory-block page GPAs, uniform over pages and reproducible from ``seed``."""
    ram = [(int(run["start"], 16), run["pages"]) for run in runs if run["kind"] == "memory-block"]
    total = sum(pages for _start, pages in ram)
    if count < 0:
        raise ValueError("sample count cannot be negative")
    chosen = random.Random(seed).sample(range(total), min(count, total))
    gpas = []
    for index in chosen:
        for start, pages in ram:
            if index < pages:
                gpas.append(start + (index << 12))
                break
            index -= pages
    return sorted(gpas)


def _ok_and_equal(comparison: dict[str, Any] | None) -> bool:
    return bool(
        comparison
        and comparison["h3"]["result"] == "ok"
        and comparison["data_matches_hvmm"] is True
    )


def phase1_verdict(result: dict[str, Any]) -> dict[str, Any]:
    """The plan's Phase 1 criteria, each a recorded boolean, for one measurement record."""
    corpus = result.get("comparisons", {})
    controls = result.get("controls", {})
    sample = result.get("sample", {})
    zero = corpus.get("mapped_zero")
    absent = [corpus.get("end_of_ram"), corpus.get("device_gap"), controls.get("far_above_ram")]
    before = (result.get("state_before") or {}).get("registers", {})
    after = (result.get("state_after") or {}).get("registers", {})
    debug = ("dr0", "dr1", "dr2", "dr3", "dr6", "dr7")
    criteria = {
        "vtl0_positive_control": _ok_and_equal(controls.get("vtl0_positive_control")),
        "vtl1_protected_pages": _ok_and_equal(corpus.get("mapped_code"))
        and _ok_and_equal(corpus.get("mapped_data")),
        "high_ram": _ok_and_equal(corpus.get("above_4gib")),
        "ram_boundary_is_exact": _ok_and_equal(controls.get("last_ram_page"))
        and bool(corpus.get("end_of_ram"))
        and corpus["end_of_ram"]["h3"]["result"] == "not-present",
        "mapped_zero_is_typed_data": bool(
            zero and zero["h3"]["result"] == "ok" and zero["h3"]["all_zero"] is True
        ),
        "absence_is_typed": all(
            entry is not None and entry["h3"]["result"] in ("not-present", "refused")
            for entry in absent
        ),
        "sample_agreement": bool(sample.get("pages"))
        and sample.get("agreed") == sample.get("pages"),
        "no_hvlib": result.get("hvlib_loaded_before") is False
        and result.get("hvlib_loaded_after") is False,
        "debug_registers_unchanged": bool(before)
        and all(before.get(name) == after.get(name) for name in debug),
        "same_boot_health": result.get("same_boot") is True,
    }
    return {"criteria": criteria, "passed": all(criteria.values())}


RAM_SAMPLES = ("mapped_code", "mapped_data", "mapped_zero", "ram_hole", "above_4gib")
ABSENT_SAMPLES = ("device_gap", "end_of_ram")


def phase2_verdict(result: dict[str, Any]) -> dict[str, Any]:
    """The plan's Phase 2 read-only acceptance for one ``validate.h3-memory`` record."""
    corpus = result.get("comparisons", {})
    controls = result.get("controls", {})
    sample = result.get("sample", {})
    refusals = result.get("refusals", {})
    before = (result.get("state_before") or {}).get("registers", {})
    after = (result.get("state_after") or {}).get("registers", {})
    debug = ("dr0", "dr1", "dr2", "dr3", "dr6", "dr7")
    text = result.get("vtl1_text") or {}
    zero = corpus.get("mapped_zero")
    criteria = {
        "ram_agrees_with_hvmm": all(_ok_and_equal(corpus.get(name)) for name in RAM_SAMPLES)
        and _ok_and_equal(controls.get("vtl0_positive_control"))
        and _ok_and_equal(controls.get("last_ram_page")),
        "mapped_zero_is_data": bool(zero and zero["h3"]["all_zero"] is True),
        "absence_is_typed": all(
            (entry := corpus.get(name) or controls.get(name)) is not None
            and entry["h3"]["result"] in ("not-present", "refused")
            for name in (*ABSENT_SAMPLES, "far_above_ram", "local_apic")
        ),
        "sample_agreement": bool(sample.get("pages")) and sample.get("agreed") == sample.get("pages"),
        "refusals": bool(refusals) and all(entry.get("passed") for entry in refusals.values()),
        "no_scratch_leak": (result.get("leak") or {}).get("passed") is True,
        "cancellation_contained": (result.get("cancellation") or {}).get("passed") is True,
        "unload_contained": (result.get("unload") or {}).get("passed") is True,
        "identity_change_refused": (result.get("identity_change") or {}).get("passed") is True,
        "no_hvlib": result.get("hvlib_loaded_before") is False
        and result.get("hvlib_loaded_after") is False,
        "debug_registers_unchanged": bool(before)
        and all(before.get(name) == after.get(name) for name in debug),
        "vtl1_text_unchanged": bool(text.get("sha256_before"))
        and text.get("sha256_before") == text.get("sha256_after"),
        "same_boot_health": result.get("same_boot") is True,
    }
    return {"criteria": criteria, "passed": all(criteria.values())}
