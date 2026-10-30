"""Address sources and the verdict for validating h3probe's memory operation (`validate.h3-memory`).

`range_map` reads VID's own GPA ranges through h3probe's translate probe, so the edges of RAM a
validation reads are the VM's rather than a constant; `sample_pages` draws a reproducible sample of
RAM from that map; `validation_verdict` states the gate's criteria as recorded booleans.

The differential against hvmm that justified the memory operation is the h3probe-only migration's
Phase 1 and Phase 2 evidence; its records and code are kept in `legacy/h3probe-migration/`.
"""

from __future__ import annotations

import random
from typing import Any, Callable


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


RAM_SAMPLES = ("mapped_code", "mapped_data", "mapped_zero", "ram_hole", "above_4gib")
RAM_CONTROLS = ("vtl0_positive_control", "secure_kernel_header", "last_ram_page")
PROTECTED_SAMPLES = ("mapped_code", "mapped_data")
# Pages the hypervisor accepts on every K3 boot measured, so its own bytes must be there to compare.
HYPERVISOR_CHECKED = ("vtl0_positive_control", "mapped_zero", "above_4gib", "last_ram_page")
ABSENT = ("device_gap", "end_of_ram", "far_above_ram", "local_apic")


def _ok(entry: dict[str, Any] | None) -> bool:
    return bool(entry) and entry["h3"]["result"] == "ok"  # type: ignore[index]


def validation_verdict(result: dict[str, Any]) -> dict[str, Any]:
    """The criteria of one ``validate.h3-memory`` record, each a recorded boolean."""
    corpus = result.get("comparisons", {})
    controls = result.get("controls", {})
    entries = {**corpus, **controls}
    sample = result.get("sample", {})
    refusals = result.get("refusals", {})
    before = (result.get("state_before") or {}).get("registers", {})
    after = (result.get("state_after") or {}).get("registers", {})
    debug = ("dr0", "dr1", "dr2", "dr3", "dr6", "dr7")
    text = result.get("vtl1_text") or {}
    zero = corpus.get("mapped_zero")
    header = controls.get("secure_kernel_header") or {}
    criteria = {
        "ram_reads": all(_ok(corpus.get(name)) for name in RAM_SAMPLES)
        and all(_ok(controls.get(name)) for name in RAM_CONTROLS),
        "hypervisor_agrees": all(entry.get("hypervisor_bytes_agree") is not False for entry in entries.values())
        and all((entries.get(name) or {}).get("hypervisor_bytes_agree") is True for name in HYPERVISOR_CHECKED),
        "protected_pages_read": all(
            _ok(corpus.get(name)) and corpus[name]["backing"] == "ReadIntercept" for name in PROTECTED_SAMPLES
        ),
        "pinned_image_in_vtl1": bool(header.get("pe_identity"))
        and header.get("pe_identity") == result.get("pinned_image"),
        "mapped_zero_is_data": bool(zero and zero["h3"]["all_zero"] is True),
        "absence_is_typed": all(
            (entry := entries.get(name)) is not None and entry["h3"]["result"] in ("not-present", "refused")
            for name in ABSENT
        ),
        "sample_agreement": bool(sample.get("pages"))
        and sample.get("read") == sample.get("pages")
        and bool(sample.get("hypervisor_checked"))
        and sample.get("hypervisor_agreed") == sample.get("hypervisor_checked"),
        "refusals": bool(refusals) and all(entry.get("passed") for entry in refusals.values()),
        "no_scratch_leak": (result.get("leak") or {}).get("passed") is True,
        "cancellation_contained": (result.get("cancellation") or {}).get("passed") is True,
        "unload_contained": (result.get("unload") or {}).get("passed") is True,
        "identity_change_refused": (result.get("identity_change") or {}).get("passed") is True,
        "no_hvlib": result.get("hvlib_loaded_before") is False and result.get("hvlib_loaded_after") is False,
        "debug_registers_unchanged": bool(before) and all(before.get(name) == after.get(name) for name in debug),
        "vtl1_text_unchanged": bool(text.get("sha256_before")) and text.get("sha256_before") == text.get("sha256_after"),
        "same_boot_health": result.get("same_boot") is True,
    }
    return {"criteria": criteria, "passed": all(criteria.values())}
