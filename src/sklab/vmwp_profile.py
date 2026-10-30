"""Offline generation and validation of exact-build vmwp dispatcher profiles."""

from __future__ import annotations

import copy
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import struct
from typing import Any

from .errors import LabError


PROFILE_SCHEMA = "windbg-mcp.sk-live-dispatcher-profile.v1"
REPORT_SCHEMA = "secure-kernel-lab.vmwp-reprofile.v1"
FUNCTION_RVAS = (
    "register_handler_rva",
    "unregister_handler_rva",
    "callback_stub_rva",
)
GUARDED_SITES = (
    "discovery.entry",
    "event_held",
    "callback_entry",
    "handle_return",
    "native_return",
    "deferred_cleanup",
)


class ProfileError(LabError):
    """A profile could not be derived without guessing."""


@dataclass(frozen=True)
class Section:
    name: str
    rva: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    executable: bool


class PeImage:
    """The small PE view needed to map guarded bytes between two images."""

    def __init__(self, path: Path):
        self.path = path.expanduser().resolve()
        self.data = self.path.read_bytes()
        if len(self.data) < 0x40 or self.data[:2] != b"MZ":
            raise ProfileError(f"not a DOS/PE image: {self.path}")
        pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        if pe > len(self.data) - 24 or self.data[pe : pe + 4] != b"PE\0\0":
            raise ProfileError(f"not a PE image: {self.path}")
        machine, count, timestamp, _, _, optional_size, _ = struct.unpack_from(
            "<HHIIIHH", self.data, pe + 4
        )
        if machine != 0x8664:
            raise ProfileError(f"expected AMD64 image, got machine 0x{machine:x}: {self.path}")
        optional = pe + 24
        if optional + optional_size > len(self.data) or optional_size < 60:
            raise ProfileError(f"truncated PE optional header: {self.path}")
        if struct.unpack_from("<H", self.data, optional)[0] != 0x20B:
            raise ProfileError(f"expected PE32+ image: {self.path}")
        self.timestamp = timestamp
        self.size_of_image = struct.unpack_from("<I", self.data, optional + 56)[0]
        table = optional + optional_size
        if table + count * 40 > len(self.data):
            raise ProfileError(f"truncated PE section table: {self.path}")
        sections: list[Section] = []
        for index in range(count):
            row = table + index * 40
            raw_name, virtual_size, rva, raw_size, raw_offset = struct.unpack_from(
                "<8sIIII", self.data, row
            )
            characteristics = struct.unpack_from("<I", self.data, row + 36)[0]
            if raw_size and raw_offset + raw_size > len(self.data):
                raise ProfileError(f"section {index} extends beyond {self.path}")
            sections.append(
                Section(
                    raw_name.rstrip(b"\0").decode("ascii", errors="replace"),
                    rva,
                    virtual_size,
                    raw_offset,
                    raw_size,
                    bool(characteristics & 0x20000000),
                )
            )
        self.sections = sections

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest().upper()

    def bytes_at(self, rva: int, size: int) -> bytes:
        if rva < 0 or size < 0:
            raise ProfileError("an RVA and its size must be nonnegative")
        for section in self.sections:
            extent = max(section.virtual_size, section.raw_size)
            if section.rva <= rva and rva + size <= section.rva + extent:
                offset = section.raw_offset + rva - section.rva
                if offset + size > section.raw_offset + section.raw_size:
                    raise ProfileError(f"RVA 0x{rva:x} extends beyond raw data in {self.path}")
                return self.data[offset : offset + size]
        raise ProfileError(f"RVA 0x{rva:x} is outside image sections in {self.path}")

    def matches_at(self, rva: int, needle: bytes) -> bool:
        try:
            return self.bytes_at(rva, len(needle)) == needle
        except ProfileError:
            return False

    def find_executable(self, needle: bytes) -> list[int]:
        if not needle:
            raise ProfileError("cannot search an image for an empty byte sequence")
        found: list[int] = []
        for section in self.sections:
            if not section.executable:
                continue
            data = self.data[section.raw_offset : section.raw_offset + section.raw_size]
            offset = 0
            while True:
                match = data.find(needle, offset)
                if match < 0:
                    break
                found.append(section.rva + match)
                offset = match + 1
        return found


@dataclass(frozen=True)
class ReprofileResult:
    candidate: dict[str, Any]
    report: dict[str, Any]


def number(value: Any) -> int:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError) as error:
        raise ProfileError(f"expected an integer, got {value!r}") from error


def format_rva(value: int) -> str:
    return f"0x{value:016x}"


def _load_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ProfileError(f"{label} is not valid JSON: {path}: {error}") from error
    if not isinstance(value, dict):
        raise ProfileError(f"{label} must be a JSON object: {path}")
    return value


def _nested(value: dict[str, Any], dotted: str) -> Any:
    current: Any = value
    try:
        for part in dotted.split("."):
            current = current[part]
    except (KeyError, TypeError) as error:
        raise ProfileError(f"baseline profile omits {dotted}") from error
    return current


def _image_record(image: PeImage, *, runtime_path: str | None = None) -> dict[str, Any]:
    record: dict[str, Any] = {
        "path": str(image.path),
        "sha256": image.sha256,
        "size_of_image": image.size_of_image,
        "coff_timestamp": f"0x{image.timestamp:08x}",
        "file_version": windows_file_version(image.path),
    }
    if runtime_path is not None:
        record["runtime_path"] = runtime_path
    return record


def windows_file_version(path: Path) -> str | None:
    """Return the four-part fixed file version when Windows exposes one."""
    if os.name != "nt":
        return None
    try:
        version = ctypes.WinDLL("version", use_last_error=True)
        version.GetFileVersionInfoSizeW.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        version.GetFileVersionInfoSizeW.restype = wintypes.DWORD
        version.GetFileVersionInfoW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
        ]
        version.GetFileVersionInfoW.restype = wintypes.BOOL
        version.VerQueryValueW.argtypes = [
            wintypes.LPCVOID,
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.UINT),
        ]
        version.VerQueryValueW.restype = wintypes.BOOL
        ignored = wintypes.DWORD()
        size = version.GetFileVersionInfoSizeW(str(path), ctypes.byref(ignored))
        if not size:
            return None
        data = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(str(path), 0, size, data):
            return None
        pointer = ctypes.c_void_p()
        length = wintypes.UINT()
        if not version.VerQueryValueW(data, "\\", ctypes.byref(pointer), ctypes.byref(length)):
            return None

        class FixedFileInfo(ctypes.Structure):
            _fields_ = [(name, wintypes.DWORD) for name in (
                "signature", "struct_version", "file_version_ms", "file_version_ls",
                "product_version_ms", "product_version_ls", "flags_mask", "flags",
                "file_os", "file_type", "file_subtype", "file_date_ms", "file_date_ls",
            )]

        info = ctypes.cast(pointer, ctypes.POINTER(FixedFileInfo)).contents
        if info.signature != 0xFEEF04BD:
            return None
        return ".".join(
            str(part)
            for part in (
                info.file_version_ms >> 16,
                info.file_version_ms & 0xFFFF,
                info.file_version_ls >> 16,
                info.file_version_ls & 0xFFFF,
            )
        )
    except (AttributeError, OSError, ValueError):
        return None


def _select_guarded(
    name: str,
    old_rva: int,
    original: bytes,
    new: PeImage,
) -> tuple[int, dict[str, Any]]:
    matches = new.find_executable(original)
    if new.matches_at(old_rva, original):
        selected, reason = old_rva, "unchanged-rva"
    elif len(matches) == 1:
        selected, reason = matches[0], "unique-byte-match"
    else:
        rendered = ", ".join(f"0x{rva:x}" for rva in matches) or "none"
        raise ProfileError(
            f"{name} moved from 0x{old_rva:x}, but its guarded bytes have "
            f"{len(matches)} executable matches ({rendered}); manual derivation is required"
        )
    return selected, {
        "baseline_rva": format_rva(old_rva),
        "selected_rva": format_rva(selected),
        "selection": reason,
        "bytes": original.hex(" "),
        "matches": [format_rva(rva) for rva in matches],
    }


def _select_unique_prefix(
    name: str, old_rva: int, prefix: bytes, new: PeImage
) -> tuple[int, dict[str, Any]]:
    matches = new.find_executable(prefix)
    if len(matches) != 1:
        rendered = ", ".join(f"0x{rva:x}" for rva in matches) or "none"
        raise ProfileError(
            f"{name}'s {len(prefix)}-byte prefix has {len(matches)} executable matches "
            f"({rendered}); manual derivation is required"
        )
    selected = matches[0]
    return selected, {
        "baseline_rva": format_rva(old_rva),
        "selected_rva": format_rva(selected),
        "selection": "unchanged-rva" if selected == old_rva else "unique-prefix-match",
        "prefix": prefix.hex(" "),
        "matches": [format_rva(selected)],
    }


def generate(
    baseline_path: Path,
    old_image_path: Path,
    new_image_path: Path,
    vid_image_path: Path,
    *,
    prefix_bytes: int = 32,
) -> ReprofileResult:
    """Generate a candidate without activating it or claiming live validation."""
    if not 8 <= prefix_bytes <= 256:
        raise ProfileError("prefix_bytes must be in 8..=256")
    baseline_path = baseline_path.expanduser().resolve()
    baseline = _load_object(baseline_path, "baseline profile")
    if baseline.get("schema") != PROFILE_SCHEMA:
        raise ProfileError(
            f"baseline schema is {baseline.get('schema')!r}, expected {PROFILE_SCHEMA!r}"
        )
    old, new, vid = PeImage(old_image_path), PeImage(new_image_path), PeImage(vid_image_path)
    expected_old_hash = str(baseline.get("vmwp_sha256", ""))
    if old.sha256.casefold() != expected_old_hash.casefold():
        raise ProfileError(
            f"old image hash {old.sha256} does not match baseline "
            f"{expected_old_hash or '<missing>'}"
        )
    if old.size_of_image != number(baseline.get("vmwp_size_of_image")):
        raise ProfileError(
            f"old image SizeOfImage {old.size_of_image} does not match baseline "
            f"{baseline.get('vmwp_size_of_image')!r}"
        )

    candidate = copy.deepcopy(baseline)
    candidate["vmwp_sha256"] = new.sha256
    candidate["vmwp_size_of_image"] = new.size_of_image
    discovery = _nested(candidate, "discovery")
    if not isinstance(discovery, dict):
        raise ProfileError("baseline discovery must be an object")
    discovery["vid_sha256"] = vid.sha256
    discovery["vid_size_of_image"] = vid.size_of_image

    guarded: dict[str, Any] = {}
    for name in GUARDED_SITES:
        site = _nested(baseline, name)
        if not isinstance(site, dict):
            raise ProfileError(f"baseline {name} must be an object")
        try:
            original = bytes(site["original"])
        except (KeyError, TypeError, ValueError) as error:
            raise ProfileError(f"baseline {name}.original is not a byte array") from error
        old_rva = number(site.get("rva"))
        if old.bytes_at(old_rva, len(original)) != original:
            raise ProfileError(f"old image bytes do not match baseline {name} at 0x{old_rva:x}")
        selected, evidence = _select_guarded(name, old_rva, original, new)
        candidate_site = _nested(candidate, name)
        candidate_site["rva"] = format_rva(selected)
        guarded[name] = evidence

    functions: dict[str, Any] = {}
    for name in FUNCTION_RVAS:
        old_rva = number(_nested(baseline, name))
        prefix = old.bytes_at(old_rva, prefix_bytes)
        selected, evidence = _select_unique_prefix(name, old_rva, prefix, new)
        candidate[name] = format_rva(selected)
        functions[name] = evidence

    old_resume = number(_nested(baseline, "callback_resume_rva"))
    resume_bytes = old.bytes_at(old_resume, 16)
    selected_resume, resume_evidence = _select_guarded(
        "callback_resume_rva", old_resume, resume_bytes, new
    )
    candidate["callback_resume_rva"] = format_rva(selected_resume)

    rendered_candidate = render_json(candidate).encode("utf-8")
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "status": "offline-pass",
        "baseline": {
            "profile": str(baseline_path),
            "vmwp": _image_record(old, runtime_path=str(baseline.get("vmwp_image", ""))),
        },
        "new": {
            "vmwp": _image_record(new, runtime_path=str(candidate.get("vmwp_image", ""))),
            "vid": _image_record(vid, runtime_path=str(discovery.get("vid_image", ""))),
        },
        "guarded_sites": guarded,
        "function_prefixes": functions,
        "callback_resume": resume_evidence,
        "invariants": {
            "profile_schema": "unchanged",
            "scratch_and_registration": "unchanged",
            "descriptor_layout": "unchanged",
            "secure_kernel_kd": "unchanged",
        },
        "candidate": {
            "sha256": hashlib.sha256(rendered_candidate).hexdigest().upper(),
            "review_required": True,
            "activated": False,
        },
        "live_validation": {
            "status": "not-run",
            "detail": "run the disposable-VM validation separately before promoting this profile",
        },
    }
    return ReprofileResult(candidate, report)


def render_json(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2) + "\n"


def default_report_path(candidate_path: Path) -> Path:
    suffix = candidate_path.suffix or ".json"
    return candidate_path.with_name(f"{candidate_path.stem}.report{suffix}")


def default_live_report_path(candidate_path: Path) -> Path:
    suffix = candidate_path.suffix or ".json"
    return candidate_path.with_name(f"{candidate_path.stem}.live{suffix}")


def write_json_new(path: Path, value: dict[str, Any]) -> Path:
    """Write one JSON artifact exclusively."""
    path = path.expanduser().resolve(strict=False)
    if path.exists():
        raise ProfileError(f"refusing to overwrite existing output: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(render_json(value))
    return path


def write_new(
    result: ReprofileResult,
    candidate_path: Path,
    report_path: Path | None = None,
) -> tuple[Path, Path]:
    """Write both artifacts exclusively; never overwrite or activate a profile."""
    candidate_path = candidate_path.expanduser().resolve(strict=False)
    report_path = (
        report_path or default_report_path(candidate_path)
    ).expanduser().resolve(strict=False)
    if candidate_path == report_path:
        raise ProfileError("candidate and report output paths must differ")
    for path in (candidate_path, report_path):
        if path.exists():
            raise ProfileError(f"refusing to overwrite existing output: {path}")
        path.parent.mkdir(parents=True, exist_ok=True)
    report = copy.deepcopy(result.report)
    report["candidate"]["path"] = str(candidate_path)
    report["report_path"] = str(report_path)
    created: list[Path] = []
    try:
        for path, value in ((candidate_path, result.candidate), (report_path, report)):
            with path.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(render_json(value))
            created.append(path)
    except BaseException:
        for path in created:
            try:
                path.unlink()
            except OSError:
                pass
        raise
    return candidate_path, report_path


def first_difference(expected: Any, actual: Any, path: str = "candidate") -> str | None:
    if type(expected) is not type(actual):
        return f"{path} has type {type(actual).__name__}, expected {type(expected).__name__}"
    if isinstance(expected, dict):
        for key in sorted(expected.keys() | actual.keys()):
            if key not in actual:
                return f"{path}.{key} is missing"
            if key not in expected:
                return f"{path}.{key} is unexpected"
            difference = first_difference(expected[key], actual[key], f"{path}.{key}")
            if difference:
                return difference
        return None
    if isinstance(expected, list):
        if len(expected) != len(actual):
            return f"{path} has {len(actual)} entries, expected {len(expected)}"
        for index, (want, got) in enumerate(zip(expected, actual, strict=True)):
            difference = first_difference(want, got, f"{path}[{index}]")
            if difference:
                return difference
        return None
    if expected != actual:
        return f"{path} is {actual!r}, expected {expected!r}"
    return None


def validate_existing_candidate(
    baseline_path: Path,
    candidate_path: Path,
    old_image_path: Path,
    new_image_path: Path,
    vid_image_path: Path,
    *,
    prefix_bytes: int = 32,
) -> dict[str, Any]:
    result = generate(
        baseline_path,
        old_image_path,
        new_image_path,
        vid_image_path,
        prefix_bytes=prefix_bytes,
    )
    actual = _load_object(candidate_path.expanduser().resolve(), "candidate profile")
    difference = first_difference(result.candidate, actual)
    if difference:
        raise ProfileError(f"candidate does not match the offline derivation: {difference}")
    report = copy.deepcopy(result.report)
    report["candidate"].update(path=str(candidate_path.expanduser().resolve()), validated=True)
    return report
