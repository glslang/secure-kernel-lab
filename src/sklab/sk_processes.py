"""Which Secure Kernel process owns a VTL1 page-table root.

`securekernel.exe` keeps an object per secure process on `SkpsProcessList`, and each object holds the
root that process runs on: `SkeSelectProcessAddressSpace` loads CR3 from it. The Secure Kernel's own
system root is recorded twice, in `PsIumSystemProcess`'s object and in `SkpsSystemDirectoryTableBase`,
which `SkiSystemStartup` copies from the loader block. So a root sampled from a VP is named by
matching it against those records, not inferred from when it was sampled.

The offsets are per build. Each was read from the code of the routine named beside it in the pinned
image, and a build with no entry here is refused rather than guessed at. The walk reads a list the
guest is still changing, so it is a census at one moment, taken after the registers were sampled: a
root whose process exited in between reads as unlisted.

`SkpsProcessList` holds trustlets only, being linked by `SkpsInitializeProcess`. A VBS enclave is an
object of its own: `SkmmCreateEnclave` makes it, keeps the host's secure process (its container) at
`+238h`, and `SkeInitializeEnclave` gives it the same header as a process, with its own address space,
flag `ENCLAVE` and the container's VTL0 process copied in. While a VP runs enclave code it is that
object whose root is loaded, and it is on no list. So each VP is also asked directly what it runs:
`SkeProcessorBlockVp[vp]` is the GS base `KiNmiInterrupt` loads for that VP index, and
`SkeSelectProcessAddressSpace` writes `gs:[40h]`, the object whose root it loads, together with that
root. Each of these objects holds the VTL0 process it belongs to, as NT's `KeInitializeProcess` and
`VslCreateEnclave` pass their KPROCESS to `VslCreateSecureProcess`; its PID and image name are read
through a VTL0 root.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Layout:
    # RVAs of globals in securekernel.exe
    system_directory_table_base: int  # SkpsSystemDirectoryTableBase: SkiSystemStartup stores SkeLoaderBlock+0x58
    system_process: int  # PsIumSystemProcess: the process SkeSelectProcessAddressSpace singles out
    process_list: int  # SkpsProcessList: SkpsInitializeProcess inserts at the tail, SkpsRundownProcess unlinks
    kva_shadow: int  # SkiKvaShadow: the byte SkeSelectProcessAddressSpace tests after writing CR3
    processor_block_vp: int  # SkeProcessorBlockVp: KiNmiInterrupt sets GS base from it, indexed by the VP index MSR
    # offsets from a VP's GS base
    current_process: int  # gs:[40h], which SkeSelectProcessAddressSpace writes with the process it switches to
    loaded_cr3: int  # gs:[2608h], the CR3 value it wrote alongside
    # offsets into a process object
    flags: int  # dword; ENCLAVE set by SkeInitializeEnclave, ENCLAVE_CONTAINER by SkeReferenceEnclaveContainerProcess
    normal_process: int  # the VTL0 KPROCESS, the first argument of the create-process secure service
    enclave_container: int  # an enclave's container process, stored by SkmmCreateEnclave
    links: int  # the SkpsProcessList entry
    directory_table_base: int  # `mov cr3, [rcx+40h]` in SkeSelectProcessAddressSpace
    pid: int  # 32 bits; "Pid" in the IumProcessStart/IumProcessStop events
    trustlet_id: int  # 64 bits; "Id" in the same events
    peb: int  # SkWriteProcessStartEvent reads the image path through it, SkpsSendDebugAttachNotifications PEB.Ldr
    # offsets into an EPROCESS of the ntoskrnl the same build ships with
    eprocess_pid: int  # UniqueProcessId
    eprocess_image: int  # ImageFileName, 15 bytes


LAYOUTS: dict[tuple[int, int, int], Layout] = {
    # securekernel.exe 10.0.26100.9457: (Machine, TimeDateStamp, SizeOfImage)
    (0x8664, 0x94DED27F, 0x175000): Layout(
        system_directory_table_base=0x12E230,
        system_process=0x12E228,
        process_list=0x133A70,
        kva_shadow=0x134988,
        processor_block_vp=0x153FA0,
        current_process=0x40,
        loaded_cr3=0x2608,
        flags=0x0,
        normal_process=0x30,
        enclave_container=0x238,
        links=0xE8,
        directory_table_base=0x40,
        pid=0x38,
        trustlet_id=0x1A0,
        peb=0x90,
        # recorded for a 26100 guest's ntoskrnl, not read from 26100.9457's; the trustlets' own PIDs check them
        eprocess_pid=0x1D0,
        eprocess_image=0x338,
    ),
}

# Bit 0 is set on trustlets, containers and enclaves alike, so it names none of them: a trustlet is a
# process the list holds. Live on K3 2026-10-17: the system process 0x0, LsaIso 0xA3, an enclave 0x293.
ENCLAVE = 0x200  # SkeInitializeEnclave ORs in 0x203
ENCLAVE_CONTAINER = 0x400  # SkeReferenceEnclaveContainerProcess: the host process an enclave belongs to

ROOT = 0x000FFFFFFFFFF000  # CR3 bits 51:12; bits 11:0 are the PCID and bit 63 the no-flush hint
PROCESS_PARAMETERS = 0x20  # PEB.ProcessParameters
IMAGE_PATH = 0x60  # RTL_USER_PROCESS_PARAMETERS.ImagePathName: Length (16 bits), Buffer at +8
MAX_PATH_BYTES = 0x400
MAX_PROCESSES = 1024


class UnreadablePage(KeyError):
    """The reader could not read a guest-physical page. A KeyError, so a walk that stops on one records
    it as it does a missing mapping; its own type, so a check can tell a page it could not read from an
    address that is not mapped. On 2026-10-16 hvlib refused every page above 4 GiB, and a root there
    was reported as not mapping the Secure Kernel when it did."""

    def __init__(self, message: str, gpa: int) -> None:
        super().__init__(message)
        self.gpa = gpa


class StrictSource:
    """A physical reader whose failed read raises UnreadablePage at the read, before the page walker
    turns it into the same KeyError it raises for an entry that is not present."""

    def __init__(self, source: Any) -> None:
        self.source = source

    def read(self, gpa: int, size: int) -> tuple[bytes, None]:
        data, error = self.source.read(gpa, size)
        if error or data is None:
            raise UnreadablePage(f"GPA 0x{gpa:X}: {error}", gpa)
        return data, None


def layout_for(identity: dict[str, int]) -> Layout | None:
    return LAYOUTS.get((identity["machine"], identity["timestamp"], identity["size_of_image"]))


def _int(reader: Any, va: int, size: int) -> int:
    return int.from_bytes(reader.virtual(va, size), "little")


def _image_path(open_root: Callable[[int], Any], root: int, peb: int) -> str:
    user = open_root(root)
    parameters = _int(user, peb + PROCESS_PARAMETERS, 8)
    length = _int(user, parameters + IMAGE_PATH, 2)
    buffer = _int(user, parameters + IMAGE_PATH + 8, 8)
    return user.virtual(buffer, min(length, MAX_PATH_BYTES)).decode("utf-16-le", errors="replace")


def _vtl0_process(open_root: Callable[[int], Any], vtl0_root: int, kprocess: int, layout: Layout) -> dict[str, Any]:
    """The PID and image name of the VTL0 process a secure process belongs to, read through a VTL0 root."""
    try:
        reader = open_root(vtl0_root)
        image = reader.virtual(kprocess + layout.eprocess_image, 15).split(b"\0")[0]
        return {"pid": _int(reader, kprocess + layout.eprocess_pid, 8), "image": image.decode("ascii", "replace")}
    except KeyError as error:
        return {"error": str(error)}


def _vtl0_check(rows: list[dict[str, Any]]) -> str:
    """Whether the EPROCESS offsets hold on this guest: each trustlet's PID as the Secure Kernel stored
    it, against the PID read from its VTL0 process."""
    pairs = [(row["pid"], row["vtl0"]["pid"]) for row in rows if "pid" in row.get("vtl0", {})]
    if not pairs:
        return "unchecked"
    return "agrees" if all(mine == theirs for mine, theirs in pairs) else "disagrees"


def census(
    open_root: Callable[[int], Any], kernel_root: int, base: int, layout: Layout, vtl0_root: int | None = None
) -> dict[str, Any]:
    """The system root and every listed process's root, read through `kernel_root`, which must map
    the Secure Kernel. `open_root(cr3)` returns a reader with `virtual(va, size)`; a "not present"
    anywhere raises KeyError, and so does a page the reader cannot read (UnreadablePage). With
    `vtl0_root`, each process also carries the VTL0 process it belongs to."""
    kernel = open_root(kernel_root)
    system_process = _int(kernel, base + layout.system_process, 8)
    result: dict[str, Any] = {
        "system_directory_table_base": hex(_int(kernel, base + layout.system_directory_table_base, 8)),
        "system_process": hex(system_process),
        "system_process_root": hex(_int(kernel, system_process + layout.directory_table_base, 8)),
        "kva_shadow": _int(kernel, base + layout.kva_shadow, 1),
        "processes": [],
    }
    head = base + layout.process_list
    seen: set[int] = set()
    try:
        entry = _int(kernel, head, 8)
        while entry != head:
            if entry in seen:
                result["walk_error"] = f"the list returns to 0x{entry:x} without reaching its head"
                break
            if len(result["processes"]) == MAX_PROCESSES:  # rows, so it holds without the guard above
                result["walk_error"] = f"stopped after {MAX_PROCESSES} entries without reaching the head"
                break
            seen.add(entry)
            process = entry - layout.links
            root = _int(kernel, process + layout.directory_table_base, 8)
            row: dict[str, Any] = {
                "process": hex(process),
                "root": hex(root),
                "pid": _int(kernel, process + layout.pid, 4),
                "trustlet_id": hex(_int(kernel, process + layout.trustlet_id, 8)),
                "system": process == system_process,
            }
            normal = _int(kernel, process + layout.normal_process, 8)
            row["normal_process"] = hex(normal)
            if vtl0_root is not None and normal:
                row["vtl0"] = _vtl0_process(open_root, vtl0_root, normal, layout)
            peb = _int(kernel, process + layout.peb, 8)
            if peb:
                try:
                    row["image_path"] = _image_path(open_root, root, peb)
                except KeyError as error:
                    row["image_path_error"] = str(error)
            result["processes"].append(row)
            entry = _int(kernel, entry, 8)
    except KeyError as error:  # an entry freed while the walk followed it, or a page the reader cannot read
        result["walk_error"] = str(error)
    if vtl0_root is not None:
        result["vtl0_check"] = _vtl0_check(result["processes"])
    return result


def current_process(
    open_root: Callable[[int], Any], kernel_root: int, base: int, layout: Layout, vp: int, vtl0_root: int | None = None
) -> dict[str, Any]:
    """The object VP `vp` has loaded, from the Secure Kernel's own per-VP record, read through
    `kernel_root`. It is read after the registers were sampled, so `root` is compared with the sample
    rather than assumed to be it. An enclave is checked against the container it records, which must
    be one and belong to the same VTL0 process. Whether a `secure-process` is a trustlet is the list's
    to say, not this record's. Raises KeyError as `census` does."""
    kernel = open_root(kernel_root)
    gs = _int(kernel, base + layout.processor_block_vp + 8 * vp, 8)
    process = _int(kernel, gs + layout.current_process, 8)
    flags = _int(kernel, process + layout.flags, 4)
    normal = _int(kernel, process + layout.normal_process, 8)
    if process == _int(kernel, base + layout.system_process, 8):
        kind = "secure-kernel"
    elif flags & ENCLAVE:
        kind = "enclave"
    elif flags & ENCLAVE_CONTAINER:
        kind = "enclave-container"
    else:
        kind = "secure-process"
    record: dict[str, Any] = {
        "process": hex(process),
        "kind": kind,
        "flags": hex(flags),
        "root": hex(_int(kernel, process + layout.directory_table_base, 8)),
        "loaded_cr3": hex(_int(kernel, gs + layout.loaded_cr3, 8)),
        "normal_process": hex(normal),
    }
    if kind == "enclave":
        container = _int(kernel, process + layout.enclave_container, 8)
        confirmed = (_int(kernel, container + layout.flags, 4) & ENCLAVE_CONTAINER
                     and _int(kernel, container + layout.normal_process, 8) == normal)
        record["container"] = hex(container)
        record["container_check"] = "agrees" if confirmed else "disagrees"
    if vtl0_root is not None and normal:
        record["vtl0"] = _vtl0_process(open_root, vtl0_root, normal, layout)
    return record


def owner(cr3: int, found: dict[str, Any]) -> dict[str, Any]:
    """Who `found` says runs on `cr3`: the Secure Kernel, one listed process, nobody listed, or, when
    the list was not read to its end, unknown."""
    root = cr3 & ROOT
    system = [
        name
        for name, key in (("SkpsSystemDirectoryTableBase", "system_directory_table_base"),
                          ("PsIumSystemProcess", "system_process_root"))
        if int(found[key], 16) & ROOT == root
    ]
    if system:
        return {"owner": "secure-kernel", "matched": system}
    matches = [row for row in found["processes"] if int(row["root"], 16) & ROOT == root]
    if len(matches) == 1:
        return {"owner": "secure-process", **matches[0]}
    if matches:
        return {"owner": "ambiguous", "processes": matches}
    if "walk_error" in found:  # the entries never read may hold it
        return {"owner": "unknown", "reason": f"the process list was not read to its end: {found['walk_error']}"}
    return {"owner": "unlisted"}
