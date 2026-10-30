from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import struct
import tempfile
import tomllib
import unittest
from unittest import mock

from sklab import bench_bridge, sk_processes
from sklab.config import load
from sklab.context import RunContext
from sklab.modules import core
from sklab.util import pe_identity

sys.path.insert(0, str(Path(__file__).resolve().parent))  # the NT fixture beside this file, however tests are run
import test_guest_ram  # noqa: E402


EXAMPLE = Path(__file__).resolve().parents[1] / "config.example.toml"
KERNEL = 0xFFFF800000000000
BASE = 0xFFFFF8044BE8A000
SYSTEM_ROOT = 0x2601000
TRUSTLET_ROOT = 0x1290000
UNLISTED_ROOT = 0x10302D000
ENCLAVE_ROOT = 0x10542C000
VTL0_ROOT = 0x7D5000
SYSTEM_PROCESS = 0xFFFFA00000001000
TRUSTLET = 0xFFFFA00000002000
ENCLAVE = 0xFFFFA00000003000  # an enclave object: on no SkpsProcessList
CONTAINER = 0xFFFFA00000004000  # the host's secure process it belongs to
PRCBS = (0xFFFFB00000000000, 0xFFFFB00000010000, 0xFFFFB00000020000)  # VP 0, 1, 2
EPROCESS_SYSTEM, EPROCESS_LSA, EPROCESS_HOST = 0xFFFFC00000000000, 0xFFFFC00000010000, 0xFFFFC00000020000  # in VTL0
PEB, PARAMETERS, BUFFER = 0x7FF600000000, 0x20000000, 0x20010000
IMAGE_PATH = "\\??\\C:\\Windows\\system32\\trustlet.exe"
IDT = 0xFFFFF8044C100000
HANDLER = BASE + 0x2345  # vector 0's handler, two unmapped pages above the image's first
PARTITION_HANDLE = 0x1F4  # hvlib's InfoPartitionHandle, as its read request carried it on K3 2026-10-17


def _pe(timestamp: int, size_of_image: int) -> bytes:
    page = bytearray(0x1000)
    page[0:2] = b"MZ"
    page[0x3C:0x40] = (0x108).to_bytes(4, "little")
    page[0x108:0x10C] = b"PE\0\0"
    page[0x10C:0x10E] = (0x8664).to_bytes(2, "little")
    page[0x110:0x114] = timestamp.to_bytes(4, "little")
    page[0x108 + 24 + 56 : 0x108 + 24 + 60] = size_of_image.to_bytes(4, "little")
    return bytes(page)


# securekernel.exe 10.0.26100.9457, the build the layout table has an entry for
SECURE_KERNEL = _pe(0x94DED27F, 0x175000)


class Memory:
    """A guest whose kernel half is shared by every root in `roots` and whose user halves are per root.

    Every offset below is written as a literal, not taken from `sk_processes.LAYOUTS`, so a wrong entry
    in the table fails here instead of agreeing with itself.
    """

    def __init__(self) -> None:
        self.roots = {SYSTEM_ROOT, TRUSTLET_ROOT, UNLISTED_ROOT, ENCLAVE_ROOT}
        self.unreadable: set[int] = set()  # roots whose top page the reader cannot read
        self.kernel: dict[int, int] = {}
        self.user: dict[int, dict[int, int]] = {}
        self.vtl0: dict[int, int] = {}  # NT's kernel half, read through VTL0_ROOT
        q = lambda va, value, root=None: self.put(va, value.to_bytes(8, "little"), root)  # noqa: E731
        # what each VP has loaded: SkeProcessorBlockVp[vp], then gs:[40h] and gs:[2608h]
        for vp, (prcb, process, root) in enumerate(zip(PRCBS, (SYSTEM_PROCESS, TRUSTLET, ENCLAVE),
                                                       (SYSTEM_ROOT, TRUSTLET_ROOT | 0x2, ENCLAVE_ROOT))):
            q(BASE + 0x153FA0 + 8 * vp, prcb)
            q(prcb + 0x40, process)
            q(prcb + 0x2608, root)
        # flags as read on K3 2026-10-17; bit 0 is set on all but the system process
        self.put(SYSTEM_PROCESS, (0x0).to_bytes(4, "little"))
        self.put(TRUSTLET, (0xA3).to_bytes(4, "little"))
        self.put(ENCLAVE, (0x293).to_bytes(4, "little"))  # 0x200: SkeInitializeEnclave
        self.put(CONTAINER, (0x403).to_bytes(4, "little"))  # 0x400: SkeReferenceEnclaveContainerProcess
        q(ENCLAVE + 0x40, ENCLAVE_ROOT)
        q(ENCLAVE + 0x238, CONTAINER)
        q(SYSTEM_PROCESS + 0x30, EPROCESS_SYSTEM)  # the VTL0 KPROCESS each was created for
        q(TRUSTLET + 0x30, EPROCESS_LSA)
        q(CONTAINER + 0x30, EPROCESS_HOST)
        q(ENCLAVE + 0x30, EPROCESS_HOST)  # copied from the container
        for eprocess, pid, image in ((EPROCESS_SYSTEM, 68, b"Secure System"), (EPROCESS_LSA, 812, b"LsaIso.exe"),
                                     (EPROCESS_HOST, 5512, b"spin_host.exe")):
            self.put0(eprocess + 0x1D0, pid.to_bytes(8, "little"))  # UniqueProcessId
            self.put0(eprocess + 0x338, image.ljust(15, b"\0"))  # ImageFileName
        self.put(BASE, SECURE_KERNEL)
        # an x64 interrupt gate: offset 15:0, selector, IST, type, offset 31:16, offset 63:32, reserved
        self.put(IDT, bytes.fromhex("45c3" "1000" "00" "8e" "e84b" "04f8ffff" "00000000"))
        q(BASE + 0x12E230, SYSTEM_ROOT)  # SkpsSystemDirectoryTableBase
        q(BASE + 0x12E228, SYSTEM_PROCESS)  # PsIumSystemProcess
        self.put(BASE + 0x134988, b"\x00")  # SkiKvaShadow
        q(SYSTEM_PROCESS + 0x40, SYSTEM_ROOT)
        q(BASE + 0x133A70, TRUSTLET + 0xE8)  # SkpsProcessList.Flink
        q(TRUSTLET + 0xE8, BASE + 0x133A70)
        q(TRUSTLET + 0x40, TRUSTLET_ROOT | 0x2)  # a PCID in the low bits, as a stored CR3 may carry
        self.put(TRUSTLET + 0x38, (812).to_bytes(4, "little") + (0xDEAD).to_bytes(4, "little"))
        q(TRUSTLET + 0x1A0, 1)
        q(TRUSTLET + 0x90, PEB)
        q(PEB + 0x20, PARAMETERS, TRUSTLET_ROOT)
        path = IMAGE_PATH.encode("utf-16-le")
        self.put(PARAMETERS + 0x60, len(path).to_bytes(2, "little"), TRUSTLET_ROOT)
        q(PARAMETERS + 0x68, BUFFER, TRUSTLET_ROOT)
        self.put(BUFFER, path, TRUSTLET_ROOT)

    def put(self, va: int, data: bytes, root: int | None = None) -> None:
        space = self.kernel if root is None else self.user.setdefault(root, {})
        for index, byte in enumerate(data):
            space[va + index] = byte

    def put0(self, va: int, data: bytes) -> None:
        for index, byte in enumerate(data):
            self.vtl0[va + index] = byte

    def guest(self, cr3: int, source: object = None) -> object:
        memory, root = self, cr3 & 0x000FFFFFFFFFF000

        class Reader:
            def virtual(self, va: int, size: int) -> bytes:
                if root in memory.unreadable:  # as the bench walker reads a page: through the source
                    data, error = source.read(root, 0x1000)
                    if error or data is None:
                        raise KeyError(f"GPA 0x{root:X}: {error}")
                if va >= KERNEL and root == VTL0_ROOT:
                    space = memory.vtl0
                elif va >= KERNEL and root not in memory.roots:
                    raise KeyError(f"VA 0x{va:X}: level 4 not present")
                else:
                    space = memory.kernel if va >= KERNEL else memory.user.get(root, {})
                try:
                    return bytes(space[va + index] for index in range(size))
                except KeyError:
                    raise KeyError(f"VA 0x{va:X}: level 1 not present") from None

        return Reader()


LAYOUT = sk_processes.layout_for({"machine": 0x8664, "timestamp": 0x94DED27F, "size_of_image": 0x175000})


class CensusTests(unittest.TestCase):
    def test_reads_the_system_root_and_each_listed_process(self) -> None:
        found = sk_processes.census(Memory().guest, SYSTEM_ROOT, BASE, LAYOUT)
        self.assertEqual(found["system_directory_table_base"], hex(SYSTEM_ROOT))
        self.assertEqual(found["system_process_root"], hex(SYSTEM_ROOT))
        self.assertEqual(found["kva_shadow"], 0)
        self.assertEqual(
            found["processes"],
            [{
                "process": hex(TRUSTLET),
                "root": hex(TRUSTLET_ROOT | 0x2),
                "pid": 812,
                "trustlet_id": "0x1",
                "system": False,
                "normal_process": hex(EPROCESS_LSA),
                "image_path": IMAGE_PATH,
            }],
        )
        self.assertNotIn("walk_error", found)
        self.assertNotIn("vtl0_check", found)  # no VTL0 root, nothing checked

    def test_names_each_trustlets_vtl0_process_and_checks_the_offsets_with_it(self) -> None:
        found = sk_processes.census(Memory().guest, SYSTEM_ROOT, BASE, LAYOUT, VTL0_ROOT)
        self.assertEqual(found["processes"][0]["vtl0"], {"pid": 812, "image": "LsaIso.exe"})
        self.assertEqual(found["vtl0_check"], "agrees")

    def test_a_vtl0_pid_other_than_the_trustlets_own_says_the_offsets_do_not_fit(self) -> None:
        memory = Memory()
        memory.put0(EPROCESS_LSA + 0x1D0, (813).to_bytes(8, "little"))
        found = sk_processes.census(memory.guest, SYSTEM_ROOT, BASE, LAYOUT, VTL0_ROOT)
        self.assertEqual(found["vtl0_check"], "disagrees")

    def test_names_the_owner_of_each_root(self) -> None:
        found = sk_processes.census(Memory().guest, SYSTEM_ROOT, BASE, LAYOUT)
        system = sk_processes.owner(SYSTEM_ROOT, found)
        self.assertEqual(system, {"owner": "secure-kernel", "matched": ["SkpsSystemDirectoryTableBase", "PsIumSystemProcess"]})
        trustlet = sk_processes.owner(TRUSTLET_ROOT, found)
        self.assertEqual((trustlet["owner"], trustlet["pid"], trustlet["image_path"]), ("secure-process", 812, IMAGE_PATH))
        self.assertEqual(sk_processes.owner(UNLISTED_ROOT, found), {"owner": "unlisted"})

    def test_a_list_that_loops_short_of_its_head_stops(self) -> None:
        memory = Memory()
        memory.put(TRUSTLET + 0xE8, (TRUSTLET + 0xE8).to_bytes(8, "little"))
        found = sk_processes.census(memory.guest, SYSTEM_ROOT, BASE, LAYOUT)
        self.assertEqual(len(found["processes"]), 1)
        self.assertIn("without reaching its head", found["walk_error"])

    def test_a_list_longer_than_the_cap_stops_at_the_cap(self) -> None:
        memory = Memory()
        second = 0xFFFFA00000003000
        memory.put(TRUSTLET + 0xE8, (second + 0xE8).to_bytes(8, "little"))
        memory.put(second + 0xE8, (BASE + 0x133A70).to_bytes(8, "little"))
        with mock.patch.object(sk_processes, "MAX_PROCESSES", 1):
            found = sk_processes.census(memory.guest, SYSTEM_ROOT, BASE, LAYOUT)
        self.assertEqual(len(found["processes"]), 1)
        self.assertIn("stopped after 1 entries", found["walk_error"])

    def test_an_entry_freed_under_the_walk_ends_it_with_the_reason(self) -> None:
        memory = Memory()
        memory.put(TRUSTLET + 0xE8, (0xFFFFA0000000F000).to_bytes(8, "little"))
        found = sk_processes.census(memory.guest, SYSTEM_ROOT, BASE, LAYOUT)
        self.assertEqual([row["pid"] for row in found["processes"]], [812])
        self.assertIn("not present", found["walk_error"])

    def test_a_census_that_stopped_early_does_not_call_a_root_unlisted(self) -> None:
        memory = Memory()
        memory.put(TRUSTLET + 0xE8, (0xFFFFA0000000F000).to_bytes(8, "little"))
        found = sk_processes.census(memory.guest, SYSTEM_ROOT, BASE, LAYOUT)
        self.assertEqual(sk_processes.owner(UNLISTED_ROOT, found)["owner"], "unknown")
        # a process read before the walk stopped is still named
        self.assertEqual(sk_processes.owner(TRUSTLET_ROOT, found)["owner"], "secure-process")

    def test_a_build_with_no_entry_has_no_layout(self) -> None:
        self.assertIsNone(sk_processes.layout_for({"machine": 0x8664, "timestamp": 0x94DED280, "size_of_image": 0x175000}))


class CurrentProcessTests(unittest.TestCase):
    def current(self, vp: int, memory: Memory | None = None) -> dict:
        return sk_processes.current_process((memory or Memory()).guest, SYSTEM_ROOT, BASE, LAYOUT, vp, VTL0_ROOT)

    def test_each_vp_says_what_it_has_loaded(self) -> None:
        # the trustlet is "secure-process": its bit 0 is set on the enclave too, and only the list says trustlet
        self.assertEqual(
            [(record["kind"], record["root"]) for record in map(self.current, (0, 1, 2))],
            [("secure-kernel", hex(SYSTEM_ROOT)), ("secure-process", hex(TRUSTLET_ROOT | 0x2)), ("enclave", hex(ENCLAVE_ROOT))],
        )

    def test_an_enclave_is_named_by_its_hosts_vtl0_process_and_confirmed_by_its_container(self) -> None:
        record = self.current(2)
        self.assertEqual(record["vtl0"], {"pid": 5512, "image": "spin_host.exe"})
        self.assertEqual(record["normal_process"], hex(EPROCESS_HOST))
        self.assertEqual(record["loaded_cr3"], hex(ENCLAVE_ROOT))
        self.assertEqual((record["container"], record["container_check"]), (hex(CONTAINER), "agrees"))
        self.assertNotIn("pid", record)  # +38h is a trustlet's; an enclave held 23 there

    def test_an_enclave_whose_container_is_not_one_is_not_confirmed(self) -> None:
        memory = Memory()
        memory.put(CONTAINER, (0x3).to_bytes(4, "little"))
        self.assertEqual(self.current(2, memory)["container_check"], "disagrees")

    def test_an_enclave_whose_container_belongs_elsewhere_is_not_confirmed(self) -> None:
        memory = Memory()
        memory.put(CONTAINER + 0x30, EPROCESS_LSA.to_bytes(8, "little"))
        self.assertEqual(self.current(2, memory)["container_check"], "disagrees")

    def test_the_secure_kernel_belongs_to_secure_system(self) -> None:
        self.assertEqual(self.current(0)["vtl0"], {"pid": 68, "image": "Secure System"})

    def test_a_process_with_no_vtl0_process_names_none(self) -> None:
        memory = Memory()
        memory.put(SYSTEM_PROCESS + 0x30, bytes(8))
        self.assertNotIn("vtl0", self.current(0, memory))


class RootCheckOwnerTests(unittest.TestCase):
    def run_check(
        self, image: bytes, cr3s: list[int], unreadable: tuple[int, ...] = (), vtl0: int | None = None,
        memory: Memory | None = None, idtr: dict | None = None, vtl0_idtr: dict | None = None,
        absent: tuple[int, ...] = (),
    ) -> dict:
        memory = memory or Memory()
        memory.unreadable = set(unreadable)
        config = load(EXAMPLE)
        self.devices: list = []
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "securekernel.exe"
            path.write_bytes(image)
            target = config.target("demo")
            target = type(target)(**{**target.__dict__, "secure_kernel_image": path})
            context = RunContext(config, mock.Mock(), mock.Mock(), target)
            devices = self.devices

            class Device:  # h3probe's memory operation: a typed answer and no bytes for what it cannot read
                def __init__(self):
                    self.requests: list[tuple[int, ...]] = []
                    self.closed = False
                    devices.append(self)

                def ioctl(self, code, payload, out_size):
                    request = struct.unpack_from("<IIQQQII", payload, 0)
                    self.requests.append(request)
                    gpa = request[4]
                    result, stage = (1, 8) if gpa & ~0xFFF in absent else (3, 10)
                    return struct.pack("<6IQ", 1, result, stage, 0xC0000005 if result == 3 else 0, 0, 0, gpa >> 12) + bytes(0x1000)

                def close(self):
                    self.closed = True

            walker = type("Walker", (), {"Guest": staticmethod(lambda source, cr3: memory.guest(cr3, source))})
            idtr = idtr or {"status": 0, "low": f"0x{0xFFF << 48:016x}", "high": f"0x{IDT:016x}"}
            snapshots = {
                str(vp): {"registers": {"cr3": {"low": f"0x{cr3:016x}"}, "idtr": idtr, "vtl0_idtr": vtl0_idtr}}
                for vp, cr3 in enumerate(cr3s)
            }
            with mock.patch.object(core.bench_bridge, "_module", return_value=walker), \
                 mock.patch.object(core.h3_memory, "Device", Device):
                return core._root_check(
                    context,
                    0x2,
                    snapshots,
                    vtl0,
                    vmwp_pid=4242,
                    partition_handle=0x2E0,
                )

    def test_each_vp_root_is_named(self) -> None:
        result = self.run_check(SECURE_KERNEL, [SYSTEM_ROOT, TRUSTLET_ROOT, UNLISTED_ROOT])
        owners = {vp: row["owner"]["owner"] for vp, row in result["vps"].items()}
        self.assertEqual(owners, {"0": "secure-kernel", "1": "secure-process", "2": "unlisted"})
        self.assertEqual(result["vps"]["1"]["owner"]["pid"], 812)
        self.assertEqual(result["identification"]["read_through"], hex(SYSTEM_ROOT))

    def test_the_census_is_read_through_a_root_that_maps_the_image(self) -> None:
        # VP 0's root maps nothing, so the census, and the search for the base, go through VP 1's.
        result = self.run_check(SECURE_KERNEL, [0x5000000, TRUSTLET_ROOT])
        self.assertEqual(result["vps"]["0"]["verdict"], "base-unmapped")
        self.assertEqual(result["identification"]["read_through"], hex(TRUSTLET_ROOT))
        self.assertEqual(result["vps"]["1"]["owner"]["owner"], "secure-process")
        self.assertEqual(result["located"]["vp"], "1")

    def test_the_base_is_the_first_pe_header_below_vector_0s_handler(self) -> None:
        result = self.run_check(SECURE_KERNEL, [SYSTEM_ROOT])
        self.assertEqual(
            result["located"],
            {"vp": "0", "idt": "0xfffff8044c100000", "idt_limit": "0xfff", "handler": "0xfffff8044be8c345",
             "base": "0xfffff8044be8a000"},
        )
        self.assertEqual(result["secure_kernel_base"], "0xfffff8044be8a000")

    def test_no_readable_idt_is_a_failure_not_a_guess(self) -> None:
        with self.assertRaises(core.ExecutionFailure) as caught:
            self.run_check(SECURE_KERNEL, [SYSTEM_ROOT], idtr={"status": 0x5, "low": "0x0", "high": "0x0"})
        self.assertIn("IDTR not read", str(caught.exception))

    def test_h3_memory_is_asked_with_vmwps_own_handle_and_the_partition(self) -> None:
        high = 0x10542C000
        result = self.run_check(SECURE_KERNEL, [high, SYSTEM_ROOT], unreadable=(high,))
        (device,) = self.devices
        self.assertEqual(result["partition_handle"], "0x2e0")
        version, pid, handle, partition, gpa, _length, reserved = device.requests[0]
        self.assertEqual((version, pid, handle, partition, reserved), (1, 4242, 0x2E0, 0x2, 0))
        self.assertEqual(gpa & ~0xFFF, high)
        self.assertTrue(device.closed)
        self.assertEqual(set(result["h3_memory"]["results"]), {"error"})

    def test_an_absent_root_is_unreadable_by_type_not_zeros(self) -> None:
        high = 0x10542C000
        result = self.run_check(SECURE_KERNEL, [high, SYSTEM_ROOT], unreadable=(high,), absent=(high,))
        self.assertEqual(result["vps"]["0"]["verdict"], "root-unreadable")
        self.assertIn("not-present at translate", result["vps"]["0"]["detail"])
        self.assertEqual(set(result["h3_memory"]["results"]), {"not-present"})
    def test_an_enclave_root_the_list_does_not_hold_is_named_by_its_vp(self) -> None:
        result = self.run_check(SECURE_KERNEL, [SYSTEM_ROOT, TRUSTLET_ROOT, ENCLAVE_ROOT], vtl0=VTL0_ROOT)
        row = result["vps"]["2"]
        self.assertEqual(row["owner"]["owner"], "unlisted")
        self.assertTrue(row["current"]["matches_sample"])
        self.assertEqual(core._owner_text(row, result["identification"]["vtl0_check"]),
                         "enclave, VTL0 pid 5512 spin_host.exe")

    def test_an_enclave_its_container_does_not_confirm_says_so(self) -> None:
        memory = Memory()
        memory.put(CONTAINER, (0x3).to_bytes(4, "little"))
        result = self.run_check(SECURE_KERNEL, [SYSTEM_ROOT, TRUSTLET_ROOT, ENCLAVE_ROOT], vtl0=VTL0_ROOT, memory=memory)
        self.assertEqual(core._owner_text(result["vps"]["2"], "agrees"),
                         f"enclave, VTL0 pid 5512 spin_host.exe (its container {hex(CONTAINER)} does not confirm it)")

    def test_a_vp_that_has_moved_on_does_not_name_the_sample(self) -> None:
        memory = Memory()
        memory.put(PRCBS[2] + 0x40, SYSTEM_PROCESS.to_bytes(8, "little"))  # back in the Secure Kernel
        result = self.run_check(SECURE_KERNEL, [SYSTEM_ROOT, TRUSTLET_ROOT, ENCLAVE_ROOT], vtl0=VTL0_ROOT, memory=memory)
        row = result["vps"]["2"]
        self.assertFalse(row["current"]["matches_sample"])
        self.assertEqual(core._owner_text(row, "agrees"), f"unlisted; the VP has since loaded secure-kernel root {hex(SYSTEM_ROOT)}")

    def test_a_root_the_reader_cannot_read_is_not_called_unmapped(self) -> None:
        # 2026-10-16: hvlib refused every page above 4 GiB, both enclave roots were there, and the check
        # said they did not map the Secure Kernel. A page the reader cannot read is not a missing mapping.
        high = 0x10542C000
        result = self.run_check(SECURE_KERNEL, [high, SYSTEM_ROOT], unreadable=(high,))
        self.assertEqual(result["vps"]["0"]["verdict"], "root-unreadable")
        self.assertIn("GPA 0x10542C000", result["vps"]["0"]["detail"])
        self.assertEqual(result["vps"]["1"]["verdict"], "maps-pinned-image")

    def test_another_build_is_not_read_with_this_layout(self) -> None:
        result = self.run_check(_pe(0x94DED280, 0x175000), [SYSTEM_ROOT])
        self.assertEqual(result["vps"]["0"]["verdict"], "maps-other-image")
        self.assertIn("skipped", result["identification"])
        self.assertNotIn("owner", result["vps"]["0"])


class StrictSourceTests(unittest.TestCase):
    """Through the bench's own page walker, not a model of it."""

    def guest(self, pages: dict[int, bytes], cr3: int) -> object:
        class Source:
            def read(self, gpa: int, size: int) -> tuple[bytes | None, str | None]:
                page = pages.get(gpa & ~0xFFF)
                if page is None:
                    return None, "NOTPRESENT"
                return page[gpa & 0xFFF:(gpa & 0xFFF) + size], None

        walker = bench_bridge._module("vtl0_find_matching_image")
        return walker.Guest(sk_processes.StrictSource(Source()), cr3)

    def test_a_page_the_reader_cannot_read_is_unreadable(self) -> None:
        with self.assertRaises(sk_processes.UnreadablePage) as caught:
            self.guest({}, 0x10542C000).virtual(BASE, 8)
        self.assertIn("GPA 0x10542C000", str(caught.exception))

    def test_an_empty_entry_is_still_not_present(self) -> None:
        with self.assertRaises(KeyError) as caught:
            self.guest({SYSTEM_ROOT: bytes(0x1000)}, SYSTEM_ROOT).virtual(BASE, 8)
        self.assertNotIsInstance(caught.exception, sk_processes.UnreadablePage)
        self.assertIn("level 4 not present", str(caught.exception))


class PinnedImageTests(unittest.TestCase):
    """The literals above were copied from the layout table, so they cannot catch a wrong key in it:
    on 2026-10-16 both carried the same mistyped timestamp and the live run was refused. This reads
    the key from the pinned image itself, which is machine-local, so it skips where it is absent."""

    def test_the_pinned_image_has_a_layout(self) -> None:
        root = Path(__file__).resolve().parents[1]
        entry = tomllib.loads((root / "artifact-manifest.toml").read_text())["artifacts"]["securekernel_26100_9457"]
        image = root / "artifacts" / entry["path"]
        if not image.exists():
            self.skipTest(f"{image} is not provisioned on this machine")
        data = image.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest().upper(), entry["sha256"])
        self.assertIsNotNone(sk_processes.layout_for(pe_identity(data[:0x1000])))


if __name__ == "__main__":
    unittest.main()
