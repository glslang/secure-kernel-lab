"""S5w: the operator-supplied live transport for `windbg-mcp --sk-live`.

`windbg-mcp` ships the client half of this protocol (`src/livesrc.rs`) and no
transport, because reading another partition's VTL1 live needs a kernel component
the repository will not distribute. This is the bench's half. It speaks the line
protocol on stdio and exits when stdin closes.

Two modes, and the difference between them is the point:

  --mode direct     hvlib's `SdkReadPhysicalMemory` through its hvmm driver. Reads
                    VTL1 and never refuses, so the whole decode runs and the
                    report is a live `securekernel.exe` walk. `--reader hvmm`
                    sends hvmm the same request directly (`sklab.hvmm`, which
                    needs `src` on PYTHONPATH), so hvlib's read bound -- 4 GiB
                    when VP 0 was in VTL1 as it opened the partition -- does not
                    apply. hvlib still opens the partition either way: hvmm
                    reads through the handle it holds.
  --mode hypercall  `HvCallReadGpa` through the h3probe driver. H4 measured this
                    answering HV_STATUS_SUCCESS with zeros and a per-access
                    `ReadIntercept` on VTL1 -- so it is the transport that
                    produces a real `ReadFailure::Refused`, which until now had
                    only ever come from a fixture.

The `hypercall` mode's `max_read` is **16**, which is not a choice: the hypercall
moves at most sixteen bytes, and `RawSource::max_read` exists in that crate
because of this call. Running both modes is what shows the decode chunking at the
source's own width.

Usage (the client spawns it; this is what the command line looks like):

    windbg-mcp --sk-live --transport "python s5w_gpa_server_pinned.py --mode direct --partition-id 0x78 --expected-cr3 0x1201000" \\
               --image C:\\Windows\\System32\\securekernel.exe

Diagnostics go to stderr, which the client leaves attached to its own, so they are
visible without disturbing the protocol.
"""
import argparse
import ctypes
import msvcrt
import os
import struct
import sys

DLLDIR = ""  # LiveCloudKd's build directory holding hvlib.dll and sdk\; pass --dll-dir
INFO_PARTITION_ID = 2
INFO_PARTITION_HANDLE = 21
INFO_CR3_SECUREKERNEL = 45
INFO_SK_BASE = 47

H3_DEVICE = r"\\.\H3Probe"
IOCTL_READ_GPA = (0x22 << 16) | (0x801 << 2)
HV_ACCESS = {0: "Accepted", 1: "Unmapped", 2: "ReadIntercept", 3: "WriteIntercept", 4: "Rom"}


def log(msg):
    print(msg, file=sys.stderr, flush=True)


class VmOperationsConfig(ctypes.Structure):
    """`VM_OPERATIONS_CONFIG`, all **seventeen** fields.

    This is declared here rather than imported, and it is the fix for the fault that
    has been written off across this bench as *"every run of these probes ends in an
    hvlib unload segfault"*.

    `hvlib.py`'s own `CfgParameters` stops at `SimpleMemory` -- twelve fields, 48
    bytes -- while `HvlibEnumPublic.h` carries five more `BOOLEAN`s after it
    (`ReplaceDecypheredKDBG`, `FullCrashDumpEmulation`, `EnumGuestOsBuild`,
    `VSMScan`, `LogSilenceMode`), making the real structure 56. So every
    `SdkGetDefaultConfig` through that binding writes **8 bytes past the end of a
    Python allocation**, and the process then dies wherever the garbage collector
    next touches the damaged block. Caught with `-X faulthandler`, which reports it
    as `Garbage-collecting` -- at a different place in every script, which is
    exactly why it looked intermittent and unattributable.

    Two consequences beyond the crash. The last five flags have never been settable
    from this bench, `VSMScan` among them. And an exit code of `0xC0000005` from any
    of these probes carries no information about what the probe was doing when it
    died, which is how S5r's `SdkWriteVirtualMemory` came to be blamed for a fault
    it had nothing to do with.
    """

    _fields_ = [
        ("ReadMethod", ctypes.c_int),
        ("WriteMethod", ctypes.c_int),
        ("SuspendMethod", ctypes.c_int),
        ("LogLevel", ctypes.c_uint64),
        ("ForceFreezeCPU", ctypes.c_bool),
        ("PausePartition", ctypes.c_bool),
        ("ExdiConsoleHandle", ctypes.c_void_p),
        ("ReloadDriver", ctypes.c_bool),
        ("PFInjection", ctypes.c_bool),
        ("NestedScan", ctypes.c_bool),
        ("UseDebugApiStopProcess", ctypes.c_bool),
        ("SimpleMemory", ctypes.c_bool),
        ("ReplaceDecypheredKDBG", ctypes.c_bool),
        ("FullCrashDumpEmulation", ctypes.c_bool),
        ("EnumGuestOsBuild", ctypes.c_bool),
        ("VSMScan", ctypes.c_bool),
        ("LogSilenceMode", ctypes.c_bool),
    ]


# The protocol starts with a SENTINEL rather than with the first byte of stdout,
# and the reason is third-party code: `hvlib.py` prints a partition menu with an
# ordinary `print()` during setup, so the client's first read would otherwise take
# "[ 0 ] Lab Guest Hyper-V" as the SHAPE reply. Everything before READY_LINE is
# the provider talking about itself, and the client echoes it for the operator.
#
# What is NOT done here, having been tried: duplicating fd 1 for the protocol and
# pointing fd 1 somewhere else. That crashed this process with an access violation
# inside Python's own allocator, deterministically, caught under a debugger on the
# stack `PyFile_WriteString` -> `PyObject_CallOneArg` -> allocation with a corrupt
# object pointer. A sentinel needs the provider to cooperate about nothing.
#
# One thing still has to be forced: `hvlib.py` calls
# `msvcrt.setmode(sys.stdout.fileno(), os.O_TEXT)` at import, which makes fd 1
# translate every LF into CR LF -- one extra byte in each page of guest memory
# containing 0x0A, which would be silent corruption rather than a failure. So the
# mode is set back to binary after the import, and `ready()` is called only then.
READY_LINE = "windbg-mcp-gpa/1"
OUT = sys.stdout.buffer
IN = sys.stdin.buffer


def ready():
    """Force both protocol descriptors binary, then announce the protocol."""
    sys.stdout.flush()
    msvcrt.setmode(1, os.O_BINARY)
    msvcrt.setmode(0, os.O_BINARY)
    send_line(READY_LINE)


def send_line(text):
    OUT.write((text + "\n").encode("ascii"))
    OUT.flush()


class Direct:
    """hvlib + its hvmm driver. Reads VTL1 and never refuses."""

    max_read = 0x1000

    def __init__(self, expected_partition_id, expected_cr3, vtl):
        sys.path.insert(0, os.path.join(DLLDIR, "sdk"))
        os.add_dll_directory(DLLDIR)
        os.chdir(DLLDIR)
        # Only the layout and the enum come from `hvlib.py`. Its `hvlib` CLASS is
        # deliberately NOT used, which is a correctness requirement rather than a
        # preference: its `EnumPartitions` asks for `InfoPartitionFriendlyName`
        # through a `ctypes.c_wchar_p("N")` -- a pointer into a one-character Python
        # string object -- and after that call this process's heap is corrupt. The
        # damage surfaces wherever the garbage collector next runs, which is why it
        # has been written off on this bench as an "hvlib unload segfault": caught
        # under `-X faulthandler` the traceback says `Garbage-collecting`, at a
        # different place in every script. A long-running transport cannot survive
        # that -- it was dying inside `EnumPartitions` itself -- so the four exports
        # this needs are called directly and the friendly name is never asked for.
        from hvlib import ReadMemoryMethod  # noqa: E402

        self.ReadMethod = int(ReadMemoryMethod.ReadInterfaceHvmmDrvInternal)
        self.dll = ctypes.CDLL(os.path.join(DLLDIR, "hvlib.dll"))
        self.dll.SdkGetDefaultConfig.restype = ctypes.c_bool
        self.dll.SdkGetDefaultConfig.argtypes = [ctypes.POINTER(VmOperationsConfig)]
        self.dll.SdkEnumPartitions.restype = ctypes.POINTER(ctypes.c_uint64)
        self.dll.SdkEnumPartitions.argtypes = [ctypes.POINTER(ctypes.c_uint64),
                                               ctypes.POINTER(VmOperationsConfig)]
        self.dll.SdkSelectPartition.restype = ctypes.c_bool
        self.dll.SdkSelectPartition.argtypes = [ctypes.c_uint64]
        self.dll.SdkGetData2.restype = ctypes.c_uint64
        self.dll.SdkGetData2.argtypes = [ctypes.c_uint64, ctypes.c_int32]
        self.dll.SdkReadPhysicalMemory.restype = ctypes.c_bool
        self.dll.SdkReadPhysicalMemory.argtypes = [ctypes.c_uint64, ctypes.c_uint64,
                                                   ctypes.c_uint64, ctypes.c_void_p,
                                                   ctypes.c_uint32]
        self.dll.SdkCloseAllPartitions.restype = ctypes.c_bool
        self.dll.SdkCloseAllPartitions.argtypes = []

        cfg = VmOperationsConfig()
        if not self.dll.SdkGetDefaultConfig(ctypes.byref(cfg)):
            raise SystemExit("SdkGetDefaultConfig failed")
        cfg.ForceFreezeCPU = False
        cfg.PausePartition = False
        cfg.ReloadDriver = False
        cfg.ReadMethod = self.ReadMethod
        count = ctypes.c_uint64(0)
        table = self.dll.SdkEnumPartitions(ctypes.byref(count), ctypes.byref(cfg))
        if not table or count.value == 0:
            raise SystemExit("SdkEnumPartitions found no partitions")
        # The caller obtained this partition id from VidGetHvPartitionId inside the
        # exact disposable vmwp. Do not select or read any other live VM merely
        # because it also happens to have a Secure Kernel.
        self.handle = None
        for i in range(count.value):
            cand = table[i]
            pid = self.dll.SdkGetData2(cand, INFO_PARTITION_ID)
            if pid != expected_partition_id:
                continue
            if not self.dll.SdkSelectPartition(cand):
                raise SystemExit("SdkSelectPartition failed for expected partition %s" % pid)
            base = self.dll.SdkGetData2(cand, INFO_SK_BASE)
            log("  expected partition %s: InfoSecureKernelBase 0x%X" % (pid, base))
            if vtl == 1 and not base:
                raise SystemExit("expected partition %s reports no Secure Kernel base" % pid)
            self.handle, self.pid = cand, pid
            break
        if self.handle is None:
            raise SystemExit("expected partition %s was not enumerated" % expected_partition_id)
        observed_secure_cr3 = self.dll.SdkGetData2(self.handle, INFO_CR3_SECUREKERNEL)
        if vtl == 0 and expected_cr3 is None:
            raise SystemExit("--expected-cr3 is required for VTL0")
        self.cr3 = observed_secure_cr3 if vtl == 1 else expected_cr3
        self.vtl = vtl
        self.sk_base = self.dll.SdkGetData2(self.handle, INFO_SK_BASE)
        if vtl == 1 and expected_cr3 is not None and self.cr3 != expected_cr3:
            raise SystemExit("partition %s CR3 mismatch: expected 0x%X, got 0x%X"
                             % (self.pid, expected_cr3, self.cr3))
        log("direct: partition %s, VTL%d CR3 0x%X, SK base 0x%X, reported SK CR3 0x%X"
            % (self.pid, self.vtl, self.cr3, self.sk_base, observed_secure_cr3))

    def close(self):
        self.dll.SdkCloseAllPartitions()

    def shape(self):
        # cr0/cr4/efer are NOT reported, and are declared `unreadable` instead:
        # hvlib exposes no VTL1 control registers here, and inventing plausible
        # ones would make the decode's long-mode control vacuous -- it answers
        # "unknown" from a missing register by design, and a transport that filled
        # them in would turn that check into one that always passes.
        return ("SHAPE cr3=0x%X kernel_base=0x%X vtl_enabled=%d paging=long max_read=%d "
                "unreadable=cr0:hvlib_exposes_no_VTL1_control_registers "
                "unreadable=cr4:hvlib_exposes_no_VTL1_control_registers "
                "unreadable=efer:hvlib_exposes_no_VTL1_control_registers"
                % (self.cr3, self.sk_base, 1, self.max_read))

    def read(self, gpa, want):
        buf = ctypes.create_string_buffer(want)
        ok = self.dll.SdkReadPhysicalMemory(self.handle, gpa, want, buf, self.ReadMethod)
        if not ok:
            # NOTPRESENT rather than REFUSED: hvlib does not distinguish "no such
            # page" from "the driver said no", and claiming a refusal here would
            # put a per-access refusal count on a source that cannot refuse.
            return None, "NOTPRESENT"
        return bytes(buf.raw[:want]), None


class HvmmDirect:
    """`Direct`, with its pages read from hvmm directly rather than through hvlib.

    The partition, its CR3 and the Secure Kernel's base are still the ones hvlib opened and reported.
    A page hvmm answered without is NOTPRESENT, as hvlib's are. A failed call to the driver is an
    ERROR instead: the client treats that as the end of the walk, which is right for a device that has
    stopped answering, where NOTPRESENT would report every later page as missing.

    A GPA with no RAM behind it is neither: hvmm answers it with a page of zeros (`sklab.hvmm`,
    measured on K3 2026-10-17). Given the guest's own RAM runs (`--ram-runs`, from `sklab.guest_ram`),
    a page of zeros outside them is NOTPRESENT; without them the zeros are passed on as data. The runs
    are the RAM NT owns, so a zero page of firmware's memory below the gap would be NOTPRESENT too;
    `--ask-hypervisor` asks h3probe's HvCallReadGpa about each such page (`sklab.backing`), and one the
    hypervisor calls memory is served as the zeros it is.
    """

    def __init__(self, direct, ram_runs=None, ask_hypervisor=False):
        from sklab import backing, guest_ram, hvmm

        self.direct = direct
        self.max_read = direct.max_read
        handle = direct.dll.SdkGetData2(direct.handle, INFO_PARTITION_HANDLE)
        ram = guest_ram.Ram(guest_ram.parse(ram_runs)) if ram_runs else None
        self.probe = None
        if ram is not None and ask_hypervisor:
            from h3_vtl1_debug_control import Probe  # beside this file

            self.probe = Probe()
        self.device = hvmm.Device()
        self.reader = hvmm.Reader(self.device, handle, direct.pid, ram,
                                  backing.Hypervisor(self.probe, direct.pid) if self.probe else None)
        log("hvmm: partition %s, partition handle 0x%X, reading directly, %s%s" % (
            direct.pid, handle, "RAM runs %s" % ram_runs if ram else "no RAM map: zeros may be no RAM",
            ", asking the hypervisor about zeros outside them" if self.probe else ""))

    def shape(self):
        return self.direct.shape()

    def read(self, gpa, want):
        failed_before = self.reader.failed_calls
        data, failure = self.reader.read(gpa, want)
        if failure is None:
            return data, None
        if self.reader.failed_calls > failed_before:
            return None, "ERROR %s" % failure
        return None, "NOTPRESENT"

    def close(self):
        reader = self.reader
        if reader.ram is not None:
            log("hvmm: outside the RAM runs, %d read(s) came back as zeros and were NOTPRESENT%s, %d as zeros "
                "the hypervisor called memory, %d with data%s" % (
                    reader.outside_zero,
                    " (%s)" % ", ".join("0x%X" % gpa for gpa in reader.refused) if reader.refused else "",
                    reader.outside_zero_backed,
                    reader.outside_with_data,
                    ", memory NT does not own: %s" % ", ".join("0x%X" % gpa for gpa in reader.contradictions)
                    if reader.outside_with_data else ""))
            if reader.answers:
                log("hvmm: the hypervisor's answers: %s" % ", ".join(
                    "0x%X %s" % (gpa, answer) for gpa, answer in reader.answers.items()))
        if self.probe is not None:
            self.probe.close()
        self.device.close()


class Hypercall:
    """`HvCallReadGpa` through the h3probe driver. Refuses VTL1 per access."""

    max_read = 16

    def __init__(self, partition_id, cr3):
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.k32.CreateFileW.restype = ctypes.c_void_p
        self.dev = self.k32.CreateFileW(H3_DEVICE, 0xC0000000, 0, None, 3, 0, None)
        if not self.dev or self.dev == ctypes.c_void_p(-1).value:
            raise SystemExit("cannot open %s (err %d) -- is h3probe.sys loaded?"
                             % (H3_DEVICE, ctypes.get_last_error()))
        self.pid = partition_id
        self.cr3 = cr3
        log("hypercall: partition %s, CR3 0x%X, max_read 16" % (self.pid, self.cr3))

    def shape(self):
        return ("SHAPE cr3=0x%X vtl_enabled=1 paging=long max_read=%d "
                "unreadable=cr0:not_read_over_this_transport "
                "unreadable=cr4:not_read_over_this_transport "
                "unreadable=efer:not_read_over_this_transport"
                % (self.cr3, self.max_read))

    def read(self, gpa, want):
        inb = struct.pack("<QQII", self.pid, gpa, want, 0)
        out = ctypes.create_string_buffer(32)
        ret = ctypes.c_ulong(0)
        ok = self.k32.DeviceIoControl(ctypes.c_void_p(self.dev), IOCTL_READ_GPA, inb, len(inb),
                                      out, 32, ctypes.byref(ret), None)
        if not ok:
            return None, "ERROR DeviceIoControl failed %d" % ctypes.get_last_error()
        status, _, access = struct.unpack_from("<IIQ", out, 0)
        if status != 0:
            return None, "ERROR HV_STATUS 0x%04X" % status
        # The whole reason this mode exists. H4 measured HV_STATUS_SUCCESS with a
        # per-access result of 2 and a buffer of zeros: the hypercall "succeeded"
        # and refused, so a transport reading the status alone would hand the
        # zeros back as data.
        if access != 0:
            return None, "REFUSED %s(%d)" % (HV_ACCESS.get(access, "?"), access)
        return out.raw[16:16 + want], None


def arguments():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=("direct", "hypercall"), default="direct")
    # hvlib by default: the bench's own runners spawn this transport too, and they read through hvlib
    ap.add_argument("--reader", choices=("hvlib", "hvmm"), default="hvlib",
                    help="where direct mode's pages come from; hvlib opens the partition either way")
    ap.add_argument("--ram-runs", help="the guest's RAM as first-end GPA pairs in hex, end exclusive, "
                                       "comma-separated; the hvmm reader refuses a page of zeros outside them")
    ap.add_argument("--ask-hypervisor", action="store_true",
                    help="with --ram-runs, ask h3probe's HvCallReadGpa whether a page of zeros outside them is "
                         "memory, and serve it if so")
    ap.add_argument("--partition-id", type=lambda value: int(value, 0), required=True)
    ap.add_argument("--expected-cr3", type=lambda value: int(value, 0))
    ap.add_argument("--vtl", type=int, choices=(0, 1), default=1)
    ap.add_argument("--dll-dir", default=DLLDIR)
    return ap


def provider(mode, reader, bootstrap, ram_runs=None, ask_hypervisor=False):
    """What the protocol serves pages from, once hvlib has opened the partition as `bootstrap`."""
    if mode == "hypercall":
        return Hypercall(bootstrap.pid, bootstrap.cr3)
    if reader == "hvmm":
        return HvmmDirect(bootstrap, ram_runs, ask_hypervisor)
    return bootstrap


def main():
    global DLLDIR
    args = arguments().parse_args()
    DLLDIR = args.dll_dir
    log("transport starting, mode=%s, pid=%d" % (args.mode, os.getpid()))

    # The hypercall mode needs a partition id and a VTL1 CR3, and the only thing on
    # this bench that knows either is hvlib -- so it is brought up first rather than
    # having the id typed in, for the reason above: partition ids turn over.
    try:
        bootstrap = Direct(args.partition_id, args.expected_cr3, args.vtl)
    except BaseException:
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.stderr.flush()
        raise
    source = provider(args.mode, args.reader, bootstrap, args.ram_runs, args.ask_hypervisor)

    ready()
    log("transport ready, mode=%s, reader=%s" % (args.mode, args.reader if args.mode == "direct" else "h3probe"))
    served = 0
    while True:
        line = IN.readline()
        if not line:
            break
        request = line.decode("ascii", "replace").strip()
        if request == "SHAPE":
            send_line(source.shape())
        elif request.startswith("READ "):
            _, gpa_text, want_text = request.split()
            gpa, want = int(gpa_text, 0), int(want_text)
            if want > source.max_read:
                send_line("ERROR %d exceeds the declared max_read %d" % (want, source.max_read))
                continue
            data, failure = source.read(gpa, want)
            served += 1
            if failure is not None:
                send_line(failure)
                continue
            send_line("OK %d" % len(data))
            OUT.write(data)
            OUT.flush()
        elif request == "":
            continue
        else:
            send_line("ERROR unknown request %r" % request)
    # Closed here rather than at atexit, because nothing registers an atexit handler
    # now that the `hvlib` class is not used -- and because a provider torn down
    # while the interpreter is still alive is one whose failure has somewhere to go.
    log("stdin closed after %d reads, closing the provider" % served)
    if isinstance(source, HvmmDirect):
        source.close()
    bootstrap.close()
    log("exiting")


if __name__ == "__main__":
    main()
