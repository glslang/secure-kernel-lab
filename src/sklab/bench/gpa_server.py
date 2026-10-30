"""windbg-mcp-gpa/1 transport over h3probe, the operator-supplied half of `windbg-mcp --sk-live`.

`windbg-mcp` ships the client half of this protocol (`src/livesrc.rs`) and no transport, because
reading another partition's VTL1 live needs a kernel component that repository will not
distribute. This is sklab's half. It speaks the line protocol on stdio and exits when stdin closes.
It loads no hvlib, and h3probe is the only driver it opens.

Two page sources, and the difference between them is the point:

  --pages h3         h3probe's exact-build VID memory operation, through vmwp's own partition
                     handle. The caller passes only per-boot coordinates discovered from the exact
                     vmwp: its PID, the handle valid inside it, and the partition ID; h3probe checks
                     all three before it reads. Reads VTL1. A page with no RAM behind it answers
                     ``NOTPRESENT`` and one VID refuses answers ``REFUSED``, never a page of zeros.
  --pages hypercall  ``HvCallReadGpa`` through h3probe. H4 measured it answering success with zeros
                     and a per-access ``ReadIntercept`` on VTL1, so it is the transport that produces
                     a real ``ReadFailure::Refused``. It moves at most sixteen bytes, so its
                     ``max_read`` is 16, and it needs only the partition ID.

Reads are uncached, so ``REFRESH`` has nothing to discard and answers ``OK 0``; advertising
``read_coherency=explicit_refresh`` is therefore a statement about this source rather than a
promise it has to keep.

``WRITE`` is served, and ``max_write`` with ``write_coherency=instruction_coherent`` advertised,
only for ``--pages h3`` under ``--writes``. h3probe applies a write as read, patch, write and
full-page read-back, and VID writes the guest's own backing pages, so a write made while the
controller holds the VM paused is what instruction fetch sees after it resumes. The server's
capability is not authority: the windbg-mcp policy decides whether a write is made at all.
"""

from __future__ import annotations

import argparse
import msvcrt
import os
import pathlib
import sys
import traceback
from typing import Any

from guest_physical import (
    GuestVirtual,
    H3Source,
    HypercallSource,
    find_secure_kernel_base,
    vtl1_identity,
)


READY_LINE = "windbg-mcp-gpa/1"
OUT = sys.stdout.buffer
IN = sys.stdin.buffer


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def send_line(message: str) -> None:
    OUT.write((message + "\n").encode("ascii"))
    OUT.flush()


def ready() -> None:
    sys.stdout.flush()
    msvcrt.setmode(1, os.O_BINARY)
    msvcrt.setmode(0, os.O_BINARY)
    send_line(READY_LINE)


def arguments() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pages", choices=("h3", "hypercall"), default="h3")
    parser.add_argument("--vmwp-pid", type=lambda value: int(value, 0))
    parser.add_argument("--partition-handle", type=lambda value: int(value, 0))
    parser.add_argument("--partition-id", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--vp", type=int, default=0)
    parser.add_argument("--expected-cr3", type=lambda value: int(value, 0))
    parser.add_argument("--image", type=pathlib.Path)
    parser.add_argument("--writes", action="store_true", help="serve WRITE and advertise it")
    return parser


def shape(cr3: int, kernel_base: int | None, source: Any, writes: bool) -> str:
    fields = [f"cr3=0x{cr3:X}"]
    if kernel_base is not None:
        fields.append(f"kernel_base=0x{kernel_base:X}")
    fields += ["vtl_enabled=1", "paging=long", f"max_read={source.max_read}"]
    if writes:
        fields += [f"max_write={source.max_write}", "write_coherency=instruction_coherent"]
    fields += [
        "read_coherency=explicit_refresh",
        "unreadable=cr0:h3probe_not_asked",
        "unreadable=cr4:h3probe_not_asked",
        "unreadable=efer:h3probe_not_asked",
    ]
    return "SHAPE " + " ".join(fields)


def serve(source: Any, cr3: int, kernel_base: int | None, writes: bool) -> int:
    served = 0
    while True:
        line = IN.readline()
        if not line:
            break
        request = line.decode("ascii", "replace").strip()
        if request == "SHAPE":
            send_line(shape(cr3, kernel_base, source, writes))
        elif request == "REFRESH":
            send_line("OK 0")
        elif request.startswith("READ "):
            try:
                _, gpa_text, size_text = request.split()
                gpa, size = int(gpa_text, 0), int(size_text, 0)
            except (ValueError, TypeError):
                send_line(f"ERROR malformed request {request!r}")
                continue
            if size > source.max_read:
                send_line(f"ERROR {size} exceeds the declared max_read {source.max_read}")
                continue
            data, failure = source.read(gpa, size)
            served += 1
            if data is None:
                send_line(failure or "ERROR the source returned no failure detail")
                continue
            send_line(f"OK {len(data)}")
            OUT.write(data)
            OUT.flush()
        elif request.startswith("WRITE "):
            limit = getattr(source, "max_write", 0) if writes else 0
            try:
                _, gpa_text, size_text = request.split()
                gpa, size = int(gpa_text, 0), int(size_text, 0)
            except (ValueError, TypeError):
                send_line(f"ERROR malformed request {request!r}")
                break  # the payload length is unknown, so the stream cannot be resynchronised
            if size <= 0 or size > max(limit, 0x1000):
                send_line(f"ERROR {size} is outside 1..{max(limit, 0x1000)}")
                break
            data = IN.read(size)
            if len(data) != size:
                send_line(f"ERROR write payload ended at {len(data)} of {size} bytes")
                break
            if not limit:
                send_line("ERROR this transport was started without --writes")
                continue
            failure = source.write(gpa, data)
            send_line(failure if failure is not None else f"OK {size}")
        elif request:
            send_line(f"ERROR unknown request {request!r}")
    log(f"stdin closed after {served} reads")
    return 0


def main() -> int:
    args = arguments().parse_args()
    source: Any = None
    try:
        identity = vtl1_identity(args.partition_id, args.vp)
        cr3 = identity["cr3"]
        if args.expected_cr3 is not None and cr3 != args.expected_cr3:
            raise RuntimeError(
                f"VTL1 CR3 0x{cr3:x} does not match expected 0x{args.expected_cr3:x}"
            )
        if args.pages == "hypercall":
            if args.writes:
                raise RuntimeError("the hypercall source refuses writes as it refuses VTL1 reads")
            source = HypercallSource(args.partition_id)
            log(f"hypercall: partition 0x{args.partition_id:x}, VP={args.vp}, CR3=0x{cr3:x}, max_read 16")
            ready()
            return serve(source, cr3, None, False)

        if args.vmwp_pid is None or args.partition_handle is None:
            raise RuntimeError("--pages h3 needs --vmwp-pid and --partition-handle")
        source = H3Source(args.vmwp_pid, args.partition_handle, args.partition_id)
        guest = GuestVirtual(source, cr3)
        kernel_base, evidence = find_secure_kernel_base(
            guest,
            identity["idtr_base"],
            identity["idtr_limit"],
            args.image,
        )
        log(
            f"h3 memory: vmwp={args.vmwp_pid}, partition_handle=0x{args.partition_handle:x}, "
            f"partition=0x{args.partition_id:x}, VP={args.vp}, CR3=0x{cr3:x}, "
            f"writes={'served' if args.writes else 'refused'}"
        )
        log(
            f"IDTR={evidence['idtr_base']}/{evidence['idtr_limit']:#x}, "
            f"handler={evidence['handler']}, Secure Kernel base=0x{kernel_base:x}, "
            f"pages_checked={evidence['pages_checked']}"
        )
        ready()
        return serve(source, cr3, kernel_base, args.writes)
    except BaseException:
        traceback.print_exc(file=sys.stderr)
        return 1
    finally:
        if source is not None:
            source.close()


if __name__ == "__main__":
    raise SystemExit(main())
