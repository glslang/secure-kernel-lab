"""windbg-mcp-gpa/1 transport using hvmm and a duplicated vmwp VID handle.

The caller passes only per-boot coordinates discovered from the exact vmwp. The
transport loads neither hvlib.dll nor its Python bindings.
"""

from __future__ import annotations

import argparse
import msvcrt
import os
import pathlib
import sys
import traceback

from hvmm_gpa import GuestVirtual, HvmmSource, find_secure_kernel_base, vtl1_identity


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
    parser.add_argument("--vmwp-pid", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--partition-handle", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--partition-id", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--vp", type=int, default=0)
    parser.add_argument("--expected-cr3", type=lambda value: int(value, 0))
    parser.add_argument("--image", type=pathlib.Path)
    return parser


def main() -> int:
    args = arguments().parse_args()
    source: HvmmSource | None = None
    try:
        identity = vtl1_identity(args.partition_id, args.vp)
        cr3 = identity["cr3"]
        if args.expected_cr3 is not None and cr3 != args.expected_cr3:
            raise RuntimeError(
                f"VTL1 CR3 0x{cr3:x} does not match expected 0x{args.expected_cr3:x}"
            )
        source = HvmmSource(args.vmwp_pid, args.partition_handle)
        guest = GuestVirtual(source, cr3)
        kernel_base, evidence = find_secure_kernel_base(
            guest,
            identity["idtr_base"],
            identity["idtr_limit"],
            args.image,
        )
        log(
            f"hvmm duplicate: vmwp={args.vmwp_pid}, source_handle=0x{args.partition_handle:x}, "
            f"partition=0x{args.partition_id:x}, VP={args.vp}, CR3=0x{cr3:x}"
        )
        log(
            f"IDTR={evidence['idtr_base']}/{evidence['idtr_limit']:#x}, "
            f"handler={evidence['handler']}, Secure Kernel base=0x{kernel_base:x}, "
            f"pages_checked={evidence['pages_checked']}"
        )
        ready()
        served = 0
        while True:
            line = IN.readline()
            if not line:
                break
            request = line.decode("ascii", "replace").strip()
            if request == "SHAPE":
                send_line(
                    f"SHAPE cr3=0x{cr3:X} kernel_base=0x{kernel_base:X} "
                    f"vtl_enabled=1 paging=long max_read={source.max_read} "
                    "unreadable=cr0:h3probe_not_asked "
                    "unreadable=cr4:h3probe_not_asked "
                    "unreadable=efer:h3probe_not_asked"
                )
            elif request.startswith("READ "):
                try:
                    _, gpa_text, size_text = request.split()
                    gpa, size = int(gpa_text, 0), int(size_text, 0)
                except (ValueError, TypeError):
                    send_line(f"ERROR malformed request {request!r}")
                    continue
                if size > source.max_read:
                    send_line(
                        f"ERROR {size} exceeds the declared max_read {source.max_read}"
                    )
                    continue
                data, failure = source.read(gpa, size)
                served += 1
                if data is None:
                    send_line(failure or "ERROR hvmm returned no failure detail")
                    continue
                send_line(f"OK {len(data)}")
                OUT.write(data)
                OUT.flush()
            elif request:
                send_line(f"ERROR unknown request {request!r}")
        log(f"stdin closed after {served} reads")
        return 0
    except BaseException:
        traceback.print_exc(file=sys.stderr)
        return 1
    finally:
        if source is not None:
            source.close()


if __name__ == "__main__":
    raise SystemExit(main())
