"""Compatibility validator for an existing vmwp profile candidate.

New candidates should be generated with ``sklab profile vmwp``. This wrapper
retains the original validation interface for recorded runbooks.
"""

from __future__ import annotations

import argparse
import json
import pathlib

from sklab.vmwp_profile import validate_existing_candidate


ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = ROOT / "profiles" / "vmwp-dispatcher-profile-26100.9457.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=pathlib.Path, default=DEFAULT_PROFILE)
    parser.add_argument("--candidate", type=pathlib.Path, required=True)
    parser.add_argument("--old", type=pathlib.Path, required=True)
    parser.add_argument(
        "--new",
        type=pathlib.Path,
        default=pathlib.Path(r"C:\Windows\System32\vmwp.exe"),
    )
    parser.add_argument(
        "--vid-image",
        type=pathlib.Path,
        default=pathlib.Path(r"C:\Windows\System32\vid.dll"),
    )
    parser.add_argument("--prefix-bytes", type=int, default=32)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args()

    report = validate_existing_candidate(
        args.profile,
        args.candidate,
        args.old,
        args.new,
        args.vid_image,
        prefix_bytes=args.prefix_bytes,
    )
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
