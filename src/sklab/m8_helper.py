from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import json
from pathlib import Path
import sys
from typing import Sequence

from .config import load
from .errors import LabError
from .m8 import boot_identity, trigger_enclave
from .modules import ALL_MODULES
from .output import Output
from .runner import execute_module


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Host callbacks for the exact M8 qualification harness"
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--target", required=True)
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("boot")
    trigger = actions.add_parser("trigger")
    trigger.add_argument("--count", type=int, required=True)
    audit = actions.add_parser("audit")
    audit.add_argument("--survival-seconds", type=int, default=60)
    audit.add_argument("--profile", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        config = load(args.config)
        target = config.target(args.target)
        if args.action == "boot":
            result = boot_identity(target)
        elif args.action == "trigger":
            result = trigger_enclave(target, args.count)
        else:
            if args.survival_seconds < 0:
                raise ValueError("survival-seconds must not be negative")
            # Provider helpers inherited from the original bench may print diagnostics. Keep the
            # callback's stdout as exactly one JSON object for the Rust harness.
            with redirect_stdout(sys.stderr):
                outcome = execute_module(
                    config,
                    ALL_MODULES["validate.kd-post-audit"],
                    target_name=target.name,
                    overrides={
                        "survival_seconds": args.survival_seconds,
                        "profile": str(args.profile) if args.profile is not None else None,
                    },
                    output=Output(stream=sys.stderr, color=False),
                    assume_yes=True,
                )
            result = {"result": "pass", "run_dir": str(outcome.run_dir), **outcome.result}
        print(json.dumps(result, sort_keys=True), flush=True)
        return 0
    except (LabError, OSError, ValueError) as error:
        print(f"{type(error).__name__}: {error}", file=sys.stderr, flush=True)
        return 1
    except Exception as error:
        print(f"{type(error).__name__}: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
