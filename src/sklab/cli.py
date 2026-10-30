from __future__ import annotations

import argparse
from dataclasses import replace
import hashlib
from pathlib import Path
import sys
from typing import Any, Callable, Sequence

from . import __version__, banner, drivers, vm_disk
from .config import Config, Target, load
from .doctor import passed, run as doctor
from .errors import Cancelled, ExecutionFailure, LabError, PrerequisiteError, RecoveryRequired
from .modules import ALL_MODULES
from .output import Output
from .runner import check_module, execute_module, select_target
from .util import parse_scalar


def module_rows() -> list[dict[str, Any]]:
    return [
        {
            "#": index,
            "module": module.id,
            "category": module.category,
            "risk": module.risk,
            "title": module.title,
        }
        for index, module in enumerate(ALL_MODULES.values(), 1)
    ]


def resolve_module(value: str):
    if value.isdigit():
        index = int(value)
        modules = list(ALL_MODULES.values())
        if 1 <= index <= len(modules):
            return modules[index - 1]
    try:
        return ALL_MODULES[value]
    except KeyError as error:
        raise PrerequisiteError(f"unknown module {value!r}; use 'sklab modules'") from error


def render_banner(config: Config | None, target_name: str | None, output: Output) -> str:
    counts: dict[str, int] = {}
    for module in ALL_MODULES.values():
        counts[module.category] = counts.get(module.category, 0) + 1
    target = None
    states: dict[str, str] = {}
    if config is not None:
        try:
            selected = select_target(config, target_name)
        except LabError:
            selected = None
        if selected is not None:
            target = f"{selected.name}: {selected.vm_name}"
        states[config.drivers.h3probe_service] = drivers.status(config.drivers.h3probe_service).state
    return banner.render(modules=counts, target=target, drivers=states, paint=output.paint)


def _driver_services(config: Config, action: str, service: str | None) -> list[str]:
    # h3probe is the only driver sklab manages; naming it is accepted so older scripts still work.
    known = [config.drivers.h3probe_service]
    if service is not None and service not in known:
        raise PrerequisiteError(f"unknown driver {service!r}; configured: {', '.join(known)}")
    return known


def run_driver(
    config: Config,
    action: str,
    service: str | None,
    output: Output,
    *,
    confirm: Callable[[str], bool],
) -> int:
    """Report, start or stop the host drivers the providers depend on."""
    services = _driver_services(config, action, service)
    if action != "status":
        warning = " Stop only when no live session holds the device." if action == "stop" else ""
        if not confirm(f"{action.capitalize()} kernel driver(s) {', '.join(services)} on this host?{warning}"):
            raise PrerequisiteError("operator declined the driver change")
    rows = []
    for name in services:
        if action == "status":
            state = drivers.status(name)
        else:
            try:
                state = drivers.start(name) if action == "start" else drivers.stop(name)
            except drivers.DriverError as error:
                raise ExecutionFailure(str(error)) from error
        rows.append({"service": state.service, "state": state.state, "image": str(state.image or "")})
    output.table(rows, ("service", "state", "image"))
    if action == "status":
        return 0
    want = "running" if action == "start" else "stopped"
    return 0 if all(row["state"] == want for row in rows) else 1


def run_vm(
    config: Config,
    target_name: str | None,
    action: str,
    output: Output,
    *,
    confirm: Callable[[str], bool],
) -> int:
    """Report or replace the selected disposable VM's differencing disk."""
    target = select_target(config, target_name)
    if target is None:
        raise PrerequisiteError("vm commands require a configured target")
    before = vm_disk.status(target)
    output.table([vm_disk.row(before)], ("state", "size_gib", "type", "disk", "parent"))
    if action == "status":
        return 0
    if action != "reset":
        raise PrerequisiteError(f"unsupported vm action {action!r}")
    size_gib = int(before["file_size_bytes"]) / (1024**3)
    if not confirm(
        f"Replace {target.vm_name}'s {size_gib:.3f} GiB child, prove a healthy boot, "
        "and permanently delete the old child?"
    ):
        raise PrerequisiteError("operator declined the VM disk reset")
    output.event("phase", "resetting the disposable VM disk", target=target.name)
    result = vm_disk.reset(target)
    output.event(
        "ok",
        "VM disk reset completed",
        reclaimed_gib=f"{int(result['reclaimed_bytes']) / (1024**3):.3f}",
        healthy_boot_seconds=result["healthy_boot_seconds"],
    )
    output.table([vm_disk.row(result)], ("state", "size_gib", "type", "disk", "parent"))
    return 0


def _confirm_cli(assume_yes: bool) -> Callable[[str], bool]:
    def confirm(prompt: str) -> bool:
        if assume_yes:
            return True
        if not sys.stdin.isatty():
            raise PrerequisiteError("a driver change requires --yes when stdin is not interactive")
        return input(f"{prompt} [y/N] ").strip().lower() in {"y", "yes"}

    return confirm


def parse_overrides(values: Sequence[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for value in values:
        if "=" not in value:
            raise PrerequisiteError(f"option {value!r} must use NAME=VALUE")
        name, raw = value.split("=", 1)
        name = name.strip().replace("-", "_")
        if not name:
            raise PrerequisiteError("option name cannot be empty")
        result[name] = parse_scalar(raw.strip())
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sklab", description="Secure Kernel research console")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", type=Path, help="TOML configuration (default: config.local.toml)")
    parser.add_argument("--target", help="configured target name")
    parser.add_argument("--output", choices=("text", "jsonl"), default="text")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--no-banner", action="store_true", help="open the console without the banner")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("console", help="open the interactive console")
    subparsers.add_parser("banner", help="print the console banner")
    driver = subparsers.add_parser("driver", help="report, start or stop h3probe")
    driver.add_argument("action", nargs="?", choices=("status", "start", "stop"), default="status")
    driver.add_argument("service", nargs="?", help="the configured driver (default: h3probe)")
    driver.add_argument("--yes", action="store_true", help="accept the driver change without a prompt")
    vm = subparsers.add_parser("vm", help="report or reset the disposable VM's differencing disk")
    vm.add_argument("action", nargs="?", choices=("status", "reset"), default="status")
    vm.add_argument("--yes", action="store_true", help="accept permanent deletion of the old child")
    subparsers.add_parser("modules", aliases=["list"], help="list modules")
    show = subparsers.add_parser("show", help="show module metadata and defaults")
    show.add_argument("module")
    subparsers.add_parser("doctor", help="check the complete configured lab")

    profile = subparsers.add_parser("profile", help="derive exact-build maintenance profiles")
    profile_kinds = profile.add_subparsers(dest="profile_kind", required=True)
    vmwp = profile_kinds.add_parser("vmwp", help="derive a vmwp dispatcher profile offline")
    vmwp.add_argument("--baseline", type=Path, required=True, help="previous validated profile")
    vmwp.add_argument(
        "--old-image",
        type=Path,
        required=True,
        help="vmwp.exe matching the baseline",
    )
    vmwp.add_argument(
        "--new-image",
        type=Path,
        default=Path(r"C:\Windows\System32\vmwp.exe"),
        help="serviced vmwp.exe to profile",
    )
    vmwp.add_argument(
        "--vid-image",
        type=Path,
        default=Path(r"C:\Windows\System32\vid.dll"),
        help="vid.dll paired with the serviced vmwp.exe",
    )
    vmwp.add_argument("--output", dest="candidate_output", type=Path, required=True)
    vmwp.add_argument("--report", type=Path, help="report path (default: beside the candidate)")
    vmwp.add_argument("--prefix-bytes", type=int, default=32)
    vmwp.add_argument(
        "--live-validate",
        action="store_true",
        help="exercise the candidate through live.ambient without changing the configuration",
    )
    vmwp.add_argument("--live-report", type=Path, help="write-once live-validation report")
    vmwp.add_argument("--live-steps", type=int, default=1)
    vmwp.add_argument("--yes", action="store_true", help="accept live target mutation")

    check = subparsers.add_parser("check", help="check one module without running it")
    check.add_argument("module")
    check.add_argument("--set", action="append", default=[], metavar="NAME=VALUE")

    run = subparsers.add_parser("run", help="run one module")
    run.add_argument("module")
    run.add_argument("--set", action="append", default=[], metavar="NAME=VALUE")
    run.add_argument("--yes", action="store_true", help="accept target-mutation confirmation")
    return parser


def _show(module, output: Output) -> None:
    if output.mode == "jsonl":
        output.event(
            "module",
            id=module.id,
            title=module.title,
            category=module.category,
            risk=module.risk,
            description=module.description,
            defaults=module.defaults,
        )
        return
    print(f"{module.id} - {module.title}", file=output.stream)
    print(f"category: {module.category}", file=output.stream)
    print(f"risk:     {module.risk}", file=output.stream)
    print(f"about:    {module.description}", file=output.stream)
    print("defaults:", file=output.stream)
    if module.defaults:
        for name, value in module.defaults.items():
            print(f"  {name} = {value!r}", file=output.stream)
    else:
        print("  (none)", file=output.stream)


def _load(args: argparse.Namespace) -> Config:
    return load(args.config)


def _profile_vmwp(args: argparse.Namespace, output: Output) -> int:
    from . import vmwp_profile

    result = vmwp_profile.generate(
        args.baseline,
        args.old_image,
        args.new_image,
        args.vid_image,
        prefix_bytes=args.prefix_bytes,
    )
    if args.live_report is not None and not args.live_validate:
        raise PrerequisiteError("--live-report requires --live-validate")
    if args.live_steps < 1:
        raise PrerequisiteError("--live-steps must be positive")
    requested_candidate = args.candidate_output.expanduser().resolve(strict=False)
    requested_report = (
        (args.report or vmwp_profile.default_report_path(requested_candidate))
        .expanduser()
        .resolve(strict=False)
    )
    live_report = (
        (args.live_report or vmwp_profile.default_live_report_path(requested_candidate))
        .expanduser()
        .resolve(strict=False)
    )
    live_config = live_target = None
    if args.live_validate:
        if live_report in {requested_candidate, requested_report}:
            raise PrerequisiteError(
                "the candidate, offline report, and live report paths must differ"
            )
        if live_report.exists():
            raise vmwp_profile.ProfileError(f"refusing to overwrite existing output: {live_report}")
        live_config = _load(args)
        live_target = select_target(live_config, args.target)
        if live_target is None:
            raise PrerequisiteError("live profile validation requires a configured target")
        if not live_target.disposable:
            raise PrerequisiteError("live profile validation requires disposable = true")
        result.report["live_validation"] = {
            "status": "separate-run-requested",
            "report": str(live_report),
        }
    candidate, report = vmwp_profile.write_new(
        result,
        requested_candidate,
        requested_report,
    )
    mappings = [
        {"site": name, **{key: row[key] for key in ("baseline_rva", "selected_rva", "selection")}}
        for name, row in {
            **result.report["guarded_sites"],
            **result.report["function_prefixes"],
            "callback_resume_rva": result.report["callback_resume"],
        }.items()
    ]
    output.event(
        "ok",
        "generated an offline vmwp profile candidate; it was not activated",
        candidate=str(candidate),
        report=str(report),
        vmwp_version=result.report["new"]["vmwp"]["file_version"] or "unavailable",
        vmwp_sha256=result.candidate["vmwp_sha256"],
        live_validation=result.report["live_validation"]["status"],
    )
    output.table(mappings, ("site", "baseline_rva", "selected_rva", "selection"))
    if args.live_validate:
        assert live_config is not None and live_target is not None
        _live_validate_profile(
            args,
            output,
            result.candidate,
            candidate,
            live_report,
            live_config,
            live_target,
        )
    return 0


def _live_validate_profile(
    args: argparse.Namespace,
    output: Output,
    candidate_value: dict[str, Any],
    candidate_path: Path,
    report_path: Path,
    config: Config,
    target: Target,
) -> None:
    """Run the existing disposable ambient gate with an ephemeral profile selection."""
    from . import vmwp_profile

    selected = replace(
        target,
        profile=candidate_path,
        expected_vmwp_sha256=str(candidate_value["vmwp_sha256"]),
    )
    configured = replace(config, targets={**config.targets, selected.name: selected})
    record: dict[str, Any] = {
        "schema": "secure-kernel-lab.vmwp-live-validation.v1",
        "candidate": str(candidate_path),
        "candidate_sha256": hashlib.sha256(candidate_path.read_bytes()).hexdigest().upper(),
        "target": selected.name,
        "module": "live.ambient",
        "steps": args.live_steps,
        "config_changed": False,
    }
    try:
        outcome = execute_module(
            configured,
            ALL_MODULES["live.ambient"],
            target_name=selected.name,
            overrides={"steps": args.live_steps},
            output=output,
            assume_yes=args.yes,
        )
    except BaseException as error:
        record.update(
            status="failed",
            error=f"{type(error).__name__}: {error}",
        )
        vmwp_profile.write_json_new(report_path, record)
        raise
    record.update(status="pass", run_dir=str(outcome.run_dir))
    vmwp_profile.write_json_new(report_path, record)
    output.event(
        "ok",
        "candidate passed the separate disposable-VM live validation",
        report=str(report_path),
        run_dir=str(outcome.run_dir),
    )


def dispatch(args: argparse.Namespace, output: Output) -> int:
    command = args.command or "console"
    if command in {"modules", "list"}:
        output.table(module_rows(), ("#", "module", "category", "risk", "title"))
        return 0
    if command == "show":
        _show(resolve_module(args.module), output)
        return 0
    if command == "profile":
        if args.profile_kind == "vmwp":
            return _profile_vmwp(args, output)
        raise PrerequisiteError(f"unsupported profile kind {args.profile_kind!r}")

    config = _load(args)
    if command == "console":
        from .console import LabConsole

        LabConsole(
            config,
            target_name=args.target,
            output=output,
            show_banner=not args.no_banner,
        ).cmdloop()
        return 0
    if command == "banner":
        print(render_banner(config, args.target, output), file=output.stream)
        return 0
    if command == "driver":
        return run_driver(config, args.action, args.service, output, confirm=_confirm_cli(args.yes))
    if command == "vm":
        return run_vm(config, args.target, args.action, output, confirm=_confirm_cli(args.yes))
    if command == "doctor":
        target = select_target(config, args.target)
        checks = doctor(config, target)
        output.table(checks, ("status", "name", "detail"))
        return 0 if passed(checks) else 2
    module = resolve_module(args.module)
    overrides = parse_overrides(args.set)
    if command == "check":
        checks = check_module(
            config,
            module,
            target_name=args.target,
            overrides=overrides,
        )
        output.table(checks, ("status", "name", "detail"))
        return 0 if passed(checks) else 2
    if command == "run":
        outcome = execute_module(
            config,
            module,
            target_name=args.target,
            overrides=overrides,
            output=output,
            assume_yes=args.yes,
        )
        if output.mode == "jsonl":
            output.event("result", module=module.id, result=outcome.result, run_dir=str(outcome.run_dir))
        return 0
    raise PrerequisiteError(f"unsupported command {command}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    output = Output(args.output, color=not args.no_color)
    try:
        return dispatch(args, output)
    except RecoveryRequired as error:
        output.event("error", str(error), exit_code=3)
        return 3
    except Cancelled:
        output.event("warning", "cancelled", exit_code=130)
        return 130
    except (PrerequisiteError, FileNotFoundError) as error:
        output.event("error", str(error), exit_code=2)
        return 2
    except (ExecutionFailure, LabError) as error:
        output.event("error", str(error), exit_code=1)
        return 1
    except KeyboardInterrupt:
        output.event("warning", "cancelled", exit_code=130)
        return 130
    except Exception as error:
        output.event("error", f"internal error: {type(error).__name__}: {error}", exit_code=1)
        return 1


if __name__ == "__main__":
    sys.exit(main())
