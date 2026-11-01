from __future__ import annotations

from pathlib import Path
from typing import Any

from .. import m8
from ..context import RunContext
from ..doctor import passed, run as doctor
from ..errors import PrerequisiteError
from ..policy import write_policy
from .spec import ModuleSpec


def _checks(ctx: RunContext, _options: dict[str, Any]) -> list[dict[str, Any]]:
    return doctor(
        ctx.config,
        ctx.target,
        required={
            "administrator",
            "mcp",
            "repo",
            "profile",
            "image",
            "identity",
            "running",
            "disposable",
            "h3probe",
        },
    )


def _kd_post_audit_checks(ctx: RunContext, options: dict[str, Any]) -> list[dict[str, Any]]:
    return _checks(ctx, options)


def kd_post_audit(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    checks = _kd_post_audit_checks(ctx, options)
    if not passed(checks):
        raise PrerequisiteError("KD post-release audit prerequisites failed")
    ctx.require_disposable()
    target = ctx.target
    assert target is not None
    ctx.confirm(f"Pause {target.vm_name} and run the KD post-release restoration audit?")
    from .core import _post_kd_audit

    configured_profile = options.get("profile")
    return _post_kd_audit(
        ctx,
        survival_seconds=int(options.get("survival_seconds", 0)),
        profile=Path(str(configured_profile)) if configured_profile else None,
    )


def _cargo_acceptance(ctx: RunContext, options: dict[str, Any], *, kd: bool) -> dict[str, Any]:
    checks = _checks(ctx, options)
    if not passed(checks):
        raise PrerequisiteError("live acceptance prerequisites failed")
    target = ctx.target
    assert target is not None
    configured = str(options.get("config", "")).strip()
    generated = False
    if configured:
        config_path = Path(configured).expanduser().resolve(strict=False)
        if not config_path.is_file():
            raise PrerequisiteError(f"acceptance config is not a file: {config_path}")
    elif kd:
        config_path = m8.write_managed_kd_config(
            ctx.config, target, ctx.run_dir / "managed-kd-config.json"
        )
        generated = True
    else:
        raise PrerequisiteError("set config to a prepared live acceptance JSON file")
    ctx.confirm(f"Run the {'KD' if kd else 'live-control'} acceptance tier against {target.vm_name}?")
    policy = ctx.run_dir / "sk-live-policy.json"
    write_policy(
        ctx.config,
        target,
        policy,
        extra_profile_roots=(config_path.parent,) if generated else (),
    )
    test = (
        "a_managed_secure_kernel_kd_session_resolves_symbols_and_unwinds_a_natural_stop"
        if kd
        else "a_live_secure_kernel_session_stops_steps_inspects_resumes_and_closes"
    )
    variable = "WINDBG_MCP_SMOKE_SK_KD" if kd else "WINDBG_MCP_SMOKE_SK_LIVE"
    ctx.run_process(
        [
            "cargo",
            "test",
            "--test",
            "mcp_smoke",
            "--",
            "--ignored",
            "--exact",
            test,
            "--nocapture",
            "--test-threads=1",
        ],
        env={
            variable: str(config_path),
            "WINDBG_MCP_SK_LIVE_POLICY": str(policy),
            "WINDBG_MCP_TRANSCRIPT": str(ctx.run_dir / "mcp.jsonl"),
            "WINDBG_MCP_TRANSCRIPT_MAX_FIELD": "0",
        },
        name="kd-acceptance" if kd else "live-acceptance",
        timeout=float(options.get("timeout", 900)),
    )
    return {"test": test, "config": str(config_path)}


def live_acceptance(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    return _cargo_acceptance(ctx, options, kd=False)


def kd_acceptance(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    return _cargo_acceptance(ctx, options, kd=True)


def _m8_checks(ctx: RunContext, options: dict[str, Any]) -> list[dict[str, Any]]:
    scope = str(options.get("scope", "composite"))
    required = {
        "administrator",
        "mcp",
        "repo",
        "profile",
        "image",
        "identity",
        "running",
        "disposable",
        "h3probe",
        "symbols",
    }
    if scope.startswith("external"):
        required |= {"windbg_classic", "windbgx"}
    checks = doctor(ctx.config, ctx.target, required=required)
    credential = ctx.target.guest_credential_file if ctx.target is not None else None
    checks.append(
        {
            "name": "guest credential file",
            "status": "ok" if credential is not None and credential.is_file() else "error",
            "detail": str(credential or "not configured"),
            "required": True,
        }
    )
    checks.append(
        {
            "name": "M8 debugger control helper",
            "status": "ok" if m8.debugger_control_script().is_file() else "error",
            "detail": str(m8.debugger_control_script()),
            "required": scope.startswith("external"),
        }
    )
    return checks


def m8_acceptance(ctx: RunContext, options: dict[str, Any]) -> dict[str, Any]:
    checks = _m8_checks(ctx, options)
    if not passed(checks):
        raise PrerequisiteError("M8 qualification prerequisites failed")
    ctx.require_disposable()
    target = ctx.target
    assert target is not None
    scope = str(options.get("scope", "composite"))
    tests = {
        "composite": (
            "a_managed_secure_kernel_kd_session_is_driven_by_this_servers_own_kernel_attach",
            "WINDBG_MCP_SMOKE_SK_KD",
        ),
        "external-preflight": (
            "sk_m8::qualification_preflight_reads_one_healthy_static_boot",
            "WINDBG_MCP_SMOKE_SK_KD_M8",
        ),
        "external-breakpoints": (
            "sk_m8::qualification_runner_executes_breakpoint_matrix_on_one_boot",
            "WINDBG_MCP_SMOKE_SK_KD_M8",
        ),
        "external-full": (
            "sk_m8::qualification_runner_executes_full_m8_2a_matrix_on_one_boot",
            "WINDBG_MCP_SMOKE_SK_KD_M8",
        ),
    }
    if scope not in tests:
        raise PrerequisiteError(
            "scope must be composite, external-preflight, external-breakpoints, or external-full"
        )
    if scope == "external-full" and not options.get("include_non_gating_gui_controls", False):
        raise PrerequisiteError(
            "external-full contains the non-gating GUI race rig; set "
            "include_non_gating_gui_controls=true to request it explicitly"
        )
    ctx.confirm(f"Run the exact M8 {scope} qualification against {target.vm_name}?")
    breakpoint = str(options.get("breakpoint", m8.DEFAULT_BREAKPOINT))
    if scope == "composite":
        config_path = m8.write_composite_config(
            ctx.config,
            target,
            ctx.run_dir / "m8-composite-config.json",
            breakpoint=breakpoint,
        )
        policy_path = ctx.run_dir / "sk-live-policy.json"
        write_policy(ctx.config, target, policy_path)
    else:
        config_path = m8.write_qualification_config(
            ctx.config,
            target,
            ctx.run_dir / "m8-external",
            breakpoint=breakpoint,
        )
        policy_path = ctx.run_dir / "m8-external" / "m8-policy-hardware.json"
    test, variable = tests[scope]
    ctx.run_process(
        [
            "cargo",
            "test",
            "--test",
            "mcp_smoke",
            "--",
            "--ignored",
            "--exact",
            test,
            "--nocapture",
            "--test-threads=1",
        ],
        env={
            variable: str(config_path),
            "WINDBG_MCP_SK_LIVE_POLICY": str(policy_path),
            "WINDBG_MCP_TRANSCRIPT": str(ctx.run_dir / "mcp.jsonl"),
            "WINDBG_MCP_TRANSCRIPT_MAX_FIELD": "0",
        },
        name=f"m8-{scope}",
        timeout=float(options.get("timeout", 14_400)),
    )
    return {"scope": scope, "test": test, "config": str(config_path)}


ADVANCED_MODULES = [
    ModuleSpec(
        "validate.kd-post-audit",
        "Validate the KD post-release audit",
        "advanced",
        "target-control",
        "Run windbg-mcp's identity, guarded-text, debug-register, flags and health audit.",
        {"survival_seconds": 0, "profile": None},
        _kd_post_audit_checks,
        kd_post_audit,
    ),
    ModuleSpec(
        "validate.live",
        "Run the opt-in live MCP acceptance",
        "advanced",
        "target-control",
        "Run the exact live-control smoke tier from a prepared JSON config.",
        {"timeout": 900},
        _checks,
        live_acceptance,
    ),
    ModuleSpec(
        "validate.kd",
        "Run the opt-in managed KD acceptance",
        "advanced",
        "target-control",
        "Run the exact managed KD symbol/unwind tier from a prepared JSON config.",
        {"timeout": 900},
        _checks,
        kd_acceptance,
    ),
    ModuleSpec(
        "validate.m8",
        "Run the exact M8 debugger qualification",
        "advanced",
        "target-control",
        "Generate sklab inputs and run windbg-mcp's M8 qualification tiers.",
        {
            "scope": "composite",
            "breakpoint": m8.DEFAULT_BREAKPOINT,
            "timeout": 14_400,
            "include_non_gating_gui_controls": False,
        },
        _m8_checks,
        m8_acceptance,
    ),
]
