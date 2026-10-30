from __future__ import annotations

from contextlib import contextmanager
import importlib
import os
from pathlib import Path
import sys
from typing import Any, Iterator

from .config import Target
from .context import RunContext
from .errors import ExecutionFailure
from .policy import bench_directory, control_transport, live_transport, write_policy
from .util import temporary_environment


def _module(name: str) -> Any:
    location = str(bench_directory())
    if location not in sys.path:
        sys.path.insert(0, location)
    return importlib.import_module(name)


def configure(ctx: RunContext, *, transition: bool = False) -> dict[str, Any]:
    if ctx.target is None:
        raise ExecutionFailure("the bench workflow requires a configured target")
    target = ctx.target
    k4 = _module("run_k4_stop_step")
    h3 = _module("h3_vtl1_debug_control")
    memory = _module("guest_physical")
    mcp_module = _module("inject_provider_death_mcp")
    exp = _module("run_vtl1_user_to_securekernel")

    k4.ROOT = ctx.config.paths.windbg_mcp_repo
    k4.HERE = ctx.run_dir
    k4.CDB = ctx.config.paths.cdb_exe
    k4.MCP_EXE = ctx.config.paths.windbg_mcp_exe
    k4.VM_NAME = target.vm_name
    k4.VM_ID = target.vm_id
    k4.IMAGE = target.secure_kernel_image
    k4.PROFILE = target.profile
    k4.DISCOVERY_CACHE = ctx.config.paths.state_root / target.name / "discovery-cache.json"
    if target.expected_image_sha256:
        k4.IMAGE_SHA256 = target.expected_image_sha256
    if target.expected_vmwp_sha256:
        k4.VMWP_SHA256 = target.expected_vmwp_sha256
    if target.expected_vid_sha256:
        k4.VID_DLL_SHA256 = target.expected_vid_sha256

    mcp_module.ROOT = ctx.config.paths.windbg_mcp_repo
    mcp_module.MCP_EXE = ctx.config.paths.windbg_mcp_exe

    exp.ROOT = ctx.config.paths.windbg_mcp_repo
    exp.HERE = ctx.run_dir
    exp.RUN_ROOT = ctx.run_dir / "transition-fresh"
    exp.VM_ID = target.vm_id
    exp.VM_NAME = target.vm_name
    exp.SK_IMAGE = target.secure_kernel_image
    exp.PROFILE = target.profile
    if target.parent_disk:
        exp.PARENT_DISK = target.parent_disk
    if target.work_disk_root:
        exp.PRIVATE_DISK_ROOT = target.work_disk_root

    policy = ctx.run_dir / "sk-live-policy.json"
    write_policy(ctx.config, target, policy)
    return {
        "k4": k4,
        "h3": h3,
        "memory": memory,
        "mcp": mcp_module,
        "exp": exp,
        "policy": policy,
        "control": control_transport(target, transition=transition),
        "live": live_transport(target),
    }


def configure_runner(ctx: RunContext, name: str, *, transition: bool = False) -> tuple[Any, dict[str, Any]]:
    configured = configure(ctx, transition=transition)
    target: Target = ctx.target  # type: ignore[assignment]
    runner = _module(name)
    runner.HERE = ctx.run_dir
    runner.RUN_ROOT = ctx.run_dir / name.removeprefix("run_")
    runner.VM_NAME = target.vm_name
    runner.VM_ID = target.vm_id
    runner.PROFILE = target.profile
    runner.IMAGE = target.secure_kernel_image
    runner.PYTHON = sys.executable
    runner.CONTROL_TRANSPORT = configured["control"]
    runner.LIVE_TRANSPORT = configured["live"]
    runner.DISCOVERY_CACHE = ctx.config.paths.state_root / target.name / "discovery-cache.json"
    if hasattr(runner, "SPIN_HOST"):
        runner.SPIN_HOST = target.guest_spin_host
    return runner, configured


@contextmanager
def runner_environment(ctx: RunContext, policy: Path) -> Iterator[None]:
    values = {
        "WINDBG_MCP_SK_LIVE_POLICY": str(policy),
        "WINDBG_MCP_TRANSCRIPT": str(ctx.run_dir / "mcp.jsonl"),
        "WINDBG_MCP_TRANSCRIPT_MAX_FIELD": "0",
        "SKLAB_GUEST_CREDENTIAL_FILE": (
            str(ctx.target.guest_credential_file)
            if ctx.target is not None and ctx.target.guest_credential_file is not None
            else None
        ),
    }
    with temporary_environment(values):
        yield


def invoke_main(module: Any, arguments: list[str]) -> int:
    before = sys.argv
    sys.argv = [str(getattr(module, "__file__", module.__name__)), *arguments]
    try:
        result = module.main()
        return int(result or 0)
    except SystemExit as error:
        return int(error.code or 0)
    finally:
        sys.argv = before


def discover(ctx: RunContext) -> tuple[int, int, int, int, str]:
    runner, _ = configure_runner(ctx, "run_k3_sk_live")
    pid = runner.k4.vmwp_pid()
    vnd, handle, partition, how = runner.discovery(pid)
    return pid, vnd, handle, partition, how

