from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
from typing import Any, Iterator

from .context import RunContext
from .errors import ExecutionFailure
from .policy import control_transport, live_transport, write_policy
from .util import temporary_environment


def configure(ctx: RunContext) -> dict[str, Any]:
    """Generate the client-side policy without importing a privileged provider."""
    if ctx.target is None:
        raise ExecutionFailure("the live workflow requires a configured target")
    policy = ctx.run_dir / "sk-live-policy.json"
    write_policy(ctx.config, ctx.target, policy)
    return {
        "policy": policy,
        "control": control_transport(ctx.target),
        "live": live_transport(ctx.target),
    }


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


def discover(ctx: RunContext) -> tuple[int, int, int, int, str]:
    """Ask windbg-mcp's isolated discovery role for this boot's private coordinates."""
    target = ctx.target
    if target is None:
        raise ExecutionFailure("identity discovery requires a configured target")
    command = [
        str(ctx.config.paths.windbg_mcp_exe),
        "--sk-discover-identity",
        "--profile",
        str(target.profile),
        "--vm-id",
        target.vm_id,
    ]
    completed = subprocess.run(
        command,
        cwd=ctx.config.paths.windbg_mcp_repo,
        text=True,
        capture_output=True,
        timeout=120,
    )
    if completed.returncode:
        raise ExecutionFailure(completed.stderr.strip() or completed.stdout.strip())
    try:
        value = json.loads(completed.stdout)
        pid = int(value["vmwp_pid"])
        vnd = int(str(value["dispatcher_vnd"]), 0)
        handle = int(str(value["partition_handle"]), 0)
        partition = int(str(value["partition_id"]), 0)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise ExecutionFailure(
            f"windbg-mcp identity discovery returned invalid JSON: {completed.stdout!r}"
        ) from error
    return pid, vnd, handle, partition, "windbg-mcp --sk-discover-identity"
