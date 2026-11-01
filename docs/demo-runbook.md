# Live demo runbook

This page is the short demonstration order. Use [`m8-runbook.md`](m8-runbook.md) to build or
replicate the VM, driver, image, symbol, profile and configuration setup first.

## Before the session

1. Use an elevated PowerShell terminal and confirm the configured VM is the disposable demo target.
2. Build the matching `windbg-mcp` debug or release binary and update `config.local.toml` if needed.
3. Boot the guest, verify the expected workload/assets, and keep the VM console visible.
4. Run `uv run sklab doctor`; resolve every error before target mutation.
5. Run `uv run sklab --target k3 check live.ambient` and `check kd.debugger`.
6. Close unrelated debugger/MCP instances. Keep the generated `runs/` directory for talk evidence.

## Suggested talk sequence

Start the console with `uv run sklab --target k3`. Use `modules` to establish the surface, then:

1. `use live.decode`, `check`, `run` to establish the pinned VTL1 image without mutation.
2. `use live.ambient`, `set steps 8`, `check`, `run` for the ambient stop/step/resume path.
3. `use live.decode`, `set mode hypercall`, `check`, `run` for the refusing negative control.
4. `use kd.debugger`, `check`, `run`. Show the run's generic-tool results for symbols, modules, the
   natural breakpoint, registers, stack, disassembly, step, `g`, and asynchronous break-in.
5. For an interactive client, `use kd.external`, choose `frontend=classic` or `windbgx`, and `run`.
   Demonstrate `.reload`, `lm m securekernel`, `x securekernel!*`, `r`, `k`, `u`, `t`, `bp`, `g`,
   and Ctrl+Break while running. Up to four hardware breakpoints and guarded INT3 are live-qualified;
   set `allow_memory_writes=true` only for the INT3 path. NT process/thread extensions such as
   `!process` remain outside the Secure Kernel facade.
6. Quit or detach WinDbg. The launcher ends the session and sklab records the restoration audit.

`kd.manual` remains available when a split-terminal demonstration is useful. It prints the exact
typed connection only after readiness; it no longer carries the old claims that `g` or running
Ctrl+Break are unavailable.

## Failure and recovery

- `stop <job>` requests managed teardown. Wait for the job to leave `running` before exiting.
- Exit code/result `3` means recovery ownership is unresolved. Do not rerun or power-cycle merely to
  hide the state; preserve the run directory and follow the matching `windbg-mcp` recovery record.
- If the target identity no longer matches, stop. The tool will not redirect recovery to another
  `vmwp` instance.
- Fault modules are not talk warm-ups. They intentionally exercise containment and may leave a VM
  requiring explicit recovery or recreation.

After each successful target-control run, inspect its `manifest.json` and retain the directory as
the evidence bundle. Secrets and bulky binary artifacts are not copied into it.
