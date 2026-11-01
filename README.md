# Secure Kernel Lab

`secure-kernel-lab` is the operator-facing console for the Secure Kernel workflows built around
[`windbg-mcp`](https://github.com/glslang/windbg-mcp). It provisions and resets the disposable VM,
starts and stops the operator-installed driver service, runs guest triggers, generates policies,
drives MCP/CLI entry points, and records evidence.

It does not embed DbgEng and does not open a driver device. `windbg-mcp` owns debugger sessions,
the typed h3probe ABI, the built-in control and memory providers, and the driver qualification.
Those privileged roles remain isolated child processes, so a wedged provider cannot pin the MCP
supervisor or another session.

For a new bench, follow [`docs/m8-runbook.md`](docs/m8-runbook.md). Historical derivation and
measurements remain in [`docs/h3probe-only-plan.md`](docs/h3probe-only-plan.md).

## Setup

Requirements are Windows, Python 3.13, `uv`, an elevated terminal for live workflows, a built
`windbg-mcp.exe`, the Windows debugger kit, and the h3probe service. Build the driver from
`windbg-mcp/drivers/h3probe`; no driver binary is distributed, and neither repository installs or
starts it automatically.

Check out `windbg-mcp` beside this repository, then:

```powershell
Copy-Item config.example.toml config.local.toml
# Edit machine-local paths, target identity, hashes, symbols, and credentials.
uv sync
uv run sklab driver start
uv run sklab doctor
```

`sklab doctor` checks the service image and hash, then asks the repository-owned provider to prove
its target identity, epoch, and capabilities. Sklab never opens `h3probe` itself. The service is
demand-start and may be left stopped between runs.

The disposable VM's differencing child grows with writes. Configure its immutable read-only base
as `targets.<name>.parent_disk`; `sklab vm status` reports the attached child and `sklab vm reset`
performs the guarded rotation and rollback workflow. Machine-local configuration, credentials,
artifacts, state, runs, dumps, disks, symbols, and driver binaries are ignored.

Guest workflows read an ignored credential JSON named by `guest_credential_file`, containing
`username` and `password`. Restrict its ACL to the operator account. M8 also requires the matching
Secure Kernel symbol store, Classic WinDbg, and the installed WinDbgX package executable—not its
WindowsApps execution alias.

## Use

Run `uv run sklab` for the console, or invoke a module directly:

```powershell
uv run sklab modules
uv run sklab --target k3 check live.ambient
uv run sklab --target k3 run live.ambient --yes
uv run sklab --target k3 run kd.debugger --set free_run_cycles=25 --yes
uv run sklab --target k3 run kd.external --set frontend=windbgx --yes
uv run sklab --target k3 run validate.m8 --set scope=external-breakpoints --yes
uv run sklab --target k3 vm status
```

Every run gets an atomic `runs/<id>/manifest.json`, logs, generated policy, and transcripts.
Exit codes are `0` success, `1` execution failure, `2` prerequisite failure, `3` recovery required,
and `130` cancellation.

## Module catalog

- `capture.inspect`: decode a VMRS, BIN/VSV pair, or named VM snapshot.
- `live.decode`: discover this boot, then decode live VTL1 memory through
  `builtin:h3probe`; `mode=hypercall` selects the refusing `HvCallReadGpa` negative control.
- `live.ambient`: discover the target and query the built-in provider's typed `SHAPE`, generate the
  boot-scoped private input, then run windbg-mcp's exact live stop/step/inspect/resume/close tier.
- `kd.manual`: expose the managed Secure Kernel KD pipe to a manually launched WinDbg client.
- `kd.external`: launch Classic WinDbg or WinDbgX through the managed facade and audit release.
- `kd.debugger`: drive the composite M8 session through ordinary debugger tools and audit release.
- `validate.kd-post-audit`: run the independent identity, health, register-restoration, flags, and
  guarded-text audit through windbg-mcp's bounded audit role.
- `validate.live`: run a prepared opt-in Rust acceptance input. `validate.kd` generates its
  natural-stop input from the selected target, Windows Kit and symbol-store configuration.
- `validate.m8`: generate current machine-local inputs and run the composite or external M8 tiers.

The old out-of-session register/transition experiments were retired instead of granting sklab a
second privileged authority. Driver memory/write/refusal, concurrency, killed-reader, service
restart, stale-identity, VID range-map, and restoration qualification moved beside the driver in
`windbg-mcp`.

Generated policies admit `builtin:h3probe` in `builtin_transports` and contain no Python
interpreter command. Custom transports remain a windbg-mcp feature, but sklab's supported path uses
the image currently running the MCP worker so provider and server builds cannot drift.

## Exact vmwp profiles

Profiles under `profiles/` are source-controlled exact-build inputs. Derive a write-once candidate
from the previously proven and serviced images:

```powershell
uv run sklab profile vmwp `
  --baseline profiles\vmwp-dispatcher-profile-26100.9457.json `
  --old-image C:\path\to\previous\vmwp.exe `
  --new-image C:\Windows\System32\vmwp.exe `
  --output .state\profiles\vmwp-candidate.json
```

Add `--live-validate --yes` to exercise the candidate through the repository-owned `live.ambient`
tier using an in-memory target selection. The command does not edit `config.local.toml`; review the
offline and live evidence before promoting a profile.

## License

MIT; see [`LICENSE`](LICENSE).
