# Secure Kernel Lab

`secure-kernel-lab` is the operator-facing console for the Secure Kernel research built around
`windbg-mcp`. It replaces a directory of one-off probes with a small catalog of named workflows.

The application does not embed DbgEng. Debugger ownership remains in the process roles implemented
by `windbg-mcp`; this repository orchestrates its CLI/MCP surfaces and the lab-specific transport
providers.

For a new bench, follow [`docs/m8-runbook.md`](docs/m8-runbook.md). It covers the exact VM shape,
images and symbols, vmwp profile lifecycle, the host driver, complete configuration, product
examples, qualification and recovery. How sklab came to need only its own driver, and the evidence
for each step, is [`docs/h3probe-only-plan.md`](docs/h3probe-only-plan.md).

## Setup

Requirements are Windows, Python 3.13, `uv`, an elevated terminal for live workflows, a built
`windbg-mcp.exe`, the Windows debugger kit, and the `h3probe` driver, whose source and build are in
[`drivers/h3probe/`](drivers/h3probe/README.md). It is the only privileged component: VTL0/VTL1
registers, guest-physical reads and the guarded write, and the refusing hypercall all go through
its device, and nothing loads hvlib. Start from a disposable VM whose exact identity and image
hashes are pinned in the configuration.

Guest-physical memory is read inside the target's own `vmwp`: h3probe attaches to it, proves the
VID partition handle there is the partition's owner's, checks the partition ID, and sends VID the
page request `vid.dll` itself sends. A page with no RAM behind it is answered `not-present` by type
rather than as a page of zeros, so no RAM map is needed to tell the two apart.

Check out [`windbg-mcp`](https://github.com/glslang/windbg-mcp) beside this repository: the example
configuration's relative paths assume that layout, and they resolve against the configuration
file's directory. From this repository's root:

```powershell
Copy-Item config.example.toml config.local.toml
# Edit config.local.toml, then provision artifacts named by artifact-manifest.toml.
# Build and install h3probe once (drivers/h3probe/README.md), then pin it under [drivers].
uv sync
uv run sklab driver start
uv run sklab doctor
```

`h3probe` is a demand-start service left stopped between runs. `doctor` reports it as an error when
the selected module uses it, including when the loaded image does not serve the versioned memory
operation the readers need. `sklab driver start` and `sklab driver stop` load and unload it.

Live module checks also require the configured VM to be running. An off target is reported as a
`Hyper-V target state` error with the exact `Start-VM` command before target control begins.

The disposable VM's differencing child grows as Windows writes blocks; shutting the VM down does
not shrink it. Configure its immutable, read-only base as `targets.<name>.parent_disk`, then use
`sklab vm status` to inspect the attached child's physical size and `sklab vm reset` to rotate it.
Reset requires the allowlisted VM to be off, refuses shared or checkpoint-referenced children,
boots the replacement through 60 seconds of healthy heartbeat, returns the VM to off, and only then
permanently deletes the superseded child. A failed validation restores the old attachment and
removes the uncommitted child. This is periodic maintenance after write-heavy runs, not a per-boot
requirement.

The machine-local `config.local.toml`, `credentials/`, `artifacts/`, `.state/`, and `runs/` are
ignored.

Guest workflows read an ignored JSON file named by `guest_credential_file` with `username` and
`password` fields. Restrict its ACL to the operator account. Credentials are read by the local
PowerShell process and are not written to policies, manifests, transcripts, or command lines.
The M8 paths also require `symbol_path` for the matching `securekernel.pdb`, classic WinDbg, and
the package UI executable (`DbgX.Shell.exe` currently; older packages used `WinDbgX.exe`) inside
the installed Microsoft.WinDbg package. Do not configure the
WindowsApps execution alias: that process can exit while the debugger UI is still running.
The exact one-VP K3 configuration and guest enclave trigger are shown in
[`docs/m8-runbook.md`](docs/m8-runbook.md); do not infer them from the placeholder values in
`config.example.toml`.

## Interactive use

Run `uv run sklab` to open the console. It opens with a banner showing the target and both
drivers' state (`--no-banner` skips it, `banner` shows it again, `NO_COLOR` or `--no-color` turns
color off):

```text
sklab (main) > driver start
sklab (main) > vm status
sklab (main) > vm reset
sklab (main) > modules
sklab (main) > use kd.debugger
sklab (kd.debugger) > check
sklab (kd.debugger) > run
```

`kd.debugger` is the ordinary M8 product path. It opens one composite session, consumes the initial
redirected stop, loads Secure Kernel symbols, arms `securekernel!IumInvokeSecureService`, starts a
guest enclave call, and uses the generic debugger tools for modules, registers, stack, disassembly,
single-step, `g`, and an asynchronous break-in. `set free_run_cycles 25` selects the repeated M8
gate. The run ends the public composite handle and performs the same restoration audit.

`kd.external` launches either Classic WinDbg or WinDbgX through windbg-mcp's `tools/launch_sk_kd.ps1`, waits for
that debugger process, then releases and audits the managed session. It supports ordinary `g`, up
to four hardware execute breakpoints, guarded INT3 breakpoints when `allow_memory_writes=true`,
single-step, and running Ctrl+Break. `kd.manual` remains the split-terminal form: it prints the
typed connection only after the pipe is ready and monitors the session while the operator attaches.
Use `jobs`, `sessions`, and `stop <job>` to monitor or cancel a background run.

## Command-line use

Every module is also scriptable:

```powershell
uv run sklab modules
uv run sklab show live.ambient
uv run sklab --target k3 check live.ambient
uv run sklab --target k3 run live.ambient --set steps=8 --yes
uv run sklab --target k3 run kd.debugger --set free_run_cycles=25 --yes
uv run sklab --target k3 run kd.external --set frontend=windbgx --yes
uv run sklab --target k3 run validate.m8 --set scope=external-preflight --yes
uv run sklab --target k3 run validate.m8 --set scope=external-breakpoints --yes
uv run sklab --target k3 vm status
uv run sklab --target k3 vm reset --yes
```

Exit codes are `0` success, `1` execution failure, `2` configuration/prerequisite failure, `3`
recovery required, and `130` cancellation. Each run has an atomic `runs/<id>/manifest.json`, logs,
policy, and transcripts sufficient to identify the app, binary, target, and options used.

## Module catalog

The eight normal demo/test paths are:

- `capture.inspect`: decode a VMRS, BIN/VSV pair, or named VM snapshot.
- `live.decode`: read-only live VTL1 decode through the direct or refusing-hypercall provider. In
  the default direct path, discovery (`windbg-mcp --sk-discover-identity`, the discovery a
  live-control session runs) captures vmwp's PID, VID partition handle, and partition ID.
  The transport (`src/sklab/bench/gpa_server.py`) obtains the VTL1 CR3 and IDTR from `h3probe`,
  finds the Secure Kernel base below the IDT vector-0 handler, and serves pages through h3probe's
  memory operation inside vmwp. The discovery attach is cached only for the lifetime of that vmwp
  PID. `set mode hypercall` reads through `HvCallReadGpa` instead, which refuses VTL1 and is the
  negative control.
- `live.registers`: gate H3 — every child partition's VTL0 and VTL1 `CR3` and VSM status, read
  through `h3probe`, with the VTL0 read as the control; `set snapshot true` also discovers the
  target, reads its VTL1 register snapshot and IDTR for each configured VP, finds the Secure Kernel's
  base as the first PE header below the handler of IDT vector 0, and walks each VP's CR3 to that base
  to check the pinned `securekernel.exe` is mapped there. A pass
  means the root carries the Secure Kernel's mappings, not that it is the Secure Kernel's own root:
  a trustlet's kernel-mode root maps it too. So the check then names the owner from the Secure
  Kernel's own records — its system root, and each secure process's root, PID, trustlet ID and image
  path from `SkpsProcessList` — and reports a root no listed process holds as `unlisted`, or as
  `unknown` when the list could not be read to its end. That list holds trustlets only: a VBS
  enclave is an object of its own with its own root, on no list. So each VP is also asked what it
  has loaded, from the Secure Kernel's per-VP record, and a sample the list does not hold is named
  from that when the two roots agree — as an `enclave`, confirmed against the container process it
  records, with the VTL0 process it belongs to, by PID and image name read through the partition's
  VTL0 root. Those EPROCESS offsets are checked on each run against the trustlets' own PIDs, and a
  disagreement is reported. A root whose own page tables cannot be read is `root-unreadable`, which
  says nothing about what it maps. Pages come from h3probe's memory operation (`src/sklab/h3_memory.py`)
  through the VID handle discovered in vmwp, used inside vmwp, so there is no read bound of the kind
  hvlib once imposed above 4 GiB, and a page with no RAM behind it is refused by type rather than
  read as zeros. The run records how many reads were made and what each answered. The
  offsets are per build (`src/sklab/sk_processes.py`); a build with no entry is not identified.
- `live.ambient`: current ambient Secure Kernel stop/step/resume workflow; its worker transport
  reads through h3probe's memory operation.
- `live.transition`: current trustlet-to-Secure-Kernel transition workflow. Both its identity
  preparation and live-memory transport read through h3probe's memory operation.
- `kd.manual`: managed Secure Kernel KD setup for a manual WinDbg client. Its post-release audit
  rediscovers VTL1 identity and reads the guarded image through `h3probe`.
- `kd.external`: the supported Classic WinDbg/WinDbgX launcher, including ordered MCP teardown and
  post-release audit. Set `allow_memory_writes=true` only when guarded INT3 breakpoints are needed.
- `kd.debugger`: the server-owned composite session used to close M8. Every debugger action after
  open is an ordinary generic MCP tool; the guest enclave trigger is started only after `g` reports
  running.

Advanced modules expose VTL separation validation, the exact opt-in Rust acceptance tests, the
`validate.memory-write` write/read/restore proof (called `validate.hvmm-write` before the migration),
`validate.h3-memory` for the memory operation itself, the standalone `validate.kd-post-audit`
replacement gate, and the build-mismatch/provider-death/debugger-loss/identity-change fault cases.
`validate.m8` generates all machine-local inputs from this configuration. `scope=composite` runs
the exact 25-break-in product gate; `external-preflight` checks one healthy static boot and every
callback; `external-breakpoints` runs Classic and WinDbgX through 100 hardware and 100 guarded-INT3
hits each. `external-full` retains the old GUI Ctrl+Break/reset race rig for explicit research use
only and requires `include_non_gating_gui_controls=true`; it is not part of the M8 product exit.
The write
proof owns a full disposable-VM boot: it changes one reserved PE-header byte, verifies that it is the
page's only delta, restores and hashes the complete page, checks guest health, then powers the VM and
the driver down. `validate.h3-memory` reads the corpus pages, controls and a seeded RAM sample through
the memory operation, checks each page the hypervisor accepts against `HvCallReadGpa`'s own bytes and
the Secure Kernel's header against the pinned image, and proves the driver's refusals, scratch
hygiene, unload and stale-identity handling. Fault modules are for a disposable target and can deliberately retain recovery
ownership. Read `docs/demo-runbook.md` before using them.

See `docs/architecture.md` for process boundaries and `docs/migration.md` for the current-versus-
historical map.

## Exact vmwp profiles

Profiles under `profiles/` are source-controlled exact-build inputs. Windows servicing can move
the handler-registration, unregister, and callback functions even when the guarded dispatcher
sites remain byte-identical. Validate a replacement against the previous image before selecting it:

```powershell
uv run sklab profile vmwp `
  --baseline profiles\vmwp-dispatcher-profile-26100.9457.json `
  --old-image C:\path\to\previous\vmwp.exe `
  --new-image C:\Windows\System32\vmwp.exe `
  --output .state\profiles\vmwp-candidate.json
```

The command needs no lab configuration for its offline phase. It identifies the new vmwp and VID
images, checks the baseline image, maps guarded sites without guessing, requires unique function
prefixes, verifies the callback resume sequence, and preserves the descriptor and Secure Kernel KD
layouts. It writes a candidate and a sibling detailed report, refuses to overwrite either, and does
not edit `config.local.toml` or activate the candidate.

Add `--live-validate --yes` to exercise that candidate through `live.ambient` on the configured
disposable target. The command selects the candidate only in memory and writes a separate
`*.live.json` result; the configured profile is unchanged. Review the offline and live evidence
before copying a candidate into `profiles/`. `scripts/reprofile_vmwp.py` remains as a compatibility
validator for an already-created candidate.

## License

MIT; see [`LICENSE`](LICENSE).
