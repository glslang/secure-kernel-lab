# Consolidation and provenance

The original bench lived under `windbg-mcp/target/private`, mixing current entry points, exploratory
probes, review helpers, generated evidence, caches, binaries, and virtual disks. This repository
turns the current entry points into modules and keeps one explicit archive, of the providers the
h3probe migration retired.

## Current paths

- `run_k3_sk_live.py` is the current ambient workflow. It supersedes
  `run_k3_hvci_trigger.py`; no guest trigger is required because the selected Secure Kernel paths
  execute ambiently.
- `run_k3_sk_syscall.py`, with `run_vtl1_user_to_securekernel.py`, is the current VTL1 user transition
  workflow.
- `open_sk_debugger` through `kd.debugger` is the ordinary M8 product path. Managed `open_sk_kd`
  remains current for `kd.external` and `kd.manual`; standalone/wire KD experiments are historical.
- `k4_control_provider.py`, `h3_vtl1_debug_control.py`, `guest_physical.py`, and
  `gpa_server.py` are the provider layer, and h3probe is the only driver beneath it. The memory
  provider reads through h3probe's exact-build VID memory operation inside vmwp; its hypercall mode
  is the refusing negative control.
- `validate.memory-write` supersedes the private one-off raw-write proof and keeps its decisive
  write/read/restore/page-hash/health gate as an ignored per-run artifact.
- The transition preparation and managed-KD post-release audit use the same h3probe identity and
  memory operation as the normal live reader.
- The hvmm and hvlib providers these replaced (`sklab.hvmm`, `hvmm_gpa.py`, `hvmm_gpa_server.py`,
  `s5w_gpa_server_pinned_vtl.py`) and the hvmm differential that qualified the replacement are kept
  for provenance in `legacy/h3probe-migration/`; nothing imports them.
- The advanced catalog retains the current VTL split, acceptance, mismatch, provider-death,
  debugger-loss, and identity-change checks.
- The private M8 boot probe, counted enclave trigger, post-release audit, debugger command sender,
  managed composite config, and external qualification config are superseded by `sklab.m8`,
  `sklab.m8_helper`, `scripts/m8_debugger_control.ps1`, and `validate.m8`. The generated JSON and
  evidence remain per-run files; no credential, symbol cache, debugger package path, or boot-scoped
  identity is committed.

These files are vendored under `src/sklab/bench/` and configured by `bench_bridge.py`. Normal users
select modules; they do not invoke the vendored files directly.

- `h3probe.c` and its `build.cmd` never lived in `target/private`: they are in the separate
  `exdi-rig` bench, which every provider above depends on through `\\.\H3Probe`. They are vendored
  under `drivers/h3probe/` so the lab carries the one piece of its stack that could not be rebuilt
  from this repository. Its README records the source commit and hash. The gate's own measurement
  (H3: VTL0 and VTL1 `CR3` per child) is the `live.registers` module.

## Historical material

The rest of the old private directory is not part of this repository. Every current path above was
promoted from it; its remaining probes, runners, plans, review helpers and JSON inputs were
superseded by those paths or abandoned, and nothing here reads them. `legacy/h3probe-migration/` is
the one archive kept, because [`h3probe-only-plan.md`](h3probe-only-plan.md) cites it as the
evidence for the provider switch; it is provenance, not a runtime dependency. See
`legacy/README.md` for the archive rules.

Generated JSON results, transcripts, dumps, videos, package caches, build output, executable/DLL/SYS
files, VMRS/BIN captures, and VHDs were deliberately not migrated. They were bulky evidence rather
than source; retaining them would obscure the supported surface and risk committing machine-local
or sensitive state. Current runs generate fresh evidence under ignored `runs/` directories.

Exact vmwp dispatcher profiles and the reusable `sklab profile vmwp` generator are current source
and belong here. `scripts/reprofile_vmwp.py` remains as a compatibility validator for recorded
runbooks. Per-machine candidates and reports, duplicate-handle page comparisons, live decode
transcripts, and control-gate results remain generated evidence and are not committed.

## Provider consolidation

LiveCloudKd's `hvmm.sys` was the last external runtime dependency: it supplied the direct
protected-GPA reads and bounded writes that h3probe's root hypercall route cannot. It was replaced
by an in-vmwp VID memory operation in h3probe, measured read-only against hvmm before anything moved
and then switched consumer by consumer; configuration and driver lifecycle now name h3probe alone.
The hypercall route stays as the refusal and backing oracle. Its final acceptance passed on
2026-10-29 with the hvmm service uninstalled; the phases, their gates and the runs that passed them
are in [`h3probe-only-plan.md`](h3probe-only-plan.md).
