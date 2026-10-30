# Architecture

The application has three layers:

1. `sklab.cli` and `sklab.console` provide the same module catalog to automation and an operator.
2. Module adapters perform checks, create an immutable run directory, generate a least-authority
   `windbg-mcp` policy, and invoke a current workflow.
3. `windbg-mcp` and the copied transport providers own target interaction. The Python app never
   constructs a `DebugEngine` and never bypasses the server's worker/session boundaries.

The providers under `src/sklab/bench/` are the smallest current set needed by the catalog. They are
copied from the proven private bench rather than rewritten during consolidation, so their measured
behavior remains reviewable. `bench_bridge.py` injects configuration and run paths into those
adapters. Nothing imports from `legacy/`, which keeps only the providers the h3probe migration
retired.

Under the providers sits the one host kernel driver, whose source the lab carries:
`drivers/h3probe/`, the root-partition probe built for gate H3. The control providers, every
guest-physical read and guarded write, and the hypercall decoder reach the hypervisor and the
partition only through its device, so it is a prerequisite rather than an implementation detail:
`doctor` checks that the service is installed, that it loads the image pinned under `[drivers]`,
that it is running, that `\\.\H3Probe` opens, and, where a module reads memory, that the loaded
image serves the versioned memory operation (`h3_memory`). `sklab.drivers` talks
to the service control manager directly for that and for `driver start`/`stop`, so a status read
costs no PowerShell process.

Every module has a risk label. Read-only modules may still require elevated driver access, but do
not request target control. Target-control and fault modules require `disposable = true`, an exact
VM id/name match, pinned profiles and hashes, and explicit confirmation (or `--yes` for automation).
Generated policies allow only that VM id, exact provider command templates, approved profile/kit
roots, and a bounded pause.

The live-memory boundary loads no hvlib and opens no driver but h3probe. Discovery is
`windbg-mcp --sk-discover-identity`, the same discovery a live-control session runs on its own
engine thread, and it captures vmwp's PID and its process-local VID partition handle. `windbg-mcp` expands `{vmwp_pid}` and
`{partition_handle}` only when it launches the live-memory child (`gpa_server.py`), and that child
hands both, with the partition ID, to h3probe's memory operation (`sklab.h3_memory`). The driver
attaches to that vmwp, references the handle there, requires the partition object's recorded owner
to be that process, asks VID for the handle's partition ID and requires the caller's, and only then
reads: it asks VID which range holds the page, finds the memory block's handle in the partition's
own table, and sends the page request `vid.dll!VidReadMemoryBlockPageRange` sends, through vmwp's
handle and from inside vmwp, which is the identity VID's IOCTL gate checks. Nothing is duplicated
and nothing is retained; three scratch pages in vmwp are freed before each call returns.
`h3probe` also supplies the VTL1 CR3 and IDTR, and the provider locates the Secure Kernel image from
the IDT before serving GPA reads. The PID, handle, and partition ID are treated as one boot-scoped
identity and are rediscovered when vmwp changes; a stale one is answered `identity`, never served.
This requires the worker placeholder support merged in `windbg-mcp` PR #502.

The answers are typed: `ok`, `not-present` (no GPA range holds the page), `refused` (a range does,
but not as memory-block RAM), `error`, and `identity` (build, process, handle, owner or partition
did not match), so a page of zeros that is RAM is never confused with no page. h3probe's
`HvCallReadGpa` route is kept beside it as an independent oracle and as the decoder's refusing
mode: it refuses protected VTL1 pages, which is what makes the memory operation's reading of them a
test. How the primitive was found and measured against LiveCloudKd's hvmm, and the gates that
qualify it, are in [`h3probe-only-plan.md`](h3probe-only-plan.md).

The same operation backs the lab's bounded write. VID moves whole pages, so h3probe applies a write
as read, patch, write and full-page read-back, and answers `ok` only when the page read back is the
patched page; a guest store to the same page between the read and the write would be lost, so
writers hold the VM paused. The `validate.memory-write` gate holds the VM paused, changes one
reserved byte in the pinned Secure Kernel image, verifies the only page delta, restores and hashes
the original page, and resumes only after restoration is proved. If restoration cannot be proved,
the disposable target is forced off without resuming. The live transport advertises the write
(`--writes`); windbg-mcp makes one only under a policy that sets `allow_memory_writes`.

The lab owns the exact vmwp build knowledge in `profiles/`; `windbg-mcp` owns only the generic
profile schema, guarded worker behavior, and placeholder expansion. `sklab profile vmwp` derives a
write-once candidate from a serviced image and a previously proven image. Its offline phase loads
no lab configuration. Optional live validation replaces the selected target's profile only in the
in-memory configuration passed to `live.ambient`; it changes neither the TOML configuration nor the
committed catalog. Generated candidates and evidence belong in ignored `.state/` or `runs/`, not in
either source tree.

`live.transition` and every KD post-release audit discover CR3, IDTR, image base, and guarded
text through `h3probe` alone: its registers and its memory operation.
`kd.manual` uses the managed `open_sk_kd` MCP path. The server generates the named pipe and owns the
guarded stop. The console merely prints the typed client connection and monitors the session.
`kd.external` wraps the source-controlled `windbg-mcp` launcher so Classic WinDbg and WinDbgX have
the same ordered open, process-lifetime, end-session, and cleanup contract. `kd.debugger` uses
`open_sk_debugger`: its second worker attaches DbgEng to the facade pipe and exposes the ordinary
debugger tools under one public composite handle. A stop request
routes through `end_session`; the app does not kill a worker when ownership is unresolved.

The M8 qualification callbacks are current sklab code rather than dependencies on
`windbg-mcp/target/private`. `sklab.m8_helper` reports the boot identity, invokes the allowlisted
guest enclave workload using the ignored credential file, and runs the 60-second release audit.
`scripts/m8_debugger_control.ps1` authenticates the facade-accepted debugger PID before delivering
the WinDbgX command program. The same helper retains the optional GUI break/reset controls, but
those non-gating race experiments are not part of the product exit. `validate.m8` writes the two
least-authority policies and exact Rust-harness JSON beneath its immutable run directory.

[`m8-runbook.md`](m8-runbook.md) is the operator-facing assembly of these boundaries: it specifies
the one-VP non-nested K3 shape, guest VBS/enclave workload, image/PDB/profile setup, current driver
installation, complete local configuration, product examples, exact qualification, evidence and
recovery.

Run manifests and transcripts redact credential/key-shaped fields. Binary images, dumps, disks,
symbols, caches, credentials, and run evidence stay outside Git and are verified against
`artifact-manifest.toml` where applicable.
