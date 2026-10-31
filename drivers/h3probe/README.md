# h3probe

`h3probe.sys` is the root-partition kernel probe built for gate H3 (may the root partition read a
child partition's VTL1 registers?) and is now sklab's only driver. Every provider under
`src/sklab/bench/` opens its device, `\\.\H3Probe`: for VTL0/VTL1 registers, for guest-physical
memory through its VID memory operation, and for the decoder's refusing `hypercall` mode. Without it
loaded, every target-control module fails at its first register read, so `sklab doctor` and each
module's `check` verify it before anything else runs, and check that the loaded image serves the
memory operation's ABI version where a module reads memory.

The memory operation replaced LiveCloudKd's `hvmm.sys`. How its primitive was found in `Vid.sys`
and measured against hvmm, and the gates that qualify it, are in
[`docs/h3probe-only-plan.md`](../../docs/h3probe-only-plan.md); the derivation is the comment above
`IOCTL_H3_VIDTRANSLATE` in `h3probe.c`.

## Provenance

`h3probe.c` was vendored byte-identical from `exdi-rig/h3probe/h3probe.c` as committed in that
repository's `1f962cd` (SHA-256 of the CRLF working copy:
`9EDCFDCBF679EB28C4C655B12351A0727FB701F10CC9346AA5C3EEE56E2D8A03`), and has since grown the VID
memory probes and operation here; this copy is the source of truth for them. The `.pre-*` snapshots
that record what each earlier gate was built against stay in `exdi-rig`; they are history, not
source.

`build.cmd` is that repository's build script with four changes: it builds beside itself whatever
the current directory, `VSROOT` and `KV` override the Build Tools root and WDK version, an optional
certificate thumbprint test-signs the result, and it links `wdmsec.lib` for `IoCreateDeviceSecure`.

## Who can open it

Only SYSTEM and Administrators. Every control code is `FILE_ANY_ACCESS`, so the device's descriptor
is the only check on who reaches them. The device is created with `SDDL_DEVOBJ_SYS_ALL_ADM_ALL` and
`FILE_DEVICE_SECURE_OPEN`, so the descriptor also covers an open of a path under the device. Every
legitimate caller is an elevated administrator already, as any debugger is.

Before 2026-10-31 it was created with `IoCreateDevice` and no descriptor. Measured that day, the
default descriptor granted Everyone read and write. A medium-integrity token with Administrators
disabled, which is what an unelevated process runs with, opened `\\.\H3Probe` and reached the
dispatch routine. Tightening the descriptor at runtime refused that token at `\\.\H3Probe` but not
at `\\.\H3Probe\x`. The rebuilt image refuses it at both and still admits an elevated caller.

## What the lab calls

| IOCTL | Function | Used by |
|---|---|---|
| `0x800` `IOCTL_H3_RUN` | the H3 gate: enumerate children, read VTL0 and VTL1 `CR3` and both VSM status registers | `live.registers`, `Probe.children()` |
| `0x801` `IOCTL_H3_READGPA` | `HvCallReadGpa` for one guest-physical range | `live.decode` with `mode=hypercall` |
| `0x804` `IOCTL_H3_CALL` | one bounded `HvCallGetVpRegisters` / `HvCallSetVpRegisters` | the control providers |
| `0x810` `IOCTL_H3_VIDTRANSLATE` | measurement probe: which VID range holds one guest page | `validate.h3-memory`'s range map (`sklab.h3_memory_probe`) |
| `0x811` `IOCTL_H3_VIDREADPROBE` | measurement probe: one page, with every intermediate VID answer | the Phase 1 measurement, now archived |
| `0x812` `IOCTL_H3_MEMREAD` | the memory operation: one in-page byte range, typed answer | `sklab.h3_memory.Reader`, every live reader |
| `0x813` `IOCTL_H3_MEMWRITE` | the memory operation: one in-page write, applied read-patch-write and read back | `sklab.h3_memory.Writer`, `validate.memory-write`, guarded INT3 |

The memory operation's request is `{Version, OwnerPid, PartitionHandle, PartitionId, Gpa, Length,
Reserved}` (40 bytes) and its answer `{Version, Result, Stage, Status, Length, Reserved, Gpn}` (32
bytes), followed for a read by the page's bytes; `C_ASSERT`s pin both. `Result` is `ok`,
`not-present`, `refused`, `error` or `identity`, and `Stage` names the step that decided it. The
caller supplies no pointer: the driver checks the exact `Vid.sys` build, attaches to the named vmwp,
refuses a kernel-handle value, requires the handle's partition to record that process as its owner
and to carry the caller's partition ID, and detaches and dereferences on every path.

The driver defines further control codes from earlier gates. No module calls them, and nothing in this
repository should start to without promoting that work into a named, checked module first.

## Build, sign, install

From a Visual Studio Build Tools + WDK install (the defaults are Build Tools 18 and WDK
10.0.26100.0):

```powershell
cd drivers\h3probe              # from the repository root
.\build.cmd                    # compile and link: h3probe.sys beside the source
.\build.cmd <thumbprint>       # ...and sign with that code-signing cert from CurrentUser\My
```

The build output (`*.obj`, `*.pdb`, `*.sys`) is ignored by Git. A test-signed driver loads only on a
host with test signing enabled and the signing certificate trusted in `LocalMachine\Root` and
`LocalMachine\TrustedPublisher`.

Install it once as a demand-start kernel service, elevated and from this directory:

```powershell
sc.exe create h3probe type= kernel start= demand binPath= "$PWD\h3probe.sys"
```

Then pin the image in `config.local.toml` under `[drivers]` — `sklab doctor` prints the hash to pin
while it is unpinned — and from then on:

```powershell
uv run sklab driver            # status of h3probe
uv run sklab driver start
uv run sklab driver stop
```

The convention is to leave it stopped between runs. Stop only when no live session holds the
device; `driver stop` reports the state the service actually reached rather than assuming the stop
took.

For the complete installation, VM and profile setup, use
[`docs/m8-runbook.md`](../../docs/m8-runbook.md).
