# Plan: make h3probe the only sklab driver

## Objective

Remove the runtime, configuration, and installation dependency on LiveCloudKd's `hvmm.sys` by
moving sklab's direct guest-physical read/write boundary behind the source-controlled
`h3probe.sys`. The end state has one demand-start driver built from this repository, one pinned
driver hash, no `hvmm` service, and no `livecloudkd_root` requirement for normal or qualification
workflows.

This was written as a plan, when h3probe owned VTL1 register/control operations and hvmm owned the
direct GPA path, with the rule that documentation and checks keep saying so until the replacement
passes every live gate.

**Status, 2026-10-29: complete.** Every gate below passed, and the final acceptance passed with the
hvmm service uninstalled: `Get-Service hvmm` answered "Cannot find any service with service name
'hvmm'", and no process had `hvlib.dll` loaded. [Results](#results-2026-10-29) records each run,
the attempts that failed and why, and the three sklab defects the final acceptance found and fixed.

**Ownership update, 2026-11-01:** windbg-mcp item 133 subsequently moved `h3probe`'s source and both
providers into windbg-mcp. The 2026-10-29 results below remain the migration's historical evidence;
the current sklab tree is an ordinary client that keeps only service lifecycle, guest triggers and
evidence orchestration, and pins the driver built in `C:\workspace\windbg-mcp\drivers\h3probe`.

## Why this is not an IOCTL rename

H3probe already exposes `IOCTL_H3_READGPA` and `IOCTL_H3_WRITEGPA`, but those exercise the root
hypercall route. The measured read moves at most 16 bytes and returns `ReadIntercept` for protected
VTL1 pages. That behavior is useful as an independent backing/refusal oracle; it is not the direct
memory semantics that M8 needs.

The working hvmm route instead uses a VID partition handle bound to the current `vmwp`. It can read
the protected pages, read high guest RAM, and perform the bounded write used by guarded INT3. Its
current read ABI also has an ambiguity: an unmapped GPA can be returned as a zero page, which sklab
must disambiguate with RAM runs and h3probe's hypercall oracle.

The replacement therefore needs a measured in-vmwp/VID GPA primitive. Copying the existing
hypercall into a new control code would retain the refusal and falsely claim the dependency was
removed.

## Current responsibility map

| Capability | h3probe now | hvmm now | Required end state |
|---|---:|---:|---:|
| Enumerate child partitions | Yes | No | h3probe |
| Read VTL0/VTL1 registers | Yes | No | h3probe |
| Set guarded VP registers | Yes | No | h3probe |
| Discover/validate vmwp VID identity | Yes | No | h3probe |
| Read protected VTL1 GPA | No, hypercall is refused | Yes | h3probe through a measured VID/in-vmwp path |
| Distinguish mapped zero from unmapped | Hypercall oracle only | No | One typed h3probe result |
| Bounded direct GPA write | Hypercall path exists but is not the M8 route | Yes | h3probe through the same measured direct path |

## Target boundary

The preferred interface preserves the identity already used throughout sklab:

```text
VM GUID -> current vmwp PID -> VID partition handle -> partition ID -> VP/VTL
```

User mode supplies only the boot-scoped PID, handle value, partition ID, GPA, and bounded length.
The driver attaches to the named `vmwp`, resolves the handle in that process, references the VID
file/partition object, proves that the partition's owner field matches the attached process, and
uses only the subsequently measured GPA primitive. It detaches and dereferences on every path.

The new ABI should have these properties:

- versioned, fixed-width request/response structures and compile-time size assertions;
- separate read and write operations, neither inferred from buffer direction;
- one request bounded to one 4 KiB page; larger user reads split above the driver;
- writes non-empty, same-page, and bounded by both the driver and live-policy gates;
- no caller-supplied kernel pointer, object pointer, callback, or function address;
- explicit identity/build failures distinct from GPA access failures;
- typed `OK`, `NOT_PRESENT`, `REFUSED`, and `ERROR` results, so a zero-filled mapped page is not
  confused with no page;
- exact returned byte count, with short success treated as failure;
- attach/detach, reference/dereference, and cleanup on every error path;
- no persistent mapping, registered handler, intercept, or guest state left by a read;
- write completion followed by a caller-visible readback path suitable for compare/restore proof.

Do not assign permanent IOCTL numbers or freeze a structure until the live measurement below
identifies the actual primitive and its failure semantics.

## Phase 0: freeze the existing contract

Before changing the driver:

1. Add unit fixtures for the existing `sklab.hvmm.Reader` and `Writer` behavior, including high
   RAM, page boundaries, short output, unmapped-zero ambiguity, and write completion.
2. Record a live corpus from the current two-driver path: mapped code/data, a mapped all-zero page,
   RAM holes, the device gap, the end of RAM, and an address above 4 GiB.
3. Record current VTL1 text, debug-register, heartbeat, boot, and `vmwp` identity before and after.
4. Hash the exact h3probe and hvmm images used by the corpus.

This corpus is the differential oracle. It is not checked into Git when it contains live memory;
its schema and synthetic fixtures are.

## Phase 1: measure the in-vmwp GPA primitive

This is the decision gate. Instrument a read-only probe that attaches to the identity-checked
`vmwp` and determines whether its VID partition handle exposes a bounded GPA read without hvmm.
Candidates may include a VID partition-handle operation or an internal partition-object copy
routine, but neither its existence nor ABI is to be guessed from a name.

The probe must:

- run only against the disposable target and current exact VID/vmwp build;
- read a known VTL0 page as a positive control;
- read a known protected VTL1 Secure Kernel page and compare its bytes with the current hvmm
  oracle;
- read a mapped zero page and an unmapped GPA and prove they remain distinguishable;
- reach the same high-RAM page that exposed hvlib's old 4 GiB bound;
- perform no write, registration, intercept, or retained mapping;
- detach, release every object, and pass the same-boot 60-second health audit.

Stop if no such path exists. At that point removing hvmm requires a separately reviewed memory
implementation, not a wrapper around the refused H3 hypercall. Do not plan later phases around an
unmeasured success.

## Phase 2: implement a read-only h3 memory source

After Phase 1 passes:

1. Add the smallest build-guarded driver operation around the measured primitive.
2. Add `sklab.h3_memory.Reader` with the same `(data, failure)` interface used by existing page
   walkers.
3. Keep `sklab.hvmm.Reader` available behind an explicit comparison option.
4. Differentially compare every corpus address and a bounded randomized sample across guest RAM.
5. Require exact agreement on data and typed agreement on absent/refused/error status.
6. Add cancellation, invalid PID/handle, changed `vmwp`, wrong partition, oversized request,
   cross-page request, and driver-unload tests.

Acceptance is read-only: `live.decode`, `live.registers snapshot=true`, the M8 open, and the KD
post-release audit all use h3 memory successfully on three fresh boots. No write path changes yet.

## Phase 3: switch all read consumers

Make h3 memory the default for:

- `live.decode`;
- Secure Kernel root/process identification in `live.registers`;
- `live.ambient` and `live.transition` memory providers;
- `kd.manual`, `kd.external`, and `kd.debugger` live transports;
- `validate.kd-post-audit` and every fault-gate audit.

At this phase:

- replace the `hvmm` capability check with a versioned `h3_memory` capability;
- update generated provider command templates and manifests;
- keep hvmm comparison code explicit and non-default for one release;
- run ordinary unit/compile checks, the live controller acceptance, three M8 composite boots, and
  read-only external hardware-breakpoint qualification.

The phase passes only if no default/read-only path opens `\\.\hvmm` and the post-release audit has
the same coverage as before.

## Phase 4: add bounded write and restoration

Implement a direct write only through the same identity-checked primitive family proved in Phase 1.
Do not reuse `IOCTL_H3_WRITEGPA` merely because it already exists; first prove it has the direct
protected-memory semantics required here.

The write gate is the existing `validate.hvmm-write` behavior renamed around provider-neutral
memory:

1. Pause the exact disposable VM.
2. Read and hash the complete page.
3. Change one reserved Secure Kernel PE-header byte.
4. Prove that byte is the page's only delta.
5. Restore the original byte.
6. Read and hash the complete restored page.
7. Resume only after restoration is proved; otherwise force the disposable target off.
8. Audit the same boot, heartbeat, text, registers, flags, processes, and driver state.

Then run Classic and WinDbgX guarded-INT3 qualification, 100 hits each, with exact byte restoration
after every hit. A driver write API is not considered complete until those two packet paths pass.

## Phase 5: remove hvmm from the product configuration

Once read and write gates pass:

- remove `Drivers.hvmm_service` and the `hvmm` prerequisite/capability;
- remove `Paths.livecloudkd_root` from the normal schema; retain it only in an explicitly named
  legacy/comparison plugin if that comparison is still valuable;
- make `sklab driver start|stop|status` manage only h3probe;
- rename `validate.hvmm-write` to a provider-neutral or h3-specific gate, leaving a compatibility
  alias for one release if useful;
- retire `sklab.hvmm`, `hvmm_gpa.py`, and `hvmm_gpa_server.py` from runtime imports;
- update README, architecture, config example, doctor, banner, manifests, tests, and runbooks;
- verify `rg "hvmm|livecloudkd" src config.example.toml README.md docs` contains only historical
  migration/provenance statements.

Do not delete historical evidence that explains why the old path existed or what semantics the new
driver had to match.

## Final acceptance

The migration is complete only when all of the following pass with `hvmm` uninstalled, not merely
stopped:

- all sklab unit tests and Python compilation;
- h3probe build, load, version/hash check, invalid-input tests, and clean unload;
- `sklab doctor` and every core module check with one configured driver;
- live decode and register/root ownership on mapped, zero, high-RAM, and absent pages;
- live ambient and transition stop/step/resume with independent restoration audit;
- the provider-neutral one-byte write/read/restore/full-page-hash gate;
- M8 composite generic assertions and 25 break-ins on each of three clean boots;
- Classic and WinDbgX, 100 hardware and 100 guarded-INT3 hits each;
- build-mismatch, provider-death, debugger-loss, and identity-change containment gates;
- same-boot 60-second health audits and no retained driver/provider/worker state.

The final run record should state that `Get-Service hvmm` returned not found and that no process
loaded hvlib. That is the evidence that sklab is self-contained at the privileged-provider layer,
apart from the operator's unavoidable local build/sign/install step for h3probe.

## Results (2026-10-29)

Every run named here is an ignored directory under `runs/` on the K3 bench: `Vid.sys`
10.0.26100.9711 (SHA-256 `633171F0...D6AD369`, timestamp `0xD2E40B4A`, image size `0xDC000`), K3
with one VP and 8 GiB of static RAM (`0`-`0xF8000000` and `0x100000000`-`0x208000000`).

### Phase 0: the contract that was frozen

The hvmm reader and writer gained fixtures for a read above 4 GiB keeping the full GPA and for a
short write completion. The live corpus (mapped code and data, a mapped zero page, a RAM hole, the
device gap, the end of RAM, a page above 4 GiB) is recorded as metadata only (address, backing,
result, all-zero, SHA-256) with the boot, identity, VTL1 register state and both drivers' image
hashes, inside each Phase 1 and 2 record. The fixtures and the differential are kept in
`legacy/h3probe-migration/`.

### Phase 1: the primitive, and the decision

Read out of the exact build with Ghidra and cdb, and stated with its RVAs above
`IOCTL_H3_VIDTRANSLATE` in `h3probe.c`:

- `0x2211C7` (`VidTranslateGpa`) takes a guest **page number**, not a byte address: the range test is
  `start <= gpn <= end` with `end = start + pages - 1`, and vmwp shifts a GPA right by 12 before it
  translates. It answers `{non-memory context, [MB+0xB0], memory-block page, range flags}`. The first
  probe sent byte addresses unshifted; it resolved GPA 0 and 0x1000 only because their low twelve
  bits are zero, and called every page above 4 GiB absent.
- `0x22113F` (`VidReadMemoryBlockPageRange`) takes `{handle, block page, pages, buffer, bytes, ...}`,
  and the handle is the memory block's entry in the partition's table at `+0xAC8`, the value
  `VsmmMemoryBlockHandleTableInsert` writes to `[MB+0x18]`, not a pointer.
- `0x2211EF` is the same request on the write path; `0x2210C3` answers the handle's partition ID.

Run `20261029T175141-measure-h3-memory-b269f5` passed all ten criteria. The VTL0 control page
(`0x7D5000`) and both protected VTL1 pages, the Secure Kernel handler's code page (`0x13BB000`) and
its CR3 page (`0x2601000`), which `HvCallReadGpa` answers `ReadIntercept`, equal hvmm's bytes; so do
the high-RAM page `0x107FFF000` and the last RAM page `0x207FFF000`. Page 0 is typed `ok` data that is
all zero, while the device gap (`0xF8000000`), the end of RAM (`0x208000000`), far above RAM
(`0x308000000`) and the local APIC are `not-present`, where hvmm returned a page of zeros for each.
64 of 64 seeded pages agree, 36 above 4 GiB. Debug registers were unchanged, the same boot was
healthy after 60 seconds, and no process loaded hvlib.

The measurement also corrected a bench constant: K3's end of RAM is `0x208000000`, not the
`0x108000000` written down when it had 4 GiB, so validations now take the edges of RAM from VID's own
ranges. And the discovery step's cdb sample (`bp vmwp+2c360` whose command ends `bc *; .detach /h`)
sometimes crashes vmwp with `0x80000003` at `0x2c360`, about 100 ms after the detach. That cost two
runs here (`20261029T145328-measure-h3-memory-1ab187`, `20261029T175911-validate-h3-memory-c9efa7`)
and predates this migration. The likely mechanism, not yet measured, is a second dispatcher thread's
breakpoint event still queued when the debugger detaches.

Measured afterwards, on 2026-10-30, and the sample is gone. A cdb probe of the same entry that
continued with `gh` instead of detaching found, in 1 of 26 samples on K3, a second dispatcher thread
already parked one byte past the `int 3`; after `bc *` it arrived as a first-chance breakpoint at
the restored entry and `gh` resumed it harmlessly. Against a test process, cdb's `.detach /h` disposed
of every such queued hit (5 of 5 survived), and the signature itself (`0x80000003` at `0x2c360`) was
reproduced by resuming a vmwp whose entry breakpoint event a debugger had abandoned un-continued. So a
queued second hit is real on vmwp, and what turns one into the crash after a handled detach is still
not caught in the act. Discovery now runs through windbg-mcp's own `--sk-discover-identity`, which
stays attached through its partition call and continues a queued entry hit handled there. Before
that change, the same event would have stopped the call short of its return and left vmwp contained.

Requalified on 2026-10-30 with the windbg-mcp build `4FB71B42...` (the dev executable's SHA-256):

- **One series boot**, discovered fresh by `live.registers` and passed in full, 25 break-ins:
  `20261030T095625-live-registers-bfac46` ... `20261030T095854-validate-m8-976201`.
- **Build mismatch with its audit:** `20261030T100727-fault-build-mismatch-fdc342` and
  `20261030T100729-validate-kd-post-audit-7f0eb5`.
- **Provider death:** `20261030T100744-fault-provider-death-a54fdf`.
- **Debugger loss:** `20261030T100956-fault-debugger-loss-528b56`, discovered fresh on its own boot.
- **Identity change:** `20261030T101159-fault-identity-change-370159`, discovered fresh on its own
  boot.

Each destructive fault's orphan worker was recovered by exact PID, as above. That series boot was
not a clean one: the 26 probe samples and four standalone discoveries had run on it first.
`late_entry_hits` was 0 in all six standalone discoveries that answered (three by modules, three by hand).
None of the server logs these runs kept records the continue, so that path has not yet fired live.

### Phase 2: the memory operation, read-only

`IOCTL_H3_MEMREAD`/`IOCTL_H3_MEMWRITE` (`0x812`/`0x813`) with a 40-byte versioned request, a
32-byte typed answer and compile-time size assertions, behind `sklab.h3_memory.Reader`/`Writer`.

Run `20261029T180536-validate-h3-memory-b13919` passed all thirteen criteria against hvmm: the same
pages and controls as Phase 1 with the same answers; 256 of 256 seeded pages agree, 128 above 4 GiB;
twelve malformed or foreign requests (empty, oversized, cross-page, short input, short output, wrong
version, reserved bits, a missing process, a kernel-handle value, a bad handle, another process's
handle, the wrong partition ID) each answered `error/request` or `identity` at the expected stage with
no data; 2000 reads in 0.19 s left vmwp's private bytes unchanged; a reader killed mid-loop left the
operation serving; stopping the driver made the device unopenable and restarting it served again;
and after a VM restart the old boot's identity was answered `identity` at `process`, and with only
the PID refreshed at `handle`. VTL1 text and debug registers were unchanged, and no process loaded
hvlib.

### Phase 3: every reader switched

`live.decode`, the `live.registers` root check, `live.ambient`, `live.transition`, the KD and M8
live transports and every post-release audit read through `gpa_server.py`/`H3Source`, and doctor
checks a versioned `h3_memory` capability. Each fresh boot ran, with the hvmm service **stopped** so
that any path opening `\\.\hvmm` would fail: `live.registers snapshot=true`, `live.decode`,
`validate.kd-post-audit`, `live.ambient`, `live.transition` and `validate.m8 scope=composite` (25
break-ins and the post-release audit, which recorded no hvlib before or after).

| Boot | vmwp | Runs | Result |
|---|---|---|---|
| 1 | 7920 | `20261029T181226-live-registers-4cfed0` ... `20261029T181455-validate-m8-d17877` | all six passed |
| 2 | 10124 | `20261029T182352-live-registers-191c20` ... `20261029T182555-validate-m8-5c74b9` | all six passed |
| 3 | 4988 | `20261029T183455-live-registers-e74cc0` ... `20261029T183720-validate-m8-8fd63f` | five passed; the composite failed |

The third boot failed on a host helper, not on a read. The composite's 24th break-in arrived 0.1 ms
after the previous `g` had started its `Resume-VM` helper, so the rendezvous waited for that helper,
and it exited 2 with nothing on stdout or stderr, which its `Stop`-mode script cannot produce itself.
The controller recovered fail-closed (VM running, nothing left paused, no recovery errors) and
released, and the guest stayed healthy. The helper's exit came within 170 ms of the bench host's agent
reaping its background shells for memory pressure; commit charge was 13.9 of 18.3 GB with no
resource-exhaustion event, so memory alone does not explain it, and the mechanism is not established.
That boot counts as failed; the final acceptance's series supplied three passing boots, with hvmm
uninstalled rather than stopped.

The same failure showed a host-side hazard to know before rerunning anything after a
`kernel_unresolved` ending. The KD client's worker was preserved as an orphan, by design, and `sklab`
stayed blocked in `subprocess.run(capture_output=True)` until that one worker was terminated, after
its supervisor, facade pipe and controller were verified gone; it returned within five seconds of the
termination. A run directory's logs are written only once `sklab` returns.

### Phases 4 and 5

Phase 4's gate is `validate.memory-write` (`validate.hvmm-write` before the migration). The live
transport serves `WRITE` only under `--writes` and declares `instruction_coherent` writes and
`explicit_refresh` reads; whether a session may write is still the policy's `allow_memory_writes`,
which the M8 hardware policy omits and the INT3 policy sets. A write is applied to the whole page
(read, patch, write, read back), so a guest store to that page between the read and the write would be
lost; writers hold the VM. Phase 5 removed `paths.livecloudkd_root` and `drivers.hvmm_service` (a
configuration still naming either is refused), made `driver start|stop|status` manage h3probe alone,
moved `sklab.hvmm`, `hvmm_gpa.py`, `hvmm_gpa_server.py`, `s5w_gpa_server_pinned_vtl.py` and the
hvmm differential to `legacy/h3probe-migration/`, replaced `validate.h3-memory`'s hvmm oracle with
`HvCallReadGpa`'s bytes and the pinned Secure Kernel image, and rewrote the documentation.
`rg "hvmm|livecloudkd"` over `src`, `config.example.toml`, `README.md` and `docs` finds only
historical statements and the stale-key refusal.

### Final acceptance, with hvmm uninstalled

`sc.exe delete hvmm` ran before any of these, after recording the service: kernel driver, demand
start, its image path, SHA-256 `BE704692...461C29`. The binary
was left in place, so `sc.exe create hvmm type= kernel start= demand binPath=` with that path
restores it. From then on `Get-Service hvmm` answered "Cannot find any service with service name
'hvmm'" and the service's registry key was gone. Every gate ran on a fresh boot that was healthy for
60 seconds first, and each destructive fault on a boot of its own.

| Gate | Run | Result |
|---|---|---|
| Unit tests and compilation | `uv run python -m unittest discover -s tests`, `compileall` | 188 passed |
| h3probe build | `build.cmd` into a scratch directory | `/W4`, no warnings; `.text`, `PAGE`, `INIT`, `.data`, `.reloc` byte-identical to the pinned `AB4651BB...8A813D` |
| Load, ABI, invalid input, unload | `20261029T194722-validate-h3-memory-ebd1fb` | all 16 criteria |
| Doctor | before each series boot | no errors, three times |
| One-byte write, read-back, restore | `20261029T195110-validate-memory-write-57065a` | pass |
| Series boot 1 | `20261029T195450-live-registers-a83eb6` ... `20261029T195645-validate-m8-872be7` | all six; 25 break-ins |
| Series boot 2 | `20261029T200532-live-registers-1737a6` ... `20261029T200756-validate-m8-e5679d` | all six; 25 break-ins |
| Series boot 3 | `20261029T201643-live-registers-ab263e` ... `20261029T201841-validate-m8-e78701` | all six; 25 break-ins |
| Classic and WinDbgX, hardware and guarded INT3 | `20261029T212657-validate-m8-9fda28` | four arms of 100, all restored, one boot |
| Build mismatch | `20261029T224104-fault-build-mismatch-ce057b`, audit `20261029T224109-validate-kd-post-audit-285804` | refused at the arm; released; nothing changed |
| Provider death | `20261029T224606-fault-provider-death-4a1fd3` | contained, ownership retained |
| Debugger loss | `20261029T225000-fault-debugger-loss-b0ccf1` | contained, ownership retained |
| Identity change | `20261029T225154-fault-identity-change-a384b4` | refused after vmwp's termination; ownership retained |

`validate.h3-memory` read the mapped, zero, high-RAM and absent pages of the corpus and 256 seeded
pages (128 above 4 GiB) through the memory operation; the 253 the hypervisor will read agreed with
`HvCallReadGpa` byte for byte, twelve of twelve refusals held, 2000 reads left vmwp's private bytes
unchanged, and after a restart the old identity was refused (the old handle under the new PID at
`owner`, since `0x2d4` was a valid handle there). The write gate changed only offset `0x30` of the
Secure Kernel's header page, restored the page to its original hash, and left the same boot healthy
60 seconds later with debug registers unchanged. Each composite recorded 25 break-ins and 26 stops,
and every post-release audit (one per composite, one per external arm) passed with no hvlib. The four
external arms each completed 100 cycles with 100 restorations: guarded INT3 planted and restored its
byte through h3probe's memory write every time, and the guarded instruction read back unchanged.
After the last gate no process had `hvlib.dll` loaded, h3probe was stopped, and no sklab provider or
windbg-mcp worker remained.

The final acceptance found three defects in sklab, none in the memory path, each fixed and tested
before the gate passed:

- **The control provider could not hold an INT3 stop.** `k4_control_provider.py` was vendored from
  the 2026-10-12 bench, before the provider contract's optional `breakpoint_events`: it advertised no
  vector-3 support and its held-event check accepted vector 1 only, so every guarded-INT3 `go` was
  refused ("the register provider does not advertise vector-3 breakpoint events") and the first matrix
  run, `20261029T202814-validate-m8-ce8849`, failed its Classic INT3 arm. It now advertises the
  capability and holds vector 3 with `breakpoint_exception`, as the bench's later provider does. The
  worker enables vector 3 only under `allow_memory_writes`, which no series module sets, so the series
  above, which ran before the change, exercised the same code it would now.
- **`fault.build-mismatch` expected the refusal at open** (`20261029T223854-fault-build-mismatch-afa93f`).
  `open_sk_live_control` now only reserves the controller; the dispatcher hashes vmwp at the first
  arm, before any provider write. The gate now arms and requires that refusal and a clean release.
- **The fault gates armed `natural`**, waiting for the guest to reach the profile's guard on its own,
  which it did not within the wait's budget, so provider death was never injected
  (`20261029T224136-fault-provider-death-6b85aa`). They now take the configured arm mode, `redirect`,
  like every other module.

One attempt was lost to the bench rather than to a gate: the first debugger-loss run's discovery hit
the `bp vmwp+2c360` crash recorded above (`20261029T224823-fault-debugger-loss-14b902`, vmwp
`0x80000003` at `0x2c360`) before any session opened.

Each destructive fault left, by design, an unresolved controller whose worker outlived its supervisor
and held vmwp. Each was recovered out of band, as the windbg-mcp session documentation prescribes for a
disposable VM: its PID was matched to the run's retained session and its supervisor confirmed gone,
that one worker was terminated, vmwp went with it, and Hyper-V restarted K3, which was then shut down
before the next boot. The first matrix run's orphan had also kept `sklab` blocked on its capture pipe
for 55 minutes until it was recovered the same way.
