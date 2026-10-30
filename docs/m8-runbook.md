# Reproducing the M8 Secure Kernel debugger

This runbook takes a new Hyper-V lab from an unconfigured checkout to the two supported M8 paths:

- `kd.debugger`: one server-owned composite session driven entirely by generic MCP debugger tools;
- `kd.external`: Classic WinDbg or WinDbgX attached to the managed Secure Kernel KD facade.

It also covers the exact live qualification used to close M8. The commands create machine-local
configuration and evidence only. Profiles and source are versioned; credentials, symbols, driver
binaries, VM disks, copied Windows images, and run directories are not.

## Current boundary

The reproducible stack has one host driver, built from this repository:

| Component | Responsibility | Source in this repository |
|---|---|---|
| `h3probe.sys` | Child discovery, VTL0/VTL1 registers, debug-register control, active-VTL and boot-scoped identity, guest-physical reads and bounded writes through vmwp's VID partition handle, and the refusing `HvCallReadGpa` oracle | Yes, under `drivers/h3probe/` |

Nothing loads `hvlib.dll` and no LiveCloudKd component is installed. Sklab hands the identity-bound
VID handle, vmwp's PID and the partition ID to h3probe, which reads inside vmwp after checking all
three. How it replaced LiveCloudKd's `hvmm.sys`, and the evidence, is in
[the h3probe-only migration plan](h3probe-only-plan.md).

`windbg-mcp` owns DbgEng, KD packet translation, stop epochs, guarded mutation, deadlines, recovery,
and release. Sklab owns host/VM configuration, provider commands, exact profiles, driver lifecycle,
guest trigger, post-release audit, and qualification evidence.

## Safety model

Use a dedicated Hyper-V host and an explicitly disposable guest. The provider can alter another
partition's VTL1 registers and memory. Do not use this setup on a machine or VM holding data of
value.

- Install the driver as a `demand` service, never a boot-start service.
- Leave the service stopped outside a run.
- Keep the VM's `AutomaticStartAction` at `Nothing`.
- Use an immutable parent plus a disposable differencing child when possible.
- Do not weaken HVCI or another protection because an event merely appears related. M8 does not
  change host security policy; arrange a legitimate local signing/test policy for the driver you
  built and record that posture separately.
- A result of `recovery required` is containment evidence, not a successful teardown. Preserve the
  run and do not start a second controller on the same VM.

## 1. Host prerequisites

Use an elevated PowerShell terminal. Install:

- Hyper-V management tools and a host capable of running a VBS guest;
- Python 3.13 and `uv`;
- Rust and the MSVC build tools needed by `windbg-mcp`;
- Windows SDK/WDK 10.0.26100 or a compatible installed kit;
- the x64 Debugging Tools for Windows, including Classic WinDbg/cdb;
- Microsoft.WinDbg when the WinDbgX arm will be run;
- Visual Studio Build Tools plus WDK for `h3probe.sys`.

Check out `windbg-mcp` beside this repository. Every command in this runbook runs from this
repository's root unless it says otherwise. Build the debugger server and install Python
dependencies:

```powershell
Push-Location ..\windbg-mcp
cargo build --release
Pop-Location

uv sync
Copy-Item config.example.toml config.local.toml
```

The selected `windbg-mcp.exe` must have the expected DbgEng runtime beside it. Run the ordinary
server tests and sklab unit tests before changing the VM:

```powershell
Push-Location ..\windbg-mcp
cargo test
Pop-Location

uv run python -m unittest discover -s tests -v
```

## 2. Create and constrain the VM

M8 needs a Generation 2 Windows guest in which VBS is actually running. The exact qualification
uses one virtual processor. One VP is mandatory for the guarded INT3 arm and also removes processor
selection from the reproduction.

A minimal new-VM example is:

```powershell
$vmName = 'Disposable Secure Kernel demo VM'
$vhd = 'D:\lab\working-disks\k3-install.vhdx'
$iso = 'D:\iso\Windows-11-25H2-x64.iso'
$switch = 'Lab Switch'

$vm = New-VM -Name $vmName -Generation 2 -MemoryStartupBytes 4GB `
  -NewVHDPath $vhd -NewVHDSizeBytes 80GB -SwitchName $switch
Set-VMProcessor -VM $vm -Count 1 -ExposeVirtualizationExtensions $false
Set-VMMemory -VM $vm -DynamicMemoryEnabled $false -StartupBytes 4GB
Set-VM -VM $vm -AutomaticStartAction Nothing -AutomaticStopAction ShutDown
Enable-VMIntegrationService -VM $vm -Name Heartbeat
$dvd = Add-VMDvdDrive -VM $vm -Path $iso -Passthru
Set-VMFirmware -VM $vm -FirstBootDevice $dvd
Start-VM -VM $vm
```

Install Windows, remove the installation DVD, enable VBS, and make a clean immutable baseline
before installing the disposable workload. M8 does not require a differencing disk, but sklab's
safe `vm reset` workflow does: attach a child of the immutable parent and configure both
`parent_disk` and `work_disk_root`.

The following is a representative host configuration after Windows has been installed. Run changes
that require it while the VM is off:

```powershell
$vmName = 'Disposable Secure Kernel demo VM'
$vm = Get-VM -Name $vmName -ErrorAction Stop

Stop-VM -VM $vm -TurnOff
Set-VMProcessor -VM $vm -Count 1 -ExposeVirtualizationExtensions $false
Set-VMMemory -VM $vm -DynamicMemoryEnabled $false -StartupBytes 4GB
Set-VM -VM $vm -AutomaticStartAction Nothing -AutomaticStopAction ShutDown
Enable-VMIntegrationService -VM $vm -Name Heartbeat

Get-VM -VMName $vmName | Select-Object Name, VMId, Generation, State, AutomaticStartAction
Get-VMProcessor -VMName $vmName | Select-Object Count, ExposeVirtualizationExtensions
Get-VMMemory -VMName $vmName | Select-Object DynamicMemoryEnabled, Startup
```

Do not enable nested virtualization for the direct K3 M8 topology. With
`ExposeVirtualizationExtensions=true`, K3 launches its nested hypervisor and K3's own VTL1 is no
longer visible to the outer root provider. That is a different, nested-parent/child topology and
must be configured as such; sklab does not silently fall back to it.

Guest Secure Boot is not an M8 switch. Preserve the guest firmware posture that supports the VBS
baseline instead of changing it merely for the debugger.

### Prove VBS and heartbeat

Start the VM and use PowerShell Direct with a guest administrator credential:

```powershell
$cred = Get-Credential
Start-VM -Name $vmName

Invoke-Command -VMName $vmName -Credential $cred -ScriptBlock {
    Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard `
      -ClassName Win32_DeviceGuard |
      Select-Object VirtualizationBasedSecurityStatus, SecurityServicesConfigured, SecurityServicesRunning
}

Get-VMIntegrationService -VMName $vmName -Name Heartbeat |
  Select-Object VMName, PrimaryStatusDescription
```

Require `VirtualizationBasedSecurityStatus = 2` and heartbeat `OK`. Configured-but-not-running VBS
does not provide an M8 target.

### Install the guest trigger

The qualification trigger creates and terminates a VBS enclave only after the facade reports
running. Place the tested pair in the guest, for example:

```text
C:\encl\spin_host.exe
C:\encl\spin_enclave.dll
```

Run the host manually once inside the guest and record both SHA-256 hashes. Sklab re-hashes them on
every trigger. Store the PowerShell Direct credential in an ignored JSON file:

```json
{
  "username": "lab-user",
  "password": "replace-with-the-lab-password"
}
```

Restrict the file ACL to the operator. The credential is read by the local PowerShell process and
is not copied into policy, command lines, manifests, or transcripts.

## 3. Pin images and symbols

Copy the target's `securekernel.exe` to the ignored `artifacts/` directory. A PowerShell Direct
session can copy from the guest without configuring guest networking:

```powershell
$session = New-PSSession -VMName $vmName -Credential $cred
Copy-Item -FromSession $session `
  -Path C:\Windows\System32\securekernel.exe `
  -Destination .\artifacts\securekernel-26100.9457.exe
Remove-PSSession $session
```

Record its hash in the local target configuration and, when intentionally updating the shared
artifact contract, in `artifact-manifest.toml`. Never substitute the host's image merely because
its version string looks similar.

Prepare a local symbol store containing the PDB that matches that exact image. For public symbols,
the installed kit's `symchk.exe` can populate a store:

```powershell
& 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe' `
  .\artifacts\securekernel-26100.9457.exe `
  /s 'SRV*C:\symbols\securekernel*https://msdl.microsoft.com/download/symbols'
```

If the build uses a private PDB, copy its existing symbol-store layout instead. `paths.symbol_path`
names the store root, not an individual PDB. The live gate proves the match by resolving
`securekernel!IumInvokeSecureService`, enumerating the module, and walking a symbolized stack; a
file with the right name but wrong identity does not pass.

Record the current host images used by the dispatcher profile:

```powershell
Get-FileHash -Algorithm SHA256 C:\Windows\System32\vmwp.exe
Get-FileHash -Algorithm SHA256 C:\Windows\System32\vid.dll
```

## 4. Install the current drivers

### Build, sign, and install h3probe

Build from the source in this repository:

```powershell
Push-Location drivers\h3probe
.\build.cmd <certificate-thumbprint>
Pop-Location
```

The certificate and host policy must permit that exact locally built image. Install it once as a
demand-start service:

```powershell
sc.exe create h3probe type= kernel start= demand `
  binPath= "$PWD\drivers\h3probe\h3probe.sys"
```

Run `uv run sklab doctor` once with `drivers.h3probe_sha256` omitted. It reports the image hash;
copy that hash into `config.local.toml`, then rerun doctor. A source rebuild is an intentional hash
change and must be reviewed and re-pinned.

The memory operation is guarded by the exact `Vid.sys` build its offsets were read from
(`H3_VID_TIMESTAMP` and `H3_VID_SIZEOFIMAGE` in `h3probe.c`); on any other build every read answers
`identity` at `build` rather than guessing. After servicing changes `Vid.sys`, re-derive and
re-measure before re-pinning (`docs/h3probe-only-plan.md`, Phase 1).

Start and stop it through sklab:

```powershell
uv run sklab driver
uv run sklab driver start
uv run sklab driver stop
```

Stop it only when no provider or live session still holds the device.

## 5. Configure sklab

Use real paths and exact identities in the ignored `config.local.toml`; a relative path resolves
against the configuration file's directory. This complete M8 shape is suitable for a one-VP direct
K3 target:

```toml
[paths]
windbg_mcp_repo = '..\windbg-mcp'
windbg_mcp_exe = '..\windbg-mcp\target\release\windbg-mcp.exe'
windows_kit_root = 'C:\Program Files (x86)\Windows Kits\10'
debugger_exe = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe'
classic_debugger_exe = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe'
windbgx_exe = 'C:\Program Files\WindowsApps\Microsoft.WinDbg_<version>_x64__8wekyb3d8bbwe\DbgX.Shell.exe'
symbol_path = 'C:\symbols\securekernel'
cdb_exe = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'
artifacts_root = 'artifacts'
runs_root = 'runs'
state_root = '.state'

[defaults]
connect_timeout_ms = 120000
idle_timeout_ms = 300000
max_pause_ms = 600000
arm_mode = 'redirect'
steps = 8

[drivers]
h3probe_service = 'h3probe'
h3probe_sha256 = 'REPLACE_WITH_64_HEX_CHARACTERS'

[targets.k3]
vm_id = '00000000-0000-0000-0000-000000000000'
vm_name = 'Disposable Secure Kernel demo VM'
disposable = true
profile = 'profiles\vmwp-dispatcher-profile-26100.9457.json'
secure_kernel_image = 'artifacts\securekernel-26100.9457.exe'
vp = 0
additional_vps = []
guest_spin_host = 'C:\encl\spin_host.exe'
guest_enclave_image = 'C:\encl\spin_enclave.dll'
guest_credential_file = 'credentials\k3.json'
expected_image_sha256 = 'REPLACE_WITH_64_HEX_CHARACTERS'
expected_vmwp_sha256 = 'REPLACE_WITH_64_HEX_CHARACTERS'
expected_vid_sha256 = 'REPLACE_WITH_64_HEX_CHARACTERS'
parent_disk = 'D:\lab\base\k3-parent.vhdx'
work_disk_root = 'D:\lab\working-disks'
```

`windbgx_exe` must name the package UI process, currently `DbgX.Shell.exe`. Do not use the
WindowsApps execution alias at `C:\Program Files\WindowsApps\...\windbgx.exe`; the alias can exit
while the UI continues, breaking lifecycle ownership.

A configuration that still names `paths.livecloudkd_root` or `drivers.hvmm_service` is refused
with a pointer to the migration; delete both keys.

## 6. Select or derive the vmwp profile

Profiles under `profiles/` bind the host's `vmwp.exe` and `vid.dll` build to the dispatcher sites,
layout, guarded bytes, and Secure Kernel KD metadata used by M8. They do not contain boot-scoped
PID, handle, partition, CR3, or Secure Kernel base values.

These are not ordinary `attach_kernel`/KDNET profiles. They contain no transport key or endpoint;
the live policy admits their directory and the Secure Kernel opener selects them by exact image
identity.

First compare the configured expected hashes and profile identities with the current host. If a
checked-in profile matches exactly, select it. A Windows cumulative update can move vmwp while the
guest Secure Kernel build remains unchanged; the filename is a catalog label, while the JSON
fields are authoritative.

For a serviced host, preserve the old image that matches the last proven profile and derive a
write-once candidate:

```powershell
uv run sklab profile vmwp `
  --baseline profiles\vmwp-dispatcher-profile-26100.9457.json `
  --old-image C:\images\26100.9457\vmwp.exe `
  --new-image C:\Windows\System32\vmwp.exe `
  --output .state\profiles\vmwp-candidate.json
```

Review the sibling report. Every guarded site must map uniquely, function prefixes must remain
unique, and the callback resume sequence and VID identity must validate. The generator refuses to
overwrite a candidate or activate it.

Then validate the candidate against the disposable VM without changing the selected configuration:

```powershell
uv run sklab --target k3 profile vmwp `
  --baseline profiles\vmwp-dispatcher-profile-26100.9457.json `
  --old-image C:\images\26100.9457\vmwp.exe `
  --new-image C:\Windows\System32\vmwp.exe `
  --output .state\profiles\vmwp-candidate-live.json `
  --live-validate --yes
```

Review both offline and live reports before copying the candidate into `profiles/` and updating the
target. This process derives a new build from a proven baseline; it does not infer a first profile
for an unrelated build. It also preserves the profile's `secure_kernel_kd` section unchanged, so
the procedure is valid only while the target's `securekernel.exe` build remains the same.

If the guest Secure Kernel build changed, take a standard unencrypted checkpoint and record the new
decode and symbols before changing the profile:

```powershell
..\windbg-mcp\target\release\windbg-mcp.exe --sk-inspect `
  --vmrs D:\captures\new-build.vmrs `
  --image .\artifacts\securekernel-new.exe `
  --symbols --cross-check --json .state\profiles\securekernel-new-inspect.json
```

That record re-establishes the mapped image, debugger-data block, loaded-module list, symbol build,
and image-relative coordinates. A reviewed new `secure_kernel_kd` section must also choose and guard
the initial instruction used by the facade. Sklab does not currently synthesize this section; do
not carry its RVAs across a Secure Kernel build change merely because the vmwp reprofile succeeded.

## 7. Preflight the bench

Start the VM and the driver, then run read-only checks:

```powershell
Start-VM -Name 'Disposable Secure Kernel demo VM'
uv run sklab driver start
uv run sklab --target k3 doctor
uv run sklab --target k3 check kd.debugger
uv run sklab --target k3 check kd.external
uv run sklab --target k3 run validate.m8 --set scope=external-preflight --yes
```

Do not continue until the preflight reports:

- elevation and both services/devices available;
- exact VM ID/name, state `Running`, one VP, and heartbeat `OK`;
- matching `securekernel.exe`, vmwp, VID, profile, and symbol store;
- both debugger executables and the M8 control helper;
- a stable boot identity and current `vmwp` PID;
- the ignored guest credential and enclave assets.

The preflight does not arm a breakpoint. It proves the static boot and every callback that later
qualification will use.

## 8. Use the debugger

### Generic MCP tools

The supported product path is one command:

```powershell
uv run sklab --target k3 run kd.debugger --yes
```

It generates the least-authority policy, opens `open_sk_debugger`, loads the symbol path, consumes
the redirected initial stop, installs `securekernel!IumInvokeSecureService`, reports running,
triggers one guest enclave call, and uses only generic tools for modules, registers, stack,
disassembly, step, free run, break-in, and release.

Exercise the repeated free-run gate with:

```powershell
uv run sklab --target k3 run kd.debugger --set free_run_cycles=25 --yes
```

### Classic WinDbg and WinDbgX

```powershell
uv run sklab --target k3 run kd.external --set frontend=classic --yes
uv run sklab --target k3 run kd.external --set frontend=windbgx --yes
```

The launcher owns the MCP session until the debugger UI process exits, then ends the facade and
runs the restoration audit. Useful supported commands include `.reload`, `lm m securekernel`,
`x securekernel!*`, `r`, `k`, `u`, `t`, `bp`, `g`, and running Ctrl+Break.

For a guarded INT3 demonstration, explicitly enable the write policy on the one-VP target:

```powershell
uv run sklab --target k3 run kd.external `
  --set frontend=classic `
  --set allow_memory_writes=true `
  --yes
```

This authorizes only the facade's guarded one-shot breakpoint byte. It does not expose arbitrary
memory writes.

### Split-terminal manual attachment

`kd.manual` prints the typed connection only after the initial stop and pipe are ready, then keeps
the controller monitored until the debugger exits:

```powershell
uv run sklab --target k3 run kd.manual --yes
```

Prefer `kd.external` for repeatable lifecycle ownership; use manual mode when showing or diagnosing
the connection itself is the point.

## 9. Re-run the M8 qualification

Sklab generates the Rust smoke configuration, read-only and write-enabled policies, trigger, boot
probe, debugger control commands, and 60-second audit. No former `target/private` script is needed.

The replacement map is explicit:

| Former bench responsibility | Current source-controlled implementation |
|---|---|
| Managed composite smoke config | `sklab.m8.write_composite_config` |
| External M8.2a config and separate hardware/INT3 policies | `sklab.m8.write_qualification_config` |
| Static boot/`vmwp`/VP/heartbeat probe | `python -m sklab.m8_helper ... boot` |
| Counted enclave secure-call trigger | `python -m sklab.m8_helper ... trigger --count N` |
| Guarded-text/register/flags/health survival audit | `python -m sklab.m8_helper ... audit --survival-seconds 60` |
| Authenticated debugger command/break/reset delivery | `scripts/m8_debugger_control.ps1` |
| Classic/WinDbgX open, process lifetime, teardown | `windbg-mcp/tools/launch_sk_kd.ps1`, invoked by `kd.external` |
| Exact Rust gate invocation and artifact directory | `validate.m8` |

Generated JSON and evidence still belong to each ignored run directory; source-controlled
replacement does not mean committing credentials, package paths, symbol caches, or boot identity.

Run the server-owned product gate on each of three clean VM boots:

```powershell
uv run sklab --target k3 run validate.m8 --set scope=composite --yes
```

Each run performs all generic assertions and 25 free-run/break-in cycles. Record the three distinct
boot identities and retain all three run directories.

Run the external breakpoint compatibility matrix on one qualified boot:

```powershell
uv run sklab --target k3 run validate.m8 --set scope=external-breakpoints --yes
```

This owns four arms: Classic/hardware, Classic/INT3, WinDbgX/hardware, and WinDbgX/INT3. Each arm
completes 100 counted enclave-triggered hits, ordered release, and the post-release audit.

The old GUI Ctrl+Break/reset race rig is retained only for explicit research:

```powershell
uv run sklab --target k3 run validate.m8 `
  --set scope=external-full `
  --set include_non_gating_gui_controls=true `
  --yes
```

It is not an M8 exit gate. Do not replace the typed composite break-in gate with GUI automation.

## 10. Read and retain the evidence

Every invocation creates `runs/<timestamp>-<module>-<suffix>/` with an atomic manifest, generated
policy/config, MCP transcript, server stderr, tool results, trigger results, and audit. A successful
M8 release must show:

- `released: true` from the controller;
- the same VM ID, boot ID, and `vmwp` PID before and after;
- heartbeat `OK` at the required samples;
- unchanged guarded Secure Kernel text;
- DR0-DR3 clear, no DR7 local enables beyond the saved baseline, and TF/RF clear;
- no retained debugger, worker, or provider process;
- no scoped `vmwp` crash record.

The 60-second qualification audit samples immediately, at 30 seconds, and at 60 seconds. Preserve
the complete run directory rather than copying only the final `pass` line.

## 11. Recovery and cleanup

Exit code `3`, `recovery_required`, or a final `released: false` means ownership is unresolved.

1. Preserve the run directory and `server.stderr.log`.
2. Do not launch another M8/live-control session for that VM.
3. Do not terminate the retained worker just to clear it from the process list.
4. Verify the exact VM/boot/`vmwp` identity in the recovery record.
5. Use the documented recovery path for that failure, or power off and discard the disposable
   child after the evidence is sealed.

After a successful run:

```powershell
uv run sklab driver stop
Stop-VM -Name 'Disposable Secure Kernel demo VM' -Shutdown
```

Use `uv run sklab --target k3 vm status` to inspect differencing-disk growth. When the configured
immutable parent and working root are correct, `vm reset --yes` rotates an off disposable child,
boots the replacement through a healthy-heartbeat check, returns it to off, and only then deletes
the old child.

## Known bounds

- One selected VTL1 VP is exposed as KD processor 0; processor switching is refused.
- Guarded INT3 requires exactly one VM VP.
- At most four breakpoint handles are available.
- Single step is limited to instructions whose stop can be proved, plus the guarded CR3-write
  successor case.
- Arbitrary target writes and NT process/thread extensions are refused.
- Exact vmwp/VID/Secure Kernel identities must be requalified after servicing.
- The memory operation is bound to the exact `Vid.sys` build it was measured on; another build
  is refused until it is re-derived and re-measured.
- A write is applied to the whole page (read, patch, write, read back); a guest store to the same
  page between the read and the write would be lost, so writes are made only while the VM is held.
