from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess
from typing import Any

from .config import Target
from .errors import ExecutionFailure, PrerequisiteError, RecoveryRequired


POWERSHELL_TIMEOUT_SECONDS = 420
HEALTHY_BOOT_SECONDS = 60


def _ps_quote(value: object) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def _invoke(script: str, *, timeout: int = POWERSHELL_TIMEOUT_SECONDS) -> dict[str, Any]:
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    try:
        completed = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                encoded,
            ],
            text=True,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise RecoveryRequired(
            "Hyper-V disk operation timed out; inspect the VM and its attached disk before retrying"
        ) from error
    except OSError as error:
        raise PrerequisiteError(f"could not start PowerShell: {error}") from error
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip() or "PowerShell failed"
        if "SKLAB_RECOVERY_REQUIRED" in detail:
            raise RecoveryRequired(detail)
        raise ExecutionFailure(detail)
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if not lines:
        raise ExecutionFailure("Hyper-V disk operation returned no result")
    try:
        value = json.loads(lines[-1])
    except (TypeError, ValueError) as error:
        raise ExecutionFailure(
            f"Hyper-V disk operation returned malformed JSON: {completed.stdout.strip()}"
        ) from error
    if not isinstance(value, dict):
        raise ExecutionFailure("Hyper-V disk operation returned a non-object result")
    return value


def _identity(target: Target) -> str:
    return f"""
$vm=Get-VM -Id {_ps_quote(target.vm_id)} -ErrorAction Stop
if($vm.Name -cne {_ps_quote(target.vm_name)}){{
  throw "VM identity mismatch: expected {_ps_quote(target.vm_name)}, got $($vm.Name)"
}}
"""


def status(target: Target) -> dict[str, Any]:
    script = f"""
$ErrorActionPreference='Stop'
{_identity(target)}
$drives=@(Get-VMHardDiskDrive -VM $vm -ErrorAction Stop)
if($drives.Count -ne 1){{throw "expected exactly one attached disk; found $($drives.Count)"}}
$path=[IO.Path]::GetFullPath($drives[0].Path)
$vhd=Get-VHD -Path $path -ErrorAction Stop
[pscustomobject]@{{
  vm_name=$vm.Name
  vm_id=$vm.VMId.Guid
  state=$vm.State.ToString()
  disk_path=$path
  disk_type=$vhd.VhdType.ToString()
  parent_path=$vhd.ParentPath
  file_size_bytes=[int64](Get-Item -LiteralPath $path -ErrorAction Stop).Length
  logical_size_bytes=[int64]$vhd.Size
}} | ConvertTo-Json -Compress
"""
    return _invoke(script, timeout=30)


def _reset_script(target: Target, parent: Path) -> str:
    return f"""
$ErrorActionPreference='Stop'
$healthyBootSeconds={HEALTHY_BOOT_SECONDS}
$parent=[IO.Path]::GetFullPath({_ps_quote(parent)})
$fresh=$null
$old=$null
$committed=$false

function Same-Path([string]$left,[string]$right) {{
  return ([IO.Path]::GetFullPath($left)).Equals(
    [IO.Path]::GetFullPath($right),[StringComparison]::OrdinalIgnoreCase)
}}

function Disk-References([string]$path) {{
  $items=@()
  foreach($candidateVm in @(Get-VM -ErrorAction Stop)) {{
    foreach($drive in @(Get-VMHardDiskDrive -VM $candidateVm -ErrorAction Stop)) {{
      if($drive.Path -and (Same-Path $drive.Path $path)) {{
        $items += [pscustomobject]@{{kind='vm';id=$candidateVm.VMId.Guid;name=$candidateVm.Name}}
      }}
    }}
    foreach($snapshot in @(Get-VMSnapshot -VM $candidateVm -ErrorAction Stop)) {{
      foreach($drive in @(Get-VMHardDiskDrive -VMSnapshot $snapshot -ErrorAction Stop)) {{
        if($drive.Path -and (Same-Path $drive.Path $path)) {{
          $items += [pscustomobject]@{{kind='snapshot';id=$snapshot.Id.Guid;name=$snapshot.Name}}
        }}
      }}
    }}
  }}
  return @($items)
}}

try {{
  {_identity(target)}
  if($vm.State.ToString() -ne 'Off'){{throw "disk reset requires the VM Off; got $($vm.State)"}}
  if(-not (Test-Path -LiteralPath $parent -PathType Leaf)){{throw "parent disk is missing: $parent"}}
  if(-not (Get-Item -LiteralPath $parent).IsReadOnly){{throw "parent disk is not read-only: $parent"}}

  $drives=@(Get-VMHardDiskDrive -VM $vm -ErrorAction Stop)
  if($drives.Count -ne 1){{throw "expected exactly one attached disk; found $($drives.Count)"}}
  $old=[IO.Path]::GetFullPath($drives[0].Path)
  if(Same-Path $old $parent){{throw 'refusing to replace or delete the configured parent disk'}}
  $oldRoot=[IO.Path]::GetDirectoryName($old).TrimEnd('\\')
  if([IO.Path]::GetExtension($old) -ine '.vhdx'){{throw "attached disk is not a VHDX: $old"}}
  $oldVhd=Get-VHD -Path $old -ErrorAction Stop
  if($oldVhd.VhdType.ToString() -ne 'Differencing'){{throw "attached disk is not differencing: $old"}}
  if(-not (Same-Path $oldVhd.ParentPath $parent)){{
    throw "attached disk has the wrong parent: $($oldVhd.ParentPath)"
  }}

  $beforeRefs=@(Disk-References $old)
  if($beforeRefs.Count -ne 1 -or $beforeRefs[0].kind -ne 'vm' -or
     $beforeRefs[0].id -ine $vm.VMId.Guid){{
    throw "attached child has unexpected VM or checkpoint references: $($beforeRefs | ConvertTo-Json -Compress)"
  }}

  $stamp=[DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
  $fresh=[IO.Path]::GetFullPath((Join-Path $oldRoot "sklab-reset-$stamp.vhdx"))
  if(-not ([IO.Path]::GetDirectoryName($fresh)).Equals(
      $oldRoot,[StringComparison]::OrdinalIgnoreCase)){{throw 'fresh child escaped the attached disk directory'}}
  if(Test-Path -LiteralPath $fresh){{throw "fresh child already exists: $fresh"}}

  New-VHD -Path $fresh -ParentPath $parent -Differencing -ErrorAction Stop | Out-Null
  Set-VMHardDiskDrive -VMHardDiskDrive $drives[0] -Path $fresh -ErrorAction Stop
  Start-VM -VM $vm -ErrorAction Stop | Out-Null

  $deadline=[DateTime]::UtcNow.AddSeconds(240)
  $healthy=$false
  do {{
    Start-Sleep -Seconds 2
    $vm=Get-VM -Id {_ps_quote(target.vm_id)} -ErrorAction Stop
    $heartbeat=Get-VMIntegrationService -VM $vm -Name 'Heartbeat' -ErrorAction Stop
    if($vm.State.ToString() -eq 'Running' -and
       $heartbeat.PrimaryStatusDescription -eq 'OK' -and
       $vm.Uptime.TotalSeconds -ge $healthyBootSeconds){{
      $healthy=$true
      break
    }}
  }} while([DateTime]::UtcNow -lt $deadline)
  if(-not $healthy){{throw "fresh child did not sustain a healthy boot for $healthyBootSeconds seconds"}}

  Stop-VM -VM $vm -ErrorAction Stop | Out-Null
  $deadline=[DateTime]::UtcNow.AddSeconds(120)
  do {{
    Start-Sleep -Seconds 2
    $vm=Get-VM -Id {_ps_quote(target.vm_id)} -ErrorAction Stop
  }} while($vm.State.ToString() -ne 'Off' -and [DateTime]::UtcNow -lt $deadline)
  if($vm.State.ToString() -ne 'Off'){{throw 'fresh VM did not stop cleanly within 120 seconds'}}

  $finalDrives=@(Get-VMHardDiskDrive -VM $vm -ErrorAction Stop)
  if($finalDrives.Count -ne 1 -or -not (Same-Path $finalDrives[0].Path $fresh)){{
    throw 'fresh child is not the sole attached disk after validation'
  }}
  $freshVhd=Get-VHD -Path $fresh -ErrorAction Stop
  if($freshVhd.VhdType.ToString() -ne 'Differencing' -or
     -not (Same-Path $freshVhd.ParentPath $parent)){{throw 'fresh child identity changed during validation'}}

  $afterRefs=@(Disk-References $old)
  if($afterRefs.Count -ne 0){{
    throw "superseded child remains referenced: $($afterRefs | ConvertTo-Json -Compress)"
  }}
  if(-not ([IO.Path]::GetDirectoryName($old)).Equals(
      $oldRoot,[StringComparison]::OrdinalIgnoreCase)){{throw 'old child escaped its validated directory'}}
  $oldVhd=Get-VHD -Path $old -ErrorAction Stop
  if($oldVhd.VhdType.ToString() -ne 'Differencing' -or
     -not (Same-Path $oldVhd.ParentPath $parent)){{throw 'old child identity changed before deletion'}}

  $reclaimed=[int64](Get-Item -LiteralPath $old -ErrorAction Stop).Length
  Remove-Item -LiteralPath $old -Force -ErrorAction Stop
  if(Test-Path -LiteralPath $old){{throw 'superseded child still exists after deletion'}}
  $committed=$true
  [pscustomobject]@{{
    result='reset'
    vm_name=$vm.Name
    vm_id=$vm.VMId.Guid
    state=$vm.State.ToString()
    old_disk=$old
    fresh_disk=$fresh
    parent_disk=$parent
    healthy_boot_seconds=$healthyBootSeconds
    reclaimed_bytes=$reclaimed
    fresh_size_bytes=[int64](Get-Item -LiteralPath $fresh).Length
  }} | ConvertTo-Json -Compress
}}
catch {{
  $primary=$_.Exception.Message
  if($committed){{throw $primary}}
  $recovery=@()
  try {{
    $vm=Get-VM -Id {_ps_quote(target.vm_id)} -ErrorAction Stop
    if($vm.State.ToString() -ne 'Off'){{
      Stop-VM -VM $vm -TurnOff -Force -ErrorAction Stop | Out-Null
      $deadline=[DateTime]::UtcNow.AddSeconds(30)
      do {{
        Start-Sleep -Seconds 1
        $vm=Get-VM -Id {_ps_quote(target.vm_id)} -ErrorAction Stop
      }} while($vm.State.ToString() -ne 'Off' -and [DateTime]::UtcNow -lt $deadline)
      if($vm.State.ToString() -ne 'Off'){{throw 'VM did not turn off for rollback'}}
    }}
    if($old -and (Test-Path -LiteralPath $old -PathType Leaf)){{
      $current=@(Get-VMHardDiskDrive -VM $vm -ErrorAction Stop)
      if($current.Count -ne 1){{throw "rollback found $($current.Count) attached disks"}}
      if(-not (Same-Path $current[0].Path $old)){{
        Set-VMHardDiskDrive -VMHardDiskDrive $current[0] -Path $old -ErrorAction Stop
      }}
    }}
    if($fresh -and (Test-Path -LiteralPath $fresh -PathType Leaf)){{
      $freshRefs=@(Disk-References $fresh)
      if($freshRefs.Count -eq 0){{Remove-Item -LiteralPath $fresh -Force -ErrorAction Stop}}
      else{{throw "rollback left the fresh child referenced: $($freshRefs | ConvertTo-Json -Compress)"}}
    }}
  }} catch {{
    $recovery += $_.Exception.Message
  }}
  if($recovery.Count){{
    throw "SKLAB_RECOVERY_REQUIRED: $primary; rollback failed: $($recovery -join '; ')"
  }}
  throw "$primary; restored the original disk and removed the uncommitted child"
}}
"""


def reset(target: Target) -> dict[str, Any]:
    if not target.disposable:
        raise PrerequisiteError("vm reset requires disposable = true")
    if target.parent_disk is None:
        raise PrerequisiteError("vm reset requires targets.<name>.parent_disk")
    return _invoke(_reset_script(target, target.parent_disk))


def row(value: dict[str, Any]) -> dict[str, Any]:
    size = int(value.get("file_size_bytes", value.get("fresh_size_bytes", 0)))
    return {
        "state": value.get("state", ""),
        "size_gib": f"{size / (1024**3):.3f}",
        "type": value.get("disk_type", "Differencing"),
        "disk": value.get("disk_path", value.get("fresh_disk", "")),
        "parent": value.get("parent_path", value.get("parent_disk", "")),
    }
