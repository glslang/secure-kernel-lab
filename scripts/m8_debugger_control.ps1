[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Break', 'Reset', 'Command')]
    [string] $Action,

    [Parameter(Mandatory = $true)]
    [uint32] $DebuggerPid,

    [string] $Text
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Authenticate the exact process accepted by the facade, then walk only its parent chain to the
# window-bearing frontend. This prevents a qualification callback from sending input to an
# unrelated debugger window.
$authenticated = Get-Process -Id $DebuggerPid -ErrorAction Stop
$windowProcess = $authenticated
for ($depth = 0; $windowProcess.MainWindowHandle -eq 0 -and $depth -lt 8; $depth++) {
    $row = Get-CimInstance Win32_Process -Filter "ProcessId=$($windowProcess.Id)" -ErrorAction Stop
    if (-not $row.ParentProcessId) {
        break
    }
    $windowProcess = Get-Process -Id ([uint32] $row.ParentProcessId) -ErrorAction Stop
}
if ($windowProcess.MainWindowHandle -eq 0) {
    throw "authenticated debugger PID $DebuggerPid has no window-bearing ancestor"
}

$shell = New-Object -ComObject WScript.Shell
if (-not $shell.AppActivate($windowProcess.Id)) {
    throw "could not activate debugger window PID $($windowProcess.Id) for authenticated PID $DebuggerPid"
}
Start-Sleep -Milliseconds 150

switch ($Action) {
    'Break' {
        # Ctrl+Break is VK_CANCEL. This control is retained for the optional non-gating race rig;
        # the breakpoint-only M8 product qualification does not invoke it.
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SklabM8KeyboardInput {
    [DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr window, int command);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr window);
    [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr window);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
    [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint source, uint target, bool attach);
    [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
    [DllImport("user32.dll")] public static extern void keybd_event(byte key, byte scan, uint flags, UIntPtr extra);
}
'@
        $targetOwner = [uint32] 0
        $targetThread = [SklabM8KeyboardInput]::GetWindowThreadProcessId(
            $windowProcess.MainWindowHandle,
            [ref] $targetOwner
        )
        $foregroundWindow = [SklabM8KeyboardInput]::GetForegroundWindow()
        $foregroundOwner = [uint32] 0
        $foregroundThread = [SklabM8KeyboardInput]::GetWindowThreadProcessId(
            $foregroundWindow,
            [ref] $foregroundOwner
        )
        $injectorThread = [SklabM8KeyboardInput]::GetCurrentThreadId()
        $attached = @()
        try {
            foreach ($thread in @($foregroundThread, $targetThread) | Select-Object -Unique) {
                if ($thread -ne 0 -and $thread -ne $injectorThread) {
                    if (-not [SklabM8KeyboardInput]::AttachThreadInput($injectorThread, $thread, $true)) {
                        throw "could not attach the injector input queue to UI thread $thread"
                    }
                    $attached += $thread
                }
            }
            [void] [SklabM8KeyboardInput]::ShowWindowAsync($windowProcess.MainWindowHandle, 9)
            [void] [SklabM8KeyboardInput]::BringWindowToTop($windowProcess.MainWindowHandle)
            [void] [SklabM8KeyboardInput]::SetForegroundWindow($windowProcess.MainWindowHandle)
            Start-Sleep -Milliseconds 100
            if ([SklabM8KeyboardInput]::GetForegroundWindow() -ne $windowProcess.MainWindowHandle) {
                throw "authenticated debugger PID $DebuggerPid did not own the foreground before VK_CANCEL"
            }
            [SklabM8KeyboardInput]::keybd_event(0x11, 0x1d, 0, [UIntPtr]::Zero)
            [SklabM8KeyboardInput]::keybd_event(0x03, 0x46, 1, [UIntPtr]::Zero)
            [SklabM8KeyboardInput]::keybd_event(0x03, 0x46, 3, [UIntPtr]::Zero)
            [SklabM8KeyboardInput]::keybd_event(0x11, 0x1d, 2, [UIntPtr]::Zero)
        }
        finally {
            foreach ($thread in $attached) {
                [void] [SklabM8KeyboardInput]::AttachThreadInput($injectorThread, $thread, $false)
            }
        }
        Write-Output "sent_extended_ctrl_break=true foreground=$($windowProcess.MainWindowHandle)"
    }
    'Reset' {
        # Retained for the optional non-gating reset/race rig.
        $shell.SendKeys('^%r')
    }
    'Command' {
        if ([string]::IsNullOrWhiteSpace($Text)) {
            throw 'Command delivery requires non-empty -Text'
        }
        Add-Type -AssemblyName UIAutomationClient
        Add-Type -AssemblyName UIAutomationTypes
        $id = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::AutomationIdProperty,
            'CommandInputTextBox'
        )
        $type = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
            [System.Windows.Automation.ControlType]::Edit
        )
        $selector = if ($windowProcess.ProcessName -ieq 'windbg') {
            $type
        }
        else {
            New-Object System.Windows.Automation.AndCondition($id, $type)
        }
        $input = $null
        $deadline = [DateTime]::UtcNow.AddSeconds(20)
        do {
            $root = [System.Windows.Automation.AutomationElement]::FromHandle(
                $windowProcess.MainWindowHandle
            )
            foreach ($candidate in $root.FindAll(
                [System.Windows.Automation.TreeScope]::Descendants,
                $selector
            )) {
                try {
                    $value = $candidate.GetCurrentPattern(
                        [System.Windows.Automation.ValuePattern]::Pattern
                    )
                    if (-not $value.Current.IsReadOnly) {
                        $candidate.SetFocus()
                        $value.SetValue($Text)
                        $input = $candidate
                        break
                    }
                }
                catch {
                    continue
                }
            }
            if ($null -eq $input) {
                Start-Sleep -Milliseconds 250
            }
        } while ($null -eq $input -and [DateTime]::UtcNow -lt $deadline)
        if ($null -eq $input) {
            throw "debugger window PID $($windowProcess.Id) did not expose a writable command input within 20 seconds"
        }
        Start-Sleep -Milliseconds 200
        $shell.SendKeys('{ENTER}')
        Start-Sleep -Milliseconds 500
        Write-Output "sent=$Text"
    }
}

Start-Sleep -Milliseconds 150
if (-not (Get-Process -Id $DebuggerPid -ErrorAction SilentlyContinue)) {
    throw "authenticated debugger PID $DebuggerPid exited while sending $Action"
}
