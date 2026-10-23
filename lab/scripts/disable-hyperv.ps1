# Run as Administrator. Turns off the Hyper-V launch at boot, disables Memory integrity,
# and excludes the VirtualBox VM folder from Microsoft Defender.
# Revert after the thesis lab is no longer needed:
#   bcdedit /set hypervisorlaunchtype auto
#   reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 1 /f
# Then reboot. Remove the Defender exclusion with:
#   Remove-MpPreference -ExclusionPath "D:\virtual_machine"
$ErrorActionPreference = "Continue"
$log = "C:\Users\fraktor\AppData\Local\Temp\nixfort-hyperv-off.txt"
function Log([string]$line) {
    Write-Output $line
    Add-Content -Path $log -Value $line
}
Set-Content -Path $log -Value "=== nixfort disable hypervisor $(Get-Date -Format o) ==="

Log "=== bcdedit /set hypervisorlaunchtype off ==="
& bcdedit /set hypervisorlaunchtype off
Log "bcdedit_exit=$LASTEXITCODE"

Log "=== DeviceGuard HypervisorEnforcedCodeIntegrity Enabled=0 ==="
& reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f
Log "reg_exit=$LASTEXITCODE"

Log "=== Add-MpPreference ExclusionPath D:\virtual_machine ==="
try {
    Add-MpPreference -ExclusionPath "D:\virtual_machine"
    Log "defender_exit=0"
} catch {
    Log "defender_exit=FAIL $($_.Exception.Message)"
}

Log "=== verify bcdedit ==="
& bcdedit /enum "{current}" | Select-String hypervisorlaunchtype | ForEach-Object { Log $_.Line }
Log "=== verify registry ==="
& reg query "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled | ForEach-Object { Log $_ }
Log "=== verify defender exclusions ==="
try {
    $paths = (Get-MpPreference).ExclusionPath
    if ($paths) { $paths | ForEach-Object { Log $_ } } else { Log "(no exclusions)" }
} catch {
    Log "defender_query_FAIL $($_.Exception.Message)"
}
Log "=== done ==="
