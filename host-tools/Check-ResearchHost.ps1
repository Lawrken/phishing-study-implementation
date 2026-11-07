<#
Read-only Windows candidate-host check. No elevation, installation, network
requests, VM start, boot edits, file writes, or security-setting changes.
Run only with the computer owner's permission. Output omits names, serial
numbers, IP addresses and recovery keys. Resource targets are planning buffers;
this report cannot approve collection or establish stable VM timing.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$taskReadErrors = @()
$taskOs = $null
$taskComputer = $null
$taskProcessors = @()
$taskGuard = $null
$taskDisk = $null
try { $taskOs = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop }
catch { $taskReadErrors += 'Operating-system information unavailable.' }
try { $taskComputer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop }
catch { $taskReadErrors += 'RAM and hypervisor information unavailable.' }
try { $taskProcessors = @(Get-CimInstance Win32_Processor -ErrorAction Stop) }
catch { $taskReadErrors += 'Processor information unavailable.' }
try {
    $taskGuard = Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
} catch { $taskReadErrors += 'VBS information unavailable; do not assume it is disabled.' }
try {
    $taskSystemDrive = $env:SystemDrive
    if ($taskSystemDrive -notmatch '^[A-Za-z]:$') { throw 'Unrecognized system drive.' }
    $taskDisk = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='" + $taskSystemDrive + "'") -ErrorAction Stop
} catch { $taskReadErrors += 'System-drive free space unavailable.' }

$taskTotalRam = $null
$taskAvailableRam = $null
$taskFreeDisk = $null
$taskLogicalCpus = $null
$taskArchitecture = $null
if ($taskComputer) {
    $taskTotalRam = [Math]::Round($taskComputer.TotalPhysicalMemory / 1GB, 2)
    $taskLogicalCpus = [int]$taskComputer.NumberOfLogicalProcessors
}
if ($taskOs) { $taskAvailableRam = [Math]::Round($taskOs.FreePhysicalMemory / 1MB, 2) }
if ($taskDisk) { $taskFreeDisk = [Math]::Round($taskDisk.FreeSpace / 1GB, 2) }
if ($taskProcessors.Count -gt 0) { $taskArchitecture = @($taskProcessors | ForEach-Object { [int]$_.Architecture } | Select-Object -Unique) }
$taskX64 = $null
if ($null -ne $taskArchitecture -and $taskArchitecture.Count -gt 0) {
    $taskX64 = ($taskArchitecture.Count -eq 1 -and $taskArchitecture[0] -eq 9)
}
$taskResourcesKnown = ($null -ne $taskAvailableRam -and $null -ne $taskFreeDisk -and $null -ne $taskLogicalCpus)
$taskResourceTargetsMet = $null
if ($taskResourcesKnown) {
    $taskResourceTargetsMet = ($taskAvailableRam -ge 5 -and $taskFreeDisk -ge 50 -and $taskLogicalCpus -ge 4)
}
$taskVBoxVersion = $null
try {
    $taskProgramFiles = [Environment]::GetFolderPath('ProgramFiles')
    $taskVBox = Join-Path $taskProgramFiles 'Oracle/VirtualBox/VBoxManage.exe'
    if (Test-Path -LiteralPath $taskVBox) { $taskVBoxVersion = (Get-Item -LiteralPath $taskVBox).VersionInfo.FileVersion }
} catch { $taskReadErrors += 'Installed VirtualBox version unavailable.' }
$taskReport = [ordered]@{
    schema=1
    purpose='Read-only candidate-host planning information'
    utc=[DateTimeOffset]::UtcNow.ToString('o')
    os_caption=if ($taskOs) { $taskOs.Caption } else { $null }
    os_build=if ($taskOs) { $taskOs.BuildNumber } else { $null }
    x64_processor=$taskX64
    processor_architecture_codes=$taskArchitecture
    logical_cpus=$taskLogicalCpus
    total_usable_ram_gib=$taskTotalRam
    available_ram_gib=$taskAvailableRam
    system_drive_free_gib=$taskFreeDisk
    hypervisor_present=if ($taskComputer) { [bool]$taskComputer.HypervisorPresent } else { $null }
    vbs_status=if ($taskGuard) { $taskGuard.VirtualizationBasedSecurityStatus } else { $null }
    security_services_running=if ($taskGuard) { @($taskGuard.SecurityServicesRunning) } else { $null }
    virtualization_firmware_flags=@($taskProcessors | ForEach-Object { $_.VirtualizationFirmwareEnabled })
    installed_virtualbox_file_version=$taskVBoxVersion
    planning_targets=[ordered]@{available_ram_gib=5;free_disk_gib=50;logical_cpus=4;existing_vm_ram_gib=4;existing_vm_cpus=2}
    resource_targets_met=$taskResourceTargetsMet
    interpretation='Targets are working buffers. Hypervisor presence alone does not prove failure. Runtime stability and full source-bound deployment verification are still required.'
    read_errors=$taskReadErrors
    research_collection_approved=$false
    timing_verified=$false
    changes_performed=$false
    network_requests_performed=$false
}
$taskReport | ConvertTo-Json -Depth 7
