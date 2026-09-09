# ============================================
# ISMS Asset Discovery Agent - Windows
# ============================================

$ErrorActionPreference = "SilentlyContinue"

# Output file will be created beside this script
$outputFile = Join-Path $PSScriptRoot "asset.json"


# --------------------------------------------
# DEVICE / HOST INFORMATION
# --------------------------------------------

$computerSystem = Get-CimInstance Win32_ComputerSystem
$computerBIOS = Get-CimInstance Win32_BIOS
$computerOS = Get-CimInstance Win32_OperatingSystem


# Device Identity
$deviceUUID = (Get-CimInstance Win32_ComputerSystemProduct).UUID

# Machine GUID
$machineGUID = (Get-ItemProperty `
    "HKLM:\SOFTWARE\Microsoft\Cryptography").MachineGuid

# TPM information
$tpm = Get-Tpm

if ($tpm.TpmPresent) {
    $tpmPresent = $true
    $tpmVersion = (Get-CimInstance -Namespace "root\CIMV2\Security\MicrosoftTpm" `
        -ClassName Win32_Tpm).SpecVersion
}
else {
    $tpmPresent = $false
    $tpmVersion = $null
}


# --------------------------------------------
# HOST IDENTITY
# --------------------------------------------

$hostname = $env:COMPUTERNAME

try {
    $fqdn = [System.Net.Dns]::GetHostByName($hostname).HostName
}
catch {
    $fqdn = $hostname
}

$domain = $computerSystem.Domain


# --------------------------------------------
# HARDWARE
# --------------------------------------------

$manufacturer = $computerSystem.Manufacturer
$model = $computerSystem.Model
$serialNumber = $computerBIOS.SerialNumber

$cpu = (Get-CimInstance Win32_Processor |
    Select-Object -First 1).Name

$ramGB = [math]::Round(
    $computerSystem.TotalPhysicalMemory / 1GB,
    2
)

$disks = Get-CimInstance Win32_DiskDrive |
    Select-Object Model, SerialNumber,
    @{Name="SizeGB";Expression={
        [math]::Round($_.Size / 1GB, 2)
    }}


# --------------------------------------------
# NETWORK
# --------------------------------------------

$networkAdapters = Get-NetIPConfiguration |
    Where-Object {
        $_.NetAdapter.Status -eq "Up"
    }

$networkInformation = @()

foreach ($adapter in $networkAdapters) {

    $networkInformation += [PSCustomObject]@{
        Interface = $adapter.InterfaceAlias

        MAC_Address = $adapter.NetAdapter.MacAddress

        IP_Address = @(
            $adapter.IPv4Address.IPAddress
        )

        Gateway = @(
            $adapter.IPv4DefaultGateway.NextHop
        )

        DNS = @(
            $adapter.DNSServer.ServerAddresses
        )
    }
}


# --------------------------------------------
# OPERATING SYSTEM
# --------------------------------------------

$osEdition = $computerOS.Caption
$osVersion = $computerOS.Version
$osBuild = $computerOS.BuildNumber

$lastBoot = $computerOS.LastBootUpTime

# Secure Boot
try {
    $secureBoot = Confirm-SecureBootUEFI
}
catch {
    $secureBoot = $null
}


# --------------------------------------------
# MANAGEMENT
# --------------------------------------------

$managementAgents = @()

# Intune / MDM enrollment
$mdmPath = "HKLM:\SOFTWARE\Microsoft\Enrollments"

$mdmPresent = Test-Path $mdmPath

# Windows management information
$managementAgents += [PSCustomObject]@{
    Name = "Windows Management"
    Present = $true
    Version = $null
    Last_Check_In = $null
}

if ($mdmPresent) {

    $managementAgents += [PSCustomObject]@{
        Name = "MDM / Intune"
        Present = $true
        Version = $null
        Last_Check_In = $null
    }
}


# --------------------------------------------
# SECURITY POSTURE
# --------------------------------------------

# Firewall
$firewallProfiles = Get-NetFirewallProfile

$firewallStatus = @()

foreach ($profile in $firewallProfiles) {

    $firewallStatus += [PSCustomObject]@{
        Profile = $profile.Name
        Enabled = $profile.Enabled
    }
}


# Antivirus / EDR
$securityProducts = @()

try {

    $securityProducts = Get-CimInstance `
        -Namespace "root\SecurityCenter2" `
        -ClassName AntiVirusProduct |
        Select-Object DisplayName, ProductState, PathToSignedProductExe

}
catch {
    $securityProducts = @()
}


# Windows Update status
$updateStatus = "Unknown"

try {

    $updateSession = New-Object -ComObject Microsoft.Update.Session

    $searcher = $updateSession.CreateUpdateSearcher()

    $updates = $searcher.Search(
        "IsInstalled=0 and IsHidden=0"
    )

    if ($updates.Updates.Count -eq 0) {
        $updateStatus = "Up to date"
    }
    else {
        $updateStatus = "$($updates.Updates.Count) updates pending"
    }

}
catch {
    $updateStatus = "Unable to determine"
}


# BitLocker / Encryption
$encryption = @()

try {

    $bitlockerVolumes = Get-BitLockerVolume

    foreach ($volume in $bitlockerVolumes) {

        $encryption += [PSCustomObject]@{
            Drive = $volume.MountPoint
            ProtectionStatus = $volume.ProtectionStatus.ToString()
            EncryptionMethod = $volume.EncryptionMethod.ToString()
        }
    }

}
catch {
    $encryption = @()
}


# Local administrators
$localAdmins = @()

try {

    $localAdmins = Get-LocalGroupMember `
        -Group "Administrators" |
        Select-Object Name, ObjectClass

}
catch {
    $localAdmins = @()
}


# --------------------------------------------
# SOFTWARE
# --------------------------------------------

$software = @()

$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($path in $registryPaths) {

    $installedPrograms = Get-ItemProperty $path

    foreach ($program in $installedPrograms) {

        if ($program.DisplayName) {

            $software += [PSCustomObject]@{
                Name = $program.DisplayName
                Version = $program.DisplayVersion
                Publisher = $program.Publisher
            }
        }
    }
}


# Remove duplicate software entries
$software = $software |
    Sort-Object Name, Version -Unique


# --------------------------------------------
# USER CONTEXT
# --------------------------------------------

$lastLoggedUser = $computerSystem.UserName

$currentUser = $env:USERNAME

$userDomain = $env:USERDOMAIN

$userContext = [PSCustomObject]@{
    Current_User = $currentUser
    Last_Logged_User = $lastLoggedUser
    Domain = $userDomain
}


# --------------------------------------------
# FINAL ASSET OBJECT
# --------------------------------------------

$asset = [PSCustomObject]@{

    discovery_timestamp = (Get-Date).ToUniversalTime().ToString("o")

    platform = "Windows"


    device_identity = [PSCustomObject]@{
        SMBIOS_UUID = $deviceUUID
        Machine_GUID = $machineGUID
        TPM_Present = $tpmPresent
        TPM_Spec_Version = $tpmVersion
    }


    host_identity = [PSCustomObject]@{
        Hostname = $hostname
        FQDN = $fqdn
        Domain = $domain
    }


    hardware = [PSCustomObject]@{
        Manufacturer = $manufacturer
        Model = $model
        Serial_Number = $serialNumber
        CPU = $cpu
        RAM_GB = $ramGB
        Disks = $disks
    }


    network = $networkInformation


    os = [PSCustomObject]@{
        Edition = $osEdition
        Version = $osVersion
        Build = $osBuild
        Last_Boot = $lastBoot
        Secure_Boot = $secureBoot
    }


    management = $managementAgents


    security_posture = [PSCustomObject]@{
        Firewall = $firewallStatus
        Antivirus_EDR = $securityProducts
        Update_Status = $updateStatus
        Encryption = $encryption
        Local_Administrators = $localAdmins
    }


    software = $software


    user_context = $userContext
}


# --------------------------------------------
# WRITE JSON FILE
# --------------------------------------------

$asset |
    ConvertTo-Json -Depth 10 |
    Out-File $outputFile -Encoding utf8


Write-Host ""
Write-Host "============================================"
Write-Host " ISMS Asset Discovery Completed"
Write-Host "============================================"
Write-Host ""
Write-Host "Asset JSON created:"
Write-Host $outputFile
Write-Host ""