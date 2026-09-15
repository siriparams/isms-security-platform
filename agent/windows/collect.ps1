# ============================================================
# ISMS Windows Asset Discovery Agent
# Version: 1.0.0
# ============================================================

$ErrorActionPreference = "Continue"

$AgentVersion = "1.0.0"
$ServerUrl = "http://127.0.0.1:5000/agent/assets"
$AgentApiKey = "isms_agent_2026_secure_key"

$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$AssetFile = Join-Path $ScriptDirectory "asset.json"

Write-Host ""
Write-Host "============================================"
Write-Host " ISMS Windows Asset Discovery Agent"
Write-Host "============================================"
Write-Host ""

# ------------------------------------------------------------
# Helper: safely run a command
# ------------------------------------------------------------
function Invoke-Safe {
    param(
        [scriptblock]$ScriptBlock,
        $Default = $null
    )

    try {
        $result = & $ScriptBlock 2>$null
        if ($null -eq $result) {
            return $Default
        }
        return $result
    }
    catch {
        return $Default
    }
}

# ------------------------------------------------------------
# Discovery timestamp
# ------------------------------------------------------------
$DiscoveryTimestamp = (Get-Date).ToUniversalTime().ToString("o")

# ------------------------------------------------------------
# DEVICE IDENTITY
# ------------------------------------------------------------
$deviceIdentity = [ordered]@{
    SMBIOS_UUID       = $null
    Machine_GUID      = $null
    TPM_Present       = $false
    TPM_Spec_Version  = $null
}

$cs = Invoke-Safe { Get-CimInstance Win32_ComputerSystemProduct }
if ($cs) {
    $deviceIdentity.SMBIOS_UUID = $cs.UUID
}

$machineGuid = Invoke-Safe {
    (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid).MachineGuid
}
if ($machineGuid) {
    $deviceIdentity.Machine_GUID = $machineGuid
}

$tpm = Invoke-Safe { Get-Tpm }
if ($tpm) {
    $deviceIdentity.TPM_Present = [bool]$tpm.TpmPresent

    $tpmSpec = Invoke-Safe {
        (Get-CimInstance -Namespace "root\CIMV2\Security\MicrosoftTpm" `
            -ClassName Win32_Tpm).SpecVersion
    }

    if ($tpmSpec) {
        $deviceIdentity.TPM_Spec_Version = $tpmSpec
    }
}

# ------------------------------------------------------------
# HOST IDENTITY
# ------------------------------------------------------------
$hostname = $env:COMPUTERNAME

$fqdn = Invoke-Safe {
    [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
} $hostname

$domain = Invoke-Safe {
    (Get-CimInstance Win32_ComputerSystem).Domain
} "WORKGROUP"

$hostIdentity = [ordered]@{
    Hostname = $hostname
    FQDN     = $fqdn
    Domain   = $domain
}

# ------------------------------------------------------------
# HARDWARE
# ------------------------------------------------------------
$computerSystem = Invoke-Safe {
    Get-CimInstance Win32_ComputerSystem
}

$bios = Invoke-Safe {
    Get-CimInstance Win32_BIOS
}

$processor = Invoke-Safe {
    Get-CimInstance Win32_Processor | Select-Object -First 1
}

$manufacturer = $null
$model = $null
$ramGB = $null
$cpuName = $null
$serialNumber = $null

if ($computerSystem) {
    $manufacturer = $computerSystem.Manufacturer
    $model = $computerSystem.Model
    $ramGB = [math]::Round(
        ($computerSystem.TotalPhysicalMemory / 1GB),
        2
    )
}

if ($processor) {
    $cpuName = $processor.Name
}

if ($bios) {
    $serialNumber = $bios.SerialNumber
}

$diskInfo = Invoke-Safe {
    Get-CimInstance Win32_DiskDrive |
        Select-Object -First 1
}

$disks = [ordered]@{
    Model        = $null
    SerialNumber = $null
    SizeGB       = $null
}

if ($diskInfo) {
    $disks.Model = $diskInfo.Model
    $disks.SerialNumber = $diskInfo.SerialNumber
    $disks.SizeGB = [math]::Round(
        ($diskInfo.Size / 1GB),
        2
    )
}

$hardware = [ordered]@{
    Manufacturer  = $manufacturer
    Model         = $model
    Serial_Number = $serialNumber
    CPU           = $cpuName
    RAM_GB        = $ramGB
    Disks         = $disks
}

# ------------------------------------------------------------
# NETWORK
# ------------------------------------------------------------
$network = @()

$adapters = Invoke-Safe {
    Get-NetIPConfiguration |
        Where-Object {
            $_.NetAdapter.Status -eq "Up" -and
            $_.NetAdapter.HardwareInterface
        }
}

foreach ($adapter in @($adapters)) {

    $dnsServers = @()

    if ($adapter.DnsServer.ServerAddresses) {
        $dnsServers = @(
            $adapter.DnsServer.ServerAddresses
        )
    }

    $ipAddresses = @()

    if ($adapter.IPv4Address) {
        $ipAddresses = @(
            $adapter.IPv4Address.IPAddress
        )
    }

    $gateways = @()

    if ($adapter.IPv4DefaultGateway) {
        $gateways = @(
            $adapter.IPv4DefaultGateway.NextHop
        )
    }

    $network += [ordered]@{
        Interface   = $adapter.InterfaceAlias
        MAC_Address = $adapter.NetAdapter.MacAddress
        IP_Address  = $ipAddresses
        Gateway     = $gateways
        DNS         = $dnsServers
    }
}

# Fallback for systems where Get-NetIPConfiguration is unavailable
if ($network.Count -eq 0) {

    $legacyAdapters = Invoke-Safe {
        Get-CimInstance Win32_NetworkAdapterConfiguration |
            Where-Object {
                $_.IPEnabled -eq $true
            }
    }

    foreach ($adapter in @($legacyAdapters)) {

        $network += [ordered]@{
            Interface   = $adapter.Description
            MAC_Address = $adapter.MACAddress
            IP_Address  = @($adapter.IPAddress | Where-Object {
                $_ -match "^\d{1,3}(\.\d{1,3}){3}$"
            })
            Gateway     = @($adapter.DefaultIPGateway)
            DNS         = @($adapter.DNSServerSearchOrder)
        }
    }
}

# ------------------------------------------------------------
# OPERATING SYSTEM
# ------------------------------------------------------------
$osInfoCim = Invoke-Safe {
    Get-CimInstance Win32_OperatingSystem
}

$osEdition = $null
$osVersion = $null
$osBuild = $null
$lastBoot = $null

if ($osInfoCim) {

    $osEdition = $osInfoCim.Caption
    $osVersion = $osInfoCim.Version
    $osBuild = $osInfoCim.BuildNumber

    if ($osInfoCim.LastBootUpTime) {

        try {
            $bootDate = [Management.ManagementDateTimeConverter]::ToDateTime(
                $osInfoCim.LastBootUpTime
            )

            $milliseconds = [DateTimeOffset]$bootDate
            $milliseconds = $milliseconds.ToUnixTimeMilliseconds()

            $lastBoot = "/Date($milliseconds)/"
        }
        catch {
            $lastBoot = $null
        }
    }
}

$secureBoot = $null

try {
    if (Confirm-SecureBootUEFI -ErrorAction Stop) {
        $secureBoot = $true
    }
    else {
        $secureBoot = $false
    }
}
catch {
    $secureBoot = $null
}

$os = [ordered]@{
    Edition     = $osEdition
    Version     = $osVersion
    Build       = $osBuild
    Last_Boot   = $lastBoot
    Secure_Boot = $secureBoot
}

# ------------------------------------------------------------
# MANAGEMENT
# ------------------------------------------------------------
$management = @()

$management += [ordered]@{
    Name          = "Windows Management"
    Present       = $true
    Version       = $null
    Last_Check_In = $null
}

$intunePresent = $false

$intunePaths = @(
    "HKLM:\SOFTWARE\Microsoft\Enrollments",
    "HKLM:\SOFTWARE\Microsoft\PolicyManager"
)

foreach ($path in $intunePaths) {
    if (Test-Path $path) {
        $intunePresent = $true
        break
    }
}

$management += [ordered]@{
    Name          = "MDM / Intune"
    Present       = $intunePresent
    Version       = $null
    Last_Check_In = $null
}

# ------------------------------------------------------------
# SECURITY POSTURE
# ------------------------------------------------------------

# Firewall
$firewallProfiles = @()

$profiles = Invoke-Safe {
    Get-NetFirewallProfile
}

foreach ($profile in @($profiles)) {
    $firewallProfiles += [ordered]@{
        Profile = $profile.Name
        Enabled = if ($profile.Enabled) { 1 } else { 0 }
    }
}

# Antivirus / EDR
$antivirus = $null

$securityProducts = Invoke-Safe {
    Get-CimInstance `
        -Namespace "root\SecurityCenter2" `
        -ClassName AntiVirusProduct
}

if ($securityProducts) {

    $product = @($securityProducts) | Select-Object -First 1

    if ($product) {
        $antivirus = [ordered]@{
            DisplayName               = $product.displayName
            ProductState               = $product.productState
            PathToSignedProductExe     = $product.pathToSignedProductExe
        }
    }
}

# Windows Update status
$updateStatus = $null

try {

    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()

    $searchResult = $updateSearcher.Search(
        "IsInstalled=0 and IsHidden=0"
    )

    $pendingUpdates = $searchResult.Updates.Count

    if ($pendingUpdates -eq 0) {
        $updateStatus = "No updates pending"
    }
    elseif ($pendingUpdates -eq 1) {
        $updateStatus = "1 update pending"
    }
    else {
        $updateStatus = "$pendingUpdates updates pending"
    }
}
catch {
    $updateStatus = "Unable to determine update status"
}

# BitLocker / Encryption
# IMPORTANT:
# Get-BitLockerVolume can produce Access Denied on some Windows systems.
# We intentionally suppress that error so asset collection continues.
$encryption = @()

try {

    $bitlockerVolumes = Get-BitLockerVolume -ErrorAction Stop

    foreach ($volume in @($bitlockerVolumes)) {

        $encryption += [ordered]@{
            MountPoint          = $volume.MountPoint
            VolumeStatus        = "$($volume.VolumeStatus)"
            ProtectionStatus    = "$($volume.ProtectionStatus)"
            EncryptionMethod    = "$($volume.EncryptionMethod)"
            EncryptionPercentage = $volume.EncryptionPercentage
        }
    }
}
catch {
    # Leave Encryption as an empty array.
}

# Local administrators
$localAdministrators = @()

try {

    $adminMembers = Get-LocalGroupMember `
        -Group "Administrators" `
        -ErrorAction Stop

    foreach ($member in @($adminMembers)) {

        $localAdministrators += [ordered]@{
            Name       = $member.Name
            ObjectClass = "$($member.ObjectClass)"
        }
    }
}
catch {

    # Fallback using WinNT provider
    try {

        $group = [ADSI]"WinNT://./Administrators,group"

        foreach ($member in @($group.Invoke("Members"))) {

            $name = $member.GetType().InvokeMember(
                "Name",
                "GetProperty",
                $null,
                $member,
                $null
            )

            $class = $member.GetType().InvokeMember(
                "Class",
                "GetProperty",
                $null,
                $member,
                $null
            )

            $localAdministrators += [ordered]@{
                Name        = "$env:COMPUTERNAME\$name"
                ObjectClass = "$class"
            }
        }
    }
    catch {
        # Keep empty if access is restricted.
    }
}

$securityPosture = [ordered]@{
    Firewall = $firewallProfiles
    Antivirus_EDR = $antivirus
    Update_Status = $updateStatus
    Encryption = $encryption
    Local_Administrators = $localAdministrators
}

# ------------------------------------------------------------
# SOFTWARE
# ------------------------------------------------------------
$software = @()

$uninstallPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($path in $uninstallPaths) {

    $installed = Invoke-Safe {
        Get-ItemProperty $path |
            Where-Object {
                $_.DisplayName
            }
    }

    foreach ($item in @($installed)) {

        $software += [ordered]@{
            Name      = "$($item.DisplayName)"
            Version   = "$($item.DisplayVersion)"
            Publisher = "$($item.Publisher)"
        }
    }
}

# Remove duplicate software entries
$software = @(
    $software |
        Group-Object {
            "$($_.Name)|$($_.Version)|$($_.Publisher)"
        } |
        ForEach-Object {
            $_.Group | Select-Object -First 1
        }
)

# ------------------------------------------------------------
# USER CONTEXT
# ------------------------------------------------------------
$currentUser = $env:USERNAME
$lastLoggedUser = $null
$userDomain = $env:USERDOMAIN

$lastLoggedUser = Invoke-Safe {
    (Get-CimInstance Win32_ComputerSystem).UserName
}

if (-not $lastLoggedUser) {
    $lastLoggedUser = "$env:USERDOMAIN\$env:USERNAME"
}

$userContext = [ordered]@{
    Current_User     = $currentUser
    Last_Logged_User = $lastLoggedUser
    Domain           = $userDomain
}

# ------------------------------------------------------------
# COMPLETE ASSET OBJECT
# ------------------------------------------------------------
$asset = [ordered]@{
    discovery_timestamp = $DiscoveryTimestamp
    platform             = "Windows"
    device_identity      = $deviceIdentity
    host_identity        = $hostIdentity
    hardware             = $hardware
    network              = @($network)
    os                   = $os
    management           = @($management)
    security_posture     = $securityPosture
    software             = @($software)
    user_context         = $userContext
    agent_version        = $AgentVersion
}

# ------------------------------------------------------------
# WRITE ASSET JSON
# ------------------------------------------------------------
try {

    $json = $asset | ConvertTo-Json -Depth 12

    $json | Set-Content `
        -Path $AssetFile `
        -Encoding UTF8

    Write-Host "============================================"
    Write-Host " Asset Discovery Completed"
    Write-Host "============================================"
    Write-Host ""
    Write-Host "Agent Version: $AgentVersion"
    Write-Host "Asset JSON created:"
    Write-Host $AssetFile
    Write-Host ""

}
catch {

    Write-Host ""
    Write-Host "Failed to create asset.json"
    Write-Host $_.Exception.Message
    exit 1
}

# ------------------------------------------------------------
# SEND ASSET TO ISMS SERVER
# ------------------------------------------------------------
Write-Host "============================================"
Write-Host " Sending asset to ISMS server..."
Write-Host "============================================"
Write-Host ""

try {

    $headers = @{
        "X-Agent-API-Key" = $AgentApiKey
    }

    # PowerShell 5.1 may encode a string body using the system code page.
    # Send explicit UTF-8 bytes so Flask can always decode the JSON correctly.
    $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($json)

    $response = Invoke-RestMethod `
        -Uri $ServerUrl `
        -Method Post `
        -Headers $headers `
        -ContentType "application/json; charset=utf-8" `
        -Body $jsonBytes `
        -ErrorAction Stop

    Write-Host ""
    Write-Host "============================================"
    Write-Host " Asset sent successfully"
    Write-Host "============================================"
    Write-Host ""

    if ($response.asset_id) {
        Write-Host "Asset ID: $($response.asset_id)"
    }

    if ($response.message) {
        Write-Host "Server: $($response.message)"
    }

    Write-Host ""

}
catch {

    Write-Host ""
    Write-Host "============================================"
    Write-Host " Failed to send asset to ISMS server"
    Write-Host "============================================"
    Write-Host ""

    if ($_.ErrorDetails.Message) {
        Write-Host $_.ErrorDetails.Message
    }
    else {
        Write-Host $_.Exception.Message
    }

    Write-Host ""
    Write-Host "Make sure Flask is running at:"
    Write-Host $ServerUrl
    Write-Host ""
}
