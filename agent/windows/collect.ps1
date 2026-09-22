# ============================================================
# ISMS WINDOWS ASSET DISCOVERY AGENT
# ============================================================

$ErrorActionPreference = "Continue"

# ------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------

$AgentVersion = "1.0.0"

$ServerUrl = "http://127.0.0.1:5000/agent/assets"

$AgentApiKey = "isms_agent_2026_secure_key"

$OutputFile = Join-Path $PSScriptRoot "asset.json"

# ------------------------------------------------------------
# SAFE EXECUTION HELPER
# ------------------------------------------------------------

function Invoke-Safe {
    param (
        [scriptblock]$Script
    )

    try {
        return & $Script
    }
    catch {
        return $null
    }
}

# ------------------------------------------------------------
# START
# ------------------------------------------------------------

Write-Host ""
Write-Host "============================================"
Write-Host " ISMS Windows Asset Discovery Agent"
Write-Host "============================================"
Write-Host ""

$DiscoveryTimestamp = (Get-Date).ToUniversalTime().ToString("o")

# ============================================================
# DEVICE IDENTITY
# ============================================================

$deviceIdentity = [ordered]@{
    SMBIOS_UUID          = $null
    Machine_GUID         = $null
    TPM_Present          = $false
    TPM_Spec_Version     = $null
    TPM_EK_PublicKeyHash = $null
}

# SMBIOS UUID

$computerProduct = Invoke-Safe {
    Get-CimInstance Win32_ComputerSystemProduct
}

if ($computerProduct) {
    $deviceIdentity.SMBIOS_UUID = $computerProduct.UUID
}

# Machine GUID

$machineGuid = Invoke-Safe {
    Get-ItemProperty `
        -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" `
        -Name "MachineGuid"
}

if ($machineGuid) {
    $deviceIdentity.Machine_GUID = $machineGuid.MachineGuid
}

# TPM

$tpm = Invoke-Safe {
    Get-Tpm
}

if ($tpm) {

    $deviceIdentity.TPM_Present = [bool]$tpm.TpmPresent

    $tpmInfo = Invoke-Safe {
        Get-CimInstance `
            -Namespace "root\CIMV2\Security\MicrosoftTpm" `
            -ClassName Win32_Tpm
    }

    if ($tpmInfo) {
        $deviceIdentity.TPM_Spec_Version = $tpmInfo.SpecVersion
    }

    # TPM Endorsement Key information
    if ($deviceIdentity.TPM_Present) {

        $tpmEk = Invoke-Safe {
            Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256
        }

        if ($tpmEk) {

            if ($tpmEk.PublicKeyHash) {
                $deviceIdentity.TPM_EK_PublicKeyHash =
                    [string]$tpmEk.PublicKeyHash
            }
        }
    }
}

# ============================================================
# HOST IDENTITY
# ============================================================

$computerSystem = Invoke-Safe {
    Get-CimInstance Win32_ComputerSystem
}

$hostname = $env:COMPUTERNAME

$fqdn = $null

try {
    $fqdn = [System.Net.Dns]::GetHostEntry($hostname).HostName
}
catch {
    $fqdn = $hostname
}

$domain = $null
$domainJoined = $false

if ($computerSystem) {

    $domain = $computerSystem.Domain

    $domainJoined = [bool]$computerSystem.PartOfDomain
}

$hostIdentity = [ordered]@{
    Hostname        = $hostname
    FQDN            = $fqdn
    Domain          = $domain
    Local_Device_Name = $hostname
    Domain_Joined   = $domainJoined
}

# ============================================================
# HARDWARE
# ============================================================

$hardware = [ordered]@{
    Manufacturer = $null
    Model        = $null
    Serial_Number = $null
    CPU          = @()
    RAM_GB       = $null
    Disks        = @()
}

if ($computerSystem) {

    $hardware.Manufacturer = $computerSystem.Manufacturer
    $hardware.Model = $computerSystem.Model

    if ($computerSystem.TotalPhysicalMemory) {

        $hardware.RAM_GB = [math]::Round(
            $computerSystem.TotalPhysicalMemory / 1GB,
            2
        )
    }
}

$bios = Invoke-Safe {
    Get-CimInstance Win32_BIOS
}

if ($bios) {
    $hardware.Serial_Number = $bios.SerialNumber
}

# CPU

$processors = Invoke-Safe {
    Get-CimInstance Win32_Processor
}

foreach ($processor in @($processors)) {

    $hardware.CPU += [ordered]@{
        Name             = $processor.Name
        Manufacturer     = $processor.Manufacturer
        Cores            = $processor.NumberOfCores
        LogicalProcessors = $processor.NumberOfLogicalProcessors
    }
}

# Disks

$diskInfo = Invoke-Safe {
    Get-CimInstance Win32_DiskDrive
}

foreach ($disk in @($diskInfo)) {

    $diskSizeGB = $null

    if ($disk.Size) {
        $diskSizeGB = [math]::Round(
            $disk.Size / 1GB,
            2
        )
    }

    $hardware.Disks += [ordered]@{
        Model        = $disk.Model
        Manufacturer = $disk.Manufacturer
        Serial_Number = $disk.SerialNumber
        Size_GB      = $diskSizeGB
        Interface    = $disk.InterfaceType
    }
}

# ============================================================
# NETWORK
# ============================================================

$network = @()

$ipConfigurations = Invoke-Safe {
    Get-NetIPConfiguration
}

foreach ($adapter in @($ipConfigurations)) {

    if (-not $adapter) {
        continue
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

    $dnsServers = @()

    if ($adapter.DNSServer) {

        $dnsServers = @(
            $adapter.DNSServer.ServerAddresses
        )
    }

    $network += [ordered]@{
        Interface   = $adapter.InterfaceAlias
        MAC_Address = if ($adapter.NetAdapter) {
            $adapter.NetAdapter.MacAddress
        }
        else {
            $null
        }
        IP_Address  = $ipAddresses
        Gateway     = $gateways
        DNS         = $dnsServers
    }
}

# Fallback

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

            IP_Address  = @(
                $adapter.IPAddress |
                    Where-Object {
                        $_ -match "^\\d{1,3}(\\.\\d{1,3}){3}$"
                    }
            )

            Gateway = @(
                $adapter.DefaultIPGateway
            )

            DNS = @(
                $adapter.DNSServerSearchOrder
            )
        }
    }
}

# ============================================================
# OPERATING SYSTEM
# ============================================================

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

            $bootDate = [DateTime]$osInfoCim.LastBootUpTime

            $lastBoot = $bootDate.ToUniversalTime().ToString("o")
        }
        catch {

            $lastBoot = $null
        }
    }
}

# ============================================================
# SECURE BOOT
# ============================================================

$secureBoot = $null

try {

    $secureBootResult =
        Confirm-SecureBootUEFI -ErrorAction Stop

    $secureBoot = [bool]$secureBootResult
}
catch {

    try {

        $secureBootRegistry =
            Get-ItemProperty `
                -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" `
                -Name "UEFISecureBootEnabled" `
                -ErrorAction Stop

        $secureBootValue =
            [int]$secureBootRegistry.UEFISecureBootEnabled

        if ($secureBootValue -eq 1) {

            $secureBoot = $true
        }
        elseif ($secureBootValue -eq 0) {

            $secureBoot = $false
        }
    }
    catch {

        $secureBoot = $null
    }
}

$os = [ordered]@{
    Edition     = $osEdition
    Version     = $osVersion
    Build       = $osBuild
    Last_Boot   = $lastBoot
    Secure_Boot = $secureBoot
}

# ============================================================
# MANAGEMENT
# ============================================================

$management = @()

$management += [ordered]@{
    Name          = "Windows Management"
    Present       = $true
    Agent_Version = $AgentVersion
    Last_Check_In = $DiscoveryTimestamp
}

# MDM / Intune

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

# ============================================================
# SECURITY POSTURE
# ============================================================

# ------------------------------------------------------------
# FIREWALL
# ------------------------------------------------------------

$firewallProfiles = @()

$profiles = Invoke-Safe {
    Get-NetFirewallProfile
}

foreach ($profile in @($profiles)) {

    $firewallProfiles += [ordered]@{
        Profile = $profile.Name
        Enabled = if ($profile.Enabled) {
            $true
        }
        else {
            $false
        }
    }
}

# ------------------------------------------------------------
# ANTIVIRUS / EDR
# ------------------------------------------------------------

$antivirus = @()

$securityProducts = Invoke-Safe {

    Get-CimInstance `
        -Namespace "root\SecurityCenter2" `
        -ClassName AntiVirusProduct
}

foreach ($product in @($securityProducts)) {

    if ($product) {

        $antivirus += [ordered]@{
            DisplayName           = $product.displayName
            ProductState          = $product.productState
            PathToSignedProductExe =
                $product.pathToSignedProductExe
        }
    }
}

$edrPresent = ($antivirus.Count -gt 0)

# ------------------------------------------------------------
# WINDOWS UPDATE
# ------------------------------------------------------------

$updateStatus = $null

try {

    $updateSession =
        New-Object -ComObject Microsoft.Update.Session

    $updateSearcher =
        $updateSession.CreateUpdateSearcher()

    $searchResult =
        $updateSearcher.Search(
            "IsInstalled=0 and IsHidden=0"
        )

    $pendingUpdates =
        $searchResult.Updates.Count

    $updateStatus = [ordered]@{
        Pending_Updates = $pendingUpdates
        Status = if ($pendingUpdates -eq 0) {
            "Up to date"
        }
        else {
            "Updates pending"
        }
    }
}
catch {

    $updateStatus = $null
}

# ------------------------------------------------------------
# ENCRYPTION / BITLOCKER
# ------------------------------------------------------------

$encryption = @()

$bitlockerVolumes = Invoke-Safe {
    Get-BitLockerVolume
}

foreach ($volume in @($bitlockerVolumes)) {

    if ($volume) {

        $encryption += [ordered]@{
            MountPoint        = $volume.MountPoint
            VolumeStatus      = $volume.VolumeStatus
            ProtectionStatus  = $volume.ProtectionStatus
            EncryptionMethod  = $volume.EncryptionMethod
            EncryptionPercent = $volume.EncryptionPercentage
        }
    }
}

# Fallback encryption information

if ($encryption.Count -eq 0) {

    $encryptableVolumes = Invoke-Safe {

        Get-CimInstance `
            -Namespace "root\CIMV2\Security\MicrosoftVolumeEncryption" `
            -ClassName Win32_EncryptableVolume
    }

    foreach ($volume in @($encryptableVolumes)) {

        if (-not $volume) {
            continue
        }

        $encryptionMethod = $null
        $conversionStatus = $null
        $protectionStatus = $null

        try {
            $methodResult =
                Invoke-Safe {
                    $volume.GetEncryptionMethod()
                }

            if ($methodResult) {
                $encryptionMethod =
                    $methodResult.EncryptionMethod
            }
        }
        catch {}

        try {
            $conversionResult =
                Invoke-Safe {
                    $volume.GetConversionStatus()
                }

            if ($conversionResult) {
                $conversionStatus =
                    $conversionResult.ConversionStatus
            }
        }
        catch {}

        try {
            $protectionResult =
                Invoke-Safe {
                    $volume.GetProtectionStatus()
                }

            if ($protectionResult) {
                $protectionStatus =
                    $protectionResult.ProtectionStatus
            }
        }
        catch {}

        $encryption += [ordered]@{
            MountPoint       = $volume.DriveLetter
            ConversionStatus = $conversionStatus
            ProtectionStatus = $protectionStatus
            EncryptionMethod = $encryptionMethod
        }
    }
}

# ------------------------------------------------------------
# LOCAL ADMINISTRATORS
# ------------------------------------------------------------

$localAdministrators = @()

$localAdmins = Invoke-Safe {
    Get-LocalGroupMember -Group "Administrators"
}

foreach ($admin in @($localAdmins)) {

    if ($admin) {

        $localAdministrators += [ordered]@{
            Name   = $admin.Name
            ObjectClass = $admin.ObjectClass
            PrincipalSource = $admin.PrincipalSource
        }
    }
}

# ------------------------------------------------------------
# SECURITY POSTURE OBJECT
# ------------------------------------------------------------

$securityPosture = [ordered]@{

    Firewall = $firewallProfiles

    Antivirus_EDR = $antivirus

    EDR_Present = $edrPresent

    Update_Status = $updateStatus

    Encryption = $encryption

    Local_Administrators = $localAdministrators
}

# ============================================================
# SOFTWARE INVENTORY
# ============================================================

$software = @()

$softwarePaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

foreach ($path in $softwarePaths) {

    $applications = Invoke-Safe {
        Get-ItemProperty $path
    }

    foreach ($app in @($applications)) {

        if (
            $app.DisplayName -and
            $app.DisplayName.Trim() -ne ""
        ) {

            $software += [ordered]@{
                Name      = $app.DisplayName
                Publisher = $app.Publisher
                Version   = $app.DisplayVersion
            }
        }
    }
}

# Remove duplicate software entries

$software = @(
    $software |
        Sort-Object Name, Publisher, Version -Unique
)

# ============================================================
# USER CONTEXT
# ============================================================

$currentUser = $env:USERNAME

$lastLoggedUser = $null

try {

    $lastLoggedUser =
        (Get-CimInstance Win32_ComputerSystem).UserName
}
catch {

    $lastLoggedUser = $currentUser
}

$userContext = [ordered]@{
    Current_User     = $currentUser
    Last_Logged_User = $lastLoggedUser
    Domain           = $domain
    Domain_Joined    = $domainJoined
}

# ============================================================
# COMPLETE ASSET OBJECT
# ============================================================

$asset = [ordered]@{

    discovery_timestamp = $DiscoveryTimestamp

    platform = "Windows"

    device_identity = $deviceIdentity

    host_identity = $hostIdentity

    hardware = $hardware

    network = @($network)

    os = $os

    management = @($management)

    security_posture = $securityPosture

    software = @($software)

    user_context = $userContext

    agent_version = $AgentVersion
}

# ============================================================
# CREATE JSON
# ============================================================

try {

    $json = $asset |
        ConvertTo-Json -Depth 15

    $json |
        Out-File `
            -FilePath $OutputFile `
            -Encoding UTF8

    Write-Host ""
    Write-Host "============================================"
    Write-Host " Asset Discovery Completed"
    Write-Host "============================================"
    Write-Host ""

    Write-Host "Agent Version: $AgentVersion"

    Write-Host "Asset JSON created:"
    Write-Host $OutputFile

    Write-Host ""
}
catch {

    Write-Host ""
    Write-Host "ERROR: Could not create asset.json"
    Write-Host $_.Exception.Message
    Write-Host ""

    exit 1
}

# ============================================================
# SEND ASSET TO ISMS SERVER
# ============================================================

Write-Host ""
Write-Host "============================================"
Write-Host " Sending asset to ISMS server..."
Write-Host "============================================"
Write-Host ""

try {

    $headers = @{
        "X-Agent-API-Key" = $AgentApiKey
    }

    $response = Invoke-RestMethod `
        -Uri $ServerUrl `
        -Method Post `
        -Headers $headers `
        -Body $json `
        -ContentType "application/json"

    Write-Host ""
    Write-Host "============================================"
    Write-Host " Asset sent successfully"
    Write-Host "============================================"
    Write-Host ""

    if ($response) {

        Write-Host "Server response:"

        $response |
            ConvertTo-Json -Depth 10 |
            Write-Host
    }
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