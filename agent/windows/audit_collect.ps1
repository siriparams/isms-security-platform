# ============================================================
# ISMS - Windows Endpoint Audit Agent
# ============================================================

$ServerUrl = "http://127.0.0.1:5000/agent/audit"
$AgentApiKey = "isms_agent_2026_secure_key"

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "      ISMS ENDPOINT AUDIT AGENT" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

function Get-Safe {
    param (
        [scriptblock]$Command
    )

    try {
        return & $Command
    }
    catch {
        return $null
    }
}

# ------------------------------------------------------------
# SYSTEM IDENTITY
# ------------------------------------------------------------

$hostname = $env:COMPUTERNAME

$machineGuid = Get-Safe {
    (Get-ItemProperty `
        -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" `
        -Name MachineGuid).MachineGuid
}

$smbiosUuid = Get-Safe {
    (Get-CimInstance Win32_ComputerSystemProduct).UUID
}

$os = Get-Safe {
    Get-CimInstance Win32_OperatingSystem
}

# ------------------------------------------------------------
# CHECK 1 - WINDOWS FIREWALL
# ------------------------------------------------------------

$firewallProfiles = Get-Safe {
    Get-NetFirewallProfile
}

$firewallEnabled = $false

if ($firewallProfiles) {
    $firewallEnabled = ($firewallProfiles | Where-Object {
        $_.Enabled -eq $true
    }).Count -eq $firewallProfiles.Count
}

$firewallStatus = if ($firewallEnabled) {
    "PASS"
}
else {
    "FAIL"
}

# ------------------------------------------------------------
# CHECK 2 - WINDOWS DEFENDER / ANTIVIRUS
# ------------------------------------------------------------

$defender = Get-Safe {
    Get-MpComputerStatus
}

$defenderEnabled = $false

if ($defender) {
    $defenderEnabled = (
        $defender.AntivirusEnabled -eq $true -and
        $defender.RealTimeProtectionEnabled -eq $true
    )
}

$antivirusStatus = if ($defenderEnabled) {
    "PASS"
}
else {
    "FAIL"
}

# ------------------------------------------------------------
# CHECK 3 - SECURE BOOT
# ------------------------------------------------------------

$secureBoot = Get-Safe {
    Confirm-SecureBootUEFI
}

$secureBootStatus = if ($secureBoot -eq $true) {
    "PASS"
}
else {
    "FAIL"
}

# ------------------------------------------------------------
# CHECK 4 - BITLOCKER
# ------------------------------------------------------------

$bitlockerVolumes = Get-Safe {
    Get-BitLockerVolume
}

$bitlockerEnabled = $false

if ($bitlockerVolumes) {
    $encryptedVolumes = $bitlockerVolumes | Where-Object {
        $_.VolumeStatus -eq "FullyEncrypted"
    }

    if ($encryptedVolumes) {
        $bitlockerEnabled = $true
    }
}

$bitlockerStatus = if ($bitlockerEnabled) {
    "PASS"
}
else {
    "FAIL"
}

# ------------------------------------------------------------
# CHECK 5 - WINDOWS UPDATE SERVICE
# ------------------------------------------------------------

$windowsUpdateService = Get-Safe {
    Get-Service -Name wuauserv
}

$windowsUpdateStatus = if (
    $windowsUpdateService -and
    $windowsUpdateService.Status -eq "Running"
) {
    "PASS"
}
else {
    "FAIL"
}

# ------------------------------------------------------------
# CHECK 6 - LOCAL ADMINISTRATORS
# ------------------------------------------------------------

$localAdmins = Get-Safe {
    Get-LocalGroupMember -Group "Administrators" |
        Select-Object -ExpandProperty Name
}

if (-not $localAdmins) {
    $localAdmins = @()
}

# ------------------------------------------------------------
# CREATE AUDIT CHECK RESULTS
# ------------------------------------------------------------

$checks = @(
    @{
        check_id = "WIN-001"
        check_name = "Windows Firewall Enabled"
        category = "Network Security"
        expected_value = "Enabled"
        observed_value = if ($firewallEnabled) { "Enabled" } else { "Disabled" }
        status = $firewallStatus
        severity = if ($firewallEnabled) { "LOW" } else { "HIGH" }
    },
    @{
        check_id = "WIN-002"
        check_name = "Real-Time Antivirus Protection"
        category = "Endpoint Protection"
        expected_value = "Enabled"
        observed_value = if ($defenderEnabled) { "Enabled" } else { "Disabled" }
        status = $antivirusStatus
        severity = if ($defenderEnabled) { "LOW" } else { "CRITICAL" }
    },
    @{
        check_id = "WIN-003"
        check_name = "Secure Boot"
        category = "System Security"
        expected_value = "Enabled"
        observed_value = if ($secureBoot) { "Enabled" } else { "Disabled/Unavailable" }
        status = $secureBootStatus
        severity = if ($secureBoot) { "LOW" } else { "MEDIUM" }
    },
    @{
        check_id = "WIN-004"
        check_name = "BitLocker Encryption"
        category = "Data Protection"
        expected_value = "Fully Encrypted"
        observed_value = if ($bitlockerEnabled) { "Fully Encrypted" } else { "Not Fully Encrypted" }
        status = $bitlockerStatus
        severity = if ($bitlockerEnabled) { "LOW" } else { "HIGH" }
    },
    @{
        check_id = "WIN-005"
        check_name = "Windows Update Service"
        category = "Patch Management"
        expected_value = "Running"
        observed_value = if ($windowsUpdateService) { $windowsUpdateService.Status.ToString() } else { "Unknown" }
        status = $windowsUpdateStatus
        severity = if ($windowsUpdateStatus -eq "PASS") { "LOW" } else { "MEDIUM" }
    }
)

# ------------------------------------------------------------
# CALCULATE SCORE
# ------------------------------------------------------------

$totalChecks = $checks.Count

$passedChecks = @(
    $checks | Where-Object {
        $_.status -eq "PASS"
    }
).Count

$failedChecks = @(
    $checks | Where-Object {
        $_.status -eq "FAIL"
    }
).Count

if ($totalChecks -gt 0) {
    $overallScore = [math]::Round(
        ($passedChecks / $totalChecks) * 100
    )
}
else {
    $overallScore = 0
}

$auditStatus = if ($failedChecks -eq 0) {
    "COMPLIANT"
}
elseif ($overallScore -ge 60) {
    "NEEDS_REVIEW"
}
else {
    "FAILED"
}

# ------------------------------------------------------------
# CREATE AUDIT JSON
# ------------------------------------------------------------

$auditData = @{
    audit_id = "AUD-" + (Get-Date -Format "yyyyMMdd-HHmmss")
    hostname = $hostname
    machine_guid = $machineGuid
    smbios_uuid = $smbiosUuid

    operating_system = if ($os) {
        $os.Caption
    }
    else {
        "Unknown"
    }

    os_version = if ($os) {
        $os.Version
    }
    else {
        "Unknown"
    }

    audit_profile = "Windows Endpoint Security"
    compliance_standard = "Initial ISMS Security Baseline"

    audit_timestamp = (Get-Date).ToUniversalTime().ToString("o")

    overall_score = $overallScore

    passed_count = $passedChecks
    failed_count = $failedChecks
    total_checks = $totalChecks

    status = $auditStatus

    checks = $checks

    local_administrators = $localAdmins
}

# ------------------------------------------------------------
# SAVE audit.json
# ------------------------------------------------------------

$json = $auditData | ConvertTo-Json -Depth 10

$jsonPath = Join-Path $PSScriptRoot "audit.json"

$json | Out-File `
    -FilePath $jsonPath `
    -Encoding UTF8

Write-Host "Audit completed." -ForegroundColor Green
Write-Host "Hostname       : $hostname"
Write-Host "Checks         : $totalChecks"
Write-Host "Passed         : $passedChecks"
Write-Host "Failed         : $failedChecks"
Write-Host "Overall Score  : $overallScore / 100"
Write-Host "Status         : $auditStatus"
Write-Host ""
Write-Host "audit.json created at:" -ForegroundColor Cyan
Write-Host $jsonPath
Write-Host ""

# ------------------------------------------------------------
# SEND AUDIT TO SERVER
# ------------------------------------------------------------

try {

    $headers = @{
        "X-Agent-API-Key" = $AgentApiKey
        "Content-Type" = "application/json"
    }

    $response = Invoke-RestMethod `
        -Uri $ServerUrl `
        -Method POST `
        -Headers $headers `
        -Body $json

    Write-Host "Audit sent successfully to server." -ForegroundColor Green
    Write-Host "Server response:"
    $response | ConvertTo-Json
}
catch {

    Write-Host ""
    Write-Host "Could not send audit to server." -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    Write-Host "audit.json is still available locally." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "          AUDIT AGENT FINISHED" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan