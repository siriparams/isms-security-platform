# Windows Asset Discovery Agent

$computer = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor
$ip = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object {$_.IPAddress -notlike "127.*" -and $_.PrefixOrigin -ne "WellKnown"} |
    Select-Object -First 1).IPAddress

$asset = @{
    hostname = $env:COMPUTERNAME
    ip_address = $ip
    operating_system = $os.Caption
    hardware = "$($computer.Manufacturer) $($computer.Model), CPU: $($cpu.Name)"
    network = $ip
    software = "Windows"
    management = "Windows Management"
    security_posture = "Basic Windows information collected"
    user_context = $env:USERNAME
}

$asset | ConvertTo-Json -Depth 3 | Out-File "asset.json" -Encoding UTF8

Write-Host "Asset information collected successfully!"
Write-Host "Saved to asset.json"