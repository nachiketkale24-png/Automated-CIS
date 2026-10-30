<#
.SYNOPSIS
    CIS Benchmark Evidence Collector for Windows Systems.
.DESCRIPTION
    Performs read-only inspection of Windows security controls according to
    CIS Benchmark principles. Collects facts for:
    - Operating System version and build
    - Windows Firewall profiles (Domain, Private, Public)
    - Windows Defender Antivirus & Real-Time Protection
    - Guest and Built-in Administrator account statuses
    - Password and lockout policies
    - Logon audit policy
    - SMBv1 configuration
    - Remote Desktop (RDP) & Network Level Authentication (NLA)
    - BitLocker OS volume status
    - Telnet client feature status
    
    Generates a normalised JSON evidence file compatible with the
    CIS Compliance Auditor backend.
.PARAMETER OutputFile
    Path where the JSON evidence report will be saved. Default: .\windows_evidence.json
.PARAMETER UploadToApi
    If set, attempts to POST the audit findings to the running API backend.
.PARAMETER ApiUrl
    URL of the audit API endpoint. Default: http://127.0.0.1:8000/api/audits
.PARAMETER AssetId
    ID of the registered asset to associate when uploading to the API.
.EXAMPLE
    .\cis_windows_scanner.ps1
.EXAMPLE
    .\cis_windows_scanner.ps1 -OutputFile C:\Reports\pc_audit.json
#>
[CmdletBinding()]
param(
    [string]$OutputFile = "windows_evidence.json",
    [switch]$UploadToApi,
    [string]$ApiUrl = "http://127.0.0.1:8000/api/audits",
    [int]$AssetId = 1
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  CIS Benchmark Evidence Scanner (Windows Read-Only)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Host: $env:COMPUTERNAME ($([System.Environment]::OSVersion.VersionString))"
Write-Host "Starting audit fact collection..." -ForegroundColor Yellow

$evidence = [ordered]@{
    "_source" = "windows_live:$($env:COMPUTERNAME)"
    "os" = @{}
    "firewall" = @{}
    "defender" = @{}
    "accounts" = @{}
    "password_policy" = @{}
    "audit_policy" = @{}
    "smb" = @{}
    "rdp" = @{}
    "bitlocker" = @{}
    "services" = @{}
}

# 1. OS Info
Write-Host "[-] Collecting OS details..." -NoNewline
try {
    $prodName = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).ProductName
    $build = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).CurrentBuild
    $ver = [System.Environment]::OSVersion.Version.ToString()
    $evidence["os"] = @{
        "caption" = $prodName
        "version" = $ver
        "build_number" = [string]$build
    }
    Write-Host " OK ($prodName, Build $build)" -ForegroundColor Green
} catch {
    $evidence["os"] = @{ "caption" = $null; "version" = $null; "build_number" = $null }
    Write-Host " SKIPPED" -ForegroundColor DarkGray
}

# 2. Firewall Profiles
Write-Host "[-] Checking Windows Firewall states..." -NoNewline
try {
    $dom = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile' -ErrorAction SilentlyContinue).EnableFirewall
    $priv = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile' -ErrorAction SilentlyContinue).EnableFirewall
    $pub = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile' -ErrorAction SilentlyContinue).EnableFirewall
    $evidence["firewall"] = @{
        "domain_enabled" = ($dom -eq 1)
        "private_enabled" = ($priv -eq 1)
        "public_enabled" = ($pub -eq 1)
    }
    Write-Host " OK (Domain:$($dom -eq 1), Private:$($priv -eq 1), Public:$($pub -eq 1))" -ForegroundColor Green
} catch {
    $evidence["firewall"] = @{ "domain_enabled" = $null; "private_enabled" = $null; "public_enabled" = $null }
    Write-Host " SKIPPED" -ForegroundColor DarkGray
}

# 3. Windows Defender
Write-Host "[-] Checking Windows Defender..." -NoNewline
try {
    $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($mp) {
        $evidence["defender"] = @{
            "antivirus_enabled" = [bool]$mp.AntivirusEnabled
            "real_time_protection" = [bool]$mp.RealTimeProtectionEnabled
        }
        Write-Host " OK (AV:$([bool]$mp.AntivirusEnabled), RTP:$([bool]$mp.RealTimeProtectionEnabled))" -ForegroundColor Green
    } else {
        $svc = (Get-Service WinDefend -ErrorAction SilentlyContinue).Status
        $isRunning = ($svc -eq "Running")
        $evidence["defender"] = @{
            "antivirus_enabled" = $isRunning
            "real_time_protection" = $isRunning
        }
        Write-Host " OK (Service Status: $svc)" -ForegroundColor Green
    }
} catch {
    $evidence["defender"] = @{ "antivirus_enabled" = $null; "real_time_protection" = $null }
    Write-Host " SKIPPED" -ForegroundColor DarkGray
}

# 4. Account Settings
Write-Host "[-] Checking Guest & Administrator accounts..." -NoNewline
try {
    $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
    $admin = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.SID -like '*-500' }
    $evidence["accounts"] = @{
        "guest_enabled" = if ($guest) { [bool]$guest.Enabled } else { $null }
        "administrator_renamed" = if ($admin) { ($admin.Name.ToLower() -ne "administrator") } else { $null }
    }
    Write-Host " OK" -ForegroundColor Green
} catch {
    $evidence["accounts"] = @{ "guest_enabled" = $null; "administrator_renamed" = $null }
    Write-Host " SKIPPED" -ForegroundColor DarkGray
}

# 5. Password Policy
Write-Host "[-] Inspecting password policy..." -NoNewline
try {
    $netAccounts = net accounts 2>$null
    $minLen = $null
    $maxAge = $null
    $lockout = $null
    foreach ($line in $netAccounts) {
        if ($line -match "Minimum password length\s*:\s*(\d+)") { $minLen = [int]$matches[1] }
        if ($line -match "Maximum password age\s*\(d\)\s*:\s*(\d+)") { $maxAge = [int]$matches[1] }
        if ($line -match "Lockout threshold\s*:\s*(\d+)") { $lockout = [int]$matches[1] }
    }
    $evidence["password_policy"] = @{
        "min_length" = $minLen
        "max_age_days" = $maxAge
        "complexity_enabled" = $null
        "lockout_threshold" = $lockout
    }
    Write-Host " OK" -ForegroundColor Green
} catch {
    $evidence["password_policy"] = @{ "min_length" = $null; "max_age_days" = $null; "complexity_enabled" = $null; "lockout_threshold" = $null }
    Write-Host " SKIPPED" -ForegroundColor DarkGray
}

# 6. Audit Policy
Write-Host "[-] Reading logon audit policy..." -NoNewline
try {
    $auditPol = auditpol /get /subcategory:"Logon","Account Logon" /r 2>$null
    $logonEv = $null
    $acctLogon = $null
    foreach ($line in $auditPol) {
        $p = $line -split ","
        if ($p.Count -ge 5) {
            $sub = $p[2].Trim()
            $set = $p[4].Trim()
            if ($sub -eq "Logon") { $logonEv = $set }
            if ($sub -eq "Account Logon") { $acctLogon = $set }
        }
    }
    $evidence["audit_policy"] = @{
        "logon_events" = $logonEv
        "account_logon" = $acctLogon
    }
    Write-Host " OK" -ForegroundColor Green
} catch {
    $evidence["audit_policy"] = @{ "logon_events" = $null; "account_logon" = $null }
    Write-Host " SKIPPED" -ForegroundColor DarkGray
}

# 7. SMBv1
Write-Host "[-] Checking SMBv1 protocol status..." -NoNewline
try {
    $smb1Reg = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -ErrorAction SilentlyContinue).SMB1
    $smb1Enabled = if ($smb1Reg -ne $null) { ($smb1Reg -eq 1) } else { $false }
    $evidence["smb"] = @{
        "smb1_enabled" = $smb1Enabled
    }
    Write-Host " OK (SMBv1 Enabled: $smb1Enabled)" -ForegroundColor Green
} catch {
    $evidence["smb"] = @{ "smb1_enabled" = $false }
    Write-Host " OK (Default disabled)" -ForegroundColor Green
}

# 8. RDP & NLA
Write-Host "[-] Checking Remote Desktop & NLA..." -NoNewline
try {
    $denyTS = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
    $userAuth = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
    $evidence["rdp"] = @{
        "enabled" = if ($denyTS -ne $null) { ($denyTS -eq 0) } else { $null }
        "nla_required" = if ($userAuth -ne $null) { ($userAuth -eq 1) } else { $null }
    }
    Write-Host " OK (RDP Enabled:$($denyTS -eq 0), NLA Required:$($userAuth -eq 1))" -ForegroundColor Green
} catch {
    $evidence["rdp"] = @{ "enabled" = $null; "nla_required" = $null }
    Write-Host " SKIPPED" -ForegroundColor DarkGray
}

# 9. BitLocker
Write-Host "[-] Checking BitLocker OS volume..." -NoNewline
try {
    $bl = Get-BitLockerVolume -MountPoint C: -ErrorAction SilentlyContinue
    $evidence["bitlocker"] = @{
        "os_drive_protected" = if ($bl) { ($bl.ProtectionStatus -eq "On" -or $bl.ProtectionStatus -eq 1) } else { $null }
    }
    Write-Host " OK" -ForegroundColor Green
} catch {
    $evidence["bitlocker"] = @{ "os_drive_protected" = $null }
    Write-Host " SKIPPED" -ForegroundColor DarkGray
}

# 10. Telnet Client Feature
Write-Host "[-] Checking Telnet client optional feature..." -NoNewline
try {
    $telnet = Get-WindowsOptionalFeature -Online -FeatureName TelnetClient -ErrorAction SilentlyContinue
    $evidence["services"] = @{
        "telnet_installed" = if ($telnet) { ($telnet.State -eq "Enabled") } else { $false }
    }
    Write-Host " OK" -ForegroundColor Green
} catch {
    $evidence["services"] = @{ "telnet_installed" = $false }
    Write-Host " OK (Not detected)" -ForegroundColor Green
}

# Convert evidence to JSON and write to file
$jsonOutput = $evidence | ConvertTo-Json -Depth 5
[System.IO.File]::WriteAllText($OutputFile, $jsonOutput, [System.Text.Encoding]::UTF8)

Write-Host ""
Write-Host "[+] Audit evidence saved to: $OutputFile" -ForegroundColor Green

if ($UploadToApi) {
    Write-Host "[+] Submitting audit payload to $ApiUrl (Asset ID: $AssetId)..." -ForegroundColor Yellow
    $payload = @{
        "asset_id" = $AssetId
        "benchmark_version" = "CIS_Windows_Server_2022_v1.0_ILLUSTRATIVE"
        "is_simulated" = $false
        "snapshot" = @{
            "is_simulated" = $false
            "evidence" = $evidence
        }
    } | ConvertTo-Json -Depth 6

    try {
        $res = Invoke-RestMethod -Uri $ApiUrl -Method POST -Body $payload -ContentType "application/json"
        Write-Host "[+] Audit created successfully! Audit ID: $($res.id)" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to upload to API: $_"
    }
}

Write-Host "Done!" -ForegroundColor Cyan
