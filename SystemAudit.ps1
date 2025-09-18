<#
.SYNOPSIS
  System Auditor Toolkit (SAT)
.DESCRIPTION
  Windows system security assessment and configuration analysis tool
  Designed for authorized penetration testing and system administration
#>

## ===== Core Modules =====

# 1. System Information Module
function Get-SystemOverview {
    Write-Output "`n=== SYSTEM INFORMATION ==="
    systeminfo | Select-String 'OS Name','OS Version','System Manufacturer','System Model','Domain' | ForEach-Object {
        Write-Output $_.ToString().Trim()
    }
    
    # Hotfixes
    Write-Output "`nInstalled Updates:"
    Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID,InstalledOn -First 5 | Format-Table -AutoSize
}

# 2. User Privilege Module
function Test-UserContext {
    Write-Output "`n=== USER CONTEXT ==="
    whoami /all | Select-String 'User Name','Privileges' -Context 0,5
    
    # Local Admins
    Write-Output "`nLocal Administrators:"
    net localgroup administrators | Where-Object { $_ -and $_ -notmatch "command completed" }
}

# 3. Service Analysis Module
function Find-VulnerableServices {
    Write-Output "`n=== SERVICE ANALYSIS ==="
    
    # Unquoted Paths
    Get-WmiObject Win32_Service | Where-Object {
        $_.PathName -like "*.exe*" -and 
        $_.PathName -notmatch "`"" -and
        $_.PathName -notlike "*Microsoft*" -and
        $_.PathName -notlike "*Windows*"
    } | Select-Object Name,PathName | Format-Table -Wrap
    
    # Weak Permissions
    Get-Service | ForEach-Object {
        $path = (Get-WmiObject Win32_Service -Filter "Name='$($_.Name)'").PathName
        if ($path -and $path -like "*.exe*") {
            $acl = Get-Acl -Path ($path -replace '^"?(.*?\.exe).*?$','$1') -ErrorAction SilentlyContinue
            if ($acl) {
                $access = $acl.Access | Where-Object {
                    $_.FileSystemRights -match "FullControl|Modify|Write" -and
                    $_.IdentityReference -notlike "*NT AUTHORITY*" -and
                    $_.IdentityReference -notlike "*BUILTIN*"
                }
                if ($access) {
                    [PSCustomObject]@{
                        Service = $_.Name
                        Path = $path
                        VulnerablePermission = $access.IdentityReference
                    }
                }
            }
        }
    } | Format-Table -AutoSize
}

# 4. Scheduled Tasks Module
function Audit-ScheduledTasks {
    Write-Output "`n=== SCHEDULED TASKS ==="
    Get-ScheduledTask | Where-Object {
        $_.State -ne "Disabled" -and
        $_.TaskPath -notlike "\Microsoft*"
    } | Select-Object TaskName,TaskPath,State | Format-Table -AutoSize
}

# 5. Network Configuration Module
function Get-NetworkConfig {
    Write-Output "`n=== NETWORK CONFIGURATION ==="
    
    # Interfaces
    Get-NetIPConfiguration | Select-Object InterfaceAlias,IPv4Address,IPv4DefaultGateway | Format-Table -AutoSize
    
    # Listening Ports
    Write-Output "`nListening Ports:"
    netstat -ano | Select-String "LISTENING" | Select-Object -First 10
    
    # WiFi Profiles
    Write-Output "`nWiFi Profiles:"
    netsh wlan show profiles | Where-Object { $_ -match "All User Profile" } | ForEach-Object {
        $name = $_.Split(":")[1].Trim()
        netsh wlan show profile name="$name" key=clear | Select-String "Key Content"
    }
}

# 6. Security Settings Module
function Check-SecuritySettings {
    Write-Output "`n=== SECURITY SETTINGS ==="
    
    # UAC Status
    Write-Output "`nUAC Status:"
    reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA
    
    # LSA Protection
    Write-Output "`nLSA Protection:"
    reg query "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v RunAsPPL
    
    # Windows Defender
    Write-Output "`nDefender Status:"
    Get-MpComputerStatus | Select-Object AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled
}

# 7. Installed Software Module
function Get-InstalledSoftware {
    Write-Output "`n=== INSTALLED SOFTWARE ==="
    
    # From Registry
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    Get-ItemProperty $paths | Where-Object {
        $_.DisplayName -and $_.Publisher -notmatch "Microsoft|Windows"
    } | Select-Object DisplayName,DisplayVersion,Publisher | Sort-Object DisplayName | Format-Table -AutoSize -Wrap
}

# 8. Sensitive Files Module
function Find-SensitiveFiles {
    Write-Output "`n=== SENSITIVE FILE SEARCH ==="
    
    $patterns = @(
        "*pass*", "*cred*", "*config*", "*.xml", "*.conf", 
        "*.cfg", "*.ini", "*.txt", "unattend.xml"
    )
    
    $locations = @(
        "$env:ProgramData",
        "$env:APPDATA",
        "C:\",
        "$env:USERPROFILE\Documents"
    )
    
    foreach ($loc in $locations) {
        if (Test-Path $loc) {
            foreach ($pattern in $patterns) {
                Get-ChildItem -Path $loc -Recurse -Filter $pattern -ErrorAction SilentlyContinue |
                Select-Object -First 5 -Property FullName,Length,LastWriteTime |
                Format-Table -AutoSize -Wrap
            }
        }
    }
}

## ===== Main Execution =====
function Start-SystemAudit {
    param(
        [switch]$Quick,
        [switch]$Stealth
    )
    
    if (-not $Stealth) {
        Write-Output @"

   _____ _______    _    ____ _____ ____  
  / ____|__   __|  / \  / ___|_   _/ ___| 
 | (___    | |    / _ \ \___ \ | | \___ \ 
  \___ \   | |   / ___ \ ___) || |  ___) |
  ____) |  | |  /_/   \_\____/ |_| |____/ 
 |_____/   |_|  System Auditor Toolkit v1.0
                                           
"@
    }
    
    # Random delay if in stealth mode
    if ($Stealth) { Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 15) }
    
    # Execute modules
    Get-SystemOverview
    Test-UserContext
    
    if (-not $Quick) {
        Find-VulnerableServices
        Audit-ScheduledTasks
        Get-NetworkConfig
        Check-SecuritySettings
        Get-InstalledSoftware
        Find-SensitiveFiles
    }
    
    if (-not $Stealth) {
        Write-Output "`nAudit completed at $(Get-Date)"
    }
}

## ===== Execution Options =====
# To run: 
#   Start-SystemAudit              # Full audit
#   Start-SystemAudit -Quick       # Basic checks only
#   Start-SystemAudit -Stealth     # No banner, random delay

Start-SystemAudit