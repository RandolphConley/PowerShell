<# 
 
.SYNOPSIS 
Administers Forticlient VPN installer for Windows if you don't have EMS from Fortinet.
 
.DESCRIPTION 
Run the script as an Administrator, follow the prompts. 
 
.EXAMPLE 
.\ForticlientVPN.ps1 
 
.NOTES 
In the Install-App function Be sure to update the $installerApp variable to reflect the current vpn client you have. 
You can download the latest vpn client here: https://www.fortinet.com/support/product-downloads#vpn
Composed by Randolph Conley
#> 



function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $timeGenerated = Get-Date -Format "yyyy_MM_dd HH:mm:ss"
    Add-Content -Path "C:\\users\\public\\documents\\ForticlientVPNInstaller.log" -Value "$timeGenerated - $Message"
}

# Get pending reboot
function Get-PendingReboot {
    $rebootPending;
    if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) { $rebootPending = $true }
    elseif (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) { $rebootPending = $true }
    elseif (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) { $rebootPending = $true }
    elseif (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\ControlSet001\Session Manager" -Name PendingFileRenameOperations -EA Ignore) { $rebootPending = $true }
    elseif (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\ControlSet002\Session Manager" -Name PendingFileRenameOperations -EA Ignore) { $rebootPending = $true }

    if ($rebootPending) {
        Write-Host "Reboot pending. Please reboot after installation completes"
        Write-Log "Reboot is pending"
    }
    else { return "No pending reboot" }
}

function Uninstall-App {
    $uninstallapplication = "Forticlient"
    # Search all subkeys for a specific product and return its UninstallString
    Write-Host "Locating MSI uninstall string"
    $uninstallInfo = Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" |
    Get-ItemProperty |
    Where-Object { $_.DisplayName -like "*$uninstallapplication*" } |
    Select-Object DisplayName, UninstallString

    if ($uninstallInfo) {
        # Split results to capture MSI string.    
        $array = $uninstallInfo.UninstallString.Split("/I")
        $uninstallString = $array[2]
        #UninstallCommand no restart, quiet, log to public documents
        Write-Host "Starting uninstall"
        Start-Process C:\windows\system32\msiexec.exe "/uninstall $uninstallString", "/norestart", "/qn", "/log C:\users\Public\Documents\$env:ComputerName-log.txt"
        write-log -Message "Uninstall completed for current ForticlientVPN"
    }
    else {
        write-host "Unable to locate Uninstall String registry entry. Please manually verify app is installed"
        exit
    }

}

function Install-App {
    # Install msi location (local or network)
    $InstallApp = "C:\users\public\documents\FortiClientSetup_7.4.6.2001.M_x64\FortiClient.msi"
        
    # Full switch menu
    # Start-Process $InstallApp -ArgumentList "q"
    # Basic installation
    Write-Log -Message "Starting application install"
    Start-Process $InstallApp -ArgumentList "/norestart", "/passive"
    Write-Log -Message "Application Install is complete. Please reboot your computer "
}

#Switch statement 
$x = 0
DO {
    Write-Host "Please download the VPN Client installer file here:"
    Write-Host "\\anguilla\publicshare\Andrew\ForticlientVPN"
    Write-Host "For Windows, download the .exe, for Apple, download the .dmg file"
    Write-Host "Welcome to Powershell!"
    Write-Host "Press 1 to Check for pending reboots"
    Write-Host "Press 2 to Uninstall Forticlient VPN"
    Write-Host "Press 3 to Install the latest forticlient VPN"
    Write-Host "Press 4 to exit"
    $number = Read-Host -Prompt "Please enter a number [1-4]"

    switch ($number) {
        1 { Get-PendingReboot }
        2 { Uninstall-App }
        3 { Install-App }
        4 { $x = 1 }
    }
} While ($x -lt 1)
Write-Host "Ending Script"
exit

