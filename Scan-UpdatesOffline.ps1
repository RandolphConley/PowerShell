<#PSScriptInfo

.VERSION 1.0

.GUID 7f1cf7cf-7a86-4124-9b20-8228ad7b13b2

.AUTHOR Andrei Stoica astoica@microsoft.com

.COMPANYNAME Microsoft

.COPYRIGHT 

.TAGS 

.LICENSEURI https://opensource.org/licenses/MIT

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES VBS version: https://docs.microsoft.com/en-us/previous-versions/windows/desktop/aa387290(v=vs.85) 

.NOTES Modified by StevenLtheThird to streamline the audit process

#>

<# 

.DESCRIPTION 
 Using WUA to Scan for Updates Offline with PowerShell 

#> 
Param()

Function Write-StatusMessage($status){
    <#
    .Synopsis
    Write status message to host
    #>
    Write-Verbose -Message $status -Verbose
}
#Out file location
$File = "\\BCSCCMPR02\SoftwareSupport\Win10\ConfigMgrHealthScript\WSUS_Scan\Logs.txt"

# Check if current user is logged on as an administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
    if ($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator ))
    {
        (get-host).UI.RawUI.Backgroundcolor="DarkRed"
        clear-host
        Write-Warning "Warning: PowerShell is running as an Administrator.`n"
    }
    else{
    Throw "Please start powershell as an administrator to run Scan-UpdatesOffline.ps1"
    }

# pull latest cab file from microsoft 
Write-StatusMessage -status "Downloading WSUSScan2.cab, this may take a while."
$Wsusscan2_File = "C:\Users\$env:Username\Documents\wsusscan2.cab"
Invoke-WebRequest -Uri 'http://download.windowsupdate.com/microsoftupdate/v6/wsusscan/wsusscn2.cab' -OutFile $Wsusscan2_File

 
$UpdateSession = New-Object -ComObject Microsoft.Update.Session 
$UpdateServiceManager  = New-Object -ComObject Microsoft.Update.ServiceManager 
$UpdateService = $UpdateServiceManager.AddScanPackageService("Offline Sync Service", $Wsusscan2_File, 1) 
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()  
 
Write-Output "Searching for updates... `r`n" 
 
$UpdateSearcher.ServerSelection = 3 #ssOthers
$UpdateSearcher.IncludePotentiallySupersededUpdates = $true # good for older OSes, to include Security-Only or superseded updates in the result list, otherwise these are pruned out and not returned as part of the final result list
$UpdateSearcher.ServiceID = $UpdateService.ServiceID.ToString() 
$SearchResult = $UpdateSearcher.Search("IsInstalled=0") # or "IsInstalled=0 or IsInstalled=1" to also list the installed updates as MBSA did 

# Results stored in $updates variable 
$Updates = $SearchResult.Updates 
 
if($Updates.Count -eq 0){ 
    Write-Output "There are no applicable updates." 
    return $null 
} 
 
Write-Output "List of applicable items on the machine when using wssuscan.cab: `r`n" 
 
$i = 0 
foreach($Update in $Updates){  
    Write-Output "$($i)> $($Update.Title)" 
    $i++ 
    Write-Output "$($i)> $($Update.Title)" | Out-File $File -Append
}
