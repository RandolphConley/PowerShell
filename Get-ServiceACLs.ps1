<#
.SYNOPSIS
    Audit service permissions.

.DESCRIPTION
    Script to AUDIT service permissions. Does not fix service permissions. There are plenty of other scripts to do that.

.NOTES
Code used from here:
    https://stackoverflow.com/questions/68691545/the-rights-of-the-exe-of-a-windows-service-powershell
#>

param(
    $Logs
)

If($Logs){}
else{$Logs = Read-Host -Prompt "Please enter a log location (No filename)"}

if(Test-Path $Logs){

   Get-CimInstance Win32_Service | Where-Object { $_.PathName -like '*.exe*'} | 
   Select-Object Name, State, Pathname, StartName |
     ForEach-Object {
        $_.PathName = ($_.PathName -split '(?<=\.exe\b)')[0].Trim('"')
        Add-Member -PassThru -InputObject $_ Acl ((Get-Acl $_.PathName).AccessToString)
        } | Export-Csv "$Logs\$($env:COMPUTERNAME).csv" -NoTypeInformation
}
else {
    throw "Log location is not valid. Please use a valid location."
}