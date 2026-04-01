<# 
 
.SYNOPSIS 
ACTUALLY install RSAT tools on windows 11 and not use optional features settings
 
.DESCRIPTION 
Run the script as an Administrator, select which tool you want and wait. Like, go grab lunch wait.
 
.EXAMPLE 
.\addRSATTools.ps1 -Feature ADUC
.\addRSATTools.ps1 -Feature DNS
.\addRSATTools.ps1 -Feature ALL #This is not completed yet. 
 
.NOTES 
The key is the verbose flag. Without this, powershell does not actually install the capability. Ask me how I know.
Be prepared to wait a long time if you run the ALL flag.
Composed by Randolph Conley
#> 
param(
  [switch]$ADUC,
  [switch]$DNS,
  [switch]$DHCP,
  [switch]$ALL
)

if($ADUC){$feature = "ActiveDirectory"}
if($DNS){$feature = "DNS"}
if($DHCP){$feature = "DHCP"}
if($feature){get-windowscapability -online -name rsat* | where-object {$_.Name -like "*$feature*"} | Add-WindowsCapability -Online -Verbose}
if($All){
    Write-Host "Bold move Cotton. This is going to take a while"
    get-windowscapability -online -name rsat* | foreach-object {Add-WindowsCapability -Online -Verbose -Name $_.Name}
}
