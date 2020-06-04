<#

.SYNOPSIS
Script to ease the pain of creating/submitting/automating the process of creating a certificate for on-prem CA

.DESCRIPTION
Required Variables: Subject, Exportable, SAN1, Template. Up to 5 SANs can be included in this script. More can be added if desired. User must have privileges to submit / create certificate template. 

.EXAMPLE
./get-certificate-inf.ps1 -Subject contoso.com -Exportable $false -Template Server -SAN1 contoso.com -SAN2 www.contoso.com -SAN3 devsite.constoso.com

.NOTES
Variables that Require user modification to the script: See "Subject Variables" Section.

#>


[CmdletBinding()]
Param(
[Parameter(Mandatory=$True)]
[string]$Subject,

[Parameter(Mandatory=$True)]
[string]$Exportable,

[Parameter(Mandatory=$True)]
[string]$SAN1,

[Parameter(Mandatory=$False)]
[string]$SAN2,

[Parameter(Mandatory=$False)]
[string]$SAN3,

[Parameter(Mandatory=$False)]
[string]$SAN4,

[Parameter(Mandatory=$False)]
[string]$SAN5,

[Parameter(Mandatory=$True)]
[string]$Template

)
$ErrorActionPreference = 'Inquire'

## Gathering Logic for SAN
$SAN = ''
if ($SAN2)
{
    $SAN +="&dns=$SAN2"
}
else{}

if ($SAN3)
{
    $SAN +="&dns=$SAN3"
}
else{}

if ($SAN4)
{
    $SAN +="&dns=$SAN4"
}
else{}

if ($SAN5)
{
    $SAN +="&dns=$SAN5"
}
else{}

$FullSAN ="{text}dns=$SAN1$SAN"

## Required Because Powershell interprets $Windows as a variable not a string
$Windows = '$Windows'

$inputfiletemplate = @"
[Version] 
Signature="$Windows NT$"

##Enter Subject Variables Here and uncomment:
# $O = [organization]
# $OU = [Organizational Unit]
# $E = [email]
# $L = [locality]
# $ST = [state]
# $C = [country]

[NewRequest] 
Subject = "CN=$Subject, O=$O, OU=$OU, E=$E, L=$L, ST=$ST, C=$C"   ; For a wildcard use "CN=*.CONTOSO.COM" for example
Exportable = $Exportable                  ; Private key is not exportable 
KeyLength = 2048                    ; Common key sizes: 512, 1024, 2048, 4096, 8192, 16384 
KeySpec = 1                         ; AT_KEYEXCHANGE 
KeyUsage = 0xA0                     ; Digital Signature, Key Encipherment 
MachineKeySet = True                ; The key belongs to the local computer account 
ProviderName = "Microsoft RSA SChannel Cryptographic Provider" 
ProviderType = 12 
SMIME = FALSE 
RequestType = CMC

; At least certreq.exe shipping with Windows Vista/Server 2008 is required to interpret the [Strings] and [Extensions] sections below

[Strings] 
szOID_SUBJECT_ALT_NAME2 = "2.5.29.17" 
szOID_ENHANCED_KEY_USAGE = "2.5.29.37" 
szOID_PKIX_KP_SERVER_AUTH = "1.3.6.1.5.5.7.3.1" 
szOID_PKIX_KP_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"

[Extensions] 
%szOID_SUBJECT_ALT_NAME2% = "$FullSAN" 
%szOID_ENHANCED_KEY_USAGE% = "{text}%szOID_PKIX_KP_SERVER_AUTH%,%szOID_PKIX_KP_CLIENT_AUTH%"

[RequestAttributes] 
CertificateTemplate=$Template
"@

$inf = Read-Host -prompt "Please enter a file name ending in .inf"

$inputfiletemplate | Out-File $inf

$generate = Read-Host -prompt "Would you like to generate a request? Please enter Y or N"

$req = Read-Host -prompt 'Please enter a file name ending in .req'

if ($generate -eq "y")
{
   & "C:\Windows\System32\certreq.exe" "-new" $inf $req
}
else
{
    "Have it your way."
}

$submit = Read-Host -prompt "Would you like to submit the request to the CA? Please enter Y or N"

if ($submit -eq "y")
{
   & "C:\Windows\System32\certreq.exe" "-submit" $req
}
else
{
    "A wild slime appears!"
}

$import = Read-Host -prompt "Would you like import the certificate? Please enter Y or N"

if ($import -eq "y")
{
    & "C:\Windows\System32\certreq.exe" "-accept" (Read-Host -prompt "Please type the name of the .cer file") 
}
else
{
    "Fine fine fine, I quit..."
}
