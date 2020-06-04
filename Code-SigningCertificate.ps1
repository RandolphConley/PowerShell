<# 
 
.SYNOPSIS 
Standard Profile features and functions that can be used accross the board. Includes the disable beep feature for powershell console.  
 
.DESCRIPTION 
Get-CodesignCert -requests AD for a code sign certificate (if one does not already exist on the machine). Sign-Script will use the code sign certificate and then use the verisign TimeStamp server for forever forward validity. If a script isn't specified, then a dialogue box will come up to select multiple scripts. 
 
.EXAMPLE 
Get-CodeSignScript; Sign-Script -Script C:\Contoso\ContosoCompanyScript.ps1 
 
.NOTES 
This can be placed in one of the 6 profile locations. See: https://blogs.technet.microsoft.com/heyscriptingguy/2012/05/21/understanding-the-six-powershell-profiles/ 
 
#> 
 
 
 
# Disables Powershel Console Beep 
Set-PSReadlineOption -BellStyle None 
 
Function Get-CodeSignCert { 
         
    $store = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert 
    $date = (Get-Date).AddDays(-30) 
    $cert_location = $env:USERPROFILE 
    $cert_import = ($cert_location+'\Desktop\codesign.cer') 
    $machine_cert = 'Cert:\CurrentUser\TrustedPublisher' 
if($store -eq $null){ 
 
       Write-Host "Obtaining Code Signing Certificate" 
       Get-Certificate -Template codesigning-crutchfield -CertStoreLocation Cert:\CurrentUser\My 
       write-host "Moving Certificate to Machine Trusted Publisher store" 
       Get-ChildItem Cert:\CurrentUser\My\ -CodeSigningCert | Export-Certificate -Type CERT -FilePath $cert_import -Force 
       Import-Certificate -FilePath $cert_import -CertStoreLocation $machine_cert 
       $cert_import | Remove-Item -Force 
       write-host "Complete!" 
} 
elseif ($store -ne $null -and $store.GetExpirationDateString() -lt $date){ 
       
       write-host "Cleaning up older certificates" 
       $store | Remove-Item 
       $reissue = Read-Host "Would you like to reissue certificate? Y or N" 
       if($reissue -eq 'y'){ 
       Get-Certificate -Template codesigning-crutchfield -CertStoreLocation Cert:\CurrentUser\My 
       write-host "Moving Certificate to Trusted Publisher store" 
       $export_cert = $env:USERPROFILE 
       Get-ChildItem Cert:\CurrentUser\My\ -CodeSigningCert | Export-Certificate -Type CERT -FilePath $cert_import -Force 
       Import-Certificate -FilePath $cert_import -CertStoreLocation $machine_cert 
       write-host "removing temporary certificate" 
       $cert_import | Remove-Item -Force 
       write-host "Complete!" 
} 
else{ 
    write-host "These are not the droids you are looking for" 
    } 
} 
} 
Function Sign-Script { 
 
[CmdletBinding()] 
Param( 
[Parameter(Mandatory=$False)] 
[string]$Script 
) 
$cert = (dir Cert:\CurrentUser\my -CodeSigningCert)[0] 
 
if($script){ 
Try{ 
    Set-AuthenticodeSignature $Script -Certificate $cert -TimestampServer http://timestamp.verisign.com/scripts/timstamp.dll 
    "$script was signed successfully with Verisign timestamp server" 
} 
Catch{ 
    "There was an error singing $script. Please ensure the absolute Path is correct and the file is a PowerShell Script" 
} 
Finally{} 
 
} 
else{ 
    if((Read-Host "Would you like to navigate to the script (Y/N)")-eq "Y") 
    { 
     
        Add-Type -AssemblyName System.Windows.Forms 
        $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{ 
        Multiselect = $true # Multiple files can be chosen 
        #Filter = 'PoSh (*.ps1)|*.ps1' # Specified file types 
    } 
  
    [void]$FileBrowser.ShowDialog() 
 
    $path = $FileBrowser.FileNames; 
        If($FileBrowser.FileNames -like "*\*") { 
 
            # Do something before work on individual files commences 
            $FileBrowser.FileNames #Lists selected files (optional) 
         
            foreach($file in Get-ChildItem $path){ 
            Get-ChildItem ($file) | 
            ForEach-Object { 
            $confirmation = read-host "Press 'Y' to confirm signature" 
            if ($confirmation -eq 'y'){ 
 
            Set-AuthenticodeSignature $file -Certificate $cert -TimestampServer http://timestamp.verisign.com/scripts/timstamp.dll 
        } 
        } 
    } 
    } 
} 
} 
}