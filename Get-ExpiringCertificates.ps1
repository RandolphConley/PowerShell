<#
.SYNOPSIS
Locate expiring certificates in certificate store

.DESCRIPTION
Winrm to remote machine, get-childitem certificates -expiring in 90 days and select the subject, expiriation and DNS names

.EXAMPLE
.\Get-ExpiringCertificates.ps1

.NOTES
Account Needs to have remote winrm access to the Sub ordinate CA as well as the remote servers

#>

# Declared variables You'll need to declare the filepath of the server list 
# OutputCSV
$filepath = "ENTER FILE PATH HERE of servers"
$servers = Get-Content "$filepath"
$errorconnect = "$filepath\ErrorConnect.txt"
$OutputCSV = "SOME FOLDER PATH\expiringcerts.csv"

# Check to see if path already exists 
if(Test-Path $OutputCSV){
Remove-Item $OutputCSV -Force
}
else{
"File does not exist. Moving on to next step."    
}


# if winrmservers exists skip this step - most likely will be modified later
if(Test-Path $filepath){"Do nothing, skip this step"}
else{
foreach($s in $servers){
    $test = (Test-NetConnection -ComputerName $s -port 5985).tcptestsucceeded
        if($test){
            $s | Out-File -FilePath "$filepath\winrmservers.txt" -Append
            }
            else{
                "$s Error: Could not connect" | Out-File -FilePath $errorconnect -Force
            }
        }
    }

# Connect to servers 2012 and newer and get certificate information. Build a table and export the information to a CSV
## variable declared after winrmservers.txt is created
$winrmservers = Get-Content "$filepath\winrmservers.txt"
#remove existing file if exits
if(test-path "$filepath\expiringcerts.csv"){Remove-Item "$filepath\expiringcerts.csv" -Force -ErrorAction SilentlyContinue }

# foreach server in winrmservers.txt try connecting over WMI to test operating system. If older than 2012 or unable to connect, it will skip the server    
foreach($s in $winrmservers){
    $array = @()
        Try{
            If(Test-NetConnection -ComputerName $s -Port 5985){
                if((Get-CimInstance Win32_OperatingSystem -ComputerName $s).Version -lt "6.3.9600"){
                        "$s, older than 2012 or refused connection" | Out-File -FilePath $errorconnect -Append
                        }
                        else{
                        "$s trying now"
                        $array += invoke-command -ComputerName $s -ScriptBlock { Get-ChildItem -Path Cert:\LocalMachine\My -ExpiringInDays 90 | Select-Object Subject,NotAfter,DNSNAmeList,Thumbprint}
                        $array
                            foreach($a in $array){
                            [PSCustomObject]@{
                                    Hostname = $s
                                    Subject = $a.subject
                                    DNSName = $a.DNSNameList
                                    Expires = $a.Notafter
                                    Thumbprint = $a.Thumbprint
                                            } | Export-Csv -LiteralPath $OutputCSV -NoTypeInformation -Append
                            }#Foreach
                            }#Else
                }#If
                }#Try
                Catch{
                    "$s Error: Could not connect" | Out-File -FilePath $errorconnect -Append
                }
}

# Starting Query to Subordinate Certificate Authority
$patt = 'Issued'
$SubCA = "SUBORDINATE SPECIFIED HERE"
# To Find Certificate Template number : https://sysengblog.wordpress.com/tag/certutil/
#Put the OID of the CertificateTemplate after the = sign before the ,
#Ex: CertificateTemplate=1.23.4.56.5.2.1THISISAFAKENUMBER.13.4.5.6.67.3.2.2.2,disposition>=...etc.etc.

#### Certificate Template is the number of the template you want to query for#####
$dump = Invoke-Command -ComputerName $SubCA -ScriptBlock {
        $notafter = (get-date).AddDays(90)
        $notbefore = Get-Date
        & 'C:\Windows\system32\certutil.exe' '-view' '-restrict' "CertificateTemplate=TOBEFILLEDOUTBYUSER,disposition>=20,Disposition<=21,NotAfter<=$notafter,NotAfter>=$notbefore" -out "CommonName,RequesterName,NotAfter,CertificateHash"
        }

##### cleanup logic #####
$string = $dump | Select-String -pattern "\w" -AllMatches | Where-Object {$_.LineNumber -gt 9}
$is = $string | select-string -Pattern "issued" | ForEach-Object {$_.Line}| ForEach-Object {$_.split('"')[1]}
$Req = $string | select-string -Pattern "Requester" | ForEach-Object {$_.Line}| ForEach-Object {$_.split('"')[1]}
$date = $string | select-string -Pattern "Date" | ForEach-Object {$_.Line}| ForEach-Object {$_.split(' ')[5]+" "+$_.split(' ')[6]}
$Thumbprint = $string | select-string -Pattern "Hash" | ForEach-Object {$_.Line}| ForEach-Object {$_.split('"')[1]}
$Thumbprint = $Thumbprint -replace ' ',''

# Create Table object
$tabName = "SampleTable"
$table = New-Object system.Data.DataTable �$tabName�

# Define Columns
$col1 = New-Object system.Data.DataColumn Hostname,([string])
$col2 = New-Object system.Data.DataColumn Subject,([string])
$col3 = New-Object system.Data.DataColumn DNSName,([string])
$col4 = New-Object system.Data.DataColumn Expires,([string])
$col5 = New-Object system.Data.DataColumn Thumbprint,([string])

# Add the Columns
$table.columns.add($col1)
$table.columns.add($col2)
$table.columns.add($col3)
$table.columns.add($col4)
$table.columns.add($col5)

# Create a row
$row = $table.NewRow()
$blank

$i = 0
DO{
$table.Rows.Add($req[$i],$i,$is[$i],$date[$i],$Thumbprint[$i])
$i++
}
while($i -le ($is.Count))


# Display the table *for testing only*
# $table | format-table -AutoSize 

# Append to existing Output CSV 
$table | export-csv $OutputCSV -noType -Append

# SendMail Portion
$recipients = "DistroGroup <DistroGroup@GETYOUROWNDOMAIN.COM>"

$smtpserver = 'GETYOUROWNMAILSERVER.COM'


    $anonUsername = "anonymous"
    $anonPassword = ConvertTo-SecureString -String "anonymous" -AsPlainText -Force
    $anonCredentials = New-Object System.Management.Automation.PSCredential($anonUsername,$anonPassword)

Send-MailMessage -SmtpServer $smtpserver -From "CertificateAuthority@YOURDOMIANHERE.COM" -To $recipients -Subject "Certificates Expiring" -Body "Attached is a CSV with certificates on IIS Servers that are expiring soon" -Attachments ($OutputCSV) -Credential $anonCredentials
