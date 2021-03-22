<#
.SYNOPSIS
Check URL/Hostname/DNS/IPs for active urls that return a SSL certificate

.DESCRIPTION
Things you will need to fill out:
-Recipients (Who the email will go to)
-From (from address ex:server@contoso.com)
-SMTPServer(Your smtp server address)

-Logging section (all of it)
-Search Scopes (see examples of what you want to look for)   

#>


#$recipients = @("YourName <YourName@contoso.com>","TeamName <TeamName@contoso.com>")
$recipients = @()
$from = "" #This is the originating server address
$smtpserver = 'Your SMTP Server'


## Logging Section ## 

    $dir = "" # top level directory where logs will go
    $file = ".csv" # Location CSV will be written to
    $Log = ".txt" # General Log location - will be overwritten each time the script runs
    $downURLs = ".txt" # IPs that don't respond to ping but are still in DNS/AD
    $activeURLs = ".txt" # IPs that are up but do not respond on 443
    $Active443Urls = ".txt" # Hostnames/DNS names that are active and respond on 443
    $UrlList = ".txt" # URL list that will be used to do the final check (export of Active443URLs for record keeping)

    # Instantiate Array Variables 

    $SearchScope = @()
    $urls = @()

    ## Search Scopes

    # ex Computer OU: $searchbase1= Get-ADComputer -SearchBase "OU=Production,OU=Servers,DC=contoso,DC=com" -Filter * | select-object DNSHostName 
    # ex DNS record CNAME: Get-DnsServerResourceRecord -ZoneName contoso.com -ComputerName "DChq2016-1" -RRType "CNAME" | Where-Object {$_.Hostname -like "*.weburl.com"} | select-object Hostname
    # ex DNS record A record: Get-DnsServerResourceRecord -ZoneName contoso.com -ComputerName "DChq2016-1" -RRType "A" | Where-Object {$_.Hostname -like "*weburl.com*" -and -not $_.TimeStamp} | select-object Hostname

    # More search bases can be added if need be
    $searchbase1= 
    $searchbase2= 
    $searchbase3= 
    $searchbase4= 
    $searchbase5= 
    $searchbase6= 
    $searchbase7= 
    $searchbase8= 

    Log "finished scope check"

    $SearchScope += $searchbase1
    $SearchScope += $searchbase2
    $SearchScope += $searchbase3
    $SearchScope += $searchbase4
    $SearchScope += $searchbase5
    $SearchScope += $searchbase6
    $SearchScope += $searchbase7
    $SearchScope += $searchbase8


# End of Array Variables

## Log Cleanup
    If(test-path $dir){}else{New-Item -ItemType Directory -Name $file -Path $dir}
    If(Test-Path $log){ Remove-Item $Log}
    If(Test-Path $downURLs){ Remove-Item $downURLs}
    If(Test-Path $activeURLs){Remove-Item $activeURLs}
    If(Test-Path $Active443Urls){Remove-Item $Active443Urls}
    If(Test-Path $file){Remove-Item $file}
    Log "Logs Cleaned up"

## STATIC VARIABLES SECTION ##

## BEGIN FUNCTIONS ##
Function Date{
    [string]$(Get-Date -Format "MM-dd-yyyy")
    }

Function Log($message){
    $newMessage = (Date) + " $message"
    Write-Host $newMessage
    $newMessage | Out-File $Log -Append
}

Function Test-TCPPort($url){
        # If URL is active, test port 443
            $timeout = 1000
            $remoteHostName = $url
            $remotePort = "443"
            $tcpClient = New-Object System.Net.Sockets.TcpClient

        Try{
            $portOpened = $tcpClient.ConnectAsync($remoteHostName, $remotePort).Wait($timeout)
            if($portOpened -eq $true){
                Return $true
                }
                else{
                Return $false
                }
            }
        Catch{
        # $_ #actual error message, but most likely it will relate to the site being down
            Return $false
            }
}

Function Get-PublicKey($weburls) {
    # shoddy way to get the content of the file
    $weburls = Get-Content $weburls
    foreach($w in $weburls){    
        $computer = $w
        $IP = Get-WmiObject -Class Win32_PingStatus -Filter "Address='$computer' AND Timeout=1000"
        $IP = $IP.IPV4Address
        $port = 443
        
        #If the all powerful powershell is so powerful... then why can't it get a cert based on a url?
            #This section is to hit URLs that are up and if they fail, try the IP route instead.         
                $webRequest = ""
                $webRequest = [Net.WebRequest]::Create("https://$w")
                $webRequest.GetResponse()
        
                if($webRequest.ServicePoint.Certificate.Subject){
                        $CertInfo = [PSCustomObject]@{ 
                                    DNSName = "https://$computer"
                                    IP = $IP
                                    Subject = $webRequest.ServicePoint.Certificate.Subject
                                    SANS = $SanArray
                                    Thumbprint = "unknown"
                                    Expires = $webRequest.ServicePoint.Certificate.GetExpirationDateString()
                                     }
                               $CertInfo | Export-Csv -Path $file -NoTypeInformation -Append
                }
                else{ 
                    $TCPClient = New-Object -TypeName System.Net.Sockets.TCPClient
                    try
                        {
                                Log "starting TCPClient with $w"
                            $TcpSocket = New-Object Net.Sockets.TcpClient($ip,$port)
                                Log "TCPClient Connected, running GetStream() for $w"
                            $tcpstream = $TcpSocket.GetStream()
                                Log "GetStream successful, starting CallBack for $w"
                            $Callback = {param($sender,$cert,$chain,$errors) return $true}
                                Log "Call back successful, starting SSL Stream for $w"
                            $SSLStream = New-Object -TypeName System.Net.Security.SSLStream -ArgumentList @($tcpstream, $True, $Callback)
                                Log "SSL Stream Established, trying authenticate client for $w"
                            try
                            {
                                $SSLStream.AuthenticateAsClient($IP)
                                    Log "AuthenticateAsClient successful, attempting remote certificate for $w"
                                $Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($SSLStream.RemoteCertificate)
                                    Log "Certificate gained, starting cleanup"
                            }
                        finally
                            {
                                Log "Starting SSLStream Dispose()"
                                $SSLStream.Dispose()
        
                            }
                        }
                        finally
                        {
                            Log "Starting TCPClient Dispose()"
                            $TCPClient.Dispose()
                        }
                               if($Certificate){
                                Log "Certificate found for $computer"
                                $SanArray = @()
                                $SanArray += $Certificate.DnsNameList.unicode
                                $SanArray = $SanArray -join ","
                    
                               $CertInfo = [PSCustomObject]@{ 
                                    DNSName = "https://$computer"
                                    IP = $IP
                                    Subject = $Certificate.Subject
                                    SANS = $SanArray
                                    Thumbprint = $Certificate.Thumbprint
                                    Expires = $Certificate.NotAfter
                                     }
                               $CertInfo | Export-Csv -Path $file -NoTypeInformation -Append
                               Remove-Variable -Name Certificate
                               } # End of If Looop
                               Log "Starting Garbage Collection"
                               [System.GC]::GetTotalMemory(‘forcefullcollection’) | out-null
                               Log "Garbage Collection Complete"
             }
             #outside if/else loop
    } # End of foreach loop
}#end Function

## END FUNCTION SCOPE ##

# Select Unique entries for search scope 

$SearchScope = $SearchScope | Select-Object -Unique

Log "Starting URL Check...this will take a while"

for($counter = 0; $counter -lt $SearchScope.Count; $counter++){
$s = $SearchScope[$counter]

    # Test if URL is active
    if(Test-Connection $s -Count 1 -Quiet){
        Log "$s is active, testing port 443"
        # Nested - If URL is active test port 443
        if((Test-TCPPort -url $s) -eq $true){
            Log "443 is open for $s"
            $urls += $s #add $s to $URLS array
            $s | Out-File $Active443Urls -Append #Add $s to active443URLs log
            }
            else{
            Log "443 is closed for $s"
            $s |Out-File $activeURLs -Append #Add $s to activeURLs log
            }#End of nested If/Else statement
        }
        else{
            Log "URL Skipped $s" #log Url is down
            $s | Out-File $downURLs -Append #Add $s to down urls list (for tracking purposes)
        }#End of If/Else Statement
    $PercentComplete = $counter/$SearchScope.Count*100
    $PercentComplete = [math]::Round($PercentComplete,2)
    Write-Progress -Activity "Iterate through DNS Names" -Status "$PercentComplete% Complete: " -PercentComplete $PercentComplete
}
Write-Progress -Activity "Iterate through DNS Names" -Status "100% Complete" -PercentComplete 100

Log "Finished URL check"

#### Check of All the Endpoints

    Log "Starting Web Cert Check"

    Log "$($urls.count) active URLs"

    $urls | Out-File $UrlList #See what urls are being tested against.

# TCP check for SSL certificates
Get-PublicKey -weburls $UrlList

Get-PayPalCert

Log "Sending mail now"

# SendMail Portion

    $anonUsername = "anonymous"
    $anonPassword = ConvertTo-SecureString -String "anonymous" -AsPlainText -Force
    $anonCredentials = New-Object System.Management.Automation.PSCredential($anonUsername,$anonPassword)

Send-MailMessage -SmtpServer $smtpserver -From $from -To $recipients -Subject "Web Cert List" -Body "Attached is a CSV with Expiring Web certificates" -Attachments $file -Credential $anonCredentials
