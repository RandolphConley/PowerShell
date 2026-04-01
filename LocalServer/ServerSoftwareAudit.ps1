$file = "C:\temp\ServerSoftwareOrig.csv"
$pcname = Import-Csv "C:\Temp\Servers.csv"

foreach($p in $pcname){
$p = $p.Name
# Check if computer is online
Write-Host "Trying $p"
if(Test-Connection -Count 1 -ComputerName $p -Verbose){
      $wmiObjectQuery = Get-WmiObject Win32_Product -ComputerName $p -ErrorAction SilentlyContinue | Select-Object Name,Version
      if($wmiObjectQuery){
        $wmiObjectQuery | ForEach-Object {
            if($_.Name){
                [PSCustomObject]@{
                    Server = $p
                    Software = $_.Name
                    Version = $_.Version
                    } | Export-Csv -LiteralPath $file -NoTypeInformation -Append
                }
        
            }
      
        }
        } #End of beginning IF test-netconnection loop
    else{$p | Out-File "C:\Temp\offline.txt" -Append}
} #end of foreach loop