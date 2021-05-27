$servers = Get-Content "C:\Temp\ServerFullList.txt"

foreach($s in $servers){
Write-Verbose -Verbose "Trying $s"
        if(Test-NetConnection -Port 5985 -ComputerName $s){
                $LocalAdmins = invoke-command -computername $s -HideComputerName { $members = net localgroup administrators | Where-Object {$_ -AND $_ -notmatch "command completed successfully"} | 
                Select-Object -skip 4
                    New-Object PSObject -Property @{
                    Computername = $env:COMPUTERNAME
                    Group = "Administrators"
                    Members=$members -join ","
                    }
                        } -ErrorAction SilentlyContinue #end of $localAdmins variable
                    
                        if($LocalAdmins){$LocalAdmins  | Select-Object * -ExcludeProperty RunspaceID,PSComputerName,PSShowComputerName | Export-CSV c:\temp\ServerAdministrators.csv -NoTypeInformation -Append}
                        else{"$s does not accept remote powershell" | Out-File C:\temp\ServersNoPowerShell.txt -Append}     
                    } #end of test-netconnection if statement
}