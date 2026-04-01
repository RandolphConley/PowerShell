# This script is simple, it will display active AD users based on properties to a csv.

$Path = Read-Host "Enter Export Path here"

get-aduser -filter { Enabled -eq $true } -Properties DisplayName, Department, EmailAddress | Select-Object Department, DisplayName, SamAccountName, EmailAddress | Export-Csv -Path $Path
