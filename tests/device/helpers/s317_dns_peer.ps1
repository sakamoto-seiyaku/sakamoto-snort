param([string[]]$Addresses, [string]$StopPath, [string]$PlanPath)
# This runner owns only53053. Existing port53 peers remain independent.
& (Join-Path $PSScriptRoot 's315_dns_peer.ps1') -Addresses $Addresses -StopPath $StopPath -PlanPath $PlanPath -Ports @(53053)
