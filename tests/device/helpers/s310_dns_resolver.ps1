param([string[]]$Addresses, [string]$StopPath)
$ErrorActionPreference = 'Stop'
$clients = @()
$pending = @()
try {
    foreach ($address in $Addresses) {
        $endpoint = [Net.IPEndPoint]::new([Net.IPAddress]::Parse($address), 53)
        $client = [Net.Sockets.UdpClient]::new($endpoint)
        $clients += $client
        $pending += $client.BeginReceive($null, $null)
    }
    @{kind='ready'; addresses=$Addresses} | ConvertTo-Json -Compress
    $deadline = [DateTime]::UtcNow.AddMinutes(15)
    while (!(Test-Path -LiteralPath $StopPath) -and [DateTime]::UtcNow -lt $deadline) {
        for ($i=0; $i -lt $clients.Count; $i++) {
            if (!$pending[$i].IsCompleted) { continue }
            $peer = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
            $wire = $clients[$i].EndReceive($pending[$i], [ref]$peer)
            $reply = [byte[]]$wire.Clone()
            if ($reply.Length -ge 4) { $reply[2] = $reply[2] -bor 128 }
            $local = $clients[$i].Client.LocalEndPoint
            @{kind='exchange'; received_utc=[DateTime]::UtcNow.ToString('o');
              peer=@($peer.Address.ToString(),$peer.Port);
              resolver=@($local.Address.ToString(),$local.Port);
              request_hex=([BitConverter]::ToString($wire)).Replace('-','').ToLowerInvariant();
              reply_hex=([BitConverter]::ToString($reply)).Replace('-','').ToLowerInvariant()
            } | ConvertTo-Json -Compress
            [void]$clients[$i].Send($reply, $reply.Length, $peer)
            $pending[$i] = $clients[$i].BeginReceive($null, $null)
        }
        Start-Sleep -Milliseconds 10
    }
} finally {
    foreach ($client in $clients) { $client.Close() }
}
