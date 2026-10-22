param([string[]]$Addresses, [string]$StopPath, [string]$PlanPath)
$ErrorActionPreference = 'Stop'
$clients = @()
$receivers = @()
$waiting = [Collections.Generic.List[object]]::new()
$responses = @{}
$lastPlan = 0
function FromHex([string]$hex) {
    $bytes = [byte[]]::new($hex.Length / 2)
    for ($n=0; $n -lt $bytes.Length; $n++) { $bytes[$n] = [Convert]::ToByte($hex.Substring(2*$n, 2), 16) }
    return ,$bytes
}
try {
    foreach ($address in $Addresses) {
        $local = [Net.IPEndPoint]::new([Net.IPAddress]::Parse($address), 53)
        $socket = [Net.Sockets.UdpClient]::new($local)
        $socket.Client.ReceiveBufferSize = 1048576
        $clients += $socket
        $receivers += $socket.BeginReceive($null, $null)
    }
    @{kind='ready'; addresses=$Addresses; protocol='explicit independent wire fixtures'; pending_limit=2048} | ConvertTo-Json -Compress
    $deadline = [DateTime]::UtcNow.AddMinutes(15)
    while (!(Test-Path -LiteralPath $StopPath) -and [DateTime]::UtcNow -lt $deadline) {
        $stamp = (Get-Item -LiteralPath $PlanPath).LastWriteTimeUtc.Ticks
        if ($stamp -ne $lastPlan) {
            $plan = Get-Content -Raw -LiteralPath $PlanPath | ConvertFrom-Json
            $responses = @{}
            foreach ($entry in $plan.responses) { $responses[$entry.request_hex] = $entry }
            $lastPlan = $stamp
        }
        for ($i=0; $i -lt $clients.Count; $i++) {
            if (!$receivers[$i].IsCompleted) { continue }
            $remote = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
            $wire = $clients[$i].EndReceive($receivers[$i], [ref]$remote)
            $receivers[$i] = $clients[$i].BeginReceive($null, $null)
            $key = ([BitConverter]::ToString($wire)).Replace('-','').ToLowerInvariant()
            $local = $clients[$i].Client.LocalEndPoint
            $row = @{kind='received'; received_utc=[DateTime]::UtcNow.ToString('o');
                     peer=@($remote.Address.ToString(),$remote.Port);
                     resolver=@($local.Address.ToString(),$local.Port); request_hex=$key}
            $row | ConvertTo-Json -Compress
            if (!$responses.ContainsKey($key) -or $waiting.Count -ge 2048) {
                @{kind='unplanned_or_capacity'; request_hex=$key} | ConvertTo-Json -Compress
                continue
            }
            $entry = $responses[$key]
            $waiting.Add(@{client=$i; peer=$remote; row=$row; entry=$entry;
                           deadline=[DateTime]::UtcNow.AddSeconds(90)})
        }
        for ($n=$waiting.Count-1; $n -ge 0; $n--) {
            $item = $waiting[$n]
            if ($item.entry.gate -and !(Test-Path -LiteralPath $item.entry.gate)) {
                if ([DateTime]::UtcNow -lt $item.deadline) { continue }
                @{kind='gate_timeout'; request_hex=$item.row.request_hex} | ConvertTo-Json -Compress
                $waiting.RemoveAt($n); continue
            }
            $reply = FromHex $item.entry.reply_hex
            $sent = $clients[$item.client].Send($reply, $reply.Length, $item.peer)
            $row = $item.row.Clone()
            $row.kind='exchange'; $row.reply_hex=$item.entry.reply_hex
            $row.sent_bytes=$sent; $row.sent_utc=[DateTime]::UtcNow.ToString('o')
            $row | ConvertTo-Json -Compress
            $waiting.RemoveAt($n)
        }
        Start-Sleep -Milliseconds 2
    }
} finally {
    foreach ($client in $clients) { $client.Close() }
    @{kind='stopped'; pending=$waiting.Count} | ConvertTo-Json -Compress
}
