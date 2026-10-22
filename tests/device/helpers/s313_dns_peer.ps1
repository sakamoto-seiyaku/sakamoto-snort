param([string[]]$Addresses, [string]$StopPath, [string]$PlanPath)
$ErrorActionPreference = 'Stop'
$listeners = @()
$connections = [Collections.Generic.List[object]]::new()
$waiting = [Collections.Generic.List[object]]::new()
$responses = @{}
$lastPlan = 0
$nextConnection = 0
$stats = @{received=0; exchanged=0; cancelled=0; closed=0}
function FromHex([string]$hex) {
    $bytes = [byte[]]::new($hex.Length / 2)
    for ($n=0; $n -lt $bytes.Length; $n++) { $bytes[$n] = [Convert]::ToByte($hex.Substring(2*$n, 2), 16) }
    return ,$bytes
}
function IsDisconnect($exception) {
    while ($null -ne $exception) {
        if ($exception -is [IO.IOException] -or $exception -is [Net.Sockets.SocketException] -or
            $exception -is [ObjectDisposedException]) { return $true }
        $exception = $exception.InnerException
    }
    return $false
}
function CloseConnection($connection, [string]$reason) {
    if ($connection.closed) { return }
    $connection.closed = $true
    $connection.client.Close()
    $script:stats.closed++
    for ($index=$script:waiting.Count-1; $index -ge 0; $index--) {
        $item = $script:waiting[$index]
        if ($item.connection.id -ne $connection.id) { continue }
        # A failed Write can have transmitted a prefix. This is cancellation of
        # the fixture obligation, never a claim that zero bytes reached wire.
        @{kind='cancelled'; connection=$connection.id; request=$item.row.request;
          request_hex=$item.row.request_hex; reason=$reason;
          completed_write_bytes=$item.written; partial_write_unknown=$item.write_failed} | ConvertTo-Json -Compress
        $script:waiting.RemoveAt($index)
        $script:stats.cancelled++
    }
    @{kind='connection_closed'; connection=$connection.id;
      buffered=$connection.bytes.Count; reason=$reason} | ConvertTo-Json -Compress
}
try {
    foreach ($address in $Addresses) {
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Parse($address), 53)
        $listener.Server.ExclusiveAddressUse = $true
        $listener.Start(16)
        $listeners += $listener
    }
    @{kind='ready'; addresses=$Addresses; protocol='independent ordinary TCP DNS peer';
      connection_limit=32; pending_limit=4096; process_id=$PID} | ConvertTo-Json -Compress
    $deadline = [DateTime]::UtcNow.AddMinutes(20)
    while (!(Test-Path -LiteralPath $StopPath) -and [DateTime]::UtcNow -lt $deadline) {
        $stamp = (Get-Item -LiteralPath $PlanPath).LastWriteTimeUtc.Ticks
        if ($stamp -ne $lastPlan) {
            $plan = Get-Content -Raw -LiteralPath $PlanPath | ConvertFrom-Json
            $responses = @{}
            foreach ($entry in $plan.responses) { $responses[$entry.request_hex] = $entry }
            $lastPlan = $stamp
        }
        foreach ($listener in $listeners) {
            while ($listener.Pending()) {
                $client = $listener.AcceptTcpClient()
                $client.NoDelay = $true
                $client.SendTimeout = 2000
                if ($connections.Count -ge 32) { $client.Close(); throw 'connection capacity' }
                $nextConnection++
                $connection = @{client=$client; stream=$client.GetStream();
                    bytes=[Collections.Generic.List[byte]]::new(); id=$nextConnection;
                    next_request=0; closed=$false; input_closed=$false}
                $connections.Add($connection)
                @{kind='connected'; connection=$nextConnection; peer=$client.Client.RemoteEndPoint.ToString();
                  resolver=$client.Client.LocalEndPoint.ToString()} | ConvertTo-Json -Compress
            }
        }
        foreach ($connection in $connections) {
            if ($connection.closed -or $connection.input_closed) { continue }
            $stream = $connection.stream
            try {
                if (!$stream.DataAvailable) {
                    # Readability can mean data arrived after DataAvailable.
                    # Only a readable socket with no available bytes proves EOF.
                    if ($connection.client.Client.Poll(0, [Net.Sockets.SelectMode]::SelectRead) -and
                        $connection.client.Client.Available -eq 0) { $connection.input_closed=$true }
                    continue
                }
                $buffer = [byte[]]::new(65536)
                $count = $stream.Read($buffer, 0, $buffer.Length)
                if ($count -le 0) { $connection.input_closed=$true; continue }
            } catch {
                if (!(IsDisconnect $_.Exception)) { throw }
                CloseConnection $connection 'read_disconnect'
                continue
            }
            $connection.bytes.AddRange([byte[]]$buffer[0..($count-1)])
            if ($connection.bytes.Count -gt 1048576) { throw 'byte capacity' }
            while ($connection.bytes.Count -ge 2) {
                $length = [int]$connection.bytes[0] * 256 + [int]$connection.bytes[1]
                if ($connection.bytes.Count -lt $length + 2) { break }
                $wire = $connection.bytes.GetRange(2, $length).ToArray()
                $connection.bytes.RemoveRange(0, $length + 2)
                $key = ([BitConverter]::ToString($wire)).Replace('-','').ToLowerInvariant()
                $remote = $connection.client.Client.RemoteEndPoint
                $local = $connection.client.Client.LocalEndPoint
                $connection.next_request++
                $row = @{kind='received'; connection=$connection.id; request=$connection.next_request;
                    received_utc=[DateTime]::UtcNow.ToString('o');
                    peer=@($remote.Address.ToString(),$remote.Port); resolver=@($local.Address.ToString(),$local.Port);
                    request_hex=$key}
                $row | ConvertTo-Json -Compress
                if (!$responses.ContainsKey($key) -or $waiting.Count -ge 4096) { throw 'unplanned request or capacity' }
                $waiting.Add(@{connection=$connection; row=$row; entry=$responses[$key];
                    deadline=[DateTime]::UtcNow.AddSeconds(90); written=0; write_failed=$false})
                $stats.received++
            }
        }
        # Each connection keeps request order while a gate can hold its next
        # reply. Other connections continue without waiting for that gate.
        $gated = @{}
        for ($n=0; $n -lt $waiting.Count;) {
            $item = $waiting[$n]
            if ($gated.ContainsKey($item.connection.id)) { $n++; continue }
            if ($item.entry.gate -and !(Test-Path -LiteralPath $item.entry.gate)) {
                if ([DateTime]::UtcNow -ge $item.deadline) { throw 'reply gate deadline' }
                $gated[$item.connection.id] = $true
                $n++; continue
            }
            $reply = FromHex $item.entry.reply_hex
            $copies = 1
            if ($item.entry.frame_copies) { $copies = [int]$item.entry.frame_copies }
            if ($copies -lt 1 -or $copies -gt 2) { throw 'coalesced reply capacity' }
            $oneFrame = [byte[]]::new($reply.Length + 2)
            $oneFrame[0] = [byte]($reply.Length -shr 8); $oneFrame[1] = [byte]($reply.Length -band 255)
            [Array]::Copy($reply,0,$oneFrame,2,$reply.Length)
            $framed = [byte[]]::new($oneFrame.Length * $copies)
            for ($copy=0; $copy -lt $copies; $copy++) {
                [Array]::Copy($oneFrame,0,$framed,$copy*$oneFrame.Length,$oneFrame.Length)
            }
            $offset = 0
            try {
                foreach ($part in $item.entry.split_bytes) {
                    $take = [Math]::Min([int]$part, $framed.Length-$offset)
                    if ($take -le 0) { break }
                    $item.connection.stream.Write($framed,$offset,$take)
                    $offset += $take; $item.written = $offset
                    if ($item.entry.split_delay_ms) { Start-Sleep -Milliseconds ([int]$item.entry.split_delay_ms) }
                }
                if ($offset -lt $framed.Length) {
                    $item.connection.stream.Write($framed,$offset,$framed.Length-$offset)
                    $item.written = $framed.Length
                }
            } catch {
                if (!(IsDisconnect $_.Exception)) { throw }
                $item.write_failed = $true
                CloseConnection $item.connection 'write_disconnect'
                # CloseConnection removes every waiting item for this one
                # connection. Revisit this index, which may now name another.
                continue
            }
            $row = $item.row.Clone(); $row.kind='exchange'; $row.reply_hex=$item.entry.reply_hex
            $row.frame_copies=$copies
            $row.sent_bytes=$framed.Length; $row.sent_utc=[DateTime]::UtcNow.ToString('o')
            $row | ConvertTo-Json -Compress
            $waiting.RemoveAt($n); $stats.exchanged++
        }
        foreach ($connection in $connections) {
            if (!$connection.closed -and $connection.input_closed -and
                @($waiting | Where-Object { $_.connection.id -eq $connection.id }).Count -eq 0) {
                CloseConnection $connection 'eof_after_replies'
            }
        }
        for ($n=$connections.Count-1; $n -ge 0; $n--) {
            if ($connections[$n].closed) { $connections.RemoveAt($n) }
        }
        Start-Sleep -Milliseconds 1
    }
    if (!(Test-Path -LiteralPath $StopPath)) { throw 'peer overall deadline' }
} finally {
    $pendingBefore = $waiting.Count
    $connectionsBefore = @($connections | Where-Object { !$_.closed }).Count
    foreach ($connection in $connections) { CloseConnection $connection 'peer_stop' }
    $connections.Clear()
    foreach ($listener in $listeners) { $listener.Stop() }
    @{kind='stopped'; pending=$waiting.Count; connections=$connections.Count;
      pending_before_close=$pendingBefore; connections_before_close=$connectionsBefore;
      received=$stats.received; exchanged=$stats.exchanged; cancelled=$stats.cancelled;
      closed=$stats.closed} | ConvertTo-Json -Compress
    if ($waiting.Count -ne 0 -or $stats.received -ne $stats.exchanged+$stats.cancelled) {
        throw 'peer obligation conservation'
    }
}
