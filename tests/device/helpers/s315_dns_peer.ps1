param([string[]]$Addresses, [string]$StopPath, [string]$PlanPath)
$ErrorActionPreference = 'Stop'
$listeners = @()
$udp = @()
$connections = [Collections.Generic.List[object]]::new()
$waiting = [Collections.Generic.List[object]]::new()
$responses = @{}
$lastPlan = 0
$nextConnection = 0
$nextRequest = 0
$stats = @{received=0; exchanged=0; cancelled=0; closed=0; udp_receive_errors=0}
function Emit($row) {
    $row | ConvertTo-Json -Compress -Depth 6 | ForEach-Object { [Console]::Out.WriteLine($_); [Console]::Out.Flush() }
}
function FromHex([string]$hex) {
    $bytes = [byte[]]::new($hex.Length / 2)
    for ($n=0; $n -lt $bytes.Length; $n++) { $bytes[$n] = [Convert]::ToByte($hex.Substring(2*$n, 2), 16) }
    return ,$bytes
}
function Hex($bytes) { return ([BitConverter]::ToString($bytes)).Replace('-','').ToLowerInvariant() }
function IsDisconnect($exception) {
    while ($null -ne $exception) {
        if ($exception -is [IO.IOException] -or $exception -is [Net.Sockets.SocketException] -or
            $exception -is [ObjectDisposedException]) { return $true }
        $exception = $exception.InnerException
    }
    return $false
}
function Cancel($item, [string]$reason) {
    Emit @{kind='cancelled'; request=$item.row.request; protocol=$item.row.protocol;
        request_hex=$item.row.request_hex; reason=$reason; completed_write_bytes=$item.written}
    $script:stats.cancelled++
}
function CloseConnection($connection, [string]$reason) {
    if ($connection.closed) { return }
    $connection.closed = $true
    $connection.client.Close()
    $script:stats.closed++
    for ($index=$script:waiting.Count-1; $index -ge 0; $index--) {
        $item = $script:waiting[$index]
        if (!$item.connection -or $item.connection.id -ne $connection.id) { continue }
        Cancel $item $reason
        $script:waiting.RemoveAt($index)
    }
    Emit @{kind='connection_closed'; connection=$connection.id; buffered=$connection.bytes.Count; reason=$reason}
}
function Admit($wire, $remote, $local, [string]$protocol, $connection, $socket) {
    if ($wire.Length -lt 2 -or $wire.Length -gt 65535 -or $script:waiting.Count -ge 1024) { throw 'request capacity' }
    $script:nextRequest++
    $hex = Hex $wire
    $row = @{kind='received'; request=$script:nextRequest; protocol=$protocol;
        connection=0; received_utc=[DateTime]::UtcNow.ToString('o');
        peer=@($remote.Address.ToString(),$remote.Port); resolver=@($local.Address.ToString(),$local.Port);
        request_hex=$hex}
    if ($connection) { $row.connection=$connection.id }
    Emit $row
    $key = $protocol + ':' + $local.Port + ':' + $hex.Substring(4)
    if ($script:responses.ContainsKey($key)) { $entry=$script:responses[$key] }
    else {
        # Background system queries remain visible and receive a bounded legal
        # NXDOMAIN. This is an independent controlled resolver, not a Product codec.
        $fallback = [byte[]]$wire.Clone()
        if ($fallback.Length -ge 12) { $fallback[2]=0x81; $fallback[3]=0x83; $fallback[6]=0; $fallback[7]=0; $fallback[8]=0; $fallback[9]=0 }
        $entry=@{reply_hex=(Hex $fallback); delay_ms=0; drop=$false; gate=''; split_bytes=@()}
        $row.unplanned=$true
    }
    $delay=0
    if ($entry.delay_ms) { $delay=[int]$entry.delay_ms }
    if ($delay -lt 0 -or $delay -gt 15000) { throw 'reply delay capacity' }
    $script:waiting.Add(@{connection=$connection; socket=$socket; peer=$remote;
        wire=$wire; row=$row; entry=$entry; due=[DateTime]::UtcNow.AddMilliseconds($delay);
        deadline=[DateTime]::UtcNow.AddSeconds(30); written=0})
    $script:stats.received++
}
try {
    foreach ($address in $Addresses) {
        foreach ($port in @(53,53053)) {
            $local=[Net.IPEndPoint]::new([Net.IPAddress]::Parse($address),$port)
            $listener=[Net.Sockets.TcpListener]::new($local)
            $listener.Server.ExclusiveAddressUse=$true
            $listener.Start(16); $listeners+=$listener
            $socket=[Net.Sockets.UdpClient]::new($local.AddressFamily)
            $socket.ExclusiveAddressUse=$true
            if ($local.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { $socket.Client.DualMode=$false }
            $socket.Client.Bind($local); $udp+=$socket
        }
    }
    Emit @{kind='ready'; addresses=$Addresses; ports=@(53,53053); protocol='independent UDP and TCP DNS peer';
        connection_limit=32; pending_limit=1024; process_id=$PID}
    $deadline=[DateTime]::UtcNow.AddMinutes(20)
    while (!(Test-Path -LiteralPath $StopPath) -and [DateTime]::UtcNow -lt $deadline) {
        $stamp=(Get-Item -LiteralPath $PlanPath).LastWriteTimeUtc.Ticks
        if ($stamp -ne $lastPlan) {
            $plan=Get-Content -Raw -LiteralPath $PlanPath | ConvertFrom-Json
            $responses=@{}
            foreach ($entry in $plan.responses) { $responses[$entry.key]=$entry }
            $lastPlan=$stamp
        }
        foreach ($socket in $udp) {
            while ($true) {
                try {
                    if ($socket.Available -eq 0) { break }
                    $any=[Net.IPAddress]::Any
                    if ($socket.Client.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) { $any=[Net.IPAddress]::IPv6Any }
                    $remote=[Net.IPEndPoint]::new($any,0)
                    $wire=$socket.Receive([ref]$remote)
                } catch {
                    $socketException=$_.Exception
                    while ($null -ne $socketException -and $socketException -isnot [Net.Sockets.SocketException]) {
                        $socketException=$socketException.InnerException
                    }
                    if ($null -eq $socketException -or $socketException.SocketErrorCode -ne [Net.Sockets.SocketError]::ConnectionReset) { throw }
                    # A late reply to a retired UDP socket can surface its ICMP
                    # error on this listener's next receive. No new datagram or
                    # request obligation was obtained, and no send is replayed.
                    $stats.udp_receive_errors++
                    if ($stats.udp_receive_errors -le 64) {
                        Emit @{kind='udp_receive_error'; socket_error=$socketException.SocketErrorCode.ToString();
                            native_error=$socketException.NativeErrorCode;
                            resolver=@($socket.Client.LocalEndPoint.Address.ToString(),$socket.Client.LocalEndPoint.Port);
                            count=$stats.udp_receive_errors; outcome='no_datagram_admitted'}
                    }
                    break
                }
                Admit $wire $remote $socket.Client.LocalEndPoint 'udp' $null $socket
            }
        }
        foreach ($listener in $listeners) {
            while ($listener.Pending()) {
                $client=$listener.AcceptTcpClient(); $client.NoDelay=$true; $client.SendTimeout=2000
                if ($connections.Count -ge 32) { $client.Close(); throw 'connection capacity' }
                $nextConnection++
                $connection=@{client=$client; stream=$client.GetStream(); bytes=[Collections.Generic.List[byte]]::new();
                    id=$nextConnection; closed=$false; input_closed=$false}
                $connections.Add($connection)
                Emit @{kind='connected'; connection=$nextConnection; peer=$client.Client.RemoteEndPoint.ToString(); resolver=$client.Client.LocalEndPoint.ToString()}
            }
        }
        foreach ($connection in $connections) {
            if ($connection.closed -or $connection.input_closed) { continue }
            try {
                if (!$connection.stream.DataAvailable) {
                    if ($connection.client.Client.Poll(0,[Net.Sockets.SelectMode]::SelectRead) -and $connection.client.Client.Available -eq 0) { $connection.input_closed=$true }
                    continue
                }
                $buffer=[byte[]]::new(65536); $count=$connection.stream.Read($buffer,0,$buffer.Length)
                if ($count -le 0) { $connection.input_closed=$true; continue }
            } catch {
                if (!(IsDisconnect $_.Exception)) { throw }
                CloseConnection $connection 'read_disconnect'; continue
            }
            $connection.bytes.AddRange([byte[]]$buffer[0..($count-1)])
            if ($connection.bytes.Count -gt 131074) { throw 'TCP byte capacity' }
            while ($connection.bytes.Count -ge 2) {
                $length=[int]$connection.bytes[0]*256+[int]$connection.bytes[1]
                if ($connection.bytes.Count -lt $length+2) { break }
                $wire=$connection.bytes.GetRange(2,$length).ToArray();$connection.bytes.RemoveRange(0,$length+2)
                Admit $wire $connection.client.Client.RemoteEndPoint $connection.client.Client.LocalEndPoint 'tcp' $connection $null
            }
        }
        for ($n=0; $n -lt $waiting.Count;) {
            $item=$waiting[$n]
            if ($item.entry.gate -and !(Test-Path -LiteralPath $item.entry.gate)) {
                if ([DateTime]::UtcNow -ge $item.deadline) { throw 'reply gate deadline' }
                $n++; continue
            }
            if ([DateTime]::UtcNow -lt $item.due) { $n++; continue }
            if ($item.entry.drop) { Cancel $item 'planned_silence'; $waiting.RemoveAt($n); continue }
            $reply=FromHex $item.entry.reply_hex
            if ($reply.Length -ge 2) { $reply[0]=$item.wire[0];$reply[1]=$item.wire[1] }
            try {
                if ($item.socket) {
                    $item.written=$item.socket.Send($reply,$reply.Length,$item.peer)
                } else {
                    $framed=[byte[]]::new($reply.Length+2);$framed[0]=[byte]($reply.Length -shr 8);$framed[1]=[byte]($reply.Length -band 255)
                    [Array]::Copy($reply,0,$framed,2,$reply.Length);$offset=0
                    foreach ($part in $item.entry.split_bytes) {
                        $take=[Math]::Min([int]$part,$framed.Length-$offset)
                        if ($take -le 0) { break }
                        $item.connection.stream.Write($framed,$offset,$take);$offset+=$take;$item.written=$offset
                        if ($item.entry.split_delay_ms) { Start-Sleep -Milliseconds ([int]$item.entry.split_delay_ms) }
                    }
                    if ($offset -lt $framed.Length) { $item.connection.stream.Write($framed,$offset,$framed.Length-$offset);$item.written=$framed.Length }
                }
            } catch {
                if (!$item.connection -or !(IsDisconnect $_.Exception)) { throw }
                CloseConnection $item.connection 'write_disconnect';continue
            }
            $row=$item.row.Clone();$row.kind='exchange';$row.reply_hex=Hex $reply;$row.sent_bytes=$item.written;$row.sent_utc=[DateTime]::UtcNow.ToString('o')
            Emit $row;$waiting.RemoveAt($n);$stats.exchanged++
        }
        foreach ($connection in $connections) {
            if (!$connection.closed -and $connection.input_closed -and @($waiting|Where-Object {$_.connection -and $_.connection.id -eq $connection.id}).Count -eq 0) { CloseConnection $connection 'eof_after_replies' }
        }
        for ($n=$connections.Count-1;$n -ge 0;$n--) { if ($connections[$n].closed) { $connections.RemoveAt($n) } }
        Start-Sleep -Milliseconds 1
    }
    if (!(Test-Path -LiteralPath $StopPath)) { throw 'peer overall deadline' }
} finally {
    foreach ($connection in $connections) { CloseConnection $connection 'peer_stop' }
    $connections.Clear()
    foreach ($item in $waiting) { Cancel $item 'peer_stop' }
    $waiting.Clear()
    foreach ($listener in $listeners) { $listener.Stop() }
    foreach ($socket in $udp) { $socket.Close() }
    Emit @{kind='stopped'; pending=$waiting.Count; connections=$connections.Count;
        received=$stats.received; exchanged=$stats.exchanged; cancelled=$stats.cancelled; closed=$stats.closed;
        udp_receive_errors=$stats.udp_receive_errors}
    if ($stats.received -ne $stats.exchanged+$stats.cancelled) { throw 'peer obligation conservation' }
}
