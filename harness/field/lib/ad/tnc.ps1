$ProgressPreference = 'SilentlyContinue'
# Read-only: the DC's view of kdc.kerber.test (#2) and its TCP reach to ports 88 and 80.
[Net.Dns]::GetHostAddresses('kdc.kerber.test') | ForEach-Object { "kdc.kerber.test -> $_" }
foreach ($p in 88, 80) {
    $t = Test-NetConnection -ComputerName kdc.kerber.test -Port $p -WarningAction SilentlyContinue
    "tcp $p : TcpTestSucceeded=$($t.TcpTestSucceeded) RemoteAddress=$($t.RemoteAddress) SourceAddress=$($t.SourceAddress.IPAddress)"
}
