$ProgressPreference = 'SilentlyContinue'
# Read-only: the DC's 4768/4769 events for the lab principals in a window on the DC's own clock (UTC).
$from = [DateTime]::Parse('@@FROM@@').ToLocalTime(); $to = [DateTime]::Parse('@@TO@@').ToLocalTime()
"window (DC clock, UTC): @@FROM@@ .. @@TO@@"
$n = 0
foreach ($e in (Get-WinEvent -FilterHashtable @{ LogName = 'Security'; StartTime = $from; EndTime = $to; Id = 4768, 4769, 4771 } -ErrorAction SilentlyContinue | Sort-Object TimeCreated)) {
    $x = [xml]$e.ToXml(); $d = @{}; foreach ($f in $x.Event.EventData.Data) { $d[$f.Name] = $f.'#text' }
    if (($d['TargetUserName'] -match '^(kbruser|alice|krbadmin|user|bob)(@|$)|@KERBER\.TEST') -or ($d['ServiceName'] -match 'KERBER\.TEST')) {
        $n++
        '{0:o}  {1}  user={2}  domain={3}  service={4}  status={5}  tktEnc={6}  ip={7}' -f $e.TimeCreated.ToUniversalTime(), $e.Id, $d['TargetUserName'], $d['TargetDomainName'], $d['ServiceName'], $d['Status'], $d['TicketEncryptionType'], $d['IpAddress']
    }
}
"($n events)"
