$ProgressPreference = 'SilentlyContinue'
# AD change #7 (ad-trust): a scheduled task as krbadmin runs Invoke-WebRequest -UseDefaultCredentials once, then is removed.
"time (UTC): $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
$name = 'kerber-ra3-spnego'
$out = 'C:\Windows\Temp\kerber-ra3-task.txt'
# The task body: no secret in it. It runs in krbadmin's own (batch, password) logon session.
$inner = @'
$ProgressPreference = 'SilentlyContinue'
$o = 'C:\Windows\Temp\kerber-ra3-task.txt'
& {
    "task logon session: $(whoami)   time (UTC): $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
    '== Invoke-WebRequest http://kdc.kerber.test/cgi-bin/whoami -UseDefaultCredentials'
    try {
        $r = Invoke-WebRequest -Uri 'http://kdc.kerber.test/cgi-bin/whoami' -UseDefaultCredentials -UseBasicParsing -TimeoutSec 90
        "HTTP $($r.StatusCode)"; $r.Content
    } catch { "FAILED: $($_.Exception.Message)" }
    '== klist (this logon session)'
    klist
} *>&1 | Out-File -FilePath $o -Encoding utf8 -Width 300
'@
$b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $b64"
'== register a temporary task as ADKERBER\krbadmin (password logon) and run it once'
Register-ScheduledTask -TaskName $name -Action $action -User 'ADKERBER\krbadmin' -Password '@@PSQ:AD_KRBADMIN_PASSWORD@@' -RunLevel Limited | Out-Null
"registered (UTC): $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))"
Start-ScheduledTask -TaskName $name
$t0 = Get-Date
do { Start-Sleep -Seconds 2; $st = (Get-ScheduledTask -TaskName $name).State } while ($st -ne 'Ready' -and ((Get-Date) - $t0).TotalSeconds -lt 150)
$info = Get-ScheduledTaskInfo -TaskName $name
"task state: $st   LastTaskResult: $($info.LastTaskResult)"
'== the task output'
if (Test-Path $out) { Get-Content $out } else { '(no output file)' }
'== clean up: unregister the task, delete its output'
Unregister-ScheduledTask -TaskName $name -Confirm:$false
Remove-Item $out -ErrorAction SilentlyContinue
"removed (UTC): $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))   task still present: $([bool](Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue))   output file still present: $(Test-Path $out)"
