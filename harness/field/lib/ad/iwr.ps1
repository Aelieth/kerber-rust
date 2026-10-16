$ProgressPreference = 'SilentlyContinue'
# The DC as the SPNEGO client with explicit credentials (SSPI Negotiate in this WinRM process).
$pw = ConvertTo-SecureString '@@PSQ:AD_KRBADMIN_PASSWORD@@' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('ADKERBER\krbadmin', $pw)
try {
    $r = Invoke-WebRequest -Uri 'http://kdc.kerber.test/cgi-bin/whoami' -Credential $cred -UseBasicParsing -TimeoutSec 90
    "HTTP $($r.StatusCode)"; $r.Content
} catch { "FAILED: $($_.Exception.Message)" }
