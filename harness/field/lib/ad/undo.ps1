$ProgressPreference = 'SilentlyContinue'
# Undoes ad-trust.sh's DC changes, each only if it is there and exactly what the scenario makes; idempotent.
Import-Module ActiveDirectory
$ok = $true
if ((Get-ADUser kbruser -Properties altSecurityIdentities).altSecurityIdentities -contains 'Kerberos:alice@KERBER.TEST') {
    Set-ADUser kbruser -Remove @{ altSecurityIdentities = 'Kerberos:alice@KERBER.TEST' }; '#1 undone'
}
$h = 'C:\Windows\System32\drivers\etc\hosts'
$b = [IO.File]::ReadAllBytes($h)
$ip = '@@KDC_LAN@@'
if ($b.Length -gt 824) {
    $sha = [Security.Cryptography.SHA256]::Create()
    $head = [BitConverter]::ToString($sha.ComputeHash($b, 0, 824)).Replace('-', '')
    $tail = [Text.Encoding]::ASCII.GetString($b, 824, $b.Length - 824)
    if ($head -eq '2D6BDFB341BE3A6234B24742377F93AA7C7CFB0D9FD64EFA9282C87852E57085' -and $tail -match '\A(\d{1,3}(\.\d{1,3}){3})\tkdc\.kerber\.test\t# kerber-lab ad-trust[^\r\n]*\r\n\z') {
        $ip = $Matches[1]; [IO.File]::WriteAllBytes($h, $b[0..823]); ipconfig /flushdns | Out-Null; '#2 undone'
    } else { '#2 NOT undone: the hosts file is not the original 824 bytes plus one ad-trust line'; $ok = $false }
}
$kdcs = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Domains\KERBER.TEST').KdcNames
foreach ($k in ($ip, '@@KDC_LAN@@' | Select-Object -Unique)) {
    if ($k -and $k -ne '10.10.44.154' -and $kdcs -contains $k) { ksetup /delkdc KERBER.TEST $k | Out-Null; "#3 undone ($k)" }
}
if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\HostToRealm\KERBER.TEST') {
    ksetup /delhosttorealmmap kdc.kerber.test KERBER.TEST | Out-Null; '#4 undone'
}
if (Get-ScheduledTask -TaskName 'kerber-ra3-spnego' -ErrorAction SilentlyContinue) { Unregister-ScheduledTask -TaskName 'kerber-ra3-spnego' -Confirm:$false; '#7 task undone' }
if (Test-Path 'C:\Windows\Temp\kerber-ra3-task.txt') { Remove-Item 'C:\Windows\Temp\kerber-ra3-task.txt'; '#7 output undone' }
if ($ok) { 'undone' }
