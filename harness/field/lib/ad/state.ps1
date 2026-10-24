$ProgressPreference = 'SilentlyContinue'
# Read-only. ad-trust.sh compares every line but the "info" ones with baseline.txt, before and after a run.
Import-Module ActiveDirectory
$kb = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos'
$b = [IO.File]::ReadAllBytes('C:\Windows\System32\drivers\etc\hosts')
$sha = [Security.Cryptography.SHA256]::Create()
'alt: ' + (((Get-ADUser kbruser -Properties altSecurityIdentities).altSecurityIdentities | Sort-Object) -join ' | ')
'hosts: {0} {1}' -f $b.Length, [BitConverter]::ToString($sha.ComputeHash($b)).Replace('-', '')
'kdcnames: ' + ((Get-ItemProperty "$kb\Domains\KERBER.TEST").KdcNames -join ' | ')
'realmflags: ' + (Get-ItemProperty "$kb\Domains\KERBER.TEST").RealmFlags
'hosttorealm: ' + ((Get-ChildItem "$kb\HostToRealm" -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName + '=' + ((Get-ItemProperty $_.PSPath).SpnMappings -join ',') }) -join ' | ')
'task: ' + [bool](Get-ScheduledTask -TaskName 'kerber-ra3-spnego' -ErrorAction SilentlyContinue)
'taskfile: ' + (Test-Path 'C:\Windows\Temp\kerber-ra3-task.txt')
$t = Get-ADObject -Filter "objectClass -eq 'trustedDomain' -and name -eq 'KERBER.TEST'" -Properties trustDirection, trustType, trustAttributes, 'msDS-SupportedEncryptionTypes', whenChanged
'trust: {0} direction={1} type={2} attributes={3} enctypes={4} changed={5:yyyy-MM-dd}' -f $t.Name, $t.trustDirection, $t.trustType, $t.trustAttributes, $t.'msDS-SupportedEncryptionTypes', $t.whenChanged.ToUniversalTime()
foreach ($u in 'kbruser', 'krbadmin') {
    $a = Get-ADUser $u -Properties PasswordLastSet, PasswordNeverExpires, LockedOut, Enabled
    'info account: {0} enabled={1} locked={2} neverexpires={3} lastset={4:yyyy-MM-dd}' -f $u, $a.Enabled, $a.LockedOut, $a.PasswordNeverExpires, $a.PasswordLastSet.ToUniversalTime()
}
'info maxpasswordage: {0} days' -f (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge.TotalDays
