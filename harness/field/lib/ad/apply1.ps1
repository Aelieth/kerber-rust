$ProgressPreference = 'SilentlyContinue'
# AD change #1 (ad-trust): alice@KERBER.TEST mapped to kbruser, beside its Kerberos:user@KERBER.TEST.
Import-Module ActiveDirectory
$v = 'Kerberos:alice@KERBER.TEST'
if ((Get-ADUser kbruser -Properties altSecurityIdentities).altSecurityIdentities -notcontains $v) { Set-ADUser kbruser -Add @{ altSecurityIdentities = $v } }
$now = (Get-ADUser kbruser -Properties altSecurityIdentities).altSecurityIdentities
$now | ForEach-Object { "altSecurityIdentities: $_" }
if ($now -contains $v) { 'applied' }
