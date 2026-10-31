$ProgressPreference = 'SilentlyContinue'
# AD changes #2-#4 (ad-trust): the DC finds kdc.kerber.test at kdc's LAN address and asks it for KERBER.TEST.
$h = 'C:\Windows\System32\drivers\etc\hosts'
$b = [IO.File]::ReadAllBytes($h)
$sha = [Security.Cryptography.SHA256]::Create()
if ($b.Length -ne 824 -or [BitConverter]::ToString($sha.ComputeHash($b)).Replace('-', '') -ne '2D6BDFB341BE3A6234B24742377F93AA7C7CFB0D9FD64EFA9282C87852E57085') {
    'NOT applied: the hosts file is not the original 824 bytes'; exit 1
}
[IO.File]::AppendAllText($h, "@@KDC_LAN@@`tkdc.kerber.test`t# kerber-lab ad-trust @@TAG@@`r`n", [Text.Encoding]::ASCII)
ipconfig /flushdns | Out-Null
ksetup /addkdc KERBER.TEST @@KDC_LAN@@ | Out-Null
ksetup /addhosttorealmmap kdc.kerber.test KERBER.TEST | Out-Null
ksetup
'applied'
