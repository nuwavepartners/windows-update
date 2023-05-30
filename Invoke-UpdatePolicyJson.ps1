#### By Chris Stone <chris.stone@nuwavepartners.com> v0.0.2 2021-04-01 12:51:41

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls11;
& ([scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://vcs.nuwave.link/git/windows/update/blob_plain/master:/Update-JsonUpdatePolicy.ps1')))
