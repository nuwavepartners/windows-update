#### By Chris Stone <chris.stone@nuwavepartners.com> v0.0.2 2021-04-01 12:51:41

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls11;
(New-Object System.Net.WebClient).DownloadFile(
	'https://endoflife.date/api/windows.json',
	'.\Windows-OperatingSystemsSupport.json')
