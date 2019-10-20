# Random Windows

## Writable by user Windows directories

Source: https://twitter.com/mattifestation/status/1172520995472756737

```
%windir%\system32\microsoft\crypto\rsa\machinekeys
%windir%\system32\tasks_migrated\microsoft\windows\pla\system
%windir%\syswow64\tasks\microsoft\windows\pla\system
%windir%\debug\wia
%windir%\system32\tasks
%windir%\syswow64\tasks
%windir%\tasks
%windir%\registration\crmlog
%windir%\system32\com\dmp
%windir%\system32\fxstmp
%windir%\system32\spool\driver\color
%windir%\system32\spool\printers
%windir%\system32\spool\servers
%windir%\syswow64\com\dmp
%windir%\syswow64\fxstmp
%windir%\temp
%windir%\tracing
```

## One-Liners

[Unique hash of every executable running](https://twitter.com/CyberRaiju/status/1151111821807349760)

```$A = $( foreach ($process in Get-WmiObject win32_process | where {$_.ExecutablePath -notlike ""}) {Get-FileHash $process.ExecutablePath | select Hash -ExpandProperty Hash}) |Sort-Object| Get-Unique;$A```

[Missing Windows Updates](https://twitter.com/wincmdfu/status/1140668272821460995)

```(New-Object -ComObject microsoft.update.session).CreateUpdateSearcher().Search("IsHidden=0 and IsInstalled=0").Updates | select Title,RebootRequired,CVEIds,IsMandatory```

[Disable Defender Remotely to Execute Code](https://twitter.com/Killswitch_GUI/status/1125930621346488320)

```Invoke-WmiMethod -ComputerName 10.0.1.2 -Class Win32_Process -Name Create -ArgumentList "powershell.exe -C `Set-MpPreference -DisableRealtimeMonitoring $true`"```

[List of IPs that have connected via RDP](https://twitter.com/wincmdfu/status/1098234743752032256)

```Get-WinEvent -Log 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' | select -exp Properties | where {$_.Value -like '*.*.*.*' } | sort Value -u```


## Access AWS Server on WinRM via HTTPS from external IP

1. Ensure that network security group allows inbound WinRM_HTTP/TCP/5986.  
2. Restric this access to your Public IP.  
3. Run below code (Adapted From Source: https://gist.github.com/andrewiankidd/f47e8bc7d6a2cc68711e8d3e01850b8a)

```
$dnsIP4 = curl http://169.254.169.254/latest/meta-data/public-hostname | Select-Object -ExpandProperty Content

##enable winrm
Write-Host "------Enabling WinRM (HTTP)"
winrm quickconfig -q

Write-Host "------Genning Thumbprint"
#get thumbprint
$thumbprint = (New-SelfSignedCertificate -certstorelocation cert:\localmachine\my -dnsname $dnsIP4 -NotAfter (Get-Date).AddMonths(36)).Thumbprint

Write-Host "------Proceeding with following details"
#create cert
Write-Host dnsIP4: $dnsIP4, thumbprint: $thumbprint
$cmd = 'winrm create winrm/config/listener?Address=*+Transport=HTTPS `@`{Hostname=`"$dnsIP4`"`; CertificateThumbprint=`"$thumbprint`"`}'

Write-Host "------Enabling WinRM (HTTPS)"
Invoke-Expression $cmd

Write-Host "------Making Firewall rule"
#poke hole in firewall
& netsh advfirewall firewall add rule name="winRM HTTPS" dir=in action=allow protocol=TCP localport=5986

Write-Host "------Testing WinRM"
& test-wsman $dnsIP4
```


