# THP Cheat Sheet Event IDs, Logging, and SIEMs

# Windows Event Logs

All Version of Windows maintain 3 core event logs:
- Application
- System
- Security

## Windows XP, Windows 2003, and any prior versions of Windows

|    <br>Event Logs      |    <br>  Event Log Path                                |
|------------------------|--------------------------------------------------------|
|    <br>Application     |    <br>%SYSTEMROOT%\System32\Config\AppEvent.evt       |
|    <br>System          |    <br>%SYSTEMROOT%\System32\Config\SysEvent.evt       |
|    <br>Security        |    <br>%SYSTEMROOT%\System32\Config\SecEvent.evt       |

## Latest Windows version (XML based)
|    <br>Event Log      |    <br> Event Log Path                                           |
|-----------------------|------------------------------------------------------------------|
|    <br>Application    |    <br> %SYSTEMROOT%\System32\Winevt\Logs\Application.evtx       |
|    <br>System         |    <br>%SYSTEMROOT%\System32\Winevt\Logs\System.evtx             |
|    <br>Security       |    <br>%SYSTEMROOT%\System32\Winevt\Logs\Security.evtx           |

## EVT & EVTX Comparison
From Windows XP Old Event Id, add 4096 to convert it to Win 7/8/10 Event ID

| Windows XP Old | Windows 7/8/10 | Description                                 |
|----------------|----------------|---------------------------------------------|
| 528            | 4624           | Successful Login                            |
| 529            | 4625           | Failed Login Attempt                        |
| 680            | 4776           | Successful Account Authentication           |
| 624            | 4720           | Creating of a new user                      |
| 636            | 4732           | A member has been added to a local group    |
| 632            | 4728           | Membership has been added to a global group |
| 2949           | 7045           | Service Creation                            |

## Event Viewer
You can access the Event Viewer by either double clicking the evtx file directly, by typing *eventvwr* in the Search box, or by navigating to:
```
 Control Panel > Administrative Tools > Event Viewer
```

Successful Account Authentication

Creating of a new user

A member has been added to a local group

Membership has been added to a global group

Service Creation
# Hunting Suspicious Accounts

Event IDs specific to account logon events
- 4624 (successful logon) 
- 4625 (failed logon) 
- 4634 (successful logoff) 
- 4647 (user-initiated logoff) 
- 4648 (logon using explicit credentials) 
- 4672 (special privileges assigned) 
- 4768 (Kerberos ticket (TGT) requested) 
- 4769 (Kerberos service ticket requested) 
- 4771 (Kerberos pre-auth failed) 
- 4776 (attempted to validate credentials) 
- 4778 (session reconnected) 
- 4779 (session disconnected)

Event IDs specific to account management: 
- 4720 (account created) 
- 4722 (account enabled) 
- 4724 (attempt to reset password) 
- 4728 (user added to global group) 
- 4732 (user added to local group) 
- 4756 (user added to universal group)

# Logon Types

|    <br>Logon Type     |    <br>Logon Title           |    <br>Description                                                                                               |
|-----------------------|------------------------------|------------------------------------------------------------------------------------------------------------------|
|    <br>2              |    <br>Interactive           |    <br>A user physically   logged onto this computer                                                             |
|    <br>3              |    <br>Network               |    <br>A user or computer   logged on from the network.                                                          |
|    <br>4              |    <br>Batch                 |    <br>Used by batch   servers where processes may be executing on behalf of a user, like scheduled   tasks.     |
|    <br>5              |    <br>Service               |    <br>A service started   by the Service Control Manager.                                                       |
|    <br>7              |    <br>Unlock                |    <br>The workstation   was unlocked.                                                                           |
|    <br>8              |    <br>NetworkClear text     |    <br>Network   credentials sent in cleartext                                                                   |
|    <br>9              |    <br>NewCredentials        |    <br>A caller cloned   its current token and specified new credentials (runas command).                        |
|    <br>10             |    <br>RemoteInteractive     |    <br>A user logged onto   computer using Terminal Services or RDP.                                             |
|    <br>11             |    <br>CachedInteractive     |    <br>A user logged onto   computer using network credentials which were stored locally on the computer.        |


## Get-WinEvent PowerShell cmdlet Cheat Sheet

Abstract
---------

Where to Acquire
---------
PowerShell is natively installed in Windows Vista and newer, and includes the Get-WinEvent cmdlet by default.

Examples/Use Case
---------
## Get-WinEvent
View all events in the live system Event Log:
```
PS C:\> Get-WinEvent -LogName system
```

View all events in the live security Event Log (requires administrator PowerShell):

```
PS C:\> Get-WinEvent -LogName security
```
View all events in the file example.evtx, format list (fl) output:
```
PS C:\> Get-WinEvent -Path example.evtx | fl
```
View all events in example.evtx, format GridView output:
```
PS C:\> Get-WinEvent -Path example.evtx | Out-GridView
```
Perform long tail analysis of example.evtx:
```
PS C:\> Get-WinEvent -Path example.evtx | Group-Object id -NoElement | sort count
```
Pull events 7030 and 7045 from system.evtx:
```
PS C:\> Get-WinEvent -FilterHashtable @{Path="system.evtx"; ID=7030,7045}
```
Same as above, but use the live system event log:
```
PS C:\> Get-WinEvent -FilterHashtable @{logname="system"; id=7030,7045}
```
Search for events containing the string "USB" in the file system.evtx:
```
PS C:\> Get-WinEvent -FilterHashtable @{Path="system.evtx"} | Where {$_.Message -like "*USB*"}
```
'grep'-style search for lines of events containing the case insensitive string "USB" in the file system.evtx:
```
PS C:\> Get-WinEvent -FilterHashtable @{Path="system.evtx"} | fl | findstr /i USB
```
Pull all errors (level=2) from application.evtx:
```
PS C:\> Get-WinEvent -FilterHashtable @{Path="application.evtx"; level=2}
```
Pull all errors (level=2) from application.evtx and count the number of lines ('wc'-style):
```
PS C:\> Get-WinEvent -FilterHashtable @{Path="application.evtx"; level=2} | Measure-Object -Line
```

### AppLocker
Pull all AppLocker logs from the live AppLocker event log (requires Applocker):
```
PS C:\> Get-WinEvent -logname "Microsoft-Windows-AppLocker/EXE and DLL"
```
Search for live AppLocker EXE/MSI block events: "(EXE) was prevented from running":
```
PS C:\> Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Applocker/EXE and DLL"; id=8004}
```
Search for live AppLocker EXE/MSI audit events: "(EXE) was allowed to run but would have been prevented from running if the AppLocker policy were enforced":
```
PS C:\> Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Applocker/EXE and DLL"; id=8003}
```

### EMET
Pull all EMET logs from the live Application Event log (requires EMET):
```
PS C:\> Get-WinEvent -FilterHashtable @{logname="application"; providername="EMET"}
 ```
Pull all EMET logs from a saved Application Event log (requires EMET):
```
PS C:\> Get-WinEvent -FilterHashtable @{path="application.evtx"; providername="EMET"}
```

### Sysmon
Pull all Sysmon logs from the live Sysmon Event log (requires Sysmon and an admin PowerShell):
```
PS C:\> Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational"
```
Pull Sysmon event ID 1 from the live Sysmon Event log
```
PS C:\> Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational"; id=1}
```
#### Sysmon Event ID 1 - Process Creation
```
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=1} | Where-Object {$_.Properties[10].Value -ilike "*TARGET_COMMANDLINE*"} | fl
```
```
 Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=1} | ? {$_
.Properties[21].Value -ilike "*TARGET_PARENTCOMMANDLINE*"} | fl
```

```
Message      : Process Create:
               RuleName: -
               UtcTime: 2022-07-06 06:18:08.890
               ProcessGuid: {221ce7aa-2920-62c5-6501-00000000e000}
               ProcessId: 3760
               Image: C:\Windows\SysWOW64\cmd.exe
               FileVersion: 10.0.17763.592 (WinBuild.160101.0800)
               Description: Windows Command Processor
               Product: Microsoft® Windows® Operating System
               Company: Microsoft Corporation
               OriginalFileName: Cmd.Exe
               CommandLine: "C:\Windows\System32\cmd.exe" /c copy
               C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe
               C:\Users\Public\Downloads\Windows_Reporting.exe
               CurrentDirectory:
               C:\Users\student\AppData\Local\Packages\Microsoft.MicrosoftEdge_8abkyb35bbwe\TempState\Downloads\
               User: ATTACKDEFENSE\Administrator
               LogonGuid: {221ce7aa-1494-62c5-c389-230000000000}
               LogonId: 0x2389C3
               TerminalSessionId: 2
               IntegrityLevel: High
               Hashes: MD5=C43699F84A68608E7E57C43B7761BBB8,SHA256=2EDB180274A51C83DDF8414D99E90315A9047B18C51DFD070326
               214D4DA59651,IMPHASH=392B4D61B1D1DADC1F06444DF258188A
               ParentProcessGuid: {221ce7aa-2920-62c5-6401-00000000e000}
               ParentProcessId: 5560
               ParentImage: C:\Windows\SysWOW64\mshta.exe
               ParentCommandLine: "C:\Windows\SysWOW64\mshta.exe" "C:\Users\student\AppData\Local\Packages\Microsoft.Mi
               crosoftEdge_8abkyb35bbwe\TempState\Downloads\report.hta"
               {1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}{1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}
               ParentUser: ATTACKDEFENSE\Administrator
```

#### Sysmon Event ID 3 - Network Connection
```
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=3} | ? {$_
.Properties[4].Value -ilike "*TARGET_IMAGE*"} | fl
```
```
Message      : Network connection detected:
               RuleName: Usermode
               UtcTime: 2022-07-06 06:18:39.090
               ProcessGuid: {221ce7aa-293e-62c5-6a01-00000000e000}
               ProcessId: 5768
               Image: C:\Users\Public\Downloads\Windows_Reporting.exe
               User: ATTACKDEFENSE\Administrator
               Protocol: tcp
               Initiated: true
               SourceIsIpv6: false
               SourceIp: 10.0.0.60
               SourceHostname: AttackDefense.ap-southeast-1.compute.internal
               SourcePort: 49822
               SourcePortName: -
               DestinationIsIpv6: false
               DestinationIp: 52.77.211.51
               DestinationHostname: ec2-52-77-211-51.ap-southeast-1.compute.amazonaws.com
               DestinationPort: 80
               DestinationPortName: http
```
#### Sysmon Event ID 8 - CreateRemoteThread
```
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=8} | Where
-Object {$_.Properties[7].Value -ilike "*TARGET_IMAGE*"} | fl
```
```
Message      : CreateRemoteThread detected:
               RuleName: -
               UtcTime: 2022-06-28 11:53:08.726
               SourceProcessGuid: {221ce7aa-eb75-62ba-0401-00000000df00}
               SourceProcessId: 1932
               SourceImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
               TargetProcessGuid: {221ce7aa-eba3-62ba-0a01-00000000df00}
               TargetProcessId: 3324
               TargetImage: C:\Windows\System32\mspaint.exe
               NewThreadId: 5548
               StartAddress: 0x00007FFF7CD1F220
               StartModule: -
               StartFunction: -
               SourceUser: ATTACKDEFENSE\Administrator
               TargetUser: ATTACKDEFENSE\Administrator
```
#### Sysmon Event ID 13 - RegistryEvent (Value Set)
```
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=13} | Where-Object{$_.Properties[5].Value -ilike '*TARGET_IMAGE*'} | fl 
```
```
Message      : Registry value set:
               RuleName: Suspicious,ImageBeginWithBackslash
               EventType: SetValue
               UtcTime: 2024-02-18 08:44:16.136
               ProcessGuid: {221ce7aa-c359-65d1-c200-00000000e000}
               ProcessId: 5604
               Image: \\?\C:\Windows\system32\wbem\WMIADAP.EXE
               TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib\Updating
               Details: WmiApRpl
               User: NT AUTHORITY\SYSTEM
```

### Windows Defender
Pull all live Windows Defender event logs
```
PS C:\> Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Windows Defender/Operational"}
```
Pull Windows Defender event logs 1116 and 1117 from the live event log
```
PS C:\> Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Windows Defender/Operational";id=1116,1117}
```
Pull Windows Defender event logs 1116 (malware detected) and 1117 (malware blocked) from a saved evtx file
```
PS C:\> Get-WinEvent -FilterHashtable @{path="WindowsDefender.evtx";id=1116,1117}
```
Additional Info
--------------
A printable PDF version of this cheatsheet is available here:
[Get-WinEvent](pdfs/Get-WinEvent.pdf)

Cheat Sheet Version
--------------
### **`Version 1.0`**


