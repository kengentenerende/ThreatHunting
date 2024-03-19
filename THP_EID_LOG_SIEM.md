# THP Cheat Sheet Event IDs, Logging, and SIEMs

# Windows Event Logs

All Version of Windows maintain 3 core event logs:
- Application
- System
- Security

## Windows XP, Windows 2003, and any prior versions of Windows

|    Event Logs      |      Event Log Path                                |
|------------------------|--------------------------------------------------------|
|    Application     |    %SYSTEMROOT%\System32\Config\AppEvent.evt       |
|    System          |    %SYSTEMROOT%\System32\Config\SysEvent.evt       |
|    Security        |    %SYSTEMROOT%\System32\Config\SecEvent.evt       |

## Latest Windows version (XML based)
|    Event Log      |     Event Log Path                                           |
|-----------------------|------------------------------------------------------------------|
|    Application    |     %SYSTEMROOT%\System32\Winevt\Logs\Application.evtx       |
|    System         |    %SYSTEMROOT%\System32\Winevt\Logs\System.evtx             |
|    Security       |    %SYSTEMROOT%\System32\Winevt\Logs\Security.evtx           |

## EVT & EVTX Comparison
From Windows XP Old Event ID, add 4096 to convert it to Win 7/8/10 Event ID

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

# Windows Event IDs

## Hunting Suspicious Accounts

### Event IDs specific to account logon events
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

### Event IDs specific to account management: 
- 4720 (account created) 
- 4722 (account enabled) 
- 4724 (attempt to reset password) 
- 4728 (user added to global group) 
- 4732 (user added to local group) 
- 4756 (user added to universal group)

### Logon Types

|    Logon Type     |    Logon Title           |    Description                                                                                               |
|-----------------------|------------------------------|------------------------------------------------------------------------------------------------------------------|
|    2              |    Interactive           |    A user physically   logged onto this computer                                                             |
|    3              |    Network               |    A user or computer   logged on from the network.                                                          |
|    4              |    Batch                 |    Used by batch   servers where processes may be executing on behalf of a user, like scheduled   tasks.     |
|    5              |    Service               |    A service started   by the Service Control Manager.                                                       |
|    7              |    Unlock                |    The workstation   was unlocked.                                                                           |
|    8              |    NetworkClear text     |    Network   credentials sent in cleartext                                                                   |
|    9              |    NewCredentials        |    A caller cloned   its current token and specified new credentials (runas command).                        |
|    10             |    RemoteInteractive     |    A user logged onto   computer using Terminal Services or RDP.                                             |
|    11             |    CachedInteractive     |    A user logged onto   computer using network credentials which were stored locally on the computer.        |

## Hunting Password Attacks
Overall, looking for a rapid succession of failed attempts to the same machine, or multiple machines, repeatedly in a small amount of time with each attempt, may indicate Password Spraying/Guessing attack. 

Of course, we know the attacker can change the timing between each attempt to make it look less suspicious. 

|    ID                  |    Description      |
|----------------------------|-------------------------|
|    Event ID 4625       |    failed logon     |
|    Logon Type 3        |    network logon    |


## Hunting Pass The Hash
We should also look for the Logon Process to be NtLmSsP and the key length to be set to 0
You can read more about this technique, here:
[How to Detect Pass-the-Hash Attacks](https://blog.netwrix.com/2021/11/30/how-to-detect-pass-the-hash-attacks/)

|    ID                  |    Description                               |
|----------------------------|--------------------------------------------------|
|    Event ID 4624       |    An account was successfully logged on     |
|    Logon Type 3        |    network logon                             |


## Hunting Golden Tickets

Oftentimes, attackers leverage native Kerberos functionality. For example, this is the case when a golden ticket is created. A golden ticket is a forged Ticket-Granting Ticket that provides the attacker with access to every network asset. You should therefore be familiar with Kerberos-related Event IDs, like 4768, when hunting for this type of attack. 

- [Event-4768](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [Detecting Lateral Movements in Windows Infrastructure](https://cert.europa.eu/static/WhitePapers/CERT-EU_SWP_17-002_Lateral_Movements.pdf)

|    ID              |    Description                                             |
|------------------------|----------------------------------------------------------------|
|    Event ID        |    4768                                                    |
|    Category        |    Account Logon                                           |
|    Sub category    |    Kerberos Authentication Service                         |
|    Description     |    A Kerberos authentication ticket (TGT) was requested    |

## Hunting RDP Sessions
If your network environment is accustomed to a lot of RDP connections into other machines, then this can be difficult to hunt for. When hunting for RDP sessions, we’re looking for Event IDs 4624 & 4778 with Logon Type 10 (Terminal Services or RDP). Also, note the expected Event IDs after successful or failed authentication attempts. 

|    ID              |    Description                                          |
|------------------------|-------------------------------------------------------------|
|    Event IDs 4624  |    Account Logon An account was successfully logged on. |
|    Event IDs 4778  |    Terminal Services or RDP                             |
|    Logon Type 10   |    Terminal Services or RDP                             |

## Hunting PsExec

PsExec, part of the SysInternals Suite, is one of the common lateral movement tools, which provides the capability to execute remote commands. Due to the way that PsExec works, we can utilize the following Event IDs to hunt for it:

|    ID                   |    Description                                             |
|-----------------------------|----------------------------------------------------------------|
|    Event ID 5145        |    (captures requests to shares, we are interested in ADMIN$ and IPC$) |
|    Event ID 5140        |    (share successfully accessed)                                       |
|    Event ID 4697 / 7045 |    (service creation)                                                  |
|    Event ID 4688        |    Sysmon EID 1                                                        |

## Hunting WMI Persistence
Hunting WMI usage for persistence involves th a WMI subscription. Therefore, our goal is to search identify any newly registered subscriptions. One way to achieve this is by utilizing WMI itself for that activity.

## Hunting Scheduled Tasks
Event ID 4698 (a scheduled task was created) is what we’ll hunt for. Also, Event IDs 106, 200, and 201 all relate to scheduled tasks. Here is an example log entry. 

|    ID              |    Description                                          |
|------------------------|-------------------------------------------------------------|
|    Event IDs 4698  |    (a scheduled task was created) |
|    106             |    generated when a new task is created, but it does not necessarily mean that the task has been executed |
|    200             |    action run - Windows Task Scheduler logs |
|    201             |    action completed - Windows Task Scheduler logs |

## Hunting Service Creations

Event ID 4697 (a service was installed in the system) is what we’ll be hunting for to find the creation of suspiciou services.

|    ID              |    Description                                             |
|--------------------|------------------------------------------------------------|
|    Event ID 4697   |   (a service was installed in the system)                  |

### Hunting Network Shares

Event ID 4776 is specific to the NTLM protocol and notifies us of successful or failed authentication attempts. Under Keywords, we should see either Audit Success or Audit Failure. Error Code will also give us information about the authentication attempt. 

|    ID              |    Description                                             |
|--------------------|------------------------------------------------------------|
|    Event ID 4776   |   A domain controller (DC) attempts to validate the credentials of an account using NTLM over Kerberos                  |
  	

Other Event IDs specific to network shares are Event IDs 5140 and 5145. Note: In order to see these event logs, a policy setting mu be enabled. This setting is within the Advanced Audit Policy Configuration > Object Access > Audit File Share.

|    ID              |    Description                                             |
|--------------------|------------------------------------------------------------|
|    Event ID 5140   |   A network share object was accessed |
|    Event ID 5145   |   A Network Share Object Was Checked To See Whether Client Can Be Granted Desired Access. |
	
## Hunting Lateral Movement
When hunting for lateral movement, we’ll refer to research performed by the Japan Computer Emergency Response Team Coordination Center - the results of the research are available here. 
- [Tool Analysis Result Sheet](https://jpcertcc.github.io/ToolAnalysisResultSheet/)

You can also check out resources from the Threat Hunting Project here, here
- [Windows Lateral Movement via Explicit Credentials](https://github.com/ThreatHuntingProject/ThreatHunting/blob/master/hunts/lateral-movement-via-explicit-credentials.md)
- [Detecting Lateral Movement in Windows Event Logs](https://github.com/ThreatHuntingProject/ThreatHunting/blob/master/hunts/lateral-movement-windows-authentication-logs.md )
- [Lateral Movement Detection via Process Monitoring](https://github.com/ThreatHuntingProject/ThreatHunting/blob/master/hunts/lateral_movement_detection_via_process_monitoring.md) 

## Windows Log Rotation & Clearing
If event logs are not forwarded, then they are at risk of being cleared (deleted) or rotated from the endpoint device.

To clear event logs, administrative rights are needed. It is possible to clear the event logs without admin rights flooding the endpoint with events to generate logs that will rotate the logs that can be seen within tools such as Even Viewer

Event IDs to hunt for regarding log clearing are Event IDs 1102 and 104.

|    ID              |    Description                                             |
|--------------------|------------------------------------------------------------|
|    Event ID 1102   |   Windows Security audit log is cleared |
|    Event ID 1104   |   The security Log is now full          |

# Sysmon Event ID
|     ID    |     Tag                       |     Event                                                 |
|-----------|-------------------------------|-----------------------------------------------------------|
|     1     |     ProcessCreate             |     Process   Create                                      |
|     2     |     FileCreateTime            |     File   creation time                                  |
|     3     |     NetworkConnect            |     Network   connection detected                         |
|     4     |     n/a                       |     Sysmon   service state change (cannot be filtered)    |
|     5     |     ProcessTerminate          |     Process   terminated                                  |
|     6     |     DriverLoad                |     Driver   Loaded                                       |
|     7     |     ImageLoad                 |     Image   loaded                                        |
|     8     |     CreateRemoteThread        |     CreateRemoteThread   detected                         |
|     9     |     RawAccessRead             |     RawAccessRead   detected                              |
|     10    |     ProcessAccess             |     Process   accessed                                    |
|     11    |     FileCreate                |     File   created                                        |
|     12    |     RegistryEvent             |     Registry   object added or deleted                    |
|     13    |     RegistryEvent             |     Registry   value set                                  |
|     14    |     RegistryEvent             |     Registry   object renamed                             |
|     15    |     FileCreateStreamHash      |     File   stream created                                 |
|     16    |     n/a                       |     Sysmon   configuration change (cannot be filtered)    |
|     17    |     PipeEvent                 |     Named   pipe created                                  |
|     18    |     PipeEvent                 |     Named   pipe connected                                |
|     19    |     WmiEvent                  |     WMI   filter                                          |
|     20    |     WmiEvent                  |     WMI   consumer                                        |
|     21    |     WmiEvent                  |     WMI   consumer filter                                 |
|     22    |     DNSQuery                  |     DNS   query                                           |
|     23    |     FileDelete                |     File   Delete archived                                |
|     24    |     ClipboardChange           |     New   content in the clipboard                        |
|     25    |     ProcessTampering          |     Process   image change                                |
|     26    |     FileDeleteDetected        |     File   Delete logged                                  |
|     27    |     FileBlockExecutable       |     File   Block Executable                               |
|     28    |     FileBlockShredding        |     File   Block Shredding                                |
|     29    |     FileExecutableDetected    |     File   Executable Detected                            |

## Hunting in Sysmon
Pull all Sysmon logs from the live Sysmon Event log (requires Sysmon and an admin PowerShell):
```
PS C:\> Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational"
```
Pull Sysmon event ID 1 from the live Sysmon Event log
```
PS C:\> Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational"; id=1}
```
Generic Hunting For Macros
```
Get-SysmonLogsProcessStarts | ? parentimage  -like '*winword*'
Get-SysmonLogsProcessStarts | ? commandline -like '*shell*'
Get-SysmonLogsProcessStarts 
```
Sysmon Event ID  10 - Process Access
```
get-winevent -FilterHashTable @{logname="'Microsoft-Windows-Sysmon/Operational"; id=10} | %{$_.Properties[0]} 
get-winevent -FilterHashTable @{logname="'Microsoft-Windows-Sysmon/Operational"; id=10} | %{$_.Properties[4]}
get-winevent -FilterHashTable @{logname="'Microsoft-Windows-Sysmon/Operational"; id=10} | %{$_.Properties[7]}
get-winevent -FilterHashTable @{logname="'Microsoft-Windows-Sysmon/Operational"; id=10} | %{$_.Properties[9].Value}
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

# Get-WinEvent PowerShell cmdlet Cheat Sheet
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


