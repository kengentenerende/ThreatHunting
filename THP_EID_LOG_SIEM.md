# THP Cheat Sheet Event IDs, Logging, and SIEMs

# Windows Event Logs

All Version of Windows maintain 3 core event logs:
- Application
    - The application log contains events logged by applications or programs
    - Program developers decide which events to log
    - For example, a database program might record a file error in the application log
- System
    - The system log contains events logged by Windows system components
    - For example, the failure of a driver or other system component to load during startup is recorded in the system log
    - The event types logged by system components are predetermined by Windows
- Security
    - The security log contains events such as valid and invalid logon  attempts, as well as events related to resource use, such as creating, opening, or deleting files or other objects
    - Administrators can specify what events are recorded in the security log
    - For example, if you have enabled logon auditing, attempts to log on to the system are recorded in the security log

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

### Account Creation Using Net Use
- When hunting for suspicious account creation, we can look for Event ID 4720 (Account Created)
- Adversaries with a sufficient level of access may create a local system, domain, or cloud tenant account. 
- The *net user* commands can be used to create a local or domain account

- Real world techniques
- Account will be created via cmd, or PowerShell. Not via GUI!!!
```
net user ncsoc_adm1n1 123456/add
```
- Check if the user was successfully created
```
net user
```
- Once added, the account will immediately being added to administrator group to have a powerful access. 
```
net localgroup administrators ncsoc_adm1n1 /add
```
- Account name normally a common username on the environment to avoid being detected

### Hunting Successful / Failed Logons

**Event ID 4624**
- After creating an account, attackers tends to log in immediately
- Another piece of information to note regarding event IDs specific to accounts is the **Login ID**
- We will know the duration of the session by the timestamps at logon and at logoff by looking at the logged field

### Most Used Logon Types

- (2) Interactive
```
Interactive
Screen Sharing
RunAs
PsExec using -l Option
```
- (3) Network
```
Guide-05/22 Gui
Access or transfer files
Native command line interaction - net.exe
Interact with system services - sc.exe
Remote task scheduler - sctasks.exe / at.exe
Remote PowerShell
Remote WMI - wmic.exe
```
- (7) Unlock
```
Unlock established RDP Sessions
```
- (10) Remote Interactive
```
Remote Desktop Protocol / Terminal Services
```


## Hunting Password Attacks
Overall, looking for a rapid succession of failed attempts to the same machine, or multiple machines, repeatedly in a small amount of time with each attempt, may indicate Password Spraying/Guessing attack. 

Of course, we know the attacker can change the timing between each attempt to make it look less suspicious. 

|    ID                  |    Description      |
|----------------------------|-------------------------|
|    Event ID 4625       |    failed logon     |
|    Logon Type 3        |    network logon    |

### Hunting Successful / Failed Logons

**Event ID 4625**
- An account failed to log on Windows keeps track of the account log on failed activities under event ID 4625
- Good indicator of brute force attack or password spraying
- Once attacker is performing brute force attack, they tend to get failed logons
- Password Spray is one way to get into the systems using collected dumped credentials such as pastebin, darkweb, paid services, etc
- We also need to look for a rapid succession of failed attempts to the same machine, or machines, repeatedly for a small space of time with each attempt


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

- To hunt for RDP sessions, look for port 3389
- Make sure to know the legitimate RDP applications running in your environment
- RMM Tools - Ghost, Anydesk, TeamViewer, VNC Connect, LogmeIn

## Hunting PsExec

PsExec, part of the SysInternals Suite, is one of the common lateral movement tools, which provides the capability to execute remote commands. Due to the way that PsExec works, we can utilize the following Event IDs to hunt for it:

|    ID                   |    Description                                             |
|-----------------------------|----------------------------------------------------------------|
|    Event ID 5145        |    (captures requests to shares, we are interested in ADMIN$ and IPC$) |
|    Event ID 5140        |    (share successfully accessed)                                       |
|    Event ID 4697 / 7045 |    (service creation)                                                  |
|    Event ID 4688        |    Sysmon EID 1                                                        |

**Sample Use Cases / Rules**

PsExec Service Start
```
(EventID:"4688" AND CommandLine:"C\:\\Windows\\PSEXESVC.exe")
```
PsExec Tool Execution
```
(EventID:"7045" AND ServiceName:"PSEXESVC" AND ServiceFileName:"*\\PSEXESVC.exe") OR (EventID:"7036" AND ServiceName:"PSEXESVC") OR (EventID:"1" AND Image:"*\\PSEXESVC.exe" AND User:"NT AUTHORITY\\SYSTEM")
```

### Alternative to PsExec
[RemCom](https://github.com/kavika13/RemCom)
- RemCom is an open-source, redistributable utility providing the same remote management functions

[PAExec](https://github.com/poweradminllc/PAExec)
- PAExec features all the same functions of RemCom and PsExec by default, PAExec
uses a named pipe containing the string PAExec combined with a unique process 
identifier and computer name values


[CSExec](https://github.com/malcomvetter/CSExec)
- CSExec is a highly configurable, C# implementation of PsExec’s functionality. By 
default, CSExec sends csexecsvc.exe to the remote computer and uses a named pipe 
called \\.\pipe\csexecsvc


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

Automatically start a process at a certain time, either once or periodically Used by malware for
- Persistence
- Lateral Movement

Configure event logging for scheduled task creation and changes by enabling the *Microsoft-Windows-TaskScheduler/Operational* setting within the event logging service Several events will then be logged on scheduled task activity, including:
- Event ID *106* on Windows 7, Server 2008 R2 - Scheduled task registered
- Event ID *140* on Windows 7, Server 2008 R2 / 4702 on Windows 10, Server 2016 - Scheduled task updated
- Event ID *141* on Windows 7, Server 2008 R2 / 4699 on Windows 10, Server 2016 - Scheduled task deleted
- Event ID *4698* on Windows 10, Server 2016 - Scheduled task created
- Event ID *4699* on Windows 10, Server 2016 - Scheduled task deleted
- Event ID *4700* on Windows 10, Server 2016 - Scheduled task enabled
- Event ID *4701* on Windows 10, Server 2016 - Scheduled task disabled

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

Attackers rarely reach the goal data from the first host
- Must pivot through the environment to gather access
- Requires both access to host and program to run
- Host access through exploit, legitimate credentials
- Code access via staging malware locally or on network
Many remote administration protocol choices
- CLI- SSH, SMB w/PSExec, PowerShell Remoting, WMI
- GUI –RDP. VNS, X11 Forwarding

**Detection**
- 4624 Logons
- 4720 Account Creation
- 4776 Local account auth
- 4672 Privileged Account Usage

**Windows Logins: Event ID 4648**
Run as style logins:
- Like *sudo* for Windows
- User X becoming account Y
- Used by attackers for pivoting through network
- Tells you who (*subject*)
- Which account they used
- Where it was used (*Target*)

When hunting for lateral movement, we'll refer to research performed by the Japan Computer Emergency Response Team Coordination Center - the results of the research are available here. 
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

# Advance Hunting

## LOLBAS 
**Living-off-the-Land Binaries and Scripts** (LOLBAS) is a term that describes Microsoft-signed, native to the OS files (or downloadable from Microsoft) that, in addition to their normal purpose, exhibit functionality which is useful to an APT or Red Team. Abusing LOLBAS increases attackers’ chances of evading detection and bypassing white listing solutions. Detection is hard, as LOLBAS activity blends in with normal activity. 

A continuously updated list with all known LOBAS files is maintained here. The list also provides descriptions, sample usage when invoked at the command line and proposed detection techniques. Common functionalities of LOLBAS are: 
- Execution 
- Download 
- Copy 

Resources:
- [Living Off The Land Binaries, Scripts and Libraries](https://lolbas-project.github.io/)
- [Fantastic Red-Team Attacks And How To Find Them](https://i.blackhat.com/USA-19/Thursday/us-19-Smith-Fantastic-Red-Team-Attacks-And-How-To-Find-Them.pdf)
- [Living off the land and fileless attack techniques](https://docs.broadcom.com/doc/istr-living-off-the-land-and-fileless-attack-techniques-en)
- [MITRE Cyber Analytics Repository](https://car.mitre.org/)

## (Unmanaged) PowerShell
In response to the high abuse and with the release of PowerShell version 5, Microsoft, in the blog post PowerShell ♥ the Blue Team, released even better enhancements to the logging capability, added Constrained language, and PowerShell scripts are submitted to AMSI – the antimalware interface. 
- [PowerShell ♥ the Blue Team](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/)


Enhanced logging (Script block logging) is great when hunting for malicious commands, as it gives visibility into the script in a plain, de-obfuscated version of a it. Some useful techniques on hunting malicious commands are described in the Sigma project under the PowerShell section. Additionally, FireEye released a great whitepaper on malicious use of PowerShell.
- [SigmaRulesWindowsPowershell](https://github.com/Neo23x0/sigma/tree/master/rules/windows/powershell )
- [THE INCREASED USE OF POWERSHELL IN ATTACKS](https://docs.broadcom.com/doc/increased-use-of-powershell-in-attacks-16-en) 

We can enable Turn On Module Logging & Turn on PowerShell Transcription as well, along with Turn On PowerShell Script Block Logging. 
Event IDs to hunt for are 
- 4104
- 4105
- 4106

## Malicious .NET and LDAP

### Execute-Assembly
Many of the PowerShell tools are being rewritten in .NET instead, in an attempt to avoid detection. Therefore, offensive tools now support injection and execution of .NET assemblies, one example is Cobalt Strike through its *execute-assembly* module.

- [Hunting For In- Memory .NET Attacks](https://www.elastic.co/security-labs/hunting-memory-net-attacks)

### .NET Tools
The enormous abuse of PowerShell resulted in close monitoring by defenders and EDR solutions, which are able to (often) detect and block even obfuscated commands. 
- [GhostPack](https://github.com/GhostPack)
- [Rubeus](https://github.com/GhostPack/Rubeus)
- [SharpView](https://github.com/tevora-threat/SharpView)
- [SharpHound](https://github.com/BloodHoundAD/SharpHound)

Hunting for the usage of .NET tools like Rubeus, combined with injection techniques such as Cobalt Strike's *execute-assembly* has proven to be a challenge task because: 
• Reflective Injection is used, so nothing is stored on disk 
• After execution, the memory region is cleared and there are very little traces of injection and/or what was injected (even in memory!).


### Event Tracing for Windows & SilkETW 
In Windows, there is a kernel-level tracing facility, which logs kernel and/or application level events to a log file known as **Event Tracing for Windows** (ETW). Although less well known, perhaps due to its complexity and the mass of events generated, it can provide valuable data for a threat hunter. **FuzzySec** released SilkETW to help deal with the complexity of setting up ETW.

- [Detecting Malicious Use of .NET](https://blog.f-secure.com/detecting-malicious-use-of-net-part-1/)
- [SilkETW & SilkService](https://github.com/mandiant/SilkETW)
- [Threat Hunting with ETW events and HELK](https://medium.com/threat-hunters-forge/threat-hunting-with-etw-events-and-helk-part-1-installing-silketw-6eb74815e4a0)

## AMSI

Essentially, AMSI provides insight into in-memory buffers, allowing AV software to analyze a de-obfuscated script, as opposed to a heavily obfuscated one stored in a file on disk. AMSI makes the execution of malicious scripts significantly more difficult. 

AMSI integrates in the following components: 
- User Account Control (UAC) 
- PowerShell 
- Windows Script Host 
- JavaScript and VBScript 
- Office VBA macro

As AMSI provides a deep look into scripts, adversaries attempt to bypass it before running malicious scripts. The following Github project contains examples of 14 bypasses as of the time of this writing. Some of them unload AMSI from the process, while others patch it in memory directly. 
![alt text](image-AMSIBYPASSPS.png)
When hunting for those techniques, they are best combined with the logging capability available. The last command generates event 4104 (presence of “amsi” is suspicious):
![alt text](image-AMSIBYPASSEL.png)

Reference: 
- [Amsi-Bypass-Powershell](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)
- [Hunting for AMSI bypasses](https://blog.f-secure.com/hunting-for-amsi-bypasses/)

## COM Hijacking
As hunters, our focus is therefore any registry additions or modifications of CLSIDs on the keys LocalServer32 or InprocServer32. If baselines are not available to compare with, we could also hunt by looking for presence of objects within HKEY_CURRENT_USER\Software\Classes\CLSID\  as their presence alone is anomalous behavior
![alt text](image.png)
References:
- [ABUSING THE COM REGISTRY STRUCTURE: CLSID, LOCALSERVER32, & INPROCSERVER32](https://bohops.com/2018/06/28/abusing-com-registry-structure-clsid-localserver32-inprocserver32/)
- [ABUSING THE COM REGISTRY STRUCTURE (PART 2): HIJACKING & LOADING TECHNIQUES](https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/)