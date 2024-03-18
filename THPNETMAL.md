# THP Cheat Sheet Hunting .Net Malware

## Sysmon Event ID 1 - Process Creation
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

# Get-WinEvent PowerShell cmdlet Cheat Sheet

Abstract
---------

Where to Acquire
---------
PowerShell is natively installed in Windows Vista and newer, and includes the Get-WinEvent cmdlet by default.

Examples/Use Case
---------
### Get-WinEvent
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

#### AppLocker
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

#### EMET
Pull all EMET logs from the live Application Event log (requires EMET):
```
PS C:\> Get-WinEvent -FilterHashtable @{logname="application"; providername="EMET"}
 ```
Pull all EMET logs from a saved Application Event log (requires EMET):
```
PS C:\> Get-WinEvent -FilterHashtable @{path="application.evtx"; providername="EMET"}
```

#### Sysmon
Pull all Sysmon logs from the live Sysmon Event log (requires Sysmon and an admin PowerShell):
```
PS C:\> Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational"
```
Pull Sysmon event ID 1 from the live Sysmon Event log
```
PS C:\> Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational"; id=1}
```

#### Windows Defender
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
#### **`Version 1.0`**