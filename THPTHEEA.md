# THP Cheat Sheet Hunting the Endpoint & Endpoint Analysis

# Windows Processes
- Did the expected parent process spawn it?
- Is it running out of the expected path?
- Is it spelled correctly?
- Is it running under the proper SID?
- Is it signed by Microsoft?

**Useful Links**

[Windows Internals, Seventh Edition, Part 1](https://www.microsoftpressstore.com/store/windows-internals-part-1-system-architecture-processes-9780735684188)

[Windows Internals, Sixth Edition, Part 2](https://www.microsoftpressstore.com/store/windows-internals-part-2-9780735665873)

## Session Maneger (**smss.exe**)
- Session 0 starts csrss.exe and wininit.exe. (OS services)
- Session 1 starts csrss.exe and winlogon.exe. (User session)
- 1 instance (Session 0) within the process tree. The child instances of smss.exe which was used to create the other sessions, by copying itself into that new session, will self-terminate.
- Loads the registry and known DLLs into shared memory locations.

> **Executable Path**: *%SystemRoot%\System32\smss.exe*\
**Parent Process**: *System*\
**Username**: *NT AUTHORITY\SYSTEM (S-1-5-18)*\
**Base Priority**: *11*\
**Time of Execution**: *For Session 0, within seconds of boot time*

### Hunting Tips
```
Sessions 0 and 1 are normal. Additional sessions may becreated by Remote Desktop Protocol (RDP) sessions and Fast User Switching on shared computers. If this does not apply to your environment, then it's worth checking theadditional sessions (if such exist). 
```

## Client/Server Run Subsystem Process (**csrss.exe**)
- Responsible for managing processes and threads, making the Windows API available for other processes.
- Responsible for mapping drive letters, creating temp files, and handling the shutdown process.
    - Runs within Session 0 and 1.
    - Will be available for each newly created user session.

> **Executable Path**: *%SystemRoot%\System32\csrss.exe*

> **Parent Process**: *Created by child instance of SMSS.EXE but that process won't exist so will appear as no parent*

> **Username**: *NT AUTHORITY\SYSTEM (S-1-5-18)*

> **Base Priority**: *13*

> **Time of Execution**: *For Sessions 0 & 1, within seconds of boot time*

### Hunting Tips
```
Malware authors can masquerade their malware to appear as this process by hiding in plain sight. They can name the malware as csrss.exe but just misspell it slightly (cssrs.exe, cssrss.exe, and csrsss.exe.)

Remember, typically you will see 2 instances of csrss.exe.
```

## Windows Logon Proxess (**winlogon.exe**)
- Responsible for user logons/logoffs. 
- It launches LogonUI.exe for username and password and passes credentials to LSASS.exe which is verified via AD or local SAM.
- Loads Userinit.exe via *Software\Microsoft\Windows NT\CurrentVersion\Winlogon*.
    - Loads NTUSER.DAT into HKCU and starts the users shell via Userinit.exe.
    - Userinit initializes the user environment and runs logon scripts and GPO.

*Both LogonUl.exe and Userinit.exe will exist and will not be visible after this process*

> **Executable Path**: *%SystemRoot%\System32\winlogon.exe*

> **Parent Process**: *Created by child instance of SMSS.EXE but that process won't exist so will appear as no parent*

> **Username**: *NT AUTHORITY\SYSTEM (S-1-5-18)*

> **Base Priority**: *13*

> **Time of Execution**: *For Sessions 1, within seconds of boot time. Other instances may start later*

### Hunting Tips
```
The abuse within this process often comes within the different components of the login process. Malware sometimes abuses the SHELL registry value. This value should be explorer.exe. 
Another registry key that is abused by malware that works in conjunction with winlogon.exe is Userinit.
```

## Windows Initialization Process (**wininit.exe**)
- It is responsible to launch services.exe, Isass.exe, and Ism.exe in Session 0.

> **Executable Path**: *%SystemRoot%\System32\wininit.exe*

> **Parent Process**: *Created by child instance of SMSS.EXE but that process won't exist so will appear as no parent*

> **Username**: *NT AUTHORITY\SYSTEM (S-1-5-18)*

> **Base Priority**: *13*

> **Time of Execution**: *Within seconds of boot time*

### Hunting Tips
```
You should only see 1 instance of wininit.exe.
```

## Local Session Manager (**lsm.exe**)
-  It is responsible to work with smss.exe to create, destroy, or manipulate new user sessions.
    - Responsible for **logon/logoff**, **shell start/end**, **lock/unlock desktop** to name a few.

> **Executable Path**: *%SystemRoot%\System32\lsm.exe*

> **Parent Process**: *wininit.exe*

> **Username**: *NT AUTHORITY\SYSTEM (S-1-5-18)*

> **Base Priority**: *8*

> **Time of Execution**: *Within seconds of boot time*

### Hunting Tips
```
You should only see 1 instance of Ism.exe on Windows 7 machines. 
You should NOT be seeing this on Windows 8 and beyond. It will be running as a service DLL instead: Ism.dll.
```

## Service Control Manager (**services.exe**)
- Responsible for loading services (auto-start) and device drivers into memory.
    - Parent to **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe**, etc.
    - Services are defined in *HKLM\SYSTEM\CurrentControlSet\Services*. 
    - Maintains an in-memory database of service information which can be queried using the built-in Windows tool, sc.exe. 
    - After a successful interactive logon, services.exe will backup a copy of the registry keys into *HKLM\SYSTEM\Select\Last Known Good* which will be known as the Last Known Good Configuration.

> **Executable Path**: *%SystemRoot%\System32\services.exe*

> **Parent Process**: *wininit.exe*

> **Username**: *NT AUTHORITY\SYSTEM (S-1-5-18)*

> **Base Priority**: *9*

> **Time of Execution**: *Within seconds of boot time*

### Hunting Tips
```
You should only see 1 instance of services.exe. This is a
protected process which makes it difficult to tamper with.
```

## Local Security Authority Subsystem (**lssas.exe**)
- Responsible for user authentication and generating access tokens specifying security policies and/or restrictions for the user and the processes spawned in the user session.
    - Uses authentication packages within *HKLM\System\CurrentControlSet\Control role\Lsa* to authenticate users.
    - Creates security tokens for SAM, AD, and NetLogon. 
    - Writes to the Security event log.


> **Executable Path**: *%SystemRoot%\System32\lsass.exe*

> **Parent Process**: *wininit.exe*

> **Username**: *NT AUTHORITY\SYSTEM (S-1-5-18)*

> **Base Priority**: *9*

> **Time of Execution**: *Within seconds of boot time*

### Hunting Tips
```
You should only see 1 instance of lsass.exe. 

This process  is commonly attacked and abused by hackers and malware. It is targeted to dump password hashes and is often used to hide in plain sight. 

You might see different variations of spelling for this process (lass.exe or lsasss.exe), and might even see multiple instances of it, like with Stuxnet malware.
```

## Generic Service Host Process (**svchost.exe**)
- Responsible for hosting multiple services DLLs into a generic shared service process. 
    - Each service will have registry entries that include **ServiceDll**. This will instruct svchost.exe what DLL to use. The entry will also include 
        > svchost.exe –k */name/*.
    - Multiple instances of svchost.exe host will be running.
        - All DLL-based services with the same */name/* will share the same svchost.exe process.
            - */name/* values are found in *Software\Microsoft\WindowNT\CurrentVersion\Svchostregistry* key.
        - Each svchost.exe process will run with a unique 
            > –k */name/*.1.2.8 svchost.exe 

> **Executable Path**: *%SystemRoot%\System32\svchost.exe*

> **Parent Process**: *services.exe*

> **Username**: 
- *NT AUTHORITY\SYSTEM (S-1-5-18)*
- *LOCAL SERVICE (S-1-5-19)*
- *NETWORK SERVICE (S-1-5-20*

> **Base Priority**: *8*

> **Time of Execution**: *Varies. In Windows 10, an instance will start as user upon logon (-k UnistackSvcGroup)*

### Hunting Tips
```
It can be used to launch malicious services (malware installed as a service). When this is done, (-k) will not be present.

This process is often misspelled to hide in plain sight. 

Another technique used with this process is to place it in different directories, but note that services.exe will not be the parent

When it comes to services, we will need to perform extra steps to determine whether the service/DLL being loaded by svchost.exe is legitimate or not. It’s more than just checking for misspellings in svchost.exe, because techniques such as Process Injection and Process Hollowingcan attack legitimate services.
```

## Windows Explorer (**explorer.exe**)
- Explorer.exe is responsible for the user’s desktop and everything that comes with it, including access to files (file browser) and launching files via their file extensions.
- Even if multiple Windows Explorer windows open, only 1 process will be spawned per logged on user
 
> **Executable Path**: *%SystemRoot%\explorer.exe*

> **Parent Process**: *%SystemRoot%\explorer.exe*

> **Username**: *As logged-on users*

> **Base Priority**: *8*

> **Time of Execution**: *Varies.*

### Hunting Tips
```
The clues to look for are provided at the beginning of this section.
```

## Task's Host for Windows (**taskhost.exe**)
- At startup, TASKHOST checks the Services portion of the Registry to construct a list of DLL-based services that it needs to load, and then loads them.
    - In Windows 8, this process was renamed to **taskhostex.exe**.
    - In Windows 10, this process was renamed to **taskhostw.exe**.
 

> **Executable Path**: *%SystemRoot%\System32\taskhost.exe*

> **Parent Process**: *services.exe*

> **Username**: *Varies.*

> **Base Priority**: *8*

> **Time of Execution**: *Varies.*


### Hunting Tips

> - They will inject into the process
> - Spawn malware named as explorer
> - Run it from a different folder or misspell it and have it run from the actual folder. 
> - Instances where explorer has CMD hanging off it or is listening/connected on a network port.
> - Core Windows processes shouldn’t run from Windows temp locations, or the Recycle Bin, and neither should be communicating to any outbound IPs.
> - Check for digital signatures (all Microsoft artifacts should be digitally signed)
> - Look for any process that have **cmd.exe**, **wscript.exe**, **powershell.exe** etc. running as a child process.

# Detection Tools

[PE Capture Service](http://www.novirusthanks.org/products/pe-capture-service/)

[NoVirusThanks](http://www.novirusthanks.org/products/pe-capture/)

[ProcScan](https://github.com/abhisek/RandomCode/tree/master/Malware/Process)

[Meterpeter Payload Detection](https://github.com/DamonMohammadbagher/Meterpreter_Payload_Detection)

[Reflective Injection Detection](https://github.com/papadp/reflective-injection-detection)

[PowershellArsenal](https://github.com/mattifestation/PowerShellArsenal)

[Get-InjectedThread.ps1](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)

## Detection Techniques
[SSDeep](https://github.com/ssdeep-project/ssdeep)

[imphash](https://github.com/Neo23x0/ImpHash-Generator) 

[ShimCacheParser](https://github.com/mandiant/ShimCacheParser)

[AppCompatProcessor](https://github.com/mbevilacqua/appcompatprocessor)

## Memory Analysis

**Live System Memory Hunting**

When identifying anomalies in processes, we are interested in: 
- **Image name** - Legitimate process? Spelled correctly? 
- **Full Path** - Appropriate path for system executable? Running from a user or a temp directory? 
- **Parent process** - Is the parent process what you would expect? 
- **Command line** - Do the arguments make sense? 
- **Start time** - Was the process started at boot? 
- **Security identifier** - Do the security identifiers make sense? Why would a system process use a user account SID?

**Anomalies in Network Activity**

When identifying anomalies in network activity, we are interested in: 
- Any process communicating over port 80, 443, or 8080 that is not a web browser
- Any browser not communicating over port 80, 443, or 8080
- Connections to unexplained internal or external IP addresses
- Web requests directly to an IP addresses rather than a domain name
- RDP connections (port 3389), especially if originating from odd IP addresses (e.g. a static IP address assigned to a printer)
- Why does this process have network capability?
DNS requests for unusual domain names

**Anomalies (Notable)**

Moreover, other anomalies are: 
- Unlinked processes 
- Loaded suspicious DLLs 
- Unlinked network connections 
- Unmapped memory pages with execute privileges (code injection) 
- Hooked API functions 
Known bad heuristics and signatures (e.g. YARA signatures). 

### Memory Analysis Tools

- [Mandiant's Redline](https://www.fireeye.com/services/freeware/redline.html)
- [Volatility](https://github.com/volatilityfoundation/volatility): [Wiki](https://github.com/volatilityfoundation/volatility/wiki/Volatility-Usage), - [Windows Analysis](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference-Mal) and [Memory Samples](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples)
- [Get-InjectedThreat.ps1](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)
- [Memdump](https://github.com/marcosd4h/memhunter)

# Volatility - CheatSheet

## Discover Profile

> vol.py imageinfo -f {filename}\
> vol.py kdbgscan -f {file.dmp}

## Hashes/Passwords
Extract SAM hashes, domain cached credentials and lsa secrets.

**vol2**
>volatility --profile=Win7SP1x86_23418 hashdump -f file.dmp #Grab common windows hashes (SAM+SYSTEM)\
volatility --profile=Win7SP1x86_23418 cachedump -f file.dmp #Grab domain cache hashes inside the registry\
volatility --profile=Win7SP1x86_23418 lsadump -f file.dmp #Grab lsa secrets

**vol3**
>./vol.py -f file.dmp windows.hashdump.Hashdump #Grab common windows hashes (SAM+SYSTEM)\
./vol.py -f file.dmp windows.cachedump.Cachedump #Grab domain cache hashes inside the registry\
./vol.py -f file.dmp windows.lsadump.Lsadump #Grab lsa secrets

## Memory Dump
The memory dump of a process will extract everything of the current status of the process. The procdump module will only extract the code.
> volatility -f file.dmp --profile=Win7SP1x86 memdump -p 2168 -D conhost/

## Processes
### List processes
Try to find suspicious processes (by name) or unexpected child processes (for example a cmd.exe as a child of iexplorer.exe).
It could be interesting to compare the result of pslist with the one of psscan to identify hidden processes.

**vol2**
> volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)\
volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)\
volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)\
volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list

**vol3**
>python3 vol.py -f file.dmp windows.pstree.PsTree # Get processes tree (not hidden)\
python3 vol.py -f file.dmp windows.pslist.PsList # Get process list (EPROCESS)\
python3 vol.py -f file.dmp windows.psscan.PsScan # Get hidden process list(malware)