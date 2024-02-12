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

## Session Manager (**smss.exe**)
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
    - [Volatility - CheatSheet](https://book.hacktricks.xyz/generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet)
    - [Linux Command Reference](https://github.com/volatilityfoundation/volatility/wiki/Linux-Command-Reference)
    - [Volatility - Command Reference Mal](https://github.com/volatilityfoundation/volatility/wiki/Command-Reference-Mal)

- [Get-InjectedThreat.ps1](https://gist.github.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2)
- [Memdump](https://github.com/marcosd4h/memhunter)

> **MemInjector**\
    *Available Options:*\
    -**h** for help\
    -**m** <injector_mode_id_to_use>\
    -**s** <source_pid_or_source_process>\
    -**t** <target_pid_or_target_process>\
    \
    *Available Injection Modes:*\
    \
    1 - DLL injection via CreateRemoteThread()\
    2 - DLL injection via an stealth CreateRemoteThread()\
    3 - DLL injection via QueueUserAPC()\
    4 - DLL injection via SetWindowsHookEx()\
    5 - DLL injection via Reflective DLL injection\
    6 - DLL injection via Shellcode DLL injection\
    7 - Code injection via Process Hollowing\
    8 - DLL injection via Suspend Injection Resume\
    9 - DLL injection via Image Mapping\
    10 - DLL injection via Thread Reuse\
    11 - .NET DLL injection into native/managed processes\
    12 - Code injection via Hasherezade Process   Doppelganging implementation\
    13 - DLL injection via Ensilo PowerLoaderEx\
    14 - DLL injection via System APPINIT_DLLS\
    15 - Code Injection via Image File Execution Options

> **MemHunter**\
    *Available Options:*\
    -**c** <conf_file>                 Path to configuration file\
    -**m** <id_list>                   List of Hunters to use. All included by Default\
    -**d**                             Enable Dissolvable mode. Disabled by Default\
    -**f**                             Enable False Positive Mitigations. Enabled by Default\
    -**r** <verbose|regular|minimal>   Report Verbosity Options. Regular by Default\
    -**e** <exclusion_list>            List of Processes To Exclude\
    -**o** <console|eventlog>          Report Output Options. Console by Default\
    -**y** <path>                      Path to YARA Rules to use\
    -**v** <path>                      Path to VirusTotal license to use\
    -**h**                             Display help information\
    \
    *Available Hunters IDs:*\
    1 - **Suspicious Threads** - It looks for RWX pages on threads base address\
    2 - **Suspicious CallStack** - It perform thread callstack analysis to check on suspicious patterns\
    3 - **Suspicious Exports** - It looks for know bad exports
    4 - **Suspicious Hollowed Modules** - It performs PE Header comparison of on-memory modules vs on-disk counterpart\
    5 - **Suspicious Modules**- It looks for RWX memory regions on modules memory areas\
    6 - **Suspicious Parents** - It looks for suspicious parents\
    7 - **Suspicious Regions** - It looks for wiped PE headers on section related memory areas\
    8 - **Suspicious Registry** - It looks for well-know persistence, evasion techniques on the registry\
    9 - **Suspicious Shellcode** - It performs fuzzy matching on commited memory to look for function prologues

# Hunting In Memory

## Volatility

### Process 
List processes
Try to find suspicious processes (by name) or unexpected child processes (for example a cmd.exe as a child of iexplorer.exe).
It could be interesting to compare the result of pslist with the one of psscan to identify hidden processes.

> volatility --profile=PROFILE pstree -f file.dmp # Get process tree (not hidden)

> volatility --profile=PROFILE pslist -f file.dmp # Get process list (EPROCESS)

> volatility --profile=PROFILE psscan -f file.dmp # Get hidden process list(malware)

> volatility --profile=PROFILE psxview -f file.dmp # Get hidden process list

### Dump proc

> volatility --profile=Win7SP1x86_23418 procdump --pid=3152 -n --dump-dir=. -f file.dmp

### Command line
Anything suspicious was executed?
> volatility --profile=PROFILE cmdline -f file.dmp #Display process command-line arguments

> volatility --profile=PROFILE consoles -f file.dmp #command history by scanning for _CONSOLE_INFORMATION

### Network
**win**
>volatility --profile=Win7SP1x86_23418 netscan -f file.dmp

>volatility --profile=Win7SP1x86_23418 connections -f file.dmp#XP and 2003 only

>volatility --profile=Win7SP1x86_23418 connscan -f file.dmp#TCP connections 

>volatility --profile=Win7SP1x86_23418 sockscan -f file.dmp#Open sockets

>volatility --profile=Win7SP1x86_23418 sockets -f file.dmp#Scanner for tcp socket objects

# Volatily - Command Reference Malware (Win)

[Volatility Labs](https://volatility-labs.blogspot.com/)

Random suspicious strings
> cat 4740.dmp.TXT | grep "powershell.exe" \
cat 4740.dmp.TXT | grep "Invoke-"\
cat 4740.dmp.TXT | grep ".hta"\
cat 4740.dmp.TXT | grep "mshta"
## malfind
- The **malfind** command helps find hidden or injected code/DLLs in user mode memory, based on characteristics such as VAD tag and page permissions.
- To analyze **malfind**, we should know that only processes with the MZ parameter in the header and *PAGE_EXECUTE_READWRITE* in the VAD (Virtual Address Descriptor) tags are important. Normal processes executed with *PAGE_EXECUTE_WRITE* and *PAGE_EXECUTE_READWRITE* are malicious.
- In legit scenarios, memory regions won’t be executable and writable at the same time.

> vol.py -f zeus.vmem — profile=WinXPSP2x86 malfind -p 936,608,632

> volatility --profile=Win7SP1x86_23418 -f file.dmp malfind [-D /tmp] #Find hidden and injected code [dump each suspicious section]
```
$ python vol.py -f zeus.vmem malfind -p 1724
Volatility Foundation Volatility Framework 2.4

Process: explorer.exe Pid: 1724 Address: 0x1600000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 1, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x01600000  b8 35 00 00 00 e9 cd d7 30 7b b8 91 00 00 00 e9   .5......0{......
0x01600010  4f df 30 7b 8b ff 55 8b ec e9 ef 17 c1 75 8b ff   O.0{..U......u..
0x01600020  55 8b ec e9 95 76 bc 75 8b ff 55 8b ec e9 be 53   U....v.u..U....S
0x01600030  bd 75 8b ff 55 8b ec e9 d6 18 c1 75 8b ff 55 8b   .u..U......u..U.

0x1600000 b835000000       MOV EAX, 0x35
0x1600005 e9cdd7307b       JMP 0x7c90d7d7
0x160000a b891000000       MOV EAX, 0x91
0x160000f e94fdf307b       JMP 0x7c90df63
0x1600014 8bff             MOV EDI, EDI
0x1600016 55               PUSH EBP

Process: explorer.exe Pid: 1724 Address: 0x15d0000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 38, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x015d0000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
0x015d0010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
0x015d0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x015d0030  00 00 00 00 00 00 00 00 00 00 00 00 d0 00 00 00   ................

0x15d0000 4d               DEC EBP
0x15d0001 5a               POP EDX
0x15d0002 90               NOP
0x15d0003 0003             ADD [EBX], AL
0x15d0005 0000             ADD [EAX], AL
0x15d0007 000400           ADD [EAX+EAX], AL
0x15d000a 0000             ADD [EAX], AL
```
## vaddump
- The Virtual Address Descriptor tree is used by the Windows memory manager to describe memory ranges used by a process as they are allocated.
> vol.py -f memdump.img --profile=Win7SP1x64 vaddump -p 1724

> vol.py -f zeus.vmem — profile=WinXPSP2x86 vaddump -b 0x15d0000 -D zeus

## apihooks
- API hooking is a technique by which we can instrument and modify the behavior and flow of API calls. This finds **IAT**, **EAT**, **Inline style hooks**, and several special types of hooks.
- For Inline hooks, it detects CALLs and JMPs to direct and indirect locations, and it detects PUSH/RET instruction sequences. 
- It also detects CALLs or JMPs to registers after an immediate value (address) is moved into the register. 
- The special types of hooks that it detects include syscall hooking in ntdll.dll and calls to unknown code pages in kernel memory.

### IAT hooks
Here is an example of detecting IAT hooks installed by Coreflood. The hooking module is unknown because there is no module (DLL) associated with the memory in which the rootkit code exists. 
```
$ python vol.py -f coreflood.vmem -p 2044 apihooks 
Volatility Foundation Volatility Framework 2.4
************************************************************************
Hook mode: Usermode
Hook type: Import Address Table (IAT)
Process: 2044 (IEXPLORE.EXE)
Victim module: iexplore.exe (0x400000 - 0x419000)
Function: kernel32.dllGetProcAddress at 0x7ff82360
Hook address: 0x7ff82360
Hooking module: <unknown>

Disassembly(0):
0x7ff82360 e8fbf5ffff       CALL 0x7ff81960
0x7ff82365 84c0             TEST AL, AL
0x7ff82367 740b             JZ 0x7ff82374
0x7ff82369 8b150054fa7f     MOV EDX, [0x7ffa5400]
0x7ff8236f 8b4250           MOV EAX, [EDX+0x50]
0x7ff82372 ffe0             JMP EAX
0x7ff82374 8b4c2408         MOV ECX, [ESP+0x8]
```
### Inline hooks
Here is an example of detecting the Inline hooks installed by Silentbanker. It shows the first hop of the hook at 0x7c81caa2 jumps to 0xe50000. Then you also see a disassembly of the code at 0xe50000 which executes the rest of the trampoline. Check for the API **Function** with designated default address along with JMP instrument that is pointing to **Hook Address**.
> volatility --profile=Win7SP1x86_23418 -f file.dmp apihooks #Detect API hooks in process and kernel memory
```
$ python vol.py -f silentbanker.vmem -p 1884 apihooks
Volatility Foundation Volatility Framework 2.4
************************************************************************
Hook mode: Usermode
Hook type: Inline/Trampoline
Process: 1884 (IEXPLORE.EXE)
Victim module: kernel32.dll (0x7c800000 - 0x7c8f4000)
Function: kernel32.dllExitProcess at 0x7c81caa2
Hook address: 0xe50000
Hooking module: <unknown>

Disassembly(0):
0x7c81caa2 e959356384       JMP 0xe50000
0x7c81caa7 6aff             PUSH -0x1
0x7c81caa9 68b0f3e877       PUSH DWORD 0x77e8f3b0
0x7c81caae ff7508           PUSH DWORD [EBP+0x8]
0x7c81cab1 e846ffffff       CALL 0x7c81c9fc

```
### PUSH/RET Inline hooks
Here is an example of detecting the PUSH/RET Inline hooks installed by Laqma:
```
$ python vol.py -f laqma.vmem -p 1624 apihooks
Volatility Foundation Volatility Framework 2.4
************************************************************************
Hook mode: Usermode
Hook type: Inline/Trampoline
Process: 1624 (explorer.exe)
Victim module: USER32.dll (0x7e410000 - 0x7e4a0000)
Function: USER32.dllMessageBoxA at 0x7e45058a
Hook address: 0xac10aa
Hooking module: Dll.dll

Disassembly(0):
0x7e45058a 68aa10ac00       PUSH DWORD 0xac10aa
0x7e45058f c3               RET
0x7e450590 3dbc04477e       CMP EAX, 0x7e4704bc
0x7e450595 00742464         ADD [ESP+0x64], DH
0x7e450599 a118000000       MOV EAX, [0x18]
0x7e45059e 6a00             PUSH 0x0
0x7e4505a0 ff               DB 0xff
0x7e4505a1 70               DB 0x70

Disassembly(1):
0xac10aa 53               PUSH EBX
0xac10ab 56               PUSH ESI
0xac10ac 57               PUSH EDI
0xac10ad 90               NOP
0xac10ae 90               NOP
```
### duqu style API hooks
Here is an example of the duqu style API hooks which moves an immediate value into a register and then JMPs to it.
```
************************************************************************
Hook mode: Usermode
Hook type: Inline/Trampoline
Process: 1176 (lsass.exe)
Victim module: ntdll.dll (0x7c900000 - 0x7c9af000)
Function: ntdll.dllZwQuerySection at 0x7c90d8b0
Hook address: 0x980a02
Hooking module: <unknown>

Disassembly(0):
0x7c90d8b0 b8020a9800       MOV EAX, 0x980a02
0x7c90d8b5 ffe0             JMP EAX
0x7c90d8b7 03fe             ADD EDI, ESI
0x7c90d8b9 7fff             JG 0x7c90d8ba
0x7c90d8bb 12c2             ADC AL, DL
0x7c90d8bd 1400             ADC AL, 0x0
0x7c90d8bf 90               NOP
0x7c90d8c0 b8a8000000       MOV EAX, 0xa8
0x7c90d8c5 ba               DB 0xba
0x7c90d8c6 0003             ADD [EBX], AL

Disassembly(1):
0x980a02 55               PUSH EBP
0x980a03 8bec             MOV EBP, ESP
0x980a05 51               PUSH ECX
0x980a06 51               PUSH ECX
0x980a07 e8f1fdffff       CALL 0x9807fd
0x980a0c 8945fc           MOV [EBP-0x4], EAX
0x980a0f e872feffff       CALL 0x980886
0x980a14 8945f8           MOV [EBP-0x8], EAX
0x980a17 83               DB 0x83
0x980a18 7df8             JGE 0x980a12
```
### NT syscall patches
Here is an example of using apihooks to detect the syscall patches in ntdll.dll (using a Carberp sample):
```
$ python vol.py -f carberp.vmem -p 1004 apihooks
Volatility Foundation Volatility Framework 2.4
************************************************************************
Hook mode: Usermode
Hook type: NT Syscall
Process: 1004 (explorer.exe)
Victim module: ntdll.dll (0x7c900000 - 0x7c9af000)
Function: NtQueryDirectoryFile
Hook address: 0x1da658f
Hooking module: <unknown>

Disassembly(0):
0x7c90d750 b891000000       MOV EAX, 0x91
0x7c90d755 ba84ddda01       MOV EDX, 0x1dadd84
0x7c90d75a ff12             CALL DWORD [EDX]
0x7c90d75c c22c00           RET 0x2c
0x7c90d75f 90               NOP
0x7c90d760 b892000000       MOV EAX, 0x92
0x7c90d765 ba               DB 0xba
0x7c90d766 0003             ADD [EBX], AL

Disassembly(1):
0x1da658f 58               POP EAX
0x1da6590 8d056663da01     LEA EAX, [0x1da6366]
0x1da6596 ffe0             JMP EAX
0x1da6598 c3               RET
0x1da6599 55               PUSH EBP
0x1da659a 8bec             MOV EBP, ESP
0x1da659c 51               PUSH ECX
0x1da659d 8365fc00         AND DWORD [EBP+0xfffffffc], 0x0
0x1da65a1 688f88d69b       PUSH DWORD 0x9bd6888f
```
### Kernelmode Inline hook
Here is an example of using apihooks to detect the Inline hook of a kernel mode function:
```
$ python vol.py apihooks -f rustock.vmem 
************************************************************************
Hook mode: Kernelmode
Hook type: Inline/Trampoline
Victim module: ntoskrnl.exe (0x804d7000 - 0x806cf980)
Function: ntoskrnl.exeIofCallDriver at 0x804ee130
Hook address: 0xb17a189d
Hooking module: <unknown>

Disassembly(0):
0x804ee130 ff2580c25480     JMP DWORD [0x8054c280]
0x804ee136 cc               INT 3
0x804ee137 cc               INT 3
0x804ee138 cc               INT 3
0x804ee139 cc               INT 3
0x804ee13a cc               INT 3
0x804ee13b cc               INT 3
0x804ee13c 8bff             MOV EDI, EDI
0x804ee13e 55               PUSH EBP
0x804ee13f 8bec             MOV EBP, ESP
0x804ee141 8b4d08           MOV ECX, [EBP+0x8]
0x804ee144 83f929           CMP ECX, 0x29
0x804ee147 72               DB 0x72

Disassembly(1):
0xb17a189d 56               PUSH ESI
0xb17a189e 57               PUSH EDI
0xb17a189f 8bf9             MOV EDI, ECX
0xb17a18a1 8b7708           MOV ESI, [EDI+0x8]
0xb17a18a4 3b35ab6d7ab1     CMP ESI, [0xb17a6dab]
0xb17a18aa 7509             JNZ 0xb17a18b5
0xb17a18ac 52               PUSH EDX
0xb17a18ad 57               PUSH EDI
0xb17a18ae e8c6430000       CALL 0xb17a5c79
0xb17a18b3 eb6a             JMP 0xb17a191f
```
### Kernel Unknown Code Page Call
Here is an example of using apihooks to detect the calls to an unknown code page from a kernel driver. In this case, malware has patched tcpip.sys with some malicious redirections.
```
$ python vol.py -f rustock-c.vmem apihooks 
Volatility Foundation Volatility Framework 2.4
************************************************************************
Hook mode: Kernelmode
Hook type: Unknown Code Page Call
Victim module: tcpip.sys (0xf7bac000 - 0xf7c04000)
Function: <unknown>
Hook address: 0x81ecd0c0
Hooking module: <unknown>

Disassembly(0):
0xf7be2514 ff15bcd0ec81     CALL DWORD [0x81ecd0bc]
0xf7be251a 817dfc03010000   CMP DWORD [EBP+0xfffffffc], 0x103
0xf7be2521 7506             JNZ 0xf7be2529
0xf7be2523 57               PUSH EDI
0xf7be2524 e8de860000       CALL 0xf7beac07
0xf7be2529 83               DB 0x83
0xf7be252a 66               DB 0x66
0xf7be252b 10               DB 0x10

Disassembly(1):
0x81ecd0c0 0e               PUSH CS
0x81ecd0c1 90               NOP
0x81ecd0c2 83ec04           SUB ESP, 0x4
0x81ecd0c5 c704246119c481   MOV DWORD [ESP], 0x81c41961
0x81ecd0cc cb               RETF
```
## idt
- The IDT table stores pointers to ISR (Interrupt Service Routines), which are called when an interrupt is triggered

Every result of this table must point to the **ntoskrnl.exe**.
> vol.py -f zeus.vmem — profile=WinXPSP2x86 idt | grep -iv unknown

To get more details about the possible IDT modification, use --verbose:
```
$ python vol.py -f rustock.vmem idt --verbose
Volatility Foundation Volatility Framework 2.4
   CPU  Index Selector Value      Module               Section     
------ ------ -------- ---------- -------------------- ------------
[snip]
     0     2E        8 0x806b01b8 ntoskrnl.exe         .rsrc       
0x806b01b8 e95c2c0f31       JMP 0xb17a2e19
0x806b01bd e9832c0f31       JMP 0xb17a2e45
0x806b01c2 4e               DEC ESI
0x806b01c3 44               INC ESP
0x806b01c4 4c               DEC ESP
0x806b01c5 45               INC EBP
0x806b01c6 44               INC ESP
0x806b01c7 5f               POP EDI
```
## Handles
- To display the open handles in a process, use the handles command. This applies to files, registry keys, mutexes, named pipes, events, window stations, desktops, threads, and all other types of securable executive objects. 
> vol.py -f zeus.vmem — profile=WinXPSP2x86 handles -p 856

## Handles (Process)
- You can display handles for a particular process by specifying --pid=PID or the physical offset of an _EPROCESS structure (--physical-offset=OFFSET).
- You can also filter by object type using -t or --object-type=OBJECTTYPE. For example to only display handles to process objects, do the following:
> vol.py -f zeus.vmem — profile=WinXPSP2x86 handles -p 856 -t Process

## Handles (Mutant)
- We can look for Mutexes that the malware might have created to ensure that only one instance of it is running at a time.
- We can use the handles plugin, specifying the object type as Mutant and providing the PID.
```
C:\volatility>vol.py --profile=WinXPSP2x86 -f C:\Users\Administrator\Desktop\memory_dump\apta.vmem handles -p 856 -t mutant
Volatility Foundation Volatility Framework 2.6
Offset(V)     Pid     Handle     Access Type             Details
---------- ------ ---------- ---------- ---------------- -------
0xff257148    856       0x24   0x1f0001 Mutant           SHIMLIB_LOG_MUTEX
0xff149878    856      0x158   0x1f0001 Mutant
0xff2342e8    856      0x1d8   0x1f0001 Mutant
0xff3864f8    856      0x1e4   0x120001 Mutant           ShimCacheMutex
.
.
.
0xff27b7e8    856      0x43c   0x1f0001 Mutant           _AVIRA_2108
0x80f19200    856      0x450   0x1f0001 Mutant
0xff1e68b0    856      0x460   0x100000 Mutant           RasPbFile
```

## callbacks
Volatility is the only memory forensics platform with the ability to print an assortment of important notification routines and kernel callbacks. Rootkits, anti-virus suites, dynamic analysis tools (such as Sysinternals' Process Monitor and Tcpview), and many components of the Windows kernel use of these callbacks to monitor and/or react to events. It detects the following:

- PsSetCreateProcessNotifyRoutine (process creation).
- PsSetCreateThreadNotifyRoutine (thread creation).
- PsSetImageLoadNotifyRoutine (DLL/image load).
- IoRegisterFsRegistrationChange (file system registration).
- KeRegisterBugCheck and KeRegisterBugCheckReasonCallback.
- CmRegisterCallback (registry callbacks on XP).
- CmRegisterCallbackEx (registry callbacks on Vista and 7).
- IoRegisterShutdownNotification (shutdown callbacks).
- DbgSetDebugPrintCallback (debug print callbacks on Vista and 7).
- DbgkLkmdRegisterCallback (debug callbacks on 7).
> C:\volatility>vol.py --profile=WinXPSP2x86 -f C:\Users\Administrator\Desktop\mem
ory_dump\aptb.vmem callbacks

## modules
- To view the list of kernel drivers loaded on the system, use the modules command. This walks the doubly-linked list of LDR_DATA_TABLE_ENTRY structures pointed to by PsLoadedModuleList. Similar to the pslist command, this relies on finding the KDBG structure.
```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 modules
Volatility Foundation Volatility Framework 2.4
Offset(V)          Name                 Base                             Size File
------------------ -------------------- ------------------ ------------------ ----
0xfffffa80004a11a0 ntoskrnl.exe         0xfffff8000261a000           0x5dd000 \SystemRoot\system32\ntoskrnl.exe
0xfffffa80004a10b0 hal.dll              0xfffff80002bf7000            0x49000 \SystemRoot\system32\hal.dll
0xfffffa80004a7950 kdcom.dll            0xfffff80000bb4000             0xa000 \SystemRoot\system32\kdcom.dll
0xfffffa80004a7860 mcupdate.dll         0xfffff88000c3a000            0x44000 \SystemRoot\system32\mcupdate_GenuineIntel.dll
0xfffffa80004a7780 PSHED.dll            0xfffff88000c7e000            0x14000 \SystemRoot\system32\PSHED.dll
0xfffffa80004a7690 CLFS.SYS             0xfffff88000c92000            0x5e000 \SystemRoot\system32\CLFS.SYS
0xfffffa80004a8010 CI.dll               0xfffff88000cf0000            0xc0000 \SystemRoot\system32\CI.dll
```
## modscan
- The modscan command finds LDR_DATA_TABLE_ENTRY structures by scanning physical memory for pool tags. This can pick up previously unloaded drivers and drivers that have been hidden/unlinked by rootkits.
```
$ python vol.py -f ~/Desktop/win7_trial_64bit.raw --profile=Win7SP0x64 modscan
Volatility Foundation Volatility Framework 2.4
Offset(P)          Name                 Base                             Size File
------------------ -------------------- ------------------ ------------------ ----
0x00000000173b90b0 DumpIt.sys           0xfffff88003980000            0x11000 \??\C:\Windows\SysWOW64\Drivers\DumpIt.sys
0x000000001745b180 mouhid.sys           0xfffff880037e9000             0xd000 \SystemRoot\system32\DRIVERS\mouhid.sys
0x0000000017473010 lltdio.sys           0xfffff88002585000            0x15000 \SystemRoot\system32\DRIVERS\lltdio.sys
0x000000001747f010 rspndr.sys           0xfffff8800259a000            0x18000 \SystemRoot\system32\DRIVERS\rspndr.sys
0x00000000174cac40 dxg.sys              0xfffff96000440000            0x1e000 \SystemRoot\System32\drivers\dxg.sys
0x0000000017600190 monitor.sys          0xfffff8800360c000             0xe000 \SystemRoot\system32\DRIVERS\monitor.sys
0x0000000017601170 HIDPARSE.SYS         0xfffff880037de000             0x9000 \SystemRoot\system32\DRIVERS\HIDPARSE.SYS
0x0000000017604180 USBD.SYS             0xfffff880037e7000             0x2000 \SystemRoot\system32\DRIVERS\USBD.SYS
0x0000000017611d70 cdrom.sys            0xfffff88001944000            0x2a000 \SystemRoot\system32\DRIVERS\cdrom.sys
```
## moddump
- To extract a kernel driver to a file, use the moddump command. Supply the output directory with -D or --dump-dir=DIR. Without any additional parameters, all drivers identified by modlist will be dumped. 
- If you want a specific driver, supply a regular expression of the driver's name with --regex=REGEX or the module's base address with --base=BASE.

> C:\volatility>vol.py --profile=WinXPSP2x86 -f C:\Users\Administrator\Desktop\mem
ory_dump\aptb.vmem moddump -b 0xfc2c0876 -D _moddump

## userassist
- The UserAssist utility displays a table of programs executed on a Windows machine, complete with running count and last execution date and time.
> vol.py -f zeus.vmem — profile=WinXPSP2x86 userassist

# Volatility - Rootkit Detection Linux

## linux_check_afinfo
- This plugin walks the file_operations and sequence_operations structures of all UDP and TCP protocol structures including, tcp6_seq_afinfo, tcp4_seq_afinfo, udplite6_seq_afinfo, udp6_seq_afinfo, udplite4_seq_afinfo, and udp4_seq_afinfo, and verifies each member. 
- This effectively detects any tampering with the interesting members of these structures. 

The following output shows this plugin against the VM infected with KBeast:

```
# python vol.py -f  kbeast.lime --profile=LinuxDebianx86 linux_check_afinfo
Volatility Foundation Volatility Framework 2.2_rc1
Symbol Name        Member          Address
-----------        ------          ----------
tcp4_seq_afinfo    show            0xe0fb9965
```

## linux_check_tty
- This plugin detects one of the kernel level keylogging methods described in "Bridging the Semantic Gap to Mitigate Kernel-level Keyloggers". 
- It works by checking the receive_buf function pointer for every active tty driver on the system. 

If the function pointer is not hooked then its symbol name is printed, otherwise "HOOKED" is printed.

```
# python vol.py -f ../this.k.lime --profile=Linuxthisx86 linux_check_syscall > ksyscall
# head -6 ksyscall
Table Name Index Address Symbol
---------- ---------- ---------- ------------------------------
32bit 0x0 0xc103ba61 sys_restart_syscall
32bit 0x1 0xc103396b sys_exit
32bit 0x2 0xc100333c ptregs_fork
32bit 0x3 0xe0fb46b9 HOOKED
# grep –c HOOKED ksyscall
10
```

## linux_keyboard_notifier
- This plugin detects the second kernel level keylogging method described in "Bridging the Semantic Gap to Mitigate Kernel-level Keyloggers". 
- It works by walking the kernel "keyboard_notifier_list" and checking if each notifier (callback) is within the kernel. If the callback is malicious then its symbol name is printed, otherwise "HOOKED" is printed.

## linux_check_creds
This plugin detects rootkits that have elevated privileges to root using DKOM techniques.

Although the kernel provides the prepare_creds and commit_creds functions to allocate and store new credentials, a number of rootkits choose not to use this functionality. Instead, they simply find another process that has the privileges of root and that never exits, usually PID 1, and set the cred pointer of the target process to that of PID 1’s. This effectively gives the attacker’s process full control and the rootkit does not have to attempt the non-trivial task of allocating its own cred structure.

The following output shows the cred structure running on an infected VM and showing that PID 1 has the same cred structure as the elevated bash shell (PID 9673):
```
$ python vol.py -f avg.hidden-proc.lime --profile=Linuxthisx86 linux_check_creds
Volatility Foundation Volatility Framework 2.2_rc1
PIDs
--------
1, 9673
```
## linux_check_fop
This plugin enumerates the /proc filesystem and all opened files and verifies that each member of every file_operations structure is valid (valid means the function pointer is either in the kernel or in a known (not hidden) loadable kernel module).

This plugin, when given the –i/--inode option, reads the inode at the given address and verifies each member of its i_fop pointer. As we can see, the plugin tells us that the read member is hooked and the address of the hooked function.
```
$ python vol.py -f avgcoder.mem --profile=LinuxCentOS63x64 linux_check_fop
Volatility Foundation Volatility Framework 2.2_rc1
Symbol Name              Member           Address
------------------------ ---------------- ------------------
proc_mnt: root           readdir          0xffffa05ce0e0
buddyinfo                write            0xffffa05cf0f0
modules                  read             0xffffa05ce8a0

$ python vol.py -f avgcoder.mem --profile=LinuxCentOS63x64 linux_check_fop -i 0x88007a85acc0
Volatility Foundation Volatility Framework 2.2_rc1
Symbol Name                   Member                 Address
----------------------------- ---------------------- ------------------
inode at 88007a85acc0         read                   0xffffa05ce4d0
```

## linux_check_idt
This plugin enumerates the interrupt descriptor table (IDT) addresses and symbols. If any entries are hooked by rootkits, you'll see "HOOKED" in the far right column instead of the symbol name.
```
$ python vol.py -f ~/Downloads/Metasploitable2-Linux/Metasploitable-555c9224.vmem --profile=LinuxMetasploitx86 linux_check_idt
Volatility Foundation Volatility Framework 2.3_alpha
     Index Address    Symbol                        
---------- ---------- ------------------------------
       0x0 0xc0108fec divide_error                  
       0x1 0xc032ff80 debug                         
       0x2 0xc032ffcc nmi                           
       0x3 0xc03300f0 int3                          
       0x4 0xc0108f8c overflow                      
       0x5 0xc0108f98 bounds                        
       0x6 0xc0108fa4 invalid_op                    
       0x7 0xc0108f3c device_not_available          
       0x8 0x00000000 xen_save_fl_direct_reloc      
       0x9 0xc0108fb0 coprocessor_segment_overrun   
       0xa 0xc0108fbc invalid_TSS                   
       0xb 0xc0108fc8 segment_not_present           
       0xc 0xc0108fd4 stack_segment                 
       0xd 0xc033011c general_protection            
       0xe 0xc032ff00 page_fault                    
       0xf 0xc0108ff8 spurious_interrupt_bug        
      0x10 0xc0108f24 coprocessor_error             
      0x11 0xc0108fe0 alignment_check               
      0x12 0xc010035c ignore_int                    
      0x13 0xc0108f30 simd_coprocessor_error        
      0x80 0xc01083d0 system_call 
```

## linux_check_syscall
- This plugin prints the system call tables and checks for hooked functions. 
- For 64-bit systems, it prints both the 32-bit and 64-bit table. 
- If a function is hooked, you'll see **HOOKED** displayed in the output, otherwise you'll see the name of the system call function.

```
# python vol.py -f kbeast.lime --profile=LinuxDebianx86 linux_check_syscall > ksyscall

# head -10 ksyscall
Table Name      Index Address    Symbol
---------- ---------- ---------- ------------------------------
32bit             0x0 0xc103ba61 sys_restart_syscall
32bit             0x1 0xc103396b sys_exit
32bit             0x2 0xc100333c ptregs_fork
32bit             0x3 0xe0fb46b9 HOOKED
32bit             0x4 0xe0fb4c56 HOOKED
32bit             0x5 0xe0fb4fad HOOKED
32bit             0x6 0xc10b1b16 sys_close
32bit             0x7 0xc10331c0 sys_waitpid

# grep HOOKED ksyscall
32bit             0x3 0xe0fb46b9 HOOKED
32bit             0x4 0xe0fb4c56 HOOKED
32bit             0x5 0xe0fb4fad HOOKED
32bit             0xa 0xe0fb4d30 HOOKED
32bit            0x25 0xe0fb4412 HOOKED
32bit            0x26 0xe0fb4ebd HOOKED
32bit            0x28 0xe0fb4db1 HOOKED
32bit            0x81 0xe0fb5044 HOOKED
32bit            0xdc 0xe0fb4b9e HOOKED
32bit           0x12d 0xe0fb4e32 HOOKED
```
```
root@attackdefense:~/memory_dump# 
vol.py --profile=Linuxprofile-2_6_32-754_el6_x86_64x64 -f infection1.memory linux_check_syscall | grep "HOOKED"            
Volatility Foundation Volatility Framework 2.6.1
64bit         62                          0xffffffffa0523190 HOOKED: diamorphine/hacked_kill                             
64bit         78                          0xffffffffa0523230 HOOKED: diamorphine/hacked_getdents                         
64bit        217                          0xffffffffa0523420 HOOKED: diamorphine/hacked_getdents64
```

## linux_check_modules / linux_hidden_modules
This plugin finds rootkits that break themselves from the module list but not sysfs. 

We have never found a rootkit that actually removes itself from sysfs, so on a live system they are hidden from lsmod and */proc/modules*, but can still be found under */sys/modules*. We perform the same differnecing with the in-memory data structures.
```
# python vol.py -f kbeast.this --profile=LinuxDebianx86 linux_check_modules
Volatility Foundation Volatility Framework 2.2_rc1
Module Name
-----------
ipsecs_kbeast_v1
```
```
root@attackdefense:~/memory_dump# vol.py --profile=Linuxprofile-2_6_32-754_el6_x86_64x64 -f infection1.memory linux_check_modules                           
Volatility Foundation Volatility Framework 2.6.1
    Module Address       Core Address       Init Address Module Name             
------------------ ------------------ ------------------ ------------------------
0xffffffffa0523740 0xffffffffa0523000                0x0 diamorphine 
```
## linux_check_creds
The purpose of this plugin is to check if any processes are sharing 'cred' structures. In the beginning of the 2.6 kernel series, the user ID and group ID were just simple integers, so rootkits could elevate the privleges of userland processes by setting these to 0 (root). In later kernels, credentials are kept in a fairly complicated 'cred' structure. So now rootkits instead of allocating and setting their own 'cred' structure simply set a processes cred structure to be that of another root process that does not exit (usually init / pid 1). This plugin checks for any processes sharing 'cred' structures and reports them as the kernel would normally never do this. It finds a wide range of rootkits and rootkit activity and you can focus your investigation on elevated process (i.e. bash)

## linux_check_inline_kernel
- Check for inline kernel hooks

Here's a brief interpretation of the output below:

1. tcp4_seq_afinfo: This entry is related to TCP IPv4 sequence information. The "JMP" under Hook Type indicates a jump (hook) at address 0x0000000000000000, which could potentially be a sign of a hook in the code execution flow.

2. udplite4_seq_afinfo: Similar to the first entry, but for UDP Lite IPv4 sequence information.

3. udp4_seq_afinfo: Related to UDP IPv4 sequence information.

4. TCP, UDP, UDP-Lite, PING, RAW: These entries show ioctl hooks for various network protocols. The "JMP" at address 0x0000000000000000 again suggests potential code redirection or modification.

The presence of hooks in these network-related functions might indicate malicious activity or tampering with the networking functionality in the kernel. 
```
root@attackdefense:~/memory_dump# vol.py --profile=Linuxprofile-2_6_32-754_el6_x86_64x64 -f infection2.memory linux_check_inline_kernel
Volatility Foundation Volatility Framework 2.6.1
Name                                             Member           Hook Type Hook Address      
------------------------------------------------ ---------------- --------- ------------------
tcp4_seq_afinfo                                  show             JMP       0x0000000000000000
udplite4_seq_afinfo                              show             JMP       0x0000000000000000
udp4_seq_afinfo                                  show             JMP       0x0000000000000000
TCP                                              ioctl            JMP       0x0000000000000000
UDP                                              ioctl            JMP       0x0000000000000000
UDP-Lite                                         ioctl            JMP       0x0000000000000000
PING                                             ioctl            JMP       0x0000000000000000
RAW                                              ioctl            JMP       0x0000000000000000
```
## volshell
- This plugin presents an interactive shell in the linux memory image.
- Get the module address in the Module.
```
root@attackdefense:~/memory_dump# vol.py --profile=Linuxprofile-2_6_32-754_el6_x86_64x64 -f infection1.memory linux_volshell     
Volatility Foundation Volatility Framework 2.6.1
Current context: process init, pid=1 DTB=0x137638000
Welcome to volshell! Current memory image is:
file:///root/memory_dump/infection1.memory
To get help, type 'hh()'
>>> db(0xffffffffa0523740, length=128)
0xffffffffa0523740  00 00 00 00 00 00 00 00 00 01 10 00 00 00 ad de   ................
0xffffffffa0523750  00 02 20 00 00 00 ad de 64 69 61 6d 6f 72 70 68   ........diamorph
0xffffffffa0523760  69 6e 65 00 00 00 00 00 00 00 00 00 00 00 00 00   ine.............
0xffffffffa0523770  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0xffffffffa0523780  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0xffffffffa0523790  e0 1f 3d a6 00 88 ff ff b8 7f 52 a0 ff ff ff ff   ..=.......R.....
0xffffffffa05237a0  18 6f 51 a0 ff ff ff ff d8 9c 80 3d 01 88 ff ff   .oQ........=....
0xffffffffa05237b0  c0 9c 80 3d 01 88 ff ff c0 74 ab 81 ff ff ff ff   ...=.....t......
>>> db(0xffffffffa0523740, length=128)
0xffffffffa0523740  00 00 00 00 00 00 00 00 00 01 10 00 00 00 ad de   ................
0xffffffffa0523750  00 02 20 00 00 00 ad de 64 69 61 6d 6f 72 70 68   ........diamorph
0xffffffffa0523760  69 6e 65 00 00 00 00 00 00 00 00 00 00 00 00 00   ine.............
0xffffffffa0523770  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0xffffffffa0523780  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0xffffffffa0523790  e0 1f 3d a6 00 88 ff ff b8 7f 52 a0 ff ff ff ff   ..=.......R.....
0xffffffffa05237a0  18 6f 51 a0 ff ff ff ff d8 9c 80 3d 01 88 ff ff   .oQ........=....
0xffffffffa05237b0  c0 9c 80 3d 01 88 ff ff c0 74 ab 81 ff ff ff ff   ...=.....t......
```

# Hunting For Process Injection & Proactive API Monitoring

## Process Injection
> - minjector.exe -m 1 -s C:\Users\Administrator\Desktop\Tools\memhunter\msimplepayload.dll -t 4016

### Detection

> **Memdump**\
    >- memhunter.exe -m 5

> **ProcessHacker**\
    > - Check for suspcious binary loaded in "Modules" and get base address.\
    > - Checl address in the "Memory" Tab. Usually it has PAGE_EXECUTE_WRITECOPY(WCX) or RCX protection.

## Process Hollowing
> - minjector.exe -m 7 -s C:\Users\Administrator\Desktop\Tools\memhunter\mhookpayload.dll -t c:\windows\system32\notepad.exe
### Detection
> **Memdump**\
    > - memhunter.exe -m 4

> **ProcessHacker**\
    > - 2 base address will be found in "Modules" related to the Process.\
    > - Check the mapped (lower) address in the "Memory".\
    > - Supicious "Current Directory" in General information.

## Reflective DLL Injection
> - minjector.exe -m 5 -s C:\Users\Administrator\Desktop\Tools\memhunter\reflective_dll.x64.dll -t 5104

### Detection
>**Memdump**\
    > - memhunter.exe -m 1

> **ProcessHacker**\
    > - Check for *ntdll.dll!RtlUserThreadStart*.\
    > - Get the address without prefix in the buttom.\
    > - Check the payload around this address range.

# Advanced Endpoint Hunting

## AMSI bypasses

At a high-level AMSI patching can be broken up into four steps,

1. Obtain handle of amsi.dll
2. Get process address of AmsiScanBuffer
3. Modify memory protections of AmsiScanBuffer
4. Write opcodes to AmsiScanBuffer

> $Patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)

> mov eax, 0x80070057\
ret 0x18

- [ASBBypass.ps1](https://github.com/killvxk/Octopus-1/blob/master/modules/ASBBypass.ps1)

### Detection

- [AmsiPatchDetection](https://github.com/IonizeCbr/AmsiPatchDetection) - Detect AMSI.dll in memory patch

> **ProcessHacker**
    > - RWX Protection on Amsi.dll payload.
    >   - VirtualProtect(asb, (UIntPtr)garbage.Length, 0x40, out uint oldProtect);
    > - But can be revert back to RX Protection to make it look normal again.
    >   - VirtualProtect(asb, (UIntPtr)garbage.Length, oldProtect, out uint _);

# Parent PID spoofing
[PPID-Spoofing](https://github.com/WithSecureLabs/ppid-spoofing/blob/master/PPID-Spoof.ps1)

```
PS> import-module .\PPID-Spoof.ps1
PS> PPID-Spoof -ppid 1944 -spawnTo "C:\Windows\System32\win32calc.exe" -dllPath .\msimplepayload.dll
```

### Detection
- [detect-ppid-spoof.py](https://github.com/WithSecureLabs/ppid-spoofing/blob/master/detect-ppid-spoof.py) 

> **ProcessHacker**
- On General Tab:
    - Commandline: 0
    - Suspicious "Current Directory" (location of the payload)
    - Parent Process: Duplicated from the filename of the parent process.
- On Threads Tab:
    - Only has Stard Address of Duplicated Process.
- On Handles Tab:
    - 0x40 shows the location of current directory
    - Spoofed Process has single Thread related to its filename.
- On Modules Tab:
    - Same with Process Injection, the payload can be traced in Modules Tab. Get the base adress.
- On Memory Tab:
    - Locate the payload using base adress on Modules Tab. Usually has WCX/RCX protection.

# Process Doppelganging

[PowerShell-Suite  - Start-Eidolon](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Start-Eidolon.ps1)

```
PS> Import-Module .\Start-Eidolon.ps1
PS> Start-Eidolon -Target .\test.txt -Mimikatz -Verbose
VERBOSE: [+] Created transaction object
VERBOSE: [+] Created transacted file
VERBOSE: [+] Overwriting transacted file
VERBOSE: [+] Created section from transacted file
VERBOSE: [+] Rolled back transaction changes
VERBOSE: [+] Created process from section
VERBOSE: [+] Acquired Eidolon PBI
VERBOSE: [+] Eidolon architecture is 64-bit
VERBOSE: [+] Eidolon image base: 0x7FF7D0FF0000
VERBOSE: [+] Eidolon entry point: 0x7FF7D10640C8
VERBOSE: [+] Created Eidolon process parameters
VERBOSE: [+] Allocated memory in Eidolon
VERBOSE: [+] Process parameters duplicated into Eidolon
VERBOSE: [+] Rewrote Eidolon->PEB->pProcessParameters
VERBOSE: [+] Created Eidolon main thread..
True
```

### Detection

> **ProcessHacker**
- On General Tab:
  - Blank Process with no Image Filename, Directory and Commandline.
  - Parent Process is Powershell
- On Threads Tab:
  - One entry, filename of the payload. On Modules Tab, using the filename, find and Check for the address.

- [PEStudio](https://www.winitor.com/download) - Load the dumped file for Static Analysis.
- [PE-SIEVE](https://github.com/hasherezade/pe-sieve) - Properly dump the payload.
```
PS> .\pe-sieve64.exe /pid 1116 /quiet
---
PID: 1116
---
SUMMARY:

Total scanned:      53
Skipped:            0
-
Hooked:             0
Replaced:           0
Hdrs Modified:      0
IAT Hooks:          0
Implanted:          1
Implanted PE:       1
Implanted shc:      0
Unreachable files:  1
Other:              1
-
Total suspicious:   2
[!] Errors:         2
---
PS C:\Users\Administrator\Desktop\Tools> .\pe-sieve64.exe /pid 1116
PID: 1116
Output filter: no filter: dump everything (default)
Dump mode: autodetect (default)
[*] Using raw process!
[!][1116] Suspicious: could not read the module file!
[*] Scanning: C:\Windows\System32\ntdll.dll
...
...
...
[*] Scanning: C:\Windows\System32\wintrust.dll
Scanning workingset: 314 memory regions.
[*] Workingset scanned in 32 ms
[+] Report dumped to: process_1116
[*] Dumped module to: C:\Users\Administrator\Desktop\Tools\\process_1116\7ff623590000.test2.txt as REALIGNED
[*] Dumped module to: C:\Users\Administrator\Desktop\Tools\\process_1116\7ff623590000.test2.txt as UNMAPPED
[+] Dumped modified to: process_1116
[+] Report dumped to: process_1116
---
PID: 1116
---
SUMMARY:

Total scanned:      53
Skipped:            0
-
Hooked:             0
Replaced:           0
Hdrs Modified:      0
IAT Hooks:          0
Implanted:          1
Implanted PE:       1
Implanted shc:      0
Unreachable files:  1
Other:              1
-
Total suspicious:   2
[!] Errors:         2
---

md5,22643617D4505DD62EE2BB2459796467
sha1,AE88DC0E346BD28D74DE0044ACF85EE8CCE92003
sha256,448BF98B570A49D2C2998A29A7E5CD607608C45DC76EC66754E22423BE55E747
language,English-US
code-page,Unicode UTF-16, little endian
ProductName,mimikatz
ProductVersion,2.1.1.0
CompanyName,gentilkiwi (Benjamin DELPY)
FileDescription,mimikatz for Windows
FileVersion,2.1.1.0
InternalName,mimikatz
LegalCopyright,Copyright (c) 2007 - 2017 gentilkiwi (Benjamin DELPY)
OriginalFilename,mimikatz.exe
PrivateBuild,Build with love for POC only
SpecialBuild,kiwi flavor !
```

[API Monitor](http://www.rohitab.com/apimonitor)

Process DoppleGanging/NTFS explicitly uses transactions:
- CreateTransaction()
- RollbackTransaction()
- CreateFileTransacted()
- DeleteFileTransacted()
- RemoveDirectoryTransacted()
- MoveFileTransacted()

# Hunting MALWARE

## Redline
- Review Processes by MRI Scores
- Analysis Data > Hierarchical Processes
- Double-click > Click on MRI Report
- Sections > Apply filter for Injected only and hit Filter.


