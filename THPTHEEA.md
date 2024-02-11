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
        > cat 4740.dmp.TXT | grep "powershell.exe" \
        cat 4740.dmp.TXT | grep "Invoke-"\
        cat 4740.dmp.TXT | grep ".hta"\
        cat 4740.dmp.TXT | grep "mshta"

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
    5 - **Suspicious Modules **- It looks for RWX memory regions on modules memory areas\
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

**linux**
>volatility --profile=SomeLinux -f file.dmp linux_ifconfig

>volatility --profile=SomeLinux -f file.dmp linux_netstat

>volatility --profile=SomeLinux -f file.dmp linux_netfilter

>volatility --profile=SomeLinux -f file.dmp linux_arp #ARP table

>volatility --profile=SomeLinux -f file.dmp linux_list_raw #Processes using promiscuous raw sockets (comm between processes)

>volatility --profile=SomeLinux -f file.dmp linux_route_cache

# Volatily - Command Reference Malware

## malfind
The malfind command helps find hidden or injected code/DLLs in user mode memory, based on characteristics such as VAD tag and page permissions.

## svcscan
Volatility is the only memory forensics framework with the ability to list services without using the Windows API on a live machine. 

A new option (--verbose) is available starting with Volatility 2.3. This option checks the ServiceDll registry key and reports which DLL is hosting the service. This is a critical capability since malware very commonly installs services using svchost.exe (the shared host service process) and implements the actual malicious code in a DLL.

```
$ python vol.py -f win7_trial_64bit.raw svcscan --verbose --profile=Win7SP0x64
Volatility Foundation Volatility Framework 2.4
Offset: 0xa26e70
Order: 71
Process ID: 1104
Service Name: DPS
Display Name: Diagnostic Policy Service
Service Type: SERVICE_WIN32_SHARE_PROCESS
Service State: SERVICE_RUNNING
Binary Path: C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork
ServiceDll: %SystemRoot%\system32\dps.dll <----- This is the component you recover from disk
```
## Volatility - Rootkit Detection Linux
### linux_check_afinfo
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

### linux_check_tty
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

### linux_keyboard_notifier
- This plugin detects the second kernel level keylogging method described in "Bridging the Semantic Gap to Mitigate Kernel-level Keyloggers". 
- It works by walking the kernel "keyboard_notifier_list" and checking if each notifier (callback) is within the kernel. If the callback is malicious then its symbol name is printed, otherwise "HOOKED" is printed.

### linux_check_creds
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
### linux_check_fop
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

### linux_check_idt
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

### linux_check_syscall
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

### linux_check_modules
This plugin finds rootkits that break themselves from the module list but not sysfs. 

We have never found a rootkit that actually removes itself from sysfs, so on a live system they are hidden from lsmod and */proc/modules*, but can still be found under */sys/modules*. We perform the same differnecing with the in-memory data structures.
```
# python vol.py -f kbeast.this --profile=LinuxDebianx86 linux_check_modules
Volatility Foundation Volatility Framework 2.2_rc1
Module Name
-----------
ipsecs_kbeast_v1
```

#### linux_check_creds
The purpose of this plugin is to check if any processes are sharing 'cred' structures. In the beginning of the 2.6 kernel series, the user ID and group ID were just simple integers, so rootkits could elevate the privleges of userland processes by setting these to 0 (root). In later kernels, credentials are kept in a fairly complicated 'cred' structure. So now rootkits instead of allocating and setting their own 'cred' structure simply set a processes cred structure to be that of another root process that does not exit (usually init / pid 1). This plugin checks for any processes sharing 'cred' structures and reports them as the kernel would normally never do this. It finds a wide range of rootkits and rootkit activity and you can focus your investigation on elevated process (i.e. bash)

# Hunting For Process Injection & Proactive API Monitoring

## Process Injection
> - minjector.exe -m 1 -s C:\Users\Administrator\Desktop\Tools\memhunter\msimplepayload.dll -t 4016

### Detection

> **Memdump**
    >- memhunter.exe -m 5

> **ProcessHacker**
    > - Check for suspcious binary loaded in "Modules" and get base address.
    > - Checl address in the "Memory" Tab. Usually it has PAGE_EXECUTE_WRITECOPY(WCX) or RCX protection.

## Process Hollowing
> - minjector.exe -m 7 -s C:\Users\Administrator\Desktop\Tools\memhunter\mhookpayload.dll -t c:\windows\system32\notepad.exe
### Detection
> **Memdump**
    > - memhunter.exe -m 4

> **ProcessHacker**
    > - 2 base address will be found in "Modules" related to the Process.
    > - Check the mapped (lower) address in the "Memory".
    > - Supicious "Current Directory" in General information.

## Reflective DLL Injection
> - minjector.exe -m 5 -s C:\Users\Administrator\Desktop\Tools\memhunter\reflective_dll.x64.dll -t 5104

### Detection
>**Memdump**
    > - memhunter.exe -m 1

> **ProcessHacker**
    > - Check for *ntdll.dll!RtlUserThreadStart*.
    > - Get the address without prefix in the buttom.
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
    > - On General Tab:
    >   - Commandline: 0
    >   - Suspicious "Current Directory" (location of the payload)
    >   - Parent Process: Duplicated from the filename of the parent process.
    > - On Threads Tab:
    >   - Only has Stard Address of Duplicated Process.
    > - On Handles Tab:
    >   - 0x40 shows the location of current directory
    >   - Spoofed Process has single Thread related to its filename.
    > - On Modules Tab:
    >   - Same with Process Injection, the payload can be traced in Modules Tab. Get the base adress.
    > - On Memory Tab:
    >   - Locate the payload using base adress on Modules Tab. Usually has WCX/RCX protection.

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
    > - On General Tab:
    >   - Blank Process with no Image Filename, Directory and Commandline.
    >   - Parent Process is Powershell
    > - On Threads Tab:
    >   - One entry, filename of the payload. On Modules Tab, using the filename, find and Check for the address.
    > - On Threads Tab:
    >   - One entry, filename of the payload. On Modules Tab, using the filename, find and Check for the address and dump in Memory Tab.

- [PEStudio](https://www.winitor.com/download) - Load the dumped file.
- [PE-SIEVE](https://github.com/hasherezade/pe-sieve) - Properly dump the payload
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
