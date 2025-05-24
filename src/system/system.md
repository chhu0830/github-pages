# System
<!-- toc -->

## Tool

### Malware Scanner
- [Microsoft Safety Scanner](https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/safety-scanner-download)
- [MSRT (Windows Malicious Software Removal Tool)](https://www.microsoft.com/en-us/download/details.aspx?id=9905)
- [Trend Micro Anti-Threat Toolkit](https://www.trendmicro.com/zh_tw/business/capabilities/solutions-for/ransomware/free-tools.html)
- [VirusTotal](https://www.virustotal.com/gui/)
- [nodistribute](https://nodistribute.com/)

### System Forensic
- wireshark
- autopsy
- sleuthkit
- OSForensic
- regsnap
- Process Monitor (SysinternalsSuite)
- Porcess Explorer (SysinternalsSuite)
- WinObj (SysinternalsSuite)
- Task Explorer (ExplorerSuite)
- Driver List (ExplorerSuite)
- FTK Imager

### Vulnerability Assessment
- OpenVAS
- metasploit
- nmap
- cobaltstrike


## Background

### Windows 🟦
> https://lolbas-project.github.io/

- Common Command

  | Run | Pannel |
  |-----|--------|
  | `control` | `控制台`
  | `ncpa.cpl` | `網路連線` |
  | `wf.msc` | `防火牆規則` |
  | `taskschd.msc` | `工作排程` |
  | `services.msc` | `服務` |
  | `winver` | 
  | `msinfo32` |

- Essential Folder

  | Folder | Usage |
  |--------|-------|
  | `%SystemRoot%\System32\Tasks` | Schedule Tasks |
  | `%SystemRoot%\Tasks` | Schedule Tasks (Legacy) |
  | `%SystemRoot%\System32\winevt\Logs` | Event Logs |
  | `%SystemRoot%\System32\config` | HKLM |
  | `%USERPROFILE%\NTUSER.DAT` | HKCU |
  | `%LOCALAPPDATA%\Microsoft\Windows\Usrclass.dat` | |

- Essential Registry

  | Path | Usage |
  |------|-------|
  | `HKLM\System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules\{GUID}` | Firewall Policy |
  | `HKLM\System\CurrentControlSet\Services\BFE\Parameters\Policy\Persistent\Provider\{GUID}` | WFP |
  | `HKLM\System\CurrentControlSet\Services\BFE\Parameters\Policy\Persistent\Filter\{GUID}` | WFP |
  | `HKLM\System\CurrentControlSet\Control\HiveList` | Reg mapping to file |
  | `{HKLM,HKCU}\Software\Classes` | `HKEY_CLASSES_ROOT` |

- `SET __COMPAT_LAYER=RunAsInvoker`
- File
  - `$ fsutil file queryfileid <file>`
  - `$ (Get-Item filename).lastwritetime=(Get-Date "mm/dd/yyyy hh:mm am/pm")`
- Process
  - `$ tasklist`
  - `$ wmic process`
  - `$ Get-CimInstance -ClassName Win32_Process`
- Task Scheduler
  - `$ schtasks`

#### Active Directory (AD)
- Command
  - `$ Get-ADObject -Filter * -Properties *`  
  - `$ Get-ADObject -Filter {ObjectGUID -eq <GUID>} -Properties *`
- Event
  - `5137` `A directory service object was created`

#### wmi
> WBEM (Web-Based Enterprise Management) 是根據 DMTF (Distributed
> Management Task Force) 的 CIM (Common Information Model) 所制訂出來的規格
>
> Microsoft implemented their own version of WBEM which they called WMI
> (Windows Management Instrumentation)

> [Windows Management Instrumentation | Microsoft](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page)

- GUI Tool
  - wbemtest
  - WMI Explorer
- Process
  - `C:\WINDOWS\system32\wbem\wmiprvse.exe`
- Command

  | Description | Powershell | wmic | WQL |
  |-------------|------------|------|-------|
  | List Namespaces | `Get-CimInstance [-Namespace <namespace:(root/cimv2)>] -ClassName __NAMESPACE` | | `SELECT * From __NAMESPACE` |
  | List Classes | `Get-CimClass [-Namespace <namespace:(root/cimv2)>] [[-ClassName] <classname:(*)>]` |
  | List Instances | `Get-CimInstance [-Namespace <namespace:(root/cimv2)>] -ClassName <classname>` | `wmic [/namespace:<namespace:(\\root\cimv2)>] path <classname>` | `Select * From <classname>` |
  
- Important Instance

  | Namespace | ClassName |
  |-----------|-----------|
  | `root/Microsoft/Windows/Defender` | `MSFT_MpComputerStatus` |
  | `root/SecurityCenter2` | `AntivirusProduct` |
  | `root/SecurityCenter2` | `FirewallProduct` |
  | `root/cimv2` | `Win32_Account` |
  | `root/cimv2` | `Win32_LoggedOnUser` |
  | `root/cimv2` | `Win32_Process` |

#### NTFS Stream
> [NTFS File Structure](https://www.researchgate.net/profile/Costas_Katsavounidis2/publication/363773832_Master_File_Table_MFT_on-disk_Structures_NTFS_31_httpsgithubcomkacos2000MFT_Browser/links/632da89086b22d3db4d9afad/Master-File-Table-MFT-on-disk-Structures-NTFS-31-https-githubcom-kacos2000-MFT-Browser.pdf)  
> [NTFS Streams](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c54dec26-1551-4d3a-a0ea-4fa40f848eb3)  
> [File Streams (Local File Systems)](https://docs.microsoft.com/en-us/windows/win32/fileio/file-streams)  
- `fsutil file layout <file>`
- Extended Attribute
  - `fsutil file queryEA <file>`
  - WSL metadata
- Alternative Data Stream
  ```cmd
  echo abc > note.txt:abc.txt
  echo C:\Windows\System32\cmd.exe > note.txt:cmd.exe
  dir /R

  wmic process call create note.txt:cmd.exe
  forfiles /M note.txt /C "note.txt:cmd.exe"

  Get-Content note.txt -stream abc.txt
  more < note.txt:abc.txt:$DATA
  ```

#### [Naming Files, Paths, and Namespaces](https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file)
- Namespace
  - Win32 File Namespace
    - `\\?\`
      > tells the Windows APIs to disable all string parsing and to send the string that follows it straight to the file system
    - `\\?\GLOBALROOT\Device\ConDrv\Console`
      > `\\?\GLOBALROOT` ensures that the path following it looks in the true root path of the system object manager and not a session-dependent path
  - Win32 Device Namespace
    - `\\.\`
      > access the Win32 device namespace instead of the Win32 file namespace
  - NT Namespace
    - `\??\` 
      > NT Object Manager paths that can look up DOS-style devices like drive letters
      > 1. process's `DosDevices` table
      > 2. `\GLOBAL??` Object Manager directory
      >
      > A "fake" prefix which refers to per-user Dos devices
      >
      > ![file path handling, user / kernal mode](https://i.stack.imgur.com/LOeeO.png)
    - | Path         | Content             |
      |:-------------|:--------------------|
      | `\Global??\` | Win32 namespace     |
      | `\Device\`   | Named device object |
- Reserved Name (`\Global??\`)

  | Filename | Meaning |
  |:----|:---------------------------|
  | CON | console (input and output) |
  | AUX | an auxiliary device. In CP/M 1 and 2, PIP used PUN: (paper tape punch) and RDR: (paper tape reader) instead of AUX: |
  | LST | list output device, usually the printer |
  | PRN | as LST:, but lines were numbered, tabs expanded and form feeds added every 60 lines |
  | NUL | null device, akin to /dev/null |
  | EOF | input device that produced end-of-file characters, ASCII 0x1A |
  | INP | custom input device, by default the same as EOF: |
  | OUT | custom output device, by default the same as NUL: |

#### Remote Command
  - psexec
    - Make sure `\\<host>\admin$` can be accessed

    ```psh
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d 1 /f
    netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
    psexec \\host -u <user> -p <pass> -i [SessID] <cmd>
    ```

  - wmic

    ```psh
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d 1 /f
    netsh firewall set service remoteadmin enable
    wmic /node:<host> /user:<user> /password:<pass> process call create <cmd>
    ```

  - winrm

#### Windows Event
  - Sysmon
    - [SysmonSimulator](https://rootdse.org/posts/understanding-sysmon-events/)

#### minifilter

#### WFP

#### AMSI

#### UWP (app container)


### Linux 🐧
> https://gtfobins.github.io/

### macOS 🍎
- Resource Fork
- Named Fork
- Data Fork
