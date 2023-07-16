![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/bbeef66a-f1dc-4148-aff8-ec0ca514f46d)

https://tryhackme.com/room/fusioncorp

## Enumeration:

I began the enumeration with the quick rustscan & found 22 open ports.

```bash
sudo rustscan -a 10.10.227.87  -- -sC -sV -vv -oN fusion_nmap
```
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/6683635e-8c8e-463d-b5b7-195c4d130d93)

```Rust
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: eBusiness Bootstrap Template
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2023-07-16 08:57:35Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fusion.corp0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fusion.corp0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: FUSION
|   NetBIOS_Domain_Name: FUSION
|   NetBIOS_Computer_Name: FUSION-DC
|   DNS_Domain_Name: fusion.corp
|   DNS_Computer_Name: Fusion-DC.fusion.corp
|   Product_Version: 10.0.17763
|_  System_Time: 2023-07-16T08:58:27+00:00
| ssl-cert: Subject: commonName=Fusion-DC.fusion.corp
| Issuer: commonName=Fusion-DC.fusion.corp
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-07-15T08:36:38
| Not valid after:  2024-01-14T08:36:38
| MD5:   d747 3ab3 4a02 7ef2 886c eeec 5082 2609
| SHA-1: dd0e 0696 cb85 2535 508c c02f 88ba 9fec afbe 7f8c
| -----BEGIN CERTIFICATE-----
| MIIC7jCCAdagAwIBAgIQMK888Y3p9ZFNfpn8LgqG/zANBgkqhkiG9w0BAQsFADAg
| MR4wHAYDVQQDExVGdXNpb24tREMuZnVzaW9uLmNvcnAwHhcNMjMwNzE1MDgzNjM4
| WhcNMjQwMTE0MDgzNjM4WjAgMR4wHAYDVQQDExVGdXNpb24tREMuZnVzaW9uLmNv
| cnAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDSSbWayNCvAP7U0Nnu
| 3CR+DFQbovPnJm8boLS9cfgJNDxVnN+hra67QstLkZxWirF9GzF7VsqIbvI/RI+M
| gHUJeE/ORP1eZfgeEX63pxFdFUYJ2x6jicIOnqCP8NUNw6diomhw4oDa6TwUavF6
| WQsp6oBpJVCoUrHBHro9HwexBk6KNgcgd+C8K3aVtyhXO4F/Tz3SvHdheE+WwxWc
| h38YV5QoAwpLFSI7RWq9bWEEO91VoDAvuC9uevpGpXYDCCSYIQJtHIhSHST3p4rM
| WkS9lEA6rCAY+gxLwVWq+n2GA/S5cs9QNO3/098YVy2uGnGVsUGlZBJAwUfSZ7Vh
| rIv1AgMBAAGjJDAiMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAsGA1UdDwQEAwIEMDAN
| BgkqhkiG9w0BAQsFAAOCAQEAhhA4ONitH+0zYFqonFcDugDYEDmVYb80PA1K0Yxb
| 0q8gsfKKrtLDgcWgZ3V26wx8a+9yrWg4bvopshELl0O6jxUmfjaDKLzxEJEVcAKf
| Q8RrrMkjvHtjEWNdXXi8OGuab6Tvi1NX5YtyavRbful6YyHNUwGQMGcO0cYJVWSq
| epObHlF9NBpCOtPL8XYckkBRj4J6TcpkcBmNLO+VDX2F4m5u3Le/YDYEYSeBTJXb
| ViCig9TCCOubAPkKKcgtdZahHHA7w7JDFczrEKF0nLUMzneeONd6sPN6BLgSlsiX
| m+wyy7RfJGUwmJXIehj8EOuwPdouCxEJZUE6TXXFVLXDKQ==
|_-----END CERTIFICATE-----
|_ssl-date: 2023-07-16T08:59:06+00:00; +3s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49689/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49699/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Host: FUSION-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2s, deviation: 0s, median: 2s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 28062/tcp): CLEAN (Timeout)
|   Check 2 (port 55242/tcp): CLEAN (Timeout)
|   Check 3 (port 43510/udp): CLEAN (Timeout)
|   Check 4 (port 3493/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-07-16T08:58:28
|_  start_date: N/A
```

After the port scan results I observed a domain: "fusion.corp" & a DC running with the name: "Fusion-DC.fusion.corp".
I added the domain to the hosts file & went throgh it.

### DNS enumeration:

Since the DNS server is open I performed DNS enumeration using **dig** & ran the vhost enumeration to find other available sub-domains.

```bash
dig fusion.corp any @10.10.41.28
```
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/6265eefb-f2d9-4951-b33f-e7de32d43a8e)

```bash
dig fusion.corp any @10.10.41.28 -t NS #to check name server
```

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/a01efdeb-eeee-4d60-9ef1-b070d3c3d83f)

```bash
dig all fusion.corp @10.10.41.28
```
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/a0512a4f-b554-4df5-a843-f26aae852ba6)

So, In the DNS enumeration I didn't observed anything new that I wasn't discovered in the port scan results.
