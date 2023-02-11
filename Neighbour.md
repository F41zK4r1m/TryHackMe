![image](https://user-images.githubusercontent.com/87700008/218257125-9ba65283-bebd-4b1e-9f0a-c1562a00fcee.png)

https://tryhackme.com/room/neighbour

Difficulty: Easy

## Enumeration :

I started with the quick rust scan & got the 2 open ports :

    22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    syn-ack ttl 62 Apache httpd 2.4.53 ((Debian))
    
![image](https://user-images.githubusercontent.com/87700008/218257342-d902f522-46e0-4fbc-8f79-ffad06e4a8ab.png)
![image](https://user-images.githubusercontent.com/87700008/218257374-b103234e-43af-4405-b83c-fca8f0637ed6.png)

I checked the Apache HTTP server & found a login page on it, with a account creation option.

![image](https://user-images.githubusercontent.com/87700008/218257460-7a18fb2e-08e9-4a58-84b9-9bfa52ec12cb.png)

I tried some SQL payloads to see if it was vulnerable, but I was unsuccessful. 😕
Then I switch to the html source code view & found 'guest' credentials to login.

![image](https://user-images.githubusercontent.com/87700008/218258583-8c8e7aec-bbdc-4fcd-afd7-877d5a14b434.png)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Flag.txt :

I logged in to the account using the credentials 'guest:guest' and found this page :

![image](https://user-images.githubusercontent.com/87700008/218258677-09412a4c-8fce-4134-a777-531f899e9338.png)

In the URL, I noticed that it was pointing towards the guest user :

    ?user=guest
    
This may lead to an IDOR vulnerability.

Considering the above scenario I changed the parameter and replaced 'guest' with 'admin' to get the flag. (pwn3d!🙂)

    ?user=admin
    
![image](https://user-images.githubusercontent.com/87700008/218258862-bda75f3f-51ef-43f7-ab08-807321aec521.png) 
