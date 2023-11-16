![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/237d1358-0f0e-4869-b6d5-bb5b59575f61)

https://tryhackme.com/room/gitandcrumpets

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Enumeration:

I began with the quick rustscan & found few open ports:

```Rust
sudo rustscan -a 10.10.213.70 -- -sC -sV -vv -oN git_nmap
```

```bash
PORT      STATE    SERVICE REASON                  VERSION 
22/tcp    open     ssh     syn-ack ttl 61          OpenSSH 8.0 (protocol 2.0)
80/tcp    open     http    syn-ack ttl 61          nginx
26164/tcp filtered unknown admin-prohibited ttl 61
52263/tcp filtered unknown admin-prohibited ttl 61
```

From the port scan results, I started checking the port 80 for http webserver. When browsing through the server it's re-directing me towards the youtube video.
So, I checked the http server using the curl & observed a note in the source-code:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/8ce039be-92cd-4109-bad8-24d74c7c03c1)

I added the domain "git.git-and-crumpets.thm" to my host config file & browsed through it & found a git instance:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/6d97e7dd-93fb-4b6e-afc8-7e914871ac2c)

On the login page I tried few default credentials but none of them worked, so I moved on with the new user registration.

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/6604cce2-8b64-4ad3-8054-93ab7417d349)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Git:

I created a new account with the username 'nimda'. Post login I obserbed 2 repositories in the Git:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/a5135e1f-7484-41ce-bab6-0fe391e1020b)

When checked the 'scones' repo history I found a deleted comming of Password file & a comment mentioned ```I kept the password in my avatar to be more secure.```

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/00af8bfe-1c73-472e-b220-5a5fc67cd961)

Using this hind I downloaded the avatar of the scones using wget:

```bash
wget http://git.git-and-crumpets.thm/avatars/3fc2cde6ac97e8c8a0c8b202e527d56d
```

upon checking the avatar metadata using the exiftool, I observed the password in the comments:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/7f6bdcc3-6609-431a-80b7-465b4f9abb33)

Using this password I was finally able to login into the "scones" account.

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/efe1d1b1-453b-4105-831f-f0f473fa28a8)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Initial access:

Once logged in to the "Scones" account I observed that I have the access to update/modify the GitHooks. While researching more about the [GitHooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) I observed that:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/b7211139-f396-45fe-a0c2-dc2ff7b76d3e)

So, I modified the pre-receive hook & added the bash reverse shell:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/06e76c47-4981-443d-9e68-0ec989b7e6ae)
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/30935084-c8ec-4731-90b3-739398642f7c)

Now, to trigger the git hook I have to perform the change in the commit. But after updating the commint I observed that the port 1337 is blocked for the connection. 😕

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/6b51a83f-b880-46c1-9e49-9891d4abb603)

After changing the port to the different port I finally received the connection back to my netcat listener. 🙂

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/fd466ae2-d780-4ed5-8115-22d93f284009)

Finally after moving into the home directory I was able retrieve the user flag, which was in base64 format. (pwn3d!🙂)

After getting the remote access I generated a ssh key pair & added my public key to the authorized key for the git user. By which I got the stable SSH access on the host.

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/c937baea-a0b4-47a2-abd9-eaba4b22affa)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Privilege Escalation:

Since, I still not have the password of the "scones" I can't check for the sudo privileges. So, I started the manual enumeration & observed that in this location ```/var/lib/gitea/data``` there is a gitea.db folder.

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/10ab68b0-ad13-4550-90f9-ecaf6ca7df13)

I used Sqlite3 to intercat with the database file:

```sql
sqlite3 gitea.db

sqlite> .tables
sqlite> SELECT * FROM user;
```
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/c30a2e4c-0c4a-4bbd-85b3-ff222dd9c45a)

```sql
sqlite> SELECT * FROM repository;
```
In the Git we can only see 2 repositories but in the database we can see there is a root database which exist & not visisble to us.

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/fbbdb0b4-0506-4ca9-9983-02b1a21d2589)

```sql
SELECT sql FROM sqlite_master WHERE type='table' AND tbl_name='repository';
```
Using the above SQL query we can see the properties of the repository, where we can see the is_private option is enabled:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/af069433-b377-4481-be19-e59fa27d82ef)

We can disable this option by using below command:

```sql
UPDATE repository SET is_private=0 WHERE id=2;  #as root id =2
```

After chaning the private value now we can see the root repository in the Git:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/20722d8c-3dbd-4a8c-94a5-04fb9c0696ef)

ENumerating the root repo in the "dotfiles" commit, in the history I observed SSH private for the root user:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/2e038ade-3156-4a17-bf7c-8283421e846e)
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/9f9f44d3-c037-4732-b0aa-e40521fae500)

Using this private key & the passphrase as "Sup3rS3cur3", I was finally able to login as a root user via "SSH".

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/9c46149f-a611-4e19-b973-7b5c5c3d2a34)

After which I was also able to fetch the root flag. (pwn3d!🙂)
