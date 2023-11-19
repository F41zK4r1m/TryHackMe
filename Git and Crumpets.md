![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/237d1358-0f0e-4869-b6d5-bb5b59575f61)

https://tryhackme.com/room/gitandcrumpets

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Enumeration:

Commencing with a swift Rustscan, I uncovered a handful of accessible ports:

```Rust
sudo rustscan -a 10.10.213.70 -- -sC -sV -vv -oN git_nmap
```

The scan revealed the following open ports:

```bash
PORT      STATE    SERVICE REASON                  VERSION 
22/tcp    open     ssh     syn-ack ttl 61          OpenSSH 8.0 (protocol 2.0)
80/tcp    open     http    syn-ack ttl 61          nginx
26164/tcp filtered unknown admin-prohibited ttl 61
52263/tcp filtered unknown admin-prohibited ttl 61
```

Proceeding from the port scan results, my focus shifted to port 80, housing an HTTP web server. Upon exploration, the server redirected me to a YouTube video. To delve deeper, I employed curl and stumbled upon a noteworthy note embedded in the source code:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/8ce039be-92cd-4109-bad8-24d74c7c03c1)

Subsequently, I added the domain "git.git-and-crumpets.thm" to my host configuration file, allowing me to navigate through it and unveil a Git instance:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/6d97e7dd-93fb-4b6e-afc8-7e914871ac2c)

Attempts to gain access via default credentials on the login page proved futile. Consequently, I proceeded with user registration:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/6604cce2-8b64-4ad3-8054-93ab7417d349)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Git:

Upon creating a new account with the username 'nimda,' I discovered two repositories within the Git platform:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/a5135e1f-7484-41ce-bab6-0fe391e1020b)

Upon inspecting the 'scones' repository history, I unearthed a deleted commit containing a Password file, accompanied by a comment stating, ```"I kept the password in my avatar to be more secure."```

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/00af8bfe-1c73-472e-b220-5a5fc67cd961)

To follow this lead, I downloaded the avatar of 'scones' using wget:

```bash
wget http://git.git-and-crumpets.thm/avatars/3fc2cde6ac97e8c8a0c8b202e527d56d
```

Examining the avatar metadata with exiftool revealed the password in the comments:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/7f6bdcc3-6609-431a-80b7-465b4f9abb33)

Leveraging this password, I successfully gained access to the "scones" account:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/efe1d1b1-453b-4105-831f-f0f473fa28a8)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Initial access:

Upon logging into the "Scones" account, I discovered the ability to update and modify GitHooks. Further exploration into [GitHooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks) revealed their role in customizing Git behavior:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/b7211139-f396-45fe-a0c2-dc2ff7b76d3e)

Taking advantage of this capability, I modified the pre-receive hook, injecting a Bash reverse shell:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/06e76c47-4981-443d-9e68-0ec989b7e6ae)
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/30935084-c8ec-4731-90b3-739398642f7c)

However, triggering the Git hook required a commit change. Unfortunately, attempts to connect on the default port 1337 were unsuccessful: 😕

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/6b51a83f-b880-46c1-9e49-9891d4abb603)

Undeterred, I changed the port to an alternative, successfully establishing a connection to my netcat listener: 🙂

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/fd466ae2-d780-4ed5-8115-22d93f284009)

Navigating to the home directory, I retrieved the user flag, encoded in base64. (pwn3d!🙂)

With remote access secured, I generated an SSH key pair, adding my public key to the authorized keys for the Git user. This provided a stable SSH connection to the host:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/c937baea-a0b4-47a2-abd9-eaba4b22affa)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Privilege Escalation:

As the password for the "scones" account was still elusive, I initiated manual enumeration. A crucial discovery emerged in the ```/var/lib/gitea/data directory```, where a hidden ```gitea.db``` folder was located:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/10ab68b0-ad13-4550-90f9-ecaf6ca7df13)

Leveraging SQLite3 to interact with the database file, I uncovered valuable information:

```sql
sqlite3 gitea.db

sqlite> .tables
sqlite> SELECT * FROM user;
```
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/c30a2e4c-0c4a-4bbd-85b3-ff222dd9c45a)

```sql
sqlite> SELECT * FROM repository;
```
Exploring the **repository** table, I identified a hidden root database not visible through Git:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/fbbdb0b4-0506-4ca9-9983-02b1a21d2589)

```sql
SELECT sql FROM sqlite_master WHERE type='table' AND tbl_name='repository';
```
Delving deeper, I altered the is_private property for the root repository, making it visible:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/af069433-b377-4481-be19-e59fa27d82ef)

```sql
UPDATE repository SET is_private=0 WHERE id=2;  #as root id =2
```
With this modification, the root repository became accessible in Git:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/20722d8c-3dbd-4a8c-94a5-04fb9c0696ef)

Inspecting the "dotfiles" commit in the root repository's history, I unearthed the SSH private key for the root user:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/2e038ade-3156-4a17-bf7c-8283421e846e)
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/9f9f44d3-c037-4732-b0aa-e40521fae500)

Utilizing this private key with the passphrase "Sup3rS3cur3," I successfully accessed the root user via SSH:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/9c46149f-a611-4e19-b973-7b5c5c3d2a34)

Subsequently, I retrieved the root flag, completing the privilege escalation.(pwn3d!🙂)
