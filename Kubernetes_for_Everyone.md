![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/605b255b-71a0-46df-9d43-85eea19155fd)

https://tryhackme.com/room/kubernetesforyouly

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Enumeration:

I started with the quick port & service scan using rustscan, which revealed 5 open ports in the environment:

```bash
sudo rustscan -a 10.10.144.85 -- -sC -sV -vv -oN kube_nmap
```

```Rust
PORT     STATE SERVICE       REASON         VERSION
22/tcp   open  ssh           syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e2:35:e1:4f:4e:87:45:9e:5f:2c:97:e0:da:a9:df:d5 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDTRQx4ZmXMByEs6dg4VTz+UtM9X9Ljxt6SU3oceqRUlV+ohx56xdD0ZPbvD0IcYwUrrqcruMG0xxgRxWuzV+FQAJVQe76ED966+lwrwAnUsVFQ5apw3N+WKnD53eldUZRq7/2nGQQizrefY7UjAGX/EZonSVOWZyhVyONu2VBBwg0B0yA3UBZV+yg+jGsrZ9ETEmfNbQRkbodEAwoZrGQ87UEdTkfj+5TGmfzqgukmBvvVV7KoXgSQIZNkqRmkAVKKXeEfydnOR37KMglBUXIR/50jkIswxWbNk2OtS6fz6UiPeEY39f4f0gwLx/HwUyel9yzH4dkDb+LBS6X/X9b9
|   256 b2:fd:9b:75:1c:9e:80:19:5d:13:4e:8d:a0:83:7b:f9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAqCgW5Mlx2VpC61acc0G4VMZUAauQDoK5xIzdHzdDLPXt0GqsoIw1fuwTSSzSy8RFmGU5PNHiWn0egoUwlXdc4=
|   256 75:20:0b:43:14:a9:8a:49:1a:d9:29:33:e1:b9:1a:b6 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFZ/jrfDX1aK1I0A/sLRVb2qoCF9xHWbVW+gBCV8dSmg
111/tcp  open  rpcbind       syn-ack ttl 61 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
3000/tcp open  ppp?          syn-ack ttl 60
| fingerprint-strings: 
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|_    Request
5000/tcp open  http          syn-ack ttl 60 Werkzeug httpd 2.0.2 (Python 3.8.12)
| http-methods: 
|_  Supported Methods: OPTIONS
|_http-server-header: Werkzeug/2.0.2 Python/3.8.12
6443/tcp open  sun-sr-https? syn-ack ttl 61
```

I started the enumeration process with checking the null authentication on RPC port 111 but this didn't worked at it needs authentication:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/17c8da57-6bad-4116-afd4-0ced27a8a4f4)

Then I checked port 3000 & observed that it's running Grafana 8.3.0:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/4457a886-dd85-4fdc-80d4-b12f1df6e6db)

Checking on port 5000 revealed another web application but looking into the html source code leaded me towards "/static/css/main.css" which is having a pastebin link present, this caught my attention. I browsed through it & observed an encoded text in it.

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/49377824-1b0d-418d-be3a-7769f600e9f0)

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/ee82e4f6-d0a9-4686-b054-691a43db4a7d)

Moving further when I decoded the text I found the name which is the first flag:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/5f699301-aeb4-405a-bd5b-c9711ec7e0be)
