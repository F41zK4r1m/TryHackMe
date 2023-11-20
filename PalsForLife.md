![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/96e062e0-a823-4074-b9fb-118b38954ba1)![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/34a3d405-1ada-4c91-a8a7-706dc541796b)

https://tryhackme.com/room/palsforlife

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Enumeration:

I started with the quick rustscan for port & service scan, this showed me multiple open ports open & running in the target host:

```Rust
sudo rustscan -a 10.10.153.17 -- -sC -sV -vv -oN result_nmap
```
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/9e1f5624-8980-47a8-90ee-8ef299941ca6)

```R
PORT      STATE SERVICE           REASON         VERSION
22/tcp    open  ssh               syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c9:f7:dd:3d:79:bb:f8:44:0f:bd:87:bd:8b:af:e1:5a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDHvPJdllGsYwbwbvXMP0T/d6NcClFy34rSyAVlCPB5jeR0/7DffGcCbj/+kwkTKw82Eb6HtTLKvQwFQduzGqba74IUgxJ3NmQ4IrnbwYg0Mqf1z0ZWeD3rMQKOJeDKcApnW24P2zjBjZ8iNf449DzQLQoQyhti0MQavrLYMwcELCd3u+83FD0pZZN4q5d5yor9EV++lZ5fpU0+seEWoXY9c0LfA9CX+6jwv2cQFTwqC8R78kkTimczT8tVVds/z0KUwpL7t2lsVMxIJ1SKi7XiroU0zJ+YkttZoio7++1vGtW+27Kv/PGQPI7v+953TPZ06BPC3/nxU7CD9Gtpig/h
|   256 4c:48:9d:c6:b4:e2:17:99:76:48:20:fe:96:d2:c8:eb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBKRe1KeqoY2DzrMJa+jbQPKLy+IMjqWDOtBQy+Oohg2R+bm1H1VcJWSTE2HhxW7GsbzBEAtqW+290KhTOOmiSQ=
|   256 d8:e2:f7:ac:4d:cd:68:66:d7:a9:64:1c:42:4a:8e:30 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKiIJ3rd6/JIuiXUx0sJhq8nY1ZypBueO4uckLvIzpur
6443/tcp  open  ssl/sun-sr-https? syn-ack ttl 61
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Mon, 20 Nov 2023 08:37:41 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Mon, 20 Nov 2023 08:37:03 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   HTTPOptions: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Mon, 20 Nov 2023 08:37:04 GMT
|     Content-Length: 129
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
| ssl-cert: Subject: commonName=k3s/organizationName=k3s
| Subject Alternative Name: DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc.cluster.local, DNS:localhost, IP Address:10.10.153.17, IP Address:10.43.0.1, IP Address:127.0.0.1, IP Address:172.30.18.136, IP Address:192.168.1.244
| Issuer: commonName=k3s-server-ca@1622498168
| Public Key type: ec
| Public Key bits: 256
| Signature Algorithm: ecdsa-with-SHA256
| Not valid before: 2021-05-31T21:56:08
| Not valid after:  2024-11-19T08:30:50
| MD5:   cfba 3840 e20c 136c 915a 0c64 9ff5 4d36
| SHA-1: c7ba 5b28 4a97 04c2 1a54 5893 1bd0 b6fb 9992 e8f6
| -----BEGIN CERTIFICATE-----
| MIIB+DCCAZ+gAwIBAgIIJubDQtsT1ZkwCgYIKoZIzj0EAwIwIzEhMB8GA1UEAwwY
| azNzLXNlcnZlci1jYUAxNjIyNDk4MTY4MB4XDTIxMDUzMTIxNTYwOFoXDTI0MTEx
| OTA4MzA1MFowHDEMMAoGA1UEChMDazNzMQwwCgYDVQQDEwNrM3MwWTATBgcqhkjO
| PQIBBggqhkjOPQMBBwNCAAQBAUGk5Ox0oLT3rZzPJUCVmQiwoHcg1zdU61yDtWZh
| 3Xv9/5BRkm/Hub4A1/z45qmNzYAdjAqi11p6s6lZhzfmo4HDMIHAMA4GA1UdDwEB
| /wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATAfBgNVHSMEGDAWgBTmY3iEZ5WD
| XNcMriUDriCamzSP1zB4BgNVHREEcTBvggprdWJlcm5ldGVzghJrdWJlcm5ldGVz
| LmRlZmF1bHSCJGt1YmVybmV0ZXMuZGVmYXVsdC5zdmMuY2x1c3Rlci5sb2NhbIIJ
| bG9jYWxob3N0hwQKCpkRhwQKKwABhwR/AAABhwSsHhKIhwTAqAH0MAoGCCqGSM49
| BAMCA0cAMEQCIC/eO7HtQWwp1lKnlx/rQIbpo2wftIuDjzXVjwZzqagUAiAqatEF
| E1cRKnOKasP83Qm/Pz93TZxF66Ns+kRpI4IGgg==
|_-----END CERTIFICATE-----
10250/tcp open  ssl/http          syn-ack ttl 61 Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
| ssl-cert: Subject: commonName=palsforlife
| Subject Alternative Name: DNS:palsforlife, DNS:localhost, IP Address:127.0.0.1, IP Address:10.10.153.17
| Issuer: commonName=k3s-server-ca@1622498168
| Public Key type: ec
| Public Key bits: 256
| Signature Algorithm: ecdsa-with-SHA256
| Not valid before: 2021-05-31T21:56:08
| Not valid after:  2024-11-19T08:30:51
| MD5:   6e02 32a7 1c54 0a29 d1f5 6573 bd5a 509a
| SHA-1: f7b1 ff98 cf02 0d74 7beb d352 a6ab 909e 6df6 66b9
| -----BEGIN CERTIFICATE-----
| MIIBpTCCAUygAwIBAgIIHSZq1NUDevEwCgYIKoZIzj0EAwIwIzEhMB8GA1UEAwwY
| azNzLXNlcnZlci1jYUAxNjIyNDk4MTY4MB4XDTIxMDUzMTIxNTYwOFoXDTI0MTEx
| OTA4MzA1MVowFjEUMBIGA1UEAxMLcGFsc2ZvcmxpZmUwWTATBgcqhkjOPQIBBggq
| hkjOPQMBBwNCAAQ3WT5sy0DB2LeKatk1dcRAuf7KwhCTIxwWTR5YwpyK+1oUEe4L
| 0hKr17Tzp30JWGZ48Xm/UUQdNfdt3iX+mzd1o3cwdTAOBgNVHQ8BAf8EBAMCBaAw
| EwYDVR0lBAwwCgYIKwYBBQUHAwEwHwYDVR0jBBgwFoAU5mN4hGeVg1zXDK4lA64g
| mps0j9cwLQYDVR0RBCYwJIILcGFsc2ZvcmxpZmWCCWxvY2FsaG9zdIcEfwAAAYcE
| CgqZETAKBggqhkjOPQQDAgNHADBEAiBPAfp9by2VDgBAJhoDJ3xBWQeNXXnQ8K3G
| jb1aZwJeWAIgYPkW5pyae2PkM5k1xvdE7IPKKXcwlUr/8nxBqu7Nnx0=
|_-----END CERTIFICATE-----
30180/tcp open  http              syn-ack ttl 60 nginx 1.21.0
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.21.0
|_http-title: 403 Forbidden
31111/tcp open  unknown           syn-ack ttl 60
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gitea=2bdbb5a3d422506b; Path=/; HttpOnly
|     Set-Cookie: _csrf=l99rnuNX_8uHAAxHaKtAnb0QlrU6MTcwMDQ2OTQxNTgzMDA3MTEyNQ%3D%3D; Path=/; Expires=Tue, 21 Nov 2023 08:36:55 GMT; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 20 Nov 2023 08:36:55 GMT
|     <!DOCTYPE html>
|     <html>
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Gitea: Git with a cup of tea</title>
|     <meta name="theme-color" content="#6cc644">
|     <meta name="author" content="Gitea - Git with a cup of tea" />
|     <meta name="description" content="Gitea (Git with a cup of tea) is a painless self-hosted Git service written in Go" />
|     <meta name="keywords" content="go,git,self-hosted,gitea
|   HTTPOptions: 
|     HTTP/1.0 404 Not Found
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gitea=e9fb7d1fe1a74651; Path=/; HttpOnly
|     Set-Cookie: _csrf=rXj7_8XU0I7jSzULacOHGp6hyBs6MTcwMDQ2OTQxNjQ1NDQ3NjU2Ng%3D%3D; Path=/; Expires=Tue, 21 Nov 2023 08:36:56 GMT; HttpOnly
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 20 Nov 2023 08:36:56 GMT
|     <!DOCTYPE html>
|     <html>
|     <head data-suburl="">
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Page Not Found - Gitea: Git with a cup of tea</title>
|     <meta name="theme-color" content="#6cc644">
|     <meta name="author" content="Gitea - Git with a cup of tea" />
|     <meta name="description" content="Gitea (Git with a cup of tea) is a painless self-hosted Git service written in Go" />
|_    <meta name="keywords" content="
31112/tcp open  ssh               syn-ack ttl 60 OpenSSH 7.5 (protocol 2.0)
| ssh-hostkey: 
|   2048 2b:c6:63:84:93:b8:04:ce:1c:f5:ce:c7:0e:ca:eb:28 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDL89blW/fideD2Xo7UKOytdLmzkVLToqJFWPKHQ4UP9ZNXTr7GAqeXvRRB9wmdsv4CpNRnQh3KtHuB7QgfZA//6aHtf5ss8zQydhZW5HS6a3Y2DhRnmOLtDQK5XHA1icP2EMYKIH0rfgPFFm1SRUieqbn62Zu//Cd8TdTfax7u1X3raA1nA7WEa+bnH1U4zO7sC6pZVSh7OoDRR/uD8r1xy2IxwcEIHyLVYdJdjxNhy8ryzkU1fwwLbzhSOsA+9bN/V4pq5/tLvipsX5FpIeF7CwHd+3EWlHl64zTWuCnvr5u/MBN3Q/bM2UGbwxj8Jq8tFRbQXoSfXpTrodKmLBSB
|   256 93:6b:41:5f:89:14:97:0c:6b:53:ab:ba:af:71:f1:40 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKWQuDYkhFhWAillXUpZDXIg86x6wt2RLODmfT6jSjAW8VQO+B6efJrMV5Z5YkJ57WmqTF2rPDxEBIegPiMHddU=
|   256 e8:c4:94:7b:72:d7:4c:1c:bd:51:4a:84:81:4b:68:c9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILJgWYJQirOpfa5TYPCcHU+p2NbHFMTjHFyTyGU9KVng
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port6443-TCP:V=7.91%T=SSL%I=7%D=11/20%Time=655B1AAA%P=x86_64-unknown-li
SF:nux-gnu%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConten
SF:t-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n
SF:400\x20Bad\x20Request")%r(GetRequest,11A,"HTTP/1\.0\x20401\x20Unauthori
SF:zed\r\nCache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20appli
SF:cation/json\r\nDate:\x20Mon,\x2020\x20Nov\x202023\x2008:37:03\x20GMT\r\
SF:nContent-Length:\x20129\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1
SF:\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"Unauthorized\",
SF:\"reason\":\"Unauthorized\",\"code\":401}\n")%r(HTTPOptions,11A,"HTTP/1
SF:\.0\x20401\x20Unauthorized\r\nCache-Control:\x20no-cache,\x20private\r\
SF:nContent-Type:\x20application/json\r\nDate:\x20Mon,\x2020\x20Nov\x20202
SF:3\x2008:37:04\x20GMT\r\nContent-Length:\x20129\r\n\r\n{\"kind\":\"Statu
SF:s\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"mess
SF:age\":\"Unauthorized\",\"reason\":\"Unauthorized\",\"code\":401}\n")%r(
SF:RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-T
SF:ype:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400
SF:\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x2
SF:0close\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSess
SF:ionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/
SF:plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Re
SF:quest")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Ty
SF:pe:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\
SF:x20Bad\x20Request")%r(FourOhFourRequest,11A,"HTTP/1\.0\x20401\x20Unauth
SF:orized\r\nCache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20ap
SF:plication/json\r\nDate:\x20Mon,\x2020\x20Nov\x202023\x2008:37:41\x20GMT
SF:\r\nContent-Length:\x20129\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\
SF:"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"Unauthorized
SF:\",\"reason\":\"Unauthorized\",\"code\":401}\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port31111-TCP:V=7.91%I=7%D=11/20%Time=655B1AA3%P=x86_64-unknown-linux-g
SF:nu%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(GetRequest,2699,"HTTP/1\.0\x20200\x20OK\r\nContent
SF:-Type:\x20text/html;\x20charset=UTF-8\r\nSet-Cookie:\x20lang=en-US;\x20
SF:Path=/;\x20Max-Age=2147483647\r\nSet-Cookie:\x20i_like_gitea=2bdbb5a3d4
SF:22506b;\x20Path=/;\x20HttpOnly\r\nSet-Cookie:\x20_csrf=l99rnuNX_8uHAAxH
SF:aKtAnb0QlrU6MTcwMDQ2OTQxNTgzMDA3MTEyNQ%3D%3D;\x20Path=/;\x20Expires=Tue
SF:,\x2021\x20Nov\x202023\x2008:36:55\x20GMT;\x20HttpOnly\r\nX-Frame-Optio
SF:ns:\x20SAMEORIGIN\r\nDate:\x20Mon,\x2020\x20Nov\x202023\x2008:36:55\x20
SF:GMT\r\n\r\n<!DOCTYPE\x20html>\n<html>\n<head\x20data-suburl=\"\">\n\t<m
SF:eta\x20charset=\"utf-8\">\n\t<meta\x20name=\"viewport\"\x20content=\"wi
SF:dth=device-width,\x20initial-scale=1\">\n\t<meta\x20http-equiv=\"x-ua-c
SF:ompatible\"\x20content=\"ie=edge\">\n\t<title>Gitea:\x20Git\x20with\x20
SF:a\x20cup\x20of\x20tea</title>\n\t<meta\x20name=\"theme-color\"\x20conte
SF:nt=\"#6cc644\">\n\t<meta\x20name=\"author\"\x20content=\"Gitea\x20-\x20
SF:Git\x20with\x20a\x20cup\x20of\x20tea\"\x20/>\n\t<meta\x20name=\"descrip
SF:tion\"\x20content=\"Gitea\x20\(Git\x20with\x20a\x20cup\x20of\x20tea\)\x
SF:20is\x20a\x20painless\x20self-hosted\x20Git\x20service\x20written\x20in
SF:\x20Go\"\x20/>\n\t<meta\x20name=\"keywords\"\x20content=\"go,git,self-h
SF:osted,gitea")%r(HTTPOptions,1E87,"HTTP/1\.0\x20404\x20Not\x20Found\r\nC
SF:ontent-Type:\x20text/html;\x20charset=UTF-8\r\nSet-Cookie:\x20lang=en-U
SF:S;\x20Path=/;\x20Max-Age=2147483647\r\nSet-Cookie:\x20i_like_gitea=e9fb
SF:7d1fe1a74651;\x20Path=/;\x20HttpOnly\r\nSet-Cookie:\x20_csrf=rXj7_8XU0I
SF:7jSzULacOHGp6hyBs6MTcwMDQ2OTQxNjQ1NDQ3NjU2Ng%3D%3D;\x20Path=/;\x20Expir
SF:es=Tue,\x2021\x20Nov\x202023\x2008:36:56\x20GMT;\x20HttpOnly\r\nX-Frame
SF:-Options:\x20SAMEORIGIN\r\nDate:\x20Mon,\x2020\x20Nov\x202023\x2008:36:
SF:56\x20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html>\n<head\x20data-suburl=\"\">
SF:\n\t<meta\x20charset=\"utf-8\">\n\t<meta\x20name=\"viewport\"\x20conten
SF:t=\"width=device-width,\x20initial-scale=1\">\n\t<meta\x20http-equiv=\"
SF:x-ua-compatible\"\x20content=\"ie=edge\">\n\t<title>Page\x20Not\x20Foun
SF:d\x20-\x20Gitea:\x20Git\x20with\x20a\x20cup\x20of\x20tea</title>\n\t<me
SF:ta\x20name=\"theme-color\"\x20content=\"#6cc644\">\n\t<meta\x20name=\"a
SF:uthor\"\x20content=\"Gitea\x20-\x20Git\x20with\x20a\x20cup\x20of\x20tea
SF:\"\x20/>\n\t<meta\x20name=\"description\"\x20content=\"Gitea\x20\(Git\x
SF:20with\x20a\x20cup\x20of\x20tea\)\x20is\x20a\x20painless\x20self-hosted
SF:\x20Git\x20service\x20written\x20in\x20Go\"\x20/>\n\t<meta\x20name=\"ke
SF:ywords\"\x20content=\"");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
