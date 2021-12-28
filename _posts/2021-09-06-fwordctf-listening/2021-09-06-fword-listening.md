---
layout: post
title: "FwordCTF 2021 - listening? [Forensic]"
tags: forensic pcap mz4b
date: 2021-08-29 16:12:00 UTC
author: mz4b
---

listening? was one of the forensics challenges in Fword ctf 2021.

The challenge description reads:
```
How Deep Can You Possibly Dig?
Flag Format: FwordCTF{....}

```


We are given a pcap file `challenge.pcap`.

It is a small trace that lasts almost 9 seconds and contains 66 packets, including DNS, ARP and ICMP traffic and a single HTTP connection.  Let's analyze this one:

```
REQUEST - packet 19

POST /token HTTP/1.1
Host: oauth2.googleapis.com
Content-length: 269
content-type: application/x-www-form-urlencoded
user-agent: google-oauth-playground

client_secret=AER8VvrXuFfYfqjhidcekAM0&grant_type=refresh_token&refresh_token=1%2F%2F044y6gZR87Kl0CgYIARAAGAQSNwF-L9IrkAFpIJPMhiGY0OPJpo5RiA5_7R-mHH-kuHwCMUeFL2JqxevGr23oBJmaxdnrD52t3X4&client_id=1097638694557-3v745luessc34bkoiqkf8tndqgvbqjpm.apps.googleusercontent.com&email=fwordplayground@gmail.com
```

```
RESPONSE - packet 33

HTTP/1.1 403 Forbidden
Vary: X-Origin
Vary: Referer
Content-Type: application/json; charset=UTF-8
Date: Fri, 27 Aug 2021 18:24:31 GMT
Server: scaffolding on HTTPServer2
Cache-Control: private
X-XSS-Protection: 0
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Accept-Ranges: none
Vary: Origin,Accept-Encoding
Transfer-Encoding: chunked

{
  "error": {
    "code": 403,
    "message": "SSL is required to perform this operation.",
    "status": "PERMISSION_DENIED"
  }
}
```

It looks like the server was expecting a connection over HTTPS instead of HTTP, so let's try to reproduce the POST request to port 443:

```
https://oauth2.googleapis.com/token

client_secret=AER8VvrXuFfYfqjhidcekAM0
grant_type=refresh_token
refresh_token=1//044y6gZR87Kl0CgYIARAAGAQSNwF-L9IrkAFpIJPMhiGY0OPJpo5RiA5_7R-mHH-kuHwCMUeFL2JqxevGr23oBJmaxdnrD52t3X4
client_id=1097638694557-3v745luessc34bkoiqkf8tndqgvbqjpm.apps.googleusercontent.com
email=fwordplayground@gmail.com
```

This gives us the Access Token we need to solve the challenge.
```json
{
    "access_token": "ya29.a0ARrdaM9n2idPYv8nnNVnR5gqL_T47o0Q0XKYvIbB8IEzgHo8Ykus3fi2K5vc5A0xMU_liwsiFVEAJQKbQrxEIMAXTRO2HYUG_aNFu9NhmZQwQTH-v4-rxQ3qP7XowFYTCzyXf7cfj-E8q-TGZ-y_uW9JONuMQA",
    "expires_in": 3599,
    "scope": "https://www.googleapis.com/auth/gmail.readonly",
    "token_type": "Bearer"
}
```

Now we can send a GET request to `https://gmail.googleapis.com/gmail/v1/users/{userId}/messages/` in order to get the ID of the the messages in the user's mailbox, specifying the userId (`fwordplayground@gmail.com`) and using the token retrieved before.

```json
{
  "messages": [
    {
      "id": "17b896f6726974e0",
      "threadId": "17b896f6726974e0"
    },
    {
      "id": "17b88c3eac07ae5e",
      "threadId": "17b88c3eac07ae5e"
    },
    {
      "id": "17b87ba8cb2223ae",
      "threadId": "17b87ba8cb2223ae"
    },
    {
      "id": "17b87ba704382ed8",
      "threadId": "17b87ba704382ed8"
    },
    {
      "id": "17b7e34d7c2c32ab",
      "threadId": "17b7e34d7c2c32ab"
    },
    {
      "id": "17b7e18804f074a3",
      "threadId": "17b7e18804f074a3"
    },
    {
      "id": "17b7e09ebbf28050",
      "threadId": "17b7e09ebbf28050"
    },
    {
      "id": "17b7da2b72dab49b",
      "threadId": "17b7da203f30dacd"
    },
    {
      "id": "17b7da27c90003dc",
      "threadId": "17b7da27c90003dc"
    },
    {
      "id": "17b7da203f30dacd",
      "threadId": "17b7da203f30dacd"
    },
    {
      "id": "17b7d91845068c5e",
      "threadId": "17b7d91845068c5e"
    },
    {
      "id": "17b7d90a62a92cf7",
      "threadId": "17b7d90a62a92cf7"
    },
    {
      "id": "17b7d8fc93407e79",
      "threadId": "17b7d8fc93407e79"
    },
    {
      "id": "17b7d8ea201ede87",
      "threadId": "17b7d8d5f2e72c65"
    },
    {
      "id": "17b7d8dd6b16b6a1",
      "threadId": "17b7d8d5f2e72c65"
    },
    {
      "id": "17b7d8d5f2e72c65",
      "threadId": "17b7d8d5f2e72c65"
    },
    {
      "id": "17b7d8c607a05e7e",
      "threadId": "17b7d8c607a05e7e"
    },
    {
      "id": "17b7d85d21fc05ba",
      "threadId": "17b7d85d21fc05ba"
    },
    {
      "id": "17b7d762e4b0777e",
      "threadId": "17b7d762e4b0777e"
    }
  ],
  "resultSizeEstimate": 19
}
```


We can now list each message by querying `https://gmail.googleapis.com/gmail/v1/users/{userId}/messages/{id}`.

The flag is found in email ID 17b7d85d21fc05ba:

`FwordCTF{email_forensics_is_interesting_73489nn7n4891}`
