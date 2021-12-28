---
layout: post
title: "2020 Metasploit Community CTF – Queen of Spades (port 8202) [Web]"
categories: ctf
tags: r1p web writeup msctf metasploit-ctf graphql ctf
date: 2020-12-08 21:00:00 +0200
author: r1p
---

Port 8202 hosts a web application with a single login form. Trying to login with random credentials, we observed that it calls a GraphQL API to authenticate against the remote server.

![](https://lh5.googleusercontent.com/2bLpjFCsIa7lTusLzl2ML2LMhH0OuqDvPuWv3GjfbXB-0MCl2j7H4t0tvJi1jhKxnuHbdRkbKiyaK9GYlAFPKFURANylAai9qWxfM69I8u2HNZHpZsWALD2N0k85Vee41VXF2b9G)

With the following payload we can dump the database schema and take a look at it:`{__schema{types{name,fields{name, args{name,description,type{name, kind, ofType{name, kind}}}}}}}`

![](https://lh4.googleusercontent.com/2v6g0dtfzbttx7TFu7bnGFSPN0sPCrhcZF_3P_F492RZowicRcIyUb45gQYmcimOnR-FGJFszRLQEdIVeBomSsJioU3wE7c4uUKdI2uNf4k69hiWDgi5fr_U1D4ULsCsuZ9vnSIh)

Investigating the response, we found an object called `userCreate`.

![](https://lh6.googleusercontent.com/iVBSVpx-YQ9GLcSh3udftQUqdAu_YkyotCKdlEPqBXDTpNAADQFOfJuqXXob0XEa2VE58Hq7SftZE64URmGo2p_2InDf4nz1CEV__m003VyEb14o54ulUx_rLhOwcPA5htOe0zNS)

By crafting a new query, after modifying the original log-in payload, we ended up creating a new user called `r1p` with password `1234abcd`.

![](https://lh5.googleusercontent.com/c3wsyUsPcO3yfnvNu7wmLY8xCOFo7w2AS4hv6rZGiYprjUahCjPZLrjl2uELvmZDCWeXKAIoXdD9WBByJsNdZjd8yUW3ftYzFPH2_SUkQmf7tJ7sNVluIIOl7mg6sgLj5U2WHbL_)

The next step was to log in with said credentials and retrieve the flag.

![](https://lh6.googleusercontent.com/Mq2X7QML5m5krc8B2OrtAbCdTGf5QPdRVpaEHQT32l968vFsMpxYgRRRhrwPIufzOuSeq_4S2Y1FzhFWIHtlcc6IadZzcmBllQg_MLNuy7PdSqyLKvijaKEsti3FvCRv3icEgm4H)![](https://rushisec.net/content/images/2020/12/queen_of_spades.png)
