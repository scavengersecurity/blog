---
layout: post
title: "2020 Metasploit Community CTF – 8 of Spades (port 1080) [Networks]"
categories: ctf
tags: r1p msctf metasploit-ctf networks ctf
date: 2020-12-08 21:00:00 +0200
author: r1p
---

Port 1080 shows a SOCKS 5 service running.

![](https://lh3.googleusercontent.com/3p1ZrSe-J3fjI0_qCBRV9F3oZZhgIEYxiMFwS0K9fkkv_8V_nbrTi2Lq8jms9qUetLupE23C5GbjUyW7pnI7ppPE25qI3d2gSUcSkxvyqPLXwteO9VMtJVi9f5bMvc8GMyb3rkii)

We tried establishing a connection through this service, but upon failure we thought it was a false positive brought by the default nmap scripts, so we configured a `proxychains` route using SOCKS 4.

![](https://lh4.googleusercontent.com/EEIEMaVvu_A1uJgEeX8EeZoL8UijsqvuFqlYV01ORFUmLRP9PLx9oVFgz6RsG5RQwGQ9Nm15hi9on8VhuZjXQs7xKjzswF2pBZccl4VdHoktrKu3poUfXvfpuPTmLGzNEUvXeY1O)

Scanning the network with the socks proxy already set, a new port 8080 was found with a web server running on it. Using `cURL`, a file could be seen in the source code, the one needed to complete the 8 of Spades challenge.

![](https://lh4.googleusercontent.com/v_ylJ8vWzNyHRY6CaPptybyrQqZwHWnEdYlnu5Xfqxp6RfWFXibUq_Eft4Cd51CQeyMwZLIhunOqN4_UnTFkbk5k2SSJuCg2per9TNlYKgAFDypdBXxUoSk-wpCrfdWTIaz6OGZQ)

We could now `wget` it and retrieve the md5 hash of the image.

![](https://lh6.googleusercontent.com/rs7S_6j3q9y88JEbn7KmuEpK6tOofowJhI9yWx6ZKL3nEXV_bWbOtgrI4nFDCncDA7BKNkTzujZLRlOzJIT5XMjIOxUOf9YgQHFj6_xuYYvDK-YWjqruNejsjyHeTX3L2I7HLbZe)![](https://rushisec.net/content/images/2020/12/8_of_spades.png)
