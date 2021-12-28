---
layout: post
title: "2020 Metasploit Community CTF - 6 of Diamonds (port 8200) [Web]"
categories: ctf
tags: ctf file_upload web
date: 2020-12-14 18:00:00 +0100
author: ikerl
---

This challenge is a web application where images can be uploaded and then be viewed in an image gallery.

![[photos-768x255.jpg]]

The only checks that are made when uploading the images are the extension check and the MIME metadata. So, if we inject PHP code into a file with the `.png.php` extension, and we add the header of a valid image, we will be able to bypass all checks and execute PHP code.

![[payload_metasploit2020.jpg]]

Once we upload this manipulated image we can easily execute command simply by passing the command to be executed in the “cmd” GET parameter.

![[metasploit2020_rce.jpg]]

Exploring the web server files we found that there is a strange directory with a long random name. Accessing it reveals the flag.

![[metasploit2020_searching_card.jpg]]

![[metasploit2020_6_of_diamonds.jpg]]