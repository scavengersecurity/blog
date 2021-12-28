---
layout: post
title: "NiteCTF 2021 - gachiHYPER [OSINT]"
categories: ctf
tags: 0xKn nitectf osint ctf
date: 2021-12-12 13:00:00 +0200
author: 0xKn
---

![](https://blog.maite.sc/content/images/2021/12/image-5.png)

> This user called timehowls on reddit was really rude to me. Can you osint him and find some sensitive information about him?

The first thing they give us is a reddit username so we go to reddit and notice that they have a comment about a discord server.

![](https://blog.maite.sc/content/images/2021/12/Imagen2.png)

The reddit comment tells us that he just joined, so we can deduce that he joined the discord server on the 29th. We check the _welcome logs_ and indeed he is there but he has changed his name.

![](https://blog.maite.sc/content/images/2021/12/Imagen3.png)

Looking at his User ID we can find out his new name

![](https://blog.maite.sc/content/images/2021/12/Screenshot_2.jpg)

At this point we can see that the user **clockcroissant** has both **twitch** and **twitter**.His twitch is empty but his twitter has some interesting information. I found the following messages that give us quite a few clues:

> I love watching twitch 12 hours a day and rest of the time I mod on discord

> I LOVE YOUR STREAMSSSS

![](https://blog.maite.sc/content/images/2021/12/Imagen5.png)![](https://blog.maite.sc/content/images/2021/12/Imagen6.png)

The challenge tells us that we have to find sensitive information, so maybe he wrote something useful in some stream.Wolfabelle has quite a few videos so we first look at the date Clockcroissant joined twitch and then download the chats of all the videos since that date.

![](https://blog.maite.sc/content/images/2021/12/Imagen7.png)![](https://blog.maite.sc/content/images/2021/12/Imagen8.png)

At first it seems that there is nothing relevant, but if we think about it, he may have said something sensitive but it has been deleted. Finally, through the following URL we can get all the conversation that had been deleted.

> [https://logs.ivr.fi/?channel=wolfabelle&username=clockcroissant](https://logs.ivr.fi/?channel=wolfabelle&username=clockcroissant)

![](https://blog.maite.sc/content/images/2021/12/image.png)

So, we get the flag :)

![](https://blog.maite.sc/content/images/2021/12/Imagen10.png)

`snite{d0nt_s1mp_fOr_3g1rl5}`
