---
layout: post
title: "NiteCTF 2021 - Mailman 1 [OSINT]"
categories: ctf
tags: r1p nitectf osint ctf
date: 2021-12-12 13:00:00 +0200
author: r1p
---

### Challenge description

> Our CTO takes Git commits quite seriously. Someone in our discord channel got an email from him. Now the person wants a similar email signature like the CTO of our company, so he decided to make an email signature of his own and commit it securely. Find the account's mail and wrap it with nite{} for the flag

Searching on the Discord server of CryptoNite, we can find the user replierNite#1887, with a Github account linked: [https://github.com/replierNite](https://github.com/replierNite) and a repo: [https://github.com/replierNite/replierNite](https://github.com/replierNite/replierNite)

Some information regarding the repo.

-   4 different commits made on October 11 2021, 6 additions and 3 deletions.
-   Latest commit contains a ZIP file, according to the Discord's OSINT channel, it won't require any kind of bruteforce.
-   Found a noreply mail linked to the account, it won't work as the flag: 88324251+replierNite@users.noreply.github.com
-   ReplierNite's pushes have been signed by GitHub using the vigilant mode: GPG key ID: 4AEE18F83AFDEB23.
-   There is one single branch (main).
-   There are a few forks forks from several users, all being done **after** the CTF started, so it's most likely nothing important: [https://github.com/replierNite/replierNite/network](https://github.com/replierNite/replierNite/network).

```
$ git log

(Latest) commit 51cb7ec52694e9d3f954f4052d712e5aa29811c1 (HEAD -> main, origin/main, origin/HEAD)
Author: replierNite <88324251+replierNite@users.noreply.github.com>
Date:   Mon Oct 11 15:57:24 2021 +0530

    Masterpiece

NOTE: confidential.zip was pushed on this commit.
    
-------------------------------------------------------------------

commit e57696c3eb8ba633b8aefcd3e403ccaede301500
Author: replierNite <88324251+replierNite@users.noreply.github.com>
Date:   Mon Oct 11 15:40:29 2021 +0530

    This will be of some help

NOTE: README.md contains the following:
👋 Hi, I’m @replierNite
📫 Email me and youll get my signature!
💡 Currently writing meaningful git commits because my CTO says so.
    
-------------------------------------------------------------------

commit fdf0feaf42dd7fac90a81382842a03a395273c39
Author: replierNite <88324251+replierNite@users.noreply.github.com>
Date:   Mon Oct 11 15:37:57 2021 +0530

    Minor edits

NOTE: README.md contains the following:
👋 Hi, I’m @replierNite
📫 How to reach me (I am almost done with the sign)

-------------------------------------------------------------------

(First) commit 5e5d596f0681767c9e85531b2acb75c7313a590b
Author: replierNite <88324251+replierNite@users.noreply.github.com>
Date:   Mon Oct 11 15:37:16 2021 +0530

    Create README.md

NOTE: README.md contains the following:
👋 Hi, I’m @replierNite
📫 How to reach me WIP (Im creating an email signature)

-------------------------------------------------------------------

$ git log --stat -M
commit 51cb7ec52694e9d3f954f4052d712e5aa29811c1 (HEAD -> main, origin/main, origin/HEAD)
Author: replierNite <88324251+replierNite@users.noreply.github.com>
Date:   Mon Oct 11 15:57:24 2021 +0530

    Masterpiece

 confidential.zip | Bin 0 -> 44252 bytes
 1 file changed, 0 insertions(+), 0 deletions(-)

commit e57696c3eb8ba633b8aefcd3e403ccaede301500
Author: replierNite <88324251+replierNite@users.noreply.github.com>
Date:   Mon Oct 11 15:40:29 2021 +0530

    This will be of some help

 README.md | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

commit fdf0feaf42dd7fac90a81382842a03a395273c39
Author: replierNite <88324251+replierNite@users.noreply.github.com>
Date:   Mon Oct 11 15:37:57 2021 +0530

    Minor edits

 README.md | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

commit 5e5d596f0681767c9e85531b2acb75c7313a590b
Author: replierNite <88324251+replierNite@users.noreply.github.com>
Date:   Mon Oct 11 15:37:16 2021 +0530

    Create README.md

 README.md | 3 +++
 1 file changed, 3 insertions(+)

-------------------------------------------------------------------

$ git rev-list --objects --all
51cb7ec52694e9d3f954f4052d712e5aa29811c1
e57696c3eb8ba633b8aefcd3e403ccaede301500
fdf0feaf42dd7fac90a81382842a03a395273c39
5e5d596f0681767c9e85531b2acb75c7313a590b
1101d0f311543031377f222b0cd41c52ef8abb41 
6d659bc0c3cf6ffbc533e4d9b198e2d719a281b1 README.md
612b1e4a5d1cc38642bab269f62dce7f029d6348 confidential.zip
80c85517191c258879ed7051cb264b83843533a3 
788ed8e415e5168d88be209416dad93cc5f1ad36 
aac42d20c26ab18136d565256b315724ed32e7ed README.md
5d40058d7fb68077b506619639c4941e76a3970d 
bee95131045834eac2d53d13190446c21b86d997 README.md
```

## Solution

You can `7z x` the `confidential.zip` file with the hash of the previous commit as the password: e57696c3eb8ba633b8aefcd3e403ccaede301500

![](https://blog.alex.sc/content/images/2021/12/imagen.png)![](https://blog.alex.sc/content/images/2021/12/imagen-1.png)

Flag is: nite{reply.nite@gmail.com}
