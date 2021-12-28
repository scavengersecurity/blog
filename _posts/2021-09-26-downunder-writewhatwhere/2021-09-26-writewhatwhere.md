---
layout: post
title: "DownUnderCTF 2021 - Write What Where [Pwn]"
categories: ctf
tags: partial-relro pwn ikerl
date: 2021-09-26 20:58:00 +0200
author: ikerl
---

`Write What Where` is an easy pwn challenge with 70 solves. We get an x64 executable and a libc shared library. The description of the challenge is the following:

```
You've got one write. What do you do?
```

This is the program's source obtained with Ghidra's decompiler:

```c
{
  int ptr2write;
  long in_FS_OFFSET;
  undefined4 user_what;
  char user_where [24];
  undefined8 local_10;

  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  init(param_1);
  puts("write");
  puts("what?");
  read(0,&user_what,4);
  puts("where?");
  read(0,user_where,9);
  ptr2write = atoi(user_where);
  *(undefined4 *)(long)ptr2write = user_what;
                    
  exit(0);
}
```

The program is compiled without PIE nor Full RELRO and allows us to perform an arbitrary write once.

These are the steps we followed to solve the challenge:

1. **Bypass the one-time write restriction:** since the binary is compiled without protections we can overwrite the `exit` GOT entry with the address of `main` to get unlimited writes.
2. **Overwrite `atoi` to get system execution**: the `atoi` function has already been used before so the GOT entry will contain `atoi`'s address in libc. By overwriting the last three bytes of the original address with those of the `system` function's address, we will get code execution when calling `atoi`.
3. **Bruteforce to bypass ASLR**: the last step is to launch the exploit many times until the bytes we have overwritten match the real address of `system` function. We will have to guess 12 bits so we will have a probability of 1 out of 4096 trials.

As soon as we succeed we will have code execution and we will be able to read the flag. The full exploit is available [here](https://gist.github.com/ikerl/5c775c460b7a15351e500585c93bd7dd).

Flag: `DUCTF{arb1tr4ry_wr1t3_1s_str0ng_www}` 
