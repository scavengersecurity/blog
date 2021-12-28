---
layout: post
title: "RedPwn CTF 2021 - simultaneity [Pwn]"
tags: pwn ikerl hooks one_gadget
date: 2021-07-21 19:00:00 UTC
author: ikerl
---

Simultaneity is a pwn challenge from RedpwnCTF 2021. We are provided a 64-bit Linux ELF. If we check the binary's memory protection, we notice that it has full RELRO, PIE and NX protections enabled. Because of full RELRO the GOT overwrite technique is not possible, and we need a memory leak to bypass full address randomization.

```
$ checksec simultaneity
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

We decompile the executable with Ghidra and look at the output:

```c
void main(void)

{
  long in_FS_OFFSET;
  size_t size;
  void *ptr;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  puts("how big?");
  __isoc99_scanf("%ld",&size);
  ptr = malloc(size);
  printf("you are here: %p\n",ptr);
  puts("how far?");
  __isoc99_scanf("%ld",&size);
  puts("what?");
  __isoc99_scanf("%zu",(void *)((long)ptr + size * 8));
                    /* WARNING: Subroutine does not return */
  _exit(0);
}
```

The program asks for three inputs from the user. The first input is a size passed to `malloc`, and the second one is used to determine the address where the third input will be stored (as an offset from the allocated heap memory). The vulnerability is the third `scanf` call, as we can obtain an arbitrary write using the second input.

```c
__isoc88_scanf("%zu",(void *)((long)ptr + size*8))
```

Controlling the size passed to `malloc` and knowing the allocation's base address we can calculate the address to overwrite:

```
address_to_overwrite = leak + size * 8
```

As previously mentioned, the binary is compiled with full RELRO, so the GOT overwrite approach is not possible. Alternatively, we can overwrite `__malloc_hook` or `__free_hook` to change the execution flow when `free` or `malloc` are called.

We noticed that we can bypass address randomization simply by allocating a considerable size of bytes. Doing this we will obtain a libc address instead of a heap address. 

```
how big?
10
you are here: 0x557f6fa6e6b0
```

```
how big?
274432
you are here: 0x7fcbd411b010
```

Now, we can calculate the base address of libc and we are ready to predict any address in the libc section. Using the `one_gadget` tool, we obtain three single-jump ROP gadgets:

```
$ one_gadget libc.so.6
0x4484f execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x448a3 execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xe5456 execve("/bin/sh", rsp+0x60, environ)
constraints:
  [rsp+0x60] == NULL
```

Through trial and error, we found that the gadget at `0x448a3` works. Since our approach in this case is to overwrite `__free_hook` with the absolute address for our gadget, we must force the program to call `free` at some point. There are no direct calls to `free` in the decompiled source, so we must find another way.

The best approach is to look for a call to `free` in some of the used libc functions; in this case, we used `scanf`. If we input a string long enough, `scanf` will call `malloc` and `free` internally. To achieve this, we will left-pad our third input with zeroes, increasing the input length without altering the final number. The full exploit code is available [here](https://gist.github.com/ikerl/d76ff0e5ef0510f7314628b0852195d1).

```
flag{sc4nf_i3_4_h34p_ch4l13ng3_TKRs8b1DRlN1hoLJ}
```
