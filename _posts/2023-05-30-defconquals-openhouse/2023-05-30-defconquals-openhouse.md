---
layout: post
title: "DEF CON CTF Qualifier 2023 - Open House [Pwn]"
categories: ctf
tags: pwn ikerl
date: 2023-05-30 8:00:00 +0100
author: ikerl
---

his year, we participated in DEF CON Quals CTF as members of the Quanterland team. We spent the entire weekend working diligently on an open-house binary exploitation challenge, which had 68 solves. 

This particular challenge proved to be quite challenging and frustrating for me. However, we also gained valuable knowledge and insights, motivating us to write a write-up documenting my newfound understanding.

The challenge description is as follows:

```
You are cordially invited to an exclusive Open House event, where dreams meet reality and possibilities abound. Join us for an unforgettable experience as we showcase a captivating array of properties, each waiting to become your dream home.
```

## Introduction

The program is an x86 ELF review management program. By default, it contains 10 reviews but allows users to create new reviews or modify existing ones. 

Users can interact with the reviews database using the following commands:

- v: List existing reviews.
- c: Create a new review.
- d: Delete an existing review.
- m: Modify an existing review.
- q: Quit the program and exit.

Reviews are stored in a linked list in the heap. Each chunk has a length of 0x208 bytes and contains 0x200 for data, as well as a few extra bytes to store two pointers. The first pointer points to the start of the current chunk, and the second pointer points to the next chunk.

```
-------------------------------------------------------------------------------------------------------------------------
|review data (0x200 bytes) | pointer to review data of current chunk (4 bytes) | pointer to next review chunk (4 bytes) |
-------------------------------------------------------------------------------------------------------------------------
```

The program is built with PIE but does not include Stack Canary or Full Relro protection. It uses version 2.34 of the libc library.

## Vulnerabilities Found

After conducting a code review, we have identified the following security issues:

1. The review creation function has a vulnerability when handling the copy of user input into the data chunk. Although the program allows the user to send a review with a maximum length of 0x400 bytes, the `strncpy` function only saves the first 0x200 bytes. Consequently, if we send a review larger than 0x200 bytes, we can store a non-null byte-terminated review in the heap. Since the program stores heap pointers after the data, this vulnerability allows for easy leaking of heap pointers.

2. The review modification function permits the replacement of existing reviews with strings of up to 0x210 bytes in length. This means we can write beyond the boundaries of the review data section and overwrite the two pointers that follow. By controlling the first pointer, we can point to any address in memory, granting us arbitrary read and write capabilities.

## Arbitrary Read/Write and Leaking the Heap

By exploiting the previous vulnerabilities, we can successfully leak the heap pointers and gain arbitrary read and write capabilities. The following steps outline the process:

- Create a review that exceeds 0x200 bytes in length.
- Create an additional review.
- List the reviews to locate and retrieve our first review, thereby leaking the heap pointers located after the review data (specifically, the address of the chunk start and the pointer to the next chunk).
- Modify the review by overwriting it with a review that is 0x210 bytes in length. The last 0x10 bytes are utilized to overwrite the pointers of the chunk.
- At this point, we have successfully leaked the heap address and acquired the ability to read from and write to any address using the `v` (list reviews) and `m` (modify review) functionalities.

## Breaking ASLR

To successfully break ASLR, we followed these steps:

1. We deleted all reviews, created 8 new ones, and then deleted 7. This way, we filled the tcache and forced the new chunks to be saved as unsorted bins. As a result, pointers to libc appeared in the heap, allowing us to leak them.
2. We ran the program within a debugger and calculated the offset between the leaked libc address and the `tzname` symbol. We selected this symbol because it contains an address to a `GMT` string in the libc, making it easy to verify its correctness. We cross-referenced this symbol in the [blukat libc database](https://libc.blukat.me/) and confirmed that the used libc version was indeed a custom one.
3. Next, we calculated the offset between the `tzname` and `__libc_argv` symbols using a similar libc version. This symbol contains a stack leak, allowing us to read from and write to the stack successfully.
4. By reading some stack addresses, we eventually discovered the address of the binary's main function.

This particular phase of the process proved to be quite time-consuming due to the usage of a custom libc version, which caused many conventional techniques to fail.

At this point, we were able to calculate the binary's base address and overwrite entries within the GOT. However, this alone was not sufficient as the program did not utilize functions such as `system` or `execve`. Therefore, we needed to obtain the address of one of these functions in libc. Despite spending considerable time attempting to leak libc data to locate these functions, we decided to explore alternative methods.

One such approach involved dumping the libc memory to locate the ELF header. We successfully did this, but we could not use its offsets due to it being a custom build.

## Archieving Command Execution

At this point, we thought we were close, but the worst was yet to come. The use of a custom libc and the limited number of gadgets in the binary were frustrating all our plans.

There are likely many different ways to exploit this challenge, but we managed to succeed using the following primitives:

- Syscall gadget in the `alarm()` function: The program utilizes this function, so we can obtain its address from the GOT. The `alarm()` function calls the syscall instruction using `call DWORD PTR gs:0x10` (equivalent to `int 80`).

- Writing the `/bin/sh` string into memory (in our case we wrote it in the `.got` section but you can write it in the heap or in any other section).

- Searching the libc memory for a gadget that allows us to control the `eax` register. We found the following one:

```
\x89\xe8    mov eax,ebp
\x5b        pop ebx
\x5e        pop esi
\x5f        pop edi
\x5d        pop ebp
\xc3        ret
```

By calling this gadget twice, we can load any value into `ebp` and copy it to `eax`. Additionally, we can use this gadget to load values into the `ebx` register.

- Overwriting the return address on the stack: To perform a ROP attack, we calculated the offset of the return address of the main function on the stack. The ROP will run once the user quits the program.

## Putting it All Togheter 

Here is the final ROP chain we crafted to obtain the flag:

```
rop_payload = p43(gadget)+p32(SYS_execve)*4+p32(gadget)+p32(binsh)*4+p32(gadget_syscall)
```

- Load the value of `SYS_execve` (11) into the `eax` register.
- Load the pointer to the `/bin/sh` string into the `ebx` register.
- Jump to the `syscall` gadget to execute the `execve(/bin/sh)` system call.
- Read the flag.

After copying it to the return address of the stack and executing the ROP chain, we successfully obtained the flag:

```
c|v|m|d|q> $ q
Thanks for stopping by!
$ ls
challenge
flag.txt
run_challenge.sh
$ cat flag.txt
flag{PenthousePrice9345n23:REDACTED}
```