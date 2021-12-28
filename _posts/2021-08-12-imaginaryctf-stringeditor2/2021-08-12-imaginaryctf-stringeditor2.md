---
layout: post
title: "Imaginary CTF 2021 - String Editor 2 [Pwn]"
categories: ctf
tags: pwn got ikerl
date: 2021-08-12 19:20:00 +0100
author: ikerl
---

String Editor 2 is a pwn challenge from ImaginaryCTF 2021. We are given a compiled executable and the target server's libc. The program is a very simple string editor that allows us to edit a 15 character string.

If we check its memory protections we notice that PIE, Full RELRO and the stack canary are disabled.

```
$ checksec string_editor_2
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Executing the program we see the following output:

```
Welcome to StringEditor™!
Today, you will have the AMAZING opportunity to edit a string!
But first, a word from our sponsors: 0x7fffff6c6f6c

Here ya go! Your string is:
***************
What character would you like to edit? (enter in 15 to see utils)
15
1. Admire your string
2. Delete your string
3. Exit
```

The string is initialized with the characters `***************`, and we can edit any character in this string, selecting a position and overwriting it with our value.
In addition, we can 'admire' (print) or delete the string (reset it with initial value). 

Decompiling the executable's main function we obtain the following:

```c
void main(void)

{
  long in_FS_OFFSET;
  undefined8 uVar1;
  undefined value;
  long target_offset;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  strcpy(target,"***************");
  puts(&DAT_00400a08);
  puts("Today, you will have the AMAZING opportunity to edit a string!");
  uVar1 = 0x4007c4;
  sleep(1);
  printf("But first, a word from our sponsors: 0x%x%x%x%x%x%x\n\n",0x7f,0xff,0xff,0x6c,0x6f,0x6c,
         uVar1);
  do {
    while( true ) {
      while( true ) {
        while( true ) {
          puts("Here ya go! Your string is:");
          puts(target);
          puts("What character would you like to edit? (enter in 15 to see utils)");
          __isoc99_scanf("%ld%*c",&target_offset);
          if (0xf < target_offset) {
            puts("Go away hacker.");
            exit(-1);
          }
          if (target_offset == 0xf) break;
          puts("What character should be in that index?");
          __isoc99_scanf("%c%*c",&value);
          target[target_offset] = value;
          puts("Done.");
        }
        puts("1. Admire your string");
        puts("2. Delete your string");
        puts("3. Exit");
        __isoc99_scanf("%ld%*c",&target_offset);
        if (target_offset != 1) break;
        admire();
      }
      if (target_offset != 2) break;
      del();
    }
  } while (target_offset != 3);
  exit(0);
}
```

The program is not vulnerable against a stack buffer overflow vulnerability, because all memory copies and moves with the user's input are properly handled. However, we found a vulnerability on this condition:

```c
puts("What character would you like to edit? (enter in 15 to see utils)");
__isoc99_scanf("%ld%*c",&target_offset);
if (0xf < target_offset) 
{
    puts("Go away hacker.");
    exit(-1);
}
```

The program does input validation when the user selects a character to overwrite. If that value exceeds the string's length, the program will exit inmediatly, displaying an error message. If, instead of introducing a positive value, we introduce a negative one, we are able to bypass the check, and therefore we can modify values in any address lower than `target`'s. This means we can perform a Global Offset Table (GOT) overwrite attack to modify any function pointer.

At this point, our plan is to bypass ASLR; this allows us to resolve the addresses of libc's functions. Once this is done, we can place arbritrary libc functions' addresses in the GOT. This results in our placed function being called when the original function, corresponding to the overwritten entry, is called.

We noticed that `strcpy` gets passed, as a first parameter, our controlled 15 character string. We can, then, place the string `%1$p` in our string, overwrite the GOT entry for `strcpy` with the address of `printf`, and force the program to call `del()`, which will leak the 1st 8-byte value from the stack.

```c
void del(void)
{
  strcpy(target,"***************");
  return;
}
```

By trying with different stack offsets (`%2$p`, `%3$p`, etc.), we found a libc pointer at offset at offset 12. With our leak, we can resolve libc's base address, and therefore the address of any of its functions.

With the `one_gadget` tool we obtain three options to call execve and obtain a shell:

```
0xe6c7e execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe6c81 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe6c84 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```

We found that the third option works best. We overwrite `exit`'s GOT entry, and force the program to call it in order to get command execution. In summary, our exploit consists of the following steps:

1. Prepare the `target` string with `%12$p%13$p%14$p`.
2. Overwrite `strcpy` to point to `printf`.
3. Call `strcpy` to execute `printf("%12$p%13$p%14$p")` and obtain a libc leak.
4. Calculate the address of `one_gadget`'s third option.
5. Overwrite `exit` with the computed address.
6. Call `exit` to spawn a shell.

The full exploit is available [here](https://gist.github.com/ikerl/c874fecb42dcc3fdb6afc0d55ed9c63a).

`ictf{g0t_0v3rwr1te?????????????????????????_953a20b1}`
