---
layout: post
title: "ångstromCTF 2022 - Dreams [Pwn]"
categories: ctf
tags: heap tcache pwn 00xc
date: 2022-05-08 16:20:00 +0100
author: 00xc
---

Dreams was an exploitation challenge from ångstromCTF 2022. We are given an ELF binary and a glibc shared object, version 2.31.

```
$ checksec ./dreams
	Arch:     amd64-64-little
	RELRO:    Full RELRO
	Stack:    Canary found
	NX:       NX enabled
	PIE:      No PIE (0x400000)
```

When ran, the program gives the user 3 options:

```
$ ./dreams 
Welcome to the dream tracker.
Sleep is where the deepest desires and most pushed-aside feelings of humankind are brought out.
Confide a month of your time.
----- MENU -----
1. Sleep
2. Sell
3. Visit a psychiatrist
> 
```

## Reverse engineering ##

The binary itself is quite simple. If we look at it in Ghidra, we see the following decompiled output after correcting type information:

```c
void main()
{

	/* ... */
	dreams = (dream_t **)malloc((long)(MAX_DREAMS << 3));
	/* ... */
	opt = 0;
	while (true) {
		while (true) {
			menu();
			printf("> ");
			__isoc99_scanf("%d",&opt);
			getchar();
			if (opt != 3) break;
			psychiatrist();
		}
		if (3 < opt) break;
		if (opt == 1) {
			gosleep();
		}
		else {
			if (opt != 2) break;
			sell();
		}
	}
	puts("Invalid input!");
	exit(1);
```

Here `dream_t` is just a user-added structure with the following layout:

```c
typedef struct {
	char date[8];
	char about[20];
} dream_t;
```

`dreams` is an array of MAX_DREAMS pointers to `dream_t` structures. MAX_DREAMS is a global variable set to 5. The three options shown in the menu correspond to the `gosleep()`, `sell()` and `psychiatrist()` functions.

- `gosleep()` allocates a new structure and copies the pointer to `dreams[i]`. `i` is user-controlled and bounds-checked. The pointer at `dreams[i]` must be NULL beforehand. The structure fields are also initialized with user-controlled values, but `dream->date` is terminated with a null byte. 
- `sell()` frees the pointer at `dreams[i]`, `i` being again user-controlled and bounds-checked.
- `psychiatrist()` first prints the `about` field of the structre at `dreams[i]`, and then allows the user to overwrite the `date` field. `i` is again user-controlled, but not bounds-checked.

Since `sell()` does not set pointers to NULL after freeing them, and `gosleep()` will only use slots that are set to NULL, 
we can only do MAX_DREAMS allocations.

## Exploitation ## 

Due to several flaws in the program, we are able to do the following:

- We can attempt to double free the same pointer. Since we are using glibc 2.31, tcache protection will not allow us to do this easily.
- We can use-after-free read/write to structures with `psychiatrist()`, as the pointers in `dreams` are not set to NULL after being freed. We have to do both a read and a write due to how that function works.
- We can read/write out of bounds with `psychiatrist()`, since `i` is not bounds-checked, but again we have to do both.

In order to get execution, our plan is to use our ability to read and write out of bounds to overwrite `__free_hook` with a pointer to the `system()` function. Once this is done, we can free a structure containing a string like `/bin/sh` to get a shell.

### Heap exploitation theory ###

Since we are going to target the heap allocator here by use-after-freeing memory chunks, we need to understand it works. Since in glibc 2.31, tcache is used. Without tcache, a heap chunk has the following layout ([malloc/malloc.c:1048](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L1048)):

```c
struct malloc_chunk {
	INTERNAL_SIZE_T mchunk_prev_size;  /* Size of previous chunk (if free).  */
	INTERNAL_SIZE_T mchunk_size;       /* Size in bytes, including overhead. */

	struct malloc_chunk* fd;         /* double links -- used only if free. */
	struct malloc_chunk* bk;

	/* Only used for large blocks: pointer to next larger size.  */
	struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
	struct malloc_chunk* bk_nextsize;
}
```

Once a chunk of memory, previously returned by malloc, is freed, the fields of `malloc_chunk` will be written over the old user data. More precisely, `fd` will be written right at the beginning of the chunk, meaning the two previous fields are placed *before* the pointer that was given to the user. In fact, those two previous fields are set when the chunk is created.

However, with tcache enabled, the following structure is used ([malloc/malloc.c:2892](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L2892)):

```c
/* We overlay this structure on the user-data portion of a chunk when the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  struct tcache_perthread_struct *key;
} tcache_entry;
```

Meaning the actual `malloc_chunk` structure looks like this:

```c
struct malloc_chunk {
	INTERNAL_SIZE_T mchunk_prev_size;
	INTERNAL_SIZE_T mchunk_size;

	struct tcache_entry *next;  // <------- user pointer (old fd)
	struct tcache_perthread_struct *key;

	struct malloc_chunk* fd_nextsize;
	struct malloc_chunk* bk_nextsize;
}
```

When a chunk is freed, the `key` field will have a pointer to the tcache structure itself ([malloc/malloc.c:2924](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L2924)):

```c
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
	tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

	/* Mark this chunk as "in the tcache" so the test in _int_free will
	 detect a double free.  */
	e->key = tcache;

	e->next = tcache->entries[tc_idx];
	tcache->entries[tc_idx] = e;
	++(tcache->counts[tc_idx]);
}
```

This field is checked before freeing a chunk, which is why we can't just do a double free ([malloc/malloc.c:4193](https://elixir.bootlin.com/glibc/glibc-2.31/source/malloc/malloc.c#L4193)):

```c
static void
_int_free (mstate av, mchunkptr p, int have_lock)
{
	/* ... */
	if (__glibc_unlikely (e->key == tcache))
	{
		if ( /* ... */)
			malloc_printerr ("free(): double free detected in tcache 2");
	/* ... */
```

Keep in mind now that, once we free a structure, the `chunk->next` field will be written over the `dream->date` field, and `chunk->key` will be readable through the `dream->about` field.

### Arbitrary write primitive ###

To get a write primitive, we need to perform a tcache poisoning attack. The idea here is to confuse the allocator into returning through `malloc()` a pointer to an area we want to write to.

To do this, we will abuse the `chunk->next` field, which points to the next free chunk. Thus, we can allocate a chunk, free it, overwrite it's `next` field with `psychiatrist()` to the address we want to write to, and then attempt to allocate a new chunk, which should return our desired pointer.

Apparently we will actually need to create two chunks, free them both and poison one of them, [since there need to be enough entries in the tcache](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/tcache_poisoning.c#L15).

### Heap pointer leak ###

We need a heap leak to find out where `dreams` resides. Once we have this, reading/writing with an out of bounds `i` in `dreams[i]` becomes much easier.

As seen before, the `chunk->key` field overlaps with `dream->about`, which can be read with `psychiatrist()`. We just need to allocate a structure, free it and read it to get the pointer to glibc's tcache.

We found that the tcache structre is 0x10 bytes above the heap base, so substracting 16 to this pointer gets us the heap base. Adding 0x2a0 to the heap base should get us the address of `dreams`.

### (Semi)arbitrary read primitive ###

To get reads we can abuse the `psychiatrist()` function with an out of bounds `i`. We won't be able to read at `dreams[i]`, but rather at wherever the pointer at `dreams[i]` points to (`dreams` is an array of pointers).

There is a complicated way in which we can get a truly arbitrary read: we can place the address we actually want to read at in a `dream_t` structure, and then have `dreams[i]` point to that structure, which in turn contains the desired pointer.

However, this won't be necessary, as we just need this primitive to get a libc pointer leak (explained below).

### libc pointer leak ###

In order to get a libc leak without the complicated setup mentioned above, we need a pointer to something which itself contains a pointer to libc, so we can read from it with the technique explained above. Thankfully, there's a great candidate in the .bss section: `stdout`.

```
(gdb) info address stdout
Symbol "stdout" is static storage at address 0x404018.
(gdb) x/1a 0x404018
0x404018 <stdout@@GLIBC_2.2.5>: 0x7f8ccea706a0 <_IO_2_1_stdout_>
(gdb) x/2a 0x7f8ccea706a0
0x7f8ccea706a0 <_IO_2_1_stdout_>:       0xfbad2887      0x7f8ccea70723 <_IO_2_1_stdout_+131>
(gdb)
```

Therefore, we can use `psychiatrist()` to read at `0x404018` to get the libc leak (`0x7f8ccea70723` above), and from there the libc base address. We will also need to preserve that first value (`0xfbad2887`) when doing the write required by the function.

### Exploitation steps ###

Once we have our desired primitives, we can formulate an exploit:

1. Use our write primitive detailed above to overwrite the MAX_DREAMS variable, as we will need more allocations for the next steps. There is no PIE (thus no ASLR is used), meaning that we can just plug in the address of the global variable.
2. Get a heap pointer leak to enable our read primitive.
3. Use our read primitive to get libc's base address. Knowing where `dreams` is and where `stdout` is, we can calculate an adequate value for `i` in `dreams[i]`.
4. Use our write primitive to overwrite `__free_hook` in libc to point to the `system()` function, also in libc. Now, the next time we free a structure, the contents of that structure will be passed to `system()`, giving us code execution.

You can find our full exploit [here](https://gist.github.com/00xc/8645bc43757e6232026e6ee7e5ddfbbd).

```
$ python3 solve.py 
[+] Opening connection to challs.actf.co on port 31227: Done
> heap_base: 0x164f000
> libc base: 0x7fd24c137000
> system@libc = 0x7fd24c1892c0
> __free_hook@libc = 0x7fd24c325e48
[*] Switching to interactive mode
$ ls
flag.txt
run
$ cat flag.txt
actf{hav3_you_4ny_dreams_y0u'd_like_to_s3ll?_cb72f5211336}
```
