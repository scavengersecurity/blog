---
layout: post
title: "Codefest 2020 - tooeasy [Reversing]"
categories: ctf
tags: reversing unpacking 00xc
date: 2021-03-20 15:29:00 +0100
author: 00xc
---

tooeasy is a reversing challenge with 17 solves. The description reads:
> I mean lets get to basics, I have my tried to get in how real malware authors would hide there stuff but still this chall is tooeasy.

Going by the text, it seems that the binary uses some kind of malware technique to prevent debugging. It is an ELF binary, so we can run it under Linux. If we do so, it asks us for a flag:
```
$ ./tooeasy 
[*]Please give me flag
flag 
[*] This aint flag try again
```

If we load the binary in Ghidra to statically analyze it, the results are not pretty. The decompiled code seems too convoluted to analyze by hand. A good rule of thumb is to switch to dynamic analysis when static analysis becomes too complicated. In order to properly analyze the binary's behavior, we can launch it with `strace`:
```
$ strace -i -s64 -Xabbrev -y ./tooeasy
[00007f6f51cbca07] execve("./tooeasy", ["./tooeasy"], 0x7ffe2eaa3f60 /* 47 vars */) = 0
[000000000045298f] mmap(0x800000, 3038765, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, 0</dev/pts/1>, 0) = 0x800000
[0000000000852aa0] readlink("/proc/self/exe", "/home/carlos/codefest/tooeasy/tooeasy", 4096) = 37
[0000000000852af4] mmap(0x400000, 2981888, PROT_NONE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x400000
[0000000000852af4] mmap(0x400000, 855157, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x400000
[0000000000852af4] mprotect(0x400000, 855157, PROT_READ|PROT_EXEC) = 0
[0000000000852af4] mmap(0x6d1000, 21208, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0xd1000) = 0x6d1000
[0000000000852af4] mprotect(0x6d1000, 21208, PROT_READ|PROT_WRITE) = 0
[0000000000852af4] mmap(0x6d7000, 2592, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x6d7000
[000000000040000e] munmap(0x800000, 3038765) = 0
...
[0000000000449411] write(1</dev/pts/1>, "[*]Please give me flag\n", 23[*]Please give me flag
) = 23
[0000000000449133] fstat(0</dev/pts/1>, {st_mode=S_IFCHR|0600, st_rdev=makedev(0x88, 0x1), ...}) = 0
[000000000044933e] read(0</dev/pts/1>, flag
"flag\n", 1024) = 5
[0000000000448a51] nanosleep({tv_sec=5, tv_nsec=0}, 0x7ffc470b9c60) = 0
[0000000000449411] write(1</dev/pts/1>, "[*] This aint flag try again\n", 29[*] This aint flag try again
) = 29
...
```

It seems that the executable is going through some unpacking by mapping several memory regions and extracting itself (the author later revealed that it is a UPX binary). In order to view the final executable, we set a breakpoint at the call to `munmap`, right after all the unpacking is done. We can easily do this in gdb with `catch syscall unmap`, and then running the program:
```
$ gdb -q ./tooeasy
Reading symbols from ./tooeasy...(no debugging symbols found)...done.
(gdb) catch syscall munmap
Catchpoint 1 (syscall 'munmap' [11])
(gdb) run
...
Catchpoint 1 (call to syscall munmap), 0x000000000040000e in ?? ()
```

We can then dump the binary to disk. We chose to do this with the `dump` gdb command. In order for `dump` to work, we must specify the start and end address of the region we want to extract; these can be obtained from `/proc/<pid>/maps`. The process' PID can be retrieved by running `info inferiors` in gdb.
```
$ cat /proc/1688/maps 
00400000-004d1000 r-xp 00000000 00:00 0 
004d1000-006d1000 ---p 00000000 00:00 0 
006d1000-006d8000 rw-p 00000000 00:00 0                                  [heap]
00800000-00ae6000 rwxp 00000000 00:00 0 
7ffff7ffa000-7ffff7ffd000 r--p 00000000 00:00 0                          [vvar]
7ffff7ffd000-7ffff7fff000 r-xp 00000000 00:00 0                          [vdso]
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
```

We are only interested in the lower memory regions, where the code resides:
```
(gdb) dump binary memory out.bin 0x400000 0x06d8000
```

We can now load `out.bin` in Ghidra. The loaded binary only exports the `entry` function, which in turn takes us to the `main` function (`FUN_00400b8d`). After renaming some variables for clarity, this is the output for said function:
```c
int FUN_00400b8d(void) {
	int out;
	long len;
	long in_FS_OFFSET;
	uint i;
	char ok [18];
	char please [23];
	char buf [25];
	char fail [29];
	char input [104];
	long local_10;
	
	local_10 = *(in_FS_OFFSET + 0x28);
	/* ... */
	FUN_00410780(please);
	FUN_0040faa0("%s", input);
	FUN_004489d0(5);
	len = FUN_004004e0(input);
	if (len == 0x18) {
		i = 1;
		while (i < 0x19) {
			if ((input[i - 1] ^ i) != buf[i - 1]) {
				FUN_00410780(fail);
				out = 1;
				goto LAB_00400efa;
			}
			i = i + 1;
		}
		FUN_00410780(ok);
		out = 0;
	} else {
		FUN_00410780(fail);
		out = 1;
	}

LAB_00400efa:
	if (local_10 != *(in_FS_OFFSET + 0x28)) {
		/* WARNING: Subroutine does not return */
		FUN_0044b9b0();
	}
	return out;
}
```

The variables `please`, `fail` and `ok` contain the strings displayed at program startup, incorrect and correct input respectively, and have been omitted for brevity. `buf` contains what seem to be random characters. Given `FUN_0040faa0`'s arguments, it looks like it reads data from stdin and writes it to `input`, much like `scanf`. It also seems that `FUN_004004e0` returns the length of the string passed to it. `FUN_004489d0` corresponds to the `nanosleep` observed in the last lines of the `strace` output above.

If the input's length is equal to 0x18 (24), each character in the input is compared to some value in a loop. If every test passes, the success message is displayed. With the contents of `buf`, we can reverse the operation in order to form the desired input. This can be done in a few lines:
```python
buf = "bmgacct|r~ce~QfcNpr!|ude"
for i, c in enumerate(list(buf), start=1):
        print(chr(ord(c) ^ i), end="")
print("")
```

Which outputs the flag: `codefest{this_is_ba5ics}`.
