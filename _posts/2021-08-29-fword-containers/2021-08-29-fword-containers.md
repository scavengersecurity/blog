---
layout: post
title: "FwordCTF 2021 - Containers? [Bash]"
categories: ctf
tags: containers privesc namespaces linux 00xc
date: 2021-08-29 19:55:00 +0200
author: 00xc
---

Containers? was a bash challenge during FwordCTF 2021 that got 9 solves. We are given an ELF binary, called `sealer`, and access to a remote server via SSH.

If we log to the server we find two files in the home directory: the same `sealer` binary and `flag.txt`, which is not readable by our user (`user1`), as it is owned by a privileged user. The binary has the suid bit set, and is owned by the privileged user as well. This information indicates that the likely way to read the flag is to exploit a flaw within the `sealer` binary.

If we open the binary with Ghidra, we clearly see there are two commands that this binary accepts: `greet` and `raijin`. The first one reads the flag, `clone`s a new process with a new namespace using the function `child_fn`, passing the flag as its first parameter. This function sets the hostname to be the flag, and runs a command as `user1` with `execv`:

```c
int main(int argc, char** argv[]) {
	int fd;
	int r;
	sockaddr addr [7];
	FILE *fp;
	char buf [260];
	int pid;
	int *rfd;
	int *piVar1;
	int s;

	if (argc == 1) {
		puts("Please Choose what you want to do!");
		r = 1;
	} else {

		if (strcmp(argv[1],"greet") == 0) {

			fp = fopen("/home/user1/flag.txt","r");
			fgets(buf,0xfa,fp);

			/* CLONE_NEWUTS|CLONE_NEWPID|CLONE_NEWNET|SIGCHLD */
			pid = clone(child_fn,&_end,0x64000011,buf);
			waitpid(pid,NULL,0);
			r = 0;

		} else if (strcmp(argv[1],"raijin") == 0) {

			/* snip */

		} else {
			puts("We don\'t do that here!");
			r = 0;
		}

	}

	return r;
}
```

```c
int child_fn(char *param_1) {
	char *cmd [4];

	sethostname(param_1,0x3d);
	cmd[0] = "su";
	cmd[1] = "user1";
	cmd[2] = "-c";
	cmd[3] = "echo \'Hakke no Fuin Shiki ..\' && sleep 1 && echo \'You are sealed now!\'";
	execv("/usr/bin/su",cmd);
	puts("Hello from inside the container; This is a fuin jutsu! I sealed everything \\o/\n");
	return 0;
}
```

The `clone`d process runs in a new UTS namespace (`CLONE_NEWUTS`), so we will not be able to see the changes made to the hostname. From the documentation (`man namespaces`):

```
UTS namespaces (CLONE_NEWUTS)
       UTS  namespaces provide isolation of two system identifiers: the hostname and the NIS domain name.  These identifiers are set using sethostname(2) and set‐
       domainname(2), and can be retrieved using uname(2), gethostname(2), and getdomainname(2).
```

The `raijin` command is more complicated. It first starts listening on a UNIX socket, and when it receives a connection, it calls `recv_fd`, which returns a pointer to a file descriptor. This file descriptor is then passed to `setns`, which reassociates the current thread to a namespace associated with that file descriptor. Then, depending on the second argument passed to the executable, it will return some information from the `utsname` struct returned by `uname`.

```c

		if (strcmp(argv[1],"greet") == 0) {

			/* snip */

		} else if (strcmp(argv[1],"raijin") == 0) {

			puts("We are doing flying raijin now!");
			s = socket(1,1,0);
			if (s == -1) {
				perror("Failed to create socket");
				exit(1);
			}

			r = unlink("/tmp/fd-pass.socket");
			if (r == -1) {
				piVar1 = __errno_location();
				if (*piVar1 != 2) {
					perror("Removing socket file failed");
					exit(1);
				}
			}

			memset(addr,0,0x6e);
			/* AF_UNIX */
			addr[0].sa_family = 1;
			strncpy(addr[0].sa_data,"/tmp/fd-pass.socket",0x6b);
			r = bind(s,addr,0x6e);
			if (r == -1) {
				perror("Failed to bind to socket");
				exit(1);
			}

			chmod("/tmp/fd-pass.socket",0x1ff);
			r = listen(s,5);
			if (r == -1) {
				perror("Failed to listen on socket");
				exit(1);
			}

			fd = accept(s,NULL,NULL);
			if (fd == -1) {
				perror("Failed to accept incoming connection");
				exit(1);
			}

			rfd = recv_fd(fd,1);
			puts("That was Flying Raijin Level 2 dattebayo");
			r = setns(*rfd,0);
			if (r == -1) {
				perror("failed to enter in sennin mode");
				exit(1);
			}

			piVar1 = __errno_location();
			*piVar1 = 0;
			r = uname(&local_2b8);
			if (r < 0) {
				perror("uname");
				exit(1);
			}

			r = strcmp(param_2[2],"sysname");
			if (r == 0) {
				printf("system name = %s\n",&local_2b8);
			}
			r = strcmp(param_2[2],"nodename");
			if (r == 0) {
				printf("node name   = %s\n",local_2b8.nodename);
			}
			r = strcmp(param_2[2],"release");
			if (r == 0) {
				printf("release     = %s\n",local_2b8.release);
			}
			r = strcmp(param_2[2],"version");
			if (r == 0) {
				printf("version     = %s\n",local_2b8.version);
			}
			r = strcmp(param_2[2],"machine");
			if (r == 0) {
				printf("machine     = %s\n",local_2b8.machine);
			}
			r = close(fd);
			if (r == -1) {
				perror("Failed to close client socket");
				exit(1);
			}
			r = 0;
		}
```

The decompilation for the `recv_fd` function is considerably worse, but we are only interested in a few lines.

```c
int* recv_fd(int s, int num) {
	int *__dest;
	int *buf;
	int local_1a0;
	int fd;
	long lVar3;
	ssize_t sVar2;
	msghdr msg;
	cmsghdr *control;

	/* snip */

	local_1a0 = num;
	fd = s;
	buf = (int *)malloc((long)num << 2);

	/* snip */

	__dest = buf;
	sVar2 = recvmsg(fd,&msg,0);
	if (-1 < sVar2) {
		control = msg.msg_control;
		if (msg.msg_controllen < 0x10) {
			control = NULL;
		}
		lVar3 = (long)local_1a0;
		memcpy(__dest,control + 1,lVar3 * 4);
		return buf;
	}

	/* snip */
 }
```

`recv_fd` calls `recvmsg` and returns a pointer to a buffer certain received information; this function is used to receive messages from a socket in a structured manner. `recvmsg` takes a pointer to a `msghdr` struct, which in turn has a field called `msg_control`. This field is a pointer to what is referred in the documentation to as "ancillary data". The ancillary data takes the form of a `cmsghdr` struct.

```c
/* Taken from `man recvmsg` */

struct msghdr {
	void         *msg_name;       /* optional address */
	socklen_t     msg_namelen;    /* size of address */
	struct iovec *msg_iov;        /* scatter/gather array */
	size_t        msg_iovlen;     /* # elements in msg_iov */
	void         *msg_control;    /* ancillary data. Typed as a void pointer, but actually struct cmsghdr pointer */
	size_t        msg_controllen; /* ancillary data buffer len */
	int           msg_flags;      /* flags on received message */
};

struct cmsghdr {
	socklen_t     cmsg_len;     /* data byte count, including hdr */
	int           cmsg_level;   /* originating protocol */
	int           cmsg_type;    /* protocol-specific type */
/* followed by
	unsigned char cmsg_data[]; */
};
```

When `recvmsg` returns, these structrues will be filled with the appropiate information. `recv_fd` checks that the `msg_controllen` field of the `msghdr` struct is greater than 16, which is `cmsghdr`'s base size without a `cmsg_data` field. In other words, it checks that `msg_control` contains some data; if so, it copies it into `__dest`, which points to the same place as `buf`, the return value.

Recall that the value returned by `recv_fd` is passed into `setns`. All of this points to the fact that the received message should contain a valid file descriptor. The documentation for `recvmsg` points us to the `SCM_RIGHTS` operation:

```
MSG_CMSG_CLOEXEC (recvmsg() only; since Linux 2.6.23)
	Set the close-on-exec flag for the file descriptor received via a UNIX domain file descriptor using the SCM_RIGHTS operation (described in unix(7)). This flag is useful for the same reasons as the O_CLOEXEC flag of open(2).
```

The description matches our requirements, as we are dealing with UNIX sockets, and SCM_RIGHTS apparently is used to send and receive file descriptors via these sockets. The manual page for `unix(7)` seems to confirm this. Clearly, file descriptors are being sent and received through the `cmsg_data` field in the ancillary data structure `cmsghdr`:

```
Ancillary data is sent and received using sendmsg(2) and recvmsg(2). For historical reasons the ancillary message types listed below are specified with a SOL_SOCKET type even though they are AF_UNIX specific. To send them set the cmsg_level field of the struct cmsghdr to SOL_SOCKET and the cmsg_type field to the type. For more information see cmsg(3).
SCM_RIGHTS
	Send or receive a set of open file descriptors from another process. The data portion contains an integer array of the file descriptors. The passed file descriptors behave as though they have been created with dup(2).
```

The manual page for `cmsg` contains an example on how to send these file descriptors.

So far we have discovered that we can send a file descriptor to the suid binary via UNIX sockets, and that the file descriptor will be used to switch namespaces. Remember that the operations for the `greet` command are being run in a separate namespace, and that its hostname contains the flag. Conveniently, after calling `setns`, the program displays the hostname if we pass `nodename` as the second parameter to `sealer`. So, if we are able to launch `./sealer greet`, obtain a file descriptor for the UTS namespace, then launch `./sealer raijin nodename` and send the file descriptor, we should see the flag in the standard output of the program.

The standard way to get a file descriptor for a process' UTS namespace is to `open` the path `/proc/$PID/ns/uts`. `sealer` has the suid bit set, so we will not have the necessary permissions to access its `ns` subdirectory. The key here is the call to `execv` within `child_fn`, as it uses `su user1`. This means that the commands passed to `su` will be started as our user, and will inherit its parent's namespace. We can, then, obtain a file descriptor for any of these new processes' namespaces. The final exploit looks something like the following sequence:

1. Launch `./sealer greet` in the background
2. There are three commands launched by `su`: `echo`, `sleep` and `echo` again. Each command is launched in a new process via `fork` + `exec`. We wait until `Hakke no Fuin Shiki` is written to stdout (first `echo`).
3. Find the pid for the `sleep` process.
4. Open `/proc/$pid/ns/uts`
5. Launch `./sealer raijin nodename` in the background
6. Connect to the recently created UNIX socket, and send the file descriptor for the namespace.

You can find the full exploit [here](https://gist.github.com/00xc/800233590dda59ca60772034d898f916).

```
$ ./exploit 
buf: Hakke no Fuin Shiki 
[+] Got pid: 30
[*] Opening /proc/30/ns/uts
[*] Sending file descriptor = 4
We are doing flying raijin now!
[+] socket()
[+] connect()
[+] sendmsg() => 2
That was Flying Raijin Level 2 dattebayo
node name   = FwordCTF{Plzz_no_UnInTendEd:(NamEsPacEs_4re_Best_S3al_JutSu}
```
