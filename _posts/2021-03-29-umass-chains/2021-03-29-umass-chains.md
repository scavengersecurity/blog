---
layout: post
title: "UMassCTF 2021 - Chains [Reversing]"
categories: ctf
tags: reversing collatz optimization 00xc
date: 2021-03-29 20:57:00 +0200
author: 00xc
---

Chains is a reversing challenge that got 20 solves. We are given a stripped aarch64 (ARM 64 bit) ELF binary called `chains`:

```
$ file chains 
chains: ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, for GNU/Linux 3.7.0, stripped
```

If we try running the program with qemu, it seemingly takes forever to run. After loading the program on Ghidra and renaming some variables, we get the following decompiled output:

```c
undefined8 main(void) {
	int res;
	uint i;
	uint j;
	int v2;
	int v1;
	
	i = 0;
	do {
		if (0x29f7 < i) {
			putchar(10);
			return 0;
		}
		v1 = arr[i];
		v2 = arr[i + 1];
		j = 1;
		while (j < 900000000) {
			res = FUN_001007cc(j);
			if (v1 == res) {
				v2 = v2 + -1;
			}
			if (v2 == 0) {
				putchar(j + 0xca5b17ff);
				fflush(stdout);
				break;
			}
			j = j + 1;
		}
		i = i + 2;
	} while (true);
}
```

`arr` is a global `int` array with 2686 elements. For each pair of `v1, v2` taken from the array, `FUN_001007cc` has to return `v1` for a total of `v2` times. Once this is done, the next character of what we assume is the flag will be printed. Thus, in order to get the flag, we must optimize the program.

The program's bottleneck is clearly `FUN_001007cc`, as it is being executed millions of times before a single character is even displayed. If we dive into this function, we see the following decompiled output:

```c
int FUN_001007cc(uint param_1) {
	uint n;
	int i;
	
	i = 0;
	n = param_1;
	while (n != 1) {
		if ((n & 1) == 0) {
			n = n >> 1;
		} else {
			n = n * 3 + 1;
		}
		i = i + 1;
	}
	return i;
}
```

This reveals that this function is returning the number of steps in the input's [Collatz sequence](https://en.wikipedia.org/wiki/Collatz_conjecture#Statement_of_the_problem). Given an integer `n`, if such number is even, it is divided by 2; if it is odd, it is multiplied by 3 and added 1. This is repeated until the number is 1. The returned value is the number of iterations needed to reach the final value of 1.

In order to optimize Collatz's function, the most common approach is to memoize it (for example, using Python's `lru_cache`). For any given number, the values in the sequence tend to converge to the same numbers, so we can cache these and reuse them later. This way, `FUN_001007cc` runs faster, but some people on Discord reported needing around 9GB of RAM to use this approach.

We took a different approach, however. We dumped to disk the output values for all inputs between 1 and 900000000. Instead of performing the computation for each iteration in the inner loop, we will do lookups on that dump. Our output file will have, on each line, an input and its corresponding output. In order to speed things up, we used a LRU cache as well, but we limited its size in order to avoid excessive RAM consumption. We also avoided using the recursive variant of Collatz's function.

If we naively take this approach, however, we will get a file of over 12 GB, which will make lookups slow. There is a faster solution: we can first collect all the possible values for `v1`, as we are only interested in the inputs that produce `v1` as an output. There are only 19 different values for `v1`, so this is perfectly doable. This reduces the dump size to just 765 MB. You can can check out the program I used to dump the values [here](https://gist.github.com/00xc/ffa7066f53633e1bb908ac5c90fefd2e). I did not monitor how long it takes for the dump to complete (probably less than 20 minutes with an underpowered VM and an old HDD), but it has a low RAM footprint.

We can make lookups even faster by separating lines with the same output value into separate files. For example, all inputs that produce the output 105 will be placed in a file called `105.out`. We can do this with a simple awk command, `awk '$2==105' collatz.out > 105.out`, and repeat it for the rest of the 19 distinct `v1` values.

Once we had separate files we wrote [this script](https://gist.github.com/00xc/2037a7d5e9887bba256705b7891c16fd) to retrieve the flag. It performs lookups on the dump files using `sed` in order to retrieve the `v2`-th input that returns `v1`. If we run the script, we get the flag within a few seconds:
```
UMASS{ oh, you want the flag? Too bad. Sit through this sponsored message first. The Collatz conjecture is a conjecture in mathematics that concerns a sequence defined as follows: start with any positive integer n. Then each term is obtained from the previous term as follows: if the previous term is even, the next term is one half of the previous term. If the previous term is odd, the next term is 3 times the previous term plus 1. The conjecture is that no matter what value of n, the sequence will always reach 1. Rawr x3 nuzzles how are you pounces on you you're so warm o3o notices you have a o:  hold up I need to make this message even longer In abstract algebra and analysis, the Archimedean property, named after the ancient Greek mathematician Archimedes of Syracuse, is a property held by some algebraic structures, such as ordered or normed groups, and fields. The property, typically construed, states that given two positive numbers x and y, there is an integer n so that nx > y. It also means that the set of natural numbers is not bounded above.[1] Roughly speaking, it is the property of having no infinitely large or infinitely small elements. It was Otto Stolz who gave the axiom of Archimedes its name because it appears as Axiom V of Archimedesâ On the Sphere and Cylinder. UMASS{7h15_15_4_f5ck1n6_l0n6_m355463_r07fl}
```