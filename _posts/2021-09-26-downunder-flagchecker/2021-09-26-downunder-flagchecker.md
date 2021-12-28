---
layout: post
title: "DownUnderCTF 2021 - Flag Checker [Reversing]"
categories: ctf
tags: z3 constraint-programming 00xc
date: 2021-09-26 20:24:00 +0200
author: 00xc
---

`flag checker` was a reversing challenge during DownUnderCTF 2021 that got 16 solves. We are given a stripped 64 bit binary ELF file for Linux.

```
$ file flag_checker 
flag_checker: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=97eb97cef6959130c2506020d89b16c91a275c7a, for GNU/Linux 4.4.0, stripped
```

After opening the file with Ghidra and cleaning up function and variable names, we get the following main function:

```c
void main(void) {
	size_t len;
	char *pos;
	int i;
	int j;
	char inp [40];
	
	/* setvbuf() stuff */
	setvbuf_FUN_001011ef();
	printf("What\'s the flag?: ");
	fgets(inp,37,stdin);
	len = strlen(inp);
	if (len != 36) {
		/* WARNING: Subroutine does not return */
		exit_err();
	}

	for (i = 0; i < 16; i += 1) {
		combine(inp);
		pos = shuffle1(inp);
		shuffle2(inp,pos);
	}

	j = 0;
	while( true ) {
		if (35 < j) {
			puts("Correct! :)");
			/* WARNING: Subroutine does not return */
			exit(0);
		}
		if (inp[j] != target[j]) break;
		j += 1;
	}

	/* WARNING: Subroutine does not return */
	exit_err();
}
```

Our input goes through 16 rounds of transformations; once that is done, if it matches the global 36-byte `target` array, it means our original character string is the intended flag. Therefore, we need to reverse engineer the `combine`, `shuffle1` and `shuffle2` functions in order to produce an input that matches our desired output.

`combine` takes 6 groups of 6 non-repeating integers, and calls `num_combine` once for each of those 6 arrays:

```c
void combine(char *inp) {
	int nums0 [6];
	int nums1 [6];
	int nums2 [6];
	int nums3 [6];
	int nums4 [6];
	int nums5 [6];

	nums0[0] = 0;
	nums0[1] = 1;
	nums0[2] = 2;
	nums0[3] = 6;
	nums0[4] = 12;
	nums0[5] = 18;
	nums1[0] = 3;
	nums1[1] = 4;
	nums1[2] = 5;
	nums1[3] = 11;
	nums1[4] = 17;
	nums1[5] = 23;

	/* ... omitted for brevity ... */

	num_combine(inp,nums0);
	num_combine(inp,nums1);
	num_combine(inp,nums2);
	num_combine(inp,nums3);
	num_combine(inp,nums4);
	num_combine(inp,nums5);

	return
}
```

`num_combine` takes the characters of the input at the offsets indicated by its second paramter, applies some transformations (`char_transform`) on them and stores them back. This function has a lot of redundancy, as some results are called several times (for example, `v0`, `w0` and `x0` are the same, as `char_transform` does not change its input).

```c
void num_combine(char *inp,int *nums) {
	byte v0;
	byte v2;
	byte v4;
	byte v1;
	byte v3;
	byte v5;
	byte w0;
	byte w1;
	byte x0;
	byte w2;
	byte x1;
	byte w3;
	byte n0;
	byte n1;
	byte n2;
	byte n3;
	byte n4;
	byte n5;

	n0 = inp[*nums];
	n1 = inp[nums[1]];
	n2 = inp[nums[2]];
	n3 = inp[nums[3]];
	n4 = inp[nums[4]];
	n5 = inp[nums[5]];
	v0 = char_transform(n0);
	v2 = char_transform(n2);
	v4 = char_transform(n4);
	v1 = char_transform(n1);
	v3 = char_transform(n3);
	v5 = char_transform(n5);
	w0 = char_transform(n0);
	w1 = char_transform(n1);
	x0 = char_transform(n0);
	w2 = char_transform(n2);
	x1 = char_transform(n1);
	w3 = char_transform(n3);
	inp[*nums] = v4 ^ v0 ^ n0 ^ n2 ^ v2;
	inp[nums[1]] = v5 ^ v1 ^ n1 ^ n3 ^ v3;
	inp[nums[2]] = w0 ^ n4;
	inp[nums[3]] = w1 ^ n5;
	inp[nums[4]] = w2 ^ x0 ^ n0;
	inp[nums[5]] = w3 ^ x1 ^ n1;
	return;
}
```

`char_transform` simply returns `(c >> 7) * 0x1b ^ (uint)c * 2` based on the input byte `c`.

So far we know that `combine`, which is called once for each of the 16 rounds, combines characters at certain offsets by way of bit shifts and XOR operations. The second step for each round are the calls to `shuffle1` and `shuffle2`. We will not show the full decompiled output for these functions, as they are moderately complex to understand. During the reversing process, we resorted to dynamic analysis to understand their function.

`shuffle1` returns a pointer some unknown byte array. `shuffle2` takes this pointer (`shuf`) and assigns its values to our input (`inp`) in the following way:

```c

	/* ... snip ... */
	*inp = shuf[0x2730];
	inp[1] = shuf[0x5b00];
	inp[2] = shuf[0x370];
	inp[3] = shuf[0x6f0];
	inp[4] = shuf[0x3120];
	inp[5] = shuf[0x3370];
	inp[6] = shuf[0x32d0];
	inp[7] = shuf[0x57b0];
	/* ... etc ... */
```

In order to debug the effects of these two functions, we patched the call to `combine` with NOP instructions (as it jumbles our data), and analyzed `inp` before and after calling `shuffle2` (`shuffle1` does not alter our input). When we used the string `ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789` as our input, `shuffle2` produced `XQTM5YRWNSZ4JCLE70DIFK16VO92HAPU38BG`, which is just our data with its characters shuffled around. We tried with different inputs and throughout different rounds, and verified that the shuffle is constant, meaning that every input offset always gets shuffled to the same output offset. We generated a Python dictionary that relates each input offset to each output offset:

```python
>>> orig = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
>>> new  = "XQTM5YRWNSZ4JCLE70DIFK16VO92HAPU38BG"
>>> 
>>> mappings = {}
>>> for i, o in enumerate(orig):
...	 mappings[i] = new.index(o)
... 
>>> print(mappings)
{0: 29, 1: 34, 2: 13, 3: 18, 4: 15, 5: 20, 6: 35, 7: 28, 8: 19, 9: 12, 10: 21, 11: 14, 12: 3, 13: 8, 14: 25, 15: 30, 16: 1, 17: 6, 18: 9, 19: 2, 20: 31, 21: 24, 22: 7, 23: 0, 24: 5, 25: 10, 26: 17, 27: 22, 28: 27, 29: 32, 30: 11, 31: 4, 32: 23, 33: 16, 34: 33, 35: 26}
```

At this point we have two options to try to obtain the flag. The first one is to program all the transformations in a SMT solver like z3 and ask the solver to produce an array that, after all the transformations, will result in our desired output; this will not work, as with only a few rounds (let alone 16 as is the case) the constraints will become too complex. When we tried this approach, the solver did not produce any results after more than 30 minutes of runtime.

The second (and correct) approach is to attempt to apply the inverse transformations, working our way backwards, starting with the `target` global seen in the main function. The `shuffle1` and `shuffle2` steps are trivial to invert, as we just need to apply the shuffle mappings the other way around. For the `combine` function, we will certainly need to use an SMT solver. For each call to `num_combine`, we need to find the values for `n0` through `n5` given the output values (`inp[nums[0]]` through `inp[nums[5]]`). This can be done as follows:

```python
from z3 import *

def ch_transform(c):
	return ((c >> 7) * 0x1b ^ c * 2) & 0xff

def reverse_num_combine(inp, nums):

	# The known output values
	n_out = [inp[nums[i]] for i in range(6)]

	# The unknown input values that produce the output
	n = [BitVec(f"n{i}", 32) for i in range(6)]

	s = Solver()
	s.add(inp[nums[0]] == ch_transform(n[4]) ^ ch_transform(n[0]) ^ n[0] ^ n[2] ^ ch_transform(n[2]))
	s.add(inp[nums[1]] == ch_transform(n[5]) ^ ch_transform(n[1]) ^ n[1] ^ n[3] ^ ch_transform(n[3]))
	s.add(inp[nums[2]] == ch_transform(n[0]) ^ n[4])
	s.add(inp[nums[3]] == ch_transform(n[1]) ^ n[5])
	s.add(inp[nums[4]] == ch_transform(n[2]) ^ ch_transform(n[0]) ^ n[0])
	s.add(inp[nums[5]] == ch_transform(n[3]) ^ ch_transform(n[1]) ^ n[1])

	if s.check() == sat:

		m = s.model()
		final_nums = [int(str(m[e])) for e in n]

		for i in range(6):
			inp[nums[i]] = final_nums[i]
		return inp
```

Combining the previous snippet with the `shuffle` step results in the script needed to retrieve the flag, which you can find [here](https://gist.github.com/00xc/4fc261156bd919c0179abf38e4eae637).

```
$ python3 solve.py 
DUCTF{rev3rs1bl3___and___1nv3rtibl3}
```