---
layout: post
title: "ASIS CTF Quals 2021 - Beans Talk [Reversing]"
categories: ctf
tags: z3 constraint-programming c++ 00xc
date: 2021-10-24 20:44:00 +0200
author: 00xc
---

*NOTE: In this CTF we participated with [ripp3rs](https://ctftime.org/team/50984).*

`Beans talk` was a reversing challenge during ASIS CTF Quals 2021 that got 37 solves. We are given a 64 bit binary ELF file with debug info for Linux.

```
$ file beanstalk 
beanstalk: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=59abf2ea6e7bd3a1d3e1d4c61833861751ed7186, for GNU/Linux 3.2.0, not stripped
```

## License Format ##

After opening the binary file with Ghidra, we notice it is a C++ program. After cleaning up the variable types and names, the first part of the program seems to be pretty straightforward:

```c++
int main() {

	/* ... */

	std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(inp);
		  /* try { // try from 00102b40 to 00102b70 has its CatchHandler @ 00102ee6 */
	std::operator<<(&std::cout,"License Key: ");
	std::operator>>(&std::cin,(basic_string *)inp);
	std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string
			  ((basic_string *)license,inp);
		  /* try { // try from 00102b7f to 00102b83 has its CatchHandler @ 00102e6c */
	ok = license_to_key(license,key);
	std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string
			  ((basic_string<char,std::char_traits<char>,std::allocator<char>> *)license);
	if (ok == '\x01') {
		/* the program continues */
		/* ... */
	} else {
		  /* try { // try from 00102ba7 to 00102bdd has its CatchHandler @ 00102ee6 */
		pbVar1 = std::operator<<(&std::cout,"[-] Invalid license format");
		std::basic_ostream<char,std::char_traits<char>>::operator<<
				  ((basic_ostream<char,std::char_traits<char>> *)pbVar1,
				   std::endl<char,std::char_traits<char>>);
		out = 1;
	}

	return out;
}
```

A license key is read into `license` from stdin, and then it is converted into a key via `license_to_key` - if that function returns `1` the program proceeds, otherwise we get an error message. We omit the contents of `license_to_key`, but in summary, it verifies that:
 * The license key has a length of 27.
 * The first 5 characters are the string "BEAN-".
 * The characters at offsets 9 and 20 of the license are equal to '-'.
 * The characters in the ranges 10-19 and 21-16 must only have characters in the set "0123456789abcdefABCDEF".

Once that is done, the characters in the aforementioned ranges are converted to bytes, intepreting them as hexadecimal, and are stored into `key`. If we have met the previous requeriments, the function returns 1.

## License Checker ##

Next, our hashed key (the result of `Beanstalk::hash()`) must match a certain target. `std::equal`'s first two parameters are pointers that delimit the range to compare (i.e. the bytes between the addresses pointed between `k2` and `k1`). The `k()` function seems to do some tricks with inline assembly and stack manipulation, so instead of statically analyzing it we retrieved the bytes in the `k2`-`k1` range by inspecting `std::equal`'s parameters at runtime.

```c++
if (ok == '\x01') {
	k2 = key;
	Beanstalk::Beanstalk(&bs,k2);
	hash = Beanstalk::hash(&bs);
	k1 = (uchar *)::k(1,k2);
	k2 = (uchar *)::k(0,k2);
	  /* try { // try from 00102c0d to 00102c40 has its CatchHandler @ 00102ed1 */
	eq = std::equal<unsigned_char*,unsigned_char_const*>(k2,k1,hash);
	if (eq == true) {
		/* the program continues */
		/* ... */
	} else {
		pbVar1 = std::operator<<(&std::cout,"[-] Invalid license key");
		std::basic_ostream<char,std::char_traits<char>>::operator<<
				  ((basic_ostream<char,std::char_traits<char>> *)pbVar1,
				   std::endl<char,std::char_traits<char>>);
		out = 1;
	}
}
```

After analyzing the constructor for `Beanstalk` and several other methods shown below, we reversed the object's memory layout:

```c
struct Beanstalk {
	short enc[4];
	char** map;
	usigned char hash[10];
}
```

`Beanstalk::hash()` simply returns the `hash` property of the object. This property is initialized inside the constructor for the type (`Beanstalk::Beanstalk`).

```c++
void __thiscall Beanstalk::Beanstalk(Beanstalk *this, uchar *key) {
	uchar **map;
	uchar *str;
	uchar *thing;
	int i;
	int j;
	
	map = (uchar **)operator.new[](80);
	this->map = map;
	for (i = 0; i < 10; i += 1) {
		map = this->map;
		str = (uchar *)operator.new[](256);
		map[i] = str;
		for (j = 0; j < 256; j += 1) {
			thing = t();
			this->map[i][j] = thing[(int)((uint)key[i] ^ j)];
		}
		this->hash[i] = this->map[i][119];
	}
	return;
}
```

Again, `t()` does some weird tricks with stack manipulation, so we extracted its returned value with gdb and verified that it is the same for each iteration of the nested loops. Since we have the value returned by `t()` (`thing`), the target hash, and we know that `this->hash` must be the same, we can brute force valid values for our key, and generate our license from it. The following function returns the valid license: `BEAN-2a21-b91dc84834-24e676`.

```python
thing = bytes.fromhex("a3d70983f848f6f4b321157899b1aff9e72d4d8ace4cca2e5295d91e4e3844280adf02a017f1606812b77ac3e9fa3d5396846bbaf2639a197caee5f5f7166aa239b67b0fc193811beeb41aead0912fb855b9da853f41bfe05a58805f660bd89035d5c0a733066569450094566d989b7697fcb2c2b0fedb20e1ebd6e4dd474a1d42ed9e6e493ccd4327d207d4dec7671889cb301f8dc68faac874dcc95d5c31a47088612c9f0d2b8750825464267d0340344b1c73d1c4fd3bccfb7fabe63e5ba5ad04239c145122f02979717eff8c0ee20cefbc72756f37a1ecd38e628b8610e8087711be924f24c532369dcff3a6bbac5e6ca9135725b5e3bda83a0105592a46")
target_hash = bytes.fromhex("bf0b0fa2a5940ed7cb85")
def find_license():
	out = []

	for t in target_hash:
		for v in range(255):
			if thing[v ^ 119] == t:
				out.append(v)
				break
		else:
			sys.exit(":(")

	license = "BEAN-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}{:02x}".format(
				out[1], out[0], out[6], out[5], out[4], out[3], out[2], out[9], out[8], out[7])
	return out, license
```

## Flag Checker ##

For the final step, we are asked for a flag, which the program will verify. The input flag will be encrypted in blocks of 8 bytes and verified against the value returned by `f()` (which, again, we obtained via dynamic analysis). The flag can have a maximum length of 48 bytes, so we have 6 blocks of 8 bytes.

```c++
	if (eq == true) {
		
		std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(license);
		std::operator<<(&std::cout,"Flag: ");
		std::operator>>(&std::cin,(basic_string *)license);

		size = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::size(license);
		if (size < 48) {
			j = 0;
			while( true ) {

				size = std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::size(license);
				if (size <= (ulong)(long)j) break;

				/* Take next group of 8 bytes */
				for (i = 0; i < 8; i += 1) {
					k2 = (uchar *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::at((ulong)license,(long)(i + j));
					decrypted[i] = *k2;
				}

				/* Encrypt and verify result */
				Beanstalk::encrypt(&bs,decrypted,encrypted);
				for (k = 0; k < 8; k += 1) {
					e = encrypted[k];
					target = (uchar *)f();
					if (e != target[k + j]) {
						/* "[-] Invalid flag" */
					}
				}
				j += 8;
			}

			pbVar1 = std::operator<<(&std::cout,"[+] Correct!");
			std::basic_ostream<char,std::char_traits<char>>::operator<<((basic_ostream<char,std::char_traits<char>> *)pbVar1,
				std::endl<char,std::char_traits<char>>);
			out = 0;

		} else {
			/* "[-] Invalid flag" */
		}
	}
```

At this point all we need is to generate a sequence of bytes that, once encrypted, matches the known valid byte string. The encryption process is quite complex as we will show next, so we turned to z3 so solve this problem.

```c++
void __thiscall Beanstalk::encrypt(Beanstalk *this,uchar *inp,uchar *out) {
	int i;
	int j;
	
	for (i = 0; i < 4; i += 1) {
		this->enc[i] = CONCAT11(inp[i * 2],inp[(long)(i * 2) + 1]);
	}
	srand(CONCAT13(this->map[9][31], CONCAT12(this->map[8][10],CONCAT11(this->map[5][14],this->map[1][14]))))

	g0(this,3);
	z(this,2,3);
	g1(this,2);
	/*
	 * 60 more function calls, omitted for brevity.
	 * The functions called are z, g0, g1, g2, g3 and g4.
	 * g0-g4 call the same underlying function with different parameters.
	 */
	for (j = 0; j < 4; j += 1) {
		out[j * 2] = (uchar)((uint)(ushort)this->enc[j] >> 8);
		out[(long)(j * 2) + 1] = (uchar)this->enc[j];
	}
}
```

The input block (8 bytes) in converted into an array of 4 short integers. The values in the `map` field are known (we can extract them at runtime or generate them with a custom script that emulates the behavior in `Beanstalk::Beanstalk`), so the seed is also known and constant. The following function calls are more problematic however. As mentioned in the comment, g0-g4 are pretty much the same.

```c++
void __thiscall Beanstalk::g0(Beanstalk *this,int n) {
	g(this,n,0,1,2,3);
}

void __thiscall Beanstalk::g1(Beanstalk *this,int n) {
	g(this,n,4,5,6,7);
}

/* omitted g2, g3 and g4 for brevity */

void __thiscall Beanstalk::g(Beanstalk *this,int n1,int n2,int n3,int n4,int n5) {
	this->enc[n1] ^= (ushort)this->map[n5][(byte)this->enc[n1]] << 8;
	this->enc[n1] ^= (ushort)this->map[n4][(int)(uint)(ushort)this->enc[n1] >> 8];
	this->enc[n1] ^= (ushort)this->map[n3][(byte)this->enc[n1]] << 8;
	this->enc[n1] ^= (ushort)this->map[n2][(int)(uint)(ushort)this->enc[n1] >> 8];
}

void __thiscall Beanstalk::z(Beanstalk *this,int n1,int n2) {
	int r;
	ushort x;
	
	x = this->enc[n2];
	r = rand();
	this->enc[n1] ^= x ^ (ushort)r;
}
```

The `z()` function is easily reversible; we know what `rand()` will return thanks to knowing the seed passed to `srand()`, so we just need to apply the XOR again to obtain the original value at `this->enc[n1]`. However, `g()` is not easily reversible in this manner, as the resulting value at `this->enc[n1]` depends on the value it had before applying the XOR operation. In this case, we use z3 to obtain such a value for `this->enc[n1]` that would generate our observed value after applying the four XOR operations.

Note that if we had an invalid license and we simply bypassed the check with a debugger, `this->map` would contain invalid values, and thus we would not be able to retrieve the flag.

Recall that in our original decompiled output we had the following check (simplified) for each 8-byte block:

```c++
Beanstalk::encrypt(&bs, decrypted, encrypted);
target = (uchar *)f();
for (k = 0; k < 8; k += 1) {
	if (encrypted[k] != target[k + j]) {
		/* "[-] Invalid flag" */
	}
}
```

Starting with the corresponding block in `target`, we will apply the 63 functions in `Beanstalk::encrypt` in reverse order; for `z()` we will simply XOR the values, but for `g` we will use z3. There are 32 calls to `z()`, so we will obtain 32 values from `rand()` and use them in reverse order.

We also used this challenge as a learning opportunity, as we used the Z3 C API instead of the usual Python one. Our solver can be found [here](https://gist.github.com/00xc/76b397157a9eed3fd49f43a6988aa63d). It is not very fast, but it gets the job done in a few minutes - it could probably be optimized as the decryption of each of the 6 blocks can be parallelized, but we didn't bother to do so :).

Flag: `ASIS{DATA_1n_TEXT_1s_4n_34sy_0bfusc4t10n}`
