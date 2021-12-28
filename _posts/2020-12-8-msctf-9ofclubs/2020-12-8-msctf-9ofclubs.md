---
layout: post
title: "2020 Metasploit Community CTF - 9 of Clubs (port 1337) [Pwn]"
categories: ctf
tags: r1p writeup pwn format-string exploitation ctf
date: 2020-12-08 21:00:00 +0200
author: r1p
---

Port 1337 hosts a TCP service that prompts the user to choose one of several options, and later takes some text input. After trying several techniques, we discovered that it had a format string vulnerability

When sending a random string over the second option (_2\. Greetings_), the server replies with `Hello _{string}_!!!`, _{string}_ being our input. This option was the only that reflected the user's input.

![](https://lh3.googleusercontent.com/8PDzTcT9Dv9c5hhMJNu8mwCWOnzHRzk53UNrucjIS3oH8B2DFxgoWJy5rsWCYvVJzCwivJiyu8aEFzcIkvZCUGg0u5f8VZ73kHjaIJayt_Qpx7iaMqlueRGQ3F8STyL9zbf0oWXa)![](https://lh4.googleusercontent.com/8MUm3uj3AKGFucD59gjAHfsamo0UtwC8cK5yYJRGSAOmaehN5PngiL00nK6ooHxzq2Cqn_vpJb2D4yFT1pel8Cpa_tqBNSCOB2uUL4pxn39GL2DujjawMhSYQPzcmmaW8Go5w9Ug)![](https://lh4.googleusercontent.com/eYdlRlsD-VHRteKgSZnsc0Q0hJ0TjhYOdBp3rltiVrvVrCMnaHKyUhqzTgNgfJ0NIQKz5DhMK_nnH0hScaIF1_M_WGOyUeFsvWP7jBln3Wycyf_YHsdirU5ogRx-0BdcC9g-E-7h)

To further understand this vulnerability we set up the following scenario locally. The C program below allocates the flag “_Scavenger{CTF\_MSF}_” on the stack.

![](https://lh3.googleusercontent.com/MP8HpeGPmv3p29yib7JgvSfQPzZoKt3AsDgCp6Fvy_gmuoOh6fLMssJT-1qR5tnsMpFAq0sAsuU7-RsMzlMMnA5bx6VKEIeW_D6AiOtcmeDshpjUvxza5-6nczUPudYzhn0nLxeS)

Since the `printf(str)` call is not properly sanitized, it is vulnerable to the format string vulnerability mentioned above.

![](https://lh6.googleusercontent.com/KtZFx4ch5FRIuizVQKTDM441ZQPrmZ7T_UGbAOMW5zW4xIrax1np3XFkCOqrzuy719WJf9u0TvOpCDjrpto9XCsNnyQWj5qzrOL1SwcMGUZemHdbDQEFZPFQQR0_N8yLAwkkP38G)

In this bash loop we generate a new input for each iteration in the format of `%i$s`, where `i` is the loop counter. This use of the dollar sign is a C language extension [introduced by the POSIX standard](https://stackoverflow.com/a/19327442/8887440). What this effectively does is to print the `i`\-th argument for `printf` with the specified format (`%s` in this case). For example, in the following snippet, the output would be `c`, as it is the third parameter:

`printf("%3$c", 'a', 'b', 'c');`

In our case, we are exploiting the format string vulnerability to print the `i`\-th pointer on the stack as a null-terminted string. The proper way to sanitize it in this case should be as shown below.

![](https://lh5.googleusercontent.com/zJ5k-jxchEokLhJC7dR00b8zguGetWcVMtZAP4akYO00mgTvI2SYGjMr6DJRkXEEScoWzNLsdbPGYMtJtDVqLPGluJ3ikuDgbDFkkl-pZtlwvV7pAExjg1up9Ppz2w7Emm8vfTcM)![](https://lh5.googleusercontent.com/_rAdfVULObVRHjBzxti8c3QhwKPkgOMQDtxkkCZgz-nGXTtw-2Zzgrzt2gjHfPvQH7y-ocN8S8wgAFTxc0v0KHG7IiiA_N_uTFocqWBegPwz2KcPGzuEguiP2qSxXLXOOFn9bElk)

Trying this same methodology on the challenge itself, we can find the flag by either using the dollar sign extension to skip positions, or manually writing the full format string to reach the element we are interested in.

![](https://lh6.googleusercontent.com/osA66Ih37xSkbS0-Qe2RPF76mysqtVlY46ar7kRQm5d10DkoWmsaEAnufWAu4BcUq1A-vGw-NUIOqXHrB3VJAONIeIlmPqIKC-pDBDKlK8hUG8yo5XM4y0SclcooNQ67F1DgF4za)![](https://lh6.googleusercontent.com/6oUfTV4M-NvIOl67Mvcy2m4vel9Eod-XWeA_UtgrcLB6RW84-zwIgUAqp-kVrKGGTBCLJViI2SoXIM51hIeui1QkLEUw-CJCIQEoGjQDrEnmEl3c20Rl72-j-r-hgTmqZwYK7Wx-)
