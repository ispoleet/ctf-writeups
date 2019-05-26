## 0CTF 2016 - momo (RE 3pt)
##### 12-14/03/2016 (48hr)


### Description: 
I think it's hard winning a war with words.

___
### Solution

In this reversing challenge, I was given a huge binary that consists of exclusively `mov` 
instructions. This is obviously a weird form of obfuscation, so after a little Googling, I found
that binary was compiled with [movfuscator](https://github.com/xoreaxeaxeax/movfuscator).

Cracking this binary seems impossible given that the side channel attacks that were used for
movfuscator crackmes do not work.


So the first step for cracking this binary, is to understand the internals of _movfuscator_. The
[slides](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)
and the [source code](https://github.com/xoreaxeaxeax/movfuscator/blob/master/movfuscator/movfuscator.c)
are the best resources for it. 


Once you see how the data flows across `mov` instruction, you can easily extract the flag character
by character. All characters are checked sequential (there are no loops in the non-movfuscated 
program) and that's why side channel attacks do no work. With a little patience we can get the
following:
```
password[0]  + 0x9 == 0x39 			=> password[0]  = 0x30 = '0'
password[1]  - 0x2 == 0x61			=> password[1]  = 0x63 = 'c'
password[2]  - 0x7 == 0x6d 			=> password[2]  = 0x74 = 't'
password[3]  + 0xf == 0x75			=> password[3]  = 0x66 = 'f'
password[4]  - 0x7 == 0x74			=> password[4]  = 0x7b = '{'
password[5]  - 0x7 == 0x66			=> password[5]  = 0x6d = 'm'
password[6]  + 0x9 == 0x39			=> password[6]  = 0x30 = '0'
password[7]  + 0x4 == 0x5a			=> password[7]  = 0x30 = 'V'
password[8]  + 0xe == 0x6d			=> password[8]  = 0x5f = '_'
password[9]  - 0x8 == 0x41			=> password[9]  = 0x49 = 'I'
password[10] + 0x13 == 0x48			=> password[10] = 0x35 = '5'
password[11] + 0x6 == 0x65			=> password[11] = 0x5f = '_'
password[12] + 0x1 == 0x75			=> password[12] = 0x74 = 't'
password[13] + 0x1 == 0x56			=> password[13] = 0x55 = 'U'
password[14] + 0x3 == 0x75			=> password[14] = 0x72 = 'r'
password[15] - 0x1 == 0x30			=> password[15] = 0x31 = '1'
password[16] + 0x9 == 0x57			=> password[16] = 0x4e = 'N'
password[17]       == 0x39			=> password[17] = 0x39 = '9'
password[18] + 0x9 == 0x68			=> password[18] = 0x5f = '_'
password[19] - 0x9 == 0x5A			=> password[19] = 0x63 = 'c'
password[20] + 0x9 == 0x39			=> password[20] = 0x30 = '0'
password[21] - 0x2 == 0x4e			=> password[21] = 0x50 = 'P'
password[22] - 0x1 == 0x30			=> password[22] = 0x31 = '1'
password[23] + 0xa == 0x4f			=> password[23] = 0x45 = 'E'
password[24] - 0x5 == 0x6f			=> password[24] = 0x74 = 't'
password[25] + 0x6 == 0x39			=> password[25] = 0x33 = '3'
password[26]       == 0x21			=> password[26] = 0x21 = '!'
password[27]       == 0x7d			=> password[27] = 0x7d = '}'
```

From here, we can see that the password/flag is **0ctf{m0V_I5_tUr1N9_c0P1Et3!}**:

```
ispo@nogirl:~/ctf/0ctf/momo$ ./momo
password: 0ctf{m0V_I5_tUr1N9_c0P1Et3!}
Congratulations!
```
