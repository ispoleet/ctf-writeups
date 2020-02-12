## Codegate CTF 2020 Preliminary - RS (RE 670)
##### 08-09/02/2020 (24hr)
___

### Description: 

ReverSe the RuSt binary.

Download:
```
http://ctf.codegate.org/099ef54feeff0c4e7c2e4c7dfd7deb6e/81866e4a863e6013f507c54c4999ddec
```
___

### Solution

Before we start the reversing, let's play a little bit with the binary:
```
ispo@leet:~/ctf/codegate_2020/RS$ echo 'AAAA' > flag; ./rs
	58 ae 80 e0 2a 9e a1 67 63 4b 73 53 a7 51 93 e2 85 dc 23 ea 06 c9 05 9d 6f 61 0a 29 74 1c 73 90 

ispo@leet:~/ctf/codegate_2020/RS$ echo 'AAAABBBBCCCC' > flag; ./rs
	a4 3b 68 b2 0b d8 5b 16 b8 05 b2 56 16 98 8d 58 22 3f eb 0f 4a 15 bb ba 3a 8c d3 61 60 27 0c 3b 

ispo@leet:~/ctf/codegate_2020/RS$ echo 'AAAABBBBCCCCDDD' > flag; ./rs
	a3 96 58 55 de 7a 04 ea 23 b0 8d 7a a9 f7 8c 01 1f d9 25 5c 24 85 26 03 9d d1 4f da 00 ab 32 f0 

ispo@leet:~/ctf/codegate_2020/RS$ echo 'AAAABBBBCCCCDDDEEE' > flag; ./rs
	9e 55 fc 67 89 45 76 35 a6 02 b5 e3 bd f9 f5 6b ab 20 5d ab f3 c5 e1 a0 5d 84 49 c2 3e 5c e1 2d
	fd ce c9 94 de e4 c5 46 47 17 7a f4 a4 13 44 01 1e 2b 8e 18 c7 e5 a2 a9 9d ed a8 05 af af 6f c9 

ispo@leet:~/ctf/codegate_2020/RS$ echo 'xxxxBBBBCCCCDDDExxx' > flag; ./rs
	0c 97 9d cc 35 0c 7d 09 33 6d e3 02 3e 66 77 b8 fd b6 30 38 d7 e4 45 89 6b 88 17 a8 9a 24 4a ba
	ac ec db 65 36 35 32 fe c2 80 5a d4 da 6d f1 34 a7 f4 e7 7c f1 17 5f 9e 33 bf 67 7a 9d 21 42 7d 

ispo@leet:~/ctf/codegate_2020/RS$ echo 'xxxxBBBBCCCCDDDEEEE' > flag; ./rs
	0c 97 9d cc 35 0c 7d 09 33 6d e3 02 3e 66 77 b8 fd b6 30 38 d7 e4 45 89 6b 88 17 a8 9a 24 4a ba
	02 2d 78 68 42 3a fa 43 85 76 1f 8d bb ed cb 72 98 57 7e c8 3a bd 46 7a ba 08 7f dd 65 80 c1 c9

ispo@leet:~/ctf/codegate_2020/RS$ echo 'AAAABBBBCCCCDDDxxxx' > flag; ./rs
	32 47 18 8a 7a b8 77 60 9e 24 19 a6 83 3e 76 63 ab 0f ce 01 3d 97 9a ec 59 3d a4 7c 39 7d 09 e5
	ac ec db 65 36 35 32 fe c2 80 5a d4 da 6d f1 34 a7 f4 e7 7c f1 17 5f 9e 33 bf 67 7a 9d 21 42 7d
```

So we have an **Electronic Code Block (ECB)** cipher that operates on 16 byte blocks. Each block
is encrypted to 32. Then we load the Rust binary on IDA. The binary is mess with full of dummy
jump statements:
```assembly
	jmp     short $+2
```

Anyway, the interesting part starts at `0x555555566190`. The flag is being read from a file called
`flag` and then encryption starts:
```assembly
.text:0000555555566190                 sub     rsp, 88h
.text:0000555555566197                 lea     rax, aCannotOpenFlag+10h ; "flag "
.text:000055555556619E                 lea     rdi, [rsp+88h+var_60]
.text:00005555555661A3                 mov     rsi, rax
.text:00005555555661A6                 mov     edx, 4
.text:00005555555661AB                 call    open_file_556CAFF7BD50
.text:00005555555661B0                 jmp     short loc_5555555661BE
....
.text:00005555555661BE
.text:00005555555661BE loc_5555555661BE:                       ; CODE XREF: main_556EB114B190+20j
.text:00005555555661BE                 lea     rax, aCannotOpenFlag ; "Cannot open flagflag "
.text:00005555555661C5                 lea     rdi, [rsp+88h+var_60]
.text:00005555555661CA                 mov     rsi, rax        ; arg2: "Cannot open flag"
.text:00005555555661CD                 mov     edx, 10h        ; arg3: strlen("Cannot open flag") == 0x10
.text:00005555555661D2                 call    sub_5555555627D0 ; returns file descriptor?
.text:00005555555661D7                 mov     [rsp+88h+var_64], eax
.text:00005555555661DB                 lea     rdi, [rsp+88h+var_48]
.text:00005555555661E0                 lea     rsi, [rsp+88h+var_64]
.text:00005555555661E5                 call    read_file_55CDA67E70E0
.text:00005555555661EA                 jmp     short $+2       ; arg1: output
.text:00005555555661EC ; ---------------------------------------------------------------------------
.text:00005555555661EC
.text:00005555555661EC loc_5555555661EC:                       ; CODE XREF: main_556EB114B190+5Aj
.text:00005555555661EC                 lea     rdi, [rsp+88h+var_30] ; arg1: output
.text:00005555555661F1                 lea     rsi, [rsp+88h+var_48] ; arg2: flag
.text:00005555555661F6                 call    encrypt_flag_55CDA67DEC90
.text:00005555555661FB                 jmp     short loc_555555566209
```

The actual encryption of a block takes place at `entrypt_round_55555555D7F0`, where a 16-character
block gets encrypted (if it's less than 16 bytes, it gets zero padded):
```assembly
.text:000055555555D91F LOOP_0_55555555D91F:                    ; CODE XREF: entrypt_block_55555555D7F0:LOOP_END_55555555DBA5j
.text:000055555555D91F     lea     rdi, [rsp+1E8h+var_98]
.text:000055555555D927     call    sub_55555555ECA0
.text:000055555555D92C     mov     [rsp+1E8h+var_120], rdx
.text:000055555555D934     mov     [rsp+1E8h+var_128], rax
.text:000055555555D93C     jmp     short $+2
....
.text:000055555555DA5C LOOP_55555555DA5C:                      ; CODE XREF: entrypt_block_55555555D7F0+3B0j
.text:000055555555DA5C     lea     rdi, [rsp+1E8h+var_68]
.text:000055555555DA64     call    sub_55555555ECA0
.text:000055555555DA69     mov     [rsp+1E8h+var_178], rdx
.text:000055555555DA6E     mov     [rsp+1E8h+var_180], rax
.text:000055555555DA73     jmp     short $+2
.text:000055555555DA75 ; ---------------------------------------------------------------------------
.text:000055555555DA75
.text:000055555555DA75 loc_55555555DA75:                       ; CODE XREF: entrypt_block_55555555D7F0+283j
.text:000055555555DA75     mov     rax, [rsp+1E8h+var_180]
.text:000055555555DA7A     mov     [rsp+1E8h+var_58], rax
.text:000055555555DA82     mov     rcx, [rsp+1E8h+var_178]
.text:000055555555DA87     mov     [rsp+1E8h+var_50], rcx
.text:000055555555DA8F     mov     rdx, [rsp+1E8h+var_58]
.text:000055555555DA97     test    rdx, rdx
.text:000055555555DA9A     mov     [rsp+1E8h+var_188], rdx
.text:000055555555DA9F     jz      short END_55555555DAB5
.text:000055555555DAA1     jmp     short $+2
.text:000055555555DAA3 ; ---------------------------------------------------------------------------
.text:000055555555DAA3
.text:000055555555DAA3 loc_55555555DAA3:                       ; CODE XREF: entrypt_block_55555555D7F0+2B1j
.text:000055555555DAA3     mov     rax, [rsp+1E8h+var_188]
.text:000055555555DAA8     sub     rax, 1
.text:000055555555DAAC     mov     [rsp+1E8h+var_190], rax
.text:000055555555DAB1     jz      short loc_55555555DABC
.text:000055555555DAB3     jmp     short loc_55555555DABA
.text:000055555555DAB5 ; ---------------------------------------------------------------------------
.text:000055555555DAB5
.text:000055555555DAB5 END_55555555DAB5:                       ; CODE XREF: entrypt_block_55555555D7F0+2AFj
.text:000055555555DAB5     jmp     LOOP_END_55555555DBA5
.text:000055555555DABA ; ---------------------------------------------------------------------------
.text:000055555555DABA
.text:000055555555DABA loc_55555555DABA:                       ; CODE XREF: entrypt_block_55555555D7F0+2C3j
.text:000055555555DABA     ud2
.text:000055555555DABC ; ---------------------------------------------------------------------------
.text:000055555555DABC
.text:000055555555DABC loc_55555555DABC:                       ; CODE XREF: entrypt_block_55555555D7F0+2C1j
.text:000055555555DABC     mov     rax, [rsp+1E8h+var_50]
.text:000055555555DAC4     mov     rcx, [rsp+1E8h+var_150]
.text:000055555555DACC     lea     rsi, [rcx+rax+1]
.text:000055555555DAD1     lea     rdi, [rsp+1E8h+var_C8]
.text:000055555555DAD9     mov     [rsp+1E8h+var_198], rax
.text:000055555555DADE     call    sub_555555559F90            ; p0
.text:000055555555DAE3     mov     [rsp+1E8h+var_1A0], rax
.text:000055555555DAE8     jmp     short $+2
.text:000055555555DAEA ; ---------------------------------------------------------------------------
.text:000055555555DAEA
.text:000055555555DAEA loc_55555555DAEA:                       ; CODE XREF: entrypt_block_55555555D7F0+2F8j
.text:000055555555DAEA     mov     rax, [rsp+1E8h+var_1A0]
.text:000055555555DAEF     mov     cl, [rax]
.text:000055555555DAF1     mov     rdx, [rsp+1E8h+var_198]     ; p1
.text:000055555555DAF6     add     rdx, 1
.text:000055555555DAFA     mov     rdi, [rsp+1E8h+var_D8]
.text:000055555555DB02     mov     rsi, rdx
.text:000055555555DB05     mov     [rsp+1E8h+key_1A1], cl
.text:000055555555DB09     call    sub_55555555E250
.text:000055555555DB0E     mov     [rsp+1E8h+prng_stream_1B0], rax
.text:000055555555DB13     jmp     short $+2
.text:000055555555DB15 ; ---------------------------------------------------------------------------
.text:000055555555DB15
.text:000055555555DB15 loc_55555555DB15:                       ; CODE XREF: entrypt_block_55555555D7F0+323j
.text:000055555555DB15     mov     rax, [rsp+1E8h+prng_stream_1B0]
.text:000055555555DB1A     mov     cl, [rax]
.text:000055555555DB1C     lea     rdi, [rsp+1E8h+var_C8]
.text:000055555555DB24     mov     rsi, [rsp+1E8h+var_150]
.text:000055555555DB2C     mov     [rsp+1E8h+var_1B1], cl
.text:000055555555DB30     call    sub_555555559F90
.text:000055555555DB35     mov     [rsp+1E8h+flag_ptr_1C0], rax
.text:000055555555DB3A     jmp     short $+2
.text:000055555555DB3C ; ---------------------------------------------------------------------------
.text:000055555555DB3C
.text:000055555555DB3C loc_55555555DB3C:                       ; CODE XREF: entrypt_block_55555555D7F0+34Aj
.text:000055555555DB3C     mov     rax, [rsp+1E8h+flag_ptr_1C0]
.text:000055555555DB41     movzx   esi, byte ptr [rax]         ; arg2: flag[i]
.text:000055555555DB44     mov     cl, [rsp+1E8h+var_1B1]
.text:000055555555DB48     movzx   edi, cl                     ; arg1: prng_stream[i]
.text:000055555555DB4B     call    gen_xor_byte_55555555EAB0
.text:000055555555DB50     mov     [rsp+1E8h+xor_byte_1C1], al
.text:000055555555DB54     jmp     short $+2
.text:000055555555DB56 ; ---------------------------------------------------------------------------
.text:000055555555DB56
.text:000055555555DB56 loc_55555555DB56:                       ; CODE XREF: entrypt_block_55555555D7F0+364j
.text:000055555555DB56     mov     al, [rsp+1E8h+key_1A1]
.text:000055555555DB5A     movzx   edi, al                     ; arg2: flag[i+1]
.text:000055555555DB5D     mov     cl, [rsp+1E8h+xor_byte_1C1]
.text:000055555555DB61     movzx   esi, cl                     ; arg1: stream_cipher_byte
.text:000055555555DB64     call    xor_byte_55555555EA90
.text:000055555555DB69     mov     [rsp+1E8h+enc_key_1C2], al
.text:000055555555DB6D     jmp     short $+2
.text:000055555555DB6F ; ---------------------------------------------------------------------------
.text:000055555555DB6F
.text:000055555555DB6F loc_55555555DB6F:                       ; CODE XREF: entrypt_block_55555555D7F0+37Dj
.text:000055555555DB6F     mov     rax, [rsp+1E8h+var_150]
.text:000055555555DB77     mov     rcx, [rsp+1E8h+var_198]
.text:000055555555DB7C     lea     rsi, [rax+rcx+1]
.text:000055555555DB81     lea     rdi, [rsp+1E8h+var_C8]
.text:000055555555DB89     call    sub_55555555B370
.text:000055555555DB8E     mov     [rsp+1E8h+cipher_ptr_1D0], rax
.text:000055555555DB93     jmp     short $+2
.text:000055555555DB95 ; ---------------------------------------------------------------------------
.text:000055555555DB95
.text:000055555555DB95 loc_55555555DB95:                       ; CODE XREF: entrypt_block_55555555D7F0+3A3j
.text:000055555555DB95     mov     rax, [rsp+1E8h+cipher_ptr_1D0]
.text:000055555555DB9A     mov     cl, [rsp+1E8h+enc_key_1C2]
.text:000055555555DB9E     mov     [rax], cl                   ; store result
.text:000055555555DBA0     jmp     LOOP_55555555DA5C           ; p2
.text:000055555555DBA5 ; ---------------------------------------------------------------------------
.text:000055555555DBA5
.text:000055555555DBA5 LOOP_END_55555555DBA5:                  ; CODE XREF: entrypt_block_55555555D7F0+20Ej
.text:000055555555DBA5                                         ; entrypt_block_55555555D7F0:END_55555555DAB5j
.text:000055555555DBA5     jmp     LOOP_0_55555555D91F
```

So what's going on here? First of all, we have a pseudo-random sequence (called `PRNG`) 
at `0x55555579DAD0` that is used to generate a stream:
```
    0x74, 0x40, 0x34, 0xAE, 0x36, 0x7E, 0x10, 0xC2, 0xA2, 0x21, 0x21, 0x9D, 0xB0, 0xC5, 0xE1, 0x0C,
    0x3B, 0x37, 0xFD, 0xE4, 0x94, 0x2F, 0xB3, 0xB9, 0x18, 0x8A, 0xFD, 0x14, 0x8E, 0x37, 0xAC, 0x58
```

On each iteration, the next byte of the flag is passed to `gen_xor_byte_55555555EAB0` along with
the next byte of the `stream_cipher_byte` and generate the XOR key. Then `xor_byte_55555555EA90`
XORs the key with the **next** character of the flag and the result is stored back to the
plaintext at `0x55555555DB9E` (`mov [rax], cl`). We repeat this **32** times (one for each
character of the stream cipher). At the end the first character is prepended as it in the front.
Since we use 1 extra character, after the first iteration, ciphertext will be **33** bytes long. 
Therefore, after **16** rounds, the ciphertext will be **48** bytes long. Program discards the
first **16** bytes and returns the remaining ones (**32**) as the ciphertext.


We also have function `gen_xor_byte_55555555EAB0` which is quite simple:
```assembly
.text:000055555555EAB0 gen_xor_byte_55555555EAB0 proc near     ; CODE XREF: entrypt_block_55555555D7F0+35Bp
.text:000055555555EAB0                                         ; sub_55555555E280+383p ...
.text:000055555555EAB0     push    rax
.text:000055555555EAB1     mov     al, sil
.text:000055555555EAB4     mov     cl, dil
.text:000055555555EAB7     mov     [rsp+8+varZ_6], 0           ; Z = 0
.text:000055555555EABE     movzx   esi, cl
.text:000055555555EAC1     mov     dx, si
.text:000055555555EAC4     mov     [rsp+8+varY_4], dx          ; Y = PRNG[i]
.text:000055555555EAC9     movzx   esi, al
.text:000055555555EACC     mov     dx, si
.text:000055555555EACF     mov     [rsp+8+varX_2], dx          ; X = flag[i]
.text:000055555555EAD4
.text:000055555555EAD4 LOOP_55555555EAD4:                      ; CODE XREF: gen_xor_byte_55555555EAB0:BELOW_256_55555555EB40j
.text:000055555555EAD4     cmp     [rsp+8+varX_2], 0
.text:000055555555EADA     jbe     short RETURN_55555555EAED   ; if X <= 0 return
.text:000055555555EADC     mov     ax, [rsp+8+varX_2]
.text:000055555555EAE1     and     ax, 1
.text:000055555555EAE5     cmp     ax, 1                       ; X & 1 == 1 ? (check if X is odd)
.text:000055555555EAE9     jz      short X_IS_ODD_55555555EAFE
.text:000055555555EAEB     jmp     short loc_55555555EB0D
.text:000055555555EAED ; ---------------------------------------------------------------------------
.text:000055555555EAED
.text:000055555555EAED RETURN_55555555EAED:                    ; CODE XREF: gen_xor_byte_55555555EAB0+2Aj
.text:000055555555EAED     mov     ax, [rsp+8+varZ_6]
.text:000055555555EAF2     mov     cl, al
.text:000055555555EAF4     mov     [rsp+8+var_7], cl
.text:000055555555EAF8     mov     al, [rsp+8+var_7]
.text:000055555555EAFC     pop     rcx
.text:000055555555EAFD     retn
.text:000055555555EAFE ; ---------------------------------------------------------------------------
.text:000055555555EAFE
.text:000055555555EAFE X_IS_ODD_55555555EAFE:                  ; CODE XREF: gen_xor_byte_55555555EAB0+39j
.text:000055555555EAFE     mov     ax, [rsp+8+varY_4]
.text:000055555555EB03     xor     ax, [rsp+8+varZ_6]
.text:000055555555EB08     mov     [rsp+8+varZ_6], ax          ; Z ^= Y
.text:000055555555EB0D
.text:000055555555EB0D loc_55555555EB0D:                       ; CODE XREF: gen_xor_byte_55555555EAB0+3Bj
.text:000055555555EB0D     mov     ax, [rsp+8+varX_2]
.text:000055555555EB12     shr     ax, 1
.text:000055555555EB16     mov     [rsp+8+varX_2], ax          ; X >>= 1
.text:000055555555EB1B     mov     ax, [rsp+8+varY_4]
.text:000055555555EB20     shl     ax, 1
.text:000055555555EB24     mov     [rsp+8+varY_4], ax          ; Y <<= 1
.text:000055555555EB29     cmp     [rsp+8+varY_4], 100h
.text:000055555555EB30     jb      short BELOW_256_55555555EB40
.text:000055555555EB32     mov     ax, [rsp+8+varY_4]
.text:000055555555EB37     xor     ax, 11Dh
.text:000055555555EB3B     mov     [rsp+8+varY_4], ax          ; Y ^= 0x11D
.text:000055555555EB40
.text:000055555555EB40 BELOW_256_55555555EB40:                 ; CODE XREF: gen_xor_byte_55555555EAB0+80j
.text:000055555555EB40     jmp     short LOOP_55555555EAD4
.text:000055555555EB40 gen_xor_byte_55555555EAB0 endp
```

The decompiled version is shown below:
```python
def gen_xor_byte(x, y):
    z = 0
    
    while x > 0:
        if x & 1 == 1:
            z ^= y;
        
        x >>= 1
        y <<= 1

        if y >= 0x100:
            y ^= 0x11D

    return z & 0xff
```

Now that we have the encryption algorithm, let's see in practice how it works:
Assume that password is `ispo\n`. On the first round we have:
```
 0: f(74, 69) = 99 ^ 73 = EA
 1: f(40, 69) = 5F ^ 70 = 2F
 2: f(34, 69) = C6 ^ 6F = A9
 3: f(AE, 69) = 1B ^ 0A = 11
 4: f(36, 69) = 14 ^ 00 = 14
 5: f(7E, 69) = 24 ^ 00 = 24
 6: f(10, 69) = DE ^ 00 = DE
 7: f(C2, 69) = 33 ^ 00 = 33
 8: f(A2, 69) = CD ^ 00 = CD
 9: f(21, 69) = C8 ^ 00 = C8
10: f(21, 69) = C8 ^ 00 = C8
11: f(9D, 69) = DF ^ 00 = DF
12: f(B0, 69) = C1 ^ 00 = C1
13: f(C5, 69) = 31 ^ 00 = 31
14: f(E1, 69) = 29 ^ 00 = 29
15: f(0C, 69) = D6 ^ 00 = D6
16: f(3B, 69) = AB ^ 00 = AB
17: f(37, 69) = 7D ^ 00 = 7D
18: f(FD, 69) = 21 ^ 00 = 21
19: f(E4, 69) = F9 ^ 00 = F9
20: f(94, 69) = D9 ^ 00 = D9
21: f(2F, 69) = CC ^ 00 = CC
22: f(B3, 69) = 7A ^ 00 = 7A
23: f(B9, 69) = C7 ^ 00 = C7
24: f(18, 69) = B1 ^ 00 = B1
25: f(8A, 69) = 03 ^ 00 = 03
26: f(FD, 69) = 21 ^ 00 = 21
27: f(14, 69) = 67 ^ 00 = 67
28: f(8E, 69) = BA ^ 00 = BA
29: f(37, 69) = 7D ^ 00 = 7D
30: f(AC, 69) = C9 ^ 00 = C9
31: f(58, 69) = EE ^ 00 = EE

69 EA 2F A9 11 14 24 DE 33 CD C8 C8 DF C1 31 29
D6 AB 7D 21 F9 D9 CC 7A C7 B1 03 21 67 BA 7D C9
EE
``` 

Function `f` is the `gen_xor_byte_55555555EAB0`. `flag[0] = 0x69 = 'i'` is used to generate the
stream cipher to encrypt `flag[1:]`. At the end `flag[0]` goes to the front of intermediate
ciphertext (total length is **33** bytes). One the second round we start from this ciphertext
and we repeat:
```
 0: f(74, EA) = 9D ^ 2F = B2
 1: f(40, EA) = 18 ^ A9 = B1
 2: f(34, EA) = 85 ^ 11 = 94
 3: f(AE, EA) = 79 ^ 14 = 6D
 4: f(36, EA) = 4C ^ 24 = 68
 5: f(7E, EA) = 57 ^ DE = 89
 6: f(10, EA) = 06 ^ 33 = 35
 7: f(C2, EA) = E1 ^ CD = 2C
 8: f(A2, EA) = F5 ^ C8 = 3D
 9: f(21, EA) = E6 ^ C8 = 2E
10: f(21, EA) = E6 ^ DF = 39
11: f(9D, EA) = 50 ^ C1 = 91
12: f(B0, EA) = 3A ^ 31 = 0B
13: f(C5, EA) = 4D ^ 29 = 64
14: f(E1, EA) = CE ^ D6 = 18
15: f(0C, EA) = 8C ^ AB = 27
16: f(3B, EA) = 2A ^ 7D = 57
17: f(37, EA) = A6 ^ 21 = 87
18: f(FD, EA) = 44 ^ F9 = BD
19: f(E4, EA) = AB ^ D9 = 72
20: f(94, EA) = B9 ^ CC = 75
21: f(2F, EA) = A3 ^ 7A = D9
22: f(B3, EA) = 19 ^ C7 = DE
23: f(B9, EA) = D3 ^ B1 = 62
24: f(18, EA) = 05 ^ 03 = 06
25: f(8A, EA) = FA ^ 21 = DB
26: f(FD, EA) = 44 ^ 67 = 23
27: f(14, EA) = 89 ^ BA = 33
28: f(8E, EA) = 75 ^ 7D = 08
29: f(37, EA) = A6 ^ C9 = 6F
30: f(AC, EA) = B0 ^ EE = 5E
31: f(58, EA) = 1D ^ 00 = 1D

69 EA B2 B1 94 6D 68 89 35 2C 3D 2E 39 91 0B 64
18 27 57 87 BD 72 75 D9 DE 62 06 DB 23 33 08 6F
5E 1D
```

Now our ciphertext is 1 byte more than the previous one. Moving on, after 16 rounds, our ciphertext
will be:
```
69 EA B2 F4 23 C2 01 93 C8 6D 37 98 39 EA B5 A3
0B 15 1D 30 41 F7 4F 25 D6 10 97 EF B0 8C 40 C0
5B 70 9F B7 12 9C 7E 25 AF 28 E4 BD 7B E8 45 3C
```

We discard the first 16 bytes and the remaining ones are the ciphertext:
```
	0B 15 1D 30 41 F7 4F 25 D6 10 97 EF B0 8C 40 C0 5B 70 9F B7 12 9C 7E 25 AF 28 E4 BD 7B E8 45 3C
```

We can verify that of course:
```
ispo@leet:~/ctf/codegate_2020/RS$ echo 'ispo' > flag; ./rs
	0b 15 1d 30 41 f7 4f 25 d6 10 97 ef b0 8c 40 c0 5b 70 9f b7 12 9c 7e 25 af 28 e4 bd 7b e8 45 3c 
```

For the full output take a look at [rs_crack.py](./rs_crack.py).
___


### Breaking the algorithm

Our goal is to decrypt [result](./result), which consists of 4 blocks (we can just crack them
individually):
```
	ef 43 4b 3f 5e b9 f0 d0 8c b5 7e 6f 7b c8 a6 7b 09 e2 61 9d 98 03 5f 56 5d 66 82 0b 9e 2b 76 92
	5b c3 dc f2 3c d0 b6 81 60 34 a5 66 ca bd 7d 6a 00 fe e4 0b 44 e1 ba 81 cb ae 8b 24 0b a5 1f 6d
	ba 0e 61 1a 30 a7 77 51 23 41 a6 1a c0 7f 71 71 9f d5 93 e5 38 ce 52 8b 25 86 b3 12 b7 a7 1c 43
	b4 08 81 47 ae d6 18 46 c5 6b 69 63 0b cc 95 ab 49 53 6f de be 2f 2e d9 9b dc dd 76 69 a4 f0 58
```

Notice in the previous example, that the last byte of the intermediate text (before XOR) is NULL. 
This is always the case since the first byte of the plaintext is used to generate the stream
and the remaining `N-1` bytes are XORed. Therefore on the last iteration the plaitext byte will 
always be NULL. At the end the first byte goes in front, so ciphertext is 1 byte longer that
the plaintext.


Let's get the first block. The last byte is `0x92`. That is, `f(58, X) = 92 ^ 00 = 92`.
Finding `X` is trivial, as we can simply brute force all 256 values and see which one gives us
`92`. Since there's one a unique solution, we find that `X = 7E`. Please note that we
can simply cache them into a dictionary instead of brute forcing them each time. Knowing that,
we can recover the stream cipher, XOR it with the cipher and get the intermediate ciphertext
for the *15th* round:
```
 0: f(74, 7E) = DB ^ EF = 34
 1: f(40, 7E) = F6 ^ 43 = B5
 2: f(34, 7E) = 2D ^ 4B = 66
 3: f(AE, 7E) = 44 ^ 3F = 7B
 4: f(36, 7E) = D1 ^ 5E = 8F
 5: f(7E, 7E) = F0 ^ B9 = 49
 6: f(10, 7E) = B3 ^ F0 = 43
 7: f(C2, 7E) = FB ^ D0 = 2B
 8: f(A2, 7E) = 76 ^ 8C = FA
 9: f(21, 7E) = 05 ^ B5 = B0
10: f(21, 7E) = 05 ^ 7E = 7B
11: f(9D, 7E) = 0E ^ 6F = 61
12: f(B0, 7E) = 39 ^ 7B = 42
13: f(C5, 7E) = 9C ^ C8 = 54
14: f(E1, 7E) = 02 ^ A6 = A4
15: f(0C, 7E) = 32 ^ 7B = 49
16: f(3B, 7E) = 9D ^ 09 = 94
17: f(37, 7E) = AF ^ E2 = 4D
18: f(FD, 7E) = 83 ^ 61 = E2
19: f(E4, 7E) = 99 ^ 9D = 04
20: f(94, 7E) = A7 ^ 98 = 3F
21: f(2F, 7E) = CB ^ 03 = C8
22: f(B3, 7E) = BB ^ 5F = E4
23: f(B9, 7E) = 90 ^ 56 = C6
24: f(18, 7E) = 64 ^ 5D = 39
25: f(8A, 7E) = DA ^ 66 = BC
26: f(FD, 7E) = 83 ^ 82 = 01
27: f(14, 7E) = 56 ^ 0B = 5D
28: f(8E, 7E) = 3F ^ 9E = A1
29: f(37, 7E) = AF ^ 2B = 84
30: f(AC, 7E) = B8 ^ 76 = CE
31: f(58, 7E) = 92 ^ 92 = 00
```

Now we can repeat the process and recover the intermediate ciphertext for the **14th** round.
This process repeats until the **1st** round:
```
 0: f(74, 00) = 00 ^ 43 = 43
 1: f(40, 00) = 00 ^ 4F = 4F
 2: f(34, 00) = 00 ^ 44 = 44
 3: f(AE, 00) = 00 ^ 45 = 45
 4: f(36, 00) = 00 ^ 47 = 47
 5: f(7E, 00) = 00 ^ 41 = 41
 6: f(10, 00) = 00 ^ 54 = 54
 7: f(C2, 00) = 00 ^ 45 = 45
 8: f(A2, 00) = 00 ^ 32 = 32
 9: f(21, 00) = 00 ^ 30 = 30
10: f(21, 00) = 00 ^ 32 = 32
11: f(9D, 00) = 00 ^ 30 = 30
12: f(B0, 00) = 00 ^ 7B = 7B
13: f(C5, 00) = 00 ^ 52 = 52
14: f(E1, 00) = 00 ^ 53 = 53
15: f(0C, 00) = 00 ^ 5F = 5F
16: f(3B, 00) = 00 ^ 00 = 00
17: f(37, 00) = 00 ^ 00 = 00
18: f(FD, 00) = 00 ^ 00 = 00
19: f(E4, 00) = 00 ^ 00 = 00
20: f(94, 00) = 00 ^ 00 = 00
21: f(2F, 00) = 00 ^ 00 = 00
22: f(B3, 00) = 00 ^ 00 = 00
23: f(B9, 00) = 00 ^ 00 = 00
24: f(18, 00) = 00 ^ 00 = 00
25: f(8A, 00) = 00 ^ 00 = 00
26: f(FD, 00) = 00 ^ 00 = 00
27: f(14, 00) = 00 ^ 00 = 00
28: f(8E, 00) = 00 ^ 00 = 00
29: f(37, 00) = 00 ^ 00 = 00
30: f(AC, 00) = 00 ^ 00 = 00
31: f(58, 00) = 00 ^ 00 = 00
```

At this point we can recover the first part of the flag: `CODEGATE2020{RS_`.
We do the same for the other blocks and we decrypt all parts of the flag:
`m4y_st4nd_f0r_R3`, `v3rS1ng_RuSt_0r_` and `R33d_S010m0n}`. We concatenate
all these to get the final flag: `CODEGATE2020{RS_m4y_st4nd_f0r_R3v3rS1ng_RuSt_0r_R33d_S010m0n}`


For more details please take a look at [rs_crack.py](./rs_crack.py).

___

