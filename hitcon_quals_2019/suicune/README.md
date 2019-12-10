

## HITCON CTF quals 2019 - suicune (Reversing 305)
##### 12/10 - 14/10/2019 (48hr)
___

### Description: 


Apparently it's not efficient enough..

```
suicune-599605a86b27d46ac13e20a224880a23be4e4e0c.tar.gz
```
___


### Solution

This is program written in crystal. Analysis starts from `__crystal_main`. Everything seems to be
inside this huge function (no other user functions are invoked).
```
04dd5a70faea88b76e4733d0fa346b086e2c0efd7d2815e3b6ca118ab945719970642b2929b18a71b28d87855796e344d8
```

Before we start reversing this mess, we play a little bit with the program:
```
ispo@nogirl:~/ctf/hitcon_ctf_2019/suicune$ ./suicune ABC 1
    d6992e

ispo@nogirl:~/ctf/hitcon_ctf_2019/suicune$ ./suicune ABC 2
    3dfee2

ispo@nogirl:~/ctf/hitcon_ctf_2019/suicune$ ./suicune ABCD 2
    f94bb7e5

ispo@nogirl:~/ctf/hitcon_ctf_2019/suicune$ ./suicune ABxx 2
    f94b8cd9

ispo@nogirl:~/ctf/hitcon_ctf_2019/suicune$ ./suicune .BC. 2
    964bb78f

ispo@nogirl:~/ctf/hitcon_ctf_2019/suicune$ ./suicune .BC. 99999999999999
    Unhandled exception: Invalid Int32: 99999999999999 (ArgumentError)
      from ???
      from ???
      from __crystal_main
      from main
      from __libc_start_main
      from _start
      from ???
```

We see from here that each character gets mapped to a single byte. Furthermore, each character
gets encrypted independently from the others. The encryptions depends on the length of the flag
and, of course, on the key. The is a 32-bit number. Given the output, we know that flag is **49**
characters long. We also know that flag starts with `hitcon{` and ends with `}`, so we can brute
force the key by supplying 49-character flags that start with `hitcon` and check whether output
starts with `04dd5a70faea`. This should like a great plan, but it's too good to be true...
Unfortunately, when we try longer flags, programs takes for ever to complete:
```
ispo@nogirl:~/ctf/hitcon_ctf_2019/suicune$ time ./suicune AAAAAAAAA 1
    3ab3dd97a5afbe9b32

    real    0m0.298s
    user    0m0.308s
    sys 0m0.000s

ispo@nogirl:~/ctf/hitcon_ctf_2019/suicune$ time ./suicune AAAAAAAAAB 1
    1f93f9e4f55823c32e45

    real    0m2.807s
    user    0m2.888s
    sys 0m0.076s

ispo@nogirl:~/ctf/hitcon_ctf_2019/suicune$ time ./suicune AAAAAAAAABC 1
    6a039982d8257acd865741

    real    0m30.114s
    user    0m30.820s
    sys 0m0.972s
```

So each character that we add blows up the complexity. That is we expect algorithm to have an
O(2^N) or something exponential. To be honest I should have expect that since the challenge
description itself mentions it: `it's not efficient`. So, it's time to go back to IDA :D

We see that most of the code is badly auto-generated, redundant and with no optimizations (or it
is just obfuscated :P), so can easily ignore it from our analysis. When program starts it first
reads the flag and copies it into the heap. Then i reads the key:
```assembly
.text:00005555555608F0 START_5555555608F0:                         ; CODE XREF: __crystal_main+892j
.text:00005555555608F0         mov     [rsp+198h+var_160], rax
.text:00005555555608F5         mov     [rax+4], ebx
.text:00005555555608F8         mov     rdi, cs:_ONCE_STATE
.text:00005555555608FF         lea     rsi, ARGV_init
.text:0000555555560906         lea     rdx, _ARGV_init
.text:000055555556090D         call    __crystal_once
.text:0000555555560912         mov     rax, cs:ARGV
.text:0000555555560919         cmp     dword ptr [rax+4], 1
.text:000055555556091D         jle     ARGV_INDEX_ERROR_555555563035
.text:0000555555560923         mov     r12, 5851F42D4C957F2Dh
.text:000055555556092D         mov     rax, [rax+10h]
.text:0000555555560931         mov     rdi, [rax+8]
.text:0000555555560935         call    _String_to_i_Int32          ; read argv[2] (= key)
.text:000055555556093A         movzx   ebx, ax                     ; truncate to 16 bits!
.text:000055555556093D         mov     edi, 18h
.text:0000555555560942         call    GC_malloc_atomic            ; allocate an 0x18 byte buffer: bufA
.text:0000555555560947         mov     r13, rax
.text:000055555556094A         mov     qword ptr [rax], 9Eh        ; bufA[0] = 0x9e (qword)
.text:0000555555560951         mov     qword ptr [rax+10h], 1      ; bufA[2] = 1 (qword)
.text:0000555555560959         imul    rbx, r12                    ; rbx = key * 0x5851F42D4C957F2D % 2**64
.text:000055555556095D         lea     rax, [rbx+r12+1]            ; rax = (key  + 1) * 0x5851F42D4C957F2D + 1
.text:0000555555560962         mov     [r13+8], rax                ; bufA[1] = ((key  + 1) * 0x5851F42D4C957F2D + 1) % 2**64 (qword)
.text:0000555555560966         xor     eax, eax
```

Very important note here: **Key is limited to 16 bits. That is we can brute force it!**
Right after code starts getting interesting:
```assembly
.text:000055555556099C         call    GC_malloc
.text:00005555555609A1         mov     r15, rax
.text:00005555555609A4         mov     qword ptr [rax], 12h        ; bytes 1-7 are set to 0
.text:00005555555609AB         mov     qword ptr [rax+8], 0
.text:00005555555609B3         mov     qword ptr [rax+10h], 0
.text:00005555555609BB         mov     eax, [rbp+8]                ; eax is 0
.text:00005555555609BE         cmp     eax, [rbp+4]                ; compare 0 with 0
.text:00005555555609C1         jl      short NEXT_2_5555555609E0   ; jump is always taken
.text:00005555555609C3         jmp     short NEXT_4_555555560A00
.text:00005555555609C3 ; ---------------------------------------------------------------------------
.text:00005555555609C5         align 10h
.text:00005555555609D0
.text:00005555555609D0 NEXT_3_5555555609D0:                        ; CODE XREF: __crystal_main+9BCj
.text:00005555555609D0                                             ; __crystal_main+A07j
.text:00005555555609D0         mov     rdi, r15
.text:00005555555609D3         call    _Array_UInt8_@Array_T_____UInt8__Array_UInt8_
.text:00005555555609D8         mov     eax, [rbp+8]
.text:00005555555609DB         cmp     eax, [rbp+4]
.text:00005555555609DE         jge     short NEXT_4_555555560A00
.text:00005555555609E0
.text:00005555555609E0 NEXT_2_5555555609E0:                        ; CODE XREF: __crystal_main+981j
.text:00005555555609E0         lea     ecx, [rax+1]
.text:00005555555609E3         mov     [rbp+8], ecx
.text:00005555555609E6         cmp     eax, 100h
.text:00005555555609EB         jnb     OVERFLOW_555555563030
.text:00005555555609F1         movzx   esi, al
.text:00005555555609F4         mov     eax, 0A5h
.text:00005555555609F9         cmp     eax, 45h
.text:00005555555609FC         jnz     short NEXT_3_5555555609D0   ; 45 != A5 ? jump always taken!
.text:00005555555609FE         jmp     short loc_555555560A49
.text:0000555555560A00 ; ---------------------------------------------------------------------------
.text:0000555555560A00
.text:0000555555560A00 NEXT_4_555555560A00:                        ; CODE XREF: __crystal_main+983j
.text:0000555555560A00                                             ; __crystal_main+99Ej
.text:0000555555560A00         mov     rdi, cs:_ONCE_STATE
```

We can see from here that we have jumps that are always taken no matter what. Code is full of
these statements. Fortunately it's not hard to spot them. However they add some confusion to the
execution flow. I think it's clear that there's some obfuscation going on here as the control
flow jumps back and forth...

Moving on, code creates a 256-byte array and fills it with values 0x00 to 0xff.
```assembly
.text:0000555555560AA0 LOOP_1_555555560AA0:                        ; CODE XREF: __crystal_main+B0Dj
.text:0000555555560AA0         test    ebp, ebp                    ; ebp = N
.text:0000555555560AA2         jle     ERROR_555555562F7B
.text:0000555555560AA8         mov     eax, ebp
.text:0000555555560AAA         neg     eax                         ; eax = ~N
.text:0000555555560AAC         xor     edx, edx
.text:0000555555560AAE         div     ebp                         ; eax = ~N / N;  edx = ~N % N
.text:0000555555560AB0         mov     rcx, [r13+8]                ; rcx = bufA[1]
.text:0000555555560AB4         mov     rdi, [r13+10h]              ; rdi = bufA[2]
.text:0000555555560AB8         test    edx, edx
.text:0000555555560ABA         jz      short ELSE_MOD_ZERO_555555560B00 ; rbx = bufA[1] (else branch)
.text:0000555555560ABC         neg     edx                         ; edx = ~(~N% N)
.text:0000555555560ABE         mov     rbx, rcx                    ; this code is garbage
....
.text:0000555555560B00
.text:0000555555560B00 ELSE_MOD_ZERO_555555560B00:                 ; CODE XREF: __crystal_main+A7Aj
.text:0000555555560B00         mov     rbx, rcx                    ; rbx = bufA[1] (else branch)
.text:0000555555560B03         imul    rbx, r12                    ; rbx = bufA[1] * 0x5851F42D4C957F2D % 2**64
.text:0000555555560B07         add     rbx, rdi                    ; rbx = bufA[1] * 0x5851F42D4C957F2D + buf[2]
.text:0000555555560B0A         mov     rax, rcx
.text:0000555555560B0D         shr     rax, 12h                    ; rax = bufA[1] >> 18
.text:0000555555560B11         xor     rax, rcx                    ; rax = bufA[1] ^ (bufA[1] >> 18)
.text:0000555555560B14         shr     rax, 1Bh                    ; rax = (bufA[1] ^ (bufA[1] >> 18)) >>  27
.text:0000555555560B18         shr     rcx, 3Bh                    ; rcx  = bufA[1] >> 59
.text:0000555555560B1C         ror     eax, cl                     ; ror((bufA[1] ^ (bufA[1] >> 18)) >> 27, bufA[1] >> 59) = a
.text:0000555555560B1E
.text:0000555555560B1E MOVE_ON_555555560B1E:                       ; CODE XREF: __crystal_main+AB2j
.text:0000555555560B1E         mov     [r13+8], rbx                ; bufA[1] = bufA[1] * 0x5851F42D4C957F2D + buf[2]
.text:0000555555560B22         xor     edx, edx
.text:0000555555560B24         div     ebp                         ; eax = a / N;  edx = a % N
.text:0000555555560B26         movsxd  rax, edx
.text:0000555555560B29         mov     cl, [r8+rax]                ; cl = tbl_A[a % N]
.text:0000555555560B2D         movsxd  rdx, esi
.text:0000555555560B30         mov     bl, [r8+rdx]                ; bl = tbl_A[i - 1]
.text:0000555555560B34         mov     [r8+rdx], cl
.text:0000555555560B38         mov     [r8+rax], bl                ; swap(tbl_A[a % N], tbl_A[i - 1])
.text:0000555555560B3C         cmp     edx, 1
.text:0000555555560B3F         jz      short FINISH_STAGE_1_555555560B60
.text:0000555555560B41         dec     esi                         ; --iter
.text:0000555555560B43         jo      OVERFLOW_555555563030
.text:0000555555560B49         mov     ebp, esi
.text:0000555555560B4B         inc     ebp
.text:0000555555560B4D         jno     LOOP_1_555555560AA0         ; ebp = N
.text:0000555555560B53         jmp     OVERFLOW_555555563030
```

I think it's clear what's going on here: We just shuffe the table using they key as a seed.
After shuffling, program selects the first `len(flag)` characters from `tbl_A` and starts
permuting them many times. At this point it comes the exponential complexity: Instead of
calculating the N-th permutation directly, program generates one permutation after other till
it hits the desired one, resulting in an `O(N!)` complexity.


After the permutation, program "zips & xors":
```assembly
.text:0000555555561370 loc_555555561370:                           ; CODE XREF: __crystal_main+12CAj
.text:0000555555561370                                             ; __crystal_main+12D4j
.text:0000555555561370         movsxd  rax, dword ptr [r15]
.text:0000555555561373         mov     [rbx+rax*2], r14b
.text:0000555555561377         mov     [rbx+rax*2+1], r12b
.text:000055555556137C         mov     ebx, [r15]                  ; zip!
.text:000055555556137F         inc     ebx
.text:0000555555561381         jo      OVERFLOW_555555563030
.text:0000555555561387         mov     [r15], ebx
.text:000055555556138A         inc     rbp
.text:000055555556138D         movsxd  rax, dword ptr [rcx+4]
.text:0000555555561391         cmp     rbp, rax
.text:0000555555561394         jl      LOOP_6_ZIP_555555561290
.text:000055555556139A         jmp     short loc_5555555613A3
.text:000055555556139A ; ---------------------------------------------------------------------------
.text:000055555556139C         align 20h
.text:00005555555613A0
.text:00005555555613A0 loc_5555555613A0:                           ; CODE XREF: __crystal_main+123Dj
.text:00005555555613A0         mov     ebx, [r15]
.text:00005555555613A3
.text:00005555555613A3 loc_5555555613A3:                           ; CODE XREF: __crystal_main+135Aj
.text:00005555555613A3         mov     edi, ebx                    ; n
.text:00005555555613A5         call    _Array_UInt8_@Array_T___new_Int32__Array_UInt8_
.text:00005555555613AA         mov     r14, rax
.text:00005555555613AD         test    ebx, ebx
.text:00005555555613AF         mov     rbp, [rsp+198h+var_188]
.text:00005555555613B4         jle     short loc_5555555613D7
.text:00005555555613B6         mov     rdi, [r14+10h]
.text:00005555555613BA         mov     ecx, ebx
.text:00005555555613BC         xor     edx, edx
.text:00005555555613BE         nop
.text:00005555555613BF         nop
.text:00005555555613C0
.text:00005555555613C0 LOOP_7_5555555613C0:                        ; CODE XREF: __crystal_main+1395j
.text:00005555555613C0         mov     rsi, [rbp+10h]
.text:00005555555613C4         movzx   eax, byte ptr [rsi+rdx*2+1]
.text:00005555555613C9         xor     al, [rsi+rdx*2]             ; xor tuples from zip
.text:00005555555613CC         mov     [rdi+rdx], al
.text:00005555555613CF         inc     rdx
.text:00005555555613D2         cmp     rcx, rdx
.text:00005555555613D5         jnz     short LOOP_7_5555555613C0
```

That is, it XORs the flag with the permuted `tbl_A` and reverses the table (that is we have a
stream cipher). The result is used as a new flag and the whole process repeats `16` times.
After `16` rounds the resulting ciphertext is the output. The complete algorithm is shown
in `encrypt_simple` function in [./suicune_crack.py](./suicune_crack.py).


### Breaking the ciphertext
This challenge reminded me the [counter challenge from Google CTF 2017](https://github.com/ispoleet/ctf-writeups/tree/master/google_ctf_2017/counter), where I had to optimize an algorithm to find the
flag. Solution is simple here: All we have to do is to replace the permutation computation. It
is possible to compute directly the K-th permutation, instead of calculating them one by one:
```python
def find_kth_permutation(N, k):
    array = [i for i in range(1, N+1)]
    perm  = [0]*N

    # if k is too large, give the sorted-in-reverse-order permutation
    k = min(k, factorial(N)) - 1

    for i in xrange(len(array)):
        fact = factorial(N-1-i)

        # find d, r such that: k = d*(n-1)! + r, subject to: d >= 0 and 0 < r <= n!
        d, r = k // fact, k % fact
        k = r

        perm[i] = array[d]
        array = array[:d] + array[d+1:]

    return perm
```

After applying this change, we can encrypt any flag quickly.

Since algorithm is a stream cipher, decryption and encryption should be the same. We can easily
verify that:
```
$ ispo@nogirl:~/ctf/hitcon_ctf_2019/suicune$ ./suicune KYRIAKOS 31337
    6a71b14abb639470
$ ispo@nogirl:~/ctf/hitcon_ctf_2019/suicune$ ./suicune $(python -c "print ''.join(chr(a) for a in [0x6a,0x71,0xb1,0x4a,0xbb,0x63,0x94,0x70])") 31337
    4b595249414b4f53
```

Which decodes back to "KYRIAKOS". Therefore all we have to do is to run our algorithm to the given
flag `04dd5a70faea88b76e4733d0fa346b086e2c0efd7d2815e3b6ca118ab945719970642b2929b18a71b28d87855796e344d8`
for each possible key between `0` and `65536`. We know that flag starts with `hitcon{` so we can
check whether the decoded plaintext starts with it.

After running [./suicune_crack.py](./suicune_crack.py) for about 9 minutes, we find the
desired key `45193`, which gives us our flag `hitcon{nth_perm_Ruby_for_writing_X_C_for_running}`.
___
