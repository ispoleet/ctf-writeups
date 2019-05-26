
## Google CTF 2017 - inst_prof (PWN 435pt)
##### 17-18/06/2017 (48hr)
___
### Description

Please help test our new compiler micro-service

Challenge running at 35.187.118.28:1337

882a86805e2dfdda-inst_prof


___
### Solution

This challenge is about shellcoding. We're given a PIE binary that calls do_test() an infinte 
number of times:

```assembly
.text:000055E03B3918C0                   loc_55E03B3918C0:
.text:000055E03B3918C0 31 C0                 xor     eax, eax
.text:000055E03B3918C2 E8 F9 01 00 00        call    do_test
.text:000055E03B3918C7 EB F7                 jmp     short loc_55E03B3918C0
```

do_test() is fairly simple:

```assembly
.text:000055E03B391AC0                   do_test proc near
.text:000055E03B391AC0
.text:000055E03B391AC0                   buf = qword ptr -18h
.text:000055E03B391AC0
.text:000055E03B391AC0 55                    push    rbp
.text:000055E03B391AC1 31 C0                 xor     eax, eax
.text:000055E03B391AC3 48 89 E5              mov     rbp, rsp
.text:000055E03B391AC6 41 54                 push    r12
.text:000055E03B391AC8 53                    push    rbx
.text:000055E03B391AC9 48 83 EC 10           sub     rsp, 10h
.text:000055E03B391ACD E8 1E FF FF FF        call    alloc_page
.text:000055E03B391AD2 48 89 C3              mov     rbx, rax
.text:000055E03B391AD5 48 8D 05 24 01 00+    lea     rax, template               ; "¦"
.text:000055E03B391ADC 48 8D 7B 05           lea     rdi, [rbx+5]
.text:000055E03B391AE0 48 8B 10              mov     rdx, [rax]
.text:000055E03B391AE3 48 89 13              mov     [rbx], rdx
.text:000055E03B391AE6 8B 50 08              mov     edx, [rax+8]
.text:000055E03B391AE9 89 53 08              mov     [rbx+8], edx
.text:000055E03B391AEC 0F B7 50 0C           movzx   edx, word ptr [rax+0Ch]
.text:000055E03B391AF0 0F B6 40 0E           movzx   eax, byte ptr [rax+0Eh]
.text:000055E03B391AF4 66 89 53 0C           mov     [rbx+0Ch], dx
.text:000055E03B391AF8 88 43 0E              mov     [rbx+0Eh], al
.text:000055E03B391AFB E8 B0 FF FF FF        call    read_inst
.text:000055E03B391B00 48 89 DF              mov     rdi, rbx
.text:000055E03B391B03 E8 18 FF FF FF        call    make_page_executable
.text:000055E03B391B08 0F 31                 rdtsc
.text:000055E03B391B0A 48 C1 E2 20           shl     rdx, 20h
.text:000055E03B391B0E 49 89 C4              mov     r12, rax
.text:000055E03B391B11 31 C0                 xor     eax, eax
.text:000055E03B391B13 49 09 D4              or      r12, rdx
.text:000055E03B391B16 FF D3                 call    rbx
.text:000055E03B391B18 0F 31                 rdtsc
.text:000055E03B391B1A BF 01 00 00 00        mov     edi, 1                      ; fd
.text:000055E03B391B1F 48 C1 E2 20           shl     rdx, 20h
.text:000055E03B391B23 48 8D 75 E8           lea     rsi, [rbp+buf]              ; buf
.text:000055E03B391B27 48 09 C2              or      rdx, rax
.text:000055E03B391B2A 4C 29 E2              sub     rdx, r12
.text:000055E03B391B2D 48 89 55 E8           mov     [rbp+buf], rdx
.text:000055E03B391B31 BA 08 00 00 00        mov     edx, 8                      ; n
.text:000055E03B391B36 E8 75 FC FF FF        call    _write
.text:000055E03B391B3B 48 83 F8 08           cmp     rax, 8
.text:000055E03B391B3F 75 11                 jnz     short EXIT_55E03B391B52
.text:000055E03B391B41 48 89 DF              mov     rdi, rbx
.text:000055E03B391B44 E8 F7 FE FF FF        call    free_page
.text:000055E03B391B49 48 83 C4 10           add     rsp, 10h
.text:000055E03B391B4D 5B                    pop     rbx
.text:000055E03B391B4E 41 5C                 pop     r12
.text:000055E03B391B50 5D                    pop     rbp
.text:000055E03B391B51 C3                    retn
.text:000055E03B391B52
.text:000055E03B391B52                   EXIT_55E03B391B52:
.text:000055E03B391B52 31 FF                 xor     edi, edi                    ; status
.text:000055E03B391B54 E8 D7 FC FF FF        call    _exit
.text:000055E03B391B54                   do_test endp
.text:000055E03B391B54
```

What do_test() does? It allocates an mmap R+W region and writes a "template" to it. The
template is this:
```assembly
debug005:00007FDB7D361000 B9 00 10 00 00        mov     ecx, 1000h
debug005:00007FDB7D361005
debug005:00007FDB7D361005                   loc_7FDB7D361005:
debug005:00007FDB7D361005 90                    nop
debug005:00007FDB7D361006 90                    nop
debug005:00007FDB7D361007 90                    nop
debug005:00007FDB7D361008 90                    nop
debug005:00007FDB7D361009 83 E9 01              sub     ecx, 1
debug005:00007FDB7D36100C 75 F7                 jnz     short loc_7FDB7D361005
debug005:00007FDB7D36100E C3                    retn
debug005:00007FDB7D36100E                   ; 
```

Then it overwrites the 4 NOP's with user's input and makes region R+X. Then it
executes it:
```assembly
.text:000055E03B391B16 FF D3                 call    rbx
```

Finally it calls _rdtsc_ to print the number of cycles between and it frees the allocated
memory.


So, nothing really to "exploit" here; All we have to do is to carefully select which
instructions to execute. The main problem here is that there are a lot of instructions 
between the execution of 2 consecutive "injected" instructions; therefore it's hard to 
keep any state. Even worse in x64, most instructions are >4 bytes long so we're really 
limiting our options. Finally we should not forget that our instruction gets executed
4096 times, so instructions like "add", "sub", etc. will really screw up the computations.


Our attack plan is to use this functionality by carefully injecting some instructions, 
in order to 
create a ROP chain in the stack (having a ROP chain makes exploitation very easy as 
there's already code for calling mprotect() and read()). The ROP chain will create an 
RWX memory region and will use write() to write attacker's shellcode in it. 
Then it will simply return to that region and will execute the arbitrary payload.
Note here the escalation:
```
	4 byte instruction --> ROP --> Shellcode
```

One last problem here is that binary is PIE, so we can't really hardcode any addresses.
Hence, we either have to leak an address (through write() call), or create the ROP chain,
using offsets and not addresses (we're implementing the 2nd approach; details in the exploit
file).


Please refer to the exploit file (inst_prof_expl.py) for a detailed description of the
attack. After all we simply send the whole payload to the server and we get the flag:
```
ispo@ispo:~/google_ctf_17$ python inst_prof_expl.py | nc 35.187.118.28 1337
initializing prof...ready
	[..... TRUNCATED FOR BREVITY .....]

	uid=1337(user) gid=1337(user) groups=1337(user)
	
	Sun May 21 23:19:40 UTC 2017
	
	total 20
	-rwxr-xr-x 1 user user    37 May 15 20:13 flag.txt
	-rwxr-xr-x 1 user user 13316 May 15 20:13 inst_prof
	
	CTF{0v3r_4ND_0v3r_4ND_0v3r_4ND_0v3r}
```

___
