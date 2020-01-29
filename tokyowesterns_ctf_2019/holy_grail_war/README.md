
## TokyoWesterns CTF 5th 2019 - Holy Grail War (RE 314)
##### 31-02/09/2019 (48hr)
___

### Solution


A quick search of function names (e.g., `IsolateEnterStub_JavaMainWrapper_run_...`) indicates
that we have a GraalVM binary, which is a universal VM emulator for JAVA, JavaScript, Python
and so on. I won't get into details just the highlights. Our goal is to break the cipher at
[output.txt](./output.txt):
```
d4f5f0aa8aeee7c83cd8c039fabdee6247d0f5f36edeb24ff9d5bc10a1bd16c12699d29f54659267
```

First let's play a little bit with the binary:
```
ispo@leet:~/ctf/tokyowesterns_ctf_2019/holy_grail_war$ ./holygrailwar A
    685a30b4d7a673d5

ispo@leet:~/ctf/tokyowesterns_ctf_2019/holy_grail_war$ ./holygrailwar AB
    cb75a7ed97693286

ispo@leet:~/ctf/tokyowesterns_ctf_2019/holy_grail_war$ ./holygrailwar ABCDEFG
    39c92373a16a4203

ispo@leet:~/ctf/tokyowesterns_ctf_2019/holy_grail_war$ ./holygrailwar ABCDEFGHI
    9373cb5858263de1931763db1b4044b7

ispo@leet:~/ctf/tokyowesterns_ctf_2019/holy_grail_war$ ./holygrailwar 1BCDEFGHI
    b53a165d57e15c1f931763db1b4044b7

ispo@leet:~/ctf/tokyowesterns_ctf_2019/holy_grail_war$ ./holygrailwar ABCDEFGH1
    9373cb5858263de14cf5e02e94ff6e3e

ispo@leet:~/ctf/tokyowesterns_ctf_2019/holy_grail_war$ ./holygrailwar ABCDEFGH123456
    9373cb5858263de12d5d0e74163866fd

ispo@leet:~/ctf/tokyowesterns_ctf_2019/holy_grail_war$ ./holygrailwar ABCDEFGH12345678
    9373cb5858263de1aa36714a8d8ac6e21bb4e13183fd98a9

ispo@leet:~/ctf/tokyowesterns_ctf_2019/holy_grail_war$ ./holygrailwar xxxxxxxx12345678
    22ff497c96c67205aa36714a8d8ac6e21bb4e13183fd98a9
```

We quickly observe that the algorithm operates on **8-character** blocks (we have padding to
8 characters; if input is multiple of 8, an empty 8-byte NULL string is padded). We also observe
that each block is encrypted independently of the others, like **Electronic Code Block (ECB)**
mode in **AES**. Given that, we have to decrypt individually the following blocks:
```
    d4f5f0aa8aeee7c8
    3cd8c039fabdee62
    47d0f5f36edeb24f
    f9d5bc10a1bd16c1
    2699d29f54659267
```


Now let's move on the binary. The code that actually does the encryption starts at:
```assembly
.text:0000000000416AE7         call    vm_main_4023C0
````

The hard part here is that data are passed around the internal structs of **GraalVM** so it
gets hard to understand what's going on. Furthermore the control flow is spaghetti (it jumps
up and down which makes it hard to isolate loops). Most of the code is irrelevant to the actual
computations even though it operates on the input. For instance:
```assembly
.text:0000000000402570                                              ; vm_main_4023C0+26Dj
.text:0000000000402570         cmp     ecx, ebp
.text:0000000000402572         jle     LOOP_3_EXIT_402651
.text:0000000000402578         cmp     ecx, ebp
.text:000000000040257A         jbe     EXCEPTION_403F0E
.text:0000000000402580         mov     esi, ebp                     ; rsi, rbp = iterator
.text:0000000000402582         movsx   edi, byte ptr [rax+rsi+10h]  ; edi = input[i]
.text:0000000000402587         lea     edi, [rdi+80h]               ; edi = input[i] + 0x80
.text:000000000040258D         mov     edi, edi
.text:000000000040258F         mov     rdi, [rbx+rdi*8+10h]         ; rdx = tbl_A[input[i] + 0x80] (8byte array)
.text:0000000000402594         mov     [rdx+rsi*8+10h], rdi         ; tbl_b[i] = tbl_A[input[i] + 0x80]
.text:0000000000402599         mov     rsi, [rdx]
.text:000000000040259C         test    rsi, 1
.text:00000000004025A3         jnz     INNER_LOOP_5_4025BE
.text:00000000004025A9
.text:00000000004025A9 loc_4025A9:                                  ; CODE XREF: vm_main_4023C0+22Bj
.text:00000000004025A9                                              ; vm_main_4023C0+231j
.text:00000000004025A9         mov     esi, ebp
.text:00000000004025AB         inc     esi
.text:00000000004025AD         dec     dword ptr [r15+0D0h]
.text:00000000004025B4         jz      loc_4025F3
.text:00000000004025BA         mov     ebp, esi                     ; ++ebp
.text:00000000004025BC         jmp     short INNER_LOOP_4_402570
```

There many cases like this one, so it gets hard to isolate the encryption algorithm. Anyway, the 
first interesting part starts at `0x402A90`:
```assembly
.text:0000000000402A90 loc_402A90:                                  ; CODE XREF: vm_main_4023C0+7D0j
.text:0000000000402A90         movsx   edi, byte ptr [r14+rcx+8]    ; initialize an object with the next 4 bytes from inputs
.text:0000000000402A96         mov     [rsi+13h], dil
.text:0000000000402A9A         mov     [rsi+12h], bpl
.text:0000000000402A9E         mov     [rsi+11h], bl
.text:0000000000402AA1         mov     [rsi+10h], dl
.text:0000000000402AA4         mov     rdi, rsi
.text:0000000000402AA7         call    sub_4CC2F0
.text:0000000000402AAC         nop
.text:0000000000402AAD         cmp     rax, r14
.text:0000000000402AB0         jz      EXCEPTION_403EDE
.text:0000000000402AB6         mov     rdi, rax
.text:0000000000402AB9         call    load_mem_to_reg_4CE320       ; load 4byte mem into rax
.text:0000000000402ABE         nop
.text:0000000000402ABF         lea     edi, [rax+80h]               ; edi = input[i:i+4] + 0x80
.text:0000000000402AC5         cmp     edi, 100h                    ; check if NULLs
.text:0000000000402ACB         jb      LOOP_END_402B95              ; goto 0x402B1A
.text:0000000000402AD1         mov     rdi, r15
.text:0000000000402AD4         mov     rsi, [rdi+38h]
.text:0000000000402AD8         mov     rcx, [rdi+30h]
.text:0000000000402ADC         sub     rcx, rsi
.text:0000000000402ADF         cmp     rcx, 10h
.text:0000000000402AE3         jb      loc_402BCD
.text:0000000000402AE9         lea     rcx, [rsi+10h]
.text:0000000000402AED         mov     [rdi+38h], rcx
.text:0000000000402AF1
.text:0000000000402AF1 loc_402AF1:                                  ; CODE XREF: vm_main_4023C0+814j
.text:0000000000402AF1         test    rsi, rsi
.text:0000000000402AF4         jz      loc_402BD9
.text:0000000000402AFA         prefetchnta byte ptr [rsi+100h]
.text:0000000000402B01         mov     rdi, [rsp+0A8h+var_58]
.text:0000000000402B06         mov     rcx, r14
.text:0000000000402B09         sub     rdi, rcx
.text:0000000000402B0C         mov     [rsi], rdi
.text:0000000000402B0F         mov     qword ptr [rsi+8], 0
.text:0000000000402B17
.text:0000000000402B17 loc_402B17:                                  ; CODE XREF: vm_main_4023C0+835j
.text:0000000000402B17         mov     [rsi+8], eax                 ; store input[i:i+4]
```

This loop loads 4 characters from the input on each iteration into `eax` and then stores them
into an internal GraalVM object. At the end a set of objects is created into the heap, one for
each 4-character block. Input is padded to 8 bytes, so loop always processes one or two NULL
objects at the end.

The next interesting part is the generation of pseudo random stream:
```assembly
.text:0000000000402CCA loc_402CCA:                                  ; CODE XREF: vm_main_4023C0+EE8j
.text:0000000000402CCA         lea     edi, [rax+539h]              ; rax = DWORD count (+2 each time)
.text:0000000000402CD0         movsxd  rdi, edi
.text:0000000000402CD3         mov     rbp, 5DEECE66Dh
.text:0000000000402CDD         xor     rdi, rbp                     ; rdi = 0x5DEECE66D ^ (0x539 + j) = 0x5DEECE354
.text:0000000000402CE0         mov     rbp, 0FFFFFFFFFFFFh
.text:0000000000402CEA         and     rdi, rbp
.text:0000000000402CED         mov     [rbx+8], rdi
.text:0000000000402CF1         sub     rbx, r14
.text:0000000000402CF4         mov     [rdx+8], rbx
.text:0000000000402CF8         mov     rdi, [rdx]
.text:0000000000402CFB         test    rdi, 1
.text:0000000000402D02         jnz     loc_40320F
.text:0000000000402D08
.text:0000000000402D08 loc_402D08:                                  ; CODE XREF: vm_main_4023C0+E7Cj
.text:0000000000402D08                                              ; vm_main_4023C0+E85j
.text:0000000000402D08         mov     rdi, rdx
.text:0000000000402D0B         mov     esi, 100h
.text:0000000000402D10         call    gen_rand_byte_544170
.text:0000000000402D15         nop
.text:0000000000402D16         mov     rdi, r15
.text:0000000000402D19         mov     rsi, [rdi+38h]
.text:0000000000402D1D         mov     rcx, [rdi+30h]
.text:0000000000402D21         sub     rcx, rsi
.text:0000000000402D24         cmp     rcx, 30h
.text:0000000000402D28         jb      loc_403273
.text:0000000000402D2E         lea     rcx, [rsi+30h]
.text:0000000000402D32         mov     [rdi+38h], rcx
.text:0000000000402D36
.text:0000000000402D36 loc_402D36:                                  ; CODE XREF: vm_main_4023C0+EBAj
.text:0000000000402D36         test    rsi, rsi
.text:0000000000402D39         jz      loc_402D77
.text:0000000000402D3F         mov     rbx, [rsp+0A8h+var_78]
.text:0000000000402D44         mov     rdi, r14
.text:0000000000402D47         sub     rbx, rdi
.text:0000000000402D4A         mov     [rsi], rbx
.text:0000000000402D4D         mov     dword ptr [rsi+8], 20h
.text:0000000000402D54         mov     rdi, 10h
.text:0000000000402D5B         jmp     loc_402D6C
.text:0000000000402D60 ; ---------------------------------------------------------------------------
.text:0000000000402D60
.text:0000000000402D60 BZERO_402D60:                                ; CODE XREF: vm_main_4023C0+9B0j
.text:0000000000402D60         mov     qword ptr [rsi+rdi], 0
.text:0000000000402D68         lea     rdi, [rdi+8]
.text:0000000000402D6C
.text:0000000000402D6C loc_402D6C:                                  ; CODE XREF: vm_main_4023C0+99Bj
.text:0000000000402D6C         cmp     rdi, 30h
.text:0000000000402D70         jb      short BZERO_402D60
.text:0000000000402D72         jmp     loc_402DEB
.text:0000000000402D77 ; ---------------------------------------------------------------------------
.text:0000000000402D77
.text:0000000000402D77 loc_402D77:                                  ; CODE XREF: vm_main_4023C0+979j
.text:0000000000402D77         mov     rsi, r14
.text:0000000000402D7A
.text:0000000000402D7A loc_402D7A:                                  ; CODE XREF: vm_main_4023C0:loc_402DEBj
.text:0000000000402D7A         cmp     rsi, r14
.text:0000000000402D7D         jz      loc_402DED
.text:0000000000402D83
.text:0000000000402D83 loc_402D83:                                  ; CODE XREF: vm_main_4023C0+A4Ej
.text:0000000000402D83         mov     [rsp+0A8h+var_60], rsi
.text:0000000000402D88         mov     [rsi+10h], al
.text:0000000000402D8B         mov     eax, 1
.text:0000000000402D90         jmp     loc_402DDC
.text:0000000000402D90 ; ---------------------------------------------------------------------------
.text:0000000000402D95         align 20h
.text:0000000000402DA0
.text:0000000000402DA0 LOOP_10_402DA0:                              ; CODE XREF: vm_main_4023C0+A24j
.text:0000000000402DA0         mov     [rsp+0A8h+inplen_4], eax     ; generate 32 pseudo random bytes = tbl_C
.text:0000000000402DA7         mov     rdi, rdx                     ; use 0x5DEECE66D ^ 0x539 as seed
.text:0000000000402DAA         mov     esi, 100h
.text:0000000000402DAF         call    gen_rand_byte_544170
.text:0000000000402DB4         nop
.text:0000000000402DB5         cmp     [rsp+0A8h+inplen_4], 20h
.text:0000000000402DBD         jnb     loc_403F5B
.text:0000000000402DC3         mov     rsi, [rsp+0A8h+var_60]
.text:0000000000402DC8         mov     edi, [rsp+0A8h+inplen_4]
.text:0000000000402DCF         mov     [rsi+rdi+10h], al
.text:0000000000402DD3         mov     eax, [rsp+0A8h+inplen_4]
.text:0000000000402DDA         inc     eax
.text:0000000000402DDC
.text:0000000000402DDC loc_402DDC:                                  ; CODE XREF: vm_main_4023C0+9D0j
.text:0000000000402DDC         mov     rdx, [rsp+0A8h+var_70]
.text:0000000000402DE1         cmp     eax, 20h
.text:0000000000402DE4         jl      short LOOP_10_402DA0         ; generate 32 pseudo random bytes = tbl_C
.text:0000000000402DE6         jmp     loc_402E13
.text:0000000000402DEB ; ---------------------------------------------------------------------------
.text:0000000000402DEB
.text:0000000000402DEB loc_402DEB:                                  ; CODE XREF: vm_main_4023C0+9B2j
.text:0000000000402DEB         jmp     short loc_402D7A
.text:0000000000402DED ; ---------------------------------------------------------------------------
.text:0000000000402DED
.text:0000000000402DED loc_402DED:                                  ; CODE XREF: vm_main_4023C0+9BDj
.text:0000000000402DED         mov     [rsp+0A8h+inplen_4], eax
.text:0000000000402DF4         mov     rdi, [rsp+0A8h+var_78]
.text:0000000000402DF9         mov     esi, 20h
.text:0000000000402DFE         call    sub_42D410
.text:0000000000402E03         nop
.text:0000000000402E04         mov     rsi, rax
.text:0000000000402E07         mov     eax, [rsp+0A8h+inplen_4]
.text:0000000000402E0E         jmp     loc_402D83
.text:0000000000402E13 ; ---------------------------------------------------------------------------
.text:0000000000402E13
.text:0000000000402E13 loc_402E13:                                  ; CODE XREF: vm_main_4023C0+A26j
.text:0000000000402E13         mov     rsi, [rsp+0A8h+var_60]
.text:0000000000402E18         mov     rdi, rsi
.text:0000000000402E1B         call    expand_maybe_402000          ; expand tbl_C into 128 bytes = tbl_D
.text:0000000000402E20         nop
```

First, `gen_rand_byte_544170` is used to generated **32** random bytes (one on each iteration)
from a seed which is `0x5DEECE66D ^ (0x539 + j)`, where `j` is `0, 2, 4, 6, 8, ...` and so on.
For instance, the first iteration (when `j = 0`) we get the following bytes:
```
    A8 2C B0 DF E2 F7 E6 CF  2C A4 F1 EB 25 05 51 FC
    D0 1A A3 E2 32 ED 7E EB  14 1E 3C 6B F1 53 29 BE
```

Next, `expand_maybe_402000` gets these 32 bytes and expands them into 32 4-byte words:
```
83F19EEE DA45ED22 0F746D84 5956AB6D 8917C0EF 7A5CF3B6 796712DD 6009FB1F
6A5BC569 376C57D3 E9BA0D38 BE82E078 77856CC1 A273CFEE D4142C83 017374A6  
A3AEAE68 02B52304 0E3D4B9E 1EB080BF 30A8374B 84F10F0F 02823509 D0DABFAB
C85353C6 768E268E 0CDD1B42 DDF3D584 FBDBA0D4 A15D7381 83F4A3F6 D4EAC3EA  
```

Let's name this array `exp_2`. Once we get this stream, the actual encryption takes place
for a block of 8-characters:
```assembly
.text:0000000000402E55 PRE_PERMUTE_402E55:                          ; CODE XREF: vm_main_4023C0+A76j
.text:0000000000402E55         cmp     rax, r14
.text:0000000000402E58         jz      loc_403F74
.text:0000000000402E5E         mov     rcx, 18F058h
.text:0000000000402E68         lea     rcx, [r14+rcx]               ; rcx = 0x78E058
.text:0000000000402E6C         mov     edi, [rcx+10h]               ; rcx = first 4 bytes of 2nd expansion
.text:0000000000402E6F         add     edi, [rax+8]                 ; add input[i:i+4]!
.text:0000000000402E72         mov     eax, [rsp+0A8h+var_C]
.text:0000000000402E79         inc     eax
.text:0000000000402E7B         mov     [rsp+0A8h+inplen_4], edi     ; V0 = exp_2[0:4] + inp[i:i+4]
.text:0000000000402E82         mov     rdi, [rsp+0A8h+var_68]
.text:0000000000402E87         mov     esi, eax
.text:0000000000402E89         mov     [rsp+0A8h+var_8], eax
.text:0000000000402E90         call    sub_4F8F40                   ; rax points to the next 4 bytes of input
.text:0000000000402E95         nop
.text:0000000000402E96         cmp     rax, r14
.text:0000000000402E99         jz      PERMUTE_402EB8
.text:0000000000402E9F         mov     rcx, 0FFFFFFFFFFFFFFF8h
.text:0000000000402EA6         and     rcx, [rax]
.text:0000000000402EA9         cmp     dword ptr [r14+rcx+78h], 20Ah
.text:0000000000402EB2         jnz     loc_403FB0
.text:0000000000402EB8
.text:0000000000402EB8 PERMUTE_402EB8:                              ; CODE XREF: vm_main_4023C0+AD9j
.text:0000000000402EB8         mov     [rsp+0A8h+var_60], rax
.text:0000000000402EBD         cmp     rax, r14
.text:0000000000402EC0         jz      loc_403F7F
.text:0000000000402EC6         mov     rdi, 18F058h
.text:0000000000402ED0         lea     rdi, [r14+rdi]               ; edx = &exp_2
.text:0000000000402ED4         mov     edx, [rdi+74h]
.text:0000000000402ED7         mov     [rsp+0A8h+var_10], edx
.text:0000000000402EDE         mov     ecx, [rax+8]                 ; ecx = input[i+4:i+8]!
.text:0000000000402EE1         mov     esi, ecx
.text:0000000000402EE3         add     esi, [rdi+14h]               ; esi = exp_2[4:8] + inpu[i+4:i+8] = V1
.text:0000000000402EE6         mov     ebx, [rdi+18h]
.text:0000000000402EE9         mov     ebp, [rdi+1Ch]
.text:0000000000402EEC         mov     r8d, [rdi+20h]
.text:0000000000402EF0         mov     r9d, [rdi+24h]
.text:0000000000402EF4         mov     r10d, [rdi+28h]
.text:0000000000402EF8         mov     r11d, [rdi+2Ch]
.text:0000000000402EFC         mov     r12d, [rdi+30h]
.text:0000000000402F00         mov     r13d, [rdi+34h]
.text:0000000000402F04         mov     ecx, [rdi+38h]
.text:0000000000402F07         mov     eax, [rdi+3Ch]
.text:0000000000402F0A         mov     edx, [rdi+40h]
.text:0000000000402F0D         mov     [rsp+0A8h+var_14], edx
.text:0000000000402F14         mov     edx, [rdi+44h]
.text:0000000000402F17         mov     [rsp+0A8h+var_18], edx
.text:0000000000402F1E         mov     edx, [rdi+48h]
.text:0000000000402F21         mov     [rsp+0A8h+var_1C], edx
.text:0000000000402F28         mov     edx, [rdi+4Ch]
.text:0000000000402F2B         mov     [rsp+0A8h+var_20], edx
.text:0000000000402F32         mov     edx, [rdi+50h]
.text:0000000000402F35         mov     [rsp+0A8h+var_24], edx
.text:0000000000402F3C         mov     edx, [rdi+54h]
.text:0000000000402F3F         mov     [rsp+0A8h+var_28], edx
.text:0000000000402F46         mov     edx, [rdi+58h]
.text:0000000000402F49         mov     [rsp+0A8h+var_2C], edx
.text:0000000000402F4D         mov     edx, [rdi+5Ch]
.text:0000000000402F50         mov     [rsp+0A8h+var_30], edx
.text:0000000000402F54         mov     edx, [rdi+60h]
.text:0000000000402F57         mov     [rsp+0A8h+var_34], edx
.text:0000000000402F5B         mov     edx, [rdi+64h]
.text:0000000000402F5E         mov     [rsp+0A8h+var_38], edx
.text:0000000000402F62         mov     edx, [rdi+68h]
.text:0000000000402F65         mov     [rsp+0A8h+var_3C], edx
.text:0000000000402F69         mov     edx, [rdi+6Ch]
.text:0000000000402F6C         mov     edi, [rsp+0A8h+inplen_4]
.text:0000000000402F73         xor     edi, esi                     ; edi = V0 ^ V1
.text:0000000000402F75         mov     [rsp+0A8h+var_40], edx
.text:0000000000402F79         mov     edx, esi
.text:0000000000402F7B         and     edx, 1Fh                     ; edx = V1 & 31
.text:0000000000402F7E         mov     [rsp+0A8h+var_44], eax
.text:0000000000402F82         mov     eax, ecx
.text:0000000000402F84         mov     ecx, edx
.text:0000000000402F86         rol     edi, cl
.text:0000000000402F88         add     edi, ebx                     ; V2 = ROL(V1 ^ V0, (V1 & 31)) + exp_2[2]
.text:0000000000402F8A         xor     esi, edi
.text:0000000000402F8C         mov     ecx, edi
.text:0000000000402F8E         and     ecx, 1Fh
.text:0000000000402F91         rol     esi, cl
.text:0000000000402F93         add     esi, ebp                     ; V3 = ROL(V2 ^ V1, (V2 & 31)) + exp_2[3]
.text:0000000000402F95         xor     edi, esi
.text:0000000000402F97         mov     ecx, esi
.text:0000000000402F99         and     ecx, 1Fh
.text:0000000000402F9C         rol     edi, cl
.text:0000000000402F9E         add     edi, r8d
.text:0000000000402FA1         xor     esi, edi
.text:0000000000402FA3         mov     ecx, edi
.text:0000000000402FA5         and     ecx, 1Fh
.text:0000000000402FA8         rol     esi, cl
.text:0000000000402FAA         add     esi, r9d
.text:0000000000402FAD         xor     edi, esi
.text:0000000000402FAF         mov     ecx, esi
.text:0000000000402FB1         and     ecx, 1Fh
.text:0000000000402FB4         rol     edi, cl
.text:0000000000402FB6         add     edi, r10d
.text:0000000000402FB9         xor     esi, edi
.text:0000000000402FBB         mov     ecx, edi
.text:0000000000402FBD         and     ecx, 1Fh
.text:0000000000402FC0         rol     esi, cl
.text:0000000000402FC2         add     esi, r11d
....
.text:00000000004030B6         lea     rcx, [r14+rcx]
.text:00000000004030BA         add     edi, [rcx+70h]               ; edi = next 4 bytes of the cipher!
.text:00000000004030BD         lea     ecx, [rdi+80h]
.text:00000000004030C3         cmp     ecx, 100h
.text:00000000004030C9         jb      loc_4031D2
....
.text:000000000040310A         mov     [rdx], rax
.text:000000000040310D         mov     qword ptr [rdx+8], 0
.text:0000000000403115
.text:0000000000403115 loc_403115:                                  ; CODE XREF: vm_main_4023C0+F36j
.text:0000000000403115         mov     [rdx+8], edi                 ; store cipher
.text:0000000000403118
.text:0000000000403118 loc_403118:                                  ; CODE XREF: vm_main_4023C0+E2Dj
.text:0000000000403118         xor     esi, edi                     ; edi = cipher
.text:000000000040311A         and     edi, 1Fh
.text:000000000040311D         mov     ecx, edi
.text:000000000040311F         rol     esi, cl
.text:0000000000403121         add     esi, [rsp+0A8h+var_10]
.text:0000000000403128         mov     [rsp+0A8h+var_10], esi       ; esi = next 4 bytes of generated cipher
.text:000000000040312F         mov     rdi, [rsp+0A8h+var_68]
.text:0000000000403134         mov     esi, [rsp+0A8h+var_C]
.text:000000000040313B         call    sub_4FA210
.text:0000000000403140         nop
```


This is an unrolled loop. The mathematic algorithm is shown below:
```
    V[0] = exp_2[0] + input[0:4]
    V[1] = exp_2[1] + input[4:8]

    for i in [2, 26): V[i] = rol(V[i-1] ^ V[i-2], (V[i-1] & 31)) + exp_2[i]
```

All operations are on 32 bits. At the end, `V[24]` and `V[25]` are concatenated to give the
8-byte blocks cipher. On the next iteration, `j = 2` (seed is `0x5DEECE66D ^ (0x539 + 2)`) and 
`gen_rand_byte_544170`  generates another **32** byte sequence, which in turn makes 
`expand_maybe_402000` to generated another **32** dword array.
The rest of the code is to concatenate all these blocks and print them to stdout.


### Breaking the algorithm

The interesting part here is that the generation of `exp_2` array (the one that
`expand_maybe_402000` generates is independent to the flag). That is, if we know `exp_2` we can
easily encrypt an 8-character input.

Function `gen_rand_byte_544170` and `expand_maybe_402000` are quite long, so instead of actually
reversing them we just set breakpoints and grab the output of `expand_maybe_402000` at
memory address `0x78E058`. Since our target ciphertext consists of 80 bytes (5 blocks), we
need 5 of these tables:

```python
exp_2a = [
    0x83F19EEE, 0xDA45ED22, 0x0F746D84, 0x5956AB6D, 0x8917C0EF, 0x7A5CF3B6, 0x796712DD, 0x6009FB1F,
    0x6A5BC569, 0x376C57D3, 0xE9BA0D38, 0xBE82E078, 0x77856CC1, 0xA273CFEE, 0xD4142C83, 0x017374A6,
    0xA3AEAE68, 0x02B52304, 0x0E3D4B9E, 0x1EB080BF, 0x30A8374B, 0x84F10F0F, 0x02823509, 0xD0DABFAB,
    0xC85353C6, 0x768E268E, 0x0CDD1B42, 0xDDF3D584, 0xFBDBA0D4, 0xA15D7381, 0x83F4A3F6, 0xD4EAC3EA
]

exp_2b = [
    0xA8780381, 0xD325B893, 0x2889F25F, 0x093C9281, 0x0CA31370, 0xF01ABBBE, 0x069B1EEB, 0x335B65CD,
    0xDBA0F812, 0x26641F2E, 0xCDCD48E0, 0x2FFB8009, 0x75077D6D, 0x8F23624A, 0x71C8F20A, 0xE254B801,
    0x443BA936, 0x6F4F4A2F, 0x8ABA595F, 0x9A8530A6, 0xC42A5A0E, 0x9AD8308D, 0x42628DBD, 0xABAB10DE,
    0x9F95660E, 0xAE0EE93C, 0x9E704772, 0x9E0FE2C0, 0x53E83F2B, 0x37DD53C7, 0xDFA1FE01, 0x04FBED0D
]

exp_2c = [
    0x77354950, 0x113B306D, 0x3F8A1235, 0xE3AF6ED1, 0xF54CD1E9, 0x9EFB71E8, 0x298D44BA, 0x8F672270,
    0xE9A97023, 0x7100D45B, 0x08F2A5E4, 0xEE09E4A5, 0xC6539FC7, 0xC8538753, 0xF59E1B4B, 0xD268290E,
    0x76F1D203, 0x9917E9B2, 0x908A32D4, 0xE8D20101, 0x6092F88E, 0x84FC73EC, 0xCBD92758, 0x44A66424,
    0x82779517, 0xEC39BEFE, 0xD9FE6B2D, 0x2520232C, 0xDDA34A8D, 0x1E5FE69A, 0xD99E98BA, 0x66AA19E2
]

exp_2d = [
    0x105426F8, 0x2945D55F, 0x5A6EC101, 0x3C60FC75, 0xBC365FA3, 0x5576699C, 0x99548715, 0x1C08BD1F,
    0xD5375697, 0x1F16FC4C, 0x541BE791, 0x169314FF, 0xDDBFC2DB, 0x9C131E7F, 0xEC9B6A6E, 0x19700898,
    0x630BC067, 0x5154DFC8, 0x739A5761, 0x9EBCE304, 0x6D8F9D46, 0x369056A4, 0x5BC4E09E, 0xA139BBE8,
    0x93023D62, 0xE5979177, 0x73911EA2, 0xED9A6998, 0x6AAD6804, 0xC6EC99AA, 0xAF8F109C, 0x81793378
]

exp_2e = [
    0x6E15B6ED, 0xF259349E, 0xFED4FDD8, 0x759A482B, 0x4B150FD6, 0xD42698F1, 0x85D88CE1, 0x253796EE,
    0x941AF694, 0x0997B347, 0xCDB22EBB, 0x365EF56C, 0x458F3E90, 0xA1C536C3, 0x00E1284D, 0x5F557B37,
    0xADF6DFF8, 0x6260A096, 0x3DB81FF5, 0x7A8E070A, 0x7A0609FA, 0x9E6DED19, 0x377743D5, 0x8EAD5A5B,
    0x69BF4721, 0x04EA93A4, 0xC2C34E47, 0xEE0B5F03, 0x9A03038A, 0xDE6BA695, 0xC7997AD9, 0x0C195D2D
]
```

Then we can move backwards and apply the decryption algorithm for a given block:
```python
def decrypt_round(a, b, exp_2):
    V = [0]*32

    V[25], V[24] = a, b

    for i in xrange(23, -1, -1):
        V[i] = ror((V[i+2] - exp_2[i+2] + 0x100000000) & 0xffffffff, V[i+1] & 31) ^ V[i+1]
        # print 'V[%2d] = 0x%08x' % (i, V[i])

    c = (V[0] - exp_2[0] + 0x100000000) & 0xffffffff
    d = (V[1] - exp_2[1] + 0x100000000) & 0xffffffff

    # convert numbers back to ASCII
    plain  = chr(c >> 24) + chr((c >> 16) & 0xff) + chr((c >> 8) & 0xff) + chr(c & 0xff)
    plain += chr(d >> 24) + chr((d >> 16) & 0xff) + chr((d >> 8) & 0xff) + chr(d & 0xff)

    return plain
```

Once we have that we can crack ciphertext block by block:
```
d4f5f0aa8aeee7c8    ==> TWCTF{Fa
3cd8c039fabdee62    ==> t3_Gr4nd
47d0f5f36edeb24f    ==> _Ord3r_1
f9d5bc10a1bd16c1    ==> s_fuck1n
2699d29f54659267    ==> 6_h07}
```

Which is our flag: `TWCTF{Fat3_Gr4nd_Ord3r_1s_fuck1n6_h07}`.

For more details please look at the [holy_grail_war_crack.py](./holy_grail_war_crack.py) script.

___

