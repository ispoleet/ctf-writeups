## Teaser Dragon CTF 2018 - Brutal Old Skull (RE 176pt)
##### 29-30/09/2018 (24hr)
___

### Description: 
The '90s called and wanted their crackme back. It's basically a walk in a park.

___
### Solution

![solution](solution.jpg)


The first skip the GUI and find where the flag is being checked. The actual flag checking starts at 
`process_flag_4017D5`. First we validate **code1** through **code4** using `hash_code_4016E4`:

```Assembly
.text:004018AB
.text:004018AB SCANF_OK_4018AB:                        ; CODE XREF: process_flag_4017D5+A0j
.text:004018AB     mov     eax, [ebp+var_398]
.text:004018B1     cmp     eax, 0FFFFh
.text:004018B6     jbe     short OK_4018C9
.text:004018B8     mov     [esp+4C8h+hWnd], offset aIncorrectCode_ ; "Incorrect Code."
.text:004018BF     call    print_message_4016C2
.text:004018C4     jmp     END_401D72
.text:004018C9 ; ---------------------------------------------------------------------------
.text:004018C9
.text:004018C9 OK_4018C9:                              ; CODE XREF: process_flag_4017D5+E1j
.text:004018C9     mov     eax, [ebp+var_398]
.text:004018CF     mov     edx, eax
.text:004018D1     mov     eax, [ebp+iter_C]
.text:004018D4     mov     [ebp+eax*2+codes_2C], dx
.text:004018D9     add     [ebp+iter_C], 1
.text:004018DD     jmp     LOOP_1_4017F2
.text:004018E2 ; ---------------------------------------------------------------------------
.text:004018E2
.text:004018E2 STAGE_2_4018E2:                         ; CODE XREF: process_flag_4017D5+21j
.text:004018E2     movzx   eax, [ebp+codes_2C]
.text:004018E6     movzx   eax, ax                     ; get code_1
.text:004018E9     mov     [esp+4C8h+nMaxCount], eax   ; int
.text:004018ED     mov     [esp+4C8h+lpString], 4C8Eh  ; size_t
.text:004018F5     mov     [esp+4C8h+hWnd], offset encrypted_binary_405020 ; int
.text:004018FC     call    hash_code_4016E4
.text:00401901     mov     [ebp+Memory], eax
.text:00401904     cmp     [ebp+Memory], 0
.text:00401908     jnz     short CODE_1_OK_40191B
.text:0040190A     mov     [esp+4C8h+hWnd], offset aWrongCode1_ ; "Wrong Code 1."
.text:00401911     call    print_message_4016C2
.text:00401916     jmp     END_401D72
.text:0040191B ; ---------------------------------------------------------------------------
.text:0040191B
.text:0040191B CODE_1_OK_40191B:                       ; CODE XREF: process_flag_4017D5+133j
...
```

`hash_code_4016E4` is fairly simple: It takes a code and a buffer and applies a simple XOR algorithm
to the input buffer and then it calculates the MD5 hash with the last 32 characters of the buffer:
```Assembly
.text:004016E4 ; int __cdecl hash_code_4016E4(int, size_t, int)
.text:004016E4 hash_code_4016E4 proc near              ; CODE XREF: process_flag_4017D5+127p
.text:004016E4                                         ; process_flag_4017D5+15Fp ...
.text:004016E4
.text:004016E4 Size= dword ptr -58h
.text:004016E4 Val = dword ptr -54h
.text:004016E4 var_50= dword ptr -50h
.text:004016E4 code_3C= word ptr -3Ch
.text:004016E4 Buf1= byte ptr -38h
.text:004016E4 Dst = dword ptr -10h
.text:004016E4 iter_C= dword ptr -0Ch
.text:004016E4 arg_0= dword ptr  8
.text:004016E4 arg_4= dword ptr  0Ch
.text:004016E4 arg_8= dword ptr  10h
.text:004016E4
.text:004016E4     push    ebp
.text:004016E5     mov     ebp, esp
.text:004016E7     push    edi
.text:004016E8     sub     esp, 54h
.text:004016EB     mov     eax, [ebp+arg_8]
.text:004016EE     mov     [ebp+code_3C], ax           ; code = arg3 (code_1, code_2, etc.)
.text:004016F2     mov     eax, [ebp+arg_4]
.text:004016F5     mov     [esp+58h+Size], eax         ; Size
.text:004016F8     call    malloc
.text:004016FD     mov     [ebp+Dst], eax              ; dst = malloc(arg2)
.text:00401700     mov     eax, [ebp+arg_4]
.text:00401703     mov     [esp+58h+var_50], eax       ; Size
.text:00401707     mov     [esp+58h+Val], 0            ; Val
.text:0040170F     mov     eax, [ebp+Dst]
.text:00401712     mov     [esp+58h+Size], eax         ; Dst
.text:00401715     call    memset
.text:0040171A     mov     [ebp+iter_C], 0
.text:00401721
.text:00401721 LOOP_1_401721:                          ; CODE XREF: hash_code_4016E4+81j
.text:00401721     mov     eax, [ebp+iter_C]
.text:00401724     cmp     eax, [ebp+arg_4]            ; arg2 as upper bound
.text:00401727     jnb     short LOOP_END_401767
.text:00401729     mov     edx, [ebp+Dst]
.text:0040172C     mov     eax, [ebp+iter_C]
.text:0040172F     add     eax, edx
.text:00401731     mov     ecx, [ebp+arg_0]
.text:00401734     mov     edx, [ebp+iter_C]
.text:00401737     add     edx, ecx                    ; edx = arg1[iter]
.text:00401739     movzx   edx, byte ptr [edx]
.text:0040173C     mov     ecx, edx
.text:0040173E     movzx   edx, [ebp+code_3C]
.text:00401742     xor     edx, ecx
.text:00401744     mov     ecx, edx                    ; ecx = arg1[iter] ^ code
.text:00401746     movzx   edx, [ebp+code_3C]
.text:0040174A     shr     dx, 8
.text:0040174E     sub     ecx, edx                    ; ecx = (arg1[iter] ^ code) - (code >> 8)
.text:00401750     mov     edx, ecx
.text:00401752     mov     [eax], dl                   ; dst[i] = (arg1[i] ^ code) - (code >> 8)
.text:00401754     movzx   eax, [ebp+code_3C]
.text:00401758     imul    ax, 62F3h
.text:0040175D     mov     [ebp+code_3C], ax           ; code *= 0x62F3 (16 bits)
.text:00401761     add     [ebp+iter_C], 1
.text:00401765     jmp     short LOOP_1_401721
.text:00401767 ; ---------------------------------------------------------------------------
.text:00401767
.text:00401767 LOOP_END_401767:                        ; CODE XREF: hash_code_4016E4+43j
.text:00401767     lea     edx, [ebp+Buf1]
.text:0040176A     mov     eax, 0
.text:0040176F     mov     ecx, 0Ah
.text:00401774     mov     edi, edx
.text:00401776     rep stosd                           ; buf: memset 10*4 = 40 bytes
.text:00401778     mov     eax, [ebp+arg_4]            ; eax = arg2 (size)
.text:0040177B     lea     edx, [eax-20h]
.text:0040177E     lea     eax, [ebp+Buf1]
.text:00401781     mov     [esp+58h+var_50], eax       ; arg3: buf
.text:00401785     mov     [esp+58h+Val], edx          ; arg2: buflen - 0x20
.text:00401789     mov     eax, [ebp+Dst]
.text:0040178C     mov     [esp+58h+Size], eax         ; arg1: dst
.text:0040178F     call    md5_401630
.text:00401794     mov     eax, [ebp+arg_4]
.text:00401797     lea     edx, [eax-20h]
.text:0040179A     mov     eax, [ebp+Dst]
.text:0040179D     add     eax, edx
.text:0040179F     mov     [esp+58h+var_50], 20h       ; Size
.text:004017A7     mov     [esp+58h+Val], eax          ; Buf2
.text:004017AB     lea     eax, [ebp+Buf1]
.text:004017AE     mov     [esp+58h+Size], eax         ; Buf1
.text:004017B1     call    memcmp
.text:004017B6     test    eax, eax
.text:004017B8     jz      short EQUAL_4017CC
.text:004017BA     mov     eax, [ebp+Dst]
.text:004017BD     mov     [esp+58h+Size], eax         ; Memory
.text:004017C0     call    free
.text:004017C5     mov     eax, 0
.text:004017CA     jmp     short loc_4017CF
.text:004017CC ; ---------------------------------------------------------------------------
.text:004017CC
.text:004017CC EQUAL_4017CC:                           ; CODE XREF: hash_code_4016E4+D4j
.text:004017CC     mov     eax, [ebp+Dst]
.text:004017CF
.text:004017CF loc_4017CF:                             ; CODE XREF: hash_code_4016E4+E6j
.text:004017CF     add     esp, 54h
.text:004017D2     pop     edi
.text:004017D3     pop     ebp
.text:004017D4     retn
.text:004017D4 hash_code_4016E4 endp
```

Determining that `md5_401630` is indeed calculates the MD5 sum of a buffer is tricky, but
we can infer it by observing input/output and looking at constants like `0x3E423112` and
`0x242070DB`.


Decompiling `hash_code_4016E4` is straightforward:
```C
dst = malloc(buflen);
code = arg2;

for (int i=0; i<buflen; ++i) {
	dst[i] = (arg1[i] ^ code) - (code >> 8)
	code = (code * 0x62F3) & 0xffff
}

hash1 = MD5(dst, buflen-0x20);

if (memcmp(hash1, &dst[buflen-0x20], 20) != 0) {
	return NULL;
} else {
	return dst;
}
```

We can easily brute force codes since we check 1 code at a time and the max value for each
code is 0xffff:
```
0 <= Code 1 <= 0xFFFF
0 <= Code 2 <= 0xFFFF
0 <= Code 3 <= 0xFFFF
0 <= Code 4 <= 0xFFFF
```

We use [brutal_oldskull_crack.py](brutal_oldskull_crack.py) to get the
codes:
```
Code 1: 0x5b42
Code 2: 0x13cc
Code 3: 0xf129
Code 4: 0x62ac
```

If all codes are correct the `encrypted_binary_405020` gets decrypted 4 times and then
it's being stored as an executable under `%TEMP%`. This executable is launched and the
actual flag is passed as an argument. If the flag is correct binary's exit code is 0.
Otherwise is non zero:
```Assembly
.text:00401A05 ALL_CODES_OK_401A05:                    ; CODE XREF: process_flag_4017D5+1FCj
.text:00401A05     mov     eax, [ebp+Memory]
...
.text:00401A3A     lea     eax, [ebp+Buffer]
.text:00401A40     mov     [esp+4C8h+lpString], eax    ; lpBuffer
.text:00401A44     mov     [esp+4C8h+hWnd], 100h       ; nBufferLength
.text:00401A4B     mov     eax, ds:GetTempPathA
.text:00401A50     call    eax ; GetTempPathA
.text:00401A52     sub     esp, 8
.text:00401A55     lea     eax, [ebp+Buffer]
.text:00401A5B     mov     ecx, 0FFFFFFFFh
.text:00401A60     mov     edx, eax
.text:00401A62     mov     eax, 0
.text:00401A67     mov     edi, edx
.text:00401A69     repne scasb
.text:00401A6B     mov     eax, ecx
.text:00401A6D     not     eax
.text:00401A6F     lea     edx, [eax-1]
.text:00401A72     lea     eax, [ebp+Buffer]
.text:00401A78     add     eax, edx
.text:00401A7A     mov     dword ptr [eax], 646C6F5Ch
.text:00401A80     mov     dword ptr [eax+4], 6C756B73h
.text:00401A87     mov     dword ptr [eax+8], 68635F6Ch
.text:00401A8E     mov     dword ptr [eax+0Ch], 656B6365h
.text:00401A95     mov     dword ptr [eax+10h], 78652E72h
.text:00401A9C     mov     word ptr [eax+14h], 65h     ; %TEMP%\oldskull_checker.exe
.text:00401AA2     mov     [esp+4C8h+lpString], offset Mode ; "wb"
.text:00401AAA     lea     eax, [ebp+Buffer]
.text:00401AB0     mov     [esp+4C8h+hWnd], eax        ; Filename
.text:00401AB3     call    fopen
...
.text:00401B02     mov     [esp+4C8h+hWnd], eax        ; File
.text:00401B05     call    fclose
...
.text:00401B74     mov     [esp+4C8h+nMaxCount], 40h   ; nMaxCount
.text:00401B7C     lea     edx, [ebp+Source]
.text:00401B82     mov     [esp+4C8h+lpString], edx    ; lpString
.text:00401B86     mov     [esp+4C8h+hWnd], eax        ; hWnd
.text:00401B89     mov     eax, ds:GetWindowTextA
.text:00401B8E     call    eax ; GetWindowTextA        ; get flag

...
.text:00401C1F     mov     [esp+4C8h+lpString], eax    ; lpCommandLine
.text:00401C23     mov     [esp+4C8h+hWnd], 0          ; lpApplicationName
.text:00401C2A     mov     eax, ds:CreateProcessA
.text:00401C2F     call    eax ; CreateProcessA
.text:00401C31     sub     esp, 28h
.text:00401C34     mov     [ebp+var_24], eax
.text:00401C37     cmp     [ebp+var_24], 0
.text:00401C3B     jnz     short loc_401C4E
.text:00401C3D     mov     [esp+4C8h+hWnd], offset aCouldnTSpawnCh ; "Couldn't spawn checker"
.text:00401C44     call    print_message_4016C2
.text:00401C49     jmp     END_401D72
.text:00401C4E ; ---------------------------------------------------------------------------
.text:00401C4E
.text:00401C4E loc_401C4E:                             ; CODE XREF: process_flag_4017D5+466j
...
.text:00401CB3     mov     [esp+4C8h+hWnd], offset aCheckerCrashed ; "Checker crashed. Sorry."
.text:00401CBA     call    print_message_4016C2
.text:00401CBF     jmp     END_401D72
...
.text:00401D1A     mov     [esp+4C8h+hWnd], offset aCheckerFailed_ ; "Checker failed. Sorry."
.text:00401D21     call    print_message_4016C2
.text:00401D26     jmp     short END_401D72
.text:00401D28 ; ---------------------------------------------------------------------------
.text:00401D28
.text:00401D28 loc_401D28:                             ; CODE XREF: process_flag_4017D5+51Dj
.text:00401D28     mov     eax, [ebp+ExitCode]
.text:00401D2E     test    eax, eax
.text:00401D30     jnz     short loc_401D40
.text:00401D32     mov     [esp+4C8h+hWnd], offset aWellDoneButYou ; "Well Done! But you know that :)"
.text:00401D39     call    print_message_4016C2
.text:00401D3E     jmp     short loc_401D4C
.text:00401D40 ; ---------------------------------------------------------------------------
.text:00401D40
.text:00401D40 loc_401D40:                             ; CODE XREF: process_flag_4017D5+55Bj
.text:00401D40     mov     [esp+4C8h+hWnd], offset aWrongFlag_ ; "Wrong Flag."
.text:00401D47     call    print_message_4016C2
...
```

### Reversing the checker binary
The first step is to find the correct codes. Once we have the correct codes, we let the crackme
to decrypt the checker binary and we grab it from `%TEMP%`. The main function in the checker
program is `main_401630`:
```Assembly
.text:00401630 main_401630     proc near               ; CODE XREF: sub_401170+26Ep
...
.text:0040163E                 cmp     [ebp+arg_0], 2
.text:00401642                 jz      short loc_40164B
.text:00401644                 mov     eax, 1
.text:00401649                 jmp     short locret_4016B1
.text:0040164B ; ---------------------------------------------------------------------------
.text:0040164B
.text:0040164B loc_40164B:                             ; CODE XREF: main_401630+12j
.text:0040164B                 mov     eax, [ebp+arg_4]
.text:0040164E                 mov     eax, [eax+4]
.text:00401651                 mov     [esp+20h+var_8], eax
.text:00401655                 mov     eax, [esp+20h+var_8]
.text:00401659                 mov     [esp+20h+Str], eax ; Str
.text:0040165C                 call    strlen
.text:00401661                 cmp     eax, 14h
.text:00401664                 jz      short LEN_OK_40166D
.text:00401666                 mov     eax, 2
.text:0040166B                 jmp     short locret_4016B1
.text:0040166D ; ---------------------------------------------------------------------------
.text:0040166D
.text:0040166D LEN_OK_40166D:                          ; CODE XREF: main_401630+34j
.text:0040166D                 mov     [esp+20h+var_4], 0
.text:00401675
.text:00401675 loc_401675:                             ; CODE XREF: main_401630+7Aj
.text:00401675                 cmp     [esp+20h+var_4], 13h
.text:0040167A                 ja      short loc_4016AC
.text:0040167C                 mov     edx, [esp+20h+var_8]
.text:00401680                 mov     eax, [esp+20h+var_4]
.text:00401684                 add     eax, edx
.text:00401686                 movzx   eax, byte ptr [eax]
.text:00401689                 mov     edx, eax
.text:0040168B                 mov     eax, [esp+20h+var_4]
.text:0040168F                 add     eax, offset byte_404008
.text:00401694                 movzx   eax, byte ptr [eax]
.text:00401697                 xor     eax, 0FFFFFF8Fh
.text:0040169A                 cmp     dl, al
.text:0040169C                 jz      short loc_4016A5
.text:0040169E                 mov     eax, 3
.text:004016A3                 jmp     short locret_4016B1
.text:004016A5 ; ---------------------------------------------------------------------------
.text:004016A5
.text:004016A5 loc_4016A5:                             ; CODE XREF: main_401630+6Cj
.text:004016A5                 add     [esp+20h+var_4], 1
.text:004016AA                 jmp     short loc_401675
.text:004016AC ; ---------------------------------------------------------------------------
.text:004016AC
.text:004016AC loc_4016AC:                             ; CODE XREF: main_401630+4Aj
.text:004016AC                 mov     eax, 0
.text:004016B1
...
```

This a simple 1 byte XOR algorithm. We can trivially get the flag with the following
code:
```python

encflag = [
    0xCB, 0xFD, 0xE8, 0xE1, 0xDC, 0xF4, 0xD8, 0xEE, 0xEE, 0xEE,
    0xF6, 0xDB, 0xE0, 0xE0, 0xCA, 0xD5, 0xAE, 0xAE, 0xBE, 0xF2    
]

print [f ^ 0x8f for f in encflag]
print [chr(f ^ 0x8f) for f in encflag]
print ''.join(chr(f ^ 0x8f) for f in encflag)
```

The flag is: `DrgnS{WaaayTooEZ!!1}`

___