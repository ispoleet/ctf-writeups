
## Plaid CTF 2020 - reee (Reversing 150)
##### 17/04 - 19/04/2020 (48hr)
___


### Description: 

Tired from all of the craziness in the Inner Sanctum, you decide to venture out to the beach
to relax. You doze off in the sand only to be awoken by the loud “reee” of an osprey. A shell
falls out of its talons and lands right where your head was a moment ago. No rest for the weary,
huh? It looks a little funny, so you pick it up and realize that it’s backwards. I guess you’ll
have to reverse it.

```
reee-969a38276c46a65001faa2eaf75bf6ab3c444096b9d34094fd0e500badfaa73d.tar.gz
```

**Hint:** Flag format

The flag format is `pctf{$FLAG}`. This constraint should resolve any ambiguities in solutions.

___


### Solution

We have a self-modifying program:
```Assembly
.text:000000000040064E ; FUNCTION CHUNK AT .text:000000000040090D SIZE 0000002C BYTES
.text:000000000040064E
.text:000000000040064E         push    rbp
.text:000000000040064F         mov     rbp, rsp
.text:0000000000400652         push    rbx
.text:0000000000400653         sub     rsp, 38h
.text:0000000000400657         mov     [rbp+var_34], edi
.text:000000000040065A         mov     [rbp+var_40], rsi
.text:000000000040065E         cmp     [rbp+var_34], 1
.text:0000000000400662         jg      short ARGV_OK_40066E
.text:0000000000400664         mov     edi, offset s           ; "need a flag!"
.text:0000000000400669         call    _puts
.text:000000000040066E
.text:000000000040066E ARGV_OK_40066E:                         ; CODE XREF: main+14j
.text:000000000040066E         mov     rax, [rbp+var_40]
.text:0000000000400672         mov     rax, [rax+8]
.text:0000000000400676         mov     [rbp+var_20], rax
.text:000000000040067A         mov     [rbp+var_18], 0
.text:0000000000400682         mov     [rbp+iter_i_24], 0
.text:0000000000400689         jmp     short OUTER_LOOP_END_4006CB
.text:000000000040068B ; ---------------------------------------------------------------------------
.text:000000000040068B
.text:000000000040068B OUTER_LOOP_40068B:                      ; CODE XREF: main+84j
.text:000000000040068B                                         ; .text:00000000004006ECj
.text:000000000040068B         mov     [rbp+iter_j_28], 0
.text:0000000000400692         jmp     short INNER_LOOP_END_4006BE ; if j < 0x227 continue
.text:0000000000400694 ; ---------------------------------------------------------------------------
.text:0000000000400694
.text:0000000000400694 INNER_LOOP_400694:                      ; CODE XREF: main+77j
.text:0000000000400694         mov     eax, [rbp+iter_j_28]
.text:0000000000400697         cdqe
.text:0000000000400699         lea     rbx, ENCR_PAYLOAD_4006E5[rax]
.text:00000000004006A0         mov     eax, [rbp+iter_j_28]
.text:00000000004006A3         cdqe
.text:00000000004006A5         add     rax, 4006E5h
.text:00000000004006AB         movzx   eax, byte ptr [rax]
.text:00000000004006AE         movsx   eax, al                 ; eax = encr_payload[j]
.text:00000000004006B1         mov     edi, eax
.text:00000000004006B3
.text:00000000004006B3 loc_4006B3:                             ; CODE XREF: .text:000000000040072Aj
.text:00000000004006B3         call    F_400526
.text:00000000004006B8         mov     [rbx], al               ; encr_payload[j++] = F(encr_payload[j])
.text:00000000004006BA         add     [rbp+iter_j_28], 1
.text:00000000004006BE
.text:00000000004006BE INNER_LOOP_END_4006BE:                  ; CODE XREF: main+44j
.text:00000000004006BE         cmp     [rbp+iter_j_28], 227h   ; if j < 0x227 continue
.text:00000000004006C5         jle     short INNER_LOOP_400694
.text:00000000004006C7         add     [rbp+iter_i_24], 1
.text:00000000004006CB
.text:00000000004006CB OUTER_LOOP_END_4006CB:                  ; CODE XREF: main+3Bj
.text:00000000004006CB         cmp     [rbp+iter_i_24], 7A68h
.text:00000000004006D2         jle     short OUTER_LOOP_40068B
.text:00000000004006D4         mov     rdx, [rbp+var_20]
.text:00000000004006D8         mov     rax, rdx
.text:00000000004006DB         call    ENCR_PAYLOAD_4006E5
.text:00000000004006E0         jmp     PRINT_MSG_40090D
.text:00000000004006E0 main    endp
```

Function `F_400526` does the actual single byte decryption:
```assembly
.text:0000000000400526
.text:0000000000400526         push    rbp
.text:0000000000400527         mov     rbp, rsp
.text:000000000040052A         mov     eax, edi
.text:000000000040052C         mov     [rbp+arg0_4], al
.text:000000000040052F         movzx   eax, cs:counter_601161
.text:0000000000400536         add     eax, 1                  ; ++counter
.text:0000000000400539         mov     cs:counter_601161, al
.text:000000000040053F         movzx   eax, cs:counter_601161
.text:0000000000400546         movzx   eax, al
.text:0000000000400549         cdqe
.text:000000000040054B         movzx   edx, tbl_A_601060[rax]  ; edx = tbl_A[counter % 256]
.text:0000000000400552         movzx   eax, cs:val_V_601162
.text:0000000000400559         add     eax, edx                ; val += tbl_A[ctr % 256] & 0xff
.text:000000000040055B         mov     cs:val_V_601162, al
.text:0000000000400561         movzx   eax, cs:counter_601161
.text:0000000000400568         movzx   edx, al
.text:000000000040056B         movzx   eax, cs:counter_601161
.text:0000000000400572         movzx   eax, al
.text:0000000000400575         cdqe
.text:0000000000400577         movzx   ecx, tbl_A_601060[rax]  ; ecx = tbl_A[ctr % 256]
.text:000000000040057E         movzx   eax, cs:val_V_601162
.text:0000000000400585         movzx   eax, al
.text:0000000000400588         cdqe                            ; SWAP(val, ctr)!
.text:000000000040058A         movzx   eax, tbl_A_601060[rax]  ; eax = tbl_A[val]
.text:0000000000400591         xor     ecx, eax
.text:0000000000400593         movsxd  rax, edx
.text:0000000000400596         mov     tbl_A_601060[rax], cl   ; tbl_A[ctr % 256] ^= tbl_A[val]
.text:000000000040059C         movzx   eax, cs:val_V_601162
.text:00000000004005A3         movzx   edx, al
.text:00000000004005A6         movzx   eax, cs:val_V_601162
.text:00000000004005AD         movzx   eax, al
.text:00000000004005B0         cdqe
.text:00000000004005B2         movzx   ecx, tbl_A_601060[rax]  ; ecx = tbl_A[val]
.text:00000000004005B9         movzx   eax, cs:counter_601161
.text:00000000004005C0         movzx   eax, al
.text:00000000004005C3         cdqe
.text:00000000004005C5         movzx   eax, tbl_A_601060[rax]  ; eax = tbl_A[ctr]
.text:00000000004005CC         xor     ecx, eax
.text:00000000004005CE         movsxd  rax, edx
.text:00000000004005D1         mov     tbl_A_601060[rax], cl   ; tbl_A[val] ^= tbl_A[ctr]
.text:00000000004005D7         movzx   eax, cs:counter_601161
.text:00000000004005DE         movzx   edx, al
.text:00000000004005E1         movzx   eax, cs:counter_601161
.text:00000000004005E8         movzx   eax, al
.text:00000000004005EB         cdqe
.text:00000000004005ED         movzx   ecx, tbl_A_601060[rax]  ; ecx = tbl_A[ctr]
.text:00000000004005F4         movzx   eax, cs:val_V_601162
.text:00000000004005FB         movzx   eax, al
.text:00000000004005FE         cdqe
.text:0000000000400600         movzx   eax, tbl_A_601060[rax]  ; eax = tbl_A[val]
.text:0000000000400607         xor     ecx, eax
.text:0000000000400609         movsxd  rax, edx
.text:000000000040060C         mov     tbl_A_601060[rax], cl   ; tbl_A[ctr] ^= tbl_A[val]
.text:0000000000400612         movzx   eax, cs:counter_601161
.text:0000000000400619         movzx   eax, al
.text:000000000040061C         cdqe
.text:000000000040061E         movzx   edx, tbl_A_601060[rax]  ; edx = tbl_A[ctr]
.text:0000000000400625         movzx   eax, cs:val_V_601162
.text:000000000040062C         movzx   eax, al
.text:000000000040062F         cdqe
.text:0000000000400631         movzx   eax, tbl_A_601060[rax]  ; eax = tbl_A[val]
.text:0000000000400638         add     eax, edx                ; eax = (tbl_A[ctr] + tbl_A[val]) % 256
.text:000000000040063A         movzx   eax, al
.text:000000000040063D         cdqe
.text:000000000040063F         movzx   edx, tbl_A_601060[rax]
.text:0000000000400646         movzx   eax, [rbp+arg0_4]       ; eax = tbl_A[tbl_A[ctr] + tbl_A[val]]
.text:000000000040064A         add     eax, edx                ; return arg0 + tbl_A[tbl_A[ctr] + tbl_A[val]]
.text:000000000040064C         pop     rbp
.text:000000000040064D         retn
```

Let's decompile it:
```python
encr_payload = [
    0xF9, 0x93, 0x75, 0x2D, 0xDB, 0xC6, 0xAB, 0xE0, 0xA2, 0x3B, 0x49, 0x9D, 0x8C, 0x5C, 0x86, 0xDD,
    0x0E, 0x73, 0xCD, 0xF9, 0x1F, 0x69, 0x18, 0x32, 0x29, 0x59, 0x2F, 0x07, 0xA7, 0x17, 0x79, 0x09,
    0x10, 0x8F, 0xD6, 0xFE, 0xCB, 0x5B, 0xC3, 0x70, 0xC3, 0x1F, 0xD6, 0xAC, 0x87, 0x42, 0x9F, 0x79,
    0x4A, 0x40, 0x35, 0xA8, 0x9D, 0xBB, 0xE0, 0xC1, 0xBD, 0x6A, 0x7F, 0xAE, 0x58, 0xEB, 0x5C, 0x01,
    0xB1, 0x97, 0x77, 0xAD, 0x1D, 0x11, 0xEC, 0x10, 0x3D, 0x1F, 0xFB, 0xF3, 0x6D, 0xE2, 0x67, 0xB1,
    0x79, 0x9E, 0x5E, 0x3C, 0x14, 0x30, 0xC9, 0xFC, 0x88, 0xFF, 0xCC, 0xE8, 0x95, 0xCD, 0x47, 0x89
    # ....
]

tbl_A = [
    0xE7, 0x9F, 0x15, 0xB0, 0xD0, 0x93, 0xCB, 0x67, 0x7B, 0x92, 0x68, 0xE1, 0x04, 0x17, 0x1E, 0x77,
    0x43, 0xAD, 0xAA, 0x23, 0xD5, 0xBA, 0x55, 0x91, 0x4A, 0x22, 0x8C, 0x5A, 0xA8, 0x44, 0x30, 0x20,
    0xDE, 0x2A, 0x79, 0x5B, 0xF3, 0xA3, 0xF2, 0x53, 0xEA, 0xD1, 0x16, 0x14, 0x9E, 0xF6, 0x09, 0x7F,
    0xBD, 0xBB, 0xC0, 0xD8, 0x6A, 0xE8, 0xBE, 0x66, 0x59, 0x58, 0x42, 0x7A, 0xDF, 0xF8, 0xFD, 0xB1,
    0xCE, 0xC9, 0x85, 0x6F, 0x6D, 0x08, 0x4C, 0xAE, 0xD6, 0x69, 0x89, 0xB8, 0x1B, 0xFC, 0x8D, 0xC1,
    0x99, 0xDD, 0x27, 0xA5, 0xA1, 0x78, 0x06, 0x97, 0x10, 0xC3, 0x96, 0xA4, 0x1F, 0xD3, 0x36, 0x0B,
    0x56, 0x25, 0x34, 0xFA, 0x49, 0x5E, 0x1C, 0x74, 0x95, 0x6B, 0xD2, 0x6E, 0x9B, 0xF4, 0x2D, 0x01,
    0x76, 0xF7, 0xB5, 0x62, 0x1A, 0xF0, 0xCF, 0x86, 0xE0, 0x32, 0x33, 0x00, 0x2B, 0x2F, 0x94, 0xDA,
    0x46, 0x87, 0x41, 0x8A, 0x0F, 0x4B, 0x1D, 0xC7, 0x28, 0xC8, 0xAF, 0xB6, 0x3E, 0x7D, 0xA7, 0x45,
    0xB4, 0xA9, 0xCD, 0xAB, 0xFE, 0x39, 0x31, 0x21, 0x4F, 0xE3, 0x83, 0x2C, 0xE5, 0x84, 0x2E, 0x81,
    0x07, 0x03, 0xD9, 0x65, 0xFF, 0xD4, 0x72, 0x90, 0xBF, 0x6C, 0xF5, 0xCA, 0x37, 0x61, 0x75, 0x35,
    0x88, 0x54, 0x9A, 0x5F, 0x70, 0xC4, 0x52, 0x3C, 0x0D, 0x57, 0x24, 0x7C, 0x3D, 0xCC, 0x29, 0x12,
    0x3F, 0xF9, 0x80, 0x7E, 0xED, 0x05, 0x38, 0xC2, 0x50, 0xEB, 0x71, 0xB3, 0x98, 0x0E, 0xEE, 0xBC,
    0x19, 0xF1, 0xFB, 0x13, 0x4E, 0xE4, 0x3A, 0x02, 0x8F, 0x8B, 0xEF, 0x3B, 0x63, 0x18, 0xA2, 0x40,
    0x73, 0x48, 0x4D, 0xA6, 0x0A, 0x9C, 0xDB, 0xB2, 0x5C, 0x82, 0xE9, 0x64, 0xB9, 0x60, 0x11, 0x9D,
    0xE6, 0xC6, 0x5D, 0xD7, 0xB7, 0x26, 0xEC, 0xE2, 0x51, 0xA0, 0x8E, 0xDC, 0x0C, 0xAC, 0x47, 0xC5
]

ctr = 0
val = 0

def F(arg0):
    global ctr, val

    ctr = (ctr + 1) % 256       
    val = (val + tbl_A[ctr % 256]) % 256
    
    tbl_A[ctr], tbl_A[val] = tbl_A[val], tbl_A[ctr]

    return arg0 + tbl_A[(tbl_A[ctr] + tbl_A[val]) % 256]

# repeat 0x228 * 0x7a69 (=552 * 31337) times
for enc in encr_payload:
    print '%x -> %x' % (enc, F(enc))
```


Nothing special here. After payload decryption, the actual encryption takes place:
```assembly
.text:00000000004006E5
.text:00000000004006E5             ENCR_PAYLOAD_4006E5:                    ; CODE XREF: main+8Dp
.text:00000000004006E5                                                     ; DATA XREF: main+4Bo
.text:00000000004006E5 55              push    rbp
.text:00000000004006E6 48 8B EC        mov     rbp, rsp
.text:00000000004006E9 E8 14 00 00+    call    loc_400702
.text:00000000004006EE 8A C8           mov     cl, al
.text:00000000004006F0 B8 32 E4 5F+    mov     eax, 0AE5FE432h
.text:00000000004006F5 05 CE 1B A0+    add     eax, 51A01BCEh
.text:00000000004006FA FF C0           inc     eax
.text:00000000004006FC 73 08           jnb     short near ptr loc_400705+1
.text:00000000004006FE 8A C1           mov     al, cl
.text:0000000000400700 C9              leave
.text:0000000000400701 C3              retn
.text:0000000000400702             ; ---------------------------------------------------------------------------
.text:0000000000400702
.text:0000000000400702             loc_400702:                             ; CODE XREF: .text:00000000004006E9p
.text:0000000000400702 53              push    rbx
.text:0000000000400703 57              push    rdi
.text:0000000000400704 55              push    rbp
.text:0000000000400705
.text:0000000000400705             loc_400705:                             ; CODE XREF: .text:00000000004006FCj
.text:0000000000400705 48 8B EC        mov     rbp, rsp
.text:0000000000400708 48 8B D0        mov     rdx, rax
.text:000000000040070B FF C8           dec     eax
.text:000000000040070B             ; ---------------------------------------------------------------------------
.text:000000000040070D EB              db 0EBh
.text:000000000040070E             ; ---------------------------------------------------------------------------
.text:000000000040070E FF C0           inc     eax
.text:0000000000400710 48 8B FA        mov     rdi, rdx
.text:0000000000400713 32 C0           xor     al, al
.text:0000000000400715 33 C9           xor     ecx, ecx
.text:0000000000400717 48 FF C9        dec     rcx
.text:000000000040071A F2 AE           repne scasb
.text:000000000040071C F7 D1           not     ecx
.text:000000000040071E FF C9           dec     ecx
.text:0000000000400720
.text:0000000000400720             loc_400720:                             ; CODE XREF: .text:000000000040075Fj
.text:0000000000400720 B8 87 59 18+    mov     eax, 92185987h
.text:0000000000400725 35 85 3A 96+    xor     eax, 32963A85h
.text:000000000040072A 79 8B           jns     short near ptr loc_4006B3+4 ; never taken
.text:000000000040072C B8 D9 42 BC+    mov     eax, 0C3BC42D9h
.text:0000000000400731 35 07 C9 D2+    xor     eax, 1ED2C907h
.text:0000000000400736 79 0A           jns     short near ptr loc_40073F+3 ; repeat 0x539 times
.text:0000000000400738 6A 50           push    50h
.text:000000000040073A 41 59           pop     r9
.text:000000000040073C 45 33 C0        xor     r8d, r8d
.text:000000000040073F
.text:000000000040073F             loc_40073F:                             ; CODE XREF: .text:0000000000400761j
.text:000000000040073F                                                     ; .text:0000000000400736j
.text:000000000040073F 41 81 F8 39+    cmp     r8d, 539h                   ; repeat 0x539 times
.text:0000000000400746
.text:0000000000400746             loc_400746:                             ; CODE XREF: .text:000000000040076Dj
.text:0000000000400746 7C 1B           jl      short SMALL_R8_400763
.text:0000000000400748 EB 2A           jmp     short loc_400774
```

The interesting part here is that there are jumps in the middle of other instructions, which makes
reversing annoying. The core of the encryption algorithm, is quite simple:
```assembly:
; initialize key to 0x50
.text:0000000000400738 6A 50           push    50h
.text:000000000040073A 41 59           pop     r9
.text:000000000040073C 45 33 C0        xor     r8d, r8d

; flag[i] ^= key and update key
.text:00000000004007F6 48 8B C2        mov     rax, rdx
.text:00000000004007F9 49 03 C2        add     rax, r10
.text:00000000004007FC 8A 00           mov     al, [rax]                   ; read flag[i]
.text:00000000004007FE             loc_4007FE:                             ; CODE XREF: .text:00000000004007D3j
.text:00000000004007FE 41 32 C1        xor     al, r9b                     ; flag[i] ^ key
.text:0000000000400801 88 03           mov     [rbx], al
.text:0000000000400803 4D 63 D3        movsxd  r10, r11d                   ; update key
.text:0000000000400806 48 8B C2        mov     rax, rdx
.text:0000000000400809 49 03 C2        add     rax, r10
.text:000000000040080C 8A 00           mov     al, [rax]
.text:000000000040080E 44 32 C8        xor     r9b, al                     ; update xor key
.text:0000000000400811 B8 78 CF 1E+    mov     eax, 91ECF78h
.text:0000000000400816 05 88 30 E1+    add     eax, 0F6E13088h             ; eax = 0
.text:000000000040081B FF C0           inc     eax
.text:000000000040082D 79 59           jns     short near ptr loc_400886+2
.text:000000000040082F E9 78 FF FF+    jmp     OUTER_LOOP_4007AC           ; loop back
```

The decompiled version is shown below:
```python
key = 0x50

for i in xrange(1337):
    for j in xrange(len(flag)):
        old_flag = flag[j]
        flag[j] ^= key
        key = old_flag

```

Each time the previous flag character becomes the key for the next flag character.


### Breaking the code


Let's assume a 4 character password `x1 x2 x3 x4`:
```
; 1st iteration
x1  ^  50  =  x1 ^ 50
x2  ^  x1  =  x2 ^ x1
x3  ^  x2  =  x3 ^ x2
x4  ^  x3  =  x4 ^ x3

; 2nd iteration
(x1 ^ 50)  ^  (x4)       =  x4 ^ x1 ^ 50
(x2 ^ x1)  ^  (x1 ^ 50)  =  x2 ^ 50
(x3 ^ x2)  ^  (x2 ^ x1)  =  x3 ^ x1
(x4 ^ x3)  ^  (x3 ^ x2)  =  x4 ^ x2

; 3rd iteration
(x4 ^ x1 ^ 50)  ^  (x4 ^ x3)       =  x1 ^ x3 ^ 50
(x2 ^ 50)       ^  (x4 ^ x1 ^ 50)  =  x1 ^ x2 ^ x4
(x3 ^ x1)       ^  (x2 ^ 50)       =  x1 ^ x2 ^ x3 ^ 50
(x4 ^ x2)       ^  (x3 ^ x1)       =  x1 ^ x2 ^ x3 ^ x4

; 4th iteration
(x1 ^ x3 ^ 50)       ^  (x4 ^ x2)           =  x1 ^ x2 ^ x3 ^ x4 ^ 50
(x1 ^ x2 ^ x4)       ^  (x1 ^ x3 ^ 50)      =  x2 ^ x3 ^ x4 ^ 50
(x1 ^ x2 ^ x3 ^ 50)  ^  (x1 ^ x2 ^ x4)      =  x3 ^ x4 ^ 50
(x1 ^ x2 ^ x3 ^ x4)  ^  (x1 ^ x2 ^ x3 ^ 50) =  x4 ^ 50

; 5th iteration
(x1 ^ x2 ^ x3 ^ x4 ^ 50)  ^  (x1 ^ x2 ^ x3 ^ x4)       =  50 
(x2 ^ x3 ^ x4 ^ 50)       ^  (x1 ^ x2 ^ x3 ^ x4 ^ 50)  =  x1
(x3 ^ x4 ^ 50)            ^  (x2 ^ x3 ^ x4 ^ 50)       =  x2
(x4 ^ 50)                 ^  (x3 ^ x4 ^ 50)            =  x3

; 6th iteration
50  ^  (x4 ^ 50)  =  x4
x1  ^  50         =  x1 ^ 50
x2  ^  x1         =  x2 ^ x1
x3  ^  x2         =  x3 ^ x2

; 7th iteration
x4        ^  x3        = x4 ^ x3
(x1 ^ 50  ^  x4        = x4 ^ x1 ^ 50
(x2 ^ x1  ^  (x1 ^ 50  = x2 ^ 50
(x3 ^ x2  ^  (x2 ^ x1  = x3 ^ x1
```

There are some repeating patterns, but it depends on the password length. The easiest solution
is to throw these equations in **z3 solver** and let him do his magic:
```
ispo@leet:~/ctf/plaid_ctf_2020/reee$ time ./reee_crack.py 
[+] reee crack started.
[+] Encrypted flag: ['1D', '1A', '5A', '59', '44', '48', '13', '18']
[+] Flag length: 33
[+] Constraining variables to 8 bits ...
[+] Adding flag and key equations ...
[+] Adding the final equation ...
[+] Checking sat ...
[+] Valid solution found!
[+]   X_0_0 = 0x70 (p)
[+]   X_0_1 = 0x63 (c)
[+]   X_0_2 = 0x74 (t)
[+]   X_0_3 = 0x66 (f)
[+]   X_0_4 = 0x7b ({)
[+]   X_0_5 = 0x6f (o)
[+]   X_0_6 = 0x6b (k)
[+]   X_0_7 = 0x5f (_)
[+]   X_0_8 = 0x6e (n)
[+]   X_0_9 = 0x6f (o)
[+]   X_0_10 = 0x74 (t)
[+]   X_0_11 = 0x68 (h)
[+]   X_0_12 = 0x69 (i)
[+]   X_0_13 = 0x6e (n)
[+]   X_0_14 = 0x67 (g)
[+]   X_0_15 = 0x5f (_)
[+]   X_0_16 = 0x74 (t)
[+]   X_0_17 = 0x6f (o)
[+]   X_0_18 = 0x6f (o)
[+]   X_0_19 = 0x5f (_)
[+]   X_0_20 = 0x66 (f)
[+]   X_0_21 = 0x61 (a)
[+]   X_0_22 = 0x6e (n)
[+]   X_0_23 = 0x63 (c)
[+]   X_0_24 = 0x79 (y)
[+]   X_0_25 = 0x5f (_)
[+]   X_0_26 = 0x74 (t)
[+]   X_0_27 = 0x68 (h)
[+]   X_0_28 = 0x65 (e)
[+]   X_0_29 = 0x72 (r)
[+]   X_0_30 = 0x65 (e)
[+]   X_0_31 = 0x21 (!)
[+]   X_0_32 = 0x7d (})
[+] Flag: pctf{ok_nothing_too_fancy_there!}
```

For more details take a look at the crack script: [reee_crack.py](./reee_crack.py)

The flag is `pctf{ok_nothing_too_fancy_there!}`. We verify it:

```
ispo@leet:~/ctf/plaid_ctf_2020/reee$ ./reee 'pctf{ok_nothing_too_fancy_there!}'
Correct!
```
___
