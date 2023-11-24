## SEECON quals 2023 - jumpout (RE 84)
#### 16/09 - 17/09/2023 (24 hrs)

### Description

*Sequential execution*

```
jumpout.tar.gz 20551442563bc7ad9c8d21806f85c68603f3822a
```

### Solution

Very simple challenge. We just need to figure out the execution flow:
```assembly
.text:00005555555550E0 ; void __fastcall main(int, char **, char **)
.text:00005555555550E0 main    proc near                       ; DATA XREF: start+18↓o
.text:00005555555550E0 ; __unwind { // 555555554000
.text:00005555555550E0         endbr64
.text:00005555555550E4         push    r15
.text:00005555555550E6         lea     rdx, STEP2_PRINT_FLAG_STR
.text:00005555555550ED         lea     rcx, STEP3_READ_FLAG
.text:00005555555550F4         push    r14
.text:00005555555550F6         mov     r14d, 2
.text:00005555555550FC         lea     r15, aWrong             ; "Wrong..."
.text:0000555555555103         push    r13
.text:0000555555555105         lea     r13, a99s               ; "%99s"
.text:000055555555510C         push    r12
.text:000055555555510E         lea     r12, aFlag              ; "FLAG: "
.text:0000555555555115         push    rbp
.text:0000555555555116         push    rbx
.text:0000555555555117         lea     ebx, [r14-1]
.text:000055555555511B         sub     rsp, 0A8h
.text:0000555555555122         mov     rax, fs:28h
.text:000055555555512B         mov     [rsp+0D8h+var_40], rax
.text:0000555555555133         lea     rax, STEP1_BZERO_BUF
.text:000055555555513A         mov     [rsp+0D8h+var_D0], rdx
.text:000055555555513F         lea     rdx, STEP5_CHECK_FLAG
.text:0000555555555146         mov     [rsp+0D8h+var_C8], rcx
.text:000055555555514B         lea     rcx, STEP6_VERIFY_FLAG
.text:0000555555555152         mov     [rsp+0D8h+var_C0], rdx
.text:0000555555555157         lea     rdx, MAIN_RETURN
.text:000055555555515E         mov     [rsp+0D8h+var_B8], rcx
.text:0000555555555163         mov     [rsp+0D8h+var_B0], rdx
.text:0000555555555168         mov     [rsp+0D8h+var_D8], rax
.text:000055555555516C         jmp     rax
```

```assembly
.text:0000555555555170
.text:0000555555555170 STEP1_BZERO_BUF:                        ; DATA XREF: main+53↑o
.text:0000555555555170         endbr64
.text:0000555555555174         lea     rsi, [rsp+0D8h+var_A8]
.text:0000555555555179         mov     ecx, 0Ch
.text:000055555555517E         xor     eax, eax
.text:0000555555555180         mov     rdi, rsi
.text:0000555555555183         rep stosq
.text:0000555555555186         mov     dword ptr [rdi], 0
```

```assembly
.text:0000555555555210 STEP2_PRINT_FLAG_STR:                   ; DATA XREF: main+6↑o
.text:0000555555555210         endbr64
.text:0000555555555214         mov     rsi, r12
.text:0000555555555217         mov     edi, 1
.text:000055555555521C         xor     eax, eax
.text:000055555555521E         add     r14d, 1
.text:0000555555555222         call    ___printf_chk
.text:0000555555555227         mov     rax, [rsp+rbx*8+0]
.text:000055555555522B         lea     ebx, [r14-1]
.text:000055555555522F         jmp     rax
```

```assembly
.text:00005555555551F0 STEP3_READ_FLAG:                        ; DATA XREF: main+D↑o
.text:00005555555551F0         endbr64
.text:00005555555551F4         xor     eax, eax
.text:00005555555551F6         lea     rsi, [rsp+0D8h+var_A8]
.text:00005555555551FB         mov     rdi, r13
.text:00005555555551FE         call    ___isoc99_scanf
.text:0000555555555203         cmp     eax, 1
.text:0000555555555206         jz      short STEP4_PARSE_FLAG
.text:0000555555555208         mov     eax, 1
.text:000055555555520D         jmp     short MAIN_EXIT
```

```assembly
.text:000055555555518C STEP4_PARSE_FLAG:                       ; CODE XREF: main+126↓j
.text:000055555555518C                                         ; main+16C↓j ...
.text:000055555555518C         mov     rax, [rsp+rbx*8+0D8h+var_D8]
.text:0000555555555190         add     r14d, 1
.text:0000555555555194         lea     ebx, [r14-1]
.text:0000555555555198         jmp     rax
```

```assembly
.text:00005555555551D0 STEP5_CHECK_FLAG:                       ; DATA XREF: main+5F↑o
.text:00005555555551D0         endbr64
.text:00005555555551D4         lea     rdi, [rsp+arg_28]
.text:00005555555551D9         add     r14d, 1
.text:00005555555551DD         call    u_check_flag
.text:00005555555551E2         mov     ebp, eax
.text:00005555555551E4         mov     rax, [rsp+rbx*8+0]
.text:00005555555551E8         lea     ebx, [r14-1]
.text:00005555555551EC         jmp     rax
```

```assembly
.text:0000555555555238
.text:0000555555555238 STEP6_VERIFY_FLAG:                      ; DATA XREF: main+6B↑o
.text:0000555555555238         endbr64
.text:000055555555523C         test    ebp, ebp
.text:000055555555523E         jnz     short BADBOY_MESSAGE
.text:0000555555555240         lea     rdi, s                  ; "Correct!"
.text:0000555555555247         call    _puts
.text:000055555555524C         jmp     STEP4_PARSE_FLAG
.text:0000555555555251
.text:0000555555555251 BADBOY_MESSAGE:                         ; CODE XREF: main+15E↑j
.text:0000555555555251         mov     rdi, r15                ; s
.text:0000555555555254         call    _puts
.text:0000555555555259         jmp     STEP4_PARSE_FLAG
```

```assembly
.text:0000555555555480 ; void u_check_flag()
.text:0000555555555480 u_check_flag proc near                  ; CODE XREF: main+FD↑p
.text:0000555555555480
.text:0000555555555480 var_68  = qword ptr -68h
.text:0000555555555480 var_60  = qword ptr -60h
.text:0000555555555480 var_58  = qword ptr -58h
.text:0000555555555480 var_50  = qword ptr -50h
.text:0000555555555480 var_40  = qword ptr -40h
.text:0000555555555480
.text:0000555555555480 ; __unwind { // 555555554000
.text:0000555555555480         endbr64
.text:0000555555555484         push    r15
.text:0000555555555486         lea     rcx, u_get_next_func
.text:000055555555548D         lea     rdx, sub_555555555560
.text:0000555555555494         mov     r15d, 2
.text:000055555555549A         push    r14
.text:000055555555549C         lea     r14d, [r15-1]
.text:00005555555554A0         push    r13
.text:00005555555554A2         lea     r13, glo_target_flag
.text:00005555555554A9         push    r12
.text:00005555555554AB         mov     r12, rdi
.text:00005555555554AE         push    rbp
.text:00005555555554AF         push    rbx
.text:00005555555554B0         sub     rsp, 38h
.text:00005555555554B4         mov     rax, fs:28h
.text:00005555555554BD         mov     [rsp+68h+var_40], rax
.text:00005555555554C2         lea     rax, u_check_flag_len
.text:00005555555554C9         mov     [rsp+68h+var_60], rcx
.text:00005555555554CE         lea     rcx, sub_555555555510
.text:00005555555554D5         mov     [rsp+68h+var_58], rdx
.text:00005555555554DA         mov     [rsp+68h+var_50], rcx
.text:00005555555554DF         mov     [rsp+68h+var_68], rax
.text:00005555555554E3         jmp     rax
.text:00005555555554E3 u_check_flag endp
```

```assembly
.text:00005555555554E8 u_check_flag_len proc near              ; DATA XREF: u_check_flag+42↑o
.text:00005555555554E8         endbr64
.text:00005555555554EC         mov     rdi, r12                ; s
.text:00005555555554EF         call    _strlen
.text:00005555555554F4         cmp     rax, 1Dh                ; must be 29 characters long
.text:00005555555554F8         jnz     loc_555555555598
.text:00005555555554F8 u_check_flag_len endp ; sp-analysis failed
```

```assembly
.text:0000555555555560 sub_555555555560 proc near              ; DATA XREF: u_check_flag+D↑o
.text:0000555555555560         endbr64
.text:0000555555555564         xor     ebx, ebx
.text:0000555555555566         db      2Eh
.text:0000555555555566         nop     word ptr [rax+rax+00000000h]
.text:0000555555555570
.text:0000555555555570 FLAG_ENCRYPT_LOOP:                      ; CODE XREF: sub_555555555560+31↓j
.text:0000555555555570         movzx   edi, byte ptr [r12+rbx] ; flag[i]
.text:0000555555555575         mov     esi, ebx
.text:0000555555555577         call    u_encrypt_char
.text:000055555555557C         cmp     [r13+rbx+0], al
.text:0000555555555581         setz    al
.text:0000555555555584         add     rbx, 1
.text:0000555555555588         movzx   eax, al
.text:000055555555558B         and     ebp, eax
.text:000055555555558D         cmp     rbx, 1Dh
.text:0000555555555591         jnz     short FLAG_ENCRYPT_LOOP ; flag[i]
.text:0000555555555593         jmp     loc_5555555554FE
.text:0000555555555593 sub_555555555560 endp
```

```asssembly
.text:0000555555555360 u_encrypt_char proc near                ; CODE XREF: sub_555555555560+17↓p
.text:0000555555555360
.text:0000555555555360 var_48  = qword ptr -48h
.text:0000555555555360 var_40  = qword ptr -40h
.text:0000555555555360 var_38  = qword ptr -38h
.text:0000555555555360 var_30  = qword ptr -30h
.text:0000555555555360 var_28  = qword ptr -28h
.text:0000555555555360 var_20  = qword ptr -20h
.text:0000555555555360 var_10  = qword ptr -10h
.text:0000555555555360
.text:0000555555555360 ; __unwind { // 555555554000
.text:0000555555555360         endbr64
.text:0000555555555364         sub     rsp, 48h
.text:0000555555555368         lea     rcx, u_encr_op_1
.text:000055555555536F         mov     edx, 2
.text:0000555555555374         mov     r11d, edi
.text:0000555555555377         mov     rax, fs:28h
.text:0000555555555380         mov     [rsp+48h+var_10], rax
.text:0000555555555385         xor     eax, eax
.text:0000555555555387         lea     rax, u_encr_op_2
.text:000055555555538E         mov     [rsp+48h+var_48], rcx
.text:0000555555555392         movsxd  rdi, esi
.text:0000555555555395         mov     [rsp+48h+var_40], rax
.text:000055555555539A         lea     rax, u_encr_op_3
.text:00005555555553A1         lea     r10, glo_buf
.text:00005555555553A8         mov     [rsp+48h+var_38], rax
.text:00005555555553AD         lea     rax, u_encr_op_4
.text:00005555555553B4         mov     [rsp+48h+var_30], rax
.text:00005555555553B9         lea     rax, u_encr_op_5
.text:00005555555553C0         mov     [rsp+48h+var_28], rax
.text:00005555555553C5         lea     rax, u_encr_op_6
.text:00005555555553CC         mov     [rsp+48h+var_20], rax
.text:00005555555553D1         lea     eax, [rdx-1]
.text:00005555555553D4         jmp     rcx
.text:00005555555553D4 u_encrypt_char endp
```

```assembly
.text:00005555555553E0 u_encr_op_6 proc near                   ; DATA XREF: u_encrypt_char+65↑o
.text:00005555555553E0
.text:00005555555553E0 arg_30  = qword ptr  38h
.text:00005555555553E0
.text:00005555555553E0 ; FUNCTION CHUNK AT .text:0000555555555473 SIZE 00000005 BYTES
.text:00005555555553E0
.text:00005555555553E0         endbr64
.text:00005555555553E4         mov     rax, [rsp+arg_30]
.text:00005555555553E9         sub     rax, fs:28h
.text:00005555555553F2         jnz     short loc_555555555473
.text:00005555555553F4         mov     eax, r8d                ; set return value
.text:00005555555553F7         add     rsp, 48h
.text:00005555555553FB         retn
.text:00005555555553FB u_encr_op_6 endp ; sp-analysis failed
.text:00005555555553FB
.text:00005555555553FB ; ---------------------------------------------------------------------------
.text:00005555555553FC         align 20h
.text:0000555555555400
.text:0000555555555400 ; =============== S U B R O U T I N E =======================================
.text:0000555555555400
.text:0000555555555400
.text:0000555555555400 u_encr_op_5 proc near                   ; DATA XREF: u_encrypt_char+59↑o
.text:0000555555555400         endbr64
.text:0000555555555404         mov     rcx, [rsp+rax*8+0]
.text:0000555555555408         add     edx, 1
.text:000055555555540B         xor     r8d, r9d                ; r8 = flag[i] ^ i ^ 0x55 ^ buf[i]
.text:000055555555540E         lea     eax, [rdx-1]
.text:0000555555555411         jmp     rcx
.text:0000555555555411 u_encr_op_5 endp
.text:0000555555555411
.text:0000555555555411 ; ---------------------------------------------------------------------------
.text:0000555555555413         align 8
.text:0000555555555418
.text:0000555555555418 ; =============== S U B R O U T I N E =======================================
.text:0000555555555418
.text:0000555555555418
.text:0000555555555418 u_encr_op_4 proc near                   ; DATA XREF: u_encrypt_char+4D↑o
.text:0000555555555418         endbr64
.text:000055555555541C         mov     rcx, [rsp+rax*8+0]
.text:0000555555555420         add     edx, 1
.text:0000555555555423         movzx   r9d, byte ptr [r10+rdi] ; r9 = buf[i]
.text:0000555555555428         lea     eax, [rdx-1]
.text:000055555555542B         jmp     rcx
.text:000055555555542B u_encr_op_4 endp
.text:000055555555542B
.text:000055555555542B ; ---------------------------------------------------------------------------
.text:000055555555542D         align 10h
.text:0000555555555430
.text:0000555555555430 ; =============== S U B R O U T I N E =======================================
.text:0000555555555430
.text:0000555555555430
.text:0000555555555430 u_encr_op_3 proc near                   ; DATA XREF: u_encrypt_char+3A↑o
.text:0000555555555430         endbr64
.text:0000555555555434         mov     rcx, [rsp+rax*8+0]
.text:0000555555555438         add     edx, 1
.text:000055555555543B         xor     r8d, 55h                ; flag[i] ^ i ^ 0x55
.text:000055555555543F         lea     eax, [rdx-1]
.text:0000555555555442         jmp     rcx
.text:0000555555555442 u_encr_op_3 endp
.text:0000555555555442
.text:0000555555555442 ; ---------------------------------------------------------------------------
.text:0000555555555444         align 8
.text:0000555555555448
.text:0000555555555448 ; =============== S U B R O U T I N E =======================================
.text:0000555555555448
.text:0000555555555448
.text:0000555555555448 u_encr_op_2 proc near                   ; DATA XREF: u_encrypt_char+27↑o
.text:0000555555555448         endbr64
.text:000055555555544C         mov     rcx, [rsp+rax*8+0]
.text:0000555555555450         add     edx, 1
.text:0000555555555453         xor     r8d, esi                ; flag[i] ^ i
.text:0000555555555456         lea     eax, [rdx-1]
.text:0000555555555459         jmp     rcx
.text:0000555555555459 u_encr_op_2 endp
.text:0000555555555459
.text:0000555555555459 ; ---------------------------------------------------------------------------
.text:000055555555545B         align 20h
.text:0000555555555460
.text:0000555555555460 ; =============== S U B R O U T I N E =======================================
.text:0000555555555460
.text:0000555555555460
.text:0000555555555460 ; __int64 __fastcall u_encr_op_1(_QWORD)
.text:0000555555555460 u_encr_op_1 proc near                   ; DATA XREF: u_encrypt_char+8↑o
.text:0000555555555460         endbr64
.text:0000555555555464         mov     rcx, [rsp+rax*8+0]
.text:0000555555555468         add     edx, 1
.text:000055555555546B         mov     r8d, r11d
.text:000055555555546E         lea     eax, [rdx-1]
.text:0000555555555471         jmp     rcx
.text:0000555555555471 u_encr_op_1 endp
```

Based on that we can write the decompiled code in Python and get the flag:
```python
buf = [
    0xF6, 0xF5, 0x31, 0xC8, 0x81, 0x15, 0x14, 0x68, 0xF6, 0x35,
    0xE5, 0x3E, 0x82, 0x09, 0xCA, 0xF1, 0x8A, 0xA9, 0xDF, 0xDF,
    0x33, 0x2A, 0x6D, 0x81, 0xF5, 0xA6, 0x85, 0xDF, 0x17
]

trg = [
    0xF0, 0xE4, 0x25, 0xDD, 0x9F, 0x0B, 0x3C, 0x50, 0xDE, 0x04,
    0xCA, 0x3F, 0xAF, 0x30, 0xF3, 0xC7, 0xAA, 0xB2, 0xFD, 0xEF,
    0x17, 0x18, 0x57, 0xB4, 0xD0, 0x8F, 0xB8, 0xF4, 0x23
]

flag = ''.join(chr(buf[i] ^ 0x55 ^ i ^ trg[i]) for i in range(0x1D))
print(flag)
```

So the flag is: `SECCON{jump_table_everywhere}`
___

