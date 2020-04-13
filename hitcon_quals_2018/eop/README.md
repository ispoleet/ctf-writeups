
## HITCON CTF quals 2018 - EOP (Reversing 257)
##### 20/10 - 22/10/2018 (48hr)
___

### Description: 

EOP.

```
eop-811afa1b9fb0c0719a75afd316ea2c57
```
___


### Solution

Let's start from `main`:
```Assembly
.text:0000555555559666     call    init_func_tbl_55555555882A
.text:000055555555966B     lea     rsi, pwd_555555767600
.text:0000555555559672     lea     rdi, format                 ; "%49s"
.text:0000555555559679     mov     eax, 0
.text:000055555555967E     call    _scanf
.text:0000555555559683     lea     rdi, pwd_555555767600       ; s
.text:000055555555968A     call    _strlen
.text:000055555555968F     cmp     rax, 30h
.text:0000555555559693     jz      short LEN_OK_55555555969A
.text:0000555555559695     call    badboy_555555559643
.text:000055555555969A ; ---------------------------------------------------------------------------
.text:000055555555969A
.text:000055555555969A LEN_OK_55555555969A:                    ; CODE XREF: main+36j
.text:000055555555969A     mov     [rbp+iter_i_1C], 0
.text:00005555555596A1
.text:00005555555596A1 OUTER_LOOP_5555555596A1:                ; CODE XREF: main+ACj
.text:00005555555596A1     cmp     [rbp+iter_i_1C], 2Fh
.text:00005555555596A5     jg      short LOOP_EXIT_55555555970B
.text:00005555555596A7     mov     [rbp+var_18], 31h
.text:00005555555596AE     mov     eax, [rbp+iter_i_1C]
.text:00005555555596B1     movsxd  rdx, eax                    ; rdx = i
.text:00005555555596B4     lea     rax, pwd_555555767600
.text:00005555555596BB     add     rax, rdx
.text:00005555555596BE     mov     rdx, [rax+8]                ; rdx = pwd[i+8:i+16]
.text:00005555555596C2     mov     rax, [rax]                  ; rax = pwd[i:i+8]
.text:00005555555596C5     mov     cs:pwd_1_5555557671A0, rax
.text:00005555555596CC     mov     cs:pwd_2_5555557671A8, rdx
.text:00005555555596D3
.text:00005555555596D3 INNER_LOOP_5555555596D3:                ; CODE XREF: main:JMP_INNER_LOOP_5555555596DDj
.text:00005555555596D3     mov     eax, [rbp+var_18]
.text:00005555555596D6     mov     edi, eax
.text:00005555555596D8     call    F_5555555595AF
.text:00005555555596DD ; ---------------------------------------------------------------------------
.text:00005555555596DD
.text:00005555555596DD JMP_INNER_LOOP_5555555596DD:            ; CODE XREF: main+12Bj
.text:00005555555596DD     jmp     short INNER_LOOP_5555555596D3
.text:00005555555596DF ; ---------------------------------------------------------------------------
.text:00005555555596DF
.text:00005555555596DF EXTEND_ENC_PWD_5555555596DF:            ; CODE XREF: main+131j
.text:00005555555596DF     mov     eax, [rbp+iter_i_1C]
.text:00005555555596E2     movsxd  rdx, eax
.text:00005555555596E5     lea     rax, encr_pwd_5555557675C0
.text:00005555555596EC     lea     rcx, [rdx+rax]              ; rcx = &encr_pwd[i]
.text:00005555555596F0     mov     rax, cs:enc_blk_1_5555557671B0
.text:00005555555596F7     mov     rdx, cs:enc_blk_2_5555557671B8
.text:00005555555596FE     mov     [rcx], rax
.text:0000555555559701     mov     [rcx+8], rdx                ; encr_pwd[i:i+16] = enc_blk_1 + enc_blk_2
.text:0000555555559705     add     [rbp+iter_i_1C], 10h
.text:0000555555559709     jmp     short OUTER_LOOP_5555555596A1
.text:000055555555970B ; ---------------------------------------------------------------------------
.text:000055555555970B
.text:000055555555970B LOOP_EXIT_55555555970B:                 ; CODE XREF: main+48j
.text:000055555555970B     mov     edx, 30h                    ; n
.text:0000555555559710     lea     rsi, target_pwd_555555767120 ; s2
.text:0000555555559717     lea     rdi, encr_pwd_5555557675C0  ; s1
.text:000055555555971E     call    _memcmp
.text:0000555555559723     test    eax, eax
.text:0000555555559725     jnz     short BADBOY_555555559741
.text:0000555555559727     lea     rsi, pwd_555555767600
.text:000055555555972E     lea     rdi, aGreatHereSTheF        ; "Great! Here's the flag: hitcon{%s}\n"
.text:0000555555559735     mov     eax, 0
.text:000055555555973A     call    _printf
.text:000055555555973F     jmp     short RET_SUCCESS_555555559746
.text:0000555555559741 ; ---------------------------------------------------------------------------
.text:0000555555559741
.text:0000555555559741 BADBOY_555555559741:                    ; CODE XREF: main+C8j
.text:0000555555559741     call    badboy_555555559643
.text:0000555555559746 ; ---------------------------------------------------------------------------
.text:0000555555559746
.text:0000555555559746 RET_SUCCESS_555555559746:               ; CODE XREF: main+E2j
.text:0000555555559746     mov     eax, 0
.text:000055555555974B     jmp     short RETURN_555555559793
.text:000055555555974D ; ---------------------------------------------------------------------------
.text:000055555555974D     cmp     rdx, 1                      ; after unwind resume
.text:0000555555559751     jz      short loc_55555555975B
.text:0000555555559753     mov     rdi, rax
.text:0000555555559756     call    __Unwind_Resume
.text:000055555555975B ; ---------------------------------------------------------------------------
.text:000055555555975B
.text:000055555555975B loc_55555555975B:                       ; CODE XREF: main+F4j
.text:000055555555975B     mov     rdi, rax
.text:000055555555975E     call    ___cxa_begin_catch
.text:0000555555559763     mov     eax, [rax]
.text:0000555555559765     mov     [rbp+var_14], eax
.text:0000555555559768     cmp     [rbp+var_14], 1Dh
.text:000055555555976C     jnz     short IFELSE_555555559775   ; else
.text:000055555555976E     mov     ebx, 0                      ; if
.text:0000555555559773     jmp     short END_555555559780
.text:0000555555559775 ; ---------------------------------------------------------------------------
.text:0000555555559775
.text:0000555555559775 IFELSE_555555559775:                    ; CODE XREF: main+10Fj
.text:0000555555559775     mov     eax, [rbp+var_14]           ; else
.text:0000555555559778     mov     [rbp+var_18], eax
.text:000055555555977B     mov     ebx, 1
.text:0000555555559780
.text:0000555555559780 END_555555559780:                       ; CODE XREF: main+116j
.text:0000555555559780     call    ___cxa_end_catch
.text:0000555555559785     cmp     ebx, 1
.text:0000555555559788     jz      JMP_INNER_LOOP_5555555596DD
.text:000055555555978E     jmp     EXTEND_ENC_PWD_5555555596DF
.text:0000555555559793 ; ---------------------------------------------------------------------------
.text:0000555555559793
.text:0000555555559793 RETURN_555555559793:                    ; CODE XREF: main+EEj
```

The control flow is hard to follow, but with some effort we can (approximately) decompile it:
```C++
init_func_tbl();

scanf("%49s", pwd);
if (strlen(pwd) != 48) {
    badboy();
}

for (i=0; i<48; i+=16) {
    // process 16 bytes from pwd
    pwd_1, pwd_2 = pwd[i:i+16];
    v18 = 0x31;

    for (;;) {
        try {
            // inner loop        
            F(v18);        
        } catch (exception &e) {
            v14 = *e

            if (v14 == 0x1D) {
                break;
            } else {
                v18 = v14;
            }
        }
    }

    encr_pwd += enc_blk_1;
    encr_pwd += enc_blk_2;        
}

if (memcmp(encr_pwd, target_pwd, 48)) {
    badboy();
}

printf("Great! Here's the flag: hitcon{%s}\n", pwd);

return 0;
```

So, everything starts from function `F_5555555595AF`:
```Assembly
.text:00005555555595BB     mov     edi, 8
.text:00005555555595C0     call    ___cxa_allocate_exception
.text:00005555555595C5     mov     edx, [rbp+arg0_24]
.text:00005555555595C8     movsxd  rdx, edx
.text:00005555555595CB     lea     rcx, ds:0[rdx*8]            ; rcx = arg0 * 8
.text:00005555555595D3     lea     rdx, func_tbl_5555557671E0
.text:00005555555595DA     mov     rdx, [rcx+rdx]              ; rdx = func_tbl[arg0] (8 bytes)
.text:00005555555595DE     mov     [rax], rdx                  ; write function pointer to exception object
.text:00005555555595E1     mov     edx, 0
.text:00005555555595E6     lea     rsi, off_555555765170
.text:00005555555595ED     mov     rdi, rax
.text:00005555555595F0     call    ___cxa_throw                ; throw() actually returns!
.text:00005555555595F5 ; ---------------------------------------------------------------------------
.text:00005555555595F5     cmp     rdx, 1
.text:00005555555595F9     jz      short loc_555555559603
.text:00005555555595FB     mov     rdi, rax
.text:00005555555595FE     call    __Unwind_Resume
.text:0000555555559603 ; ---------------------------------------------------------------------------
.text:0000555555559603
.text:0000555555559603 loc_555555559603:                       ; CODE XREF: F_5555555595AF+4Aj
.text:0000555555559603     mov     rdi, rax
.text:0000555555559606     call    ___cxa_begin_catch
.text:000055555555960B     mov     [rbp+var_18], rax
.text:000055555555960F     mov     rax, [rbp+var_18]
.text:0000555555559613     mov     rax, [rax]
.text:0000555555559616     mov     rax, [rax]                  ; rax = func_tbl[arg0]
.text:0000555555559619     mov     rdx, [rbp+var_18]
.text:000055555555961D     mov     rdi, rdx
.text:0000555555559620     call    rax
.text:0000555555559622     call    ___cxa_end_catch
.text:0000555555559627     jmp     short RETURN_55555555963C
.text:0000555555559629 ; ---------------------------------------------------------------------------
.text:0000555555559629     mov     rbx, rax                    ; after unwind resume
.text:000055555555962C     call    ___cxa_end_catch
.text:0000555555559631     mov     rax, rbx
.text:0000555555559634     mov     rdi, rax
.text:0000555555559637     call    __Unwind_Resume
```

Let's decompile this function:
```C++
void F(arg0) {
    try {
        throw func_tbl[arg0];

    } catch (exception &e) {
        // forget about the syntax, just invoke whatever is thrown :P
        e();
    }

    // point 2
}
```

Program maintains table with function pointers, named `func_tbl_5555557671E0` and invokes functions
from it. Instead of using return instructions, program uses exceptions to return. Hence the name
**EOP** probably stands for **Exception Oriented Programming**!

Program initially calls function at index `0x31`:
```assembly
.text:0000555555559ADC func_31_555555559adc proc near          ; DATA XREF: .data.rel.ro:off_555555765080o
.text:0000555555559ADC
.text:0000555555559ADC var_28= qword ptr -28h
.text:0000555555559ADC iter_14= dword ptr -14h
.text:0000555555559ADC
.text:0000555555559ADC     push    rbp
.text:0000555555559ADD     mov     rbp, rsp
.text:0000555555559AE0     push    rbx
.text:0000555555559AE1     sub     rsp, 28h
.text:0000555555559AE5     mov     [rbp+var_28], rdi
.text:0000555555559AE9     mov     edi, 8
.text:0000555555559AEE     call    ___cxa_allocate_exception
.text:0000555555559AF3     mov     rbx, rax
.text:0000555555559AF6     mov     rdi, rbx
.text:0000555555559AF9     call    sub_5555555597F8
.text:0000555555559AFE     mov     rax, cs:_ZNSt9exceptionD1Ev_ptr
.text:0000555555559B05     mov     rdx, rax
.text:0000555555559B08     lea     rsi, _ZTISt9exception       ; `typeinfo for'std::exception
.text:0000555555559B0F     mov     rdi, rbx
.text:0000555555559B12     call    ___cxa_throw
.text:0000555555559B17 ; ---------------------------------------------------------------------------
.text:0000555555559B17     mov     rdi, rax
.text:0000555555559B1A     call    ___cxa_begin_catch          ; Node: 0x31
.text:0000555555559B1F     mov     [rbp+iter_14], 0
.text:0000555555559B26
.text:0000555555559B26 XOR_LOOP_555555559B26:                  ; CODE XREF: func_31_555555559adc+88j
.text:0000555555559B26     cmp     [rbp+iter_14], 0Fh
.text:0000555555559B2A     jg      short END_XOR_555555559B66
.text:0000555555559B2C     mov     eax, [rbp+iter_14]
.text:0000555555559B2F     movsxd  rdx, eax
.text:0000555555559B32     lea     rax, pwd_1_5555557671A0
.text:0000555555559B39     movzx   ecx, byte ptr [rdx+rax]     ; ecx = pwd[0]
.text:0000555555559B3D     mov     eax, [rbp+iter_14]
.text:0000555555559B40     movsxd  rdx, eax
.text:0000555555559B43     lea     rax, enc_blk_1_5555557671B0
.text:0000555555559B4A     movzx   eax, byte ptr [rdx+rax]
.text:0000555555559B4E     xor     ecx, eax                    ; pwd[0:16] ^= enc_blk_1/2[0:16]
.text:0000555555559B50     mov     eax, [rbp+iter_14]
.text:0000555555559B53     movsxd  rdx, eax
.text:0000555555559B56     lea     rax, pwd_1_5555557671A0
.text:0000555555559B5D     mov     [rdx+rax], cl
.text:0000555555559B60     add     [rbp+iter_14], 1
.text:0000555555559B64     jmp     short XOR_LOOP_555555559B26
.text:0000555555559B66 ; ---------------------------------------------------------------------------
.text:0000555555559B66
.text:0000555555559B66 END_XOR_555555559B66:                   ; CODE XREF: func_31_555555559adc+4Ej
.text:0000555555559B66     mov     edi, 4
.text:0000555555559B6B     call    ___cxa_allocate_exception
.text:0000555555559B70     mov     dword ptr [rax], 3Ah
.text:0000555555559B76     mov     edx, 0
.text:0000555555559B7B     lea     rsi, _ZTIi                  ; `typeinfo for'int
.text:0000555555559B82     mov     rdi, rax
.text:0000555555559B85     call    ___cxa_throw
.text:0000555555559B8A ; ---------------------------------------------------------------------------
.text:0000555555559B8A     mov     rbx, rax
.text:0000555555559B8D     call    ___cxa_end_catch
.text:0000555555559B92     mov     rax, rbx
.text:0000555555559B95     mov     rdi, rax
.text:0000555555559B98     call    __Unwind_Resume
.text:0000555555559B98 func_31_555555559adc endp
```

Since `___cxa_throw` never returns, IDA screws function boundaries, but we can adjust them
(see [eop_analyzer.py](./eop_analyzer.py) script).

There are 2 things to note here: *First*, we have a dummy `throw` and the actual code is inside
a catch statement (between `call ___cxa_begin_catch` and `call ___cxa_allocate_exception`
instructions. *Second*, After the actual code there's another throw instruction which takes
a 1 byte value as argument: `mov dword ptr [rax], 3Ah`. This value `0x3A` is used as an index
in `func_tbl_5555557671E0` to indicate the next hop:


```assembly
.text:000055555555AE98 func_3a_55555555ae98 proc near          ; DATA XREF: .data.rel.ro:off_555555764DC8o
.text:000055555555AE98
.text:000055555555AE98 var_18= qword ptr -18h
.text:000055555555AE98
.text:000055555555AE98     push    rbp
.text:000055555555AE99     mov     rbp, rsp                    ; func 2
.text:000055555555AE9C     push    rbx
.text:000055555555AE9D     sub     rsp, 18h
.text:000055555555AEA1     mov     [rbp+var_18], rdi
.text:000055555555AEA5     mov     edi, 8
.text:000055555555AEAA     call    ___cxa_allocate_exception
.text:000055555555AEAF     mov     rbx, rax
.text:000055555555AEB2     mov     rdi, rbx
.text:000055555555AEB5     call    sub_5555555597F8
.text:000055555555AEBA     mov     rax, cs:_ZNSt9exceptionD1Ev_ptr
.text:000055555555AEC1     mov     rdx, rax
.text:000055555555AEC4     lea     rsi, _ZTISt9exception       ; `typeinfo for'std::exception
.text:000055555555AECB     mov     rdi, rbx
.text:000055555555AECE     call    ___cxa_throw
.text:000055555555AED3 ; ---------------------------------------------------------------------------
.text:000055555555AED3     mov     rdi, rax
.text:000055555555AED6     call    ___cxa_begin_catch          ; Node: 0x3a
.text:000055555555AEDB     movzx   eax, byte ptr cs:pwd_1_5555557671A0
.text:000055555555AEE2     movzx   eax, al
.text:000055555555AEE5     movzx   edx, byte ptr cs:pwd_1_5555557671A0+1
.text:000055555555AEEC     movzx   edx, dl
.text:000055555555AEEF     shl     edx, 8
.text:000055555555AEF2     or      edx, eax
.text:000055555555AEF4     movzx   eax, byte ptr cs:pwd_1_5555557671A0+2
.text:000055555555AEFB     movzx   eax, al
.text:000055555555AEFE     shl     eax, 10h
.text:000055555555AF01     or      edx, eax
.text:000055555555AF03     movzx   eax, byte ptr cs:pwd_1_5555557671A0+3
.text:000055555555AF0A     movzx   eax, al
.text:000055555555AF0D     shl     eax, 18h
.text:000055555555AF10     or      edx, eax                    ; edx = atoi(pwd_1[0:4])
.text:000055555555AF12     mov     rax, cs:tbl_A_555555767150
.text:000055555555AF19     mov     eax, [rax]
.text:000055555555AF1B     xor     eax, edx
.text:000055555555AF1D     mov     cs:tmp_A_5555557671C0, eax  ; tmp_A = atoi(pwd_1[0:4]) ^ tbl_A[0]
.text:000055555555AF23     mov     edi, 4
.text:000055555555AF28     call    ___cxa_allocate_exception
.text:000055555555AF2D     mov     dword ptr [rax], 3Bh
.text:000055555555AF33     mov     edx, 0
.text:000055555555AF38     lea     rsi, _ZTIi                  ; `typeinfo for'int
.text:000055555555AF3F     mov     rdi, rax
.text:000055555555AF42     call    ___cxa_throw
.text:000055555555AF47 ; ---------------------------------------------------------------------------
.text:000055555555AF47     mov     rbx, rax
.text:000055555555AF4A     call    ___cxa_end_catch
.text:000055555555AF4F     mov     rax, rbx
.text:000055555555AF52     mov     rdi, rax
.text:000055555555AF55     call    __Unwind_Resume
.text:000055555555AF55 func_3a_55555555ae98 endp
```

We can see here the exact same pattern. So we write [eop_analyzer.py](./eop_analyzer.py) script
to parse all these functions and reconstruct the control flow. Luckily for us, each function has
exactly 1 next hop (except function `0x1D` which is the terminating one).

After we run program, we get a nice disassembly listing:
```assembly
; ---------------- Node 31 at 0x555555559ADC. Next: 3A ----------------
    mov     [rbp+iter_14], 0
    cmp     [rbp+iter_14], 0Fh
    jg      short END_XOR_555555559B66
    mov     eax, [rbp+iter_14]
    movsxd  rdx, eax
    lea     rax, pwd_1_5555557671A0
    movzx   ecx, byte ptr [rdx+rax]     ; ecx = pwd[0]
    mov     eax, [rbp+iter_14]
    movsxd  rdx, eax
    lea     rax, enc_blk_1_5555557671B0
    movzx   eax, byte ptr [rdx+rax]
    xor     ecx, eax                    ; pwd[0:16] ^= enc_blk_1/2[0:16]
    mov     eax, [rbp+iter_14]
    movsxd  rdx, eax
    lea     rax, pwd_1_5555557671A0
    mov     [rdx+rax], cl
    add     [rbp+iter_14], 1
    jmp     short XOR_LOOP_555555559B26
; ---------------- Node 3A at 0x55555555AE98. Next: 3B ----------------
    movzx   eax, byte ptr cs:pwd_1_5555557671A0
    movzx   eax, al
    movzx   edx, byte ptr cs:pwd_1_5555557671A0+1
    movzx   edx, dl
    shl     edx, 8
    or      edx, eax
    movzx   eax, byte ptr cs:pwd_1_5555557671A0+2
    movzx   eax, al
    shl     eax, 10h
    or      edx, eax
    movzx   eax, byte ptr cs:pwd_1_5555557671A0+3
    movzx   eax, al
    shl     eax, 18h
    or      edx, eax                    ; edx = atoi(pwd_1[0:4])
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax]
    xor     eax, edx
    mov     cs:tmp_A_5555557671C0, eax  ; tmp_A = atoi(pwd_1[0:4]) ^ tbl_A[0]
; ---------------- Node 3B at 0x55555555A026. Next: 3 ----------------
    movzx   eax, byte ptr cs:pwd_1_5555557671A0+4
    movzx   eax, al
    movzx   edx, byte ptr cs:pwd_1_5555557671A0+5
    movzx   edx, dl
    shl     edx, 8
    or      edx, eax
    movzx   eax, byte ptr cs:pwd_1_5555557671A0+6
    movzx   eax, al
    shl     eax, 10h
    or      edx, eax
    movzx   eax, byte ptr cs:pwd_1_5555557671A0+7
    movzx   eax, al
    shl     eax, 18h
    or      edx, eax                    ; edx = atoi(pwd[4:8])
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+4]
    xor     eax, edx
    mov     cs:tmp_B_5555557671C4, eax  ; tmp_B = edx = atoi(pwd[4:8]) ^ tbl_A[1]
; ---------------- Node 3 at 0x55555555AFE2. Next: 13 ----------------
    movzx   eax, byte ptr cs:pwd_2_5555557671A8
    movzx   eax, al
    movzx   edx, byte ptr cs:pwd_2_5555557671A8+1
    movzx   edx, dl
    shl     edx, 8
    or      edx, eax
    movzx   eax, byte ptr cs:pwd_2_5555557671A8+2
    movzx   eax, al
    shl     eax, 10h
    or      edx, eax
    movzx   eax, byte ptr cs:pwd_2_5555557671A8+3
    movzx   eax, al
    shl     eax, 18h
    or      edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+8]
    xor     eax, edx
    mov     cs:tmp_C_5555557671C8, eax  ; tmp_C = atoi(pwd_2[0:4]) ^ tbl_A[2]
; ---------------- Node 13 at 0x55555555BC30. Next: 0 ----------------
    movzx   eax, byte ptr cs:pwd_2_5555557671A8+4
    movzx   eax, al
    movzx   edx, byte ptr cs:pwd_2_5555557671A8+5
    movzx   edx, dl
    shl     edx, 8
    or      edx, eax
    movzx   eax, byte ptr cs:pwd_2_5555557671A8+6
    movzx   eax, al
    shl     eax, 10h
    or      edx, eax
    movzx   eax, byte ptr cs:pwd_2_5555557671A8+7
    movzx   eax, al
    shl     eax, 18h
    or      edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+0Ch]
    xor     eax, edx
    mov     cs:tmp_D_5555557671CC, eax  ; tmp_D = atoi(pwd_2[4:8]) ^ tbl_A[3]
; ---------------- Node 0 at 0x55555555A1E6. Next: C ----------------
; ---------------- Node C at 0x55555555BB34. Next: 49 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 40h                    ; sub_A = tbl_A + 0x40
    mov     edx, [rax+rdx*4]            ; edx = sub_A[tmp_A & 0xFF] = sub_A[BYTE_1(tmp_A)]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_A_5555557671C0
    shr     ecx, 8
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h                   ; sub_B = tbl_A + 0x140
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax                    ; ecx = sub_A[tmp_A & 0xFF] ^ sub_B[(tmp_A >> 8) & 0xFF])
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h                   ; sub_C = tbl_A + 0x240
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 340h                   ; sub_D = tbl_A + 0x340
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_E_5555557671D0, eax  ; tmp_E = sub_A[B1(tmp_A)] ^ sub_B[B2(tmp_A)] ^ sub_C[B3(tmp_A)] ^ sub_D[B4(tmp_A)]
; ---------------- Node 49 at 0x55555555D282. Next: 21 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]            ; a = sub_A[B4(tmp_B)]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_B_5555557671C4
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]            ; b = sub_B[B1(tmp_B)]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]            ; c = sub_C[B2(tmp_B)]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]            ; d = sub_D[B3(tmp_B)]
    xor     eax, ecx
    mov     cs:tmp_F_5555557671D4, eax  ; tmp_F = a ^ b ^ c ^ d
; ---------------- Node 21 at 0x55555555A7D2. Next: 19 ----------------
    mov     edx, cs:tmp_E_5555557671D0
    mov     eax, cs:tmp_F_5555557671D4
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+20h]
    add     edx, eax                    ; edx = tmp_E + tmp_F + tbl_A[8]
    mov     eax, cs:tmp_C_5555557671C8
    xor     eax, edx
    mov     cs:tmp_C_5555557671C8, eax  ; tmp_C ^= tmp_E + tmp_F + tbl_A[8]
; ---------------- Node 19 at 0x55555555DD88. Next: 1F ----------------
    mov     eax, cs:tmp_C_5555557671C8
    ror     eax, 1                      ; tmp_C = ror(tmp_C, 1)
    mov     cs:tmp_C_5555557671C8, eax
; ---------------- Node 1F at 0x55555555E1EA. Next: 39 ----------------
    mov     eax, cs:tmp_D_5555557671CC
    rol     eax, 1                      ; tmp_D = rol(tmp_D, 1)
    mov     cs:tmp_D_5555557671CC, eax
; ---------------- Node 39 at 0x55555555C51E. Next: 47 ----------------
    mov     eax, cs:tmp_F_5555557671D4
    lea     edx, [rax+rax]              ; edx = tmp_F * 2 (32 bit)
    mov     eax, cs:tmp_E_5555557671D0
    add     edx, eax                    ; edx = 2*tmp_F + tmp_E (32 bit)
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+24h]
    add     edx, eax
    mov     eax, cs:tmp_D_5555557671CC
    xor     eax, edx
    mov     cs:tmp_D_5555557671CC, eax  ; tmp_D ^= 2*tmp_F + tmp_E + tbl_A[9]
; ---------------- Node 47 at 0x55555555A0EA. Next: 3D ----------------
    mov     rax, cs:tbl_A_555555767150

[.... LOOP CONTINUES ....]

; ---------------- Node 67 at 0x55555555DC12. Next: 36 ----------------
; ---------------- Node 36 at 0x55555555A306. Next: 2C ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, [rax+10h]
    mov     eax, cs:tmp_C_5555557671C8
    xor     eax, edx
    mov     cs:tmp_C_5555557671C8, eax  ; tmp_C ^= tbl_A[4]
; ---------------- Node 2C at 0x55555555991A. Next: 68 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, [rax+14h]
    mov     eax, cs:tmp_D_5555557671CC
    xor     eax, edx
    mov     cs:tmp_D_5555557671CC, eax  ; tmp_D ^= tbl_A[5]
; ---------------- Node 68 at 0x55555555E272. Next: 4F ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, [rax+18h]
    mov     eax, cs:tmp_A_5555557671C0
    xor     eax, edx
    mov     cs:tmp_A_5555557671C0, eax  ; tmp_A ^= tbl_A[6]
; ---------------- Node 4F at 0x55555555B896. Next: 57 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, [rax+1Ch]
    mov     eax, cs:tmp_B_5555557671C4
    xor     eax, edx
    mov     cs:tmp_B_5555557671C4, eax  ; tmp_B ^= tbl_A[7]
; ---------------- Node 57 at 0x55555555D5F2. Next: 22 ----------------
    mov     eax, cs:tmp_C_5555557671C8
    mov     byte ptr cs:enc_blk_1_5555557671B0, al
; ---------------- Node 22 at 0x555555559F9C. Next: 52 ----------------
    mov     eax, cs:tmp_C_5555557671C8
    shr     eax, 8
    mov     byte ptr cs:enc_blk_1_5555557671B0+1, al
; ---------------- Node 52 at 0x55555555DE10. Next: 51 ----------------
    mov     eax, cs:tmp_C_5555557671C8
    shr     eax, 10h
    mov     byte ptr cs:enc_blk_1_5555557671B0+2, al
; ---------------- Node 51 at 0x55555555AA9E. Next: 2B ----------------
    mov     eax, cs:tmp_C_5555557671C8
    shr     eax, 18h
    mov     byte ptr cs:enc_blk_1_5555557671B0+3, al
; ---------------- Node 2B at 0x55555555CFD0. Next: 5A ----------------
    mov     eax, cs:tmp_D_5555557671CC
    mov     byte ptr cs:enc_blk_1_5555557671B0+4, al
; ---------------- Node 5A at 0x555555559E8A. Next: 79 ----------------
    mov     eax, cs:tmp_D_5555557671CC
    shr     eax, 8
    mov     byte ptr cs:enc_blk_1_5555557671B0+5, al
; ---------------- Node 79 at 0x55555555D37E. Next: 29 ----------------
    mov     eax, cs:tmp_D_5555557671CC
    shr     eax, 10h
    mov     byte ptr cs:enc_blk_1_5555557671B0+6, al
; ---------------- Node 29 at 0x55555555A6A2. Next: 5 ----------------
    mov     eax, cs:tmp_D_5555557671CC
    shr     eax, 18h
    mov     byte ptr cs:enc_blk_1_5555557671B0+7, al
; ---------------- Node 5 at 0x55555555D678. Next: 33 ----------------
    mov     eax, cs:tmp_A_5555557671C0
    mov     byte ptr cs:enc_blk_2_5555557671B8, al
; ---------------- Node 33 at 0x55555555C13E. Next: 6 ----------------
    mov     eax, cs:tmp_A_5555557671C0
    shr     eax, 8
    mov     byte ptr cs:enc_blk_2_5555557671B8+1, al
; ---------------- Node 6 at 0x55555555C494. Next: 5F ----------------
    mov     eax, cs:tmp_A_5555557671C0
    shr     eax, 10h
    mov     byte ptr cs:enc_blk_2_5555557671B8+2, al
; ---------------- Node 5F at 0x5555555599AC. Next: 46 ----------------
    mov     eax, cs:tmp_A_5555557671C0
    shr     eax, 18h
    mov     byte ptr cs:enc_blk_2_5555557671B8+3, al
; ---------------- Node 46 at 0x55555555CF4A. Next: 18 ----------------
    mov     eax, cs:tmp_B_5555557671C4
    mov     byte ptr cs:enc_blk_2_5555557671B8+4, al
; ---------------- Node 18 at 0x55555555C5C4. Next: B ----------------
    mov     eax, cs:tmp_B_5555557671C4
    shr     eax, 8
    mov     byte ptr cs:enc_blk_2_5555557671B8+5, al
; ---------------- Node B at 0x55555555A398. Next: 1C ----------------
    mov     eax, cs:tmp_B_5555557671C4
    shr     eax, 10h
    mov     byte ptr cs:enc_blk_2_5555557671B8+6, al
; ---------------- Node 1C at 0x55555555CEC0. Next: 1D ----------------
    mov     eax, cs:tmp_B_5555557671C4
    shr     eax, 18h
    mov     byte ptr cs:enc_blk_2_5555557671B8+7, al
```

The full listing is located at [eop_disas.asm](./eop_disas.asm). This is essentially an unrolled
loop. Encryption algorithm breaks the 48 input password into 3 blocks and encrypts each block
in Cipher Block Chaining (CBC) mode. Below is the decompiled encryption algorithm:
```python
def encrypt_block(plain):
    print '[+] Encrypting block:', ' '.join('%02X' % p for p in plain)

    A = ltoi(plain[ 0: 4]) ^ tbl_A[0]
    B = ltoi(plain[ 4: 8]) ^ tbl_A[1]
    C = ltoi(plain[ 8:12]) ^ tbl_A[2]
    D = ltoi(plain[12:16]) ^ tbl_A[3]


    print '[+] Init: A:%08X, B:%08X, C:%08X, D:%08X' % (A, B, C, D)

    for i in xrange(8, 40, 4):
        # Round 1
        E = sub_A[B1(A)] ^ sub_B[B2(A)] ^ sub_C[B3(A)] ^ sub_D[B4(A)]       
        F = sub_A[B4(B)] ^ sub_B[B1(B)] ^ sub_C[B2(B)] ^ sub_D[B3(B)]

        C ^= (E + F + tbl_A[i]) & 0xFFFFFFFF

        C = ror(C, 1)
        D = rol(D, 1)

        D ^= (2*F + E + tbl_A[i+1]) & 0xFFFFFFFF

        # Round 2
        E = sub_A[B1(C)] ^ sub_B[B2(C)] ^ sub_C[B3(C)] ^ sub_D[B4(C)]
        F = sub_A[B4(D)] ^ sub_B[B1(D)] ^ sub_C[B2(D)] ^ sub_D[B3(D)]

        A ^= (E + F + tbl_A[i+2]) & 0xFFFFFFFF

        A = ror(A, 1)
        B = rol(B, 1)

        B ^= (2*F + E + tbl_A[i+3]) & 0xFFFFFFFF        


        print '[+] Round %d: A:%08X, B:%08X, C:%08X, D:%08X, E:%08X, F:%08X' % (
                    (i - 8) >> 2, A, B, C, D, E, F)

    C ^= tbl_A[4]
    D ^= tbl_A[5]
    A ^= tbl_A[6]
    B ^= tbl_A[7]

    print '[+] Final: A:%08X, B:%08X, C:%08X, D:%08X' % (A, B, C, D)

    cipher = []
    for i in [C, D, A, B]:
        for j in xrange(0, 32, 8):
            cipher.append(((i >> j) & 0xFF))   

    return cipher
```


### Breaking the cipher

Our goal is to break the target ciphertext that is passed to `memcmp`:
```
4F6FA787E9518764382A46E54F219E1CCD65E19A4FCFDE5209BF53C4B0957531AC2FF4971DA59A02A8FFAE2EB970CC02
```

Which consists of 3 blocks:
```
    4F6FA787E9518764382A46E54F219E1C
    CD65E19A4FCFDE5209BF53C4B0957531
    AC2FF4971DA59A02A8FFAE2EB970CC02
```

First we reverse the encryption algorithm:
```python
def decrypt_block(cipher):
    print '[+] Decrypting block:', ' '.join('%02X' % c for c in cipher)

    C = ltoi(cipher[ 0: 4]) ^ tbl_A[4]
    D = ltoi(cipher[ 4: 8]) ^ tbl_A[5]
    A = ltoi(cipher[ 8:12]) ^ tbl_A[6]
    B = ltoi(cipher[12:16]) ^ tbl_A[7]

    print '[+] Init: A:%08X, B:%08X, C:%08X, D:%08X' % (A, B, C, D)

    for i in xrange(36, 4, -4):
        # Round 2
        E = sub_A[B1(C)] ^ sub_B[B2(C)] ^ sub_C[B3(C)] ^ sub_D[B4(C)]
        F = sub_A[B4(D)] ^ sub_B[B1(D)] ^ sub_C[B2(D)] ^ sub_D[B3(D)]

        A = rol(A, 1)
        A ^= (E + F + tbl_A[i+2]) & 0xFFFFFFFF

        B ^= (2*F + E + tbl_A[i+3]) & 0xFFFFFFFF
        B = ror(B, 1)

        # Round 1
        E = sub_A[B1(A)] ^ sub_B[B2(A)] ^ sub_C[B3(A)] ^ sub_D[B4(A)]       
        F = sub_A[B4(B)] ^ sub_B[B1(B)] ^ sub_C[B2(B)] ^ sub_D[B3(B)]

        C = rol(C, 1)
        C ^= (E + F + tbl_A[i]) & 0xFFFFFFFF

        
        D ^= (2*F + E + tbl_A[i+1]) & 0xFFFFFFFF
        D = ror(D, 1)


        print '[+] Round %d: A:%08X, B:%08X, C:%08X, D:%08X, E:%08X, F:%08X' % (
                    (i - 8) >> 2, A, B, C, D, E, F)

    A ^= tbl_A[0]
    B ^= tbl_A[1]
    C ^= tbl_A[2]
    D ^= tbl_A[3]

    print '[+] Final: A:%08X, B:%08X, C:%08X, D:%08X' % (A, B, C, D)

    plain = []
    for i in [A, B, C, D]:
        for j in xrange(0, 32, 8):
            plain.append(((i >> j) & 0xFF))   

    return plain
```

And we work backwards to crack the last block: `AC2FF4971DA59A02A8FFAE2EB970CC02`

Decryption gives us: `9F0AAEAA2CA4AD7328E33C9AEFCB1A1E`, which is the after-XOR plaintext.
Since we know the ciphertext, we XOR it with the ciphertext of the previous block
`CD65E19A4FCFDE5209BF53C4B0957531` and we recover the last part of the password: `RoO0cks!!\o^_^o/`

We continue working backwards for the other 2 blocks and we recover the whole password:
```
~Exc3p7i0n-Ori3n7ed-Pr0grammin9~RoO0cks!!\o^_^o/
```

For more details take a look at the crack script: [eop_crack.py](./eop_crack.py)

We also verify that the flag works:
```
ispo@nogirl:~/ctf/hitcon_ctf_2018/eop$ ./eop-811afa1b9fb0c0719a75afd316ea2c57 
~Exc3p7i0n-Ori3n7ed-Pr0grammin9~RoO0cks!!\o^_^o/
Great! Here's the flag: hitcon{~Exc3p7i0n-Ori3n7ed-Pr0grammin9~RoO0cks!!\o^_^o/}
```

___
