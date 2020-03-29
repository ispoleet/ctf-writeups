## Teaser CONFidence CTF 2020 - Borken Counter (Reversing 207) - 17 solves
##### 14/03 - 15/03/2020 (24hr)
___

### Description: 

So we all have that one **special** friend that constantly downloads weird binaries from the
internet and runs them without a moment's hesitation, right?

Well... One of my friends went a step further and entered some of our secret keys into this weird
looking binary.

I tried asking him what does the binary do but he just stares into the void and mutters something
about counting the sponges there were but not are.

...Anyway, I also found this other file just laying around. Maybe it will help you recover
the leaked secret?

```
ef8689d8d1b3873ed084df9cfeecac027878a240c5b466ab90524c19c8209074_borken_counter.tar 60K
```

The flag format is: `p4{letters_digits_and_special_characters}`.

___

### Solution

Yet another VM reversing challenge. First binary decodes the VM program:
```Assembly
.text:565556D0 PAYLOAD_DECODE_565556D0:                             ; CODE XREF: main_56555630+D7j
.text:565556D0         cmp     ebx, 18h
.text:565556D3         jg      loc_56556195
.text:565556D9         cmp     ecx, 9
.text:565556DC         jg      loc_56556195
.text:565556E2         mov     edi, [ebp-34h]
.text:565556E5         lea     esi, [ebx+ebx*4]
.text:565556E8         xor     edx, 69h                             ; XOR decode payload
.text:565556EB         add     eax, 1
.text:565556EE         lea     esi, [edi+esi*2]
.text:565556F1         mov     [esi+ecx], dl
.text:565556F4         add     ecx, 1
.text:565556F7         cmp     [ebp-2Ch], eax
.text:565556FA         mov     esi, 1
.text:565556FF         jz      short loc_5655571F
.text:56555701
```

We can view the decoded program to emulate as a 2D array:
```
    +----------+
1   |955+*1-v) |
2   |v_#   #<v |
3   |1 v<v<v<# |
4   |+!:g/912D |
5   |0`00\:+g# |
6   |0*809g+%U |
7   |p5gp%009# |
8   | ^<^<^<\C |
9   |>00g:9/^  |
10  |v$U#D#K#< |
11  |s  s/7Y\s |
12  |   "   7  |
13  |       *  |
14  |s!   !!.9 |
15  | s.\s  [  |
16  | 6  s ;[  |
17  | d    Y[  |
18  | .    ,   |
19  | (  ;/[   |
20  | ;.6m/[5  |
21  |;{722(*y  |
22  |s5d6.!!9  |
23  |;1'*+=    |
24  |          |
25  |          |
    +----------+
```


After initialization program enters a huge switch statement that dispatches all opcodes:
```Assembly
.text:565557A8 LOOP_1_565557A8:                                     ; CODE XREF: main_56555630+26Fj
.text:565557A8         lea     eax, [ecx+ecx*4]
.text:565557AB         lea     edx, [edi+eax*2]                     ; edx = edi + ecx*10 = pc_x + 10*pc_y
.text:565557AE         mov     eax, [ebp-34h]                       ; eax = vm_prog
.text:565557B1         movzx   eax, byte ptr ds:(STACK_BASE_56557FB0 - 56557FB0h)[eax+edx] ; vm_prog[pc_x + 10*pc_y]
.text:565557B5         cmp     al, 40h
.text:565557B7         mov     [ebp-2Ch], al                        ; opcode = vm_prog[pc_x + 10*pc_y]
.text:565557BA         jz      OPCODE_@_56555F40
.text:565557C0         mov     eax, [ebp-30h]
.text:565557C3         mov     eax, (dword_56558108 - 56557FB0h)[eax]
.text:565557C9         test    eax, eax
.text:565557CB         jnz     PRINT_PC_56555F90
.text:565557D1         mov     eax, [ebp-44h]
.text:565557D4         mov     edx, ds:(STACK_BASE_56557FB0 - 56557FB0h)[eax] ; edx = v_44
.text:565557D6         test    edx, edx
.text:565557D8         jnz     loc_56555FCF
.text:565557DE
.text:565557DE SWITCH_565557DE:                                     ; CODE XREF: main_56555630+999j
.text:565557DE         movzx   eax, byte ptr [ebp-2Ch]
.text:565557E2         lea     ebx, (unk_56557F90 - 56557FB0h)[eax] ; ebx = opcode - 0x20
.text:565557E5         cmp     bl, 5Eh                              ; switch 95 cases
.text:565557E8         ja      UNKNOWN_ERROR_56556183               ; jumptable 000007FB default case
.text:565557EE         mov     eax, [ebp-30h]
.text:565557F1         movzx   ebx, bl
.text:565557F4         add     eax, ds:(off_5655648C - 56557FB0h)[eax+ebx*4]
.text:565557FB         jmp     eax                                  ; switch jump
```

The interesting part is that each instruction is a single byte. If we loop at the XREFs from the
`jmp eax` statement we'll see that there are not many instructions:
```
Direction Type Address                                Text                                                                  
--------- ---- -------                                ----                                                                  
Down      j    main_56555630:READ_CHAR_56555800       mov     esi, [ebp-40h]               ; jumptable 000007FB case 94     
Down      j    main_56555630:JZ_DOWN_565558A8         mov     eax, [ebp-48h]               ; jumptable 000007FB case 92     
Down      j    main_56555630:MEM_READ_WRITE_565558E8  mov     eax, [ebp-40h]               ; jumptable 000007FB cases 71,80 
Down      j    main_56555630:DIRECTION_DOWN_56555968  mov     eax, [ebp-48h]               ; jumptable 000007FB case 86     
Down      j    main_56555630:CMP_BELOW_56555988       mov     esi, [ebp-40h]               ; jumptable 000007FB case 64     
Down      j    main_56555630:JZ_RIGHT_565559F0        mov     esi, [ebp-40h]               ; jumptable 000007FB case 63     
Down      j    main_56555630:DIRECTION_RIGHT_56555A30 mov     eax, [ebp-48h]               ; jumptable 000007FB case 30     
Down      j    main_56555630:DIRECTION_LEFT_56555A50  mov     eax, [ebp-48h]               ; jumptable 000007FB case 28     
Down      j    main_56555630:DUPLICATE_56555A70       mov     esi, [ebp-40h]               ; jumptable 000007FB case 26     
Down      j    main_56555630:PUSH_DIGIT_56555AE0      mov     eax, [ebp-40h]               ; jumptable 000007FB cases 16-25 
Down      j    main_56555630:SWAP_56555B20            mov     esi, [ebp-40h]               ; jumptable 000007FB case 60     
Down      j    main_56555630:RAND_DIR_56555B98        mov     ebx, [ebp-30h]               ; jumptable 000007FB case 31     
Down      j    main_56555630:DIRECTION_UP_56555BF0    mov     eax, [ebp-48h]               ; jumptable 000007FB case 62     
Down      j    main_56555630:DIV_56555C10             mov     eax, [ebp-40h]               ; jumptable 000007FB case 15     
Down      j    main_56555630:PRINT_NUM_56555C88       mov     esi, [ebp-40h]               ; jumptable 000007FB case 14     
Down      j    main_56555630:SUB_56555CC0             mov     ebx, [ebp-40h]               ; jumptable 000007FB case 13     
Down      j    main_56555630:PRINT_CHAR_56555D30      mov     esi, [ebp-40h]               ; jumptable 000007FB case 12     
Down      j    main_56555630:ADD_56555D60             mov     ebx, [ebp-40h]               ; jumptable 000007FB case 11     
Down      j    main_56555630:MUL_56555DB0             mov     ebx, [ebp-40h]               ; jumptable 000007FB case 10     
Down      j    main_56555630:READ_NUM_56555DF0        mov     esi, [ebp-30h]               ; jumptable 000007FB case 6      
Down      j    main_56555630:MODULO_56555E48          mov     eax, [ebp-40h]               ; jumptable 000007FB case 5      
Down      j    main_56555630:POP_56555EB0             mov     ebx, [ebp-40h]               ; jumptable 000007FB case 4      
Down      j    main_56555630:SKIP_NEXT_INSN_56555ED8  mov     eax, [ebp-48h]               ; jumptable 000007FB case 3      
Down      j    main_56555630:TOP_SETZ_56555EF0        mov     eax, [ebp-40h]               ; jumptable 000007FB case 1      
Down      j    main_56555630:NOP_56555F30             mov     eax, [ebp-48h]               ; jumptable 000007FB case 0      
Down      j    main_56555630:loc_56555FD5             mov     esi, [ebp-44h]               ; jumptable 000007FB case 2      
Down      j    main_56555630:UNKNOWN_ERROR_56556183   mov     eax, [ebp-30h]               ; jumptable 000007FB default case
```

At the end of each instruction, program counters (yes we have 2) are updated:
```Assembly
.text:56555850 SWITCH_END_56555850:                                 ; CODE XREF: main_56555630+2AEj
.text:56555850                                                      ; main_56555630+32Ej ...
.text:56555850         lea     ebx, [edx+edi+0Ah]                   ; ebx = (edx + edi + 10) = (x_dir + pc_x + 10) = X
.text:56555854         mov     edx, 66666667h                       ; modulo
.text:56555859         mov     eax, ebx
.text:5655585B         imul    edx
.text:5655585D         mov     eax, ebx
.text:5655585F         sar     eax, 1Fh                             ; eax = X >> 31
.text:56555862         sar     edx, 2                               ; edx = X * 0x66666667 >> 34
.text:56555865         mov     edi, edx                             ; N = 2^34 / 0x66666667 = 10!
.text:56555867         mov     edx, 51EB851Fh
.text:5655586C         sub     edi, eax                             ; edi = (X * 0x66666667 >> 34) - (X >> 31)
.text:5655586E         lea     eax, [edi+edi*4]                     ; eax = edi * 5
.text:56555871         mov     edi, ebx                             ; edi = X
.text:56555873         lea     ebx, [ecx+esi+19h]                   ; ebx = (ecx + esi + 25) = (y_dir + pc_y + 25) = Y
.text:56555877         add     eax, eax
.text:56555879         sub     edi, eax                             ; edi = X % 10
.text:5655587B         mov     eax, [ebp-3Ch]                       ; eax = v_3c
.text:5655587E         mov     ds:(STACK_BASE_56557FB0 - 56557FB0h)[eax], edi ; v_3c = X % 10
.text:56555880         mov     eax, ebx
.text:56555882         imul    edx
.text:56555884         mov     eax, ebx
.text:56555886         sar     eax, 1Fh
.text:56555889         sar     edx, 3                               ; edx = Y * 0x51eb851f >> 35
.text:5655588C         mov     ecx, edx                             ; N = 2^35 - 0x51eb851f = 25!
.text:5655588E         sub     ecx, eax
.text:56555890         lea     eax, [ecx+ecx*4]
.text:56555893         mov     ecx, ebx
.text:56555895         lea     eax, (STACK_BASE_56557FB0 - 56557FB0h)[eax+eax*4]
.text:56555898         sub     ecx, eax                             ; ecx = Y % 25
.text:5655589A         mov     eax, [ebp-38h]                       ; eax = v_38
.text:5655589D         mov     ds:(STACK_BASE_56557FB0 - 56557FB0h)[eax], ecx ; v_38 = Y % 25
.text:5655589F         jmp     LOOP_1_565557A8
```

Let's decode the instructions. We have a stack based VM. If instruction is a digit (`0-9`) then
this digit is pushed to the stack:
```Assembly
.text:56555AE0
.text:56555AE0 PUSH_DIGIT_56555AE0:                                 ; CODE XREF: main_56555630+1CBj
.text:56555AE0                                                      ; DATA XREF: .rodata:off_5655648Co
.text:56555AE0         mov     eax, [ebp-40h]                       ; jumptable 000007FB cases 16-25
.text:56555AE3         mov     edx, ds:(STACK_BASE_56557FB0 - 56557FB0h)[eax] ; edx = SP
.text:56555AE5         cmp     edx, 3E7h
.text:56555AEB         jg      STACK_OVERFLOW_565560CA
.text:56555AF1         lea     ebx, [edx+1]                         ; ++SP
.text:56555AF4         mov     ds:(STACK_BASE_56557FB0 - 56557FB0h)[eax], ebx
.text:56555AF6         mov     eax, [ebp-30h]
.text:56555AF9         lea     ebx, (STACK_BASE_56558260 - 56557FB0h)[eax]
.text:56555AFF         movzx   eax, byte ptr [ebp-2Ch]
.text:56555B03         sub     eax, 30h                             ; eax = opcode - 0x30
.text:56555B06
.text:56555B06 loc_56555B06:                                        ; CODE XREF: main_56555630+55Cj
.text:56555B06                                                      ; main_56555630+A6Fj
.text:56555B06         mov     [ebx+edx*4], eax                     ; stack_base[SP] = opcode - 0x30
.text:56555B09         mov     eax, [ebp-48h]                       ; push(opcode - 0x30)
.text:56555B0C         mov     edx, ds:(STACK_BASE_56557FB0 - 56557FB0h)[eax]
.text:56555B0E         mov     eax, [ebp-4Ch]
.text:56555B11         mov     esi, ds:(STACK_BASE_56557FB0 - 56557FB0h)[eax]
.text:56555B13         jmp     SWITCH_END_56555850
```

If instruction is `g` program extracts the 2 top arguments from the stack and uses them as location
`(y, x)` to read the contents of the VM program. `p` instruction is similar but it extracts 3
arguments from stack (`x`, `y`, `v`) and writes the `v` at location `(y, x)`:
```Assembly
.text:565558E8 MEM_READ_WRITE_565558E8:                             ; CODE XREF: main_56555630+1CBj
.text:565558E8                                                      ; DATA XREF: .rodata:off_5655648Co
.text:565558E8         mov     eax, [ebp-40h]                       ; jumptable 000007FB cases 71,80
.text:565558EB         mov     edx, ds:(STACK_BASE_56557FB0 - 56557FB0h)[eax]
.text:565558ED         test    edx, edx
.text:565558EF         jz      STACK_EMPTY_56556078
.text:565558F5         lea     esi, [edx-1]
.text:565558F8         mov     ebx, [ebp-30h]
.text:565558FB         mov     [ebp-54h], esi
.text:565558FE         cmp     dword ptr [ebp-54h], 0
.text:56555902         lea     ebx, [ebx+2B0h]
.text:56555908         mov     ds:(STACK_BASE_56557FB0 - 56557FB0h)[eax], esi
.text:5655590A         mov     esi, [ebx+esi*4]                     ; esi = stack_base[SP - 1]
.text:5655590D         jz      short loc_5655591D
.text:5655590F         sub     edx, 2
.text:56555912         mov     ds:(STACK_BASE_56557FB0 - 56557FB0h)[eax], edx
.text:56555914         mov     edx, [ebx+edx*4]                     ; edx = stack_base[SP - 2]
.text:56555917         lea     edx, [edx+edx*4]                     ; edx = edx * 5
.text:5655591A         lea     esi, [esi+edx*2]                     ; esi = stack_base[SP - 1] + stack_base[SP - 2] * 10
.text:5655591D
.text:5655591D loc_5655591D:                                        ; CODE XREF: main_56555630+2DDj
.text:5655591D         cmp     esi, 0F9h                            ; F9 = 249 = end of array
.text:56555923         ja      ERROR_565561EE
.text:56555929         cmp     byte ptr [ebp-2Ch], 67h              ; 'g'
.text:5655592D         mov     eax, [ebp-40h]
.text:56555930         mov     edx, ds:(STACK_BASE_56557FB0 - 56557FB0h)[eax]
.text:56555932         jz      IS_G_565560C2                        ; 3e7 = 999
.text:56555938         test    edx, edx
.text:5655593A         jz      EMPTY_STACK_565561CF
.text:56555940         mov     eax, [ebp-40h]
.text:56555943         sub     edx, 1                               ; --SP
.text:56555946         mov     ds:(STACK_BASE_56557FB0 - 56557FB0h)[eax], edx
.text:56555948         movzx   eax, byte ptr [ebx+edx*4]            ; eax = stack_base[SP - 3]
.text:5655594C         mov     edx, esi
.text:5655594E
.text:5655594E loc_5655594E:                                        ; CODE XREF: main_56555630+A50j
.text:5655594E                                                      ; main_56555630+BA3j
.text:5655594E         mov     esi, [ebp-34h]
.text:56555951         mov     [esi+edx], al                        ; write to VM program
.text:56555951                                                      ; VM[stack_base[SP-2]][stack_base[SP-1]] = stack_base[SP-3]
.text:56555954         mov     eax, [ebp-48h]
.text:56555957         mov     edx, ds:(STACK_BASE_56557FB0 - 56557FB0h)[eax]
.text:56555959         mov     eax, [ebp-4Ch]
.text:5655595C         mov     esi, ds:(STACK_BASE_56557FB0 - 56557FB0h)[eax]
.text:5655595E         jmp     SWITCH_END_56555850
```

VM payload uses `p` and `g` instructions to modify itself (yes, it's a self modifying VM).
VM has the following context variables:
```
ebp-0x2C ---> current opcode
ebp-0x30 ---> stack base
ebp-0x34 ---> VM program base
ebp-0x38 ---> pc x dimension
ebp-0x3C ---> pc y dimension
ebp-0x40 ---> stack pointer
ebp-0x44 ---> debug flag
ebp-0x48 ---> x direction (-1, 0, 1)
ebp-0x4C ---> y direction (-1, 0, 1)

[stack]:FFFFCFCC         dd offset DIR_Y_56558144
[stack]:FFFFCFD0         dd offset DIR_X_56559200
[stack]:FFFFCFD4         dd offset DEBUG_FLAG_5655825C
[stack]:FFFFCFD8         dd offset STACK_PTR_5655814c
[stack]:FFFFCFDC         dd offset PC_Y_56558140
[stack]:FFFFCFE0         dd offset PC_X_56558148
[stack]:FFFFCFE4         dd offset EMU_PROGRAM_56558160
[stack]:FFFFCFE8         dd offset STACK_BASE_56557FB0
[stack]:FFFFCFEC         dd 76h
```


We work similarly to decode the remaining instructions. Here's what we get:
```
0-f: push value to the stack
+  : addition
-  : subtraction
*  : multiplication
/  : division
%  : modulo
v  : direction down
<  : direction left
>  : direction right
^  : direction up
#  : skip next instruction
' ': nop
g  : read from VM program memory
p  : write to VM program memory
:  : duplicate top of the stack
\  : swap top elements of the stack
`  : check if top of stack is less than second stack element
_  : if top of the stack is non-zero direction right else direction left
!  : setz on top of stack
$  : pop
~  : read 1 character from stdin
|  : if top of the stack is non-zero direction up else direction down
.  : printf & pop   
?  : change direction to random
@  : return (exit the VM)
```

Having that we can write our emulatoer: [borken_counter_emu.py](./borken_counter_emu.py). Loops
are unrolled, but we can easily find then by looking for repeating instructions. We also remove
the direction, skip and nop commands to clean the code. The resulting emulated assembly is shown
below:
```assembly
    1: (0, 0) push 9               S:[09]           ;
    2: (0, 1) push 5               S:[09,05]        ;
    3: (0, 2) push 5               S:[09,05,05]     ;
    4: (0, 3) add                  S:[09,0a]        ;
    5: (0, 4) mul                  S:[5a]           ;
    6: (0, 5) push 1               S:[5a,01]        ;
    7: (0, 6) sub                  S:[59]           ; push 0x59 'Y' = iter
   13: (1, 2) skip (1, 1)          S:[59]           ;
; -------------------------------------------------------------------------------------------------
; Decode payload (yes, it's self modifying)
;
; for i in xrange(0x5a, 0xcd):
;   vm_prog[i / 9][i % 9] += 3
; -------------------------------------------------------------------------------------------------
   15: (2, 0) push 1               S:[59,01]        ;
   16: (3, 0) add                  S:[5a]           ; ++iter
   17: (4, 0) push 0               S:[5a,00]        ;
   18: (5, 0) push 0               S:[5a,00,00]     ;
   19: (6, 0) *(0, 0) = 5a         S:[]             ; v0_0 = ++iter
   22: (8, 1) push 0               S:[00]           ;
   23: (8, 2) push 0               S:[00,00]        ;
   24: (8, 3) push *(0, 0)         S:[5a]           ; push v0_0
   25: (8, 4) dup                  S:[5a,5a]        ;
   26: (8, 5) push 9               S:[5a,5a,09]     ;
   27: (8, 6) div                  S:[5a,0a]        ; v0_0 / 9
   29: (7, 7) swap                 S:[0a,5a]        ;
   30: (6, 7) push 9               S:[0a,5a,09]     ;
   31: (5, 7) mod                  S:[0a,00]        ; v0_0 % 9
   32: (4, 7) push *(0, 10)        S:[73]           ; push v{v0_0 % 9}_{v0_0 / 9}
   33: (3, 7) push 2               S:[73,02]        ;
   36: (3, 6) push 1               S:[73,02,01]     ;
   37: (4, 6) add                  S:[73,03]        ;
   38: (5, 6) add                  S:[76]           ; v{v0_0 % 9}_{v0_0 / 9} + 3
   39: (6, 6) push 0               S:[76,00]        ;
   42: (6, 5) push 0               S:[76,00,00]     ;
   43: (5, 5) push *(0, 0)         S:[76,5a]        ; v0_0 = iter
   44: (4, 5) dup                  S:[76,5a,5a]     ;
   45: (3, 5) push 9               S:[76,5a,5a,09]  ;
   48: (3, 4) div                  S:[76,5a,0a]     ; v0_0 / 9
   49: (4, 4) swap                 S:[76,0a,5a]     ;
   50: (5, 4) push 9               S:[76,0a,5a,09]  ;
   51: (6, 4) mod                  S:[76,0a,00]     ; v0_0 % 9
   54: (6, 3) *(0, 10) = 76        S:[]             ; v{v0_0 % 9}_{v0_0 / 9} += 3
   55: (5, 3) push 0               S:[00]           ;
   56: (4, 3) push 0               S:[00,00]        ;
   57: (3, 3) push *(0, 0)         S:[5a]           ; v0_0
   60: (3, 2) dup                  S:[5a,5a]        ;
   61: (4, 2) push 0               S:[5a,5a,00]     ;
   62: (5, 2) push 8               S:[5a,5a,00,08]  ;
   63: (6, 2) push *(8, 0)         S:[5a,5a,29]     ; v8_0
   66: (6, 1) push 5               S:[5a,5a,29,05]  ;
   67: (5, 1) mul                  S:[5a,5a,cd]     ; v8_0 * 5
   68: (4, 1) cmp below (cd < 5a)? S:[5a,00]        ; if v0_0 <= v8_0 * 5 then continue
   69: (3, 1) not                  S:[5a,01]        ;
   71: (1, 1) jz right (dir: <)    S:[5a]           ;
; -------------------------------------------------------------------------------------------------
 6800: (1, 2) skip (1, 3)          S:[ce]
 6801: (1, 4) nop                  S:[ce]
 6802: (1, 5) nop                  S:[ce]
 6803: (1, 6) skip (1, 7)          S:[ce]
 6804: (1, 8) dir down             S:[ce]
 6805: (2, 8) skip (3, 8)          S:[ce]
 6806: (4, 8) skip (5, 8)          S:[ce]
 6807: (6, 8) skip (7, 8)          S:[ce]
 6808: (8, 8) nop                  S:[ce]
 6809: (9, 8) dir left             S:[ce]
 6810: (9, 7) skip (9, 6)          S:[ce]
 6811: (9, 5) skip (9, 4)          S:[ce]
 6812: (9, 3) skip (9, 2)          S:[ce]
 6813: (9, 1) pop                  S:[]

; -------------------------------------------------------------------------------------------------
; Loop 1 (outer): Read a character from the password
; -------------------------------------------------------------------------------------------------
 6822: (20, 1) read char (I)        S:[49]          ; pw[0]
 6823: (20, 2) dup                  S:[49,49]       ;
 6824: (20, 3) push 5               S:[49,49,05]    ;
 6825: (20, 4) push 5               S:[49,49,05,05] ;
 6826: (20, 5) add                  S:[49,49,0a]    ;
 6827: (20, 6) sub                  S:[49,3f]       ; pw[0] - '\n'
 6828: (20, 7) jz down (dir: ^)     S:[49]          ; if new goto point D
 
 6829: (19, 7) push 8               S:[49,08]       ; iter = 8
; -------------------------------------------------------------------------------------------------
; Loop 2 (inner): Sum all bits from pw[i]
; ------------------------------------------------------------------------------------------------- 
 6834: (13, 7) push 1               S:[49,08,01]    ;
 6835: (12, 7) sub                  S:[49,07]       ; --iter
 6836: (11, 7) dup                  S:[49,07,07]    ;
 6837: (10, 7) jz right (dir: <)    S:[49,07]       ; if iter > 0 then loop else goto point C
 
 6838: (10, 6) swap                 S:[07,49]       ;
 6839: (10, 5) dup                  S:[07,49,49]    ;
 6840: (10, 4) push 2               S:[07,49,49,02] ;
 6842: (11, 3) mod                  S:[07,49,01]    ; pw[i] % 2
 6844: (14, 3) jz right (dir: <)    S:[07,49]       ; 
 
 ; if pw[i] % 2 != 0
 6845: (14, 2) push 1               S:[07,49,01]        ;
 6847: (15, 1) push 9               S:[07,49,01,09]     ;
 6848: (16, 1) push *(1, 9)         S:[07,49,20]        ; v1_9 initialized to 0x20
 6849: (17, 1) push 1               S:[07,49,20,01]     ;
 6850: (18, 1) add                  S:[07,49,21]        ;
 6852: (19, 2) push 1               S:[07,49,21,01]     ;
 6853: (19, 3) push 9               S:[07,49,21,01,09]  ;
 6854: (19, 4) *(1, 9) = 21         S:[07,49]           ; ++v1_9
 6855: (19, 5) push 2               S:[07,49,02]        ;

 ; else pw[i] % 2 == 0
 6878: (18, 5) push 2               S:[06,24,02]    ;

 6858: (17, 6) div                  S:[07,24]           ; pw[i] /= 2
 6859: (16, 6) swap                 S:[24,07]           ;

 ; goto loop (13, 7)

 ; point C
 7013: (10, 8) dir down             S:[00,00]       ;
 7016: (13, 7) push 1               S:[00,00,01]    ;
 7017: (13, 6) pop                  S:[00,00]       ;
 7018: (13, 5) pop                  S:[00]          ;
 7026: (20, 1) read char (S)        S:[00,53]       ;
; -------------------------------------------------------------------------------------------------
 7652: (20, 1) read char (\n)       S:[00,00,00,00,0a]
 7653: (20, 2) dup                  S:[00,00,00,00,0a,0a]
 7654: (20, 3) push 5               S:[00,00,00,00,0a,0a,05]
 7655: (20, 4) push 5               S:[00,00,00,00,0a,0a,05,05]
 7656: (20, 5) add                  S:[00,00,00,00,0a,0a,0a]
 7657: (20, 6) sub                  S:[00,00,00,00,0a,00]
 7658: (20, 7) jz down (dir: v)     S:[00,00,00,00,0a]
 ; point D 
 7660: (21, 6) pop                  S:[00,00,00,00]
 7661: (21, 5) pop                  S:[00,00,00]
 7662: (21, 4) push 1               S:[00,00,00,01]
 7663: (21, 3) push 9               S:[00,00,00,01,09]
 7664: (21, 2) push *(1, 9)         S:[00,00,00,2e]     ;
 7665: (21, 1) push 8               S:[00,00,00,2e,08]  ;
 7668: (22, 1) push 4               S:[00,00,00,2e,08,04]
 7669: (22, 2) mul                  S:[00,00,00,2e,20]
 7670: (22, 3) sub                  S:[00,00,00,0e]
 7671: (22, 4) print 14 (0xe)       S:[00,00,00]
 7672: (22, 5) return               S:[00,00,00]
```

As it name suggests the emulated program reads a string, takes its binary representation and counts
the number of `1`. Then it prints that number and exit. We can summarize the whole binary in the
following code:
```Python
    stdin_stream = 'ISPO'
    sum = 0
    
    for key in stdin_stream:
        bin_key = "{0:b}".format(ord(key))
        count_1 = bin_key.count('1')
        print '%c -> %x -> %s = %d' % (key, ord(key), bin_key, count_1)

        sum += count_1

    print '[+] SUM: %d' % sum
```

### Recovering the flag

Along with the binary there's a file called `out.txt`, which contains a long sequence of numbers
one per line. However when we run the program is prints a single integer. If we go back to the
switch loop we'll see a condition that is always false:
```Assembly
.text:565557AB         lea     edx, [edi+eax*2]                     ; edx = edi + ecx*10 = pc_x + 10*pc_y
.text:565557AE         mov     eax, [ebp-34h]                       ; eax = vm_prog
.text:565557B1         movzx   eax, byte ptr ds:(STACK_BASE_56557FB0 - 56557FB0h)[eax+edx] ; vm_prog[pc_x + 10*pc_y]
.text:565557B5         cmp     al, 40h
.text:565557B7         mov     [ebp-2Ch], al                        ; opcode = vm_prog[pc_x + 10*pc_y]
.text:565557BA         jz      OPCODE_@_56555F40
.text:565557C0         mov     eax, [ebp-30h]
.text:565557C3         mov     eax, (dword_56558108 - 56557FB0h)[eax]
.text:565557C9         test    eax, eax
.text:565557CB         jnz     PRINT_PC_56555F90                    ; always false!
```

If we follow `PRINT_PC_56555F90`, we will see that it prints the current PC (`pc_y*10 + pc_x`):
```Assembly
.text:56555F90
.text:56555F90 PRINT_PC_56555F90:                                   ; CODE XREF: main_56555630+19Bj
.text:56555F90                                                      ; main_56555630+928j
.text:56555F90         mov     ebx, [ebp-30h]
.text:56555F93         sub     esp, 4
.text:56555F96         push    edx
.text:56555F97         lea     eax, [ebx-1B5Ch]
.text:56555F9D         push    eax
.text:56555F9E         push    1
.text:56555FA0         call    ___printf_chk
.text:56555FA5         mov     eax, [ebp-38h]
.text:56555FA8         mov     esi, [ebp-34h]
.text:56555FAB         add     esp, 10h
.text:56555FAE         mov     ecx, ds:(STACK_BASE_56557FB0 - 56557FB0h)[eax]
.text:56555FB0         mov     eax, [ebp-3Ch]
.text:56555FB3         mov     edi, ds:(STACK_BASE_56557FB0 - 56557FB0h)[eax]
.text:56555FB5         lea     eax, [ecx+ecx*4]
.text:56555FB8         lea     eax, [esi+eax*2]
.text:56555FBB         movzx   eax, byte ptr ds:(STACK_BASE_56557FB0 - 56557FB0h)[eax+edi]
.text:56555FBF         mov     [ebp-2Ch], al
.text:56555FC2         mov     eax, [ebp-44h]
.text:56555FC5         mov     edx, ds:(STACK_BASE_56557FB0 - 56557FB0h)[eax]
.text:56555FC7         test    edx, edx
.text:56555FC9         jz      SWITCH_565557DE
```

Therefore, `out.txt` contains all the executed PCs from the emulated program. If we go back to the
emulated program, we see that every time that instruction `(20, 1)` or `20*10 + 1` is executed
a character is read from the stdin:
```Assembly
 6822: (20, 1) read char (I)        S:[49]          ; pw[0]
```

After that if the next bit of the character is `1`, instruction `(18, 1)` or `18*10 + 1` is
executed:
```Assembly
6850: (18, 1) add                  S:[07,49,21]
```

Otherwise (if the next bit of the character is `0`), instruction `(18, 5)` or `18*10 + 5` is
executed:
```Assembly
6878: (18, 5) push 2               S:[06,24,02]
```

Hence all we have to do is to keep track of instruction `(18, 1)` (bit `1`) and `(18, 5)` (bit `0`)
between instructions `(20, 1)`. Note that the bits are checked in **reverse** order so we have
to flip the bits first. [borken_counter_crack.py](./borken_counter_crack.py), parses `out.txt`
and recovers the bitstream:
```
[+] Borken Counter crack started ...
1110000 0x70 p
0110100 0x34 4
1111011 0x7b {
1110111 0x77 w
1101000 0x68 h
1111001 0x79 y
1011111 0x5f _
1101001 0x69 i
1110011 0x73 s
1011111 0x5f _
1100010 0x62 b
1100101 0x65 e
1100110 0x66 f
1110101 0x75 u
1101110 0x6e n
1100111 0x67 g
1100101 0x65 e
1011111 0x5f _
1100101 0x65 e
1110110 0x76 v
1100101 0x65 e
1101110 0x6e n
1011111 0x5f _
1100101 0x65 e
1110011 0x73 s
1101111 0x6f o
1110100 0x74 t
1100101 0x65 e
1110010 0x72 r
1101001 0x69 i
1100011 0x63 c
1111101 0x7d }
[+] Flag is: p4{why_is_befunge_even_esoteric}
```

Therefore our flag is: `p4{why_is_befunge_even_esoteric}`

Note that this language is not custom and it's called [befunge](https://en.wikipedia.org/wiki/Befunge).

___
