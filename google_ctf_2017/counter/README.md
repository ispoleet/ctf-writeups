## Google CTF 2017 - counter (RE 420pt)
##### 17-18/06/2017 (48hr)

___
### Description

This strange program was found, which apparently specialises in counting. In order to 
find the flag, you need to output find what the output of ./counter 9009131337 is.


c7edc32f5aaf6740-code

04ddd382687332f2-counter

___
### Solution

##### Reversing the binary

This reversing challenge belongs to my favorite category: VM crackmes. The 
term "crackme" might be misleading here as the goal of tis challenge isn't to find any
password, but to optimize the code. More specifically we need to get the output when
we run program with a (large) input: 9009131337. We start by trying to see how program
behaves with small inputs (using the given code file) and we see that for values > 30, 
it starts getting really slow.

Let's start. Binary was pretty simple to reverse. We start from main():
```assembly
.....
.text:00000000004006D1 loc_4006D1:                  ; CODE XREF: main+9j
.text:00000000004006D1    mov     rdi, [rsi+8]      ; nptr
.text:00000000004006D5    mov     edx, 0Ah          ; base
.text:00000000004006DA    xor     esi, esi          ; endptr
.text:00000000004006DC    call    _strtol
.text:00000000004006E1    mov     rbp, rax			; rbp = llong(argv[1])
.text:00000000004006E4    xor     eax, eax
.text:00000000004006E6    call    READ_CODE_400990
.text:00000000004006EB    mov     edi, 0D0h         ; size
.text:00000000004006F0    call    _malloc
.text:00000000004006F5    xor     edx, edx
.text:00000000004006F7    mov     rbx, rax
.text:00000000004006FA    nop     word ptr [rax+rax+00h]
.text:0000000000400700
.text:0000000000400700 BZERO_400700:                ; CODE XREF: main+63j
.text:0000000000400700    mov     qword ptr [rbx+rdx], 0         ; memset
.text:0000000000400708    add     rdx, 8
.text:000000000040070C    cmp     rdx, 0D0h
.text:0000000000400713    jnz     short BZERO_400700             ; memset
.text:0000000000400715    xor     esi, esi          ; arg2 = 0
.text:0000000000400717    mov     rdi, rbx
.text:000000000040071A    movsxd  rbp, ebp
.text:000000000040071D    mov     [rbx], rbp		; array[0] = llong(argv[1])
.text:0000000000400720    call    COUNT_4008A0
.text:0000000000400725    mov     rdx, [rbx]
.text:0000000000400728    mov     esi, offset aCtf016llx         ; "CTF{%016llx}\n"
.text:000000000040072D    mov     edi, 1
.text:0000000000400732    xor     eax, eax
.text:0000000000400734    call    ___printf_chk
.....
```

main() calls READ_CODE(), which loads the "code" file into memory and then it calls 
a strange recursive function. The command line argument is stored in the 1st entry of
an array, which is initialized at 0x400700. After function call the same element is 
printed as a flag.

READ_CODE() actually opens a file called "code" and loads it into memory:

```assembly
.....
.text:0000000000400990    push    r12
.text:0000000000400992    mov     esi, offset modes              ; "rb"
.text:0000000000400997    mov     edi, offset filename           ; "code"
.text:000000000040099C    push    rbp
.text:000000000040099D    push    rbx
.text:000000000040099E    sub     rsp, 10h
.text:00000000004009A2    call    _fopen
.text:00000000004009A7    test    rax, rax
.text:00000000004009AA    mov     r12, rax
.text:00000000004009AD    jz      FILE_NOT_FOUND_400B21
.text:00000000004009B3    lea     rdi, [rsp+28h+ptr]             ; ptr
.text:00000000004009B8    mov     rcx, rax          ; stream
.text:00000000004009BB    mov     edx, 1            ; n
.text:00000000004009C0    mov     esi, 4            ; size
.text:00000000004009C5    call    _fread            ; read 1 integer from file
.text:00000000004009CA    cmp     rax, 1
.text:00000000004009CE    jnz     ERR_READ_FILE_400AD1
.text:00000000004009D4    movsxd  rdi, [rsp+28h+ptr]
.text:00000000004009D9    lea     eax, [rdi-1]      ; eax = number -1 (iterator)
.text:00000000004009DC    cmp     eax, 3E7h
.text:00000000004009E1    ja      INVALID_NUMBER_400B0D
.text:00000000004009E7    shl     rdi, 4            ; size
.text:00000000004009EB    call    _malloc
.text:00000000004009F0    mov     edx, [rsp+28h+ptr]
.text:00000000004009F4    mov     cs:buf_602098, rax
.text:00000000004009FB    test    edx, edx
.text:00000000004009FD    mov     cs:number_602090, edx
.text:0000000000400A03    jle     GOOD_400AC0
.text:0000000000400A09    mov     rdi, rax
.text:0000000000400A0C    xor     ebx, ebx          ; counter
.text:0000000000400A0E    xor     ebp, ebp
.text:0000000000400A10    jmp     short loc_400A3A
.text:0000000000400A10 ; ---------------------------------------------------------------------------
.text:0000000000400A12    align 8
.text:0000000000400A18
.text:0000000000400A18 LOOP_OUTER_400A18:           ; CODE XREF: READ_CODE_400990+D4j
.text:0000000000400A18    cmp     byte ptr [rdx+4], 19h
.text:0000000000400A1C    ja      INVALID_REG_400AA6
.text:0000000000400A22    mov     eax, [rsp+28h+ptr]
.text:0000000000400A26    cmp     [rdx+8], eax
.text:0000000000400A29    ja      short INVALID_NEXT_400A88
.text:0000000000400A2B
.text:0000000000400A2B LOOP_400A2B:                 ; CODE XREF: READ_CODE_400990+F6j
.text:0000000000400A2B    add     ebp, 1
.text:0000000000400A2E    add     rbx, 10h
.text:0000000000400A32    cmp     ebp, eax
.text:0000000000400A34    jge     GOOD_400AC0
.text:0000000000400A3A
.text:0000000000400A3A loc_400A3A:                  ; CODE XREF: READ_CODE_400990+80j
.text:0000000000400A3A    add     rdi, rbx          ; ptr
.text:0000000000400A3D    mov     rcx, r12          ; stream
.text:0000000000400A40    mov     edx, 1            ; n
.text:0000000000400A45    mov     esi, 10h          ; size
.text:0000000000400A4A    call    _fread            ; read 4 ints from file (buf b)
.text:0000000000400A4F    cmp     rax, 1
.text:0000000000400A53    jnz     short loc_400AD1
.text:0000000000400A55    mov     rdi, cs:buf_602098
.text:0000000000400A5C    lea     rdx, [rdi+rbx]
.text:0000000000400A60    mov     esi, [rdx]        ; esi = b[0] = ins
.text:0000000000400A62    test    esi, esi
.text:0000000000400A64    jz      short LOOP_OUTER_400A18        ; if it's 0 skip it
.text:0000000000400A66    cmp     esi, 1
.text:0000000000400A69    jz      short loc_400AA0               ; it must be 1 or 2
.text:0000000000400A6B    cmp     esi, 2
.text:0000000000400A6E    jnz     INVALID_INS_400AF9
.text:0000000000400A74    cmp     dword ptr [rdx+4], 1Ah         ; b[1] = amo < 26
.text:0000000000400A78    ja      short INVALID_AMO_400AE5
.text:0000000000400A7A
.text:0000000000400A7A loc_400A7A:                  ; CODE XREF: READ_CODE_400990+114j
.text:0000000000400A7A    mov     eax, [rsp+28h+ptr]
.text:0000000000400A7E    cmp     [rdx+8], eax      ; b[2] = next > number ?
.text:0000000000400A81    ja      short INVALID_NEXT_400A88
.text:0000000000400A83    cmp     eax, [rdx+0Ch]    ; if b[3] < number, continue
.text:0000000000400A86    jnb     short LOOP_400A2B
.text:0000000000400A88
.text:0000000000400A88 INVALID_NEXT_400A88:         ; CODE XREF: READ_CODE_400990+99j
.text:0000000000400A88                 ; READ_CODE_400990+F1j
.text:0000000000400A88    mov     edi, offset aInvalidNext       ; "Invalid next"
.text:0000000000400A8D    call    _puts
.text:0000000000400A92    mov     edi, 1            ; status
.text:0000000000400A97    call    _exit
.text:0000000000400A97 ; ---------------------------------------------------------------------------
.text:0000000000400A9C    align 20h
.text:0000000000400AA0
.text:0000000000400AA0 loc_400AA0:                  ; CODE XREF: READ_CODE_400990+D9j
.text:0000000000400AA0    cmp     byte ptr [rdx+4], 19h          ; b[1] = reg
.text:0000000000400AA4    jbe     short loc_400A7A
.text:0000000000400AA6
.text:0000000000400AA6 INVALID_REG_400AA6:          ; CODE XREF: READ_CODE_400990+8Cj
.text:0000000000400AA6    mov     edi, offset aInvalidReg        ; "Invalid reg"
.text:0000000000400AAB    call    _puts
.text:0000000000400AB0    mov     edi, 1            ; status
.text:0000000000400AB5    call    _exit
.text:0000000000400AB5 ; ---------------------------------------------------------------------------
.text:0000000000400ABA    align 20h
.text:0000000000400AC0
.text:0000000000400AC0 GOOD_400AC0:                 ; CODE XREF: READ_CODE_400990+73j
.text:0000000000400AC0                 ; READ_CODE_400990+A4j
.text:0000000000400AC0    mov     rdi, r12          ; stream
.text:0000000000400AC3    call    _fclose
.text:0000000000400AC8    add     rsp, 10h
.text:0000000000400ACC    pop     rbx
.text:0000000000400ACD    pop     rbp
.text:0000000000400ACE    pop     r12
.text:0000000000400AD0    retn
.....
```

This function reveals the format of the code. At first there's a 4 byte integer that indicates
the number of rows in the file. Each row consists of 4 4-byte integers. Let _b0, b1, b2, b3_
be those integers. Clearly, b0 must be in [0, 1, 2]. If it's 0, b1 must be <26 and b2
must be < #rows. If it's 1 or 2, then b1 must be <26 and b2, b3 must be < #rows. Also,
b0 is called "ins", b1 "reg" or "amo" and b2 and b3 are called "next". As we'll see later, 
these names are very informative.

The last part of the binary is the recursive function COUNT_4008A0():
```assembly
.....
.text:00000000004008B0 MAIN_LOOP_4008B0:            ; CODE XREF: COUNT_4008A0+48j
.text:00000000004008B0                 ; COUNT_4008A0+BBj ...
.text:00000000004008B0    cmp     esi, edx          ; if arg2 = deep >R number; return
.text:00000000004008B2    jz      short RETURN_4008D9
.text:00000000004008B4
.text:00000000004008B4 INNER_LOOP_4008B4:           ; CODE XREF: COUNT_4008A0+37j
.text:00000000004008B4    movsxd  rbx, esi
.text:00000000004008B7    shl     rbx, 4
.text:00000000004008BB    add     rbx, cs:buf_602098             ; read row[deep]
.text:00000000004008C2    mov     eax, [rbx]        ; eax = ins
.text:00000000004008C4    test    eax, eax
.text:00000000004008C6    jnz     short NON_ZERO_INS_4008E0      ; if ins == 0 then flag[ b[1] ]++
.text:00000000004008C8    movzx   eax, byte ptr [rbx+4]
.text:00000000004008CC    mov     esi, [rbx+8]
.text:00000000004008CF    add     qword ptr [rbp+rax*8+0], 1
.text:00000000004008D5    cmp     esi, edx
.text:00000000004008D7    jnz     short INNER_LOOP_4008B4
.text:00000000004008D9
.text:00000000004008D9 RETURN_4008D9:               ; CODE XREF: COUNT_4008A0+12j
.....
.text:00000000004008E0 NON_ZERO_INS_4008E0:         ; CODE XREF: COUNT_4008A0+26j
.text:00000000004008E0    cmp     eax, 1
.text:00000000004008E3    jz      short INS_400960               ; eax = reg
.text:00000000004008E5    cmp     eax, 2
.text:00000000004008E8    jnz     short MAIN_LOOP_4008B0         ; if arg2 = deep > number; return
.text:00000000004008EA ------------------------------------------------------------------
.text:00000000004008EA ins = 2
.text:00000000004008EA ------------------------------------------------------------------
.text:00000000004008EA
.text:00000000004008EA    mov     edi, 0D0h         ; size
.text:00000000004008EF    call    _malloc
.text:00000000004008F4    xor     edx, edx
.text:00000000004008F6    mov     r12, rax
.text:00000000004008F9    nop     dword ptr [rax+00000000h]
.text:0000000000400900
.text:0000000000400900 COPY_BACKUP_400900:          ; CODE XREF: COUNT_4008A0+74j
.text:0000000000400900    mov     rax, [rbp+rdx+0]               ; copy flag buffer
.text:0000000000400905    mov     [r12+rdx], rax
.text:0000000000400909    add     rdx, 8
.text:000000000040090D    cmp     rdx, 0D0h
.text:0000000000400914    jnz     short COPY_BACKUP_400900       ; copy flag buffer
.text:0000000000400916    mov     esi, [rbx+8]
.text:0000000000400919    mov     rdi, r12
.text:000000000040091C    call    COUNT_4008A0
.text:0000000000400921    mov     eax, [rbx+4]      ; eax = amo
.text:0000000000400924    test    eax, eax
.text:0000000000400926    jz      short loc_40094A
.text:0000000000400928    sub     eax, 1
.text:000000000040092B    xor     edx, edx
.text:000000000040092D    lea     rcx, ds:8[rax*8]
.text:0000000000400935    nop     dword ptr [rax]
.text:0000000000400938
.text:0000000000400938 COPY_RESTORE_400938:         ; CODE XREF: COUNT_4008A0+A8j
.text:0000000000400938    mov     rax, [r12+rdx]    ; restore flag buffer
.text:000000000040093C    mov     [rbp+rdx+0], rax
.text:0000000000400941    add     rdx, 8
.text:0000000000400945    cmp     rdx, rcx
.text:0000000000400948    jnz     short COPY_RESTORE_400938      ; restore flag buffer
.text:000000000040094A
.text:000000000040094A loc_40094A:                  ; CODE XREF: COUNT_4008A0+86j
.text:000000000040094A    mov     rdi, r12          ; ptr
.text:000000000040094D    call    _free
.text:0000000000400952    mov     esi, [rbx+0Ch]
.text:0000000000400955    mov     edx, cs:number_602090
.text:000000000040095B    jmp     MAIN_LOOP_4008B0               ; if arg2 = deep > number; return
.text:0000000000400960 ; ---------------------------------------------------------------------------
.text:0000000000400960
.text:0000000000400960 INS_400960:                  ; CODE XREF: COUNT_4008A0+43j
.text:0000000000400960    movzx   eax, byte ptr [rbx+4]          ; eax = reg
.text:0000000000400964    lea     rax, [rbp+rax*8+0]
.text:0000000000400969    mov     rcx, [rax]        ; rcx = flag[reg]
.text:000000000040096C    test    rcx, rcx
.text:000000000040096F    jnz     short END_400980
.text:0000000000400971    mov     esi, [rbx+0Ch]
.text:0000000000400974    jmp     MAIN_LOOP_4008B0               ; if arg2 = deep > number; return
....
```

This function takes 2 arguments, an array to work on and an offset to that array. It processes
the corresponding offset and moves on the another row. If the offset is out of bounds, function
returns. The first call contains an array (let'scall it flag):
```
flag = [int(argv[1]), 0, ... 24 more 0's ...]
```

as the first argument and an offset of 0. Thus, COUNT_4008A0() starts from 1st row of the flag 
array. The behavior of this function can be summarized in the following lines. Based on b0 
(ins), functions acts differently:

* _ins 0_: flag[reg]++; goto next1;
* _ins 1_: if( flag[reg] > 0 ) { flag[reg]--; goto next1; } else goto next2;
* _ins 2_: flag[:reg] = count(flag, next1); goto next2


For completeness the fully decompiled code is shown in  
[counter_decompiled.py](./counter_decompiled.py).

So, this code jumps around this table and each time modifies incrementally a part of the flag.
The code file indicates the rows. As you can see from the 3 candidate instructions,
we can modify values, access random rows and having conditional jumps. All these properties
mean that we can have Turing-complete computations using just these 3 instructions.

So we are sure now, that we actually emulate some code.

___

##### Reversing the code

According to the format of READ_CODE(), there are 118 rows in the code file, as shown below:
```
ispo@nogirl:~/ctf/google_ctf_17/counter$ hexdump -s 4 -e '"%8xh %8xh %8xh %8xh\n"' code
       1h        0h        1h        2h
       0h        1h        0h        0h
       0h        2h        3h        0h
       0h        2h        4h        0h
       0h        2h        5h        0h
       0h        2h        6h        0h
       0h        2h        7h        0h
       0h        2h        8h        0h
       0h        2h        9h        0h
       0h        2h        ah        0h
       0h        2h        bh        0h
       0h        2h        ch        0h
       0h        2h        dh        0h
       2h        1h       6ch        eh
       1h        0h       77h        fh
       2h        1h       14h       10h
       1h        2h       10h       11h
       1h        0h       12h       13h
       0h        2h       11h        0h
       2h        1h       40h       77h
       1h        2h       14h       15h
       2h        1h       1dh       16h
       1h        0h       17h       18h
       0h        2h       16h        0h
       1h        1h       19h       1ah
       1h       19h        0h       15h
       1h        0h       1ah       1bh
       1h        2h       1ch       77h
       0h        0h       1bh        0h
       1h        2h       1dh       1eh
       2h        1h       54h       1fh
       1h        3h       1fh       20h
       1h        0h       21h       22h
       0h        3h       20h        0h
       1h        3h       23h       2ah
       1h        3h       24h       2ah
       2h        1h       2dh       25h
       0h        2h       26h        0h
       1h        1h       26h       27h
       1h        0h       28h       29h
       0h        1h       27h        0h
       1h       19h        0h       1eh
       1h        0h       2ah       2bh
       1h        2h       2ch       77h
       0h        0h       2bh        0h
       1h        2h       2dh       2eh
       2h        1h       54h       2fh
       1h        0h       30h       31h
       0h        2h       2fh        0h
       2h        2h       5ch       32h
       1h        1h       33h       77h
       1h        0h       33h       34h
       1h        1h       34h       35h
       1h        2h       36h       37h
       0h        1h       35h        0h
       2h        1h       54h       38h
       1h        0h       39h       3ah
       0h        2h       38h        0h
       2h        1h       54h       3bh
       1h        1h       3ch       3dh
       0h        0h       3bh        0h
       1h        2h       3eh       3fh
       0h        0h       3dh        0h
       0h        0h       77h        0h
       2h        1h       54h       41h
       1h        3h       41h       42h
       1h        0h       43h       44h
       0h        3h       42h        0h
       1h        3h       45h       77h
       0h        0h       46h        0h
       1h        3h       47h       77h
       1h        1h       48h       77h
       2h        1h       40h       49h
       1h        4h       49h       4ah
       1h        0h       4bh       4ch
       0h        4h       4ah        0h
       1h        1h       4dh       77h
       2h        1h       40h       4eh
       1h        0h       4fh       50h
       0h        4h       4eh        0h
       1h        1h       50h       51h
       1h        4h       52h       53h
       0h        1h       51h        0h
       2h        1h       63h       77h
       1h        0h       54h       55h
       1h        1h       56h       77h
       0h        0h       55h        0h
       1h        0h       57h       58h
       1h        1h       59h       5ah
       0h        0h       58h        0h
       1h        2h       5bh       77h
       0h        0h       5ah        0h
       1h        0h       5ch       5dh
       1h        1h       5dh       5eh
       1h        2h       5fh       77h
       1h        2h       60h       62h
       0h        0h       61h        0h
       1h       19h        0h       5eh
       0h        1h       77h        0h
       2h        1h       6ch       64h
       1h        0h       65h       67h
       1h        1h       66h       77h
       0h        0h       65h        0h
       2h        1h       71h       68h
       1h        1h       68h       69h
       1h        0h       6ah       6bh
       0h        1h       69h        0h
       1h       19h        0h       63h
       1h        0h       6ch       6dh
       1h        2h       6eh       77h
       1h        1h       6fh       70h
       1h       19h        0h       6ch
       0h        0h       77h        0h
       1h        2h       72h       74h
       1h        1h       73h       77h
       1h       19h        0h       71h
       1h        0h       74h       75h
       1h        1h       76h       77h
       0h        0h       75h        0h
```

A quick look at this code gives us some useful hints:

* flag[25] is never incremented (and is initialized to 0). Therefore _ins 1_ for b1 = 25
	is always false. So instruction
	`if( flag[25] > 0 ) { flag[25]--; goto next1; } else goto next2;`, becomes `goto next2`


* All function calls (_ins 2_) affect flag[0] except call at row 99 which affects flag[0] 
	and flag[1]. This is because we make a backup of the flag array, so the only elements 
	of the flag that are affected are `flag[0]` (and flag[1] in case of #99)


From now on, flag[0] = F0, flag[1] = F1, and so on. The first thing is to "slice" the program.
We're looking for _ins 2_ and we split the program at the point that b2 points to (the
function's entry point). Then, we try to reverse the emulated code. Because functions usually
invoke other functions, we start reversing the emulated code backwards. I'll give a detailed
example of the last function on the code (starting at line #113):

```
113:  1   2  114  116	; if( F2 > 0 ) F2--; else goto 116
114:  1   1  115  119	; if( F1 > 0 ) F1--; else return
115:  1  25    0  113	; goto 113

116:  1   0  116  117	; F0 = 0	(and also F1 -= F2)

117:  1   1  118  119	; if( F1 > 0 ) F1--; else return
118:  0   0  117    0	; F0++; goto 117
```

The comments on the right make instruction readable. We can rewrite these instructions
as follows (in python style):
```python
	F0 = F1 - F2 if F1 >= F2 else 0
```

Hmmm, this looks like a subtraction! As you see, subtraction is implemented by decrementing
numbers by 1, which justifies why the code is so slow even for small values. We can
continue this way and reverse the whole code (working backwards always; so start reading
from the bottom :P):

```
# -----------------------------------------------------------------------------
# MAIN 
# -----------------------------------------------------------------------------
  0:  1   0    1    2	; F1 = F0		$ if( F0 > 0 ) F0--; else goto 2;
  1:  0   1    0    0	; 				$ F1++; goto 1;
  2:  0   2    3    0	; F2++;
  3:  0   2    4    0	; F2++;
  4:  0   2    5    0	; F2++;
  5:  0   2    6    0	; F2++;
  6:  0   2    7    0	; F2++;
  7:  0   2    8    0	; F2++;
  8:  0   2    9    0	; F2++;
  9:  0   2   10    0	; F2++;
 10:  0   2   11    0	; F2++;
 11:  0   2   12    0	; F2++;
 12:  0   2   13    0	; F2++;
 13:  2   1  108   14	; F0 = CMP(F1, F2)
 14:  1   0  119   15	; if( F0 > 0 ) F0--; else return

 15:  2   1   20   16	; F0 = FUNC_0
 
 16:  1   2   16   17	; F2 = F0		$ F2 = 0 
 17:  1   0   18   19	; 	 			$ if( F0 > 0 ) F0--; else goto 19
 18:  0   2   17    0	; 				$ F2++; goto 17

 19:  2   1   64  119	; F0 = FUNC_3(); return

# -----------------------------------------------------------------------------
# FUNC #0 (SUM)
# ----------------------------------------------------------------------------- 
 20:  1   2   20   21	; F2 = 0
 
 21:  2   1   29   22	; F0 = FUNC1()
 22:  1   0   23   24	; 				$ if( F0 > 0 ) F0--; else goto 24
 23:  0   2   22    0	; F2 = F0		$ F2++; goto 22

 24:  1   1   25   26	; if( F1 > 0 ) F1--; else goto 26
 25:  1  25    0   21	; goto 21

 26:  1   0   26   27	; F0 = F2		$ F0 = 0
 27:  1   2   28  119	; 				$ if( F2 > 0 ) F2--; else return
 28:  0   0   27    0	; 				$ F0++; goto 27

$$$ START OF DECOMPILED CODE $$$
F2 = 0
while(1) {
	F2 += FUNC_1(F1, ... )

	if( F1 == 0 ) break
	F1--;
}

F0 = F2
$$$ END OF DECOMPILED CODE $$$

# -----------------------------------------------------------------------------
# FUNC #1
# ----------------------------------------------------------------------------- 
 29:  1   2   29   30	; F2 = 0

 30:  2   1   84   31	; MOV: F0 = F1

 31:  1   3   31   32	; 				$ F3 = 0
 32:  1   0   33   34	; F3 = F0 		$ if( F0 > 0 ) F0--; else goto 34
 33:  0   3   32    0	;				$ F3++; goto 32

 34:  1   3   35   42	; if( F3 > 0 ) F3--; else goto 42
 35:  1   3   36   42	; if( F3 > 0 ) F3--; else goto 42

 36:  2   1   45   37	; F0 = FUNC_2()

 37:  0   2   38    0	; F2++
 38:  1   1   38   39	; F1 = F0 		$ F1 = 0
 39:  1   0   40   41	; 				$ if( F0 > 0 ) F0--; else goto 41
 40:  0   1   39    0	; 				$ F1++; goto 39

 41:  1  25    0   30	; goto 30
 

 42:  1   0   42   43	; F0 = F2		$ F0 = 0
 43:  1   2   44  119	; 				$ if( F2 > 0 ) F2--; else return
 44:  0   0   43    0	; 				$ F0++; goto 43


$$$ START OF DECOMPILED CODE $$$
F2 = 0

while True:
	F3 = F1

	if( F3 == 0 ) break
	F3--

	if( F3 == 0 ) break
	F3--

	F1 = FUNC_2()
	F2++

F0 = F2
$$$ END OF DECOMPILED CODE $$$

# -----------------------------------------------------------------------------
# FUNC #2
# ----------------------------------------------------------------------------- 
 45:  1   2   45   46	; F2 = 0
 46:  2   1   84   47	; MOV: F0 = F1
 
 47:  1   0   48   49	; F2 = F0		$ if( F0 > 0 ) F0--; else goto 49
 48:  0   2   47    0	; 				$ F2++; goto 47
 
 49:  2   2   92   50	; SHR: F0 = F2 / 2; F1 = F2 % 2
 50:  1   1   51  119	; if( F1 > 0 ) F1--; else return
 
 51:  1   0   51   52	; F0 = 0

 52:  1   1   52   53	; 				$ F1 = 0 
 53:  1   2   54   55	; F1 = F2		$ if( F2 > 0 ) F2--; else goto 55
 54:  0   1   53    0	; 				$ F1++; goto 53
 
 55:  2   1   84   56	; MOV: F0 = F1

 56:  1   0   57   58	; F2 = F0		$ if( F0 > 0 ) F0--; else goto 58
 57:  0   2   56    0	; 				$ F2++; goto 56

 58:  2   1   84   59	; MOV: F0 = F1
 
 59:  1   1   60   61	; 				$ if( F1 > 0 ) F1--; else goto 61
 60:  0   0   59    0	; F0 = 2*F1		$ F0++; goto 59

 61:  1   2   62   63	; 				$ if( F2 > 0 ) F2--; else goto 63
 62:  0   0   61    0	; F0 += F2		$ F0++; goto 61

 63:  0   0  119    0	; F0++; return


$$$ START OF DECOMPILED CODE $$$
F2 = F1

F0 = F2 / 2
F1 = F2 % 2

if( F1 == 0 ) return

F0 = 2*F2 + F2 + 1
$$$ END OF DECOMPILED CODE $$$

# -----------------------------------------------------------------------------
# FUNC #3
# ----------------------------------------------------------------------------- 
 64:  2   1   84   65	; MOV: F0 = F1
 65:  1   3   65   66	; 					$ F3 = 0
 66:  1   0   67   68	; F3 = F0 			$ if( F0 > 0 ) F0--; else goto 68
 67:  0   3   66    0	; 					$ F3++; goto 66
 
 68:  1   3   69  119	; if( F3 > 0 ) F3--; else return

 69:  0   0   70    0	; F0++;
 70:  1   3   71  119	; if( F3 > 0 ) F3--; else return
 71:  1   1   72  119	; if( F1 > 0 ) F1--; else return

 72:  2   1   64   73	; F0 = FUNC_3()

 73:  1   4   73   74	; F4 = F0			$ F4 = 0
 74:  1   0   75   76	; 					$ if( F0 > 0 ) F0--; else goto 76
 75:  0   4   74    0	; 					$ F4++; goto 74

 76:  1   1   77  119	; if( F1 > 0 ) F1--; else return
 77:  2   1   64   78	; F0 = FUNC_3()

 78:  1   0   79   80	; F4 += F0			$ if( F0 > 0 ) F0--; else goto 80
 79:  0   4   78    0	; 					$ F4++; goto 78
 
 80:  1   1   80   81	; F1 = F4			$ F1 = 0
 81:  1   4   82   83	; 					$ if( F4 > 0 ) F4--; else goto 83 
 82:  0   1   81    0	; 					$ F1++; goto 81

 83:  2   1   99  119	; F0 = DIV; return
 
$$$ START OF DECOMPILED CODE $$$
FUNC_3(F1, F2) 
{
	F3 = F1

	if( F3 == 0 ) return
	
	F3--; F0++;

	if( F3 == 0 || F1 == 0 ) return

	F3--; F1--;

	F4 = FUNC_3(F1, F2)

	if( F1 == 0 ) return
	F1--;
	
	F4 += FUNC_3(F1, F2)

	F1 = F4

	F0 = MOD(F1, F2)
}
$$$ END OF DECOMPILED CODE $$$

# -----------------------------------------------------------------------------
# FUNC #4 (MOV)
# -----------------------------------------------------------------------------
 84:  1   0   84   85	; F0 = 0
 85:  1   1   86  119	; if( F1 > 0 ) F1--; else return
 86:  0   0   85    0	; F0++; goto 85

 87:  1   0   87   88	; DEAD CODE
 88:  1   1   89   90	; 
 89:  0   0   88    0	; 
 90:  1   2   91  119	; 
 91:  0   0   90    0	; 


$$$ START OF DECOMPILED CODE $$$
F0 = F1
$$$ END OF DECOMPILED CODE $$$

# -----------------------------------------------------------------------------
# FUNC #5 (SHR)
# -----------------------------------------------------------------------------
 92:  1   0   92   93	; F0 = 0
 93:  1   1   93   94	; F1 = 0
 
 94:  1   2   95  119	; if( F2 > 0 ) F2--; else return
 95:  1   2   96   98	; if( F2 > 0 ) F2--; else goto 98
 96:  0   0   97    0	; F0++;
 97:  1  25    0   94	; goto 94;

 98:  0   1  119    0	; F1++; return

$$$ START OF DECOMPILED CODE $$$
F0 = F2 / 2
F1 = F2 % 2
$$$ END OF DECOMPILED CODE $$$

# -----------------------------------------------------------------------------
# FUNC #6 (MOD)
# -----------------------------------------------------------------------------
 99:  2   1  108  100	; CMP: if( F1 < F2 ) F0 = 1; else F0 = 0
100:  1   0  101  103	; if( F0 > 0 ) F0--; else goto 103

# F1 < F2	; F0 = F1; return
101:  1   1  102  119	; if( F1 > 0 ) F1--; else return
102:  0   0  101    0	; F0++; goto 101

# F1 >= F2	; F0 = F1; F1 = 0
103:  2   1  113  104	; SUB: F0 = F1 - F2 

104:  1   1  104  105	; F1 = 0

105:  1   0  106  107	; if( F0 > 0 ) F0--; else goto 107
106:  0   1  105    0	; F1++; goto 105

107:  1  25    0   99	; goto 99

$$$ START OF DECOMPILED CODE $$$
while( 1 )
{
	if( F1 < F2 ) {
		F0 = F1
		return 
	}
	else {
		F0 = F1 - F2
		F1 = F0

		// F1 -= F2
	}
}

/* MODULO! F0 = F1 % F2 */
$$$ END OF DECOMPILED CODE $$$

# -----------------------------------------------------------------------------
# FUNC #7 (CMP)
# -----------------------------------------------------------------------------
108:  1   0  108  109	; F0 = 0
109:  1   2  110  119	; if( F2 > 0 ) F2--; else return
110:  1   1  111  112	; if( F1 > 0 ) F1--; else goto 112
111:  1  25    0  108	; goto 108

112:  0   0  119    0	; F0++; return

$$$ START OF DECOMPILED CODE $$$
if( F1 < F2 ) F0 = 1; else F0 = 0
$$$ END OF DECOMPILED CODE $$$

# -----------------------------------------------------------------------------
# FUNC #8 (SUB)
# -----------------------------------------------------------------------------
113:  1   2  114  116	; if( F2 > 0 ) F2--; else goto 116
114:  1   1  115  119	; if( F1 > 0 ) F1--; else return
115:  1  25    0  113	; goto 113

116:  1   0  116  117	; F0 = 0	(and also F1 -= F2)

117:  1   1  118  119	; if( F1 > 0 ) F1--; else return
118:  0   0  117    0	; F0++; goto 117

$$$ START OF DECOMPILED CODE $$$
F0 = F1 - F2 if ( F1 >= F2 ) else 0
$$$ END OF DECOMPILED CODE $$$
```


Now you can see why code is so slow. All operations are performed incrementally. 
All functions but FUNC_1, FUNC_2 and FUNC_3 are easy to spot what they're doing.
Let's rewrite FUNC_3:
```python
def FUNC_3(F1, F2):
	
	F0 = 0
	
	if F1 == 0: return 0	
	if F1 == 1: return 1

	F1 = FUNC_3(F1-1, F2) + FUNC_3(F1-2, F2)

	F0 = F1 % F2


	return F0
```

Do you see what's that? It's modulo Fibonacci! But it's implemented using recursion 
and therefore it's very slow.

Let's go on FUNC_2:
```python
def FUNC_2(F1):
	if F1 % 2 == 0:
		return F1 / 2
	else:
		return 3*F1 + 1
```

And to FUNC_1:
```python
def FUNC_1(F1):
	F2 = 0

	while F1 > 1:
		F1 = FUNC_2(F1)
		F2 += 1

	return F2
```

Ok that's weird. We have a number and we divided by 2 when it's even or we multiply it by 3
and we add 1 when it's odd. We do that until this number becomes one and we count how many 
steps it took. A quick google search shows us that this is the "3x + 1" problem or the 
*Collatz conjecture*. The Collatz conjecture says that this process will eventually reach 
number 1, regardless of which positive integer is chosen initially.

___

##### Optimizing the program

At this point we have a clean output of the emulated code:
[counter_crack.py](./counter_crack.py).

Optimizing the Fibonacci function is trivial. However, optimizing the summation can't
be really optimized as there's no correlation between numbers "3x + 1" problem.  The only
thing that we can do here is to break the summation into smaller ones and calculate them
in parallel. Then, we add them together to get the desired summation.
See file [collatz_partial.py](./collatz_partial.py) for more details.

So, we run the following commands to get partial summations (it spawns ~900+ 
processes and it takes ~6 hours):
```
for ((i=0; i<=9000000000; i+=10000000))
do 
	j=$((i + 10000000 -1)); 
	./collatz_partial.py $i $j >> sums & 
done

for ((i=9000000000; i<9009000000; i+=1000000)) 
do 
	j=$((i + 1000000 -1)); 
	./collatz_partial.py $i $j >> sums  & 
done


./collatz_partial.py 9009000000 9009131337 >> sums

awk {'print $6'} sums > sums_clean
```

After all, we can finally get the flag:
```
ispo@nogirl:~/ctf/google_ctf_17/counter$ ./collatz_partial.py 
Summation is: 2037448192360

ispo@nogirl:~/ctf/google_ctf_17/counter$ ./counter_crack.py 2037448192360
CTF{000001bae15b6382}
```
___
