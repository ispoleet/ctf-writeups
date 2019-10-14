

## HITCON CTF quals 2019 - emojivm (Reversing 300)
##### 12/10 - 14/10/2019 (48hr)
___

### Description: 

A simple VM that takes emojis as input! Try figure out the secret!

```
emojivm-d967bd1b53b927820de27960f8eec7d7833150ca.zip
```
___


### Solution

First of all we are dealing with **a stack machine VM**. We start by getting the unique emojis
(opcodes). We use [./get_unique_emojis.py](./get_unique_emojis.py) to to get all unique emojis.


`vm_main_555555558DB8` is where emulation takes place. We have a switch loop, with `0x17`
cases, one for each instruction. At the beginning we get the next emoji and we convert it
to int, to dispatch it in the switch statement using `emoji_to_int_55555555A108`:
```assembly
.text:0000555555558E6D         mov     [rbp+next_opcode_28], eax
.text:0000555555558E70         lea     rax, [rbp+next_opcode_28]
.text:0000555555558E74         mov     rsi, rax                ; arg2: &emoji_opcode
.text:0000555555558E77         lea     rdi, qword_555555762180
.text:0000555555558E7E         call    emoji_to_int_55555555A108
.text:0000555555558E83         mov     eax, [rax]              ; opcode range: 0x1-0x17
.text:0000555555558E85         cmp     eax, 17h
```

`emoji_to_int_55555555A108`, is quite complicated, so instead we use a blackbox analysis: We 
set debugger to `0x0000555555558E6D` and we set `eax` to the emoji code. Then we run
`emoji_to_int_55555555A108` and we collect the return value. We do this for every unique emoji
we have (there are not too many so we're good). After that we can build our table:
```
	🈳	0x1f233    ---> 0x01
	➕	0x02795    ---> 0x02
	➖	0x02796    ---> 0x03
	❌	0x0274c    ---> 0x04
	❓	0x02753    ---> 0x05
	❎	0x0274e    ---> 0x06
	👫	0x1f46b    ---> 0x07
	💀	0x1f480    ---> 0x08
	💯	0x1f4af    ---> 0x09
	🚀	0x1f680    ---> 0x0a
	🈶	0x1f236    ---> 0x0b
	🈚	0x1f21a    ---> 0x0c
	⏬	0x023ec    ---> 0x0d
	?
	📤	0x1f4e4    ---> 0x0f
	📥	0x1f4e5    ---> 0x10
	🆕	0x1f195    ---> 0x11
	?
	📄	0x1f4c4    ---> 0x13
	📝	0x1f4dd    ---> 0x14
	?
	?
	🛑	0x1f6d1    ---> 0x17
```

All instructions are exactly 1 opcode except 1 (the `push imm`) which is 2 opcodes (the 2nd emoji
is a constant pushed to the stack):
```assembly
.text:000055571ADA53CC INST_D_5555555593CC:
.text:000055571ADA53CC         mov     eax, [rbp+mem_ptr_2C]
....
.text:000055571ADA540B         add     eax, 1
.text:000055571ADA540E         movsxd  rdx, eax
.text:000055571ADA5411         mov     rax, [rbp+var_38]
.text:000055571ADA5415         mov     rsi, rdx
.text:000055571ADA5418         mov     rdi, rax
.text:000055571ADA541B         call    __ZNSt7__cxx1112basic_stringIwSt11char_traitsIwESaIwEEixEm ; std::__cxx11::basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t>>::operator[](ulong)
.text:000055571ADA5420         mov     eax, [rax]
.text:000055571ADA5422         mov     edi, eax
.text:000055571ADA5424         call    emoji_to_digit_d_55555555868F
.text:000055571ADA5429         cdqe
.text:000055571ADA542B         mov     [rbp+mem_val_1_18], rax
.text:000055571ADA542F         mov     eax, [rbp+mem_ptr_2C]
.text:000055571ADA5432         add     eax, 1
.text:000055571ADA5435         mov     [rbp+mem_ptr_2C], eax
.text:000055571ADA5438         mov     eax, [rbp+mem_ptr_2C]
.text:000055571ADA543B         cdqe
.text:000055571ADA543D         lea     rcx, ds:0[rax*8]
.text:000055571ADA5445         lea     rax, vm_memory_555555762260
.text:000055571ADA544C         mov     rdx, [rbp+mem_val_1_18]
.text:000055571ADA5450         mov     [rcx+rax], rdx
.text:000055571ADA5454         add     [rbp+pc_24], 2  ; push unknown_1(op_1)
.text:000055571ADA5458         jmp     55571ADA5733h
```

We can understand that it's 2 bytes from instruction `000055571ADA5454`
```assembly
add     [rbp+pc_24], 2
```

The 1st operand (2nd emoji) is converted into an integer and pushed to the stack. We repeat the
same process as before to analyze `emoji_to_digit_d_55555555868F`. Below is the integer that each
emoji is associated to:
```
	😀	0x1f600    ---> 0x00 	---> 0x00 (unknown_d)
	😁	0x1f601    ---> 0x00 	---> 0x01
	😂	0x1f602    ---> 0x00 	---> 0x02
	😄	0x1f604    ---> 0x00 	---> 0x05
	😅	0x1f605    ---> 0x00  	---> 0x06
	😆	0x1f606    ---> 0x00 	---> 0x07
	😉	0x1f609    ---> 0x00 	---> 0x08
	😊	0x1f60a    ---> 0x00 	---> 0x09
	😍	0x1f60d    ---> 0x00 	---> 0x0a
	😜	0x1f61c    ---> 0x00 	---> 0x04
	🤣	0x1f923    ---> 0x00    ---> 0x03
```

By analyzing all instructions we easily get the emoji assembly:
```
01: NOP; pc += 1

02: add: a = pop; b = pop; push a + b; pc += 1
03: sub: a = pop; b = pop; push a - b; pc += 1;
04: mul: a = pop; b = pop; push a * b; pc += 1;
05: mod: a = pop; b = pop; push a % b; pc += 1;
06: xor: a = pop; b = pop; push a ^ b; pc += 1;
07: and: a = pop; b = pop; push a & b; pc += 1;

08: a = pop, b = pop; if (a >= b) push 0; else push 1; pc += 1
09: a = pop, b = pop; if (a != b) push 0; else push 1; pc += 1

0A: a = pop; goto a
0B: a = pop, b = pop; if (!b) pc += 1 else pc = a
0C: a = pop, b = pop; if (b)  pc += 1 else pc = a

0D: push  emoji_to_digit(operand_1);  pc += 2
0E: pop; pc += 1

0F: a = pop, b = pop; push gptr_read(a, b); pc += 1 ; gptr[arg1][arg2]
10: a = pop, b = pop, c = pop; gptr_write(a, b, c); pc += 1; gptr[arg1][arg2] = arg3

11: a = pop; malloc(a); pc += 1 (a = size)
12: a = pop; free(a); pc += 1
13: a = pop; scanf_gptr(a); pc += 1
14: a = pop; printf_gptr(a); pc += 1

15: print_string(&top_of_stack); pc += 1
16: a = pop; print_long(a); pc += 1;

17: return
```

Instructions `0x11 - 0x16` are tricky as they invoke other functions complicated functions.
By looking at the big picture and not focusing on the details we can infer what they're doing.
VM maintains a global list of pointers called "gptr". We can allocate memory to these global
pointers, we can read and write to it and of course we can print the contents and read from stdin
into them. The most important ones are the read and write shown below:
```assembly
.text:000055571ADA4744 gptr_mem_read_f_555555558744 proc near  ; CODE XREF: vm_main_555555558DB8+743p
.text:000055571ADA4744
.text:000055571ADA4744 var_18          = dword ptr -18h
.text:000055571ADA4744 var_14          = dword ptr -14h
.text:000055571ADA4744 var_8           = qword ptr -8
.text:000055571ADA4744
.text:000055571ADA4744         push    rbp
.text:000055571ADA4745         mov     rbp, rsp
.text:000055571ADA4748         sub     rsp, 20h
.text:000055571ADA474C         mov     [rbp+var_14], edi
.text:000055571ADA474F         mov     [rbp+var_18], esi
.text:000055571ADA4752         mov     eax, [rbp+var_14]
.text:000055571ADA4755         mov     edx, eax
.text:000055571ADA4757         mov     esi, 0Ah
.text:000055571ADA475C         mov     edi, 0
.text:000055571ADA4761         call    a1_le_a3_lt_a2_555555558712
.text:000055571ADA4766         xor     eax, 1
.text:000055571ADA4769         test    al, al
.text:000055571ADA476B         jnz     short loc_55571ADA478A
.text:000055571ADA476D         mov     eax, [rbp+var_14]
.text:000055571ADA4770         cdqe
.text:000055571ADA4772         lea     rdx, ds:0[rax*8]
.text:000055571ADA477A         lea     rax, gptr_555555762200
.text:000055571ADA4781         mov     rax, [rdx+rax]
.text:000055571ADA4785         test    rax, rax
.text:000055571ADA4788         jnz     short loc_55571ADA4791
.text:000055571ADA478A
.text:000055571ADA478A loc_55571ADA478A:               ; CODE XREF: gptr_mem_read_f_555555558744+27j
.text:000055571ADA478A         mov     eax, 1
.text:000055571ADA478F         jmp     short loc_55571ADA4796
.text:000055571ADA4791 ; ---------------------------------------------------------------------------
.text:000055571ADA4791
.text:000055571ADA4791 loc_55571ADA4791:               ; CODE XREF: gptr_mem_read_f_555555558744+44j
.text:000055571ADA4791         mov     eax, 0
.text:000055571ADA4796
.text:000055571ADA4796 loc_55571ADA4796:               ; CODE XREF: gptr_mem_read_f_555555558744+4Bj
.text:000055571ADA4796         test    al, al
.text:000055571ADA4798         jz      short loc_55571ADA47CC
.text:000055571ADA479A         lea     rsi, aInvalidGptrInd ; "Invalid gptr index"
.text:000055571ADA47A1         lea     rdi, _ZSt5wcout ; std::wcout
.text:000055571ADA47A8         call    __ZStlsIwSt11char_traitsIwEERSt13basic_ostreamIT_T0_ES6_PKc ; std::operator<<<wchar_t,std::char_traits<wchar_t>>(std::basic_ostream<wchar_t,std::char_traits<wchar_t>> &,char const*)
.text:000055571ADA47AD         mov     rdx, rax
.text:000055571ADA47B0         mov     rax, cs:_ZSt4endlIwSt11char_traitsIwEERSt13basic_ostreamIT_T0_ES6__ptr
.text:000055571ADA47B7         mov     rsi, rax
.text:000055571ADA47BA         mov     rdi, rdx
.text:000055571ADA47BD         call    __ZNSt13basic_ostreamIwSt11char_traitsIwEElsEPFRS2_S3_E ; std::basic_ostream<wchar_t,std::char_traits<wchar_t>>::operator<<(std::basic_ostream<wchar_t,std::char_traits<wchar_t>>& (*)(std::basic_ostream<wchar_t,std::char_traits<wchar_t>>&))
.text:000055571ADA47C2         mov     edi, 1          ; status
.text:000055571ADA47C7         call    _exit
.text:000055571ADA47CC ; ---------------------------------------------------------------------------
.text:000055571ADA47CC
.text:000055571ADA47CC loc_55571ADA47CC:               ; CODE XREF: gptr_mem_read_f_555555558744+54j
.text:000055571ADA47CC         mov     eax, [rbp+var_14]
.text:000055571ADA47CF         cdqe
.text:000055571ADA47D1         lea     rdx, ds:0[rax*8]
.text:000055571ADA47D9         lea     rax, gptr_555555762200
.text:000055571ADA47E0         mov     rax, [rdx+rax]
.text:000055571ADA47E4         mov     [rbp+var_8], rax
.text:000055571ADA47E8         mov     rax, [rbp+var_8]
.text:000055571ADA47EC         mov     rax, [rax]
.text:000055571ADA47EF         mov     ecx, eax
.text:000055571ADA47F1         mov     eax, [rbp+var_18]
.text:000055571ADA47F4         mov     edx, eax
.text:000055571ADA47F6         mov     esi, ecx
.text:000055571ADA47F8         mov     edi, 0
.text:000055571ADA47FD         call    a1_le_a3_lt_a2_555555558712
.text:000055571ADA4802         xor     eax, 1
.text:000055571ADA4805         test    al, al
.text:000055571ADA4807         jz      short loc_55571ADA483B
.text:000055571ADA4809         lea     rsi, aInvalidOffsetD ; "Invalid offset detected in LD"
.text:000055571ADA4810         lea     rdi, _ZSt5wcout ; std::wcout
.text:000055571ADA4817         call    __ZStlsIwSt11char_traitsIwEERSt13basic_ostreamIT_T0_ES6_PKc ; std::operator<<<wchar_t,std::char_traits<wchar_t>>(std::basic_ostream<wchar_t,std::char_traits<wchar_t>> &,char const*)
.text:000055571ADA481C         mov     rdx, rax
.text:000055571ADA481F         mov     rax, cs:_ZSt4endlIwSt11char_traitsIwEERSt13basic_ostreamIT_T0_ES6__ptr
.text:000055571ADA4826         mov     rsi, rax
.text:000055571ADA4829         mov     rdi, rdx
.text:000055571ADA482C         call    __ZNSt13basic_ostreamIwSt11char_traitsIwEElsEPFRS2_S3_E ; std::basic_ostream<wchar_t,std::char_traits<wchar_t>>::operator<<(std::basic_ostream<wchar_t,std::char_traits<wchar_t>>& (*)(std::basic_ostream<wchar_t,std::char_traits<wchar_t>>&))
.text:000055571ADA4831         mov     edi, 1          ; status
.text:000055571ADA4836         call    _exit
.text:000055571ADA483B ; ---------------------------------------------------------------------------
.text:000055571ADA483B
.text:000055571ADA483B loc_55571ADA483B:               ; CODE XREF: gptr_mem_read_f_555555558744+C3j
.text:000055571ADA483B         mov     rax, [rbp+var_8]
.text:000055571ADA483F         mov     rdx, [rax+8]    ; rdx = *(gptr[arg1] + 8)
.text:000055571ADA4843         mov     eax, [rbp+var_18]
.text:000055571ADA4846         cdqe
.text:000055571ADA4848         add     rax, rdx
.text:000055571ADA484B         movzx   eax, byte ptr [rax] ; read: *(gptr[arg1] + 8 + arg2)
.text:000055571ADA484E         leave
.text:000055571ADA484F         retn
.text:000055571ADA484F gptr_mem_read_f_555555558744 endp
```

```assembly
.text:000055571ADA4850 gptr_mem_write_10_555555558850 proc near
.text:000055571ADA4850                                         ; CODE XREF: vm_main_555555558DB8+7F3p
.text:000055571ADA4850
.text:000055571ADA4850 var_1C          = byte ptr -1Ch
.text:000055571ADA4850 var_18          = dword ptr -18h
.text:000055571ADA4850 var_14          = dword ptr -14h
.text:000055571ADA4850 gptr_ptr_8      = qword ptr -8
.text:000055571ADA4850
.text:000055571ADA4850                 push    rbp
.text:000055571ADA4851                 mov     rbp, rsp
.text:000055571ADA4854                 sub     rsp, 20h
.text:000055571ADA4858                 mov     [rbp+var_14], edi
.text:000055571ADA485B                 mov     [rbp+var_18], esi
.text:000055571ADA485E                 mov     eax, edx
.text:000055571ADA4860                 mov     [rbp+var_1C], al
.text:000055571ADA4863                 mov     eax, [rbp+var_14]
.text:000055571ADA4866                 mov     edx, eax
.text:000055571ADA4868                 mov     esi, 0Ah
.text:000055571ADA486D                 mov     edi, 0
.text:000055571ADA4872                 call    a1_le_a3_lt_a2_555555558712
.text:000055571ADA4877                 xor     eax, 1
.text:000055571ADA487A                 test    al, al
.text:000055571ADA487C                 jnz     short loc_55571ADA489B
.text:000055571ADA487E                 mov     eax, [rbp+var_14]
.text:000055571ADA4881                 cdqe
.text:000055571ADA4883                 lea     rdx, ds:0[rax*8]
.text:000055571ADA488B                 lea     rax, gptr_555555762200
.text:000055571ADA4892                 mov     rax, [rdx+rax]
.text:000055571ADA4896                 test    rax, rax
.text:000055571ADA4899                 jnz     short loc_55571ADA48A2
.text:000055571ADA489B
.text:000055571ADA489B loc_55571ADA489B:                       ; CODE XREF: gptr_mem_write_10_555555558850+2Cj
.text:000055571ADA489B                 mov     eax, 1
.text:000055571ADA48A0                 jmp     short loc_55571ADA48A7
.text:000055571ADA48A2 ; ---------------------------------------------------------------------------
.text:000055571ADA48A2
.text:000055571ADA48A2 loc_55571ADA48A2:                       ; CODE XREF: gptr_mem_write_10_555555558850+49j
.text:000055571ADA48A2                 mov     eax, 0
.text:000055571ADA48A7
.text:000055571ADA48A7 loc_55571ADA48A7:                       ; CODE XREF: gptr_mem_write_10_555555558850+50j
.text:000055571ADA48A7                 test    al, al
.text:000055571ADA48A9                 jz      short loc_55571ADA48DD
.text:000055571ADA48AB                 lea     rsi, aInvalidGptrInd ; "Invalid gptr index"
.text:000055571ADA48B2                 lea     rdi, _ZSt5wcout ; std::wcout
.text:000055571ADA48B9                 call    __ZStlsIwSt11char_traitsIwEERSt13basic_ostreamIT_T0_ES6_PKc ; std::operator<<<wchar_t,std::char_traits<wchar_t>>(std::basic_ostream<wchar_t,std::char_traits<wchar_t>> &,char const*)
.text:000055571ADA48BE                 mov     rdx, rax
.text:000055571ADA48C1                 mov     rax, cs:_ZSt4endlIwSt11char_traitsIwEERSt13basic_ostreamIT_T0_ES6__ptr
.text:000055571ADA48C8                 mov     rsi, rax
.text:000055571ADA48CB                 mov     rdi, rdx
.text:000055571ADA48CE                 call    __ZNSt13basic_ostreamIwSt11char_traitsIwEElsEPFRS2_S3_E ; std::basic_ostream<wchar_t,std::char_traits<wchar_t>>::operator<<(std::basic_ostream<wchar_t,std::char_traits<wchar_t>>& (*)(std::basic_ostream<wchar_t,std::char_traits<wchar_t>>&))
.text:000055571ADA48D3                 mov     edi, 1          ; status
.text:000055571ADA48D8                 call    _exit
.text:000055571ADA48DD ; ---------------------------------------------------------------------------
.text:000055571ADA48DD
.text:000055571ADA48DD loc_55571ADA48DD:                       ; CODE XREF: gptr_mem_write_10_555555558850+59j
.text:000055571ADA48DD                 mov     eax, [rbp+var_14]
.text:000055571ADA48E0                 cdqe
.text:000055571ADA48E2                 lea     rdx, ds:0[rax*8]
.text:000055571ADA48EA                 lea     rax, gptr_555555762200
.text:000055571ADA48F1                 mov     rax, [rdx+rax]
.text:000055571ADA48F5                 mov     [rbp+gptr_ptr_8], rax
.text:000055571ADA48F9                 mov     rax, [rbp+gptr_ptr_8]
.text:000055571ADA48FD                 mov     rax, [rax]      ; rax = actual value
.text:000055571ADA4900                 mov     ecx, eax
.text:000055571ADA4902                 mov     eax, [rbp+var_18]
.text:000055571ADA4905                 mov     edx, eax
.text:000055571ADA4907                 mov     esi, ecx
.text:000055571ADA4909                 mov     edi, 0
.text:000055571ADA490E                 call    a1_le_a3_lt_a2_555555558712 ; 0 <= arg2 < *gptr[arg1]
.text:000055571ADA4913                 xor     eax, 1
.text:000055571ADA4916                 test    al, al
.text:000055571ADA4918                 jz      short 55571ADA494Ch
.text:000055571ADA491A                 lea     rsi, aInvalidOffse_0 ; "Invalid offset detected in ST"
.text:000055571ADA4921                 lea     rdi, _ZSt5wcout ; std::wcout
.text:000055571ADA4928                 call    __ZStlsIwSt11char_traitsIwEERSt13basic_ostreamIT_T0_ES6_PKc ; std::operator<<<wchar_t,std::char_traits<wchar_t>>(std::basic_ostream<wchar_t,std::char_traits<wchar_t>> &,char const*)
.text:000055571ADA492D                 mov     rdx, rax
.text:000055571ADA4930                 mov     rax, cs:_ZSt4endlIwSt11char_traitsIwEERSt13basic_ostreamIT_T0_ES6__ptr
.text:000055571ADA4937                 mov     rsi, rax
.text:000055571ADA493A                 mov     rdi, rdx
.text:000055571ADA493D                 call    __ZNSt13basic_ostreamIwSt11char_traitsIwEElsEPFRS2_S3_E ; std::basic_ostream<wchar_t,std::char_traits<wchar_t>>::operator<<(std::basic_ostream<wchar_t,std::char_traits<wchar_t>>& (*)(std::basic_ostream<wchar_t,std::char_traits<wchar_t>>&))
.text:000055571ADA4942                 mov     edi, 1          ; status
.text:000055571ADA4947                 call    _exit
.text:000055571ADA494C ; ---------------------------------------------------------------------------
.text:000055571ADA494C                 mov     rax, [rbp+gptr_ptr_8]
.text:000055571ADA494C                                         ; CODE XREF: gptr_mem_write_10_555555558850+C8j
.text:000055571ADA4950                 mov     rdx, [rax+8]    ; rdx = *(gptr[arg1] + 8)
.text:000055571ADA4954                 mov     eax, [rbp+var_18]
.text:000055571ADA4957                 cdqe
.text:000055571ADA4959                 add     rdx, rax        ; *(gptr[arg1] + 8) + arg2
.text:000055571ADA495C                 movzx   eax, [rbp+var_1C]
.text:000055571ADA4960                 mov     [rdx], al       ; *(gptr[arg1] + 8 + arg2) = arg3
.text:000055571ADA4962                 nop
.text:000055571ADA4963                 leave
.text:000055571ADA4964                 retn
.text:000055571ADA4964 gptr_mem_write_10_555555558850 endp
```

Now that we have all the pieces, we can write our [disassembler](./emojivm_disassembler.py) to 
convert these emojis into a nice stack-machine assembly listing.

Since this is a stack machine assembly, there are way too many instructions. To make analysis
easier it's good to have an emulated stack next to each instruction to understand what's going
on. However, to have a precise stack we have to emulated the program and not just disassemble it.
This is not a big problem as all we want is to understand the code.

### Cracking the encryption

To make analysis of the emulated program simple, we get rid of the `nops` and the **constant
calculations**. For example:
```assembly
1CBCh: ⏬ 😆	push 7                      [07
1CBEh: ⏬ 😍	push 10                     [07 0a]
1CC0h: ❌  	mul                         [46]   
1CC1h: ⏬ 😍	push 10                     [46 0a]
1CC3h: ❌  	mul                         [2bc]  
1CC4h: ⏬ 😍	push 10                     [2bc 0a]
1CC6h: ❌  	mul                         [1b58]   
1CC7h: ⏬ 😁	push 1                      [1b58 01] 
1CC9h: ⏬ 😍	push 10                     [1b58 01 0a]   
1CCBh: ❌  	mul                         [1b58 0a]      
1CCCh: ⏬ 😍	push 10                     [1b58 0a 0a]   
1CCEh: ❌  	mul                         [1b58 64]      
1CCFh: ⏬ 😆	push 7                      [1b58 64 07]   
1CD1h: ⏬ 😍	push 10                     [1b58 64 07 0a]
1CD3h: ❌  	mul                         [1b58 64 46]   
1CD4h: ⏬ 😆	push 7                      [1b58 64 46 07]
1CD6h: ➕  	add                         [1b58 64 4d]   
1CD7h: ➕  	add                         [1b58 b1]      
1CD8h: ➕  	add                         [1c09]
1CD9h: 🚀  	jump 1C09h                  []
```

In this example all these instructions are used to build number `0x1c09`. So we can merge them
into a single one.


The biggest portion of the program is to print the banner. Then it asks for the key. The it creates
4 global arrays. as follows:
```
	gptr_0 --> buffer to print to stdout (allocated at the beginning)
    gptr_1 --> key
    gptr_2 --> const
    gptr_3 --> encrypted key
    gtpr_4 --> const
```

Then we get the length of the key which should be `24` characters. Then check if it's in
the form `xxxx-yyyy-zzzz-wwww-qqqq`:

``` assembly
; ---------------------------------------------------------------------------------------
1B8Eh: ⏬ 😀	push 0                      [00]                      ; 
1B90h: ⏬ 😄	push 5                      [00 05]                   ; 
1B91h: 📤  	mem read: 1 = *gptr[5][0]   [01]                      ; 
1B93h: ⏬ 😂	push 2                      [01 02]                   ; 
1B95h: ⏬ 😍	push 10                     [01 02 0a]                ; 
1B96h: ❌  	mul                         [01 14]                   ; 
1B98h: ⏬ 😜	push 4                      [01 14 04]                ; 
1B99h: ➕  	add                         [01 18]                   ; 
1B9Ah: 💯  	cmp: 24 == 1 ?              [00]                      ; key must be 24 characters
1B9Ch: ⏬ 😉	push 8                      [00 08]                   ; 
...
1BB7h: ➕  	add                         [00 2166]                 ; 
1BB8h: 🈚  	jz (0) 2166h                []                        ; if not, go to bad boy messsage
1BC9h: ⏬ 😀	push 0                      [00]                      ; 
1BCBh: ⏬ 😁	push 1                      [00 01]                   ; 
1BCDh: ⏬ 😄	push 5                      [00 01 05]                ; 
1BCEh: 📥  	mem write: *gptr[5][1] = 0  []                        ; gptr[5][1] = 0

1BD0h: ⏬ 😄	push 5                      [05]                      ; 
1BD2h: ⏬ 😁	push 1                      [05 01]                   ; 
1BD4h: ⏬ 😄	push 5                      [05 01 05]                ; 
1BD5h: 📤  	mem read: 0 = *gptr[5][1]   [05 00]                   ; 
1BD7h: ⏬ 😁	push 1                      [05 00 01]                ;
1BD8h: ➕  	add                         [05 01]                   ; 
1BD9h: ❓  	modulo                      [00]                      ;
1BDBh: ⏬ 😀	push 0                      [00 00]                   ; 
1BDCh: 💯  	cmp: 0 == 0 ?               [01]                      ; (gptr[5][1] + 1) % 5 == 0 ? 
1BDEh: ⏬ 😆	push 7                      [01 07]                   ; 
...
1BF9h: ➕  	add                         [01 1c7e]                 ; 
1BFAh: 🈶  	jnz (1) 1C7Eh               []                        ; if yes goto CODE_2

1C0Bh: ⏬ 😁	push 1                      [01]                      ; if not, move on
1C0Dh: ⏬ 😄	push 5                      [01 05]                   ; 
1C0Eh: 📤  	mem read: 0 = *gptr[5][1]   [00]                      ; 
1C10h: ⏬ 😁	push 1                      [00 01]                   ; 
1C11h: ➕  	add                         [01]                      ; 
1C13h: ⏬ 😁	push 1                      [01 01]                   ; 
1C15h: ⏬ 😄	push 5                      [01 01 05]                ; 
1C16h: 📥  	mem write: *gptr[5][1] = 1  []                        ; iter ++;
1C18h: ⏬ 😂	push 2                      [02]                      ; 
1C1Ah: ⏬ 😍	push 10                     [02 0a]                   ; 
1C1Bh: ❌  	mul                         [14]                      ; 
1C1Dh: ⏬ 😜	push 4                      [14 04]                   ; 
1C1Eh: ➕  	add                         [18]                      ; 
1C20h: ⏬ 😁	push 1                      [18 01]                   ; 
1C22h: ⏬ 😄	push 5                      [18 01 05]                ; 
1C23h: 📤  	mem read: 1 = *gptr[5][1]   [18 01]                   ; 
1C24h: 💀  	cmp: 1 < 24 ?               [01]                      ; iter < 24 ?
1C26h: ⏬ 😆	push 7                      [01 07]                   ; 
...
1C41h: ➕  	add                         [01 1bce]                 ; 
1C42h: 🈶  	jnz (1) 1BCEh               []                        ; if yes loop back
1C53h: ⏬ 😆	push 7                      [07]                      ; 
1C6Eh: ➕  	add                         [1ce9]                    ; 
1C6Fh: 🚀  	jump 1CE9h                  []                        ; else break

CODE_2:
1C80h: ⏬ 😜	push 4                      [04]                      ; 
1C82h: ⏬ 😍	push 10                     [04 0a]                   ; 
1C83h: ❌  	mul                         [28]                      ; 
1C85h: ⏬ 😄	push 5                      [28 05]                   ; 
1C86h: ➕  	add                         [2d]                      ; const: 45 = '-'
1C88h: ⏬ 😁	push 1                      [2d 01]                   ; 
1C8Ah: ⏬ 😄	push 5                      [2d 01 05]                ; 
1C8Bh: 📤  	mem read: 1 = *gptr[5][1]   [2d 01]                   ; iter <--- gptr[5][1] 
1C8Dh: ⏬ 😁	push 1                      [2d 01 01]                ; 
1C8Eh: 📤  	mem read: 0 = *gptr[1][1]   [2d 00]                   ;
1C8Fh: 💯  	cmp: 0 == 45 ?              [00]                      ; key[iter] == '-' ? 
1C91h: ⏬ 😉	push 8                      [00 08]                   ; 
...
1CACh: ➕  	add                         [00 2166]                 ; 
1CADh: 🈚  	jz (0) 2166h                []                        ; if not go to bad boy messsage
1CBEh: ⏬ 😆	push 7                      [07]                      ; 
1CD9h: ➕  	add                         [1c09]                    ; 
1CDAh: 🚀  	jump 1C09h                  []                        ; 
```

If key has the right format, then we do some mutations to it and get generate `gptr_3`:
```assembly
1CF7h: 📤  	mem read: 0 = *gptr[5][1]   [04 00]                   ;
1CF8h: ❓  	modulo                      [00]                      ;
1CFAh: ⏬ 😂	push 2                      [00 02]                   ; 
1CFCh: ⏬ 😄	push 5                      [00 02 05]                ; 
1CFDh: 📥  	mem write: *gptr[5][2] = 0  []                        ; gptr[5][2] = iter / 4  
1CFFh: ⏬ 😂	push 2                      [02]                      ; 
1D01h: ⏬ 😄	push 5                      [02 05]                   ; 
1D02h: 📤  	mem read: 0 = *gptr[5][2]   [00]                      ; 
1D04h: ⏬ 😀	push 0                      [00 00]                   ; 
1D05h: 💯  	cmp: 0 == 0 ?               [01]                      ; iter % 4 == 0 ? 
...
1D23h: 🈶  	jnz (1) 1E46h               []                        ; 
...
1D3Ah: 💯  	cmp: 1 == 0 ?               [00]                      ; iter % 4 == 1 ?
...
1D58h: 🈶  	jnz (0) 1E8Ch               []                        ; 
...
1D6Fh: 💯  	cmp: 2 == 0 ?               [00]                      ; iter % 4 == 2 ? 
...
1D8Dh: 🈶  	jnz (0) 1ECFh               []                        ; 
...
1DA4h: 💯  	cmp: 3 == 0 ?               [00]                      ; iter % 4 == 3 ? 
...
1DC2h: 🈶  	jnz (0) 1F21h               []                        ; 
...
1DDEh: 📥  	mem write: *gptr[5][1] = 1  []                        ; iter ++;
1DECh: 💀  	cmp: 1 < 24 ?               [01]                      ; if iter < 24 loop back
...
1E37h: 🚀  	jump 1F8Bh                  []                        ; else break
; ---------------------------------------------------------------------------------------
; Case #0: iter / 4 = 0
; ---------------------------------------------------------------------------------------
1E48h: ⏬ 😁	push 1                      [01]                      ; 
1E4Ah: ⏬ 😄	push 5                      [01 05]                   ; 
1E4Bh: 📤  	mem read: 1 = *gptr[5][1]   [01]                      ; 
1E4Dh: ⏬ 😁	push 1                      [01 01]                   ; 
1E4Eh: 📤  	mem read: 0 = *gptr[1][1]   [00]                      ; read key[iter]
1E50h: ⏬ 🤣	push 3                      [00 03]                   ; 
1E52h: ⏬ 😍	push 10                     [00 03 0a]                ; 
1E53h: ❌  	mul                         [00 1e]                   ; 
1E55h: ⏬ 😀	push 0                      [00 1e 00]                ; 
1E56h: ➕  	add                         [00 1e]                   ; 
1E57h: ➕  	add                         [1e]                      ; key[iter] + 0x1e
1E59h: ⏬ 😁	push 1                      [1e 01]                   ; 
1E5Bh: ⏬ 😄	push 5                      [1e 01 05]                ; 
1E5Ch: 📤  	mem read: 1 = *gptr[5][1]   [1e 01]                   ; 
1E5Eh: ⏬ 🤣	push 3                      [1e 01 03]                ; 
1E5Fh: 📥  	mem write: *gptr[3][1] = 30 []                        ; gptr[3][iter] = key[iter] + 30
1E61h: ⏬ 😆	push 7                      [07]                      ;
...
1E7Ch: ➕  	add                         [1dd1]                    ;
1E7Dh: 🚀  	jump 1DD1h                  []                        ; [18 05 1d 10 42 09 4a 24 00 5b 08 17 40 00 72 30 09 6c 56 40 09 5b 05 1a 00 00 00 00 00 00] [00 1e 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00]
; ---------------------------------------------------------------------------------------
; Case #1: iter / 4 = 1
; ---------------------------------------------------------------------------------------
1E8Eh: ⏬ 😉	push 8                      [08]                      ;
1E90h: ⏬ 😁	push 1                      [08 01]                   ; 
1E92h: ⏬ 😄	push 5                      [08 01 05]                ; 
1E93h: 📤  	mem read: 1 = *gptr[5][1]   [08 01]                   ; 
1E95h: ⏬ 😁	push 1                      [08 01 01]                ; 
1E96h: 📤  	mem read: 0 = *gptr[1][1]   [08 00]                   ; 
1E97h: ➖  	sub                         [-8]                      ; 
1E99h: ⏬ 😆	push 7                      [-8 07]                   ; 
1E9Ah: ❎  	xor                         [-1]                      ; 
1E9Ch: ⏬ 😁	push 1                      [-1 01]                   ; 
1E9Eh: ⏬ 😄	push 5                      [-1 01 05]                ; 
1E9Fh: 📤  	mem read: 1 = *gptr[5][1]   [-1 01]                   ; 
1EA1h: ⏬ 🤣	push 3                      [-1 01 03]                ; 
1EA2h: 📥  	mem write: *gptr[3][1] = -1 []                        ; gptr[3][iter] = (key[iter] - 8) ^ 7
1EA4h: ⏬ 😆	push 7                      [07]                      ;
...
1EBFh: ➕  	add                         [1dd1]                    ; 
1EC0h: 🚀  	jump 1DD1h                  []                        ; [18 05 1d 10 42 09 4a 24 00 5b 08 17 40 00 72 30 09 6c 56 40 09 5b 05 1a 00 00 00 00 00 00] [00 -1 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00]
; ---------------------------------------------------------------------------------------
; Case #2: iter / 4 = 2
; ---------------------------------------------------------------------------------------
1ED1h: ⏬ 😜	push 4                      [04]                      ; 
1ED3h: ⏬ 😁	push 1                      [04 01]                   ; 
1ED5h: ⏬ 😄	push 5                      [04 01 05]                ; 
1ED6h: 📤  	mem read: 1 = *gptr[5][1]   [04 01]                   ; 
1ED8h: ⏬ 😁	push 1                      [04 01 01]                ; 
1ED9h: 📤  	mem read: 0 = *gptr[1][1]   [04 00]                   ; key[iter]
1EDBh: ⏬ 😜	push 4                      [04 00 04]                ; 
1EDDh: ⏬ 😍	push 10                     [04 00 04 0a]             ; 
1EDEh: ❌  	mul                         [04 00 28]                ; 
1EE0h: ⏬ 😜	push 4                      [04 00 28 04]             ; 
1EE1h: ➕  	add                         [04 00 2c]                ; 
1EE2h: ➕  	add                         [04 2c]                   ; key[iter] + 0x2c
1EE4h: ⏬ 😅	push 6                      [04 2c 06]                ; 
1EE6h: ⏬ 😍	push 10                     [04 2c 06 0a]             ;
1EE7h: ❌  	mul                         [04 2c 3c]                ; 
1EE9h: ⏬ 😉	push 8                      [04 2c 3c 08]             ; 
1EEAh: ➕  	add                         [04 2c 44]                ; 
1EEBh: ❎  	xor                         [04 68]                   ; (key[iter] + 0x2c) ^ 0x44 
1EECh: ➖  	sub                         [64]                      ; ((key[iter] + 0x2c) ^ 0x44) - 4
1EEEh: ⏬ 😁	push 1                      [64 01]                   ; 
1EF0h: ⏬ 😄	push 5                      [64 01 05]                ; 
1EF1h: 📤  	mem read: 1 = *gptr[5][1]   [64 01]                   ; 
1EF3h: ⏬ 🤣	push 3                      [64 01 03]                ; 
1EF4h: 📥  	mem write: *gptr[3][1] = 100[]                        ; gptr[3][iter] = ((key[iter] + 0x2c) ^ 0x44) - 4
1EF6h: ⏬ 😆	push 7                      [07]                      ;
...
1F11h: ➕  	add                         [1dd1]                    ;
1F12h: 🚀  	jump 1DD1h                  []                        ; [18 05 1d 10 42 09 4a 24 00 5b 08 17 40 00 72 30 09 6c 56 40 09 5b 05 1a 00 00 00 00 00 00] [00 64 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00]
; ---------------------------------------------------------------------------------------
; Case #3: iter / 4 = 3
; ---------------------------------------------------------------------------------------
1F23h: ⏬ 😁	push 1                      [01]                      ; 
1F25h: ⏬ 😄	push 5                      [01 05]                   ; 
1F26h: 📤  	mem read: 1 = *gptr[5][1]   [01]                      ; 
1F28h: ⏬ 😁	push 1                      [01 01]                   ; 
1F29h: 📤  	mem read: 0 = *gptr[1][1]   [00]                      ; key[iter]
1F2Bh: ⏬ 😁	push 1                      [00 01]                   ; 
1F2Dh: ⏬ 😍	push 10                     [00 01 0a]                ; 
1F2Eh: ❌  	mul                         [00 0a]                   ; 
1F30h: ⏬ 😍	push 10                     [00 0a 0a]                ; 
1F31h: ❌  	mul                         [00 64]                   ; 
1F33h: ⏬ 😀	push 0                      [00 64 00]                ; 
1F35h: ⏬ 😍	push 10                     [00 64 00 0a]             ; 
1F36h: ❌  	mul                         [00 64 00]                ; 
1F38h: ⏬ 😁	push 1                      [00 64 00 01]             ; 
1F39h: ➕  	add                         [00 64 01]                ; 
1F3Ah: ➕  	add                         [00 65]                   ; 
1F3Bh: ❎  	xor                         [65]                      ; key[iter] ^ 0x65
1F3Dh: ⏬ 😁	push 1                      [65 01]                   ; 
1F3Fh: ⏬ 😍	push 10                     [65 01 0a]                ; 
1F40h: ❌  	mul                         [65 0a]                   ; 
1F42h: ⏬ 😍	push 10                     [65 0a 0a]                ; 
1F43h: ❌  	mul                         [65 64]                   ; 
1F45h: ⏬ 😆	push 7                      [65 64 07]                ; 
1F47h: ⏬ 😍	push 10                     [65 64 07 0a]             ; 
1F48h: ❌  	mul                         [65 64 46]                ; 
1F4Ah: ⏬ 😂	push 2                      [65 64 46 02]             ; 
1F4Bh: ➕  	add                         [65 64 48]                ; 
1F4Ch: ➕  	add                         [65 ac]                   ; 
1F4Eh: ⏬ 😂	push 2                      [65 ac 02]                ; 
1F50h: ⏬ 😍	push 10                     [65 ac 02 0a]             ; 
1F51h: ❌  	mul                         [65 ac 14]                ; 
1F53h: ⏬ 😀	push 0                      [65 ac 14 00]             ; 
1F54h: ➕  	add                         [65 ac 14]                ; 
1F55h: 👫  	and                         [65 04]                   ;
1F56h: ❎  	xor                         [61]                      ; key[iter] ^ 0x61  
1F58h: ⏬ 😁	push 1                      [61 01]                   ; 
1F5Ah: ⏬ 😄	push 5                      [61 01 05]                ; 
1F5Bh: 📤  	mem read: 1 = *gptr[5][1]   [61 01]                   ; 
1F5Dh: ⏬ 🤣	push 3                      [61 01 03]                ; 
1F5Eh: 📥  	mem write: *gptr[3][1] = 97 []                        ; gptr[3][iter] = key[iter] ^ 0x61
1F60h: ⏬ 😆	push 7                      [07]                      ;
...
1F7Bh: ➕  	add                         [1dd1]                    ;
1F7Ch: 🚀  	jump 1DD1h                  []                        ; [18 05 1d 10 42 09 4a 24 00 5b 08 17 40 00 72 30 09 6c 56 40 09 5b 05 1a 00 00 00 00 00 00] [00 61 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00]
```

Finally we check if `gptr_3` is equal to `gptr_4`. And if so, we XOR the `key` with `gptr_2`.
We can rewrite the algorithm in python:
```python
 	# Original algorithm
    # Key must be in the form: xxxx-yyyy-zzzz-wwww-qqqq

    key = 'xxxx-yyyy-zzzz-wwww-qqqq'

    for i in range(key):
          if i % 4 == 0: gptr_3[i] = key[i] + 0x1e
        elif i % 4 == 1: gptr_3[i] = (key[i] - 8) ^ 7
        elif i % 4 == 2: gptr_3[i] = ((key[i] + 0x2c) ^ 0x44) - 4
        elif i % 4 == 3: gptr_3[i] = key[i] ^ 4


    # At the end gptr_3 must be equal with gptr_4
    # If yes, gptr_2 is XOR-ed with the key
```

Reversing the algorithm is trivial. [./emojivm_crack.py](./emojivm_crack.py) applies
the reverse algorithm to find the key and the flag:
```
ispo@nogirl:~/ctf/hitcon_ctf_2019/emojivm_reverse$ ./emojivm_crack.py 
Recorvered key:
    [112, 108, 105, 115, 45, 103, 49, 118, 51, 45, 109, 101, 51, 51, 45, 116, 104, 51, 101, 45, 102, 49, 52, 103]
    ['p', 'l', 'i', 's', '-', 'g', '1', 'v', '3', '-', 'm', 'e', '3', '3', '-', 't', 'h', '3', 'e', '-', 'f', '1', '4', 'g']
    plis-g1v3-me33-th3e-f14g
Recovered flag (gptr_2):
    [104, 105, 116, 99, 111, 110, 123, 82, 51, 118, 101, 114, 115, 51, 95, 68, 97, 95, 51, 109, 111, 106, 49, 125, 0]
    ['h', 'i', 't', 'c', 'o', 'n', '{', 'R', '3', 'v', 'e', 'r', 's', '3', '_', 'D', 'a', '_', '3', 'm', 'o', 'j', '1', '}', '\x00']
    hitcon{R3vers3_Da_3moj1}
```
