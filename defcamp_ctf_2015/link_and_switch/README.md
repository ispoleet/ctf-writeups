## D-CTF 2015 - Link & Switch (Reversing 200)
##### 02/10 - 04/10/2015 (36hr)
___
### Solution

We'll use IDA pro for this challenge. First of all let's get rid of anti debugging protections:
```assembly
		.text:000000000040084A         push    rbp
		.text:000000000040084B         mov     rbp, rsp
		.text:000000000040084E         mov     edi, offset name                  ; "LD_PRELOAD"
		.text:0000000000400853         call    _getenv
		.text:0000000000400858         test    rax, rax
		.text:000000000040085B         jz      short loc_40085F
		.text:000000000040085D
		.text:000000000040085D loc_40085D:
		.text:000000000040085D         jmp     short loc_40085D
```
The first one checks if LD_PRELOAD is used.	If so, program gets trapped in an infinity loop.
The second is the classic ptrace trick:
```assembly
	.text:000000000040085F loc_40085F:
	.text:000000000040085F         mov     ecx, 0
	.text:0000000000400864         mov     edx, 0
	.text:0000000000400869         mov     esi, 0
	.text:000000000040086E         mov     edi, 0                            ; request
	.text:0000000000400873         mov     eax, 0
	.text:0000000000400878         call    _ptrace
	.text:000000000040087D         test    rax, rax
	.text:0000000000400880         jns     short loc_400884                  ; TOGGLE SF to 0
	.text:0000000000400882
	.text:0000000000400882 loc_400882:
	.text:0000000000400882         jmp     short loc_400882
```

All we have to do is to set a BP to 0x400880 and once we hit it, toggle value of SF and then 
continue execution.

in main() there's code that generates a single linked list:
```assembly
	.text:00000000004008AD         mov     edi, 10h                          ; size
	.text:00000000004008B2         call    _malloc
	.text:00000000004008B7         mov     [rbp+ptr_18], rax                 ; v18 = malloc(16)
	.text:00000000004008BB         mov     rax, [rbp+ptr_18]
	.text:00000000004008BF         mov     edx, [rbp+i_1C]
	.text:00000000004008C2         mov     [rax], edx                        ; v18[0] = i
	.text:00000000004008C4         mov     rax, [rbp+ptr_18]
	.text:00000000004008C8         mov     eax, [rax]
	.text:00000000004008CA         add     eax, 6Dh
	.text:00000000004008CD         mov     edx, eax                          ; edx = v18[0] + 0x6d
	.text:00000000004008CF         mov     rax, [rbp+ptr_18]
	.text:00000000004008D3         mov     [rax+4], dl                       ; v18[4] = v18[0] + 0x6d
	.text:00000000004008D6         mov     rdx, cs:LIST_HEAD_601080
	.text:00000000004008DD         mov     rax, [rbp+ptr_18]
	.text:00000000004008E1         mov     [rax+8], rdx                      ; v18[8] = HEAD
	.text:00000000004008E5         mov     rax, [rbp+ptr_18]
	.text:00000000004008E9         mov     cs:LIST_HEAD_601080, rax          ; HEAD = v18
	.text:00000000004008F0         add     [rbp+i_1C], 1                     ; i++
```
Each item in the list has the following structure:
```c
	struct item {
		int   i;
		int   ch;
		item* next;
	};
```
That's our list after initialization: [1, 'n'], [2, 'o'], ... [10, 'w']. Then function 0x40074D
is called to check the password. Password is checked character by character. For each character,
we search for it's index within list and then we compare it against the original's password index.
If they are equal we proceed to the next character. The disassembly is show below (along with comments):

```assembly
.text:000000000040074D
.text:000000000040074D ; =============== S U B R O U T I N E =======================================
.text:000000000040074D
.text:000000000040074D ; Attributes: bp-based frame
.text:000000000040074D
.text:000000000040074D PW_CHECK_40074D proc near                         ; CODE XREF: MAIN_400886+A7
.text:000000000040074D
.text:000000000040074D pwd_58  = qword ptr -58h
.text:000000000040074D i_50    = dword ptr -50h
.text:000000000040074D position_4C= dword ptr -4Ch
.text:000000000040074D head_48 = qword ptr -48h
.text:000000000040074D var_40  = qword ptr -40h
.text:000000000040074D var_38  = qword ptr -38h
.text:000000000040074D var_30  = qword ptr -30h
.text:000000000040074D original_pwd_20= dword ptr -20h
.text:000000000040074D var_1C  = dword ptr -1Ch
.text:000000000040074D var_18  = dword ptr -18h
.text:000000000040074D var_14  = dword ptr -14h
.text:000000000040074D var_10  = dword ptr -10h
.text:000000000040074D var_C   = dword ptr -0Ch
.text:000000000040074D
.text:000000000040074D         push    rbp
.text:000000000040074E         mov     rbp, rsp
.text:0000000000400751         mov     [rbp+pwd_58], rdi                 ; password stored here
.text:0000000000400755         mov     [rbp+head_48], 0
.text:000000000040075D         mov     [rbp+var_40], 0
.text:0000000000400765         mov     [rbp+var_38], 0
.text:000000000040076D         mov     [rbp+var_30], 0
.text:0000000000400775         mov     [rbp+i_50], 0
.text:000000000040077C         mov     [rbp+original_pwd_20], 5          ; (that's the original password) 5 --> 'r'
.text:0000000000400783         mov     [rbp+var_1C], 2                   ; 2 --> 'o'
.text:000000000040078A         mov     [rbp+var_18], 7                   ; 7 --> 't'
.text:0000000000400791         mov     [rbp+var_14], 2                   ; 2 --> 'o'
.text:0000000000400798         mov     [rbp+var_10], 5                   ; 5 --> 'r'
.text:000000000040079F         mov     [rbp+var_C], 6                    ; 6 --> 's'  Password is: rotors
.text:00000000004007A6         mov     [rbp+i_50], 0
.text:00000000004007AD         jmp     short loc_40080D                  ; check value before enter loop => for loop
.text:00000000004007AF ; ---------------------------------------------------------------------------
.text:00000000004007AF NOTE: Head of list is a convention. You can tread head as tail, and move list backwards.
.text:00000000004007AF It's the same thing.
.text:00000000004007AF
.text:00000000004007AF FIRST_LOOP_4007AF:                                ; CODE XREF: PW_CHECK_40074D+C4
.text:00000000004007AF         mov     rax, cs:LIST_HEAD_601080
.text:00000000004007B6         mov     [rbp+head_48], rax                ; set head to the beginning
.text:00000000004007BA         mov     [rbp+position_4C], 0
.text:00000000004007C1         jmp     short loc_4007F6                  ; as long as we haven't reach end
.text:00000000004007C3 ; ---------------------------------------------------------------------------
.text:00000000004007C3
.text:00000000004007C3 GET_NEXT_ITEM_4007C3:                             ; CODE XREF: PW_CHECK_40074D+A
.text:00000000004007C3         mov     rax, [rbp+head_48]
.text:00000000004007C7         movzx   edx, byte ptr [rax+4]             ; edx = item.ch
.text:00000000004007CB         mov     eax, [rbp+i_50]
.text:00000000004007CE         movsxd  rcx, eax                          ; rcx = i
.text:00000000004007D1         mov     rax, [rbp+pwd_58]
.text:00000000004007D5         add     rax, rcx
.text:00000000004007D8         movzx   eax, byte ptr [rax]               ; eax = pwd[i]
.text:00000000004007DB         cmp     dl, al                            ; item.ch == pwd[i] ?
.text:00000000004007DD         jnz     short NOT_EQUAL_4007EA            ; if not equal, update global and go back
.text:00000000004007DF         mov     rax, [rbp+head_48]
.text:00000000004007E3         mov     eax, [rax]
.text:00000000004007E5         mov     [rbp+position_4C], eax            ; v4c = item.i
.text:00000000004007E8         jmp     short loc_4007FD
.text:00000000004007EA ; ---------------------------------------------------------------------------
.text:00000000004007EA
.text:00000000004007EA NOT_EQUAL_4007EA:                                 ; CODE XREF: PW_CHECK_40074D+90
.text:00000000004007EA         mov     rax, [rbp+head_48]                ; if not equal, update global and go back
.text:00000000004007EE         mov     rax, [rax+8]                      ; rax = item->next
.text:00000000004007F2         mov     [rbp+head_48], rax                ; head = item->next
.text:00000000004007F6
.text:00000000004007F6 loc_4007F6:                                       ; CODE XREF: PW_CHECK_40074D+74
.text:00000000004007F6         cmp     [rbp+head_48], 0                  ; as long as we haven't reach end
.text:00000000004007FB         jnz     short GET_NEXT_ITEM_4007C3
.text:00000000004007FD
.text:00000000004007FD loc_4007FD:                                       ; CODE XREF: PW_CHECK_40074D+9B
.text:00000000004007FD         mov     eax, [rbp+i_50]
.text:0000000000400800         cdqe
.text:0000000000400802         mov     edx, [rbp+position_4C]
.text:0000000000400805         mov     dword ptr [rbp+rax*4+var_40], edx ; v40[i] = item->i
.text:0000000000400809         add     [rbp+i_50], 1                     ; i++
.text:000000000040080D
.text:000000000040080D loc_40080D:                                       ; CODE XREF: PW_CHECK_40074D+60
.text:000000000040080D         cmp     [rbp+i_50], 5
.text:0000000000400811         jle     short FIRST_LOOP_4007AF           ; 6 repetitions
.text:0000000000400813         mov     [rbp+i_50], 0                     ; i = 0
.text:000000000040081A         jmp     short loc_40083D                  ; i <= 5 ?
.text:000000000040081C ; ---------------------------------------------------------------------------
.text:000000000040081C
.text:000000000040081C SECOND_LOOP_40081C:                               ; CODE XREF: PW_CHECK_40074D+F4
.text:000000000040081C         mov     eax, [rbp+i_50]
.text:000000000040081F         cdqe
.text:0000000000400821         mov     edx, dword ptr [rbp+rax*4+var_40] ; edx = v40[i]
.text:0000000000400825         mov     eax, [rbp+i_50]
.text:0000000000400828         cdqe
.text:000000000040082A         mov     eax, [rbp+rax*4+original_pwd_20]  ; compare item index with original
.text:000000000040082E         cmp     edx, eax
.text:0000000000400830         jz      short loc_400839
.text:0000000000400832         mov     eax, 1                            ; wrong password
.text:0000000000400837         jmp     short END_400848
.text:0000000000400839 ; ---------------------------------------------------------------------------
.text:0000000000400839
.text:0000000000400839 loc_400839:                                       ; CODE XREF: PW_CHECK_40074D+E3
.text:0000000000400839         add     [rbp+i_50], 1
.text:000000000040083D
.text:000000000040083D loc_40083D:                                       ; CODE XREF: PW_CHECK_40074D+CD
.text:000000000040083D         cmp     [rbp+i_50], 5                     ; i <= 5 ?
.text:0000000000400841         jle     short SECOND_LOOP_40081C          ; if so look back
.text:0000000000400843         mov     eax, 0                            ; valid password
.text:0000000000400848
.text:0000000000400848 END_400848:                                       ; CODE XREF: PW_CHECK_40074D+EA
.text:0000000000400848         pop     rbp
.text:0000000000400849         retn
.text:0000000000400849 PW_CHECK_40074D endp
.text:0000000000400849
.text:000000000040084A
```

From the above code we can see that the password is the list elements: 5, 2, 7, 2, 5 and 6, which
gives the password:  **rotors**.
___