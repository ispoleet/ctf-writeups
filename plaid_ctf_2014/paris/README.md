## Plaid CTF 2014 - paris (RE 300) (VM crackme)
##### 11-13/04/2014 (48hr)
___

### Description: 
This binary was found on some of our Windows machines. It's got The Plague written all over it.
What secrets are contained inside?
___
### Solution

For this challenge we'll use IDA pro. The program reads the user's password and then it calls
function sub_402066. When program returns it checks if the $esi == 0xdeadbeef and word_4024A3 == 0
and if yes, it shows the good boy message: "Yeah!". So, let's start with sub_402066:

```assembly
.text:00402066 sub_402066 proc near                    ; CODE XREF: .text:00401056p
.text:00402066 xor     ecx, ecx
.text:00402068
.text:00402068 loc_402068:                             ; CODE XREF: sub_402066+39j
.text:00402068 push    offset EH_402376                ; ACCESS_VIOLATION exception handler
.text:0040206D push    large dword ptr fs:0			   ; add handler to PEB
.text:00402074 mov     large fs:0, esp                 ; replace current SEH
.text:0040207B mov     eax, 0
.text:00402080 mov     [eax], eax                      ; generate an exception, jump to 402376
.text:00402082 sub     edi, 1111h
.text:00402088 pop     large dword ptr fs:0
.text:0040208F add     esp, 4
.text:00402092 cmp     byte_4024AA, 1
.text:00402099 jz      locret_401C90                   ; return from function
.text:0040209F jmp     short loc_402068
.text:0040209F sub_402066 endp
```

Here, an exception handler is initialized at 0x402376, and then an ACCESS VIOLATION exception
is generated in order to trigger to exception handler. When exception handler is called the 
3rd argument is a pointer to a CONTEXT struct:

```c
EXCEPTION_DISPOSITION __cdecl _except_handler
(
     struct _EXCEPTION_RECORD *ExceptionRecord,
     void * EstablisherFrame,
     struct _CONTEXT *ContextRecord,
     void * DispatcherContext
);
```

Inside exception handler we have:

```assembly
.text:00402376 EH_402376:                              ; DATA XREF: sub_402066:loc_402068o
.text:00402376 movzx   eax, byte ptr unk_40225E        ; ACCESS_VIOLATION exception handler
.text:0040237D add     eax, offset off_40220E
.text:00402382 mov     eax, [eax]
.text:00402384 add     byte ptr unk_40225E, 4          ; this is an infinity loop
.text:0040238B cmp     byte ptr unk_40225E, 50h
.text:00402392 jl      short loc_40239B
.text:00402394 mov     byte ptr unk_40225E, 0
.text:0040239B
.text:0040239B loc_40239B:                             ; CODE XREF: .text:00402392j
.text:0040239B jmp     eax
```

There is an array of pointers here, and each time the program transfers control to the
next pointer (in cyclic order) in the array. The pointers (we'll call them "functions")
are:
```
0040247C,00402323,0040211E,004020A1,0040241C,004022F2,004022C1,00402290,0040225F,0040239D,
004023FF,004023E2,004020E4,00402450,004023C0,00402196,0040215B,0040234F,004021D4,00402439
```

In each of the above addresses, the representing code is very similar (and this is a 
strong clue that we have a VM crackme):

```assembly
    call 0x401CF0 or 0x401D19 or 0x401D50
    [... instructions ...]
    sub eax, ID_VALUE
    setz al
    jmp 0x401FCA
```

Each of these functions: 0x401CF0, 0x401D19, 0x401D50 starts with a call to 0x401C91:

```assembly
.text:00401C91 COPY_401C91 proc near                   ; CODE XREF: INC_401CF0p
...
.text:00401CEF retn
.text:00401CEF COPY_401C91 endp
```

This function copies some data from one location to another. It looks like a "backup" function.
Code at 0x401FCA, is very similar with 0x401C91:

```assembly
.text:00401FCA RESTORE_COPY_401FCA:                    ; CODE XREF: .text:004020DFj
.text:00401FCA                                         ; .text:00402119j ...
.text:00401FCA mov     edx, [esp+0Ch]                  ; edx = CONTEXT
.text:00401FCE cmp     al, 1
.text:00401FD0 jz      FIN_402467
...
.text:0040202C mov     word_4024A3, ax                 ; (word) 4024A3 = 4024A1
.text:00402032 jmp     FIN_402467
```

At first the value of al is checked, and if it's 0, it performs the inverse job of function
0x401C91. While 0x401C91 copies some data in a new location, 0x401FCA copies the data from the
new location back to the original place. Thus, if value of al is not 1 then the executed code
has no effect. After that, the code at 0x402467 is called:

```assembly
.text:00402467 FIN_402467:                             ; CODE XREF: .text:00401FD0j
.text:00402467                                         ; .text:00402032j
.text:00402467 xor     eax, eax
.text:00402469 add     dword ptr [edx+0B8h], 2         ; increase EIP by 2
.text:00402470 retn                                    ; go back
```
It's time to talk a bit about windows exceptions. When an exception is called, the OS saves
the internal state of the program (registers, etc) in a CONTEXT structure. After the execution
of the exception handler, the OS restores the state of the program using the information from the
CONTEXT structure. Here, edx points to a CONTEXT structure:

```assembly
    00000000 ContextFlags dd ?
    00000004 Dr0 dd ?
    00000008 Dr1 dd ?
    0000000C Dr2 dd ?
    00000010 Dr3 dd ?
    00000014 Dr6 dd ?
    00000018 Dr7 dd ?
    0000001C FloatSave FLOATING_SAVE_AREA ?
    0000008C SegGs dd ?
    00000090 SegFs dd ?
    00000094 SegEs dd ?
    00000098 SegDs dd ?
    0000009C _Edi dd ?
    000000A0 _Esi dd ?
    000000A4 _Ebx dd ?
    000000A8 _Edx dd ?
    000000AC _Ecx dd ?
    000000B0 _Eax dd ?
    000000B4 _Ebp dd ?
    000000B8 _Eip dd ?
    000000BC SegCs dd ?
    000000C0 EFlags dd ?
    000000C4 _Esp dd ?
    000000C8 SegSs dd ?
    000000CC ExtendedRegisters db 512 dup(?)
    000002CC _CONTEXT ends
```
It's easy to see that at offset 0xB8 is the saved eip, which now increased by 2, and always 
transfers control to 0x402082, and if byte at 0x4024AA is not 1, we repeat the same process.

In each step we jump to a different function (of 20 possible). But if at the end the value of
al is not 1 -which means the value of eax is not the same as the ID_VALUE-, then program undo
the changes has made.

It seems that each function tries to do something and if it fails, undo the changes. The value of 
eax in each pointer is calculated at functions: 0x401CF0, 0x401D19 and 0x401D50. Let's decompile
them:
```
i    = WORD(0x4024A7)
prog = BYTE(0x401D8E)

0x401CF0:
	ax  = prog[i] / 8;          
    bx  = (prog[i] & 7) * 2;    
	i++;

0x401D19:	
	cmd = (prog[i]<<8) | prog[i+1]; 
    ax  =   cmd >> 6;           
	bx  = ((cmd >> 3) & 7)*2;   
	cx  =  (cmd & 7)*2;         
	i += 2;
	
0x401D50:
	cmd = (prog[i]<<16) | (prog[i+2]<<8) | (prog[i+1]); 
    ax =  cmd >> 19;            
    bx = (cmd & 7)*2;           
    cx =  cmd & 0xffff;         
	i += 3;
```
	
Everything is clear now. We are dealing with a VM crackme. At first we read an instruction
(may be 1,2 or 3 bytes long), with ax containing the opcode, and bx, cx containing the
operands. Each function (from table of pointers) can emulate 1 instruction. In each step
the command emulated, and if the opcode doesn't match the al is set to 0 and the jump at 
0x401FD0 is not taken, which means that program undo the changes. The executable program
bytes are:
```
0x00, 0x00, 0x00, 0x9A, 0x33, 0x31, 0x9B, 0x00, 0x00, 0x9C, 0x00, 0xFF, 0x9D, 0xFF, 0x00, 0x80,
0xD8, 0x80, 0x47, 0xDF, 0xAF, 0x0F, 0xD7, 0xEF, 0x37, 0x00, 0x80, 0x7E, 0x26, 0xE6, 0x26, 0xEF,
0x4E, 0x26, 0xB7, 0x9E, 0x00, 0x02, 0x26, 0x3F, 0x26, 0x3E, 0x80, 0xF7, 0xDF, 0xC6, 0x26, 0xB7,
0x3E, 0x3F, 0x53, 0x13, 0xFF, 0x0F, 0x00, 0x26, 0xBF, 0x9A, 0x00, 0x01, 0x9E, 0x21, 0xAF, 0x80,
0xD5, 0xDD, 0x12, 0x12, 0xC3, 0x0F, 0xF5, 0xEF, 0x56, 0x00, 0x0F, 0xDD, 0xEF, 0x3F, 0x00, 0x9B,
0x00, 0x00, 0x9A, 0x00, 0x00, 0xA7, 0x9D, 0x4D, 0x5A, 0x0F, 0xEB, 0xEF, 0x65, 0x00, 0x9B, 0x00,
0x00, 0x9A, 0x00, 0x00, 0xA7, 0x9B, 0xAD, 0xDE, 0x9A, 0xEF, 0xBE, 0xA7, 0xA9, 0x2D, 0xF2, 0x6D,
0x2E, 0x34, 0xAA, 0x55, 0x7A, 0xC3, 0x94, 0xCC, 0xA2, 0x11, 0xD8, 0xB9, 0xA5, 0xF0, 0xE2, 0x8C,
0x54, 0xCB, 0x5D, 0x18, 0xD8, 0x79, 0x5F, 0x3A, 0x15, 0x9E, 0xDA, 0xEA, 0xFC, 0x77, 0x2B, 0x91,
0x4F, 0x21, 0x29, 0x26, 0x1F, 0x60, 0x8F, 0xC4, 0xBE, 0x63, 0x87, 0xD8, 0x81, 0x1E, 0x3F, 0x76,
0xE8, 0x61, 0xEB, 0x94, 0xF6, 0xFA, 0x74, 0x47, 0xFB, 0x52, 0xBA, 0x53, 0x7C, 0x59, 0x6F, 0x51,
0x3E, 0xC8, 0xEE, 0x2F, 0x3A, 0x69, 0x80, 0x1A, 0xCF, 0x74, 0x60, 0xCD, 0x0F, 0xC9, 0x72, 0xC7,
0xF9, 0x45, 0xAD, 0x91, 0x45, 0x95, 0x45, 0x14, 0xCF, 0xF5, 0x57, 0x6F, 0x39, 0x5A, 0xD8, 0x3C,
0xDF, 0x96, 0xF0, 0xCE, 0x90, 0xBE, 0x29, 0x8E, 0xFE, 0x67, 0xD7, 0x7B, 0x8D, 0x4F, 0x22, 0xD9,
0x7A, 0x76, 0x47, 0x98, 0x50, 0x4A, 0xF7, 0x47, 0x4C, 0x92, 0x63, 0x44, 0x98, 0xD9, 0x34, 0x2D,
0xF8, 0xC2, 0x95, 0xCA, 0xD4, 0xBC, 0x89, 0xC6, 0x98, 0x64, 0x16, 0xBC, 0xAD, 0xE2, 0x0E, 0xFD,
0xD0, 0x58, 0x6D, 0x75, 0xC9, 0x10, 0xD6, 0x5B, 0x0F, 0x2A, 0xBB, 0xCF, 0x32, 0x3D, 0xB4, 0x4A,
0xFF, 0x36, 0xB5, 0xD2, 0x27, 0x4A, 0x91, 0xB8, 0xA6, 0x0C, 0x33, 0x3A, 0x35, 0xF2, 0x66, 0x39,
0x7F, 0x7A, 0xFB, 0x4B, 0x35, 0x41, 0x1E, 0xC2, 0x50, 0xE1, 0x4F, 0xD5, 0x60, 0xB4, 0x1E, 0x7D,
0xE4, 0x35, 0xDC, 0xFC, 0x3B, 0xA9, 0x78, 0xF5, 0x66, 0xAD, 0xA0, 0x5E, 0x93, 0x17, 0xDB, 0x99,
0x59, 0x61, 0x86, 0x2F, 0x6F, 0x63, 0xF8, 0xF6, 0xEF, 0xFB, 0x94, 0x47, 0x9B, 0x17, 0xD8, 0x5D,
0x08, 0x26, 0x40, 0xE9, 0x1C, 0x73, 0xF5, 0x1A, 0x4D, 0xB4, 0x85, 0x02, 0xE9, 0xCF, 0xCF, 0x14,
0x65, 0xCA, 0x74, 0xE7, 0xF9, 0x9D, 0xB6, 0x1A, 0xC1, 0xA7, 0xF2, 0x94
```

And the the instructions are:
```assembly
0x40247C --> Opcode: 0x0   --> Length: 1 --> nop
0x402323 --> Opcode: 0x201 --> Length: 2 --> mov reg_cx, reg_bx
0x40211E --> Opcode: 0x202 --> Length: 2 --> psw[reg_bx] = reg_cx
0x4020A1 --> Opcode: 0x203 --> Length: 2 --> reg_cx = psw[reg_bx]
0x40241C --> Opcode: 0x13  --> Length: 3 --> mov reg_bx, const_value
0x4022F2 --> Opcode: 0x98  --> Length: 2 --> add reg_cx, reg_bx
0x4022C1 --> Opcode: 0x99  --> Length: 2 --> sub reg_cx, reg_bx
0x402290 --> Opcode: 0x9A  --> Length: 2 --> xor reg_cx, reg_bx
0x40225F --> Opcode: 0x9B  --> Length: 1 --> and reg_cx, reg_bx
0x40239D --> Opcode: 0x9   --> Length: 1 --> shr reg_bx, 8
0x4023FF --> Opcode: 0x15  --> Length: 1 --> nor reg_bx
0x4023E2 --> Opcode: 0x2   --> Length: 1 --> inc reg_bx
0x4020E4 --> Opcode: 0x3F  --> Length: 2 --> cmp reg_bx, reg_cx (ZF =  0x4024ac)
0x402450 --> Opcode: 0x1F  --> Length: 3 --> jmp reg_cx
0x4023C0 --> Opcode: 0x1D  --> Length: 3 --> jz  reg_cx (ZF =  0x4024ac)
0x402196 --> Opcode: 0x7   --> Length: 1 --> push reg_bx
0x40215B --> Opcode: 0x18  --> Length: 1 --> pop reg_bx
0x40234F --> Opcode: 0x1B  --> Length: 1 --> xchg reg_bx (htons() equivalent)
0x4021D4 --> Opcode: 0xA   --> Length: 1 --> DECRYPT
0x402439 --> Opcode: 0x14  --> Length: 1 --> halt (set 0x4024AA to 1)
```

The DECRYPT command is doing the following:
```
	for(int ecx=0x200; ecx>=0; ecx--)
		40168F[ecx--] ^= 401DFA[reg_bx]
```

We know the instructions, but which of them are executed? We can find them by setting a BP at 
0x401FCE and see if al is 1. We also need to set a BP in each function to trace the emulated
instruction. Thus when we are in 0x401FCE we know from which function we came from. The idc
script (paris.idc) can do all the boring job for us ;)

(File em_trace.txt contains the emulated instructions for the correct password)

After that, we can see which virtual instruction are executed. eip from 0 to 12 is the 
initialization phase. Then we have a loop for each password character:

```assembly
#  8	cmd: 4	addr:0x4020a1	eip:15	$0[ccd5] = psw[$6[0]]
#  9	cmd: 2	addr:0x402323	eip:17	mov  $e[8], $0[3847]
# 10	cmd:18	addr:0x40234f	eip:19	xchg $e[3847]
# 11	cmd:11	addr:0x4023ff	eip:20	not  $e[4738]
# 12	cmd:13	addr:0x4020e4	eip:21	cmp  $4[3133], $e[b8c7] -> 0
# 13	cmd:15	addr:0x4023c0	eip:23	jz   $55 -> 0
# 14	cmd: 2	addr:0x402323	eip:26	mov  $c[e3c8], $e[b8c7]
# 15	cmd: 9	addr:0x40225f	eip:28	and  $c[b8c7], $8[ff00]
# 16	cmd: 9	addr:0x40225f	eip:30	and  $e[b8c7], $a[ff]
# 17	cmd:10	addr:0x40239d	eip:32	shr  $c[b800], 8
# 18	cmd: 8	addr:0x402290	eip:33	xor  $e[c7], $c[b8]
# 19	cmd: 5	addr:0x40241c	eip:35	mov  $c[b8], 0x200
# 20	cmd: 6	addr:0x4022f2	eip:38	add  $e[7f], $e[7f]
# 21	cmd: 6	addr:0x4022f2	eip:40	add  $c[200], $e[fe]
# 22	cmd: 4	addr:0x4020a1	eip:42	$e[fe] = psw[$c[2fe]]
# 23	cmd:18	addr:0x40234f	eip:44	xchg $e[e419]
# 24	cmd:17	addr:0x40215b	eip:45	pop  $c[2fe]
# 25	cmd: 8	addr:0x402290	eip:46	xor  $e[19e4], $c[5a4d]
# 26	cmd:16	addr:0x402196	eip:48	push $c[5a4d]
# 27	cmd:16	addr:0x402196	eip:49	push $e[43a9]
# 28	cmd:19	addr:0x4021d4	eip:50	decr $6[0] 		5B  7 22 E6 E0 6A 4C  A  A B3 84  C 39 D3 27 A1 					
# 29	cmd:12	addr:0x4023e2	eip:51	inc  $6[0]
# 30	cmd:14	addr:0x402450	eip:52	jmp  $15
```

Let encr be the "stack type" array at (0x401490+0x200) for push/pop instructions
and H be the array at 0x40168F:

```c
	r_e = xchg((psw[i]*256 + psw[i+1] - 0x1111*18) & 0xffff);   // read 2 chars from password
	r_e = ~((r_e & 0xff00) >> 8) ^ ~(r_e & 0xff);               // convert 2 bytes to 1 byte index
	r_e *= 2;
	r_e = ((H[r_e+1]<<8) + H[r_e]);                             // hash index

	encr[i+1] = r_e ^ encr[i];                                  // XOR with previous encrypted word

	for( j=0; j<0x200; j++) H[j] ^= key[i];                     // XOR hash table
```

Did you notice anything strange here?  
```
#  8	cmd: 4	addr:0x4020a1	eip:15	$0[ccd5] = psw[$6[0]]
#  9	cmd: 2	addr:0x402323	eip:17	mov  $e[8], $0[3847]
```

We read 2 character from password in the #8 instruction, but in the next instruction the 
$0 doesn't contain the value we have just read! To find out why this happens look again at
sub_402066:	.text:00402082 sub     edi, 1111h

The $0 virtual register is stored at CONTEXT + 0x9C address. Thus when we return from exception
handler the registers from CONTEXT are copied back to original registers, and the virtual registers
$0 and $1 are copied to edi. When the next exception is generated the (reduced) value of edi -and 
all the other registers- are saved to the CONTEXT struct. But $0 is now retuced by 0x1111. Thus, 
to go from #4 instruction to #2, we must pass through 18 exceptions, which means the $0 will 
be reduced by 0x1111*18 = 0x13332 = 0x3332 (WORD) -and $1 by 0x1 but it doesn't matter.

After we parse all the character of password the virtual stack contains some values, which they
are compared with values at (0x401490 + 0x100):.
```assembly
#198	cmd: 8	addr:0x402290	eip:55	xor  $e[3133], $e[3133]
#199	cmd: 5	addr:0x40241c	eip:57	mov  $4[3133], 0x100
#200	cmd: 5	addr:0x40241c	eip:60	mov  $c[201c], 0xaf21
#201	cmd: 4	addr:0x4020a1	eip:63	$a[ff] = psw[$4[100]]
#202	cmd:18	addr:0x40234f	eip:65	xchg $a[b2e]
#203	cmd:12	addr:0x4023e2	eip:66	inc  $4[100]
#204	cmd:12	addr:0x4023e2	eip:67	inc  $4[101]
#205	cmd:17	addr:0x40215b	eip:68	pop  $6[8]
#206	cmd:13	addr:0x4020e4	eip:69	cmp  $c[af21], $a[2e0b] -> 0
#207	cmd:15	addr:0x4023c0	eip:71	jz   $86 -> 0
#208	cmd:13	addr:0x4020e4	eip:74	cmp  $6[151b], $a[2e0b] -> 0
#209	cmd:15	addr:0x4023c0	eip:76	jz   $63 -> 0
#210	cmd: 5	addr:0x40241c	eip:79	mov  $6[151b], 0x0
#211	cmd: 5	addr:0x40241c	eip:82	mov  $4[102], 0x0
#212	cmd:20	addr:0x402439	eip:85	halt
```

If all the values of the stack match with the values at 0x401590, then the following code is
executed (we can verify it by writing: PatchWord(0x4024AC, 1), in the correct order to make
jump: eip:71	jz   $86 -> 0 to taken).

```assembly
#955	cmd: 5	addr:0x40241c	eip:101	mov  $6[5a4d], 0xdead
#956	cmd: 5	addr:0x40241c	eip:104	mov  $4[13c], 0xbeef
#957	cmd:20	addr:0x402439	eip:107	halt
```

So, all we have to do is to decrypt this cipher:
```
0x0B,0x2E,0x02,0x6D,0x92,0x74,0x0C,0x87,0xB9,0x93,0xB3,0xED,0x2C,0x31,0x07,0x71,
0x10,0x7D,0x07,0x20,0xC6,0xE7,0x1B,0x3A,0xD8,0xBA,0x17,0x94,0x6B,0xFA,0x6C,0xBE,
0x1D,0x62,0x3B,0x4D,0xAD,0x47,0x7A,0x7A,0x9D,0x3E,0xA2,0x53,0x2F,0xF2,0xA9,0xD1,
0x74,0xF5,0x73,0x81,0xBC,0x11,0x15,0xAE,0x79,0x61,0x21,0xAF
```

By reversing this algorithm: 
```c
	for( i=0; i<(int)strlen(psw); i++ ) // for each password character
    {
        r_e = xchg((psw[i]*256 + psw[i+1] - 0x1111*18) & 0xffff);   // read 2 chars from password
		r_e = ~((r_e & 0xff00) >> 8) ^ ~(r_e & 0xff);               // convert 2 bytes to 1 byte index
        r_e *= 2;
		r_e = ((H[r_e+1]<<8) + H[r_e]);                             // hash index

		encr[i+1] = r_e ^ encr[i];                                  // XOR with previous encrypted word

        for( j=0; j<0x200; j++) H[j] ^= key[i];                     // XOR hash table
    }
```

Because the algorithm XORes each byte with the previous, we need to decrypt them in the 
reverse order. We must also keep in mind that we always know the last character of the 
password: the NULL byte. The complete solution and the reversing algorithm are inside 
crack.cpp

After running the code we get the flag: **V1rTu4L_M4ch1n3s_4r3_Aw3s0m3!**

___