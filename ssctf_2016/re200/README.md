## SSCTF 2016 - Re2 (Reversing 200)
##### 26/02 - 28/02/2016 (48hr)
___
First we open program with CFF explorer. We see that is compressed with UPX v3.0. We download UPX 
and we decompress it. Then we open program in IDA pro.

We have to deal with a multi-threading program.	The music and the animation are stored as resources
in the program and get extracted and displayed during runtime. I won't analyze the code that does that,
I'll only focus on the actual code.

The first important function is 0x4022B0, which reads flag from stdin and spawn all threads.
```assembly
.text:004022B7 57                    push    edi
.text:004022B8 8B 3D 18 31 40 00     mov     edi, ds:printf
.text:004022BE C6 45 F4 7A           mov     [ebp+var_C], 7Ah            ; "Input flag:" message
.text:004022C2 C6 45 F5 5D           mov     [ebp+var_B], 5Dh
.text:004022C6 C6 45 F6 43           mov     [ebp+var_A], 43h
.text:004022CA C6 45 F7 46           mov     [ebp+var_9], 46h
.text:004022CE C6 45 F8 47           mov     [ebp+var_8], 47h
.text:004022D2 C6 45 F9 13           mov     [ebp+var_7], 13h
.text:004022D6 C6 45 FA 75           mov     [ebp+var_6], 75h
.text:004022DA C6 45 FB 5F           mov     [ebp+var_5], 5Fh
.text:004022DE C6 45 FC 52           mov     [ebp+var_4], 52h
.text:004022E2 C6 45 FD 54           mov     [ebp+var_3], 54h
.text:004022E6 C6 45 FE 09           mov     [ebp+var_2], 9
.text:004022EA 33 F6                 xor     esi, esi
.text:004022EC
.text:004022EC                   loc_4022EC:                             ; CODE XREF: spawn_threads_4022B0+53
.text:004022EC 0F BE 44 35 F4        movsx   eax, [ebp+esi+var_C]        ; XOR character and print it
.text:004022F1 83 F0 33              xor     eax, 33h
.text:004022F4 50                    push    eax
.text:004022F5 68 4C 41 40 00        push    offset Format               ; "%c"
.text:004022FA FF D7                 call    edi ; printf
.text:004022FC 83 C4 08              add     esp, 8
.text:004022FF 46                    inc     esi
.text:00402300 83 FE 0B              cmp     esi, 0Bh
.text:00402303 7C E7                 jl      short loc_4022EC            ; XOR character and print it
.text:00402305 68 E4 43 40 00        push    offset flag_4043E4
.text:0040230A 68 24 41 40 00        push    offset aS                   ; "%s"
.text:0040230F FF 15 1C 31 40 00     call    ds:scanf
.text:00402315 BF E4 43 40 00        mov     edi, offset flag_4043E4
.text:0040231A 83 C9 FF              or      ecx, 0FFFFFFFFh
.text:0040231D 33 C0                 xor     eax, eax
.text:0040231F 83 C4 08              add     esp, 8
.text:00402322 F2 AE                 repne scasb
.text:00402324 F7 D1                 not     ecx
.text:00402326 49                    dec     ecx                         ; ecx = strlen(flag)
.text:00402327 5F                    pop     edi
.text:00402328 83 F9 21              cmp     ecx, 21h                    ; flag must be between 1 and 32 characters
.text:0040232B 5E                    pop     esi
.text:0040232C 0F 8D F5 03 00 00     jge     RET_0_402727
.text:00402332 85 C9                 test    ecx, ecx
.text:00402334 0F 8E ED 03 00 00     jle     RET_0_402727
```

This is our first clue: Flags must be between 1 and 32 characters. After that we spawn 39 threads:
```assembly
.text:0040233A 50                    push    eax                         ; struct _SECURITY_ATTRIBUTES *
.text:0040233B 6A 04                 push    4                           ; unsigned __int32
.text:0040233D 50                    push    eax                         ; unsigned int
.text:0040233E 50                    push    eax                         ; int
.text:0040233F 50                    push    eax                         ; void *
.text:00402340 68 80 10 40 00        push    offset thrd_rtn_0_401080    ; unsigned int (__cdecl *)(void *)
.text:00402345 E8 16 0A 00 00        call    ?AfxBeginThread@@YGPAVCWinThread@@P6AIPAX@Z0HIKPAU_SECURITY_ATTRIBUTES@@@Z
.text:0040234A 6A 00                 push    0                           ; struct _SECURITY_ATTRIBUTES *
.text:0040234C 6A 04                 push    4                           ; unsigned __int32
.text:0040234E 6A 00                 push    0                           ; unsigned int
.text:00402350 6A 00                 push    0                           ; int
.text:00402352 6A 00                 push    0                           ; void *
.text:00402354 68 10 11 40 00        push    offset thrd_rtn_1_401110    ; unsigned int (__cdecl *)(void *)
.text:00402359 A3 F4 42 40 00        mov     thrd_hdl_0_4042F4, eax
.text:0040235E E8 FD 09 00 00        call    ?AfxBeginThread@@YGPAVCWinThread@@P6AIPAX@Z0HIKPAU_SECURITY_ATTRIBUTES@@@Z
.....
.text:0040271E B8 01 00 00 00        mov     eax, 1                      ; return 1
.text:00402723 8B E5                 mov     esp, ebp
.text:00402725 5D                    pop     ebp
.text:00402726 C3                    retn
```

After we create all threads we exit. Note that we create threads in suspended mode, so none of these threads will
be executed. Going back in main(), if flag is between 1 and 32 characters, we start executing all threads:
```assembly
.text:00402A1E E8 8D F8 FF FF        call    spawn_threads_4022B0
.text:00402A23 83 F8 01              cmp     eax, 1
.text:00402A26 75 09                 jnz     short loc_402A31
.text:00402A28 8D 4C 24 24           lea     ecx, [esp+44h+var_20]
.text:00402A2C E8 CF FD FF FF        call    resume_threads_402800
```
As you can guess, function 0x402800 resumes all of these suspended threads. Note that this is not the only job of this
function. It also extacts the TXT resource and displays it (that's our animation). Now let's analyze our threads.
Let A, B, C, D, E, F and G be some public arrays (we'll define them later). Whenever there are threads, there should
be mutexes or some sort of synchronization. In this program, there's just 1 mutex, which ensures that only one thread
each time will have access to any of the above arrrays. For simplicity, we ignore the mutex locks/unlocks in the code
and we'll focus on the actual code that each thread executes. We know that every time only 1 thread does some useful
progress. This means this code could have a single thread while keeping the same functionality. Let's see the threads:
___
**Thread routine #0 (0x401080):**
```c
	flag[0] ^= A[0] ^ B[0] ^ is_dbg
```
___
**Thread routines #1 - #31 (0x401110 - 0x401A70):**
```assembly
.text:00401110                   ; unsigned int __cdecl thrd_rtn_1_401110(void *)
.text:00401110                   thrd_rtn_1_401110 proc near             ; DATA XREF: spawn_threads_4022B0+A4o
.text:00401110
.text:00401110                   is_dbg_1= byte ptr -1
.text:00401110
.text:00401110 55                    push    ebp
.text:00401111 8B EC                 mov     ebp, esp
.text:00401113 51                    push    ecx
.text:00401114 C6 45 FF 00           mov     [ebp+is_dbg_1], 0
.text:00401118 50                    push    eax
.text:00401119 33 C0                 xor     eax, eax
.text:0040111B 64 A1 30 00 00 00     mov     eax, large fs:30h           ; get Process Environment Block
.text:00401121 8A 40 02              mov     al, [eax+2]                 ; get IsDebugged bit
.text:00401124 88 45 FF              mov     [ebp+is_dbg_1], al          ; if debugger is present, set this to 1
.text:00401127 58                    pop     eax
.text:00401128 8A 0D D5 42 40 00     mov     cl, A_1_4042D5
.text:0040112E A0 E5 43 40 00        mov     al, thrd_1_val_4043E5       ; flag[1]
.text:00401133 32 C8                 xor     cl, al
.text:00401135 A0 FD 40 40 00        mov     al, B_1_4040FD
.text:0040113A 32 C8                 xor     cl, al
.text:0040113C 8A 45 FF              mov     al, [ebp+is_dbg_1]
.text:0040113F 32 C1                 xor     al, cl
.text:00401141 C7 05 CC 42 40 00+    mov     DBG_FLAG_4042CC, 1
.text:0040114B A2 E5 43 40 00        mov     thrd_1_val_4043E5, al       ; flag[1] ^= B[1] ^ A[1] ^ is_dbg_1
.text:00401150 33 C0                 xor     eax, eax                    ; return 0
.text:00401152 8B E5                 mov     esp, ebp
.text:00401154 5D                    pop     ebp
.text:00401155 C3                    retn
.text:00401155                   thrd_rtn_1_401110 endp
.text:00401155
```
Note the anti-debug trick here. All we have to do here, is simply to patch the IsDebugged bit, and 
continue our analysis. Each of these threads access a different element of A, B and flag arrays. Each
thread does:

```c	
flag[tid] ^= B[tid] ^ A[tid] ^ is_dbg_1 
(is_dbg_1 must be 0)
```
___
**Thread routine #32 (0x401ac0):**
```assembly
.text:00401AC0 53                    push    ebx
.text:00401AC1 56                    push    esi
.text:00401AC2 57                    push    edi
.text:00401AC3 68 E8 41 40 00        push    offset CriticalSection      ; lpCriticalSection
.text:00401AC8 FF 15 50 30 40 00     call    ds:EnterCriticalSection
.text:00401ACE 33 F6                 xor     esi, esi                    ; i = 0
.text:00401AD0 BF E4 43 40 00        mov     edi, offset flag_4043E4
.text:00401AD5
.text:00401AD5                   outer_loop_401AD5:                      ; CODE XREF: thrd_rtn_32_401AC0+3E
.text:00401AD5 8A 9E C4 42 40 00     mov     bl, arr_C0_4042C4[esi]      ; b = arr_C_4042C4[i]
.text:00401ADB 33 C0                 xor     eax, eax                    ; j = 0
.text:00401ADD                   ----------------------------------------------------------------
.text:00401ADD                   for(i=0; i<4; ++i) {
.text:00401ADD                       for(b=arr_C_4042C4[i], j=0; j<8; ++j)
.text:00401ADD                           b = 2*b + flag[i*8 + j];
.text:00401ADD
.text:00401ADD                       arr_C_4042C4[i] = b;
.text:00401ADD                   }
.text:00401ADD                   ----------------------------------------------------------------
.text:00401ADD
.text:00401ADD                   inner_loop_401ADD:                      ; CODE XREF: thrd_rtn_32_401AC0+2C
.text:00401ADD 8A 14 07              mov     dl, [edi+eax]               ; dl = flag[i*8 + j]
.text:00401AE0 8A CB                 mov     cl, bl
.text:00401AE2 D0 E1                 shl     cl, 1                       ; cl = b*2
.text:00401AE4 02 D1                 add     dl, cl                      ; dl = 2*b + flag[i*8 + j]
.text:00401AE6 40                    inc     eax                         ; ++j
.text:00401AE7 83 F8 08              cmp     eax, 8                      ; j < 8 ?
.text:00401AEA 8A DA                 mov     bl, dl                      ; b = 2*b + flag[i*8 + j]
.text:00401AEC 7C EF                 jl      short inner_loop_401ADD     ; if yes, continue
.text:00401AEE 88 9E C4 42 40 00     mov     arr_C0_4042C4[esi], bl      ; arr_C_4042C4[i] = b
.text:00401AF4 83 C7 08              add     edi, 8
.text:00401AF7 46                    inc     esi                         ; ++i
.text:00401AF8 81 FF 04 44 40 00     cmp     edi, offset thrd_arr_end_404404
.text:00401AF8                   ----------------------------------------------------------------
.text:00401AF8                   edi goes from 4043E4 to 404404 with step 8 => 4 reps
.text:00401AF8                   ----------------------------------------------------------------
.text:00401AFE 7C D5                 jl      short outer_loop_401AD5     ; iterate over thrd_arr
.text:00401B00 A1 78 43 40 00        mov     eax, thrd_hdl_33_404378
.text:00401B05 8B 48 2C              mov     ecx, [eax+2Ch]
.text:00401B08 51                    push    ecx                         ; hThread
.text:00401B09 FF 15 54 30 40 00     call    ds:ResumeThread
.text:00401B0F 68 E8 41 40 00        push    offset CriticalSection      ; lpCriticalSection
.text:00401B14 C7 05 CC 42 40 00+    mov     DBG_FLAG_4042CC, 1
.text:00401B1E FF 15 5C 30 40 00     call    ds:LeaveCriticalSection     ; start thread #33
.text:00401B24 5F                    pop     edi
.text:00401B25 5E                    pop     esi
.text:00401B26 33 C0                 xor     eax, eax
.text:00401B28 5B                    pop     ebx
.text:00401B29 C3                    retn
.text:00401B29                   thrd_rtn_32_401AC0 endp
```
Let's decompile it:
```c
	for(i=0; i<4; ++i) {
		for(b=C[i], j=0; j<8; ++j)
			b = 2*b + flag[i*8 + j];

		C[i] = b;
	}
	Start thread #33
```
___
**Thread routine #33 (0x401B30):**
This is a little bit tricky, because it uses bogus bytes to confuse dissasembler:
```assembly
.text:00401B58 75 63                 jnz     short loc_401BBD
.text:00401B5A 74 61                 jz      short loc_401BBD
.text:00401B5A                   ; ---------------------------------------------------------------------------
.text:00401B5C E9 03 C2 C1           dd 0C1C203E9h
.text:00401B60 14 3B C3 FF           dd 0FFC33B14h
.text:00401B64 D2 11                 dw 11D2h
.text:00401B66 C3                    db 0C3h ; +
.text:00401B67                   ; ---------------------------------------------------------------------------
.text:00401B67
.text:00401B67                   loc_401B67:                             ; CODE XREF: .text:loc_401BBDj
```
However it's easy to undefine the bogus bytes and "make code" the right bytes. After that, there are some
weird jumps back and forth, but after a while, there's the actual code:
```assembly
.text:00401BC7 33 C0                 xor     eax, eax
.text:00401BC9
.text:00401BC9                   LOOP_401BC9:                            ; CODE XREF: sub_401BC7+14j
.text:00401BC9 8A 88 C4 42 40 00     mov     cl, arr_C0_4042C4[eax]
.text:00401BCF 8A 5D FC              mov     bl, [ebp-4]
.text:00401BD2 02 D9                 add     bl, cl
.text:00401BD4 40                    inc     eax
.text:00401BD5                   ----------------------------------------------------------------
.text:00401BD5                   1. C[0] + C[1] + C[2] + C[3] == 0xDC
.text:00401BD5                   2. C[0] ^ 0x66 == C[1] ^ 0x77 == C[3] ^ 0x6F == C[1] ^ C[2] ^ C[3]
.text:00401BD5
.text:00401BD5                   ----------------------------------------------------------------
.text:00401BD5
.text:00401BD5                   loc_401BD5:
.text:00401BD5 83 F8 04              cmp     eax, 4
.text:00401BD8 88 5D FC              mov     [ebp-4], bl
.text:00401BDB 7C EC                 jl      short LOOP_401BC9
.text:00401BDD 8A C3                 mov     al, bl                      ; al = SUM(C) = C[0] + C[1] + C[2] + C[3]
.text:00401BDF 3C DC                 cmp     al, 0DCh                    ; SUM(C) must be 0xDC
.text:00401BE1 0F 85 A2 00 00 00     jnz     END_401C89                  ; start thread #34
.text:00401BE7 A0 C5 42 40 00        mov     al, arr_C1_4042C5
.text:00401BEC 8A 0D C7 42 40 00     mov     cl, arr_C3_4042C7
.text:00401BF2 8A 15 C4 42 40 00     mov     dl, arr_C0_4042C4
.text:00401BF8 34 77                 xor     al, 77h                     ; al = C[1] ^ 0x77
.text:00401BFA 80 F1 6F              xor     cl, 6Fh                     ; cl = C[3] ^ 0x6F
.text:00401BFD 8A D8                 mov     bl, al                      ; bl = C[1] ^ 0x77
.text:00401BFF 88 4D FC              mov     [ebp-4], cl                 ; v_4 = C[3] ^ 0x6F
.text:00401C02 32 C1                 xor     al, cl                      ; al = C[1]^0x77 ^ C[3]^0x6F = C[1]^C[3]^0x18
.text:00401C04 8A 0D C6 42 40 00     mov     cl, arr_C2_4042C6
.text:00401C0A 80 F2 66              xor     dl, 66h                     ; dl = C[0] ^ 0x66
.text:00401C0D 32 C8                 xor     cl, al                      ; cl = C[2] ^ C[1]^C[3]^0x18
.text:00401C0F 32 C3                 xor     al, bl                      ; al = C[1]^C[3]^0x18 ^ C[1]^0x77 = C[3] ^0x6F
.text:00401C11 80 F1 18              xor     cl, 18h                     ; cl = C[2]^C[1]^C[3]^0x18^0x18
.text:00401C14 88 55 F8              mov     [ebp-8], dl                 ; v_8 =  C[0] ^ 0x66
.text:00401C17 3A D9                 cmp     bl, cl                      ; C[1] ^ 0x77 == C[1]^C[2]^C[3] ?
.text:00401C19 88 4D F4              mov     [ebp-0Ch], cl               ; v_c = C[2]^C[1]^C[3]
.text:00401C1C 88 45 F0              mov     [ebp-10h], al               ; v_10 = C[3] ^0x6F
.text:00401C1F 75 68                 jnz     short END_401C89            ; start thread #34
.text:00401C21 3A C2                 cmp     al, dl                      ; C[3] ^0x6F ==  C[0] ^ 0x66 ?
.text:00401C23 75 64                 jnz     short END_401C89            ; start thread #34
.text:00401C25 3A D8                 cmp     bl, al                      ; C[1] ^ 0x77 == C[3] ^0x6F ?
.text:00401C27 75 60                 jnz     short END_401C89            ; start thread #34
.text:00401C29 8B 55 F8              mov     edx, [ebp-8]
.text:00401C2C 8B 45 F4              mov     eax, [ebp-0Ch]
.text:00401C2F 8B 4D FC              mov     ecx, [ebp-4]
.text:00401C32 81 E2 FF 00 00 00     and     edx, 0FFh
.text:00401C38 25 FF 00 00 00        and     eax, 0FFh
.text:00401C3D 81 E1 FF 00 00 00     and     ecx, 0FFh
.text:00401C43 03 D0                 add     edx, eax                    ; edx = C[0]^0x66 + C[2]^C[1]^C[3]
.text:00401C45 8B 45 F0              mov     eax, [ebp-10h]
.text:00401C48 03 D1                 add     edx, ecx                    ; edx +=  C[3] ^ 0x6F
.text:00401C4A 25 FF 00 00 00        and     eax, 0FFh
.text:00401C4F 03 D0                 add     edx, eax                    ; edx += C[3] ^0x6F
.text:00401C51 BF 20 40 40 00        mov     edi, offset arr_D_404020
.text:00401C56 83 C9 FF              or      ecx, 0FFFFFFFFh
.text:00401C59 33 C0                 xor     eax, eax
.text:00401C5B C1 EA 02              shr     edx, 2                      ; dd = (C[0]^0x66 + C[2]^C[1]^C[3] + 2*C[3] ^0x6F) / 4
.text:00401C5E 33 F6                 xor     esi, esi                    ; i = 0
.text:00401C60 F2 AE                 repne scasb
.text:00401C62 F7 D1                 not     ecx
.text:00401C64 49                    dec     ecx
.text:00401C65 74 22                 jz      short END_401C89            ; ecx = strlen(D);
.text:00401C67
.text:00401C67                   loc_401C67:                             ; CODE XREF: sub_401BC7+C0j
.text:00401C67 8A 8E 20 40 40 00     mov     cl, arr_D_404020[esi]
.text:00401C6D BF 20 40 40 00        mov     edi, offset arr_D_404020
.text:00401C72 32 CA                 xor     cl, dl
.text:00401C74 33 C0                 xor     eax, eax
.text:00401C76 88 8E 20 40 40 00     mov     arr_D_404020[esi], cl       ; D[i] ^= dd
.text:00401C7C 83 C9 FF              or      ecx, 0FFFFFFFFh
.text:00401C7F 46                    inc     esi
.text:00401C80 F2 AE                 repne scasb
.text:00401C82 F7 D1                 not     ecx
.text:00401C84 49                    dec     ecx
.text:00401C85 3B F1                 cmp     esi, ecx
.text:00401C87 72 DE                 jb      short loc_401C67            ; for each character
.text:00401C89
.text:00401C89                   END_401C89:                             ; CODE XREF: sub_401BC7+1Aj
.text:00401C89                                                           ; sub_401BC7+58j ...
.text:00401C89 8B 0D 7C 43 40 00     mov     ecx, thrd_hdl_34_40437C     ; start thread #34
.text:00401C8F 8B 51 2C              mov     edx, [ecx+2Ch]
.text:00401C92 52                    push    edx                         ; hThread
.text:00401C93 FF 15 54 30 40 00     call    ds:ResumeThread
.text:00401C99 68 E8 41 40 00        push    offset CriticalSection      ; lpCriticalSection
.text:00401C9E FF 15 5C 30 40 00     call    ds:LeaveCriticalSection
.text:00401CA4 5F                    pop     edi
.text:00401CA5 5E                    pop     esi
.text:00401CA6 33 C0                 xor     eax, eax
.text:00401CA8 5B                    pop     ebx
.text:00401CA9 8B E5                 mov     esp, ebp
.text:00401CAB 5D                    pop     ebp
.text:00401CAC C3                    retn
```

So if we decompile it, we get:
```c
The following must be true:
1. C[0] + C[1] + C[2] + C[3] == 0xDC
2. C[0] ^ 0x66 == C[1] ^ 0x77 == C[3] ^ 0x6F == C[1] ^ C[2] ^ C[3] 

	dd = (C[0]^0x66 + C[2]^C[1]^C[3] + 2*(C[3]^0x6F)) / 4;
	
	for( b=0, i=0; i<strlen(D); ++i )
		D[i] ^= dd;
	
	Start thread #34
```
___
**Thread routine #34 (0x00401CB0):**
This function is very similar with the previous one:

```c
	for( b=0, i=0; i<strlen(D); ++i )
		b ^= D[i];

	if( strlen(E) > 0 )
	{
		b ^= 0xc6;
		for( i=0; i<strlen(E); ++i )
			E[i] ^= b;
	}

	Start thread #35
```
___
**Thread routine #35 (0x00401D50):**
```assembly
.text:00401D50                   thrd_rtn_35_401D50 proc near            ; DATA XREF: spawn_threads_4022B0+3F6o
.text:00401D50 56                    push    esi
.text:00401D51 57                    push    edi
.text:00401D52 68 E8 41 40 00        push    offset CriticalSection      ; lpCriticalSection
.text:00401D57 FF 15 50 30 40 00     call    ds:EnterCriticalSection
.text:00401D5D BF 88 40 40 00        mov     edi, offset E_404088
.text:00401D62 83 C9 FF              or      ecx, 0FFFFFFFFh
.text:00401D65 33 C0                 xor     eax, eax
.text:00401D67 32 D2                 xor     dl, dl                      ; d = 0
.text:00401D69 33 F6                 xor     esi, esi
.text:00401D6B F2 AE                 repne scasb
.text:00401D6D F7 D1                 not     ecx
.text:00401D6F 49                    dec     ecx
.text:00401D70 74 1C                 jz      short loc_401D8E            ; strlen(E) > 0 ?
.text:00401D72                   ----------------------------------------------------------------
.text:00401D72                   if( strlen(E) > 0 )
.text:00401D72                   {
.text:00401D72                       for( d=0, i=0; i<strlen(E); ++i )
.text:00401D72                           d ^= E[i];
.text:00401D72
.text:00401D72                   }
.text:00401D72                   ----------------------------------------------------------------
.text:00401D72
.text:00401D72                   loc_401D72:                             ; CODE XREF: thrd_rtn_35_401D50+3Cj
.text:00401D72 8A 86 88 40 40 00     mov     al, E_404088[esi]
.text:00401D78 BF 88 40 40 00        mov     edi, offset E_404088
.text:00401D7D 32 D0                 xor     dl, al                      ; d ^= E[i]
.text:00401D7F 83 C9 FF              or      ecx, 0FFFFFFFFh
.text:00401D82 33 C0                 xor     eax, eax
.text:00401D84 46                    inc     esi
.text:00401D85 F2 AE                 repne scasb
.text:00401D87 F7 D1                 not     ecx
.text:00401D89 49                    dec     ecx
.text:00401D8A 3B F1                 cmp     esi, ecx
.text:00401D8C 72 E4                 jb      short loc_401D72            ; repeat for each character of E
.text:00401D8E
.text:00401D8E                   loc_401D8E:                             ; CODE XREF: thrd_rtn_35_401D50+20j
.text:00401D8E 80 F2 5A              xor     dl, 5Ah                     ; d ^= 0x5a
.text:00401D91 68 E8 41 40 00        push    offset CriticalSection      ; lpCriticalSection
.text:00401D96 8A C2                 mov     al, dl                      ; a = d ^ 0x5A
.text:00401D98 C7 05 CC 42 40 00+    mov     DBG_FLAG_4042CC, 1
.text:00401DA2 34 18                 xor     al, 18h                     ; a = d ^ 0x5A ^ 0x18 = d ^ 0x42
.text:00401DA4 02 C2                 add     al, dl                      ; a = d ^ 0x5a + d^0x42
.text:00401DA6 A2 D0 42 40 00        mov     B_byte_4042D0, al           ; B_byte = d^0x5a + d^0x42
.text:00401DAB FF 15 5C 30 40 00     call    ds:LeaveCriticalSection
.text:00401DB1 8B 0D 84 43 40 00     mov     ecx, thrd_hdl_36_404384     ; start threads 36, 37, 38 and 39
.text:00401DB7 8B 35 54 30 40 00     mov     esi, ds:ResumeThread
.text:00401DBD 8B 51 2C              mov     edx, [ecx+2Ch]
.text:00401DC0 52                    push    edx                         ; hThread
.text:00401DC1 FF D6                 call    esi ; ResumeThread
.text:00401DC3 A1 88 43 40 00        mov     eax, thrd_hdl_37_404388
.text:00401DC8 8B 48 2C              mov     ecx, [eax+2Ch]
.text:00401DCB 51                    push    ecx                         ; hThread
.text:00401DCC FF D6                 call    esi ; ResumeThread
.text:00401DCE 8B 15 90 43 40 00     mov     edx, thrd_hdl_39_404390
.text:00401DD4 8B 42 2C              mov     eax, [edx+2Ch]
.text:00401DD7 50                    push    eax                         ; hThread
.text:00401DD8 FF D6                 call    esi ; ResumeThread
.text:00401DDA 8B 0D 8C 43 40 00     mov     ecx, thrd_hdl_38_40438C
.text:00401DE0 8B 51 2C              mov     edx, [ecx+2Ch]
.text:00401DE3 52                    push    edx                         ; hThread
.text:00401DE4 FF D6                 call    esi ; ResumeThread
.text:00401DE6 5F                    pop     edi
.text:00401DE7 33 C0                 xor     eax, eax
.text:00401DE9 5E                    pop     esi
.text:00401DEA C3                    retn
```

Decompiling is also straightforward: 
```c	
	for( d=0, i=0; i<strlen(E); ++i )
			d ^= E[i];
	
	B_byte = d^0x5a + d^0x42

	Start threads #36, #37, #38 and #39
```
___
**Thread routine #36 (0x00401DF0):**
This is also very similar to thread routine #34:
```c
	for( i=0; i<strlen(G); ++i )
		G[i] ^= B_byte;

	Start threads #37 and #39
```
___
**Thread routine #37 (0x401E70):**
This is our antidebuging thread:
```c
	Start threads #38 and #39

	for( ;; )
	{
		Sleep(1000);
		Start thread #38

		if program being debugged then
			is_dbg = 2 
	}
```
___
**Thread routine #38 (0x401EF0):**

This is where the main check is done. At a first glance it seems pretty complicated but it actually
isn't. Let's focus on the most important parts:
```assembly
.....
.text:00401F08 A1 88 43 40 00        mov     eax, thrd_hdl_37_404388
.text:00401F0D 53                    push    ebx
.text:00401F0E C7 44 24 0C 00 00+    mov     [esp+7Ch+phProv], 0
.text:00401F16 C7 44 24 04 00 00+    mov     [esp+7Ch+phHash], 0
.text:00401F1E 8B 48 2C              mov     ecx, [eax+2Ch]
.text:00401F21 56                    push    esi
.text:00401F22 8B 35 54 30 40 00     mov     esi, ds:ResumeThread        ; start threads #37 and #38
.text:00401F28 57                    push    edi
.text:00401F29 51                    push    ecx                         ; hThread
.text:00401F2A FF D6                 call    esi ; ResumeThread
.text:00401F2C 8B 15 90 43 40 00     mov     edx, thrd_hdl_39_404390
.text:00401F32 8B 42 2C              mov     eax, [edx+2Ch]
.text:00401F35 50                    push    eax                         ; hThread
.text:00401F36 FF D6                 call    esi ; ResumeThread

.text:00401F38 B0 FD                 mov     al, 0FDh
.text:00401F3A B1 C5                 mov     cl, 0C5h
.text:00401F3C 88 44 24 28           mov     [esp+84h+loc_H_5C], al		  ; this is array H
.text:00401F40 88 44 24 2A           mov     [esp+84h+var_5A], al
.text:00401F44 B0 E7                 mov     al, 0E7h
.text:00401F46 88 4C 24 29           mov     [esp+84h+var_5B], cl
.text:00401F4A 88 44 24 2B           mov     [esp+84h+var_59], al
.text:00401F4E 88 44 24 2D           mov     [esp+84h+var_57], al
.text:00401F52 88 4C 24 2C           mov     [esp+84h+var_58], cl
.text:00401F56 B0 C7                 mov     al, 0C7h
.text:00401F58 B1 E5                 mov     cl, 0E5h
.text:00401F5A 88 44 24 2E           mov     [esp+84h+var_56], al
.text:00401F5E 88 44 24 30           mov     [esp+84h+var_54], al
.text:00401F62 88 4C 24 2F           mov     [esp+84h+var_55], cl
.text:00401F66 B0 DD                 mov     al, 0DDh
.text:00401F68 88 4C 24 32           mov     [esp+84h+var_52], cl
.text:00401F6C 8D 4C 24 20           lea     ecx, [esp+84h+var_64]
.text:00401F70 88 44 24 31           mov     [esp+84h+var_53], al
.text:00401F74 88 44 24 33           mov     [esp+84h+var_51], al
.text:00401F78 C6 44 24 34 00        mov     [esp+84h+var_50], 0
.....
.text:00401FB8 68 28 41 40 00        push    offset aFbc4a31e4e17d8      ; "FBC4A31E4E17D829CA2242B2F893481B"
.....
.text:00402005                   ----------------------------------------------------------------
.text:00402005                   if( strlen(F) > 0 )
.text:00402005                   {
.text:00402005                       for(i=0; i<strlen(F); i++)
.text:00402005                          F[i] ^= B_byte;
.text:00402005                   }
.....
.text:0040203F                   ----------------------------------------------------------------
.text:0040203F                   b = 0;
.text:0040203F                   if( strlen(F) > 0 )
.text:0040203F                   {
.text:0040203F                       for(i=0; i<strlen(F); i++)
.text:0040203F                          b ^= F[i];
.text:0040203F                   }
.....
.text:0040203F
.text:0040203F                   loc_40203F:                             ; CODE XREF: thrd_rtn_38_401EF0+169j
.text:0040203F 8A 8A 48 40 40 00     mov     cl, arr_F_404048[edx]
.text:00402045 BF 48 40 40 00        mov     edi, offset arr_F_404048
.text:0040204A 32 D9                 xor     bl, cl                      ; b ^= F[i]
.text:0040204C 83 C9 FF              or      ecx, 0FFFFFFFFh
.text:0040204F 33 C0                 xor     eax, eax
.text:00402051 42                    inc     edx
.text:00402052 F2 AE                 repne scasb
.text:00402054 F7 D1                 not     ecx
.text:00402056 49                    dec     ecx
.text:00402057 3B D1                 cmp     edx, ecx
.text:00402059 72 E4                 jb      short loc_40203F
.text:0040205B
.text:0040205B                   loc_40205B:                             ; CODE XREF: thrd_rtn_38_401EF0+14Dj
.text:0040205B A1 CC 42 40 00        mov     eax, DBG_FLAG_4042CC
.text:00402060 80 F3 02              xor     bl, 2
.text:00402063 02 D8                 add     bl, al                      ; b = b ^ 2 + is_dbg
.text:00402065 83 F8 02              cmp     eax, 2
.text:00402068 0F 84 50 01 00 00     jz      END_4021BE                  ; if program is being debugged, skip this
.text:0040206E 8D 7C 24 28           lea     edi, [esp+84h+loc_H_5C]
.text:00402072 83 C9 FF              or      ecx, 0FFFFFFFFh
.text:00402075 33 C0                 xor     eax, eax
.text:00402077 33 D2                 xor     edx, edx
.text:00402079 F2 AE                 repne scasb
.text:0040207B F7 D1                 not     ecx
.text:0040207D 49                    dec     ecx
.text:0040207E 74 1D                 jz      short loc_40209D            ; ecx = strlen(loc_H)
.text:00402080                   ----------------------------------------------------------------
.text:00402080                   if( strlen(loc_H) > 0 )
.text:00402080                   {
.text:00402080                       for(i=0; i<strlen(loc_H); i++)
.text:00402080                          loc_H[i] ^= b;
.text:00402080                   }
.....
.text:0040209D
.text:0040209D                   loc_40209D:                             ; CODE XREF: thrd_rtn_38_401EF0+18Ej
.text:0040209D 8D 4C 24 28           lea     ecx, [esp+84h+loc_H_5C]
.text:004020A1 8D 54 24 10           lea     edx, [esp+84h+var_74]
.text:004020A5 51                    push    ecx
.text:004020A6 68 24 41 40 00        push    offset aS                   ; "%s"
.text:004020AB 52                    push    edx                         ; this
.text:004020AC E8 9D 0C 00 00        call    ?Format@CString@@QAAXPBDZZ  ; CString::Format(char const *,...)
.text:004020B1 83 C4 0C              add     esp, 0Ch
.text:004020B4 8D 44 24 14           lea     eax, [esp+84h+phProv]
.text:004020B8 68 00 00 00 F0        push    0F0000000h                  ; dwFlags
.text:004020BD 6A 01                 push    1                           ; dwProvType
.text:004020BF 6A 00                 push    0                           ; szProvider
.text:004020C1 6A 00                 push    0                           ; szContainer
.text:004020C3 50                    push    eax                         ; phProv
.text:004020C4 FF 15 14 30 40 00     call    ds:CryptAcquireContextA
.text:004020CA 85 C0                 test    eax, eax                    ; get a handle to a Crypto Service Provider (CSP)
.text:004020CC 0F 84 AB 00 00 00     jz      CRYPTO_FAILURE_40217D
.text:004020D2 8B 54 24 14           mov     edx, [esp+84h+phProv]
.text:004020D6 8D 4C 24 0C           lea     ecx, [esp+84h+phHash]
.text:004020DA 51                    push    ecx                         ; phHash
.text:004020DB 6A 00                 push    0                           ; dwFlags
.text:004020DD 6A 00                 push    0                           ; hKey
.text:004020DF 68 03 80 00 00        push    8003h                       ; Algid = MD5 hashing algorithm
.text:004020E4 52                    push    edx                         ; hProv
.text:004020E5 FF 15 00 30 40 00     call    ds:CryptCreateHash
.text:004020EB 85 C0                 test    eax, eax
.text:004020ED 0F 84 8A 00 00 00     jz      CRYPTO_FAILURE_40217D
.text:004020F3 8B 44 24 10           mov     eax, [esp+84h+var_74]
.text:004020F7 6A 00                 push    0                           ; dwFlags
.text:004020F9 8D 4C 24 14           lea     ecx, [esp+88h+var_74]       ; this
.text:004020FD 8B 40 F8              mov     eax, [eax-8]
.text:00402100 50                    push    eax                         ; dwDataLen
.text:00402101 6A 00                 push    0                           ; int
.text:00402103 E8 40 0C 00 00        call    ?GetBuffer@CString@@QAEPADH@Z ; CString::GetBuffer(int)
.text:00402108 8B 4C 24 14           mov     ecx, [esp+8Ch+phHash]
.text:0040210C 50                    push    eax                         ; pbData
.text:0040210D 51                    push    ecx                         ; hHash
.text:0040210E FF 15 04 30 40 00     call    ds:CryptHashData            ; calc MD5(loc_H)
.text:00402114 85 C0                 test    eax, eax
.text:00402116 74 65                 jz      short CRYPTO_FAILURE_40217D
.text:00402118 B9 0F 00 00 00        mov     ecx, 0Fh
.text:0040211D 33 C0                 xor     eax, eax
.text:0040211F 8D 7C 24 39           lea     edi, [esp+84h+var_4B]
.text:00402123 C6 44 24 38 00        mov     [esp+84h+pbData], 0
.text:00402128 F3 AB                 rep stosd
.text:0040212A 8B 4C 24 0C           mov     ecx, [esp+84h+phHash]
.text:0040212E 8D 54 24 24           lea     edx, [esp+84h+pdwDataLen]
.text:00402132 66 AB                 stosw
.text:00402134 AA                    stosb
.text:00402135 6A 00                 push    0                           ; dwFlags
.text:00402137 8D 44 24 3C           lea     eax, [esp+88h+pbData]
.text:0040213B 52                    push    edx                         ; pdwDataLen
.text:0040213C 50                    push    eax                         ; pbData
.text:0040213D 6A 02                 push    2                           ; dwParam
.text:0040213F 51                    push    ecx                         ; hHash
.text:00402140 C7 44 24 38 40 00+    mov     [esp+98h+pdwDataLen], 40h
.text:00402148 FF 15 08 30 40 00     call    ds:CryptGetHashParam        ; read MD5 hash
.text:0040214E 33 F6                 xor     esi, esi
.text:00402150
.text:00402150                   HEX_TO_STR_402150:                      ; CODE XREF: thrd_rtn_38_401EF0+28Bj
.text:00402150 33 D2                 xor     edx, edx                    ; convert hex to string
.text:00402152 8D 44 24 1C           lea     eax, [esp+84h+var_68]
.text:00402156 8A 54 34 38           mov     dl, [esp+esi+84h+pbData]
.text:0040215A 52                    push    edx
.text:0040215B 68 1C 41 40 00        push    offset a02x                 ; "%02X"
.text:00402160 50                    push    eax                         ; this
.text:00402161 E8 E8 0B 00 00        call    ?Format@CString@@QAAXPBDZZ  ; CString::Format(char const *,...)
.text:00402166 83 C4 0C              add     esp, 0Ch
.text:00402169 8D 4C 24 1C           lea     ecx, [esp+84h+var_68]
.text:0040216D 51                    push    ecx
.text:0040216E 8D 4C 24 24           lea     ecx, [esp+88h+var_64]
.text:00402172 E8 CB 0B 00 00        call    ??YCString@@QAEABV0@ABV0@@Z ; CString::operator+=(CString const &)
.text:00402177 46                    inc     esi
.text:00402178 83 FE 10              cmp     esi, 10h
.text:0040217B 7C D3                 jl      short HEX_TO_STR_402150     ; convert hex to string
.text:0040217D
.text:0040217D                   CRYPTO_FAILURE_40217D:                  ; CODE XREF: thrd_rtn_38_401EF0+1DCj
.text:0040217D                                                           ; thrd_rtn_38_401EF0+1FDj ...
.text:0040217D 8B 44 24 0C           mov     eax, [esp+84h+phHash]
.text:00402181 85 C0                 test    eax, eax
.text:00402183 74 07                 jz      short loc_40218C
.text:00402185 50                    push    eax                         ; hHash
.text:00402186 FF 15 0C 30 40 00     call    ds:CryptDestroyHash
.text:0040218C
.text:0040218C                   loc_40218C:                             ; CODE XREF: thrd_rtn_38_401EF0+293j
.text:0040218C 8B 44 24 14           mov     eax, [esp+84h+phProv]
.text:00402190 85 C0                 test    eax, eax
.text:00402192 74 09                 jz      short loc_40219D
.text:00402194 6A 00                 push    0                           ; dwFlags
.text:00402196 50                    push    eax                         ; hProv
.text:00402197 FF 15 10 30 40 00     call    ds:CryptReleaseContext
.text:0040219D
.text:0040219D                   loc_40219D:                             ; CODE XREF: thrd_rtn_38_401EF0+2A2j
.text:0040219D 8B 54 24 18           mov     edx, [esp+84h+hash_6C]
.text:004021A1 8B 44 24 20           mov     eax, [esp+84h+var_64]
.text:004021A5 52                    push    edx                         ; unsigned __int8 *
.text:004021A6 50                    push    eax                         ; unsigned __int8 *
.text:004021A7 FF 15 28 31 40 00     call    ds:_mbscmp                  ; compare hashes
.text:004021AD 83 C4 08              add     esp, 8
.text:004021B0 85 C0                 test    eax, eax
.text:004021B2 75 0A                 jnz     short END_4021BE
.text:004021B4 C7 05 CC 42 40 00+    mov     DBG_FLAG_4042CC, 13h        ; if they are equeal, enable flag!
.text:004021BE
.text:004021BE                   END_4021BE:                             ; CODE XREF: thrd_rtn_38_401EF0+178j
.....
```

Let's decompile that:
```c
	Start threads #37 and #39
	
	if( strlen(F) > 0 )
	{
		for(i=0; i<strlen(F); ++i)
		   F[i] ^= B_byte;

		b = 0;
		
		for(i=0; i<strlen(F); ++i)
		   b ^= F[i];
	   
		b = b^2 + is_dbg;			// is_dbg must not be 2 (=1)
		
		if( is_dbg != 2 )
		{
			if( strlen(H) > 0 )
			{
				for(i=0; i<strlen(H); i++)
				   H[i] ^= b;			   
			}

		if( md5(H) == "FBC4A31E4E17D829CA2242B2F893481B") 
			is_dbg = 19;			// success!	
		}
	}
```		
___
**Thread routine #39 (0x402230):**
This is the last piece of our puzzle. Let's decompile it:
```c
	Start threads #37 and #38

	for( ;; )
	{
		Sleep(1000);
		Start thread #38

		if program being debugged then
			is_dbg = 2 
  }
```
___
After all these, let's go back to main:

```assembly
.text:00402AF3 83 3D CC 42 40 00+    cmp     DBG_FLAG_4042CC, 13h
.text:00402AFA 75 44                 jnz     short WRONG_402B40
.text:00402AFC 8D 7C 24 14           lea     edi, [esp+44h+var_30]
.text:00402B00 83 C9 FF              or      ecx, 0FFFFFFFFh
.text:00402B03 33 C0                 xor     eax, eax
.text:00402B05 F2 AE                 repne scasb
.text:00402B07 F7 D1                 not     ecx
.text:00402B09 49                    dec     ecx
.text:00402B0A 74 71                 jz      short END_402B7D
.text:00402B0C 8B 1D 18 31 40 00     mov     ebx, ds:printf
.text:00402B12
.text:00402B12                   GOODBOY_402B12:                         ; CODE XREF: _main+1BCj
.text:00402B12 8B 0D CC 42 40 00     mov     ecx, DBG_FLAG_4042CC        ; decrypt "Ok you got it!" and print it
.....
.text:00402B3E EB 3D                 jmp     short END_402B7D
.text:00402B40                   ; ---------------------------------------------------------------------------
.text:00402B40
.text:00402B40                   WRONG_402B40:                           ; CODE XREF: _main+17Aj
```
___
Ok now we have everything we need, except the values of the arrays that we use all this time:
```
A = "\0\0......\0";
B = "c678d6g64307gf4g`b263473ge35b5`9";
D = { 0xEC, 0xFC, 0x9E, 0xB9, 0xFC, 0xB3, 0xAE, 0xFC, 0x92, 0xB3, 0xA8, 0xFC, 0x88, 0xB3, 0xFC, 0x9E,
	  0xB9, 0xF0, 0x88, 0xB4, 0xBD, 0xA8, 0xFC, 0xB5, 0xAF, 0xFC, 0x88, 0xB4, 0xB9, 0xFC, 0x8D, 0xA9,
	  0xB9, 0xAF, 0xA8, 0xB5, 0xB3, 0xB2, 0x00 };
  
E = {0xF5, 0xD0, 0xDF, 0xDC, 0x99, 0xD8, 0xD5, 0xCE, 0xD8, 0xC0, 0xCA, 0x99, 0xD4, 0xD8, 0xD2, 0xDC,
 	 0xCA, 0x99, 0xCC, 0xCA, 0x99, 0xDB, 0xD5, 0xD8, 0xDA, 0xD2, 0x99, 0xD8, 0xD7, 0xDD, 0x99, 0xDB,
	 0xD5, 0xCC, 0xDC, 0x95, 0xD8, 0xD7, 0xDD, 0x99, 0xCD, 0xD1, 0xD6, 0xCA, 0xDC, 0x99, 0xCE, 0xD1,
	 0xDC, 0xCB, 0xDC, 0x99, 0xCD, 0xD1, 0xDC, 0x99, 0xCE, 0xD6, 0xCC, 0xD7, 0xDD, 0x99, 0xD1, 0xD8,
	 0xDD, 0x99, 0xDB, 0xDC, 0xDC, 0xD7, 0x99, 0xCD, 0xD1, 0xDC, 0x99, 0xCA, 0xCD, 0xCB, 0xD6, 0xD7,
	 0xDE, 0xDC, 0xCA, 0xCD, 0x99, 0xCE, 0xD0, 0xD5, 0xD5, 0x99, 0xDB, 0xDC, 0xDA, 0xD6, 0xD4, 0xDC,
	 0x99, 0xD8, 0x99, 0xC9, 0xD5, 0xD8, 0xDA, 0xDC, 0x99, 0xCE, 0xD1, 0xDC, 0xCB, 0xDC, 0x99, 0xCE,
	 0xDC, 0x00 };

F = { "Wx}>JL\\5*#P\x7fWxUd KB%5\"fH"};
	  
G = { 0xDE, 0xF4, 0xF9, 0xFF, 0xE3, 0xAA, 0xAD, 0xFE, 0xA1, 0xFD, 0xAF, 0xA1, 0xAC, 0xAB, 0xAA, 0xAB,
	  0xFA, 0xAC, 0xAD, 0xAB, 0xA0, 0xA0, 0xAD, 0xFE, 0xAD, 0xA9, 0xA0, 0xA9, 0xFE, 0xA9, 0xFA, 0xAE,
	  0xAA, 0xAC, 0xFC, 0xA8, 0xFA, 0xE5, 0x00 };	  
	
H = { 0xFD, 0xC5, 0xFD, 0xE7, 0xC5, 0xE7, 0xC7, 0xE5, 0xC7, 0xDD, 0xE5, 0xDD, 0 };
```
Now let's find the order of the threads:

* First, start threads #0 - #31
* Then start #32	
* \#32 -> #33
* \#33 -> #34
* \#34 -> #35
* \#35 -> #36, #37, #38, #39
* \#36 -> #37, #39
* \#37 -> #38, #39
* \#38 -> #37, #39
* \#39 -> #37, #39

Now we can write donw the actual algorithm (note that array G and thread #36 not really used 
anywhere):
```c
	for( i=0; i<32; ++i)
		flag[i] ^= B[i];

	for(i=0; i<4; ++i) {
		for(b=0, j=0; j<8; ++j)
			b = 2*b + flag[i*8 + j];

		C[i] = b;
	}

	if( C[0] + C[1] + C[2] + C[3] == 0xDC &&
	    C[0] ^ 0x66 == C[1] ^ 0x77 == C[3] ^ 0x6F == C[1] ^ C[2] ^ C[3] )
	{
		dd = (C[0]^0x66 + C[2]^C[1]^C[3] + 2*(C[3]^0x6F)) / 4;
	
		for( b=0, i=0; i<strlen(D); ++i ) D[i] ^= dd;
		for( b=0, i=0; i<strlen(D); ++i ) b ^= D[i];

		b ^= 0xc6;
		for( i=0; i<strlen(E); ++i ) E[i] ^= b;

		for( d=0, i=0; i<strlen(E); ++i ) d ^= E[i];

		B_byte = d^0x5a + d^0x42				// B_byte must be 0x98
		
		for(b=0, i=0; i<strlen(F); ++i)
			b ^= F[i] ^ B_byte;  
		  		
		b = b^2 + 1;							// b must be 0xb6 and is_dbg must be 1

		for(i=0; i<strlen(H); i++)				// b must be 0xb5
		   H[i] ^= b;			   

	   if( md5(H) == "FBC4A31E4E17D829CA2242B2F893481B") 
			is_dbg = 19;						// success!	
		}		
	}
```
After cracking the code (using the python script), we can get some valid flags:
```
Flag: t1yuec5dlxi93fjp5934x19g6wbxicxb
Flag: pumqllrvawxa9ze6wut67mscnda7dkmp
Flag: 8vgh7a14pe6hmdgbtd7e5k2ecmr5alyd
Flag: neg9h9s8dt5gii8hu47czcssl92236ud
Flag: xztvxxy8y481byy2i2z30kfe8zb71p0f
```
___
