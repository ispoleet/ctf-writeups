## D-CTF 2015 - LBS Checker (Reversing 300)
##### 02/10 - 04/10/2015 (36hr)
___
### Solution

This is a little harder challenge. The goal is to find the password of Administrator. However there
are some checks that don't allow the program do that. The first protection is to see whether
password contains "A". If so, we exit:
```assembly
	.text:00000000004016BE         mov     rax, [rbp+creds_28]
	.text:00000000004016C2         add     rax, 4
	.text:00000000004016C6         mov     edx, 41h                ; int
	.text:00000000004016CB         mov     rcx, rax                ; char *
	.text:00000000004016CE         call    strchr
	.text:00000000004016D3         test    rax, rax                ; if password contains 'A' exit
	.text:00000000004016D6         jz      short loc_4016E2        ; PATCH ME
	.text:00000000004016D8         mov     ecx, 1                  ; int
	.text:00000000004016DD         call    exit
```
Then get_product is called to caclulate a checksum of the username. There are also checks there:
```assembly
	.text:0000000000401A6E get_product proc near                   ; CODE XREF: main+1BD
	.text:0000000000401A6E                                         ; DATA XREF: .pdata:0000000000406060
	.text:0000000000401A6E
	.text:0000000000401A6E prod_18 = dword ptr -18h
	.text:0000000000401A6E len_12  = word ptr -12h
	.text:0000000000401A6E usr_0   = qword ptr  10h
	.text:0000000000401A6E
	.text:0000000000401A6E         push    rbp
	.text:0000000000401A6F         push    rbx
	.text:0000000000401A70         sub     rsp, 18h
	.text:0000000000401A74         lea     rbp, [rsp+80h]
	.text:0000000000401A7C         mov     [rbp-60h+usr_0], rcx
	.text:0000000000401A80         mov     [rbp-60h+len_12], 1
	.text:0000000000401A86         mov     [rbp-60h+prod_18], 1
	.text:0000000000401A8D         mov     ebx, 0
	.text:0000000000401A92         jmp     loc_401B24
	.text:0000000000401A97 ; ---------------------------------------------------------------------------
	.text:0000000000401A97
	.text:0000000000401A97 GET_NEXT_CH_401A97:                     ; CODE XREF: get_product+D6
	.text:0000000000401A97         movsxd  rdx, ebx
	.text:0000000000401A9A         mov     rax, [rbp-60h+usr_0]    ; rax = &usr
	.text:0000000000401A9E         add     rax, rdx
	.text:0000000000401AA1         movzx   eax, byte ptr [rax]
	.text:0000000000401AA4         movsx   eax, al                 ; eax = usr[i]
	.text:0000000000401AA7         mov     edx, [rbp-60h+prod_18]
	.text:0000000000401AAA         imul    eax, edx
	.text:0000000000401AAD         mov     [rbp-60h+prod_18], eax  ; prod *= usr[i]
	.text:0000000000401AB0         cmp     [rbp-60h+prod_18], 7FFFh
	.text:0000000000401AB7         jbe     short LESS_401B09       ; prod < 0x8000?
	.text:0000000000401AB9         mov     ecx, [rbp-60h+prod_18]
	.text:0000000000401ABC         mov     edx, ecx
	.text:0000000000401ABE         mov     rax, rdx
	.text:0000000000401AC1         shl     rax, 0Fh                ; prod << 15
	.text:0000000000401AC5         add     rax, rdx                ; rax = (prod << 15) + prod
	.text:0000000000401AC8         shl     rax, 2                  ; rax = ((prod << 15) + prod) << 2
	.text:0000000000401ACC         add     rax, rdx                ; rax = (((prod << 15) + prod) << 2) + prod
	.text:0000000000401ACF         shr     rax, 20h                ; rax = ((((prod << 15) + prod) << 2) + prod) >> 0x20 = A
	.text:0000000000401AD3         mov     edx, ecx
	.text:0000000000401AD5         sub     edx, eax                ; edx = prod - A
	.text:0000000000401AD7         shr     edx, 1                  ; edx = (prod - A) >> 1
	.text:0000000000401AD9         add     eax, edx                ; eax = A + ((prod - A) >> 1)
	.text:0000000000401ADB         shr     eax, 0Eh                ; eax = (A + ((prod - A) >> 1)) >> 14 = B
	.text:0000000000401ADE         mov     edx, eax
	.text:0000000000401AE0         shl     edx, 0Fh                ; edx = B << 15
	.text:0000000000401AE3         sub     edx, eax                ; edx = (B << 15) - B
	.text:0000000000401AE5         mov     eax, ecx
	.text:0000000000401AE7         sub     eax, edx                ; eax = prod - (B << 15) + B
	.text:0000000000401AE9         movsxd  rcx, ebx                ; rcx = i
	.text:0000000000401AEC         mov     rdx, [rbp-60h+usr_0]
	.text:0000000000401AF0         add     rdx, rcx
	.text:0000000000401AF3         movzx   edx, byte ptr [rdx]
	.text:0000000000401AF6         movsx   edx, dl                 ; edx = usr[i]
	.text:0000000000401AF9         add     eax, edx                ; eax = prod - (B << 15) + B + usr[i]
	.text:0000000000401AFB         mov     [rbp-60h+prod_18], eax  ; prod = prod - (B << 15) + B + usr[i]
	.text:0000000000401AFE         movzx   eax, [rbp-60h+len_12]
	.text:0000000000401B02         add     eax, 1                  ; len++
	.text:0000000000401B05         mov     [rbp-60h+len_12], ax    ; update password_length
	.text:0000000000401B09
	.text:0000000000401B09 LESS_401B09:                            ; CODE XREF: get_product+49
	.text:0000000000401B09         movsxd  rdx, ebx
	.text:0000000000401B0C         mov     rax, [rbp-60h+usr_0]
	.text:0000000000401B10         add     rax, rdx
	.text:0000000000401B13         movzx   eax, byte ptr [rax]
	.text:0000000000401B16         cmp     al, 41h
	.text:0000000000401B18         jnz     short loc_401B21        ; PATCH ME for usr[0]
	.text:0000000000401B1A         mov     eax, 539h
	.text:0000000000401B1F         jmp     short RET_401B5F
	.text:0000000000401B21 ; ---------------------------------------------------------------------------
	.text:0000000000401B21
	.text:0000000000401B21 loc_401B21:                             ; CODE XREF: get_product+AA
	.text:0000000000401B21         add     ebx, 1                  ; i++
	.text:0000000000401B24
	.text:0000000000401B24 loc_401B24:                             ; CODE XREF: get_product+24
	.text:0000000000401B24         movsxd  rdx, ebx
	.text:0000000000401B27         mov     rax, [rbp-60h+usr_0]
	.text:0000000000401B2B         add     rax, rdx
	.text:0000000000401B2E         movzx   eax, byte ptr [rax]     ; eax = usr[i]
	.text:0000000000401B31         test    al, al
	.text:0000000000401B33         jz      short NULL_REACHED_401B4A
	.text:0000000000401B35         movsxd  rdx, ebx
	.text:0000000000401B38         mov     rax, [rbp-60h+usr_0]
	.text:0000000000401B3C         add     rax, rdx
	.text:0000000000401B3F         movzx   eax, byte ptr [rax]
	.text:0000000000401B42         cmp     al, 41h                 ; if usr[i] == 'A' then break
	.text:0000000000401B44         jnz     GET_NEXT_CH_401A97      ; PATCH ME for usr[0]
	.text:0000000000401B4A
	.text:0000000000401B4A NULL_REACHED_401B4A:                    ; CODE XREF: get_product+C5
	.text:0000000000401B4A         movzx   edx, [rbp-60h+len_12]
	.text:0000000000401B4E         lea     rax, password_length    ; password_length = len_12
	.text:0000000000401B55         mov     [rax], edx
	.text:0000000000401B57         movzx   eax, [rbp-60h+len_12]
	.text:0000000000401B5B         imul    eax, [rbp-60h+prod_18]  ; return len * prod
	.text:0000000000401B5F
	.text:0000000000401B5F RET_401B5F:                             ; CODE XREF: get_product+B1
	.text:0000000000401B5F         add     rsp, 18h
	.text:0000000000401B63         pop     rbx
	.text:0000000000401B64         pop     rbp
	.text:0000000000401B65         retn
	.text:0000000000401B65 get_product endp
	.text:0000000000401B65
	.text:0000000000401B66
```
There are 2 checks here:
```assembly
	.text:0000000000401B13         movzx   eax, byte ptr [rax]
	.text:0000000000401B16         cmp     al, 41h
	.text:0000000000401B18         jnz     short loc_401B21        ; PATCH ME for usr[0]
	.text:0000000000401B1A         mov     eax, 539h

	.text:0000000000401B3F         movzx   eax, byte ptr [rax]
	.text:0000000000401B42         cmp     al, 41h                 ; if usr[i] == 'A' then break
	.text:0000000000401B44         jnz     GET_NEXT_CH_401A97      ; PATCH ME for usr[0]
```
We can bypass them by setting a bp at the right locations, and once we hit these breakpoints,
toggle ZF and continue execution. Note that the password_length variable is also set here.
This indicates the right value for the password length. If our password has the right length,
we update product, to the first prime number which is smaller than current product:
```assembly
	.text:000000000040171D         call    set_bit_field           ; last_byte = 0x23
	.text:0000000000401722         mov     rax, [rbp+creds_28]
	.text:0000000000401726         mov     eax, [rax]
	.text:0000000000401728         mov     ecx, eax                ; find the first smaller prime from that number
	.text:000000000040172A         call    first_prime             ; 0x22733
	.text:000000000040172F         mov     edx, eax
	.text:0000000000401731         mov     rax, [rbp+creds_28]
	.text:0000000000401735         mov     [rax], edx
	.text:0000000000401737
````
After that set_bit_field is called which sets last_byte glbal variable to 0x23 (no matter what
the password is). Then we enter in the main loop:
```assembly
	.text:000000000040174C PROC_PWD_CH_40174C:                     ; CODE XREF: main+2A9
	.text:000000000040174C         cmp     [rbp+is_valid_14], 0
	.text:0000000000401751         jz      short WRONG_401796
	.text:0000000000401753         movzx   ecx, [rbp+i_12]
	.text:0000000000401757         movzx   eax, cx                 ; eax = i
	.text:000000000040175A         imul    eax, 0CCCDh             ; eax = i*0xcccd
	.text:0000000000401760         shr     eax, 10h                ; eax = i*0xcccd >> 16
	.text:0000000000401763         mov     edx, eax
	.text:0000000000401765         shr     dx, 2                   ; edx = i*0xcccd >> 18
	.text:0000000000401769         mov     eax, edx                ; eax = i*0xcccd >> 18
	.text:000000000040176B         shl     eax, 2                  ; eax = (i*0xcccd >> 18) << 2
	.text:000000000040176E         add     eax, edx                ; edx = ((i*0xcccd >> 18) << 2) + (i*0xcccd >> 18) = (i*0xcccd >> 18)*5
	.text:0000000000401770         mov     edx, ecx                ; edx = i
	.text:0000000000401772         sub     edx, eax                ; edx = i - (i*0xcccd >> 18)*5
	.text:0000000000401774         movzx   edx, dx
	.text:0000000000401777         movzx   eax, [rbp+i_12]         ; eax = i
	.text:000000000040177B         mov     rcx, [rbp+creds_28]
	.text:000000000040177F         cdqe
	.text:0000000000401781         movzx   eax, byte ptr [rcx+rax+19h]
	.text:0000000000401786         movsx   eax, al                 ; arg2: i - ((i*0xcccd >> 18) << 2) + (i*0xcccd >> 18)
	.text:0000000000401789         mov     ecx, eax                ; arg1: pwd[i]
	.text:000000000040178B         call    cbc_password_check      ; must return 1
	.text:0000000000401790         mov     [rbp+is_valid_14], ax
	.text:0000000000401794         jmp     short INC_i_4017B3      ; last char can be wrong
	.text:0000000000401796 ; ---------------------------------------------------------------------------
	.text:0000000000401796
	.text:0000000000401796 WRONG_401796:                           ; CODE XREF: main+221
	.text:0000000000401796         call    print_wrong
	.text:000000000040179B         mov     ecx, 0BB8h              ; dwMilliseconds
	.text:00000000004017A0         mov     rax, cs:__imp_Sleep
	.text:00000000004017A7         call    rax ; __imp_Sleep
	.text:00000000004017A9         mov     ecx, 0                  ; int
	.text:00000000004017AE         call    exit
	.text:00000000004017B3 ; ---------------------------------------------------------------------------
	.text:00000000004017B3
	.text:00000000004017B3 INC_i_4017B3:                           ; CODE XREF: main+264
	.text:00000000004017B3         movzx   eax, word ptr [rbp-10010b]
	.text:00000000004017B7         add     eax, 1                  ; i++
	.text:00000000004017BA         mov     [rbp+i_12], ax
	.text:00000000004017BE
	.text:00000000004017BE loc_4017BE:                             ; CODE XREF: main+21A
	.text:00000000004017BE         movzx   ebx, [rbp+i_12]
	.text:00000000004017C2         mov     rax, [rbp+creds_28]
	.text:00000000004017C6         add     rax, 19h
	.text:00000000004017CA         mov     rcx, rax                ; char *
	.text:00000000004017CD         call    strlen                  ; strlen(usr)
	.text:00000000004017D2         sub     rax, 1
	.text:00000000004017D6         cmp     rbx, rax
	.text:00000000004017D9         jb      PROC_PWD_CH_40174C
```
For each character we call cbc_password_check() with 2 arguments. The first is the current character from
username and the second and iterator from modulo 5. As long as cbc_password_check() returns 1, we are ok.
Once it returns 0 we print the wrong password message. Note in this code that the last character of the 
password can be wrong, without producing any errors. The last thing to do, is to check the last character
against 0x23 (the value set_bit_field sets). If they are equal we get the "good boy" message.
```assembly
	.text:00000000004017DF         mov     rax, [rbp+creds_28]     ; loop ends
	.text:00000000004017E3         add     rax, 19h
	.text:00000000004017E7         mov     rcx, rax                ; char *
	.text:00000000004017EA         call    strlen
	.text:00000000004017EF         lea     rdx, [rax-1]            ; rdx = strlen(pwd) - 1
	.text:00000000004017F3         mov     rax, [rbp+creds_28]
	.text:00000000004017F7         movzx   eax, byte ptr [rax+rdx+19h]
	.text:00000000004017FC         movsx   eax, al                 ; al = pwd[strlen(pwd) - 1]
	.text:00000000004017FF         mov     ecx, eax
	.text:0000000000401801         call    cmp_last_byte
	.text:0000000000401806         test    eax, eax
	.text:0000000000401808         jz      short NO_40180E
	.text:000000000040180A         add     [rbp+var_18], 1
	.text:000000000040180E
	.text:000000000040180E NO_40180E:
	.text:000000000040180E         cmp     [rbp+var_18], 0
	.text:0000000000401812         jz      short loc_401819
	.text:0000000000401814         call    print_right
```
	
	
Everything's fine so far, but we miss one thing: cbc_password_check(). This function initializes
a constant mapping array first which maps a printable character to another. Then based on the 
second argument, we execute one of the following statements:
```assembly
	.text:0000000000401C53         cmp     [rbp+10h+loc_8], 0
	.text:0000000000401C58         jnz     short LOC_NOT_0_401C9B
	.text:0000000000401C5A         call    _1st
	.text:0000000000401C5F         mov     ebx, eax
	.text:0000000000401C61         movzx   edx, [rbp+10h+loc_8]    ; edx = loc
	.text:0000000000401C65         mov     eax, edx
	.text:0000000000401C67         shl     eax, 2                  ; eax = loc << 2
	.text:0000000000401C6A         add     eax, edx
	.text:0000000000401C6C         add     eax, eax                ; eax = loc*10
	.text:0000000000401C6E         cdqe
	.text:0000000000401C70         movzx   eax, byte ptr [rbp+rax+10h+var_70] ; eax = map[ loc*6 ]
	.text:0000000000401C75         movsx   eax, al
	.text:0000000000401C78         mov     ecx, eax
	.text:0000000000401C7A         call    soad                    ; soad( map[ loc*6 ] )
	.text:0000000000401C7F         add     eax, ebx                ; eax = soad( map[loc*6] ) + _1st()
	.text:0000000000401C81         cdqe
	.text:0000000000401C83         movzx   eax, byte ptr [rbp+rax+10h+var_70] ; eax = map[ soad( map[loc*6] ) + _1st() ]
	.text:0000000000401C88         cmp     al, [rbp+10h+pwd_ch_0]  ; eax == pwd[i] ?
	.text:0000000000401C8B         jnz     WRONG_401DAD            ; if not return 0
	.text:0000000000401C91         mov     eax, 1
	.text:0000000000401C96         jmp     END_401DB2
```		
If loc_8 is 0, we execute this code. If it's 1 we execute the same code but we call _2nd() instead of 
_1st(). If it's 3, we do the same with _3rd, if it's 4 with _4th and if it's 5 with _5th. The only
difference between functions _1st, _2nd, _3rd, _4th and _5th is the value that they add at the end.
Thus, we can merge all these function in a single, and use loc8 as argument. After that we can
decompile this function:
```c
int cbc_password(int loc)
{
	char map[] = {"aBcDeFgHiJkLmNoPqRsTuVwXyZ1!2@3#4$5%6^7&8*9(0)_AbCdEfGhIjKlMnOpQrStUvWxYz[]{}-+=,.'><\0"};
	
	return map[ soad( map[loc*10] ) + _ith(loc + 1) ];
}	
```
In order to get the password, all we have to do is to set breakpoints before each check:
```assembly
	.text:0000000000401C88         cmp     al, [rbp+10h+pwd_ch_0]  ; eax == pwd[i] ?
	.text:0000000000401CD0         cmp     al, [rbp+10h+pwd_ch_0]
	.text:0000000000401D18         cmp     al, [rbp+10h+pwd_ch_0]
	.text:0000000000401D60         cmp     al, [rbp+10h+pwd_ch_0]
	.text:0000000000401DA1         cmp     al, [rbp+10h+pwd_ch_0]
```	
The value of al, will tell us the right password character.
For completeness we will continue analysis. Let's see _1st function:
```assembly
	.text:0000000000401DD1 _1st    proc near  
	.text:0000000000401DD1
	.text:0000000000401DD1 prod_8  = dword ptr -8
	.text:0000000000401DD1 var_4   = dword ptr -4
	.text:0000000000401DD1
	.text:0000000000401DD1         push    rbp
	.text:0000000000401DD2         mov     rbp, rsp
	.text:0000000000401DD5         sub     rsp, 10h
	.text:0000000000401DD9         mov     [rbp+var_4], 0
	.text:0000000000401DE0         lea     rax, code
	.text:0000000000401DE7         mov     eax, [rax]
	.text:0000000000401DE9         mov     [rbp+prod_8], eax
	.text:0000000000401DEC         jmp     short loc_401E2F        ; prime == 0 ?
	.text:0000000000401DEE ; ---------------------------------------------------------------------------
	.text:0000000000401DEE
	.text:0000000000401DEE loc_401DEE:                             ; CODE XREF: _1st+62
	.text:0000000000401DEE         mov     ecx, [rbp+prod_8]
	.text:0000000000401DF1         mov     edx, 66666667h
	.text:0000000000401DF6         mov     eax, ecx
	.text:0000000000401DF8         imul    edx                     ; eax = prod * 0x66666667 = L,  edx = H (high 32 bits)
	.text:0000000000401DFA         sar     edx, 2                  ; signed edx = H >> 2
	.text:0000000000401DFD         mov     eax, ecx
	.text:0000000000401DFF         sar     eax, 1Fh                ; signed eax = prod >> 31 (=0 prime is small)
	.text:0000000000401E02         sub     edx, eax
	.text:0000000000401E04         mov     eax, edx
	.text:0000000000401E06         shl     eax, 2                  ; eax = (H >> 2) << 2
	.text:0000000000401E09         add     eax, edx                ; eax = ((H >> 2) << 2) + (H >> 2) = 5*(H >> 2)
	.text:0000000000401E0B         add     eax, eax                ; eax = 10*(H >> 2)
	.text:0000000000401E0D         sub     ecx, eax                ; ecx = prod - 10*(H >> 2)
	.text:0000000000401E0F         mov     edx, ecx
	.text:0000000000401E11         add     [rbp+var_4], edx        ; v4 += prod - 10*(H >> 2)
	.text:0000000000401E14         mov     ecx, [rbp+prod_8]
	.text:0000000000401E17         mov     edx, 66666667h
	.text:0000000000401E1C         mov     eax, ecx
	.text:0000000000401E1E         imul    edx                     ; eax = prod * 0x66666667 = L,  edx = H (high 32 bits)
	.text:0000000000401E20         sar     edx, 2                  ; edx = H >> 2
	.text:0000000000401E23         mov     eax, ecx
	.text:0000000000401E25         sar     eax, 1Fh                ; eax = 0 (=prod is small)
	.text:0000000000401E28         sub     edx, eax
	.text:0000000000401E2A         mov     eax, edx
	.text:0000000000401E2C         mov     [rbp+prod_8], eax       ; prod = A
	.text:0000000000401E2F
	.text:0000000000401E2F loc_401E2F:                             ; CODE XREF: _1st+1B
	.text:0000000000401E2F         cmp     [rbp+prod_8], 0         ; prime == 0 ?
	.text:0000000000401E33         jnz     short loc_401DEE        ; if not continue loop
	.text:0000000000401E35         mov     eax, [rbp+var_4]
	.text:0000000000401E38         add     eax, 1
	.text:0000000000401E3B         add     rsp, 10h
	.text:0000000000401E3F         pop     rbp
	.text:0000000000401E40         retn
	.text:0000000000401E40 _1st    endp
```
The only difference with _2nd, etc. functions is the at line:
```
	.text:0000000000401E38         add     eax, 1	
```
Let's decompile all these function now:
```c
	int _ith( int idx )
	{
		int prod = (int) product;
		int L, H, v4 = 0;
		
		while( prod > 0 )
		{
			H = ((long long int)prod * 0x66666667) >> 32;	// high 32 bits
			L = prod * 0x66666667;							// low  32 bits

			v4 += prod - 10*(H >> 2);
			prod = H >> 2;
		}

		return v4 + idx;
	}
```
The last function which we have to analyze is soad:
```assembly
	.text:0000000000402262 soad    proc near                       ; CODE XREF: cbc_password_check+DA
	.text:0000000000402262
	.text:0000000000402262 var_4   = dword ptr -4
	.text:0000000000402262 ch_0    = byte ptr  10h
	.text:0000000000402262
	.text:0000000000402262         push    rbp
	.text:0000000000402263         mov     rbp, rsp
	.text:0000000000402266         sub     rsp, 10h
	.text:000000000040226A         mov     eax, ecx
	.text:000000000040226C         mov     [rbp+ch_0], al
	.text:000000000040226F         mov     [rbp+var_4], 0
	.text:0000000000402276         jmp     short loc_4022C2        ; character == 0 ?
	.text:0000000000402278 ; ---------------------------------------------------------------------------
	.text:0000000000402278
	.text:0000000000402278 loc_402278:                             ; CODE XREF: soad+64
	.text:0000000000402278         movzx   ecx, [rbp+ch_0]
	.text:000000000040227C         movsx   ax, cl
	.text:0000000000402280         imul    eax, 67h                ; eax = ch * 0x67
	.text:0000000000402283         shr     ax, 8                   ; eax = (ch * 0x67) >> 8
	.text:0000000000402287         mov     edx, eax
	.text:0000000000402289         sar     dl, 2                   ; edx = (char)((ch * 0x67) >> 8) >> 2
	.text:000000000040228C         mov     eax, ecx
	.text:000000000040228E         sar     al, 7                   ; eax = ch >> 7 (=0 as we only deal with printable ASCII)
	.text:0000000000402291         sub     edx, eax
	.text:0000000000402293         mov     eax, edx                ; A = (char)((ch * 0x67) >> 8) >> 2
	.text:0000000000402295         shl     eax, 2                  ; eax = A << 2
	.text:0000000000402298         add     eax, edx                ; eax = A*5
	.text:000000000040229A         add     eax, eax
	.text:000000000040229C         sub     ecx, eax                ; ecx = ch - 10*A
	.text:000000000040229E         mov     edx, ecx
	.text:00000000004022A0         movsx   eax, dl
	.text:00000000004022A3         add     [rbp+var_4], eax        ; v4 += ch - 10*A
	.text:00000000004022A6         movzx   eax, [rbp+ch_0]
	.text:00000000004022AA         movsx   dx, al
	.text:00000000004022AE         imul    edx, 67h                ; edx = (ch * 0x67) >> 8
	.text:00000000004022B1         shr     dx, 8
	.text:00000000004022B5         sar     dl, 2                   ; (ch * 0x67) >> 10
	.text:00000000004022B8         sar     al, 7                   ; al = 0
	.text:00000000004022BB         sub     edx, eax
	.text:00000000004022BD         mov     eax, edx
	.text:00000000004022BF         mov     [rbp+ch_0], al          ; ch = (ch * 0x67) >> 10
	.text:00000000004022C2
	.text:00000000004022C2 loc_4022C2:                             ; CODE XREF: soad+14
	.text:00000000004022C2         cmp     [rbp+ch_0], 0           ; character == 0 ?
	.text:00000000004022C6         jnz     short loc_402278
	.text:00000000004022C8         mov     eax, [rbp+var_4]        ; return v4
	.text:00000000004022CB         add     rsp, 10h
	.text:00000000004022CF         pop     rbp
	.text:00000000004022D0         retn
	.text:00000000004022D0 soad    endp
	.text:00000000004022D0
```
Not too hard, right? Here's the decompiled version:
```c
	int soad( char ch )
	{
		int v4 = 0;

		while( ch > 0 )
		{
			v4 += ch - 10*(((ch * 0x67) >> 8) >> 2);
			ch = (ch * 0x67) >> 10;
		}

		return v4;
	}
```
Now that we have all pieces together we can reconstruct the whole algorithm. I created this C program
that generates a valid password for each username. Once we execute it, we get the password:
```
	username: Administrator
	product : 22733
	pwd len : 12
	password: #y1y3#y1y3##
```


___