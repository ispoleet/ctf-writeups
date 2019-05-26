## CSAW CTF 2016 - hungman (Reversing 125pt)
##### 16/09 - 18/09/2016 (48hr)
___

### Description: 
	key.exe
	
### Solution

This was an easy windows revering one. When we run the program we get the message: 
"?W?h?a?t h?a?p?p?e?n?". A quick search for that string takes us into the following code:
```assembly
.text:00C21224     call    sub_C21620
.text:00C21229     mov     byte ptr [ebp+var_4], 3
.text:00C2122D     mov     eax, [ebp+Dst]
.text:00C21233     mov     eax, [eax+4]
.text:00C21236     test    [ebp+eax+var_118], 6
.text:00C2123E     jz      short loc_C21265
.text:00C21240     mov     ecx, ds:?cerr@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A 
.text:00C21246     mov     edx, offset a?w?h?a?tH?a?p? ; "?W?h?a?t h?a?p?p?e?n?"
.text:00C2124B     push    offset sub_C22C50
.text:00C21250     call    sub_C22A00
.text:00C21255     mov     ecx, eax
.text:00C21257     call    ds:??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QAEAAV01@P6AAAV01@AAV01@@Z@Z ; 
.text:00C2125D     push    0FFFFFFFFh                  ; Code
.text:00C2125F     call    ds:__imp_exit
.text:00C21265 loc_C21265:
```

function sub_C21620() is invoked, and if the value is not 6 this message is not displayed.
Inside this function there's another one:
```assembly
.text:00C216EE     call    sub_C22550
```

Once we enter inside, we can see this interesting thing:
```assembly
.text:00C22587     push    offset aCUsersCsaw2016      ; "C:\\Users\\CSAW2016\\haha\\flag_dir\\fl"...
.text:00C2258C     call    ds:?_Fiopen@std@@YAPAU_iobuf@@PBDHH@Z ; std::_Fiopen(char const *,int,int)
```

Ok. It's obvious. Program tries to open that file. If we create it we can see that we don't get the
"W?h?a?t h?a?p?p?e?n?" message anymore. But this time we get the message: "=W=r=o=n=g=K=e=y=":
```assembly
.text:00C21415     mov     edx, offset aCongratsYouGot ; "Congrats You got it!"
.text:00C2141A     push    offset sub_C22C50
.text:00C2141F     jmp     short loc_C21426
.text:00C21421 ; ---------------------------------------------------------------------------
.text:00C21421
.text:00C21421 WRONG_C21421:                             ; CODE XREF: sub_C21100+238j
.text:00C21421     mov     edx, offset aWRONGKEY       ; "=W=r=o=n=g=K=e=y="
.text:00C21426
```

The critical comparison is here:
```assembly
.text:00C21323     lea     ecx, [ebp+var_54]
.text:00C21326     call    check_flag_4020C0
.text:00C2132B     mov     ecx, ds:?cout@std@@3V?$basic_ostream@DU?$char_traits@D@std@@@1@A
.text:00C21331     push    offset sub_C22C50
.text:00C21336     test    eax, eax
.text:00C21338     jnz     WRONG_C21421
```

Function check_flag_4020C0() must return zero. In order to speed up our process, we 
write some contents in the flag.txt file and we see how they are processed. 
First the flag length is checked. It must be 0x12 (=18) characters long:
```assembly
.text:00C220D7     mov     ebx, [ebp+arg_C]            ; chk first 12 chars
.text:00C220DA     cmp     edi, ebx
.text:00C220DC     mov     edx, ebx
.text:00C220DE     cmovb   edx, edi
.text:00C220E1     test    edx, edx
.text:00C220E3     jz      short WRONG_C22141          ; pw must be 0x12
```

Then the first 12 characters are compared with those from flag.txt:
```assembly
.text:00C220F0 LOOP_1_C220F0:                          ; CODE XREF: check_flag_4020C0+3Fj
.text:00C220F0     mov     eax, [ecx]
.text:00C220F2     cmp     eax, [esi]
.text:00C220F4     jnz     short NEXT_C22106
.text:00C220F6     add     ecx, 4
.text:00C220F9     add     esi, 4
.text:00C220FC     sub     edx, 4
.text:00C220FF     jnb     short LOOP_1_C220F0
.text:00C22101
.text:00C22101 GO_ON_C22101:                           ; CODE XREF: check_flag_4020C0+2Cj
.text:00C22101     cmp     edx, 0FFFFFFFCh
.text:00C22104     jz      short loc_C2213A
```

The comparison is straight forward, so the first part from the flag is: "idg_cni~bjbf". 
Note that there's some code that "decrypts" this string; we don't care about decryption, 
as we can read the decrypted one.

Then we continue manually comparing characters one by one:
```assembly
.text:00C22106 NEXT_C22106:                            ; CODE XREF: check_flag_4020C0+34j
.text:00C22106     mov     al, [ecx]
.text:00C22108     cmp     al, [esi]                   ; flag[12] == 'i'
.text:00C2210A     jnz     short loc_C22133
.text:00C2210C     cmp     edx, 0FFFFFFFDh
.text:00C2210F     jz      short loc_C2213A
.text:00C22111     mov     al, [ecx+1]
.text:00C22114     cmp     al, [esi+1]
.text:00C22117     jnz     short loc_C22133
.text:00C22119     cmp     edx, 0FFFFFFFEh
.text:00C2211C     jz      short loc_C2213A
.text:00C2211E     mov     al, [ecx+2]
.text:00C22121     cmp     al, [esi+2]
.text:00C22124     jnz     short loc_C22133
.text:00C22126     cmp     edx, 0FFFFFFFFh
.text:00C22129     jz      short loc_C2213A
.text:00C2212B     mov     al, [ecx+3]
.text:00C2212E     cmp     al, [esi+3]
.text:00C22131     jz      short loc_C2213A
```

If the flag is **idg_cni~bjbfi|gsxb** then we can pass the checks and get the congratz message.
___