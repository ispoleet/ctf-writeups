
##  PlaidCTF 2016 - quite quixotic quest (Reversing 300)
##### 15/04 - 17/02/2016 (48hr)

___
### Description: 
Well yes, it certainly is quite quixotic. (Yes, the flag format is PCTF{} )

___
### Solution

The binary for that challenge was very big. It was not stripped so it was very easy to understand
that it's was the "curl" tool. The program's help was very verbose, so the first thought was to
search for keywords, like "key", "flag", etc.  
```
root@nogirl:~/ctf/plaidctf# ./qqq_ba4356a66c6a0f6802e5cebc3de5c4d1 --help | grep flag
     --pctfkey KEY   Validate KEY as the PlaidCTF flag for this challenge
```
This can narrow down our search a lot. We know what to reverse. When we execute the program we
get the message: "Validating key..." before the "wrong" answer. So, we're looking at which location
this string appears. So we set a breakpoint here:
```
    .text:08052AAC C7 04 24 1B CE 14+    mov     dword ptr [esp], offset aValidatingKey_ ; "Validating key...\n"
```
and we start our analysis. After a while we can realize that the control flow is ROP-like. We have
a very large program (with thousands of gadgets) and we execute a ROP program on top of it. 
Reversing that program is tricky but not that hard.

The hard part here is to realize which instructions are really useful. When we ROP, the gadgets are
not exactly as we want. They usually contain more instructions that do not affect the original
computation.

The first part of the ROP code is to calculate the length of the flag (we return inside strlen).
esi points to the flag in memory. After few dummy gadgets, address of the flag finally goes to edx:
```assembly
    .text:080A2311 89 FA                 mov     edx, edi
```
Then to ecx:
```assembly
    .eh_frame:08174149 8D 0A             lea     ecx, [edx]
    .eh_frame:0817414B C3                retn
```
ebx is the leftover from strlen() and contains the address of the NULL byte of our flag. This we
move it to eax:
```assembly
    .text:0806497B 89 D8                 mov     eax, ebx
    .text:0806497D 5B                    pop     ebx
    .text:0806497E C3                    retn
```
And finally, eax contains the flag length:
```assembly
    .text:080B25F8 29 C8                 sub     eax, ecx
    .text:080B25FA C3                    retn
```
Then we extact the original flag legth (which we can see that is 0x35 = 53):
```assembly
    .text:0804E242 5A                    pop     edx
    .text:0804E243 C3                    retn
```
And we compare them:
```assembly
    .text:08066AA7 29 DA                 sub     edx, ebx
```
Now is the nice part: How we do the if-else condition using ROP? We're at the point that we did the
comparison. If edx = 0 then ZF = 1 and we should continue. Otherwise we should print the "wrong" 
message. After the comparison, eax gets a constant offset (0x94) and ebx becomes zero:
```assembly
    .text:0811A256 58                    pop     eax
    .text:0811A257 C3                    retn 

    .init:0804820A 5B                    pop     ebx
    .init:0804820B C3                    retn
```
Then we do the actual "if" statement:
```assembly
    .text:080AB65E 0F 45 C3              cmovnz  eax, ebx

    .text:080AD35D 89 C7                 mov     edi, eax
    .text:080AD35F 89 D6                 mov     esi, edx
    .text:080AD361 8B 44 24 04           mov     eax, [esp+arg_0]
    .text:080AD365 C3                    retn

    .eh_frame:081887E4 03 E7             add     esp, edi
    .eh_frame:081887E6 01 0A             add     [edx], ecx
    .eh_frame:081887E8 C3                retn
```
If ZF = 1 (flag length matches, then eax will become 0. Otherwise it will remain 0x94). Then this
offset goes to edi, which is addredd to esp at 0x081887E4. Thus the result of the computation will
affect the stack alignment and thus the next ROP gadgets. Obviously if the length of the flag is
not 53, the "wrong" message is displayed. 

After the length check we start doing some calculations to find the location of the last character
of the flag and then we enter in a loop. Let's ignore the initialization and focus on the body. All 
dummy instructions and all returns have been removed:
```assembly
    .eh_frame:08176458 58                pop     eax                        ; double pointer to flag
    .text    :0807BD79 8B 00             mov     eax, [eax]                 ; &flag[0]
    .text    :0807BD7B 5B                pop     ebx                        ; ebx = &sum
    .text    :08067A36 5F                pop     edi                        ; 32
    .text    :080F4821 03 C7             add     eax, edi                   ; &flag[32]
    .text    :0805AEB7 8D 50 E0          lea     edx, [eax-20h]             ; &flag[0]
    .text    :0806626E 5F                pop     edi                        ; 0x7bf00001
    .text    :080F647E 8D 84 EF FF FF 0F+lea     eax, [edi+ebp*8-78F00001h] ; eax = ebp*8
    .eh_frame:08187036 59                pop     ecx                        ; 0
    .text    :080E8F3C 01 C1             add     ecx, eax                   ; ecx = ebp*8
    .text    :080E8F3E 89 C8             mov     eax, ecx                   ; eax = ebp * 8
    .text    :08076215 8D 04 40          lea     eax, [eax+eax*2]           ; eax = ebp * 24 
    .text    :080BDE4F 01 C8             add     eax, ecx                   ; eax = ebp * 32
    .text    :080D1F3E C1 E8 05          shr     eax, 5                     ; eax = ebp

    .text    :080BDFB3 01 D0             add     eax, edx                   ; eax = &flag[ebp]
    .text    :0804EDFC 5B                pop     ebx                        ; 0
    .text    :0805DB7D 01 C3             add     ebx, eax                   ; ebx = &flag[ebp]
    .text    :081148C0 89 D8             mov     eax, ebx                   ; eax = &flag[ebp]
    .text    :080A40C9 0F B6 00          movzx   eax, byte ptr [eax]        ; eax = flag[ebp]
    .eh_frame:08187036 59                pop     ecx                        ; 0
    .text    :080E8F3C 01 C1             add     ecx, eax                   ; ecx = flag[ebp]
    .text    :0804E242 5A                pop     edx                        ; edx = &sum
    .eh_frame:081887E6 01 0A             add     [edx], ecx                 ; sum += flag[ebp]

    /* * * loop condition check * * */
    .text    :080622E8 31 C0             xor     eax, eax                   ; eax = 0
    .text    :0811C47B 5B                pop     ebx                        ; ebx = 0xffffff30
    .eh_frame:0817F8F2 4D                dec     ebp                        ; ebp--
    .text    :080AB65E 0F 45 C3          cmovnz  eax, ebx                   ; 
    .text    :080AD35D 89 C7             mov     edi, eax                   ;
    .eh_frame:081887E4 03 E7             add     esp, edi                   ; if ebp > 0 move esp backwards
``` 
Oooouf! So much work to realize that all this code takes the sum of all characters (except the
first character). That's a bug of the programmer (he counts NULL and forgets flag[0]).

Let's move on:
```assembly
    .text    :080BE6BE C0 0A 5F          ror     byte ptr [edx], 5Fh    ; ror and
    .eh_frame:08178748 D1 02             rol     dword ptr [edx], 1     ; rol sum
    .eh_frame:08187036 59                pop     ecx                    ; ecx = 0x01F9933D
    .eh_frame:08176458 58                pop     eax                    ; eax = 0x081CC444
    .text    :080C54EB 31 0E             xor     [esi], ecx             ; sum ^= 0x01F9933D
    .text    :080B643C 89 D0             mov     eax, edx               ; eax = &sum
    .text    :0807BD79 8B 00             mov     eax, [eax]             ; eax = sum
    .text    :080CCE68 35 FA FF FF C7    xor     eax, 0C7FFFFFAh        ; sum ^ 0x0C7FFFFFA
```

The sum gets ror and rol'ed and xored with 2 keys. Then we return into Curl_md5it and we
calculate the md5 of the sum value:
```assembly
    .text:08091CC0                       public Curl_md5it
    .....
    .text:08091CC0 56                    push    esi
```
Then we XOR the first 4 bytes of the hash with a give constant (0x0x86F4FA3F)
```assembly
    .text:080D6B6C 33 C7                 xor     eax, edi
```
And we compare them against a target value:
```assembly
    .text:080B84D0 3D FF FF FF 5B        cmp     eax, 5BFFFFFFh
    .....
    .eh_frame:08176458 58                    pop     eax        ; 0
    .text    :0811C46B 5B                    pop     ebx        ; 0xFFFDFD1C
    .text    :080AB65E 0F 45 C3              cmovnz  eax, ebx   ; if statement
    .....
```
If the sum is correct, we move on with the next part:
```assembly
    .text    :08100DD4 43                inc     ebx                    ; i++
    .text    :080B1177 42                inc     edx                    ; j++

    /* * * do this every 16 times * * */
    .text    :080FE450 89 D0             mov     eax, edx               ; rewind ebx
    .text    :080FE452 5B                pop     ebx                    ;

    .text    :08061D38 31 C0             xor     eax, eax               ; 
    .text    :0804F005 32 83 C4 30 5B 5E xor     al, [ebx+5E5B30C4h]    ; al = h[i]
    .eh_frame:081768B5 30 02             xor     [edx], al              ; flag[i] ^= h[i]
```

Here we XOR each byte of the flag with the md5 hash. Because flag is much larger than the
hash, hash is repeated. Note here that loop is unfolded; there's no condition check.


The last part is to compare the result against a given string:
```assembly
    .text    :08061D38 31 C0             xor     eax, eax           ; eax = 0
    .eh_frame:08187951 0B 43 0A          or      eax, [ebx+0Ah]     ; eax = next 4 bytes from hash
    .eh_frame:08187036 59                pop     ecx                ; get next 4 bytes
    .text    :080B2608 29 C8             sub     eax, ecx           ; compare
    .text    :0810E47C 09 C2             or      edx, eax           ; if not equal, >0 bits will be set
    .text    :0805D7B4 01 F3             add     ebx, esi           ; ebx += 4 (esi = fixed)
```
If we set a breakpoint at 0x080B2608, we can extract all target string:
```
    0x9B5F4690
    0x17541D0F
    0x5F9E4B1B
    0xCD0C58E0
    0xA95460AC
    0x034F1E1C
    0x6CA02530
    0xE61D02BD
    0xBE5435B4
    0x3B4D1B15
    0x668F7B1D
    0xD81B1AF9
    0xB3646CB4
    0x00000009
```
The final check is to see if edx is zero or not:
```assembly
    .text:080A5190 B8 FF FF FF FF        mov     eax, 0FFFFFFFFh
    .text:0810E435 21 D0                 and     eax, edx
    .text:080AB65E 0F 45 C3              cmovnz  eax, ebx
    ....
```
If the edx is zero then the "right" message is printed, otherwise the "wrong" message is printed.

___
Now we know how the algorithm works. Reversing it is very easy because the hash depends only on the
sum of the flag, so we can easily brute force it. The flag with the minimum sum is:
```
    PCTF{                                               }
```
and the flag with the maximum sum is:
```
    PCTF{~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~}
```
for each possible sum, we check if the first 4 bytes of the hash are 0x5BFFFFFF. If so, we XOR the
hash with the target string and we get the flag: 
    `PCTF{just_a_l1ttle_thing_1_l1ke_t0_call_ropfuscation}`.
    
```
root@nogirl:~/ctf/plaidctf/quite quixotic quest# ./qqq_crack.py 
    Min Key: 0x805
    Max Key: 0x1947
    Target sum found: 0x145f
    Flag found: PCTF{just_a_l1ttle_thing_1_l1ke_t0_call_ropfuscation}
```
___
