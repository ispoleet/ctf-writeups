
## Teaser CONFidence CTF 2019 - watchmen (Reversing 264)
##### 16/03 - 17/03/2019 (24hr)
___

### Description: 

Elementary, my dear Watson.


The flag format is: `p4{letters_digits_and_special_characters}`.
If you have any questions, you can find our team-members at the IRC channel #p4team @ freenode.

___

### Solution

Binary structure is very simple: It reads the flag, and invokes `checkFlag` to check
whether flag is correct. `checkFlag` consists of `831` "blocks". Each block checks an arbitrary
bit from the flag. In order to move on the next check, the previous check must be passed.

Each block looks like this:
```Assembly
.text:00005613AA991BB4        mov     rax, [rbp+var_18]
.text:00005613AA991BB8        add     rax, 40h
.text:00005613AA991BBC        movzx   eax, byte ptr [rax]
.text:00005613AA991BBF        movsx   eax, al
.text:00005613AA991BC2        sar     eax, 2
.text:00005613AA991BC5        and     eax, 1
.text:00005613AA991BC8        mov     [rbp+var_4], eax
.text:00005613AA991BCB        mov     eax, [rbp+var_4]
.text:00005613AA991BCE        mov     edi, eax
.text:00005613AA991BD0        call    function1
.text:00005613AA991BD5        test    eax, eax
.text:00005613AA991BD7        jz      short loc_5613AA991BE3
.text:00005613AA991BD9        mov     eax, 0
.text:00005613AA991BDE        jmp     locret_5613AA99B284
```

A specific bit is passed in `function1` where it checks whether bit is correct or not.
`function1` is the following:
```Assembly
.text:00005613AA8C3C43        push    rbp
.text:00005613AA8C3C44        mov     rbp, rsp
.text:00005613AA8C3C47        push    rbx
.text:00005613AA8C3C48        mov     [rbp+var_1C], edi
.text:00005613AA8C3C4B        mov     eax, [rbp+var_1C]
.text:00005613AA8C3C4E        mov     eax, eax
.text:00005613AA8C3C50        mov     ebx, 1
.text:00005613AA8C3C55        or      ebx, 8
.text:00005613AA8C3C58        and     ebx, 1
.text:00005613AA8C3C5B        or      ebx, 6
.text:00005613AA8C3C5E        and     ebx, 1
.text:00005613AA8C3C61        or      ebx, 6
.text:00005613AA8C3C64        and     ebx, 1
.text:00005613AA8C3C67        xor     ecx, ecx
.text:00005613AA8C3C69        xor     ecx, 1
.text:00005613AA8C3C6C        xor     ecx, 2
.text:00005613AA8C3C6F        xor     ecx, 1
.text:00005613AA8C3C72        xor     ecx, 4
.text:00005613AA8C3C75        xor     ecx, 0
.text:00005613AA8C3C78        xor     ecx, 6
.text:00005613AA8C3C7B        xor     ecx, 5
.text:00005613AA8C3C7E        xor     ecx, 2
.text:00005613AA8C3C81        xor     ecx, 1
.text:00005613AA8C3C84        xor     ecx, 6
.text:00005613AA8C3C87        xor     ecx, 0
.text:00005613AA8C3C8A        or      ebx, ecx
.text:00005613AA8C3C8C        and     ebx, 1
.text:00005613AA8C3C8F        and     ebx, 9
.text:00005613AA8C3C92        and     ebx, 9
.text:00005613AA8C3C95        and     ebx, 5
.text:00005613AA8C3C98        and     ebx, 5
.text:00005613AA8C3C9B        xor     ecx, ecx
.text:00005613AA8C3C9D        xor     ecx, 7
.text:00005613AA8C3CA0        xor     ecx, 3
.text:00005613AA8C3CA3        xor     ecx, 4
.text:00005613AA8C3CA6        xor     ecx, 5
.text:00005613AA8C3CA9        xor     ecx, 3
.text:00005613AA8C3CAC        xor     ecx, 2
.text:00005613AA8C3CAF        xor     ecx, 4
.text:00005613AA8C3CB2        xor     ecx, 0
.text:00005613AA8C3CB5        xor     ecx, 9
.text:00005613AA8C3CB8        xor     ecx, 9
.text:00005613AA8C3CBB        xor     ecx, 0
.text:00005613AA8C3CBE        or      ebx, ecx
.text:00005613AA8C3CC0        and     ebx, 1
.text:00005613AA8C3CC3        and     ebx, 7
.text:00005613AA8C3CC6        xor     ecx, ecx
.text:00005613AA8C3CC8        xor     ecx, 7
.text:00005613AA8C3CCB        xor     ecx, 9
.text:00005613AA8C3CCE        xor     ecx, 2
.text:00005613AA8C3CD1        xor     ecx, 3
.text:00005613AA8C3CD4        xor     ecx, 7
.text:00005613AA8C3CD7        xor     ecx, 1
.text:00005613AA8C3CDA        xor     ecx, 0
.text:00005613AA8C3CDD        xor     ecx, 7
.text:00005613AA8C3CE0        xor     ecx, 2
.text:00005613AA8C3CE3        xor     ecx, 4
.text:00005613AA8C3CE6        xor     ecx, 8
.text:00005613AA8C3CE9        or      ebx, ecx
.text:00005613AA8C3CEB        and     ebx, 1
.text:00005613AA8C3CEE        xor     ecx, ecx
.text:00005613AA8C3CF0        xor     ecx, 9
.text:00005613AA8C3CF3        xor     ecx, 6
.text:00005613AA8C3CF6        xor     ecx, 2
.text:00005613AA8C3CF9        xor     ecx, 1
.text:00005613AA8C3CFC        xor     ecx, 2
.text:00005613AA8C3CFF        xor     ecx, 5
.text:00005613AA8C3D02        xor     ecx, 0
.text:00005613AA8C3D05        xor     ecx, 8
.text:00005613AA8C3D08        xor     ecx, 3
.text:00005613AA8C3D0B        xor     ecx, 6
.text:00005613AA8C3D0E        xor     ecx, 6
.text:00005613AA8C3D11        or      ebx, ecx
.text:00005613AA8C3D13        and     ebx, 1
.text:00005613AA8C3D16        and     ebx, 7
.text:00005613AA8C3D19        or      ebx, 2
.text:00005613AA8C3D1C        and     ebx, 1
.text:00005613AA8C3D1F        or      ebx, 0
.text:00005613AA8C3D22        and     ebx, 1
.text:00005613AA8C3D25        xor     ecx, ecx
.text:00005613AA8C3D27        xor     ecx, 2
.text:00005613AA8C3D2A        xor     ecx, 9
.text:00005613AA8C3D2D        xor     ecx, 2
.text:00005613AA8C3D30        xor     ecx, 9
.text:00005613AA8C3D33        xor     ecx, 6
.text:00005613AA8C3D36        xor     ecx, 8
.text:00005613AA8C3D39        xor     ecx, 9
.text:00005613AA8C3D3C        xor     ecx, 1
.text:00005613AA8C3D3F        xor     ecx, 7
.text:00005613AA8C3D42        xor     ecx, 9
.text:00005613AA8C3D45        xor     ecx, 8
.text:00005613AA8C3D48        or      ebx, ecx
.text:00005613AA8C3D4A        and     ebx, 1
.text:00005613AA8C3D4D        or      ebx, 6
.text:00005613AA8C3D50        and     ebx, 1
.text:00005613AA8C3D53        or      ebx, 8
.text:00005613AA8C3D56        and     ebx, 1
.text:00005613AA8C3D59        xor     ecx, ecx
.text:00005613AA8C3D5B        xor     ecx, 5
.text:00005613AA8C3D5E        xor     ecx, 8
.text:00005613AA8C3D61        xor     ecx, 5
.text:00005613AA8C3D64        xor     ecx, 3
.text:00005613AA8C3D67        xor     ecx, 1
.text:00005613AA8C3D6A        xor     ecx, 8
.text:00005613AA8C3D6D        xor     ecx, 3
.text:00005613AA8C3D70        xor     ecx, 4
.text:00005613AA8C3D73        xor     ecx, 9
.text:00005613AA8C3D76        xor     ecx, 1
.text:00005613AA8C3D79        xor     ecx, 0Dh
.text:00005613AA8C3D7C        or      ebx, ecx
.text:00005613AA8C3D7E        and     ebx, 1
.text:00005613AA8C3D81        or      ebx, 2
.text:00005613AA8C3D84        and     ebx, 1
.text:00005613AA8C3D87        and     ebx, 9
.text:00005613AA8C3D8A        or      ebx, 2
.text:00005613AA8C3D8D        and     ebx, 1
.text:00005613AA8C3D90        or      ebx, 4
.text:00005613AA8C3D93        and     ebx, 1
.text:00005613AA8C3D96        xor     ecx, ecx
.text:00005613AA8C3D98        xor     ecx, 6
.text:00005613AA8C3D9B        xor     ecx, 8
.text:00005613AA8C3D9E        xor     ecx, 2
.text:00005613AA8C3DA1        xor     ecx, 1
.text:00005613AA8C3DA4        xor     ecx, 2
.text:00005613AA8C3DA7        xor     ecx, 4
.text:00005613AA8C3DAA        xor     ecx, 3
.text:00005613AA8C3DAD        xor     ecx, 1
.text:00005613AA8C3DB0        xor     ecx, 6
.text:00005613AA8C3DB3        xor     ecx, 4
.text:00005613AA8C3DB6        xor     ecx, 0Bh
.text:00005613AA8C3DB9        or      ebx, ecx
.text:00005613AA8C3DBB        and     ebx, 1
.text:00005613AA8C3DBE        xor     ecx, ecx
.text:00005613AA8C3DC0        xor     ecx, 0
.text:00005613AA8C3DC3        xor     ecx, 4
.text:00005613AA8C3DC6        xor     ecx, 7
.text:00005613AA8C3DC9        xor     ecx, 9
.text:00005613AA8C3DCC        xor     ecx, 6
.text:00005613AA8C3DCF        xor     ecx, 0
.text:00005613AA8C3DD2        xor     ecx, 5
.text:00005613AA8C3DD5        xor     ecx, 5
.text:00005613AA8C3DD8        xor     ecx, 1
.text:00005613AA8C3DDB        xor     ecx, 2
.text:00005613AA8C3DDE        xor     ecx, 0Fh
.text:00005613AA8C3DE1        or      ebx, ecx
.text:00005613AA8C3DE3        and     ebx, 1
.text:00005613AA8C3DE6        and     ebx, 9
.text:00005613AA8C3DE9        and     ebx, 7
.text:00005613AA8C3DEC        xor     ecx, ecx
.text:00005613AA8C3DEE        xor     ecx, 4
.text:00005613AA8C3DF1        xor     ecx, 0
.text:00005613AA8C3DF4        xor     ecx, 6
.text:00005613AA8C3DF7        xor     ecx, 4
.text:00005613AA8C3DFA        xor     ecx, 6
.text:00005613AA8C3DFD        xor     ecx, 3
.text:00005613AA8C3E00        xor     ecx, 1
.text:00005613AA8C3E03        xor     ecx, 3
.text:00005613AA8C3E06        xor     ecx, 7
.text:00005613AA8C3E09        xor     ecx, 7
.text:00005613AA8C3E0C        xor     ecx, 1
.text:00005613AA8C3E0F        or      ebx, ecx
.text:00005613AA8C3E11        and     ebx, 1
.text:00005613AA8C3E14        or      ebx, 4
.text:00005613AA8C3E17        and     ebx, 1
.text:00005613AA8C3E1A        or      ebx, 0
.text:00005613AA8C3E1D        and     ebx, 1
.text:00005613AA8C3E20        and     ebx, 1
.text:00005613AA8C3E23        or      ebx, 8
.text:00005613AA8C3E26        and     ebx, 1
.text:00005613AA8C3E29        and     ebx, 5
.text:00005613AA8C3E2C        or      ebx, 2
.text:00005613AA8C3E2F        and     ebx, 1
.text:00005613AA8C3E32        xor     ecx, ecx
.text:00005613AA8C3E34        xor     ecx, 6
.text:00005613AA8C3E37        xor     ecx, 0
.text:00005613AA8C3E3A        xor     ecx, 4
.text:00005613AA8C3E3D        xor     ecx, 5
.text:00005613AA8C3E40        xor     ecx, 3
.text:00005613AA8C3E43        xor     ecx, 8
.text:00005613AA8C3E46        xor     ecx, 9
.text:00005613AA8C3E49        xor     ecx, 5
.text:00005613AA8C3E4C        xor     ecx, 3
.text:00005613AA8C3E4F        xor     ecx, 5
.text:00005613AA8C3E52        xor     ecx, 6
.text:00005613AA8C3E55        or      ebx, ecx
.text:00005613AA8C3E57        and     ebx, 1
.text:00005613AA8C3E5A        and     ebx, 5
.text:00005613AA8C3E5D        or      ebx, 6
.text:00005613AA8C3E60        and     ebx, 1
.text:00005613AA8C3E63        and     ebx, 1
.text:00005613AA8C3E66        or      ebx, 8
.text:00005613AA8C3E69        and     ebx, 1
.text:00005613AA8C3E6C        xor     ecx, ecx
.text:00005613AA8C3E6E        xor     ecx, 6
.text:00005613AA8C3E71        xor     ecx, 9
.text:00005613AA8C3E74        xor     ecx, 0
.text:00005613AA8C3E77        xor     ecx, 1
.text:00005613AA8C3E7A        xor     ecx, 3
.text:00005613AA8C3E7D        xor     ecx, 0
.text:00005613AA8C3E80        xor     ecx, 7
.text:00005613AA8C3E83        xor     ecx, 5
.text:00005613AA8C3E86        xor     ecx, 9
.text:00005613AA8C3E89        xor     ecx, 2
.text:00005613AA8C3E8C        xor     ecx, 4
.text:00005613AA8C3E8F        or      ebx, ecx
.text:00005613AA8C3E91        and     ebx, 1
.text:00005613AA8C3E94        and     ebx, 1
.text:00005613AA8C3E97        or      ebx, 6
.text:00005613AA8C3E9A        and     ebx, 1
.text:00005613AA8C3E9D        or      ebx, 2
.text:00005613AA8C3EA0        and     ebx, 1
.text:00005613AA8C3EA3        and     ebx, 1
.text:00005613AA8C3EA6        and     ebx, 9
.text:00005613AA8C3EA9        xor     ecx, ecx
.text:00005613AA8C3EAB        xor     ecx, 3
.text:00005613AA8C3EAE        xor     ecx, 7
.text:00005613AA8C3EB1        xor     ecx, 0
.text:00005613AA8C3EB4        xor     ecx, 3
.text:00005613AA8C3EB7        xor     ecx, 0
.text:00005613AA8C3EBA        xor     ecx, 2
.text:00005613AA8C3EBD        xor     ecx, 2
.text:00005613AA8C3EC0        xor     ecx, 6
.text:00005613AA8C3EC3        xor     ecx, 1
.text:00005613AA8C3EC6        xor     ecx, 0
.text:00005613AA8C3EC9        xor     ecx, 0
.text:00005613AA8C3ECC        or      ebx, ecx
.text:00005613AA8C3ECE        and     ebx, 1
.text:00005613AA8C3ED1        xor     ecx, ecx
.text:00005613AA8C3ED3        xor     ecx, 9
.text:00005613AA8C3ED6        xor     ecx, 1
.text:00005613AA8C3ED9        xor     ecx, 7
.text:00005613AA8C3EDC        xor     ecx, 5
.text:00005613AA8C3EDF        xor     ecx, 1
.text:00005613AA8C3EE2        xor     ecx, 8
.text:00005613AA8C3EE5        xor     ecx, 9
.text:00005613AA8C3EE8        xor     ecx, 3
.text:00005613AA8C3EEB        xor     ecx, 1
.text:00005613AA8C3EEE        xor     ecx, 2
.text:00005613AA8C3EF1        xor     ecx, 0Ah
.text:00005613AA8C3EF4        or      ebx, ecx
.text:00005613AA8C3EF6        and     ebx, 1
.text:00005613AA8C3EF9        and     ebx, 9
.text:00005613AA8C3EFC        xor     ecx, ecx
.text:00005613AA8C3EFE        xor     ecx, 4
.text:00005613AA8C3F01        xor     ecx, 0
.text:00005613AA8C3F04        xor     ecx, 5
.text:00005613AA8C3F07        xor     ecx, 5
.text:00005613AA8C3F0A        xor     ecx, 3
.text:00005613AA8C3F0D        xor     ecx, 8
.text:00005613AA8C3F10        xor     ecx, 9
.text:00005613AA8C3F13        xor     ecx, 3
.text:00005613AA8C3F16        xor     ecx, 1
.text:00005613AA8C3F19        xor     ecx, 9
.text:00005613AA8C3F1C        xor     ecx, 0Dh
.text:00005613AA8C3F1F        or      ebx, ecx
.text:00005613AA8C3F21        and     ebx, 1
.text:00005613AA8C3F24        and     ebx, 5
.text:00005613AA8C3F27        and     ebx, 9
.text:00005613AA8C3F2A        xor     ecx, ecx
.text:00005613AA8C3F2C        xor     ecx, 0
.text:00005613AA8C3F2F        xor     ecx, 5
.text:00005613AA8C3F32        xor     ecx, 5
.text:00005613AA8C3F35        xor     ecx, 5
.text:00005613AA8C3F38        xor     ecx, 1
.text:00005613AA8C3F3B        xor     ecx, 7
.text:00005613AA8C3F3E        xor     ecx, 6
.text:00005613AA8C3F41        xor     ecx, 6
.text:00005613AA8C3F44        xor     ecx, 7
.text:00005613AA8C3F47        xor     ecx, 2
.text:00005613AA8C3F4A        xor     ecx, 6
.text:00005613AA8C3F4D        or      ebx, ecx
.text:00005613AA8C3F4F        and     ebx, 1
.text:00005613AA8C3F52        or      ebx, 0
.text:00005613AA8C3F55        and     ebx, 1
.text:00005613AA8C3F58        or      ebx, 8
.text:00005613AA8C3F5B        and     ebx, 1
.text:00005613AA8C3F5E        or      ebx, 2
.text:00005613AA8C3F61        and     ebx, 1
.text:00005613AA8C3F64        and     ebx, 5
.text:00005613AA8C3F67        xor     ecx, ecx
.text:00005613AA8C3F69        xor     ecx, 6
.text:00005613AA8C3F6C        xor     ecx, 7
.text:00005613AA8C3F6F        xor     ecx, 4
.text:00005613AA8C3F72        xor     ecx, 7
.text:00005613AA8C3F75        xor     ecx, 6
.text:00005613AA8C3F78        xor     ecx, 9
.text:00005613AA8C3F7B        xor     ecx, 2
.text:00005613AA8C3F7E        xor     ecx, 5
.text:00005613AA8C3F81        xor     ecx, 4
.text:00005613AA8C3F84        xor     ecx, 5
.text:00005613AA8C3F87        xor     ecx, 0Bh
.text:00005613AA8C3F8A        or      ebx, ecx
.text:00005613AA8C3F8C        and     ebx, 1
.text:00005613AA8C3F8F        xor     ecx, ecx
.text:00005613AA8C3F91        xor     ecx, 8
.text:00005613AA8C3F94        xor     ecx, 5
.text:00005613AA8C3F97        xor     ecx, 8
.text:00005613AA8C3F9A        xor     ecx, 7
.text:00005613AA8C3F9D        xor     ecx, 7
.text:00005613AA8C3FA0        xor     ecx, 7
.text:00005613AA8C3FA3        xor     ecx, 9
.text:00005613AA8C3FA6        xor     ecx, 0
.text:00005613AA8C3FA9        xor     ecx, 9
.text:00005613AA8C3FAC        xor     ecx, 0
.text:00005613AA8C3FAF        xor     ecx, 2
.text:00005613AA8C3FB2        or      ebx, ecx
.text:00005613AA8C3FB4        and     ebx, 1
.text:00005613AA8C3FB7        or      ebx, 2
.text:00005613AA8C3FBA        and     ebx, 1
.text:00005613AA8C3FBD        and     ebx, 3
.text:00005613AA8C3FC0        and     ebx, 9
.text:00005613AA8C3FC3        xor     ebx, eax
.text:00005613AA8C3FC5        mov     eax, ebx
.text:00005613AA8C3FC7        mov     [rbp+var_C], eax
.text:00005613AA8C3FCA        mov     eax, [rbp+var_C]
.text:00005613AA8C3FCD        pop     rbx
.text:00005613AA8C3FCE        pop     rbp
.text:00005613AA8C3FCF        retn
.text:00005613AA8C3FCF function1       endp
``` 

Each block invokes a different function (from `function2` to `function831`)

### Cracking the binary

We apply a side channel attack here: First we extract the order that bits are checked from 
the flag, using **capstone** (or simpler, we can use IDA decompiler which generates a nice
code for checkFlag, and use regular expressions to extract the bit order). Then we generate 2 
flags: The first flag has all characters random, except this specific bit which is clear, 
while the second flag is identical with the first flag, but this specific bit is set.

Then we run binary twice giving these two flags as input and we instrument the number of
instructions executed using PIN. The more instructions we count during execution, the deeper
the control flow entered inside `checkFlag`, which means that we can infer which bit value was
the correct one. We do this for each bit position and we get the flag: 
```
p4{I_really_hope_you_automated_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}
```

For more details take a look at [elementary_crack.py](./elementary_crack.py)

___