
## HITCON CTF 2014 - hop (RE 350)
##### 16-18/08/2014 (48 hr)
___

### Description: 

https://github.com/hitcon2014ctf/ctf/raw/master/hop/hop-62fa7ade9a1fa9254361e69d70e7a7e3.exe 

https://dl.dropbox.com/s/5l4q7iztyfhc8c1/hop-62fa7ade9a1fa9254361e69d70e7a7e3.exe
___

### Solution

Binary reads a 40-byte key. At each step the next character of the key is used to calculate the
address of the next 'hop'. Each hop has the following structure:

```Assembly
.text:00000000004735F4 58                           pop     rax
.text:00000000004735F5 48 69 C0 3F 3B 00 00         imul    rax, 3B3Fh
.text:00000000004735FC 8B 84 02 8B 00 00 00         mov     eax, [rdx+rax+8Bh]
.text:0000000000473603 48 98                        cdqe
.text:0000000000473605 48 01 C2                     add     rdx, rax
.text:0000000000473608 FF E2                        jmp     rdx
```

The only difference between hops is the constant numbers in the `imul` and `mov` instructions.
If the key is correct, the last hop is this:
```Assembly
.text:00000000004015B9 48 31 C0                     xor     rax, rax
.text:00000000004015BC B0 01                        mov     al, 1
.text:00000000004015BE C3                           retn
```

Otherwise, the last hop is this:
```Assembly
.text:00000000004015BF 48 31 C0                     xor     rax, rax
.text:00000000004015C2 C3                           retn
```


Clearly all we have to do is to find the right path from the entry point at 0x044F491 to 0x4015B9. But this path 
should have length exactly 40. There are many valid paths but only one of them has length 40:
`HITCON{Cap7ur3 Wh1t3 F1ag 0f Us@ 5hr1n3}`

For more details please refer to the crack file.

___
