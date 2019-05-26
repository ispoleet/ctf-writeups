## Codegate CTF Preliminary 2014 - Clone Technique (RE 250pt)
##### 22/02 - 23/02/2014 (30hr)
___

### Description: 
	Limited processes will be generated. Which one has the flag?

	Download


### Solution

The most challenging part was to find where the flag is. Before WinMain(),  __cinit() is called
which performs some initializations. There's a special function, decrypt_401070() which takes as
input a buffer that contains random bytes and the first 2 command line arguments. Then it 
generates a new buffer and returns a pointer to it. Then, this buffer is zeroed out immediately:

```assembly
.text:004011E1     mov     esi, 7
.text:004011E6     xor     ebx, ebx
.text:004011E8     mov     ecx, [ebp+var_4]
.text:004011EB     push    ecx                         ; arg3: num_B
.text:004011EC     mov     edx, [ebp+Buffer]
.text:004011EF     push    edx                         ; arg2: num_A
.text:004011F0     push    offset FLAG_407030          ; arg1: flag
.text:004011F5     call    decrypt_401070
.text:004011FA     add     esp, 0Ch
.text:004011FD     mov     edi, eax
.text:004011FF     mov     eax, ebx
.text:00401201     mov     ecx, esi                    ; 7*4 = 28 bytes
.text:00401203     rep stosd                           ; clear flag!
```

This is probably our flag. So all we have to do is to simulate the "cloning" and try to decrypt
the buffer each time. Flag should contain only printable characters, so we can easily discard
the "incorrect" flags.

The rest is just straightforward reverse engineering of the code. The only difference is that 
we simulate process cloning with a recursion.

Please take a look at the crack file. The flag is `And Now His Watch is Ended`.
___
