## HackTheVote 2016 - Consul (RE 100)
##### 04/11 - 06/11/2016 (48hr)

___

### Description: 
Bernie Sanders 2018

consul.bin
___

### Solution

The binary has a dummy main function():

```assembly
.text:0000000000400B3D ; int __cdecl main(int argc, const char **argv, const char **envp)
.text:0000000000400B3D     public main
.text:0000000000400B3D main proc near                          ; DATA XREF: _start+1Do
.text:0000000000400B3D
.text:0000000000400B3D var_10= qword ptr -10h
.text:0000000000400B3D var_4= dword ptr -4
.text:0000000000400B3D
.text:0000000000400B3D     push    rbp
.text:0000000000400B3E     mov     rbp, rsp
.text:0000000000400B41     sub     rsp, 10h
.text:0000000000400B45     mov     [rbp+var_4], edi
.text:0000000000400B48     mov     [rbp+var_10], rsi
.text:0000000000400B4C     mov     edi, offset s               ; "Poor Bernie.\r"
.text:0000000000400B51     call    _puts
.text:0000000000400B56     mov     eax, 0
.text:0000000000400B5B     leave
.text:0000000000400B5C     retn
.text:0000000000400B5C main endp
```

However there are many other functions in the binary. This means that we have to execute some
of them in the right order. Some functions have names like "help", "fake_help", "real_help".
If we call real_help function we'll get the message:
```
    Leonardo De Pisa? Who's that–The next president?
```

But this message is decrypted before it get's displayed. Decryption is done through 4 equivalent
functions:
``` 
    decrypt_2_40064C .text 000000000040064C 00000074 00000038 00000000 R . . . B . .
    decrypt_1_4006C0 .text 00000000004006C0 00000078 00000038 00000000 R . . . B . .
    decrypt_4_400738 .text 0000000000400738 00000078 00000038 00000000 R . . . B . .
    decrypt_3_4007B0 .text 00000000004007B0 00000078 00000038 00000000 R . . . B . .
```

Let's analyze the first one:
```assembly
.text:00000000004006C9     mov     [rbp+s], rdi
.text:00000000004006CD     mov     [rbp+add_key_2C], esi
.text:00000000004006D0     mov     rbx, cs:m0
.text:00000000004006D7     mov     rax, [rbp+s]
.text:00000000004006DB     mov     rdi, rax                    ; s
.text:00000000004006DE     call    _strlen
.text:00000000004006E3     mov     rdi, rax
.text:00000000004006E6     call    rbx ; m0                    ; malloc
.text:00000000004006E8     mov     [rbp+decr_20], rax
.text:00000000004006EC     mov     [rbp+var_14], 0
.text:00000000004006F3     jmp     short loc_400719
.text:00000000004006F5 ; ---------------------------------------------------------------------------
.text:00000000004006F5
.text:00000000004006F5 loc_4006F5:                             ; CODE XREF: decrypt_1_4006C0+6Bj
.text:00000000004006F5     mov     edx, [rbp+var_14]
.text:00000000004006F8     mov     rax, [rbp+decr_20]
.text:00000000004006FC     add     rdx, rax
.text:00000000004006FF     mov     ecx, [rbp+var_14]
.text:0000000000400702     mov     rax, [rbp+s]
.text:0000000000400706     add     rax, rcx
.text:0000000000400709     movzx   eax, byte ptr [rax]         ; eax = enc[i]
.text:000000000040070C     mov     ecx, eax
.text:000000000040070E     mov     eax, [rbp+add_key_2C]
.text:0000000000400711     add     eax, ecx
.text:0000000000400713     mov     [rdx], al                   ; decr[i] = enc[i] + add_key
.text:0000000000400715     add     [rbp+var_14], 1
.text:0000000000400719
.text:0000000000400719 loc_400719:                             ; CODE XREF: decrypt_1_4006C0+33j
.text:0000000000400719     mov     ebx, [rbp+var_14]
.text:000000000040071C     mov     rax, [rbp+s]
.text:0000000000400720     mov     rdi, rax                    ; s
.text:0000000000400723     call    _strlen
.text:0000000000400728     cmp     rbx, rax
.text:000000000040072B     jb      short loc_4006F5
.text:000000000040072D     mov     rax, [rbp+decr_20]
```

Function does something very simple: It adds a constant value (modulo 256) to every byte
of a buffer. The only tricky part is at line 0x4006E6, which we have to initialize the 
cs:m0 first. By looking the XREFs to m0, we can find where it get's initialized:
```assembly
    .text:0000000000400A6A     mov     cs:m0, offset _malloc
```

Decrypt 2 is identical except that call ebx is now replaced with:
```assembly
    .text:000000000040066B     call    _malloc
```

Then there are some other functions (c1, c1_, c2, c3, etc.) That they call the decryption
functions with some buffers from .data section.

___

This problem is obviously a puzzle: We have to understand the hints and find which functions to
execute and in which order in order to successfully decrypt the flag. But this is going to take
some time :\

We need a quick n dirty solution here. The key observation here is that the _whole_ buffer gets
decrypted by adding a constant value. So what we can do is to simply dump all buffers (the whole
.data section) and try all possible keys. Then for each key we search for string "flag".

Let's write a 1 line python script:

```python
# get the whole .data section
A = [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
     0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
     0x26,0x2C,0x21,0x27,0x3B,0x37,0x32,0x29,0x34,0x25,0x1F,0x29,0x2E,0x1F,0x22,0x25,
     0x32,0x2E,0x29,0x25,0xE1,0x3D,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
     0x3F,0x58,0x62,0x61,0x54,0x65,0x57,0x62,0x13,0x37,0x58,0x13,0x43,0x40,0x66,0x54,
     0x32,0x13,0x4A,0x5B,0x62,0x1A,0x66,0x13,0x67,0x5B,0x54,0x67,0xD5,0x73,0x86,0x47,
     0x5B,0x58,0x13,0x61,0x58,0x6B,0x67,0x13,0x63,0x65,0x58,0x66,0x5C,0x57,0x58,0x61,
     0x67,0x32,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
     0x4B,0x59,0x14,0x58,0x5D,0x58,0x62,0x1B,0x68,0x14,0x58,0x59,0x67,0x59,0x66,0x6A,
     0x59,0x14,0x36,0x59,0x66,0x62,0x5D,0x59,0x22,0xCB,0xB0,0xA2,0x67,0x68,0x2D,0x00,
     0x00,0x13,0x14,0x59,0x03,0x23,0x07,0x01,0x13,0x59,0x00,0x00,0x00,0x00,0x00,0x00,
     0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
     0x42,0x56,0x53,0x0E,0x53,0x5C,0x52,0x0E,0x57,0x61,0x0E,0x54,0x5D,0x60,0x53,0x64,
     0x53,0x60,0x1C,0x0E,0x30,0x63,0x62,0x0E,0x4F,0x54,0x62,0x53,0x60,0x0E,0x62,0x56,
     0x4F,0x62,0x1A,0x0E,0x67,0x5D,0x63,0x15,0x60,0x53,0x0E,0x55,0x5D,0x5D,0x52,0x0E,
     0x62,0x5D,0x0E,0x55,0x5D,0x1C,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
     0x09,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x20,0x05,0x40,0x00,0x00,0x00,0x00,0x00 ]

# try all possible keys to "decrypt" all buffers
for i in range(256): print ''.join( [ chr((j+i) % 256) for j in A ] )
```

Then we execute it and we get the flag:
```
ispo@nogirl:~/ctf/hackthevote_16$ python consul.py | strings | grep flag
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@flag{write_in_bernie!}@@@@@@@@@@
```
The flag is: **flag{write_in_bernie!}**

___
