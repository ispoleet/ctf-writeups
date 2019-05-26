## 9447 Security Society CTF 2014 - no strings attached (Reversing 25)
##### 29-30/11/2014 (36hr)
___

### Solution

Very easy challenge. Load the program in gdb:

```assembly
(gdb) disas main
Dump of assembler code for function main:
   0x080487a9 <+0>:		push   %ebp
   0x080487aa <+1>:		mov    %esp,%ebp
   0x080487ac <+3>:		and    $0xfffffff0,%esp
   0x080487af <+6>:		sub    $0x10,%esp
   0x080487b2 <+9>:		movl   $0x8048be4,0x4(%esp)
   0x080487ba <+17>:	movl   $0x6,(%esp)
   0x080487c1 <+24>:	call   0x8048540 <setlocale@plt>
   0x080487c6 <+29>:	call   0x8048604 <banner>
   0x080487cb <+34>:	call   0x8048643 <prompt_authentication>
   0x080487d0 <+39>:	call   0x8048708 <authenticate>
   0x080487d5 <+44>:	mov    $0x0,%eax
   0x080487da <+49>:	leave  
   0x080487db <+50>:	ret    
End of assembler dump.
```

Follow call to authenticate:
```assembly
(gdb) disas authenticate
Dump of assembler code for function authenticate:
   0x08048708 <+0>:	push   %ebp
   0x08048709 <+1>:	mov    %esp,%ebp
   0x0804870b <+3>:	sub    $0x8028,%esp
   0x08048711 <+9>:	movl   $0x8048a90,0x4(%esp)
   0x08048719 <+17>:	movl   $0x8048aa8,(%esp)
   0x08048720 <+24>:	call   0x8048658 <decrypt>
   0x08048725 <+29>:	mov    %eax,-0xc(%ebp)
   0x08048728 <+32>:	mov    0x804a03c,%eax
   0x0804872d <+37>:	mov    %eax,0x8(%esp)
   0x08048731 <+41>:	movl   $0x2000,0x4(%esp)
   0x08048739 <+49>:	lea    -0x800c(%ebp),%eax
   0x0804873f <+55>:	mov    %eax,(%esp)
   0x08048742 <+58>:	call   0x80484a0 <fgetws@plt>
   0x08048747 <+63>:	test   %eax,%eax
   0x08048749 <+65>:	je     0x804879c <authenticate+148>
   0x0804874b <+67>:	lea    -0x800c(%ebp),%eax
   0x08048751 <+73>:	mov    %eax,(%esp)
   0x08048754 <+76>:	call   0x8048520 <wcslen@plt>
   0x08048759 <+81>:	sub    $0x1,%eax
   0x0804875c <+84>:	movl   $0x0,-0x800c(%ebp,%eax,4)
   0x08048767 <+95>:	mov    -0xc(%ebp),%eax
   0x0804876a <+98>:	mov    %eax,0x4(%esp)
   0x0804876e <+102>:	lea    -0x800c(%ebp),%eax
   0x08048774 <+108>:	mov    %eax,(%esp)
   0x08048777 <+111>:	call   0x80484d0 <wcscmp@plt>
   0x0804877c <+116>:	test   %eax,%eax
   0x0804877e <+118>:	jne    0x804878f <authenticate+135>
   0x08048780 <+120>:	mov    $0x8048b44,%eax
   0x08048785 <+125>:	mov    %eax,(%esp)
   0x08048788 <+128>:	call   0x80484b0 <wprintf@plt>
   0x0804878d <+133>:	jmp    0x804879c <authenticate+148>
   0x0804878f <+135>:	mov    $0x8048ba4,%eax
   0x08048794 <+140>:	mov    %eax,(%esp)
   0x08048797 <+143>:	call   0x80484b0 <wprintf@plt>
   0x0804879c <+148>:	mov    -0xc(%ebp),%eax
   0x0804879f <+151>:	mov    %eax,(%esp)
   0x080487a2 <+154>:	call   0x8048480 <free@plt>
   0x080487a7 <+159>:	leave  
   0x080487a8 <+160>:	ret    
```

The interestring point here is this:
```assembly
   0x08048777 <+111>:	call   0x80484d0 <wcscmp@plt>
```

At first, decrypt() is called. We don't care how it works. Just set a bp on the wcscmp() and 
see the stack arguments. The one argument is our string (in UNICODE) and the other is the flag:
```assembly
(gdb) b * 0x08048777
	Breakpoint 1 at 0x8048777
(gdb) r
	Breakpoint 1, 0x08048777 in authenticate ()
(gdb) x/4xw $esp
	0xffff54a0:	0xffff54bc	0x0804e448	0xf7fc0440	0x00000000
(gdb) x/32c 0x0804e448
0x804e448:	57 '9'	0 '\000'	0 '\000'	0 '\000'	52 '4'	0 '\000'	0 '\000'	0 '\000'
0x804e450:	52 '4'	0 '\000'	0 '\000'	0 '\000'	55 '7'	0 '\000'	0 '\000'	0 '\000'
0x804e458:	123 '{'	0 '\000'	0 '\000'	0 '\000'	121 'y'0 '\000'	0 '\000'	0 '\000'
0x804e460:	111 'o'	0 '\000'	0 '\000'	0 '\000'	117 'u'0 '\000'	0 '\000'	0 '\000'
```

Cool! Get all the characters of the flag:
```assembly
0x804e448:	57 '9'	0 '\000'	0 '\000'	0 '\000'	52 '4'	0 '\000'	0 '\000'	0 '\000'
0x804e450:	52 '4'	0 '\000'	0 '\000'	0 '\000'	55 '7'	0 '\000'	0 '\000'	0 '\000'
0x804e458:	123 '{'	0 '\000'	0 '\000'	0 '\000'	121 'y'	0 '\000'	0 '\000'	0 '\000'
0x804e460:	111 'o'	0 '\000'	0 '\000'	0 '\000'	117 'u'	0 '\000'	0 '\000'	0 '\000'
0x804e468:	95 '_'	0 '\000'	0 '\000'	0 '\000'	97 'a'	0 '\000'	0 '\000'	0 '\000'
0x804e470:	114 'r'	0 '\000'	0 '\000'	0 '\000'	101 'e'	0 '\000'	0 '\000'	0 '\000'
0x804e478:	95 '_'	0 '\000'	0 '\000'	0 '\000'	97 'a'	0 '\000'	0 '\000'	0 '\000'
0x804e480:	110 'n'	0 '\000'	0 '\000'	0 '\000'	95 '_'	0 '\000'	0 '\000'	0 '\000'
0x804e488:	105 'i'	0 '\000'	0 '\000'	0 '\000'	110 'n'	0 '\000'	0 '\000'	0 '\000'
0x804e490:	116 't'	0 '\000'	0 '\000'	0 '\000'	101 'e'	0 '\000'	0 '\000'	0 '\000'
0x804e498:	114 'r'	0 '\000'	0 '\000'	0 '\000'	110 'n'	0 '\000'	0 '\000'	0 '\000'
0x804e4a0:	97 'a'	0 '\000'	0 '\000'	0 '\000'	116 't'	0 '\000'	0 '\000'	0 '\000'
0x804e4a8:	105 'i'	0 '\000'	0 '\000'	0 '\000'	111 'o'	0 '\000'	0 '\000'	0 '\000'
0x804e4b0:	110 'n'	0 '\000'	0 '\000'	0 '\000'	97 'a'	0 '\000'	0 '\000'	0 '\000'
0x804e4b8:	108 'l'	0 '\000'	0 '\000'	0 '\000'	95 '_'	0 '\000'	0 '\000'	0 '\000'
0x804e4c0:	109 'm'	0 '\000'	0 '\000'	0 '\000'	121 'y'	0 '\000'	0 '\000'	0 '\000'
0x804e4c8:	115 's'	0 '\000'	0 '\000'	0 '\000'	116 't'	0 '\000'	0 '\000'	0 '\000'
0x804e4d0:	101 'e'	0 '\000'	0 '\000'	0 '\000'	114 'r'	0 '\000'	0 '\000'	0 '\000'
0x804e4d8:	121 'y'	0 '\000'	0 '\000'	0 '\000'	125 '}'	0 '\000'	0 '\000'	0 '\000'
```

Now we use awk to extract the password (get the 3rd and 11th columns). Then we split in 
seperate lines, and the we merge all lines to 1: 
	awk '{ print $3,"\n",$11}' re25.txt | awk '{printf("%s",$1)}'

The result is:
```
'9''4''4''7''{''y''o''u''_''a''r''e''_''a''n''_''i''n''t''e''r''n''a''t''i''o''n''a''l''_''m''y''s''t''e''r''y''}'
```
We remove the quotes and we get the flag: **9447{you_are_an_international_mystery}**

___
