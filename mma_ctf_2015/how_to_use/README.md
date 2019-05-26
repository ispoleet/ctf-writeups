
## MMA 1st CTF 2015 - howtouse (RE 30)
##### 05/09 - 07/09/2015 (48hr)
___
### Description: 
How to use?

___
### Solution

A very simple RE challenge. However binary is a dll file so we can't execute it (we can but it's 
not trivial though). Let's solve just by disassembly:
```assembly
	.text:10001080 M_loc_10001080:
	.text:10001080                 mov     eax, 4Dh ; 'M'
	.text:10001085                 retn

	.text:10001090 _0_loc_10001090:
	.text:10001090                 mov     eax, 30h ; '0'
	.text:10001095                 retn

	.text:100010B0 _2_loc_100010B0:
	.text:100010B0                 mov     eax, 32h ; '2'
	.text:100010B5                 retn
```
At first there are some funtions that set eax with a character. We rename all these functions 
using IDA pro to make analysis easier. Then we move in the core:
```assembly
	.text:10001136                 mov     eax, offset M_loc_10001080
	.text:1000113B                 mov     [esp+0B4h+v_45], eax                          ; M
	.text:1000113E                 mov     [esp+0B4h+v_44], eax                          ; M
	.text:10001142                 mov     eax, offset _0_loc_10001090
	.text:10001147                 mov     [esp+0B4h+v_36], eax
	.text:1000114B                 mov     [esp+0B4h+v_33], eax
	.text:1000114F                 mov     [esp+0B4h+v_32], eax                          ; 0
	.text:10001153                 push    esi
	....
	.text:1000124E                 mov     [esp+0B8h+v_7], offset b_loc_10001020         ; 07: b
	.text:10001259                 mov     [esp+0B8h+v_6], offset _3_loc_100010C0        ; 06: 3
	.text:10001264                 mov     [esp+0B8h+v_5], offset _2_loc_100010B0        ; 05: 2
	.text:1000126F                 mov     [esp+0B8h+v_2], edx                           ; 02: 8
	.text:10001276                 mov     [esp+0B8h+v_1], offset _RBRAC_loc_10001120    ; 01: }
```

Now we start setting values from the stack in a random order with these character. We can either
run the program and then dump the stack, or start filling a "puzzle" with the missing characters
in each memory address. After a while we complete the "puzzle":
```
01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 
{  8  d  e  2  3  b  9  e  9  a  f  e  7  e  e  9  d  8  8  d  7  9  4  2  1  7  8  c  f

31 32 33 34 35 36 37 38 39 40 41 42 43 44 45
1  0  0  a  c  0  9  d  7  c  f  {  A  M  M
```
The flag is inverted so the final answer is: **MMA{fc7d90ca001fc8712497d88d9ee7efa9e9b32ed8}**
___