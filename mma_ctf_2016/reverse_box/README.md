## Tokey Westerns/MMA CTF 2nd 2016 - Reverse Box  (Re 50pt)
##### 03/09 - 05/09/2016 (48hr)
___

### Description: 
$ ./reverse_box ${FLAG}

95eeaf95ef94234999582f722f492f72b19a7aaf72e6e776b57aee722fe77ab5ad9aaeb156729676ae7a236d99b1df4a

	reverse_box.7z
___
### Solution

Let's start by looking at main() function:

```assembly
.text:080486D4 ; DO ARGUMENT CHECK FIRST
.text:080486D4 ARGV_OK_80486D4:                        ; CODE XREF: main_8048689+27j
.text:080486D4     lea     eax, [esp+1Ch]              ; eax = &map
.text:080486D8     mov     [esp], eax
.text:080486DB     call    gen_array
.text:080486E0     mov     dword ptr [esp+18h], 0      ; iterator = 0
.text:080486E8     jmp     short LOOP_END_804871C      ; ebx = iterator
.text:080486EA ; ---------------------------------------------------------------------------
.text:080486EA
.text:080486EA LOOP_START_80486EA:                     ; CODE XREF: main_8048689+AAj
.text:080486EA     mov     eax, [esp+0Ch]
.text:080486EE     add     eax, 4
.text:080486F1     mov     edx, [eax]                  ; edx = &flag
.text:080486F3     mov     eax, [esp+18h]
.text:080486F7     add     eax, edx
.text:080486F9     movzx   eax, byte ptr [eax]         ; eax = flag[iterator]
.text:080486FC     movsx   eax, al
.text:080486FF     movzx   eax, byte ptr [esp+eax+1Ch]
.text:08048704     movzx   eax, al                     ; eax = map[ flag[iterator] ]
.text:08048707     mov     [esp+4], eax
.text:0804870B     mov     dword ptr [esp], offset a02x ; "%02x"
.text:08048712     call    _printf                     ; printf("%02x", map[ flag[iterator] ] );
.text:08048717     add     dword ptr [esp+18h], 1      ; ++iterator
.text:0804871C
.text:0804871C LOOP_END_804871C:                       ; CODE XREF: main_8048689+5Fj
.text:0804871C     mov     ebx, [esp+18h]              ; ebx = iterator
.text:08048720     mov     eax, [esp+0Ch]
.text:08048724     add     eax, 4
.text:08048727     mov     eax, [eax]                  ; eax = argv[1]
.text:08048729     mov     [esp], eax                  ; s
.text:0804872C     call    _strlen                     ; get flag length
.text:08048731     cmp     ebx, eax
.text:08048733     jb      short LOOP_START_80486EA
```

Things are very easy here: function gen_array (0x0804858D) is called and generates a 256 byte
array. Then we substitute each character from the flag using the array:
```c
	printf("%02x", map[ flag[iterator] ] ); 
```

This is pretty much like an substitution box (SBox). Let's take a look into gen_array:

```assembly
.text:08048593     mov     dword ptr [esp], 0          ; timer
.text:0804859A     call    _time
.text:0804859F     mov     [esp], eax                  ; seed
.text:080485A2     call    _srand                      ; srand(time(NULL))
.text:080485A7
.text:080485A7 ZERO_BYTE_80485A7:                      ; CODE XREF: gen_array+2Bj
.text:080485A7     call    _rand
.text:080485AC     and     eax, 0FFh
.text:080485B1     mov     [ebp+rand_C], eax           ; rand_C = rand() % 256
.text:080485B4     cmp     [ebp+rand_C], 0
.text:080485B8     jz      short ZERO_BYTE_80485A7     ; if( rand_C == 0 ) then get a new random byte

.text:080485BA     mov     eax, [ebp+rand_C]
.text:080485BD     mov     edx, eax
.text:080485BF     mov     eax, [ebp+arg_0]
.text:080485C2     mov     [eax], dl                   ; map[0] = rand_C
.text:080485C4     mov     [ebp+var_E], 1
.text:080485C8     mov     [ebp+var_D], 1
.text:080485CC
.text:080485CC loc_80485CC:                            ; CODE XREF: gen_array+F4j
.....
.....				; do substitutions
.....
.text:0804867D     cmp     [ebp+var_E], 1
.text:08048681     jnz     loc_80485CC
.text:08048687     leave
.text:08048688     retn
.text:08048688 gen_array endp
```

The key point here is that the initial seed for that array is 1 byte long, so there are 255 
possible arrays.


At this point we can reverse the algorithm and generate all possible arrays. But we'll solve it
without reversing the algorithm! The idea is to use an IDC script which sets accordingly the 
random seed, lets the program generates the array by itself, and then collect the results.
We can repeat this process for each of 255 possible seeds.


Our IDC script will print in the output window of IDA all arrays in a python list format.
Then we can copy all these arrays in a python script and get the flag:

```python
enc ='95eeaf95ef94234999582f722f492f72b19a7aaf72e6e776b57aee722fe77ab5ad9aaeb156729676ae7a236d99b1df4a'
	idx = [ord(i) for i in enc.decode('hex') ]
	
	for m in map:
		flag = ''.join([chr(m.index(i)) for i in idx])
		if flag.find('TWCTF') != -1:
			print 'Flag Found:', flag
			break
```

We know that flag starts with "TWCTF", so we can easily find out the which is the correct array.
Once we execute it, we get the flag: **TWCTF{5UBS717U710N_C1PH3R_W17H_R4ND0M123D_5-B0X}**
___