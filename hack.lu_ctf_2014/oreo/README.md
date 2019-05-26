## Hack.lu CTF 2014 - OREO (Pwn 400)
##### 21-23/10/2014 (48hr)

___

### Description: 
The Original Rifle Company has the most finest rifles and revolvers in whole Rodeo 
City! However their buildings are pretty secure, so your only chance to get into their offices 
is by hacking through the Original Rifle Ecommerce Online (OREO) System and steal all those 
pretty weapons from the inside! Makes sense right? Good luck!

Download nc wildwildweb.fluxfingers.net 1414

___
### Solution

The bug was easy to find. When you add a new rifle there's an overflow in name/desc. Both are 0x19
bytes long but the fgets() reads up to 0x38 bytes:

```assembly
.text:08048688     mov     eax, ds:rifle_804A288
.text:0804868D     mov     edx, [ebp+prev_rifle_10]
.text:08048690     mov     [eax+34h], edx              ; rifle.prev (0x34)
.text:08048693     mov     dword ptr [esp], offset format ; "Rifle name: "
.text:0804869A     call    _printf
.text:0804869F     mov     eax, ds:stdin
.text:080486A4     mov     edx, ds:rifle_804A288
.text:080486AA     add     edx, 19h                    ; rifle.name (0x19 ~ 0x33)
.text:080486AD     mov     [esp+8], eax                ; stream
.text:080486B1     mov     dword ptr [esp+4], 38h      ; n
.text:080486B9     mov     [esp], edx                  ; s
.text:080486BC     call    _fgets                      ; overflow!
.text:080486C1     mov     eax, ds:rifle_804A288
.text:080486C6     add     eax, 19h
.text:080486C9     mov     [esp], eax
.text:080486CC     call    trim_80485EC
.text:080486D1     mov     dword ptr [esp], offset aRifleDescripti ; "Rifle description: "
.text:080486D8     call    _printf
.text:080486DD     mov     edx, ds:stdin
.text:080486E3     mov     eax, ds:rifle_804A288       ; rifle.description (0 ~ 0x18)
.text:080486E8     mov     [esp+8], edx                ; stream
.text:080486EC     mov     dword ptr [esp+4], 38h      ; n
.text:080486F4     mov     [esp], eax                  ; s
.text:080486F7     call    _fgets                      ; overflow!
.text:080486FC     mov     eax, ds:rifle_804A288
.text:08048701     mov     [esp], eax
.text:08048704     call    trim_80485EC
.text:08048709     mov     eax, ds:rifle_counter_804A2A4
.text:0804870E     add     eax, 1
.text:08048711     mov     ds:rifle_counter_804A2A4, eax
```

So we can overflow rifle.prev pointer. If we set the this pointer somewhere in .got, and then see
the added rifles, then we can leak an address from .got.

After that, if we can order the rifles so we can have total control of the argument in the free(),
so we can apply the house of spirit (https://gbmaster.wordpress.com/2015/07/21/x86-exploitation-101-house-of-spirit-friendly-stack-overflow/)

attack. Here we leave a message with our order and we create a fake chunk there. The address is known and
is stored at 0x0804A2A8. What we do is to create another fastbin chunk at 0804A2Ac. We need a fake 
prev size so we must set rifle_counter_804A2A4 to 0x41 (just add 0x41 rifles). Then we add a new rifle
and we set rifle.prev to 0x0804a2a8 and we order the rifles. The 2nd chunk that we'll free will be the
fake one, and then we'll stop because fake_chunk.prev (at offset 0x34) is null.

```assembly
.bss:0804A285     align 4
.bss:0804A288 ; char *rifle_804A288
.bss:0804A288 rifle_804A288 dd ?                      ; DATA XREF: add_rifle_8048644+11r
.bss:0804A288                                         ; add_rifle_8048644+25w ...
.bss:0804A28C     align 20h
.bss:0804A2A0 order_counter_804A2A0 dd ?              ; DATA XREF: order_rifles_8048810+5Ar
.bss:0804A2A0                                         ; order_rifles_8048810+62w ...
.bss:0804A2A4 rifle_counter_804A2A4 dd ?              ; DATA XREF: add_rifle_8048644+C5r
.bss:0804A2A4                                         ; add_rifle_8048644+CDw ...
.bss:0804A2A8 ; char *order_message_ptr_804A2A8
.bss:0804A2A8 order_message_ptr_804A2A8 dd ?          ; DATA XREF: leave_msg_80487B4+23r
.bss:0804A2A8                                         ; leave_msg_80487B4+3Cr ...
.bss:0804A2AC     align 20h
```

If we add a new rifle, malloc(0x38) will return 0x0804a2a8. From there we can set its description
and overwrite message ptr (order_message_ptr_804A2A8) with an arbitrary address. We set this 
address to .got.free(). 

Then we leave a new message and we can directly overwrite .got.free() with the address of system().
We can find &system() from the previous leak.


Finally we add a new rifle and we set the /bin/sh as description. Then we order the rifles
and we trigger free(/bin/sh) which is actually system(/bin/sh). Game over.

```
id
	uid=1000(oreo) gid=1000(oreo) groups=1000(oreo)
ls -l
total 12
	-rw-r--r-- 1 root root   35 Oct  7 14:54 fl4g
	-rwxr-xr-x 1 oreo oreo 6172 Oct  7 14:47 oreo
cat fl4g
	flag{FASTBINS_ARE_NICE_ARENT_THEY}
```

___
