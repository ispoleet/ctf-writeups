## Tokey Westerns/MMA CTF 2nd 2016 - shadow (Pwn 400pt)
##### 03/09 - 05/09/2016 (48hr)
___

### Description: 
	Host : pwn2.chal.ctf.westerns.tokyo
	
	Port : 18294
	
	shadow
### Solution

This binary implements a basic vulnerable message service, which is protected with a shadow stack
to prevent ROP attacks. The core of the program is the message() function:

```assembly
.text:08048794 65 A1 14 00+    mov     eax, large gs:14h
.text:0804879A 89 45 F4        mov     [ebp+canary_C], eax
.text:0804879D 31 C0           xor     eax, eax
.text:0804879F C7 45 CC 00+    mov     [ebp+msg_ctr_34], 0
.text:080487A6 E9 6D 01 00+    jmp     LOOP_END_8048918
.text:080487AB             ; ---------------------------------------------------------------------------
.text:080487AB
.text:080487AB             LOOP_START_80487AB:                               ; CODE XREF: message+192j
.text:080487AB 8D 55 D4        lea     edx, [ebp+arr_2C]                     ; a 32 byte array
.text:080487AE B9 00 00 00+    mov     ecx, 0
.text:080487B3 B8 20 00 00+    mov     eax, 20h
.text:080487B8 83 E0 FC        and     eax, 0FFFFFFFCh
.text:080487BB 89 C3           mov     ebx, eax
.text:080487BD B8 00 00 00+    mov     eax, 0
.text:080487C2
.text:080487C2             BZERO_80487C2:                                    ; CODE XREF: message+3Ej
.text:080487C2 89 0C 02        mov     [edx+eax], ecx
.text:080487C5 83 C0 04        add     eax, 4
.text:080487C8 39 D8           cmp     eax, ebx
.text:080487CA 72 F6           jb      short BZERO_80487C2                   ; zero out arr_2C
.text:080487CC 01 C2           add     edx, eax
.text:080487CE 8B 45 08        mov     eax, [ebp+arg_0]
.text:080487D1 89 44 24 04     mov     [esp+4], eax
.text:080487D5 C7 04 24 40+    mov     dword ptr [esp], offset _strlen
.text:080487DC E8 E0 04 00+    call    call
.text:080487E1 85 C0           test    eax, eax
.text:080487E3 74 2F           jz      short CHANGE_NAME_8048814
.text:080487E5 C7 44 24 04+    mov     dword ptr [esp+4], offset aChangeName?YN ; "Change name? (y/n) : "
.text:080487ED C7 04 24 E0+    mov     dword ptr [esp], offset _printf
.text:080487F4 E8 C8 04 00+    call    call
.text:080487F9 C7 44 24 08+    mov     dword ptr [esp+8], 20h
.text:08048801 8D 45 D4        lea     eax, [ebp+arr_2C]
.text:08048804 89 44 24 04     mov     [esp+4], eax
.text:08048808 C7 04 24 48+    mov     dword ptr [esp], offset getnline
.text:0804880F E8 AD 04 00+    call    call
.text:08048814
.text:08048814             CHANGE_NAME_8048814:                              ; CODE XREF: message+57j
.text:08048814 8B 45 08        mov     eax, [ebp+arg_0]
.text:08048817 89 44 24 04     mov     [esp+4], eax
.text:0804881B C7 04 24 40+    mov     dword ptr [esp], offset _strlen
.text:08048822 E8 9A 04 00+    call    call                                  ; strlen(name)
.text:08048827 85 C0           test    eax, eax
.text:08048829 74 08           jz      short SET_NAME_8048833
.text:0804882B 0F B6 45 D4     movzx   eax, [ebp+arr_2C]
.text:0804882F 3C 79           cmp     al, 79h                               ; 'y' pressed?
.text:08048831 75 2E           jnz     short GET_MSG_8048861
.text:08048833
.text:08048833             SET_NAME_8048833:                                 ; CODE XREF: message+9Dj
.text:08048833 C7 44 24 04+    mov     dword ptr [esp+4], offset aInputName  ; "Input name : "
.text:0804883B C7 04 24 E0+    mov     dword ptr [esp], offset _printf
.text:08048842 E8 7A 04 00+    call    call
.text:08048847 8B 45 08        mov     eax, [ebp+arg_0]                      ; buf
.text:0804884A 8B 55 0C        mov     edx, [ebp+arg_4]                      ; buflen
.text:0804884D 89 54 24 08     mov     [esp+8], edx
.text:08048851 89 44 24 04     mov     [esp+4], eax                          ; arbitrary WRITE the 2nd time!
.text:08048855 C7 04 24 48+    mov     dword ptr [esp], offset getnline
.text:0804885C E8 60 04 00+    call    call
.text:08048861
.text:08048861             GET_MSG_8048861:                                  ; CODE XREF: message+A5j
.text:08048861 C7 44 24 04+    mov     dword ptr [esp+4], offset aMessageLength ; "Message length : "
.text:08048869 C7 04 24 E0+    mov     dword ptr [esp], offset _printf
.text:08048870 E8 4C 04 00+    call    call
.text:08048875 C7 44 24 08+    mov     dword ptr [esp+8], 20h
.text:0804887D 8D 45 D4        lea     eax, [ebp+arr_2C]
.text:08048880 89 44 24 04     mov     [esp+4], eax
.text:08048884 C7 04 24 48+    mov     dword ptr [esp], offset getnline
.text:0804888B E8 31 04 00+    call    call
.text:08048890 8D 45 D4        lea     eax, [ebp+arr_2C]
.text:08048893 89 44 24 04     mov     [esp+4], eax
.text:08048897 C7 04 24 70+    mov     dword ptr [esp], offset _atoi
.text:0804889E E8 1E 04 00+    call    call
.text:080488A3 89 45 D0        mov     [ebp+msglen_30], eax
.text:080488A6 83 7D D0 20     cmp     [ebp+msglen_30], 20h
.text:080488AA 7E 07           jle     short LEN_OK_80488B3                  ; VULN: signed comparison. Give <0 length
.text:080488AC C7 45 D0 20+    mov     [ebp+msglen_30], 20h                  ; maximum length is 32
.text:080488B3
.text:080488B3             LEN_OK_80488B3:                                   ; CODE XREF: message+11Ej
.text:080488B3 C7 44 24 04+    mov     dword ptr [esp+4], offset aInputMessage ; "Input message : "
.text:080488BB C7 04 24 E0+    mov     dword ptr [esp], offset _printf
.text:080488C2 E8 FA 03 00+    call    call
.text:080488C7 8B 45 D0        mov     eax, [ebp+msglen_30]
.text:080488CA 89 44 24 08     mov     [esp+8], eax
.text:080488CE 8D 45 D4        lea     eax, [ebp+arr_2C]
.text:080488D1 89 44 24 04     mov     [esp+4], eax
.text:080488D5 C7 04 24 48+    mov     dword ptr [esp], offset getnline      ; trivial BOf here
.text:080488DC E8 E0 03 00+    call    call
.text:080488E1 8B 45 08        mov     eax, [ebp+arg_0]
.text:080488E4 8B 55 CC        mov     edx, [ebp+msg_ctr_34]
.text:080488E7 8D 4A 01        lea     ecx, [edx+1]                          ; msg_ctr + 1
.text:080488EA 8D 55 D4        lea     edx, [ebp+arr_2C]
.text:080488ED 89 54 24 14     mov     [esp+14h], edx                        ; arg5: %s: message
.text:080488F1 89 44 24 10     mov     [esp+10h], eax                        ; arg5: %s: name arbitrary_read (str)
.text:080488F5 8B 45 10        mov     eax, [ebp+arg_8]
.text:080488F8 89 44 24 0C     mov     [esp+0Ch], eax                        ; arg3: %d: read your data (int)
.text:080488FC 89 4C 24 08     mov     [esp+8], ecx                          ; arg2: %d: msg_ctr+1
.text:08048900 C7 44 24 04+    mov     dword ptr [esp+4], offset aDDSS       ; "(%d/%d) <%s> %s\n\n"
.text:08048908 C7 04 24 E0+    mov     dword ptr [esp], offset _printf
.text:0804890F E8 AD 03 00+    call    call
.text:08048914 83 45 CC 01     add     [ebp+msg_ctr_34], 1
.text:08048918
.text:08048918             LOOP_END_8048918:                                 ; CODE XREF: message+1Aj
.text:08048918 8B 45 CC        mov     eax, [ebp+msg_ctr_34]
.text:0804891B 3B 45 10        cmp     eax, [ebp+arg_8]
.text:0804891E 0F 8C 87 FE+    jl      LOOP_START_80487AB                    ; a 32 byte array
.text:08048924 C7 04 24 00+    mov     dword ptr [esp], 0
.text:0804892B E8 BE 03 00+    call    ret
.text:08048930 8B 75 F4        mov     esi, [ebp+canary_C]
.text:08048933 65 33 35 14+    xor     esi, large gs:14h
.text:0804893A 74 05           jz      short loc_8048941
.text:0804893C E8 BF FB FF+    call    ___stack_chk_fail
.text:08048941             ; ---------------------------------------------------------------------------
.text:08048941
.text:08048941             loc_8048941:                                      ; CODE XREF: message+1AEj
.text:08048941 83 C4 50        add     esp, 50h
.text:08048944 5B              pop     ebx
.text:08048945 5E              pop     esi
.text:08048946 5D              pop     ebp
.text:08048947 C3              retn
.text:08048947             message endp
```


There are 2 bugs here: The first one is that length comparison is signed:
```assembly
	.text:080488AA 7E 07           jle     short LEN_OK_80488B3
```

By giving a negative length, we can overflow the stack buffer. The second bug is at getnline().
When the input fills the buffer, then no NULL byte is added. Thus it's possible to get a non
NULL terminated string and leak information using printf().


### Leaking a stack address
First of all we need to leak a stack address. By supplying a 16 byte name we can fill the
name buffer. When message (according with the name) is printing we can leak the data from 
the stack after the name. 12 bytes after the name buffer there's a stack address, so we
can easily leak it.


### Leaking the canary
Leaking the canary value is not needed for our attack. However I put some effort to leak it,
so I'll present the method. Canary is stored right after the name buffer. If we fill the
buffer (which is 32) bytes we cannot leak it for a strange reason: The LSB of the canary
is always zero. Thus the printf() will stop on LSB of canary without actually leaking it.

What we can do, is to use the negative length bug, supply a negative message length and
overflow the message buffer by 1 byte. Thus we can overwrite the LSB of the canary and
leak the remaining 3 bytes. 

### Bypassing shadow stack
Shadow stack is a protection against ROP execution. With shadow stack, return addresses are
kept in a separate (hidden) stack. Addresses are usually encrypted using a simple xor with a
random key. Upon call the return address is pushed on shadow stack, and upon return the 
return value is popped from shadow stack. The return address from the stack is compared with
the return address from shadow stack and if they're equal the return is taken.

Let's see an example of a "push" operation. Here there's a hidden region, and a pointer to
it is stored at gs:20h. This region has no permissions, so it can't be leaked or written:

```assembly
.stext:08048AD9 55              push    ebp
.stext:08048ADA 89 E5           mov     ebp, esp
.stext:08048ADC 53              push    ebx
.stext:08048ADD 83 EC 14        sub     esp, 14h
.stext:08048AE0 65 A1 20 00+    mov     eax, large gs:20h                     ; shadow esp is here
.stext:08048AE6 A3 48 A0 04+    mov     ds:SHADOW_ESP_804A048, eax
.stext:08048AEB 8B 15 48 A0+    mov     edx, ds:SHADOW_ESP_804A048
.stext:08048AF1 A1 4C A0 04+    mov     eax, ds:stack_buf
.stext:08048AF6 39 C2           cmp     edx, eax
.stext:08048AF8 77 0C           ja      short loc_8048B06
.stext:08048AFA C7 04 24 01+    mov     dword ptr [esp], 1                    ; status
.stext:08048B01 E8 EA F9 FF+    call    __exit
.stext:08048B06             ; ---------------------------------------------------------------------------
.stext:08048B06
.stext:08048B06             loc_8048B06:                                      ; CODE XREF: push+1Fj
.stext:08048B06 A1 48 A0 04+    mov     eax, ds:SHADOW_ESP_804A048
.stext:08048B0B 83 E8 04        sub     eax, 4                                ; descrease shadow esp
.stext:08048B0E A3 48 A0 04+    mov     ds:SHADOW_ESP_804A048, eax
.stext:08048B13 A1 4C A0 04+    mov     eax, ds:stack_buf
.stext:08048B18 C7 44 24 08+    mov     dword ptr [esp+8], 2                  ; prot (PROT_WRITE)
.stext:08048B20 C7 44 24 04+    mov     dword ptr [esp+4], 1000h              ; len
.stext:08048B28 89 04 24        mov     [esp], eax                            ; addr
.stext:08048B2B E8 90 F9 FF+    call    _mprotect
.stext:08048B30 8B 1D 48 A0+    mov     ebx, ds:SHADOW_ESP_804A048
.stext:08048B36 8B 45 08        mov     eax, [ebp+arg_0]
.stext:08048B39 89 04 24        mov     [esp], eax
.stext:08048B3C E8 CA 00 00+    call    enc_dec
.stext:08048B41 89 03           mov     [ebx], eax
.stext:08048B43 A1 4C A0 04+    mov     eax, ds:stack_buf
.stext:08048B48 C7 44 24 08+    mov     dword ptr [esp+8], 0                  ; prot (PROT_NONE)
.stext:08048B50 C7 44 24 04+    mov     dword ptr [esp+4], 1000h              ; len
.stext:08048B58 89 04 24        mov     [esp], eax                            ; addr
.stext:08048B5B E8 60 F9 FF+    call    _mprotect
.stext:08048B60 A1 48 A0 04+    mov     eax, ds:SHADOW_ESP_804A048            ; VULN: don't clear shadow esp from .bss
.stext:08048B65 65 A3 20 00+    mov     large gs:20h, eax
.stext:08048B6B 83 C4 14        add     esp, 14h
.stext:08048B6E 5B              pop     ebx
.stext:08048B6F 5D              pop     ebp
.stext:08048B70 C3              retn
```

It seems that program is unbreakable right? However there's a small detail here that most
people forget: Performance. A simple call is replaced with:
```assembly
.asm:08048CC1 55              push    ebp
.asm:08048CC2 89 E5           mov     ebp, esp
.asm:08048CC4 83 EC 04        sub     esp, 4
.asm:08048CC7 8B 45 04        mov     eax, [ebp+4]
.asm:08048CCA 89 04 24        mov     [esp], eax
.asm:08048CCD E8 07 FE FF+    call    push
.asm:08048CD2 8B 45 00        mov     eax, [ebp+var_s0]
.asm:08048CD5 89 04 24        mov     [esp], eax
.asm:08048CD8 E8 FC FD FF+    call    push
.asm:08048CDD 8B 45 08        mov     eax, [ebp+arg_0]
.asm:08048CE0 BA 1B 8D 04+    mov     edx, offset ret_stub
.asm:08048CE5 89 55 08        mov     [ebp+arg_0], edx
.asm:08048CE8 C9              leave
.asm:08048CE9 83 C4 04        add     esp, 4
.asm:08048CEC FF E0           jmp     eax
.asm:08048CEC             call endp
```

Which is a pretty big overhead. The same holds for return. If shadow stack is implemented in 
libc, performance will be terrible! Thus, shadow stack is only implemented in the main program.


So, what if the stack overflow happens within libc? In that case, we can overwrite a return 
address and bypass shadow stack. Because of the overflow in message buffer, we can control
the message buffer and its length, which is passed to read(). This gives us an arbitrary
write primitive.

We also have a stack address, so we can have our arbitrary write in the stack. We set message
buffer to point at the saved return address of read() when it's called from getnline(). This
way we can get control of eip. 


### Exploitation
After we get control of eip, we can ROP without any issues. mprotect() is there, so we can
reuse them to make stack executable. After we do that, we can return to an address there
and execute our shellcode. This is possible as we have leaked a stack address.

### Final words
Finally, we can get our shell and read the flag: **TWCTF{pr3v3n7_ROP_u51ng_h0m3m4d3_5h4d0w_574ck}**
Unfortunately when the ctf was over, I only had control of eip, so I missed the 400 points :(

### Getting the flag
```
/usr/bin/python2.7 /root/ctf/mmactf_16/shadow/shadow_expl.py
[*] Stack Address:  0xff8cd11c
[*] Canary Value : 0xc8b9b200
[+] Opening Shell...
id
    uid=18294034 gid=18294(p18294) groups=18294(p18294)
ls -la
    total 28
    drwxr-x--- 2 root p18294  4096 Sep  3 16:05 .
    drwxr-xr-x 6 root root    4096 Sep  2 23:49 ..
    -rw-r----- 1 root p18294    47 Sep  2 23:49 flag
    -rwxr-x--- 1 root p18294 12300 Sep  3 16:05 shadow
cat flag
    TWCTF{pr3v3n7_ROP_u51ng_h0m3m4d3_5h4d0w_574ck}
exit
*** Connection closed by remote host ***

Process finished with exit code 0
```

For more details take a look at exploit file.
___
