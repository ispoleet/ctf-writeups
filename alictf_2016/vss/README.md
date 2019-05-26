## AliCTF 2016 - VSS - Very Secure System (Pwn 100)
##### 04-06/06/2016 (48hr)
___

### Description: 
It's a very secure system. (attachment)

nc 121.40.56.102 2333
___
### Solution


Let's start with analysing the binary. It's a statically linked file, which means that there will
be many ROP gadgets available :). Although there are no names library calls, it's easy to find
out what each function does just by observing the argument and the input/output.

main() asks for a password and invokes function at 0x40108E for the check:
```assembly
.text:00000000004011E4     mov     edi, offset aPassword       ; "Password:"
.text:00000000004011E9     call    puts_408800
.text:00000000004011EE     lea     rax, [rbp+var_400]
.text:00000000004011F5     mov     edx, 400h                   ; arg3: 1024
.text:00000000004011FA     mov     rsi, rax                    ; arg2: &s
.text:00000000004011FD     mov     edi, 0                      ; arg1: stdin (0)
.text:0000000000401202     call    read_437EA0                 ; fprintf() ??
.text:0000000000401207     lea     rax, [rbp+var_400]
.text:000000000040120E     mov     rdi, rax
.text:0000000000401211     call    pw_check_40108E
```

pw_check() is a buggy function; It always ends up in a seg fault. The overflow is easy to find:

```assembly
.text:000000000040108E     push    rbp
.text:000000000040108F     mov     rbp, rsp
.text:0000000000401092     sub     rsp, 50h
.....
.text:00000000004010D1     mov     edx, 50h                    ; arg3: 0x50 --> overflow
.text:00000000004010D6     mov     rsi, rcx                    ; arg2: pw
.text:00000000004010D9     mov     rdi, rax                    ; arg1: &loc
.text:00000000004010DC     call    memcpy_400330               ; memcpy()
.text:00000000004010E1     movzx   eax, byte ptr [rbp+pw_40]   ; eax = pw[0]
.text:00000000004010E5     cmp     al, 70h                     ; pw[0] == 'p'?
.text:00000000004010E7     jnz     short OK_4010FB
.text:00000000004010E9     movzx   eax, byte ptr [rbp+pw_40+1]
.text:00000000004010ED     cmp     al, 79h                     ; pw[1] == 'y'?
.text:00000000004010EF     jnz     short OK_4010FB             ; exit
.text:00000000004010F1     mov     eax, 1
.text:00000000004010F6     jmp     locret_4011AF
```

memcpy() copies 0x50 bytes on a stack buffer which is 0x38 bytes. If the first 2 characters are 'py' then
function returns success. Otherwise it XOR each character with 0x66 and compares it with a string that
reads from a file 'pass.enc': 
```assembly
.text:0000000000401116 LOOP_401116:         ; CODE XREF: pw_check_40108E+BFj
.text:0000000000401116     mov     ecx, cs:iterator_6C7A98
.text:000000000040111C     mov     eax, cs:iterator_6C7A98
.text:0000000000401122     cdqe
.text:0000000000401124     movzx   eax, byte ptr [rbp+rax+pw_40]
.text:0000000000401129     xor     eax, 66h                    ; eax = pw[i] ^ 0x66
.text:000000000040112C     mov     edx, eax
.text:000000000040112E     movsxd  rax, ecx
.text:0000000000401131     mov     byte ptr [rbp+rax+pw_40], dl ; pw[i] ^= 0x66
.text:0000000000401135     mov     eax, cs:iterator_6C7A98
.text:000000000040113B     add     eax, 1                      ; i++
.text:000000000040113E     mov     cs:iterator_6C7A98, eax
.text:0000000000401144
.text:0000000000401144 loc_401144:          ; CODE XREF: pw_check_40108E+86j
.text:0000000000401144     mov     eax, cs:iterator_6C7A98
.text:000000000040114A     cmp     eax, [rbp+guard_4]
.text:000000000040114D     jl      short LOOP_401116
.text:000000000040114F     mov     esi, 0
.text:0000000000401154     mov     edi, offset aPass_enc       ; "pass.enc"
.text:0000000000401159     mov     eax, 0
.text:000000000040115E     call    open_437E40                 ; open()
.text:0000000000401163     mov     [rbp+fd_8], eax
.text:0000000000401166     cmp     [rbp+fd_8], 0FFFFFFFFh
.text:000000000040116A     jnz     short FILE_OK_401176        ; file found
.text:000000000040116C     mov     edi, 0FFFFFFFFh
.text:0000000000401171     call    exit_407700
.text:0000000000401176 ; ---------------------------------------------------------------------------
.text:0000000000401176
.text:0000000000401176 FILE_OK_401176:      ; CODE XREF: pw_check_40108E+DCj
.text:0000000000401176     lea     rcx, [rbp+enc_30]           ; file found
.text:000000000040117A     mov     eax, [rbp+fd_8]
.text:000000000040117D     mov     edx, 28h                    ; arg3: 0x28
.text:0000000000401182     mov     rsi, rcx                    ; arg2: buf
.text:0000000000401185     mov     edi, eax                    ; arg1: fd
.text:0000000000401187     call    read_437EA0                 ; read()
.text:000000000040118C     lea     rdx, [rbp+enc_30]
.text:0000000000401190     lea     rax, [rbp+pw_40]
.text:0000000000401194     mov     rsi, rdx                    ; arg2: enc
.text:0000000000401197     mov     rdi, rax                    ; arg1: pw
.text:000000000040119A     call    strcmp_400360               ; strcmp()
.text:000000000040119F     test    eax, eax
.text:00000000004011A1     jnz     short NOT_EQUAL_4011AA
.text:00000000004011A3     mov     eax, 1                      ; success!
.text:00000000004011A8     jmp     short locret_4011AF
```

The first 0x50 bytes are copied directly on the stack, so we can overwrite return address.
But if we execute function body, things will go wrong. The problem is the loop at 0x401116
will eventually overwrite guard variable, so we'll end up in a huge guard value (3 MSB are 0
so they will become 0x66) until we segfault.

To get rid of all these problems we simply set the first 2 character to 'py'. If we do that
we can control return address. However we cannot ROP because we can't write anything below
RIP. To overcome this problem we need to "push" the stack up; We need to return to a gadget
that will move the stack first, so we can continue ROPing in stack address that we can
control from the original 0x400 buffer copy on main. We need an "add rsp, XX" gadget where
XX is big enough to move us on main's buffer. Here's a suitable gadget:
```assembly
.text:00000000004055B6 48 83 C4 78    add     rsp, 78h
.text:00000000004055BA 4C 89 E8       mov     rax, r13
.text:00000000004055BD 5B             pop     rbx
.text:00000000004055BE 5D             pop     rbp
.text:00000000004055BF 41 5C          pop     r12
.text:00000000004055C1 41 5D          pop     r13
.text:00000000004055C3 41 5E          pop     r14
.text:00000000004055C5 41 5F          pop     r15
.text:00000000004055C7 C3             retn
```

After that all we have to do is to calculate the right offsets and continue ROPing. By using
ROPgadget, we can find a ROP chain to execute our shell:
```
	/opt/ROPgadget/ROPgadget.py --binary vss_72e30bb98bdfbf22307133c16f8c9966 --ropchain 
```

Finally we make a python script to perform the attack and we get the flag: **alictf{n0t_v3ry_secure}**
___