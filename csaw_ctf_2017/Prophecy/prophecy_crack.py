#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# CSAW 2017 - Prophecy (RE 200)
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
    s = socket.create_connection(('reversing.chal.csaw.io', 7668))
    #s = socket.create_connection(('127.0.0.1', 7777))

    recv_until('>>')

    s.send('ispo.starcraft\n')                      # name should contain ".starcraft"

    recv_until('>>')


    secret  = struct.pack("<L", 0x17202508)

    # -------------------------------------------------------------------------
    # The last character of the secret (which is a \n) is replaced with a NULL
    # byte. We should add a NULL byte at the first 8 bytes (which are not used),
    # otherwise we'll replace the 0xe4 byte from '\x93\xea\xe4\x00' with a NULL.
    # -------------------------------------------------------------------------
    secret += 'AAAAAAA\x00'
    secret += 'O'                       # 4 paths here: 0x4A, 0x4B, 0x4F and 0x5A. Pick any
    secret += '\x03'                    # This can be any of 1, 2, 3
    secret += '\x93\xea\xe4\x00'        # be careful here!
    secret += 'ZERATUL'
    secret += '\x00SAVED'
    secret += '\x00LLA'

    s.send(secret + '\n')

    for i in range(16):                 # catch any responses
        print 'RECV:', s.recv(1000)

# --------------------------------------------------------------------------------------------------
'''
ispo@nogirl:~/ctf/2017/csaw_ctf$ ./prophecy_crack.py
RECV: [*]Interpreting the secret....

RECV: [*]Waiting....
[*]On a distant, shadowed world, the protoss will make their final stand.
[*]You'll see that better future Matt. But it 'aint for the likes of us.
[*]The xel'naga, who forged the stars,Will transcend their creation....
[*]Yet, the Fallen One shall remain,Destined to cover the Void in shadow...
[*]Before the stars wake from their Celestial courses,
[*]He shall break the cycle of the gods,Devouring all light and hope.
==========================================================================================================
[*]ZERATUL:flag{N0w_th3_x3l_naga_that_f0rg3d_us_a11_ar3_r3turn1ng_But d0_th3y_c0m3_to_sav3_0r_t0_d3str0y?}
==========================================================================================================
[*]Prophecy has disappered into the Void....

RECV:
RECV:
RECV:
RECV:
RECV:
RECV:
RECV:
RECV:
RECV:
RECV:
RECV:
RECV:
RECV:
RECV:
'''
# --------------------------------------------------------------------------------------------------
