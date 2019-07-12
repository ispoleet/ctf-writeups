#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Teaser CONFidence CTF 2019 - watchmen (RE 264)
# --------------------------------------------------------------------------------------------------
import string
import capstone
from ctypes import *
from ctypes.wintypes import *



# --------------------------------------------------------------------------------------------------
# encryption stage #1
#
def xor_flag(flag):
    C_STR1 = "October 12th, 1985. Tonight, a comedian died in New York"

    for i in range(32): flag[i] ^= ord(C_STR1[i])

    return flag



# --------------------------------------------------------------------------------------------------
# encryption stage #2
#
def rotate_nibbles(flag):
    v5 = flag[0]

    for i in range(31):
        flag[i] = ((flag[i] >> 4) | (flag[i+1] << 4)) & 0xff

    flag[31] = ((flag[31] >> 4) | (v5 << 4) & 0xff) & 0xff

    return flag



# --------------------------------------------------------------------------------------------------
# encryption stage #3
#
def shuffle_flag(flag):
    C_STR2 = "I am tired of Earth, these people. I'm tired of being caught in the tangle of their lives."

    v94, vb4 = [0]*len(C_STR2), [0]*len(C_STR2)

    for i in range(32):
        v94[i] = i
        vb4[i] = flag[i]

    for j in range(len(C_STR2)):
        # swap element at offset j % 32 with element at offset C_STR2[j] % 32
        v11 = v94[j % 32]
        v94[j % 32] = v94[ord(C_STR2[j]) % 32]
        v94[ord(C_STR2[j]) % 32] = v11

    for k in range(32):
        flag[k] = vb4[v94[k]] & 0xff

    return flag



# --------------------------------------------------------------------------------------------------
# decryption stage #2 (inverse of rotate_nibbles())
#
def rotate_nibbles_inverse(flag):
    flag2 = [ch for ch in flag]                             # do a deep copy

    # you can also do it w/o flag2, if you rotate backwards
    flag2[0]  = ((flag[0] << 4) | (flag[31] >> 4) & 0xff) & 0xff

    for i in range(1, 32):
        flag2[i] = ((flag[i] << 4) | (flag[i-1] >> 4)) & 0xff

    return flag2



# --------------------------------------------------------------------------------------------------
# decryption stage #1 (inverse of shuffle_flag())
#
def shuffle_flag_inverse(flag):
    C_STR2 = "I am tired of Earth, these people. I'm tired of being caught in the tangle of their lives."

    v94, vb4 = [0]*(len(C_STR2)+10), [0]*(len(C_STR2)+10)

    # build the same mapping table
    for i in range(32):
        v94[i] = i
        vb4[i] = flag[i]

    for j in range(len(C_STR2)):
        # swap element at offset j % 32 with element at offset C_STR2[j] % 32
        v11 = v94[j % 32]

        v94[j % 32] = v94[ord(C_STR2[j]) % 32]
        v94[ord(C_STR2[j]) % 32] = v11

    # apply it backwards
    for k in range(32):
        flag[v94[k]] = vb4[k] & 0xff

    return flag



# --------------------------------------------------------------------------------------------------
# A cool trick to read clone's memory at runtime. That way we can access intermediate results
#
def debug_remote_read(pid, address, size):
    PROCESS_ALL_ACCESS = 0x1F0FFF
    
    buff   = c_char_p(" "*size)
    buflen = len(buff.value)
    nread  = c_ulong(0)

    # open process
    proc_hdl = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

    if  windll.kernel32.ReadProcessMemory(proc_hdl, address, buff, buflen, byref(nread)):
        size, data = nread.value, buff.value

    else:
        print 'ReadProcessMemory failed'
        size, data = 0, ""


    windll.kernel32.CloseHandle(proc_hdl)

    return size, data



# --------------------------------------------------------------------------------------------------
# main()
#
if __name__ == "__main__":
    print 'Watchmen code crack started.'


    '''
    # Use process explorer to find process ID
    pid = 10100

    sz, buf = debug_remote_read(pid, 0x43a0cc, 128)
    print "Test Read:", ''.join(buf)

    # at any point of clone's execution you can read the (intermediate) flag
    # (set a breakpoint at GetThreadContext to read ebp)
    ebp     = 0x28FE68
    address = ebp - 0x2a
    sz, buf = debug_remote_read(pid, address, 128)

    print "Flag:", ['%02x' % ord(b) for b in buf]

    '''


    # test encode
    flag = [ord(c) for c in 'ispoleet'*4]
    
    for i in range(16):
        flag = xor_flag(flag)
        flag = rotate_nibbles(flag)        
        flag = shuffle_flag(flag)


    print 'Test Encode', ['%02x' % x for x in flag]


    flag = [ 0xE8, 0xF4, 0xDA, 0xF1, 0x15, 0xC6, 0xB8, 0xBD,
              0x77, 0x8C, 0xC1, 0xF9, 0x74, 0x46, 0x78, 0xBA,
              0xD1, 0x4E, 0xBC, 0x3A, 0xF3, 0x6D, 0xA9, 0x61,
              0x44, 0x61, 0x65, 0x13, 0x6D, 0x3D, 0xCE, 0x7B ]


    for i in range(16):
        flag = shuffle_flag_inverse(flag)
        flag = rotate_nibbles_inverse(flag)
        flag = xor_flag(flag)

    
    print 'Final Flag:', ''.join(['%c' % f for f in flag])


# --------------------------------------------------------------------------------------------------
'''
C:\Users\ispo\watchmen> C:\Python27\python.exe watchmen_crack.py
Watchmen code crack started.
Test Encode ['cc', 'f7', '9a', 'e8', '02', 'c0', 'b0', 'ab', '6c', 'a7', 'db', 'ef', '64', '6f',
             '3f', 'f8', 'c7', '4e', 'ba', '77', 'f3', '76', '8c', '58', '6b', '68', '70', '06',
             '7d', '11', 'd5', '7a']

Final Flag: p4{~JusticeIsComingToAllOfUs...}
'''
# --------------------------------------------------------------------------------------------------
