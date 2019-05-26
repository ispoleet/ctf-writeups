#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Google CTF 2017 - Counter (RE 420)
# --------------------------------------------------------------------------------------------------
import sys
import struct
import copy

buf_602098    = []
number_602090 = 0


# --------------------------------------------------------------------------------------------------
def read_code():
    global buf_602098, number_602090

    f = open("code", "r")

    number_602090 = struct.unpack("<L", f.read(4))[0]

    # ignore the checks
    for i in range(number_602090):
        buf_602098.append( [
            struct.unpack("<L", f.read(4))[0],
            struct.unpack("<L", f.read(4))[0],
            struct.unpack("<L", f.read(4))[0],
            struct.unpack("<L", f.read(4))[0]
        ])

    f.close()


# --------------------------------------------------------------------------------------------------
def count(flag, curr):
    global buf_602098, number_602090

    while curr != number_602090:
        b = buf_602098[ curr ]

        if b[0] == 0:
            flag[ b[1] ] += 1
            curr = b[2]

        elif b[0] == 1:
            if flag[ b[1] ] == 0: 
                curr = b[3]
            else:
                curr = b[2]
                flag[ b[1] ] -= 1
            
        elif b[0] == 2:
            F = copy.deepcopy(flag)

            count(F, b[2])
                
            for i in range(b[1]):
                flag[i] = F[i]
                
            del F

            curr = b[3]


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":

    flag_603010    = [0]*26
    flag_603010[0] = int(sys.argv[1])

    read_code()

    count(flag_603010, 0)

    print "CTF{%016x}" % flag_603010[0]

    
# --------------------------------------------------------------------------------------------------
