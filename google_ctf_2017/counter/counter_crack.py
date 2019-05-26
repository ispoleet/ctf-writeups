#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Google CTF 2017 - Counter (RE 420)
# --------------------------------------------------------------------------------------------------import sys
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
def FUNC_3(F1, F2):                     # fibonacci!
    F0 = 0
    
    if F1 == 0: return 0    
    if F1 == 1: return 1

    F1 = FUNC_3(F1-1, F2) + FUNC_3(F1-2, F2)
    F0 = F1 % F2

    return F0


# --------------------------------------------------------------------------------------------------
def fibonacci(n, m):                    # optimized fibonacci
    if n == 0: return 0, 1
    else:
        a, b = fibonacci(n // 2, m)
        c    = a * (2*b - a) % m
        d    = (a**2 + b**2) % m

        if n % 2 == 0: return c, d
        else:          return d, (c + d) % m


# --------------------------------------------------------------------------------------------------
def FUNC_2(F1):                         # 3x + 1 problem

    if F1 % 2 == 0:
        return F1 / 2
    else:
        return 3*F1 + 1


# --------------------------------------------------------------------------------------------------
def FUNC_1(F1):     
    # Collatz conjecture is: This process will eventually reach the number 1, regardless of 
    # which positive integer is chosen initially.
    F2 = 0

    while F1 > 1:
        F1 = FUNC_2(F1)
        F2 += 1

    return F2


# --------------------------------------------------------------------------------------------------
def SUM(F1):                            # a(i) + a(i-1) + a(i-2) + ... + a(1) + a(0)
    F2 = 0

    while True:
        F2 += FUNC_1( F1 )
        if F1 == 0: break
        F1 -= 1

    return F2


# --------------------------------------------------------------------------------------------------
def emulated(F0):                       # that's the actual emulated program
    F1 = F0
    F2 = 11

    if F1 < F2: return 0


    F2 = SUM(F1)                    
    F0 = fibonacci(F1, F2)[0]

    return F0


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":

    if len(sys.argv) == 1:                  # do tests
        read_code()


        # do some checks to make sure that the emulated code is correct
        for i in range(23): 
            flag_603010 = [0]*26
            flag_603010[0] = i

            count(flag_603010, 0)           # use slow method

            print "CTF{%016x}" % flag_603010[0], '\t', "CTF{%016x}" % emulated(i)

    else:                                   # calc 2nd part
        # Correct Sum: 2037448192360
        # Flag: CTF{000001bae15b6382}

        print "CTF{%016x}" % fibonacci(9009131337, int(sys.argv[1]))[0]     


# --------------------------------------------------------------------------------------------------
