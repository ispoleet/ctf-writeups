#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
import sys
import struct
import copy


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
def SUM(ST, F1):                        # a(i) + a(i-1) + a(i-2) + ... + a(1) + a(0)
    F2 = 0
    c = ST

    while True:
        F2 += FUNC_1( c )

        if c >= F1: break

        c += 1

    return F2

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":

    if len(sys.argv) == 1:
        f = open("sums_clean", "r")

        num = [int(x.strip()) for x in f.readlines()]

        print 'Summation is:', sum(num)

        f.close()

    else:
        a = int(sys.argv[1])
        b = int(sys.argv[2])
        
        c = SUM(a, b)

        print 'Sum[' + str(a) + ', ' + str(b) + '] =', c


# --------------------------------------------------------------------------------------------------
