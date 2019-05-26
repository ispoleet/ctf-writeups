#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# 0CTF 2016 - VM (RE 7)
# --------------------------------------------------------------------------------------------------
import struct

# those numbers are the result of seed(). We don't care how seed() finds them, we just use them
A = 0x3579beb4
B = 0xf8094a63

encflag = [                                     # encrypted flag
    0xCC, 0xED, 0xF5, 0xAC, 0x70, 0xA4, 0x68, 0x6C, 0xC3, 0x9C, 0x4B, 0x1B, 0x1F, 0x9F, 0xCB, 0xF2,
    0x74, 0x7D, 0x1D, 0x4E, 0xDF, 0x6C, 0x30, 0xCB, 0x23, 0xEB, 0x7F, 0x0E, 0x77, 0x98, 0x79, 0x7E
]
# --------------------------------------------------------------------------------------------------
# This function generates a pseudo-random number. Code directly extracted from the emulated
# program.
def rand():
    global A, B

    C = ((A + B)*0x11 + 0xc)                   & 0xffffffff
    x = (0x24924925 * B) >> 32
    D = (A - ((((B - x) >> 1) + x) >> 2))      & 0xffffffff
    E = (((0xaaaaaaab * (A ^ B)) >> 32) >> 3)  & 0xffffffff       
    F = (((A * B) & 0xffffffff) + (D + E - B)) & 0xffffffff

    A = C ^ F

    if B != 0:
        G = (0x13572468*(A*3 + B)) & 0xffffffff
        B = (G - (A % B) + 0xbc)   & 0xffffffff

    else:
        if A != 0:
            B = ((A*3 + B)*23 - (B % A) + 0xbc) & 0xffffffff
        else:
            # A and B are 0, so B 0xbc
            B = ((A*3 + B)*23 + 0xbc) & 0xffffffff

    H = ((B ^ ~A) ^ (B |  A)) & 0xffffffff
    I = ((A |  B) ^ (A | ~B)) & 0xffffffff
    J = (~(B | A)) & 0xffffffff
    
    return I ^ J ^ H 

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    # -------------------------------------------------------------------------
    # Here's the original algorithm:
    #
    #    flag = 'kyriakos12345678ispo1234foooooo\0'
    #    flag = [ord(f) for f in flag]
    # 
    #    for i in range(0x80):
    #        loc_20 = (rand() >> 10) & 7
    #        loc_24 = rand() & 0x1f
    #        loc_1c = rand() & 0x1f
    #
    #        while loc_1c == loc_24:
    #            loc_1c = rand() & 0x1f            
    #       
    #        if   loc_20 == 0: flag[loc_24] += flag[loc_1c]
    #        elif loc_20 == 1: flag[loc_24] += loc_1c
    #        elif loc_20 == 2: flag[loc_24] -= flag[loc_1c]
    #        elif loc_20 == 3: flag[loc_24] -= loc_1c
    #        elif loc_20 == 4: flag[loc_24] ^= flag[loc_1c]
    #        elif loc_20 == 5: flag[loc_24] ^= loc_1c
    #        elif loc_20 == 6: flag[loc_24] += 1
    #        elif loc_20 == 7: flag[loc_24], flag[loc_1c] = flag[loc_1c], flag[loc_24]
    #
    #
    # print ['%02x' % (x & 0xff) for x in flag]
    # -------------------------------------------------------------------------


    flag = encflag
 
    # -------------------------------------------------------------------------
    # Step 1: collect pseudo-random numbers
    # -------------------------------------------------------------------------
    PRNG = []


    for i in range(0x80):                       # run the algorithm
        loc_20 = (rand() >> 10) & 7
        loc_24 = rand() & 0x1f
        loc_1c = rand() & 0x1f

        while loc_1c == loc_24:
            loc_1c = rand() & 0x1f            

        PRNG.append( (loc_20, loc_24, loc_1c) ) # collect numbers only


    # -------------------------------------------------------------------------
    # Step 2: execute algorithm backwards
    # -------------------------------------------------------------------------
    for i in range(0x80, 0, -1):
        loc_20, loc_24, loc_1c = PRNG[i-1]

        # inverse all operations
        if   loc_20 == 0: flag[loc_24] -= flag[loc_1c]
        elif loc_20 == 1: flag[loc_24] -= loc_1c
        elif loc_20 == 2: flag[loc_24] += flag[loc_1c]
        elif loc_20 == 3: flag[loc_24] += loc_1c
        elif loc_20 == 4: flag[loc_24] ^= flag[loc_1c]
        elif loc_20 == 5: flag[loc_24] ^= loc_1c
        elif loc_20 == 6: flag[loc_24] -= 1
        elif loc_20 == 7: flag[loc_24], flag[loc_1c] = flag[loc_1c], flag[loc_24]


    # -------------------------------------------------------------------------
    # Step 3: simply print the flag
    # -------------------------------------------------------------------------
    print ['%02x' % (x & 0xff) for x in flag]
    print 'Flag found: %s' % ''.join(['%c' % (x & 0xff) for x in flag])

# --------------------------------------------------------------------------------------------------
'''
ispo@nogirl:~/ctf/2016/0ctf/vm$ ./vm_crack.py 
['30', '63', '74', '66', '7b', '4d', '69', '70', '73', '65', '6c', '5f', '56', '69', '72', '74', 
 '75', '61', '6c', '5f', '4d', '61', '63', '68', '69', '6e', '65', '5f', '3e', '3c', '7d', '00']
Flag found: 0ctf{Mipsel_Virtual_Machine_><}
'''
# --------------------------------------------------------------------------------------------------
