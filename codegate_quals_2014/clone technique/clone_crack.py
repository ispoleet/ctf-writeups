#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Codegate 2014 - Clone Technique (re 250)
# --------------------------------------------------------------------------------------------------
def __cinit(*argv):
    if len(argv) != 3:
        num_A = 0xa8276bfa
        num_B = 0x92f837ed
        num_C = 1
    else:
        num_A = argv[0] & 0xffffffff
        num_B = argv[1] & 0xffffffff
        num_C = argv[2] & 0xffffffff


    # try to decrypt flag
    decr = decrypt(flag, num_A, num_B)

    # if it contains non-printable characters, don't print it
    if filter(lambda x: x < 0x20 or x > 0x7e, decr) == []:
        print 'Flag found with', hex(num_A), hex(num_B), num_C
        print ''.join([chr(x) for x in decr])


    num_A ^= 0xb72af098
    num_B ^= (num_A * num_B) & 0xffffffff

    return num_A, num_B, num_C


# -------------------------------------------------------------------------------------------------
def decrypt(flag, num_A, num_B):
    decr = [0] * (len(flag)-1)

    for i in range(0, len(flag)-1, 2):
        decr[i] = flag[i] ^ (num_A & 0xff)
        num_A = (((num_A << 5) & 0xffffffff) | (num_A >> 27)) ^ 0x2f

        if flag[i+1] == 0:
            break

        decr[i + 1] = flag[i + 1] ^ (num_B & 0xff)

        num_B = (((num_B << 11) & 0xffffffff) | (num_B >> 21)) ^ (num_A & 0xff)

    return decr


# -------------------------------------------------------------------------------------------------
def pow(x, n):
    y = 1
    for i in range(n):
        y = (y * x) & 0xffffffff

    return y


# -------------------------------------------------------------------------------------------------
def clone(*argv):
    num_A, num_B, num_C = __cinit(*argv)

    tmp_A = num_A
    num_A = (pow(num_A, 2) * 7 + num_A * 0x1d) & 0xffffffff
    num_B = pow(num_B ^ num_A, (num_A % 2) + 5) 


    if tmp_A <= 0xd0000000:
        while True:
            if num_C > 0x190: return 0

            num_C += 1
            num_A = clone(num_A, num_B, num_C)
            num_B = pow(num_B ^ num_A, num_A % 0x1e)

            if num_A == 0: return 0
    else:
        return (13 * (num_A / 0x1B)) ^ 0x1f2a990d

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":

    # we want to decrypt this
    flag = [ 
        0x0F, 0x8E, 0x9E, 0x39, 0x3D, 0x5E, 0x3F,
        0xA8, 0x7A, 0x68, 0x0C, 0x3D, 0x8B, 0xAD,
        0xC5, 0xD0, 0x7B, 0x09, 0x34, 0xB6, 0xA3,
        0xA0, 0x3E, 0x67, 0x5D, 0xD6, 0x00
    ]

    clone()

# --------------------------------------------------------------------------------------------------
'''
C:\Python27>python.exe C:\Users\ispo\CTF\codegate\clone_crack.py
    Flag found with 0xaf0fd84eL 0x1c7108e0L 286
    And Now His Watch is Ended
'''
# --------------------------------------------------------------------------------------------------
