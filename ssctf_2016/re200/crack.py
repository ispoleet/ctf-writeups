#!/usr/bin/python
# --------------------------------------------------------------------------------------------------
# SSCTF 2016 - Re2 crack
# --------------------------------------------------------------------------------------------------
import hashlib
import random

charset = 'abcdefghijklmnopqrstuvwxyz1234567890'
B       = 'c678d6g64307gf4g`b263473ge35b5`9'
flag    = [0,0,0,0,0,0,0,0]
# --------------------------------------------------------------------------------------------------
def crack(c, j, depth):
    global flag                                         # use the global flag

    if depth == 8:
        b = 0
        for i in range(0, 8): b = (2*b + (ord(flag[i]) ^ ord(B[i+j*8]))) & 0xff

        if b == c: return ''.join(flag)
        return ''

    # add some randomness
    randset = ''.join(random.sample(charset,len(charset)))
    for ch in randset :
        flag[depth] = ch
        retn = crack(c, j, depth+1)

        if retn != '': return retn

    return ''
# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":

    # first find b
    H = [0xFD, 0xC5, 0xFD, 0xE7, 0xC5, 0xE7, 0xC7, 0xE5, 0xC7, 0xDD, 0xE5, 0xDD];

    for b in range(0, 256):                             # for each possible b
        m = hashlib.md5()
        m.update( ''.join([chr(x^b) for x in H]) )
        hash = m.hexdigest()

        if hash == "FBC4A31E4E17D829CA2242B2F893481B".lower():
            print 'b =', hex(b), 'gives hash', hash     #  b = 0xb5
            break

    b = b^2 - 1
    print 'b is', hex(b)

    # then find B_byte
    F =  "Wx}>JL\\5*#P\x7fWxUdKB%5\"fH"

    for B_byte in range(0,256):                         # for each possible B_byte
        F2 = [ord(f) ^ B_byte for f in F]

        b = 0
        for i in range(len(F2)): b ^= F2[i]

        if b == 0xb6:
            print 'B_byte =', hex(B_byte)               # B_byte = 0x98
            break

    # although G is not used anywhere, crack it:
    G = [ 0xDE, 0xF4, 0xF9, 0xFF, 0xE3, 0xAA, 0xAD, 0xFE, 0xA1, 0xFD, 0xAF, 0xA1, 0xAC, 0xAB, 0xAA, 0xAB,
          0xFA, 0xAC, 0xAD, 0xAB, 0xA0, 0xA0, 0xAD, 0xFE, 0xAD, 0xA9, 0xA0, 0xA9, 0xFE, 0xA9, 0xFA, 0xAE,
          0xAA, 0xAC, 0xFC, 0xA8, 0xFA, 0xE5];

    print 'G:', ''.join([chr(x ^ B_byte) for x in G])   # Flag{25f9e794323b453885f5181f1b624d0b}

    # now starts the actual cracking algorithm.
    # first we have to find all possible values of C array. it's only 4 bytes long,
    # so we can brute force it
    print 'Cracking array C...'


    # skip this as it takes some time
    '''
    C = [0, 0, 0, 0]
    for C[0] in range(0,256):
        for C[1] in range(0,256):
            for C[2] in range(0,256):
                for C[3] in range(0,256):

                    if C[0] + C[1] + C[2] + C[3] == 0xDC and \
                       C[0] ^ 0x66 == C[1] ^ 0x77        and \
                       C[0] ^ 0x66 == C[3] ^ 0x6F        and \
                       C[0] ^ 0x66 == C[1] ^ C[2] ^ C[3] :
                            print 'Valid C value:', C
    '''
    '''
    Some valid C arrays are:
        Valid C value: [34, 51, 92, 43]
        Valid C value: [35, 50, 93, 42]
        Valid C value: [42, 59, 84, 35]
        Valid C value: [43, 58, 85, 34]
        Valid C value: [50, 35, 76, 59]
        Valid C value: [51, 34, 77, 58]
        Valid C value: [58, 43, 68, 51]
        Valid C value: [59, 42, 69, 50]
    '''

    # the final steps is to find a valid flag that gives a valid C array.
    # we can brute force here, because each character from C depends only on 8 characters from flag
    # let's use the 1st set: [34, 51, 92, 43]
    print 'Flag:', crack(34, 0, 0) + crack(51, 1, 0) + crack(92, 2, 0) + crack(43, 3, 0)

# --------------------------------------------------------------------------------------------------
