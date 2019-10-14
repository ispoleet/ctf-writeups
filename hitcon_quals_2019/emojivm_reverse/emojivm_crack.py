#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# HITCON CTF quals 2019 - EmojiVM (RE 300)
# --------------------------------------------------------------------------------------------------
import sys
import struct
import codecs


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":    
    gptr_2 = [24, 5, 29, 16, 66, 9, 74, 36, 0, 91, 8, 23, 64, 0, 114, 48, 9, 108, 86, 64, 9, 91, 5,
              26, 0]
    
    gptr_3 = [0]*24

    gptr_4 = [142, 99, 205, 18, 75, 88, 21, 23, 81, 34, 217, 4, 81, 44, 25, 21, 134, 44, 209, 76,
              132, 46, 32, 6, 0]

    '''
    # Original algorithm
    # Key must be in the form: xxxx-yyyy-zzzz-wwww-qqqq

    key = 'xxxx-yyyy-zzzz-wwww-qqqq'

    for i in range(key):
          if i % 4 == 0: gptr_3[i] = key[i] + 0x1e
        elif i % 4 == 1: gptr_3[i] = (key[i] - 8) ^ 7
        elif i % 4 == 2: gptr_3[i] = ((key[i] + 0x2c) ^ 0x44) - 4
        elif i % 4 == 3: gptr_3[i] = key[i] ^ 4


    # At the end gptr_3 must be equal with gptr_4
    # If yes, gptr_2 is XOR-ed with the key
    '''

    # Reverse algorithm
    key = [0]*24
    gptr_3 = gptr_4

    for i in range(24):
        if i % 4 == 0: key[i] = gptr_3[i] - 0x1e
        elif i % 4 == 1: key[i] = (gptr_3[i] ^ 7) + 8
        elif i % 4 == 2: key[i] = ((gptr_3[i] + 4) ^ 0x44) - 0x2c
        elif i % 4 == 3: key[i] = gptr_3[i] ^ 0x61


    print 'Recorvered key:'
    print '\t', key
    print '\t', ['%c' % c for c in key]
    print '\t', ''.join(['%c' % c for c in key])


    print 'Recovered flag (gptr_2):'
    
    for i in range(24):
        gptr_2[i] ^= key[i]


    print '\t', gptr_2
    print '\t', ['%c' % c for c in gptr_2]
    print '\t', ''.join(['%c' % c for c in gptr_2])

# --------------------------------------------------------------------------------------------------
'''
ispo@nogirl:~/ctf/hitcon_ctf_2019/emojivm_reverse$ ./emojivm_crack.py 
Recorvered key:
    [112, 108, 105, 115, 45, 103, 49, 118, 51, 45, 109, 101, 51, 51, 45, 116, 104, 51, 101, 45, 102, 49, 52, 103]
    ['p', 'l', 'i', 's', '-', 'g', '1', 'v', '3', '-', 'm', 'e', '3', '3', '-', 't', 'h', '3', 'e', '-', 'f', '1', '4', 'g']
    plis-g1v3-me33-th3e-f14g
Recovered flag (gptr_2):
    [104, 105, 116, 99, 111, 110, 123, 82, 51, 118, 101, 114, 115, 51, 95, 68, 97, 95, 51, 109, 111, 106, 49, 125, 0]
    ['h', 'i', 't', 'c', 'o', 'n', '{', 'R', '3', 'v', 'e', 'r', 's', '3', '_', 'D', 'a', '_', '3', 'm', 'o', 'j', '1', '}', '\x00']
    hitcon{R3vers3_Da_3moj1}
'''
# --------------------------------------------------------------------------------------------------
