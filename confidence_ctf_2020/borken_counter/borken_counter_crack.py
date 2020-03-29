#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Teaser CONFidence CTF 2020 - Borken Counter (Reversing 207)
# --------------------------------------------------------------------------------------------------
import struct
import sys

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    qword = lambda value: struct.pack("<Q", value)

    print '[+] Borken Counter crack started ...'

    # Read PC traces
    pc_tbl = []
    with open('out.txt', 'r') as fp:
        line = fp.readline().strip()
        while line:
            pc_tbl.append(int(line))
            line = fp.readline().strip()


    flag_bits = []
    key = ''

    for pc in pc_tbl:        
        #  6822: (20, 1) read char (I)        S:[49]
        if pc == 20*10 + 1:
            flag_bits.append(key)
            key = ''

        # 6850: (18, 1) add                  S:[07,49,21]
        elif pc == 18*10 + 1:
            key += '1'

        # 6878: (18, 5) push 2               S:[06,24,02]
        elif pc == 18*10 + 5:
            key += '0'

    flag = ''
    for key in flag_bits[1:]:
        num = int(key[::-1], 2)
        print '%s 0x%x %c' % (key[::-1], num, num)

        flag += chr(num)


    print '[+] Flag is:', flag

# --------------------------------------------------------------------------------------------------
'''
[+] Borken Counter crack started ...
1110000 0x70 p
0110100 0x34 4
1111011 0x7b {
1110111 0x77 w
1101000 0x68 h
1111001 0x79 y
1011111 0x5f _
1101001 0x69 i
1110011 0x73 s
1011111 0x5f _
1100010 0x62 b
1100101 0x65 e
1100110 0x66 f
1110101 0x75 u
1101110 0x6e n
1100111 0x67 g
1100101 0x65 e
1011111 0x5f _
1100101 0x65 e
1110110 0x76 v
1100101 0x65 e
1101110 0x6e n
1011111 0x5f _
1100101 0x65 e
1110011 0x73 s
1101111 0x6f o
1110100 0x74 t
1100101 0x65 e
1110010 0x72 r
1101001 0x69 i
1100011 0x63 c
1111101 0x7d }
[+] Flag is: p4{why_is_befunge_even_esoteric}
'''
# --------------------------------------------------------------------------------------------------
