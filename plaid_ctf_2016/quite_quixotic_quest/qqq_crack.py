#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# PlaidCTF 2016 - quite quixotic quest (RE 300)
# --------------------------------------------------------------------------------------------------
import struct
import md5

# --------------------------------------------------------------------------------------------------
rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":

    # find limits
    minkey  = 'PCTF{                                               }'   # min
    maxkey  = 'PCTF{~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~}'   # max
    min_sum = 0
    max_sum = 0

    for i in minkey : min_sum += ord(i)
    for i in maxkey: max_sum += ord(i)

    print 'Min Key:', hex(min_sum)
    print 'Max Key:', hex(max_sum)

    for s1 in range(min_sum, max_sum+1):                        # for each key

        r = ror(s1, 0x5F, 8)
        s = s1 & 0xffffff00 | r 
        s = rol(s, 1, 32)
        s = s ^ 0x01F9933D ^ 0xC7FFFFFA

        m = md5.new()
        m.update( struct.pack("<I", s) )
        h = m.digest()

        a = struct.unpack("I", h[0:4])[0]
        a = a ^ 0x86F4FA3F

        if a == 0x5BFFFFFF:
            print "Target sum found:", hex(s1)

            h = h + h + h + h
            x = ''
            K = '\x90\x46\x5f\x9b\x0f\x1d\x54\x17\x1b\x4b\x9e\x5f\xe0\x58\x0c\xcd' + \
                '\xac\x60\x54\xa9\x1c\x1e\x4f\x03\x30\x25\xa0\x6c\xbd\x02\x1d\xe6' + \
                '\xb4\x35\x54\xbe\x15\x1b\x4d\x3b\x1d\x7b\x8f\x66\xf9\x1a\x1b\xd8' + \
                '\xb4\x6c\x64\xb3\x09'   
            
            for i in range(0, len(K)):          
                x = x + chr(ord(K[i]) ^ ord(h[i]))


            print 'Flag found:', ''.join( [ (y) for y in x] )
    
    exit(0)

# --------------------------------------------------------------------------------------------------
'''
root@nogirl:~/ctf/plaidctf/quite quixotic quest# ./qqq_crack.py 
    Min Key: 0x805
    Max Key: 0x1947
    Target sum found: 0x145f
    Flag found: PCTF{just_a_l1ttle_thing_1_l1ke_t0_call_ropfuscation}
'''
# --------------------------------------------------------------------------------------------------
