#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Tokyo Westerns CTF 2019 - M Poly Cipher (RE 314)
# --------------------------------------------------------------------------------------------------
import struct
import sys


# set a breakpoint at 0x402E1B to grab the result of `call expand_maybe_402000` at 0x78E068
# since our target output is 80 (16*5) characters long, 5 expansions are enough
exp_2a = [
    0x83F19EEE, 0xDA45ED22, 0x0F746D84, 0x5956AB6D, 0x8917C0EF, 0x7A5CF3B6, 0x796712DD, 0x6009FB1F,
    0x6A5BC569, 0x376C57D3, 0xE9BA0D38, 0xBE82E078, 0x77856CC1, 0xA273CFEE, 0xD4142C83, 0x017374A6,
    0xA3AEAE68, 0x02B52304, 0x0E3D4B9E, 0x1EB080BF, 0x30A8374B, 0x84F10F0F, 0x02823509, 0xD0DABFAB,
    0xC85353C6, 0x768E268E, 0x0CDD1B42, 0xDDF3D584, 0xFBDBA0D4, 0xA15D7381, 0x83F4A3F6, 0xD4EAC3EA
]

exp_2b = [
    0xA8780381, 0xD325B893, 0x2889F25F, 0x093C9281, 0x0CA31370, 0xF01ABBBE, 0x069B1EEB, 0x335B65CD,
    0xDBA0F812, 0x26641F2E, 0xCDCD48E0, 0x2FFB8009, 0x75077D6D, 0x8F23624A, 0x71C8F20A, 0xE254B801,
    0x443BA936, 0x6F4F4A2F, 0x8ABA595F, 0x9A8530A6, 0xC42A5A0E, 0x9AD8308D, 0x42628DBD, 0xABAB10DE,
    0x9F95660E, 0xAE0EE93C, 0x9E704772, 0x9E0FE2C0, 0x53E83F2B, 0x37DD53C7, 0xDFA1FE01, 0x04FBED0D
]

exp_2c = [
    0x77354950, 0x113B306D, 0x3F8A1235, 0xE3AF6ED1, 0xF54CD1E9, 0x9EFB71E8, 0x298D44BA, 0x8F672270,
    0xE9A97023, 0x7100D45B, 0x08F2A5E4, 0xEE09E4A5, 0xC6539FC7, 0xC8538753, 0xF59E1B4B, 0xD268290E,
    0x76F1D203, 0x9917E9B2, 0x908A32D4, 0xE8D20101, 0x6092F88E, 0x84FC73EC, 0xCBD92758, 0x44A66424,
    0x82779517, 0xEC39BEFE, 0xD9FE6B2D, 0x2520232C, 0xDDA34A8D, 0x1E5FE69A, 0xD99E98BA, 0x66AA19E2
]

exp_2d = [
    0x105426F8, 0x2945D55F, 0x5A6EC101, 0x3C60FC75, 0xBC365FA3, 0x5576699C, 0x99548715, 0x1C08BD1F,
    0xD5375697, 0x1F16FC4C, 0x541BE791, 0x169314FF, 0xDDBFC2DB, 0x9C131E7F, 0xEC9B6A6E, 0x19700898,
    0x630BC067, 0x5154DFC8, 0x739A5761, 0x9EBCE304, 0x6D8F9D46, 0x369056A4, 0x5BC4E09E, 0xA139BBE8,
    0x93023D62, 0xE5979177, 0x73911EA2, 0xED9A6998, 0x6AAD6804, 0xC6EC99AA, 0xAF8F109C, 0x81793378
]

exp_2e = [
    0x6E15B6ED, 0xF259349E, 0xFED4FDD8, 0x759A482B, 0x4B150FD6, 0xD42698F1, 0x85D88CE1, 0x253796EE,
    0x941AF694, 0x0997B347, 0xCDB22EBB, 0x365EF56C, 0x458F3E90, 0xA1C536C3, 0x00E1284D, 0x5F557B37,
    0xADF6DFF8, 0x6260A096, 0x3DB81FF5, 0x7A8E070A, 0x7A0609FA, 0x9E6DED19, 0x377743D5, 0x8EAD5A5B,
    0x69BF4721, 0x04EA93A4, 0xC2C34E47, 0xEE0B5F03, 0x9A03038A, 0xDE6BA695, 0xC7997AD9, 0x0C195D2D
]

# aggregate all expansions together
exp = [exp_2a, exp_2b, exp_2c, exp_2d, exp_2e]


# --------------------------------------------------------------------------------------------------
# ROL and ROR instructions for 32 bits
rol = lambda a, b: ((a << b) & 0xffffffff) | (a >> (32 - b))
ror = lambda a, b: (a >> b) | ((a << (32 - b)) & 0xffffffff)


# --------------------------------------------------------------------------------------------------
# Encryption function
def encrypt_round(a, b, exp_2):
    # We don't really need a table for V's but nevermind.
    V = [0]*32

    V[0] = (exp_2[0] + a) & 0xffffffff
    V[1] = (exp_2[1] + b) & 0xffffffff

    print 'V[ 0] = 0x%08x' % V[0]
    print 'V[ 1] = 0x%08x' % V[1]

    for i in xrange(2, 26):
        V[i] = (rol(V[i-1] ^ V[i-2], (V[i-1] & 31)) + exp_2[i]) & 0xffffffff
        print 'V[%2d] = 0x%08x' % (i, V[i])

    return V[24], V[25]


# --------------------------------------------------------------------------------------------------
# Decryption function (reversed algorithm)
def decrypt_round(a, b, exp_2):
    V = [0]*32

    V[25], V[24] = a, b

    for i in xrange(23, -1, -1):
        V[i] = ror((V[i+2] - exp_2[i+2] + 0x100000000) & 0xffffffff, V[i+1] & 31) ^ V[i+1]
        # print 'V[%2d] = 0x%08x' % (i, V[i])

    c = (V[0] - exp_2[0] + 0x100000000) & 0xffffffff
    d = (V[1] - exp_2[1] + 0x100000000) & 0xffffffff

    # convert numbers back to ASCII
    plain  = chr(c >> 24) + chr((c >> 16) & 0xff) + chr((c >> 8) & 0xff) + chr(c & 0xff)
    plain += chr(d >> 24) + chr((d >> 16) & 0xff) + chr((d >> 8) & 0xff) + chr(d & 0xff)

    return plain


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    print '[+] Holy Grail War crack started.'

    # -------------------------------------------------------------------------
    # Encryption example
    # -------------------------------------------------------------------------
    '''
    input = 'KYRIAKOZ'    
    input += '\x00'*(8 - len(input) % 8)    # zero padding to 8 bytes

    input_chunks = [input[i:i+4] for i in xrange(0, len(input), 4)]
    input_chunks2 = [ord(c[3]) | (ord(c[2]) << 8) | (ord(c[1]) << 16) | (ord(c[0]) << 24)
                        for c in input_chunks]
    print input_chunks
    print [hex(x) for x in input_chunks2]

    cipher = ''
    
    # encrypt
    for i in xrange(len(input_chunks2) >> 1):
        print hex(input_chunks2[2*i]), hex(input_chunks2[2*i+1])

        a, b = encrypt_round(input_chunks2[2*i], input_chunks2[2*i+1], exp[i])
        cipher += '%x%x' % (a, b)

    print '[+] Ciphertext: %s' % cipher
    '''

    # -------------------------------------------------------------------------
    # Crack ciphertext
    #
    # d4f5f0aa8aeee7c83cd8c039fabdee6247d0f5f36edeb24ff9d5bc10a1bd16c12699d29f54659267
    #
    # Break it into 8 byte chunks:
    #       d4f5f0aa8aeee7c8
    #       3cd8c039fabdee62
    #       47d0f5f36edeb24f
    #       f9d5bc10a1bd16c1
    #       2699d29f54659267
    #
    # Crack each block individually.
    # -------------------------------------------------------------------------
    print "[+] Breaking block 'd4f5f0aa8aeee7c8' (1/5):",
    a, b = 0xd4f5f0aa, 0x8aeee7c8
    p1 = decrypt_round(b, a, exp[0])
    print p1

    print "[+] Breaking block '3cd8c039fabdee62' (2/5):",
    a, b = 0x3cd8c039, 0xfabdee62
    p2 = decrypt_round(b, a, exp[1])
    print p2

    print "[+] Breaking block '47d0f5f36edeb24f' (3/5):",
    a, b = 0x47d0f5f3, 0x6edeb24f
    p3 = decrypt_round(b, a, exp[2])
    print p3

    print "[+] Breaking block 'f9d5bc10a1bd16c1' (4/5):",
    a, b = 0xf9d5bc10, 0xa1bd16c1
    p4 = decrypt_round(b, a, exp[3])
    print p4


    print "[+] Breaking block '2699d29f54659267' (5/5):",
    a, b = 0x2699d29f, 0x54659267
    p5 = decrypt_round(b, a, exp[4])
    print p5

    print '[+] Flag: %s' % (p1 + p2 + p3 + p4 + p5)


# --------------------------------------------------------------------------------------------------
'''
ispo@leet:~/ctf/tokyowesterns_ctf_2019/holy_grail_war$ ./holy_grail_war_crack.py 
    [+] Holy Grail War crack started.
    [+] Breaking block 'd4f5f0aa8aeee7c8' (1/5): TWCTF{Fa
    [+] Breaking block '3cd8c039fabdee62' (2/5): t3_Gr4nd
    [+] Breaking block '47d0f5f36edeb24f' (3/5): _Ord3r_1
    [+] Breaking block 'f9d5bc10a1bd16c1' (4/5): s_fuck1n
    [+] Breaking block '2699d29f54659267' (5/5): 6_h07}
    [+] Flag: TWCTF{Fat3_Gr4nd_Ord3r_1s_fuck1n6_h07}
'''
# --------------------------------------------------------------------------------------------------

