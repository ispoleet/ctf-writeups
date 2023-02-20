#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# HXP CTF 2020 - restless (RE 833)
# ----------------------------------------------------------------------------------------
import hashlib
import z3


leak_values = [
    0x033, 0x11C, 0x3F1, 0x02F, 0x176, 0x37D, 0x36F, 0x11C, 0x0BA, 0x1DC,
    0x2CC, 0x31B, 0x3FF, 0x22F, 0x1EE, 0x159, 0x363, 0x1B4, 0x2A7, 0x2CB,
    0x30B, 0x165, 0x0C6, 0x25B, 0x186, 0x2C9, 0x2E8, 0x360, 0x001, 0x3E4,
    0x104, 0x32C, 0x3A8, 0x1A8, 0x38D, 0x3CA, 0x2E7, 0x2C2, 0x1DA, 0x100,
    0x32F, 0x13C, 0x073, 0x399, 0x355, 0x245, 0x1DC, 0x0B1, 0x287, 0x19E,
    0x0AE, 0x275, 0x1D1, 0x082, 0x339, 0x0B7, 0x2C2, 0x329, 0x087, 0x026,
    0x01C, 0x36B, 0x153, 0x3AD
]


trg_md5 = [
    0x30, 0x6F, 0x03, 0x06, 0xBC, 0x6B, 0x9B, 0x57,
    0x1A, 0x52, 0xF0, 0x59, 0x67, 0x98, 0xAE, 0x42
]


# ----------------------------------------------------------------------------------------
# MD5 helpers

# s specifies the per-round shift amounts
s  = [ 7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22 ]
s += [ 5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20 ]
s += [ 4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23 ]
s += [ 6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21 ]

# (Or just use the following precomputed table):
K  = [ 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ]
K += [ 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ]
K += [ 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ]
K += [ 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ]
K += [ 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ]
K += [ 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ]
K += [ 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ]
K += [ 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ]
K += [ 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ]
K += [ 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ]
K += [ 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ]
K += [ 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ]
K += [ 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ]
K += [ 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ]
K += [ 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ]
K += [ 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 ]

rol = lambda a, b: ((a << b) | (a >> (32 - b))) & 0xFFFFFFFF
ror = lambda a, b: ((a >> b) | (a << (32 - b))) & 0xFFFFFFFF

# Change endianess (big <-> little) in 32 and 64 bits.
ch_endian = lambda a: (( a        & 0xFF) << 24 |
                       ((a >> 8)  & 0xFF) << 16 |
                       ((a >> 16) & 0xFF) << 8  |
                        (a >> 24))

ch_endian64 = lambda a: ( (a        & 0xFF) << 56 |
                         ((a >> 8)  & 0xFF) << 48 |
                         ((a >> 16) & 0xFF) << 40 |
                         ((a >> 24) & 0xFF) << 32 |
                         ((a >> 32) & 0xFF) << 24 |
                         ((a >> 40) & 0xFF) << 16 |
                         ((a >> 48) & 0xFF) << 8  |
                          (a >> 56))

#masks = [0xFE000007, 0x3FF00000, 0x01FF80

# ----------------------------------------------------------------------------------------
def my_md5(inp):
    """Vanilla implemtation of MD5 (code taken from Wikipedia)."""
    # https://en.wikipedia.org/wiki/MD5#Pseudocode
    global s, K  # `s` and `K` are global

    # Initialize variables
    a0 = 0x67452301  # A
    b0 = 0xefcdab89  # B
    c0 = 0x98badcfe  # C
    d0 = 0x10325476  # D

    # Convert input string to bit string
    msg  = ''.join(f'{ord(i):08b}' for i in inp)

    # append "1" bit to message
    msg += '1'

    # append "0" bit until message length in bits = 448 (mod 512)
    msg += '0'*(448 - len(msg))

    # append original length in bits mod 2**64 to message
    msg += '{0:064b}'.format(ch_endian64(len(inp)*8))

    assert len(msg) == 512

    # Process the message in successive 512-bit chunks:
    # for each 512-bit chunk of padded message do
    #     break chunk into sixteen 32-bit words M[j], 0 <= j <= 15
    #
    # ~> We have 1 chunk, so no need for that

    # Initialize hash value for this chunk:
    A, B, C, D = a0, b0, c0, d0    
    b_values = []

    #  Main loop:
    for i in range(64):
        if 0 <= i and i <= 15:
            F = (B & C) | (~B & D)
            g = i
        elif 16 <= i and i <= 31:
            F = (D & B) | (~D & C)
            g = (5*i + 1) % 16
        elif 32 <= i and i <= 47:
            F = B ^ C ^ D
            g = (3*i + 5) % 16
        elif 48 <= i <= 63:
            F = C ^ (B | ~D)
            g = (7*i) % 16

        F &= 0xFFFFFFFF

        inp_chunk = ch_endian(int(msg[32*g:32*g + 32], 2))

        # Be wary of the below definitions of a,b,c,d
        F = (F + A + K[i] + inp_chunk) & 0xFFFFFFFF # M[g] must be a 32-bits block
        A = D
        D = C
        C = B
        B = (B + rol(F, s[i])) & 0xFFFFFFFF

        print(f'{i:2d}: A:{A:08X}, B:{B:08X}, C:{C:08X}, D:{D:08X} ~> g:{g} $ {inp_chunk:08X} $ X:{B & 0x3FF:03X}')

        b_values.append(B & 0x3FF)  # Get the leak.

    # Add this chunk's hash to result so far:
    a0 = (a0 + A) & 0xFFFFFFFF
    b0 = (b0 + B) & 0xFFFFFFFF
    c0 = (c0 + C) & 0xFFFFFFFF
    d0 = (d0 + D) & 0xFFFFFFFF
    # end for

    a0 = ch_endian(a0)
    b0 = ch_endian(b0)
    c0 = ch_endian(c0)
    d0 = ch_endian(d0)

    print(f'{a0:08X}-{b0:08X}-{c0:08X}-{d0:08X}')
    
    # var char digest[16] := a0 append b0 append c0 append d0 // (Output is in little-endian)
    print(f'{a0:08x}{b0:08x}{c0:08x}{d0:08x}')

    return b_values


# ----------------------------------------------------------------------------------------
def add_inp_constraint(inp_len, inp, slv):
    """Adds constraints to flag bytes."""
    # Allowed characters for the flag.
    charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_'

    # Add constraints to whitelist each character from `charset`.
    def whitelist(inp, slv):
        return z3.Or([inp == ord(x) for x in charset])

    # The MD5 input is flag + 0x80 + zero padding + flag length in bits.
    #
    # Based on the flag length, add the appropriate constraints.
    for g in range(16):
        if g < inp_len // 4:
            slv.add(
                z3.And([
                    whitelist(inp[g] & 0xFF, slv),
                    whitelist(z3.LShR(inp[g], 8) & 0xFF, slv),
                    whitelist(z3.LShR(inp[g], 16) & 0xFF, slv),
                    whitelist(z3.LShR(inp[g], 24) & 0xFF, slv),
            ]))
        elif g == inp_len // 4:
            if inp_len % 4 == 0:
                slv.add(
                    z3.And([                    
                        (inp[g] & 0xFF) == 0x80,
                        (inp[g] >> 8) & 0xFF == 0,
                        (inp[g] >> 16) & 0xFF == 0,
                        (inp[g] >> 24) & 0xFF == 0
                ]))
            elif inp_len % 4 == 1:
                slv.add(
                    z3.And([                    
                        whitelist(inp[g] & 0xFF, slv),
                        (inp[g] >> 8) & 0xFF == 0x80,
                        (inp[g] >> 16) & 0xFF == 0,
                        (inp[g] >> 24) & 0xFF == 0
                ]))
            elif inp_len % 4 == 2:
                slv.add(
                    z3.And([
                        whitelist(inp[g] & 0xFF, slv),
                        whitelist((inp[g] >> 8) & 0xFF, slv),
                        (inp[g] >> 16) & 0xFF == 0x80,
                        (inp[g] >> 24) & 0xFF == 0
                ]))
            elif inp_len % 4 == 3:
                slv.add(
                    z3.And([
                        whitelist(inp[g] & 0xFF, slv),
                        whitelist((inp[g] >> 8) & 0xFF, slv),
                        whitelist((inp[g] >> 16) & 0xFF, slv),
                        (inp[g] >> 24) & 0xFF == 0x80
                ]))
        elif g == 14:
            slv.add(inp[g] == inp_len*8)
        elif g == 15:
            slv.add(inp[g] == 0x0)
        elif g > inp_len // 4:
            slv.add(inp[g] == 0x0)


# ----------------------------------------------------------------------------------------
def crack_md5(cand_len, b_values):
    """Symbolic implementation of MD5 . """
    global s, K  # `s` and `K` are global

    slv = z3.Solver()
    
    inp = [z3.BitVec(f'inp_{i}', 32) for i in range(16)]

    add_inp_constraint(cand_len, inp, slv)

    # MD5 implementation using symbolic variables.
    a0 = 0x67452301  # A
    b0 = 0xefcdab89  # B
    c0 = 0x98badcfe  # C
    d0 = 0x10325476  # D

    A, B, C, D = a0, b0, c0, d0
   
    for i in range(64):
        if 0 <= i and i <= 15:
            F = (B & C) | (~B & D)
            g = i
        elif 16 <= i and i <= 31:
            F = (D & B) | (~D & C)
            g = (5*i + 1) % 16
        elif 32 <= i and i <= 47:
            F = B ^ C ^ D
            g = (3*i + 5) % 16
        elif 48 <= i <= 63:
            F = C ^ (B | ~D)
            g = (7*i) % 16

        F &= 0xFFFFFFFF
        F = (F + A + K[i] + inp[g]) & 0xFFFFFFFF 
        A = D
        D = C
        C = B

        # NOTE: rol DOES NOT WORK! WE HAVE TO USE z3's `RotateLeft`.
        B = (B + z3.RotateLeft(F, s[i])) & 0xFFFFFFFF

        slv.add(B & 0x3FF == b_values[i])

        
    # Check for solutions
    def to_ascii(x):
        return chr(x & 0xFF) + chr((x >> 8) & 0xFF) + chr((x >> 16) & 0xFF) + chr(x >> 24)

    while slv.check() == z3.sat:
        mdl = slv.model()

        print('[+] Solution FOUND!')
        
        flag = ''
        for i, j in enumerate(inp):
            yy = mdl.evaluate(j).as_long()        
            print(f'[+] {i:2d} ~~> {yy:08X} ~~> {repr(to_ascii(yy))}')
            flag += to_ascii(yy)

        flag = flag[:cand_len]

        print('[+] FLAG IS: hxp{%s}' % flag)
        return 1
    else:
        print('[+] Cannot find satisfiable solution :\\')
        return -1


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Restless crack started.')

    # inp = 'LEETMORE12'
    # b_values = my_md5(inp)
    # hashlib.md5(inp.encode('utf-8')).hexdigest()

    b_values = leak_values[::-1]

    # We do not know the flag length, so we brute force it.
    for i in range(20, 56):
        print(f'[+] Trying flag length {i} ...')
        if crack_md5(i, b_values) != -1:
            break

    print('[+] Program finished. Bye bye :)')


# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop2:~/ctf/hxp_2020/restless$ time ./restless_crack.py
[+] Restless crack started.
[+] Trying flag length 20 ...
[+] Cannot find satisfiable solution :\
[+] Trying flag length 21 ...
[+] Cannot find satisfiable solution :\
[+] Trying flag length 22 ...
[+] Cannot find satisfiable solution :\
[+] Trying flag length 23 ...
[+] Cannot find satisfiable solution :\
[+] Trying flag length 24 ...
[+] Cannot find satisfiable solution :\
[+] Trying flag length 25 ...
[+] Cannot find satisfiable solution :\
[+] Trying flag length 26 ...
[+] Cannot find satisfiable solution :\
[+] Trying flag length 27 ...
[+] Cannot find satisfiable solution :\
[+] Trying flag length 28 ...
[+] Cannot find satisfiable solution :\
[+] Trying flag length 29 ...
[+] Cannot find satisfiable solution :\
[+] Trying flag length 30 ...
[+] Solution FOUND!
[+]  0 ~~> 72305F69 ~~> 'i_0r'
[+]  1 ~~> 33723364 ~~> 'd3r3'
[+]  2 ~~> 30635F64 ~~> 'd_c0'
[+]  3 ~~> 74753072 ~~> 'r0ut'
[+]  4 ~~> 53336E31 ~~> '1n3S'
[+]  5 ~~> 3072665F ~~> '_fr0'
[+]  6 ~~> 31775F6D ~~> 'm_w1'
[+]  7 ~~> 00806873 ~~> 'sh\x80\x00'
[+]  8 ~~> 00000000 ~~> '\x00\x00\x00\x00'
[+]  9 ~~> 00000000 ~~> '\x00\x00\x00\x00'
[+] 10 ~~> 00000000 ~~> '\x00\x00\x00\x00'
[+] 11 ~~> 00000000 ~~> '\x00\x00\x00\x00'
[+] 12 ~~> 00000000 ~~> '\x00\x00\x00\x00'
[+] 13 ~~> 00000000 ~~> '\x00\x00\x00\x00'
[+] 14 ~~> 000000F0 ~~> 'ð\x00\x00\x00'
[+] 15 ~~> 00000000 ~~> '\x00\x00\x00\x00'
[+] FLAG IS: hxp{i_0rd3r3d_c0r0ut1n3S_fr0m_w1sh}
[+] Program finished. Bye bye :)

real	1m20.566s
user	1m20.103s
sys	0m0.461s
'''
# ----------------------------------------------------------------------------------------

