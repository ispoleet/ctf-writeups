#!/usr/bin/env python3
# --------------------------------------------------------------------------------------------------
# Plaid CTF 2022 - coregasm (RE)
# --------------------------------------------------------------------------------------------------


# Recovered from `core` at address 0x55FA6CF0A0A0.
globalbuf = [  
    0xF5, 0xE6, 0xF1, 0xE3, 0xDE, 0xC7, 0xC4, 0xCB, 0xC4, 0xCB, 0xC4, 0xFA, 0xC7, 0xC4, 0xCB, 0xC4,
    0xCB, 0xC4, 0xD8, 0xA5, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85,
    0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85,
    0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85, 0x85
]

make_str = lambda arr: ''.join('%c'    % a for a in arr)
make_hex = lambda arr: ' '.join('%02X' % a for a in arr)


# --------------------------------------------------------------------------------------------------
# Code taken from (I modified it a little to convert to double numbers):
# https://www.geeksforgeeks.org/python-program-to-represent-floating-number-as-hexadecimal-by-ieee-754-standard/
# --------------------------------------------------------------------------------------------------
# Code taken from (I modified it a little to convert to double numbers):
# Function for converting decimal to binary
def float_bin(my_number, places = 3):
    my_whole, my_dec = str(my_number).split(".")
    my_whole = int(my_whole)
    res = (str(bin(my_whole))+".").replace('0b','')

    for x in range(places):
        my_dec = str('0.')+str(my_dec)
        temp = '%1.20f' %(float(my_dec)*2)
        my_whole, my_dec = temp.split(".")
        res += my_whole
    return res


def IEEE754(n) :
    # identifying whether the number
    # is positive or negative
    sign = 0
    if n < 0 :
        sign = 1
        n = n * (-1)
    p = 60#30
    # convert float to binary
    dec = float_bin (n, places = p)

    dotPlace = dec.find('.')
    onePlace = dec.find('1')
    # finding the mantissa
    if onePlace > dotPlace:
        dec = dec.replace(".","")
        onePlace -= 1
        dotPlace -= 1
    elif onePlace < dotPlace:
        dec = dec.replace(".","")
        dotPlace -= 1
    mantissa = dec[onePlace+1:]

    # calculating the exponent(E)
    exponent = dotPlace - onePlace
    exponent_bits = exponent + (2**10 - 1) #127

    # converting the exponent from
    # decimal to binary
    exponent_bits = bin(exponent_bits).replace("0b",'')

    mantissa = mantissa[0:52]#23]

    # the IEEE754 notation in binary
    final = str(sign) + exponent_bits.zfill(8) + mantissa

    # convert the binary to hexadecimal
    hstr = '0x%0*X' %((len(final) + 3) // 4, int(final, 2))
    return (hstr, final)


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] coregasm crack started.')

    # -------------------------------------------------------------------------
    # Flag 1
    # -------------------------------------------------------------------------
    flag1 = [g ^ 0xA5 for g in globalbuf]
    print(f'[+] Recovering flag #1: {make_str(flag1)}')


    # -------------------------------------------------------------------------
    # Flag 2
    # -------------------------------------------------------------------------
    A = (
        list(0x80083ED7E794313B.to_bytes(8, 'little')) + 
        list(0x75136EBBBF60734F.to_bytes(8, 'little')) + 
        list(0x6C46A704AF4D8380.to_bytes(8, 'little')) + 
        list(0xC1991AB8C1674BBF.to_bytes(8, 'little')) + 
        list(0xDC0B819132401105.to_bytes(8, 'little')) + 
        list(0xAF4464465D7D4DC0.to_bytes(8, 'little')) + 
        list(0x9EAD54BD51956632.to_bytes(8, 'little')) + 
        list(0x0C4D2C981312F974.to_bytes(8, 'little'))) 


    otp = [  # OTP recovered from `core` at address 0x55FA6D3054A0.
      0x1B, 0x80, 0x32, 0xDA, 0x78, 0x8C, 0x0D, 0xF2, 0x65, 0xC6, 
      0xA0, 0x32, 0x97, 0xBF, 0xDA, 0x7F, 0x1F, 0x27, 0xFB, 0xF1, 
      0x7D, 0x65, 0x28, 0xDE, 0xD1, 0x81, 0x7E, 0x08, 0x82, 0xA7, 
      0xEC, 0x01, 0x0A, 0x40, 0x10, 0xF5, 0x38, 0x17, 0x63, 0x67, 
      0xEA, 0x4E, 0xBA, 0x20, 0x7F, 0x10, 0x48, 0xDA, 0x40, 0x6B, 
      0xC0, 0x89, 0x6E, 0x86, 0x24, 0x72, 0x4B, 0x0C, 0xB9, 0x89, 
      0x81, 0x4C, 0xA3, 0x39, 0x3B, 0x31, 0x94, 0xE7, 0xD7, 0x3E, 
      0x08, 0x80, 0x4F, 0x73, 0x60, 0xCA, 0xBB, 0x6E, 0x13, 0x75, 
      0x80, 0x83, 0x14, 0xCD, 0x45, 0xE9, 0x07, 0x22, 0xFE, 0x4A, 
      0x25, 0x80, 0xF6, 0x5B, 0xD7, 0x80, 0x58, 0x31, 0x40, 0x32, 
      0x91, 0x81, 0x0B, 0xDC, 0xC0, 0x4D, 0x7D, 0x5D, 0x46, 0x64, 
      0x44, 0xAF, 0x32, 0x66, 0x95, 0x51, 0xBD, 0x54, 0xAD, 0x9E, 
      0x74, 0xF9, 0x12, 0x13, 0x98, 0x2C, 0x4D, 0x0C
    ]

    flag2 = [globalbuf[i] ^ 0xA5 ^ A[i] ^ otp[i + 64] for i in range(64)]
    print(f'[+] Recovering flag #2: {make_str(flag2)}')

    # -------------------------------------------------------------------------
    # Flag 3
    # -------------------------------------------------------------------------
    print(f'[+] Recovering flag #3 ...')

    B = (
        list(0x6301641F2866C34B.to_bytes(8, 'little')) +
        list(0x1EB4DEF5AC740DCF.to_bytes(8, 'little')) +
        list(0x4F490B1C93DF4671.to_bytes(8, 'little')) +
        list(0x9F82C6EC691CA0B0.to_bytes(8, 'little')) +
        list(0xC2D142FCAF5DCA6B.to_bytes(8, 'little')) +
        list(0xFA68305EB42FCB00.to_bytes(8, 'little')) +
        list(0x62212646A9E04B61.to_bytes(8, 'little')) +
        list(0x0BB73AD9A9992C6B.to_bytes(8, 'little')))


    globuf_stage3 = [
        globalbuf[i] ^ 0xA5 ^ A[i] ^ otp[i + 64] ^ B[i] ^ otp[i] for i in range(64)
    ]

    # Convert a list into a little endian 32-bit.
    DWORD = lambda a: a[0] | (a[1] << 8) | (a[2] << 16) | (a[3] << 24)


    globuf_stage3_dwords = [DWORD(globuf_stage3[i:i + 4]) for i in range(0, 64, 4)]

    print('[+] globalbuf stage #3 (as DWORDs):')
    for i, dword in enumerate(globuf_stage3_dwords):
        print(f'[+] {i:2d} ~> 0x{dword:08X}')

    print('[+] Moving 1 more step backwards...')

    C = (
        list(0x2F01D6F7C8701DA9.to_bytes(8, 'little')) +
        list(0x230ED5E2EC453098.to_bytes(8, 'little')) +
        list(0x2F01DAE2EF4A3F97.to_bytes(8, 'little')) +
        list(0x2301DAE2EC45309B.to_bytes(8, 'little')) +
        list(0x230ED5E2EC4A3F97.to_bytes(8, 'little')) +
        list(0x2002D5E2EC4A3F97.to_bytes(8, 'little')) +
        list(0x200ED5E2EF4A3F97.to_bytes(8, 'little')) +
        list(0x6140948CF3453C97.to_bytes(8, 'little')))

    # Recovered from `core` at address 0x55FA6D304260.
    half_flag = 'PCTF{.............................nbnanbnanbnabanananananba}' 

    print(f'[+] Half flag from core: {half_flag}')
    
    globuf_stage4 = [ord(h) ^ c for h, c in zip(half_flag, C)]

    print('[+] globuf stage #4 (as QWORDs):')
    for i in range(0, 64, 8):
        print(f'[+] {i:2d} ~> {make_hex(globuf_stage4[i:i + 8])}')

    secret = globuf_stage4[40: 48]
    print(f'[+] Repeated secret: {make_hex(secret)}')

    flag3 = [s ^ c for s, c in zip(secret*8, C)]

    print(f'[+] Recovering flag #3: {make_str(flag3)}')


    # -------------------------------------------------------------------------
    # Flag 4
    # -------------------------------------------------------------------------
    print(f'[+] Recovering flag #4 ...')

    D = (
        list(0x6301641F2866C34B.to_bytes(8, 'little')) +
        list(0x1EB4DEF5AC740DCF.to_bytes(8, 'little')) +
        list(0x4F490B1C93DF4671.to_bytes(8, 'little')) +
        list(0x9F82C6EC691CA0B0.to_bytes(8, 'little')) +
        list(0xC2D142FCAF5DCA6B.to_bytes(8, 'little')) +
        list(0xFA68305EB42FCB00.to_bytes(8, 'little')) +
        list(0x62212646A9E04B61.to_bytes(8, 'little')) +
        list(0x0BB73AD9A9992C6B.to_bytes(8, 'little')))

    fpu_stack = [
        15.6579354707501636756,
        214.831820219884093451,
        2526.22752352315034186,
        24751.5189151917131252,
        193984.053677134516846,
        1139716.96293101242827,
        4457828.61824004405162,
        8758372.44193981720582,
        1  # We need an extra element for the last iteration to avoid corner cases.
    ]

    flag4 = []
    abcdefgh = [0]*8

    for i in range(8):
        abcdefgh[i] = fpu_stack[7 - i] / fpu_stack[7 - i - 1]

        print(f"[+] Recovering {'ABCDEFGH'[i]} = {abcdefgh[i]}")

        if i > 0:
            abcdefgh[i] -= sum(abcdefgh[:i])
        
        ieee = IEEE754(abcdefgh[i])[0]
        print(f"[+] Recovering {'abcdefgh'[i]} = {abcdefgh[i]:.16f} ({ieee})")
        
        flag4.append(bytes.fromhex(ieee[6:]).decode('utf-8'))

    # Invert each double as we copy it in big endian.
    flag4 = ''.join(f[::-1] for f in flag4)
    
    print(f'[+] Recovering flag #4: {flag4}')


# --------------------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop:~/ctf/plaid_ctf_2022/coregasm$ ./coregasm_crack.py 
[+] coregasm crack started.
[+] Recovering flag #1: PCTF{banana_banana}                                            
[+] Recovering flag #2: PCTF{banana*banana$banana!banana}                              
[+] Recovering flag #3 ...
[+] globalbuf stage #3 (as DWORDs):
[+]  0 ~> 0xB4000000
[+]  1 ~> 0xFF6D8A1C
[+]  2 ~> 0xB4B5A5CB
[+]  3 ~> 0x00000000
[+]  4 ~> 0x00000000
[+]  5 ~> 0xFF000000
[+]  6 ~> 0x00000000
[+]  7 ~> 0xFF000000
[+]  8 ~> 0x7A6D8A1C
[+]  9 ~> 0x859275E4
[+] 10 ~> 0xB4B5A5CA
[+] 11 ~> 0x00000001
[+] 12 ~> 0x00000001
[+] 13 ~> 0x30258008
[+] 14 ~> 0x00000000
[+] 15 ~> 0x12345678
[+] Moving 1 more step backwards...
[+] Half flag from core: PCTF{.............................nbnanbnanbnabanananananba}
[+] globuf stage #4 (as QWORDs):
[+]  0 ~> F9 5E 24 8E 8C F8 2F 01
[+]  8 ~> B6 1E 6B C2 CC FB 20 0D
[+] 16 ~> B9 11 64 C1 CC F4 2F 01
[+] 24 ~> B5 1E 6B C2 CC F4 2F 0D
[+] 32 ~> B9 11 24 8E 8C B4 60 41
[+] 40 ~> F9 5E 24 8E 8C B4 60 41
[+] 48 ~> F9 5E 24 8E 8C B4 60 41
[+] 56 ~> F9 5E 24 8E
[+] Repeated secret: F9 5E 24 8E 8C B4 60 41
[+] Recovering flag #3: PCTF{bananabnanbnanannanbnabnnabnanbnanbnanbnabanananananba}   
[+] Recovering flag #4 ...
[+] Recovering A = 1.964717173312426
[+] Recovering a = 1.9647171733124260 (0x3FFF6F7B46544350)
[+] Recovering B = 3.9113470828545336
[+] Recovering b = 1.9466299095421076 (0x3FFF2565676E6172)
[+] Recovering C = 5.8753126420790664
[+] Recovering c = 1.9639655592245329 (0x3FFF6C6726756F7E)
[+] Recovering D = 7.837258567516562
[+] Recovering d = 1.9619459254374956 (0x3FFF642169246458)
[+] Recovering E = 9.797818559380007
[+] Recovering e = 1.9605599918634447 (0x3FFF5E74276E6470)
[+] Recovering F = 11.759093792239495
[+] Recovering f = 1.9612752328594887 (0x3FFF616223796170)
[+] Recovering G = 13.720315850145191
[+] Recovering g = 1.9612220579056956 (0x3FFF612A616E6168)
[+] Recovering H = 15.657935470750164
[+] Recovering h = 1.9376196206049734 (0x3FFF007D6E696170)
[+] Recovering flag #4: PCTF{orange%~ou&glXd$i!dpdn't^pay#bahana*apain}
'''
# --------------------------------------------------------------------------------------------------

