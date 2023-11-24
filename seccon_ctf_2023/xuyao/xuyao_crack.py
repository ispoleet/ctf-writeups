#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# SECCON Quals 2023 - xuyao (RE 176)
# ----------------------------------------------------------------------------------------
import struct


fish = [
    0xFF324600, 0x4F9A25B8, 0x3CC7477C, 0x0C0B9ECD
]

cat = [
    0xEC656287, 0xD9A22031, 0x01C7BCA8, 0xABE7033B, 0x313FE5DC, 0x940FFAD0,
    0x176EDEB8, 0x7C61B20E, 0x9EAD452F, 0x80E2C15B, 0xBA500D7B, 0xA2C0449F,
    0xBC0E774F, 0x3E393763, 0x43D46B3F, 0x2ADEF404, 0xCA884B87, 0x3C953C45,
    0x7CDBDE63, 0x6E995945, 0xB6CF3655, 0x8D60396A, 0x9A496B38, 0x9D87D81B,
    0x36FEDBC9, 0x79882953, 0x10611E15, 0x0030AB3E, 0x12503487, 0x187E21FF,
    0x6D85127E, 0xDF42C76C
]

sbox = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 
    0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 
    0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 
    0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 
    0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 
    0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 
    0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 
    0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 
    0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 
    0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 
    0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 
    0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 
    0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 
    0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 
    0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 
    0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 
    0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 
    0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

enc_msg = [
    0xFE, 0x60, 0xA8, 0xC0, 0x3B, 0xFE, 0xBC, 0x66, 0xFC, 0x9A, 
    0x9B, 0x31, 0x9A, 0xD8, 0x03, 0xBB, 0xA9, 0xE1, 0x56, 0xFC, 
    0xFC, 0x11, 0x9F, 0x89, 0x5F, 0x4D, 0x9F, 0xE0, 0x9F, 0xAE, 
    0x2A, 0xCF, 0x5E, 0x73, 0xCB, 0xEC, 0x3F, 0xFF, 0xB9, 0xD1, 
    0x99, 0x44, 0x1B, 0x9A, 0x79, 0x79, 0xEC, 0xD1, 0xB4, 0xFD, 
    0xEA, 0x2B, 0xE2, 0xF1, 0x1A, 0x70, 0x76, 0x3C, 0x2E, 0x7F, 
    0x3F, 0x3B, 0x7B, 0x66, 0xA3, 0x4B, 0x1B, 0x5C, 0x0F, 0xBE, 
    0xDD, 0x98, 0x5A, 0x5B, 0xD0, 0x0A, 0x3D, 0x7E, 0x2C, 0x10, 
    0x56, 0x2A, 0x10, 0x87, 0x5D, 0xD9, 0xB9, 0x7F, 0x3E, 0x2E, 
    0x86, 0xB7, 0x17, 0x04, 0xDF, 0xB1, 0x27, 0xC4, 0x47, 0xE2, 
    0xD9, 0x7A, 0x9A, 0x48, 0x7C, 0xDB, 0xC6, 0x1D, 0x3C, 0x00, 
    0xA3, 0x21
]

# Helper functions
rol   = lambda n, c: ((n << c) | (n >> (32 - c))) & 0xFFFFFFFF
ror   = lambda n, c: ((n >> c) | (n << (32 - c))) & 0xFFFFFFFF
bswap = lambda n: (((n & 0xff) << 24) | 
                   (((n >> 8) & 0xFF) << 16) |
                   (((n >> 16) & 0xFF) << 8) |
                   (((n >> 24) & 0xFF) << 0))

# ----------------------------------------------------------------------------------------
# Helper functions from the binary (not reversed).
# ----------------------------------------------------------------------------------------
def tnls(tmp):
    return ( sbox[ tmp        & 0xFF]        |
            (sbox[(tmp >> 8)  & 0xFF] << 8)  |
            (sbox[(tmp >> 16) & 0xFF] << 16) |
            (sbox[(tmp >> 24) & 0xFF] << 24) )


def kls(v_x):
    return v_x ^ rol(v_x, 11) ^ ror(v_x, 7)


def some_func(xor):
    a = tnls(xor)
    bkp_a = a
    a ^= rol(bkp_a, 3)
    a ^= rol(bkp_a, 14)
    a ^= rol(bkp_a, 15)
    a ^= rol(bkp_a, 9)
    return a


def r(cipher, key_12):
    xor = key_12 ^ cipher[1] ^ cipher[2] ^ cipher[3]
    cipher[0] ^= some_func(xor)

    return cipher


# ----------------------------------------------------------------------------------------
def encrypt_block(keystream, msg_blk):
    print(f'[+] Encrypting message block: {msg_blk}')
    cipher = []
    for i in range(0, 16, 4):
        cipher.append(struct.unpack('>L', msg_blk[i:i+4])[0])
    
    print('[+] Initial cipher:', ' '.join(f'{x:08X}' for x in cipher))

    for i in range(32):
        cipher = r(cipher, keystream[12 + i]) # Key stream starts from 12th entry
        #print(f'[+] Round #{i}:', ' '.join(f'{x:08X}' for x in cipher))

        # Rotate to the left.
        cipher = [cipher[1], cipher[2], cipher[3], cipher[0]]
        print(f'[+] Round #{i}:', ' '.join(f'{x:08X}' for x in cipher))

    # Change endianess for each DWORD and flip order.
    cipher = [bswap(a) for a in cipher[::-1]]
    print('[+] Swapped cipher:', ' '.join(f'{x:08X}' for x in cipher))

    return cipher


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] xuyao crack started.')

    # Step 1: Compute key stream.
    key = b'SECCON CTF 2023!'
    key = [
       struct.unpack('>L', key[i:i+4])[0] for i in range(0, 16, 4)
    ]
    print(f'[+] Generating key stream from key: {key}')
    print(f'[+] Key as DWORDs:', ' '.join(f'{x:08X}' for x in key))

    key= [f ^ k for f, k in zip(fish, key)]
    print(f'[+] Key XOR fish :', ' '.join(f'{x:08X}' for x in key))

    # Actual computations start from offset 0x34. Add some padding (8 DWORDs).
    keystream = [0] * 8 + key + [0]*32  

    for j in range(32):
        tmp = keystream[9] ^ keystream[10] ^ keystream[11] ^ cat[j]
        enc = kls(tnls(tmp))

        print(f'Round #{j}: tmp:{tmp:08X} enc:{enc:08X} ~> new:{enc ^ keystream[8]:08X}')

        # XOR first entry and rotate to the left at the same time.
        keystream[8], keystream[9], keystream[10], keystream[11] = (
                keystream[9], keystream[10],  keystream[11], enc ^ keystream[8])

        # Extend key stream by 1 DWORD.
        keystream[12 + j] = keystream[11]  # Or, old keystream[8] ^ enc.

    print('Final key stream:', ' '.join(f'{x:08X}' for x in keystream[8:]))


    # Step 2: Do the forward encryption (OPTIONAL).
    msg = 'ISPOLEETMORE\n'  # Test message.

    pad = chr(16 - len(msg) % 16)*(16 - len(msg) % 16)   
    msg += pad
    
    print(f'Encrypting test message: {msg!r}')

    msg = msg.encode('utf-8')   
    tst_enc = b''
    for i in range(0, len(msg), 16):  # Encrypt in blocks of 16 bytes.
        enc = encrypt_block(keystream, msg[i:i + 16])
        tst_enc += b''.join(struct.pack('<L', e) for e in enc)

    print('[+] Encrypted (test) message:', ' '.join(f'{x:02X}' for x in tst_enc))


    # Step 3: Crack the encrypted message
    print('[+] Cracking the encrypted message ...')

    decr = b''

    #enc_msg = tst_enc
    for k in range(0, len(enc_msg), 16):
        enc = bytes(enc_msg[k:k + 16])
        print('[+] Decrypting message block:', ' '.join(f'{x:02X}' for x in enc))

        plain = []
        for j in range(0, 16, 4):
            plain.append(struct.unpack('<L', enc[j:j+4])[0])

        # Do the swap first.
        plain = [bswap(a) for a in plain[::-1]]

        print('[+] Swapped cipher:',  ' '.join(f'{x:08X}' for x in plain))

        # Run the rounds in inverse.
        for i in range(31, -1, -1):
            # First we rotate to the right.
            plain = [plain[3], plain[0], plain[1], plain[2]]
            # `r` simply XORs so we don't need to inverse it.
            plain = r(plain, keystream[12 + i])
            
            print(f'[+] Round #{i}:', ' '.join(f'{x:08X}' for x in plain))

        for a in plain:
            decr += struct.pack('>L', a)

        print('[+] Decrypted message:', ' '.join(f'{x:02X}' for x in decr))
        print(f'[+] Decrypted message: {decr!r}')

    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
r"""
ispo@ispo-glaptop2:~/ctf/seccon_quals_2023/xuyao$ ./xuyao_crack.py 
[+] xuyao crack started.
[+] Generating key stream from key: [1397048131, 1330520131, 1413881906, 808596257]
[+] Key as DWORDs: 53454343 4F4E2043 54462032 30323321
[+] Key XOR fish : AC770543 00D405FB 6881674E 3C39ADEC
Round #0: tmp:B809ADDE enc:5A717D57 ~> new:F6067814
Round #1: tmp:7B1C9287 enc:EDA7CE85 ~> new:ED73CB7E
Round #2: tmp:268BA22E enc:7D02CFFC ~> new:1583A8B2
Round #3: tmp:A51118E3 enc:31E7207F ~> new:0DDE8D93
Round #4: tmp:C4110B83 enc:D5E44F5F ~> new:23E2374B
Round #5: tmp:AFB0E8BA enc:ADCBF70C ~> new:40B83C72
Round #6: tmp:79EA5812 enc:1EBC29A8 ~> new:0B3F811A
Round #7: tmp:1404382D enc:DB392400 ~> new:D6E7A993
Round #8: tmp:03CD51D4 enc:05C0E937 ~> new:2622DE7C
Round #9: tmp:7B1837AE enc:8539E0DC ~> new:C581DCAE
Round #10: tmp:8F14A63A enc:A239D356 ~> new:A906524C
Round #11: tmp:E8651401 enc:0DA88552 ~> new:DB4F2CC1
Round #12: tmp:0BC6D56C enc:2BF9EA0B ~> new:0DDB3477
Round #13: tmp:41AB7D99 enc:499B4E0A ~> new:8C1A92A4
Round #14: tmp:195AE12D enc:92D1438C ~> new:3BD711C0
Round #15: tmp:90C84317 enc:C0FE49C2 ~> new:1BB16503
Round #16: tmp:66F4ADE0 enc:0D77E357 ~> new:00ACD720
Round #17: tmp:1C5F9FA6 enc:AB2F6074 ~> new:2735F2D0
Round #18: tmp:40F39E90 enc:A144113E ~> new:9A9300FE
Round #19: tmp:D3937C4B enc:E09433A4 ~> new:FB2556A7
Round #20: tmp:F04C92DC enc:CB4D2978 ~> new:CBE1FE58
Round #21: tmp:2737916B enc:E7084A19 ~> new:C03DB8C9
Round #22: tmp:6AB07B0E enc:6DEFB7FF ~> new:F77CB701
Round #23: tmp:6127298B enc:F13AD309 ~> new:0A1F85AE
Round #24: tmp:0BA051AF enc:DF3CD984 ~> new:14DD27DC
Round #25: tmp:90363C20 enc:21985B60 ~> new:E1A5E3A9
Round #26: tmp:EF065FCE enc:B6AD4EEF ~> new:41D1F9EE
Round #27: tmp:B49996A5 enc:F4757949 ~> new:FE6AFCE7
Round #28: tmp:4C4ED227 enc:CCD38BEE ~> new:D80EAC32
Round #29: tmp:7FCB88C4 enc:159B1D04 ~> new:F43EFEAD
Round #30: tmp:BFDFBC06 enc:25A421E1 ~> new:6475D80F
Round #31: tmp:97074DFC enc:C6C9EC31 ~> new:38A310D6
Final key stream: D80EAC32 F43EFEAD 6475D80F 38A310D6 F6067814 ED73CB7E 1583A8B2 0DDE8D93 23E2374B 40B83C72 0B3F811A D6E7A993 2622DE7C C581DCAE A906524C DB4F2CC1 0DDB3477 8C1A92A4 3BD711C0 1BB16503 00ACD720 2735F2D0 9A9300FE FB2556A7 CBE1FE58 C03DB8C9 F77CB701 0A1F85AE 14DD27DC E1A5E3A9 41D1F9EE FE6AFCE7 D80EAC32 F43EFEAD 6475D80F 38A310D6
Encrypting test message: 'ISPOLEETMORE\n\x03\x03\x03'
[+] Encrypting message block: b'ISPOLEETMORE\n\x03\x03\x03'
[+] Initial cipher: 4953504F 4C454554 4D4F5245 0A030303
[+] Round #0: 4C454554 4D4F5245 0A030303 EE1B22D4
[+] Round #1: 4D4F5245 0A030303 EE1B22D4 4F4D588A
[+] Round #2: 0A030303 EE1B22D4 4F4D588A E8AD19FC
[+] Round #3: EE1B22D4 4F4D588A E8AD19FC E8C6A89A
[+] Round #4: 4F4D588A E8AD19FC E8C6A89A 0F2451C3
[+] Round #5: E8AD19FC E8C6A89A 0F2451C3 5BE910D6
[+] Round #6: E8C6A89A 0F2451C3 5BE910D6 0A22DE1B
[+] Round #7: 0F2451C3 5BE910D6 0A22DE1B 6E84E9AE
[+] Round #8: 5BE910D6 0A22DE1B 6E84E9AE 695FD8BC
[+] Round #9: 0A22DE1B 6E84E9AE 695FD8BC DE4C3ECD
[+] Round #10: 6E84E9AE 695FD8BC DE4C3ECD 20697026
[+] Round #11: 695FD8BC DE4C3ECD 20697026 E1208742
[+] Round #12: DE4C3ECD 20697026 E1208742 2D098114
[+] Round #13: 20697026 E1208742 2D098114 5925D012
[+] Round #14: E1208742 2D098114 5925D012 002A303D
[+] Round #15: 2D098114 5925D012 002A303D DAA0D457
[+] Round #16: 5925D012 002A303D DAA0D457 186703D2
[+] Round #17: 002A303D DAA0D457 186703D2 730F5223
[+] Round #18: DAA0D457 186703D2 730F5223 A59E0D30
[+] Round #19: 186703D2 730F5223 A59E0D30 996EC37E
[+] Round #20: 730F5223 A59E0D30 996EC37E A63B692D
[+] Round #21: A59E0D30 996EC37E A63B692D 6AA7BE27
[+] Round #22: 996EC37E A63B692D 6AA7BE27 BAB3BABA
[+] Round #23: A63B692D 6AA7BE27 BAB3BABA 6B1DEBBF
[+] Round #24: 6AA7BE27 BAB3BABA 6B1DEBBF CA96D049
[+] Round #25: BAB3BABA 6B1DEBBF CA96D049 6F832D95
[+] Round #26: 6B1DEBBF CA96D049 6F832D95 A3EFC0BD
[+] Round #27: CA96D049 6F832D95 A3EFC0BD C3BDE9B3
[+] Round #28: 6F832D95 A3EFC0BD C3BDE9B3 5CA6E6F7
[+] Round #29: A3EFC0BD C3BDE9B3 5CA6E6F7 7F87DC45
[+] Round #30: C3BDE9B3 5CA6E6F7 7F87DC45 A76898BA
[+] Round #31: 5CA6E6F7 7F87DC45 A76898BA D224B72C
[+] Swapped cipher: 2CB724D2 BA9868A7 45DC877F F7E6A65C
[+] Encrypted (test) message: D2 24 B7 2C A7 68 98 BA 7F 87 DC 45 5C A6 E6 F7
[+] Cracking the encrypted message ...
[+] Decrypting message block: FE 60 A8 C0 3B FE BC 66 FC 9A 9B 31 9A D8 03 BB
[+] Swapped cipher: 9AD803BB FC9A9B31 3BFEBC66 FE60A8C0
[+] Round #31: 57F14149 9AD803BB FC9A9B31 3BFEBC66
[+] Round #30: 6B26B4FC 57F14149 9AD803BB FC9A9B31
[+] Round #29: 2003BF38 6B26B4FC 57F14149 9AD803BB
[+] Round #28: EFA9E4F5 2003BF38 6B26B4FC 57F14149
[+] Round #27: A071CE93 EFA9E4F5 2003BF38 6B26B4FC
[+] Round #26: 6390F9AA A071CE93 EFA9E4F5 2003BF38
[+] Round #25: 1EC3B39D 6390F9AA A071CE93 EFA9E4F5
[+] Round #24: 71EB9BDB 1EC3B39D 6390F9AA A071CE93
[+] Round #23: 15919B7B 71EB9BDB 1EC3B39D 6390F9AA
[+] Round #22: 5B2B331A 15919B7B 71EB9BDB 1EC3B39D
[+] Round #21: 0BCD32FA 5B2B331A 15919B7B 71EB9BDB
[+] Round #20: B523171A 0BCD32FA 5B2B331A 15919B7B
[+] Round #19: F49F6579 B523171A 0BCD32FA 5B2B331A
[+] Round #18: 99C3983F F49F6579 B523171A 0BCD32FA
[+] Round #17: FB1F324D 99C3983F F49F6579 B523171A
[+] Round #16: 21DE9A1E FB1F324D 99C3983F F49F6579
[+] Round #15: 971A03EB 21DE9A1E FB1F324D 99C3983F
[+] Round #14: 5C52A353 971A03EB 21DE9A1E FB1F324D
[+] Round #13: CB7F588E 5C52A353 971A03EB 21DE9A1E
[+] Round #12: 63D49438 CB7F588E 5C52A353 971A03EB
[+] Round #11: 3F862BB3 63D49438 CB7F588E 5C52A353
[+] Round #10: 05549D14 3F862BB3 63D49438 CB7F588E
[+] Round #9: F9B0AA45 05549D14 3F862BB3 63D49438
[+] Round #8: BB199419 F9B0AA45 05549D14 3F862BB3
[+] Round #7: 5DCAA27C BB199419 F9B0AA45 05549D14
[+] Round #6: 43625FD0 5DCAA27C BB199419 F9B0AA45
[+] Round #5: 6A15E7C7 43625FD0 5DCAA27C BB199419
[+] Round #4: BB6F9CB7 6A15E7C7 43625FD0 5DCAA27C
[+] Round #3: 6F6E7321 BB6F9CB7 6A15E7C7 43625FD0
[+] Round #2: 6C617469 6F6E7321 BB6F9CB7 6A15E7C7
[+] Round #1: 72617475 6C617469 6F6E7321 BB6F9CB7
[+] Round #0: 436F6E67 72617475 6C617469 6F6E7321
[+] Decrypted message: 43 6F 6E 67 72 61 74 75 6C 61 74 69 6F 6E 73 21
[+] Decrypted message: b'Congratulations!'
[+] Decrypting message block: A9 E1 56 FC FC 11 9F 89 5F 4D 9F E0 9F AE 2A CF
[+] Swapped cipher: 9FAE2ACF 5F4D9FE0 FC119F89 A9E156FC
[+] Round #31: CE80F21B 9FAE2ACF 5F4D9FE0 FC119F89
[+] Round #30: 78D6DECD CE80F21B 9FAE2ACF 5F4D9FE0
[+] Round #29: CB7D5937 78D6DECD CE80F21B 9FAE2ACF
[+] Round #28: 81E8FA05 CB7D5937 78D6DECD CE80F21B
[+] Round #27: 57693670 81E8FA05 CB7D5937 78D6DECD
[+] Round #26: E801DF99 57693670 81E8FA05 CB7D5937
[+] Round #25: FE8A8381 E801DF99 57693670 81E8FA05
[+] Round #24: FCD09F38 FE8A8381 E801DF99 57693670
[+] Round #23: F39607AF FCD09F38 FE8A8381 E801DF99
[+] Round #22: 1B7D0D3F F39607AF FCD09F38 FE8A8381
[+] Round #21: 306634A8 1B7D0D3F F39607AF FCD09F38
[+] Round #20: B9AC726D 306634A8 1B7D0D3F F39607AF
[+] Round #19: 64D95A82 B9AC726D 306634A8 1B7D0D3F
[+] Round #18: 72DA19A0 64D95A82 B9AC726D 306634A8
[+] Round #17: BD99C856 72DA19A0 64D95A82 B9AC726D
[+] Round #16: 368F0009 BD99C856 72DA19A0 64D95A82
[+] Round #15: E175B1C7 368F0009 BD99C856 72DA19A0
[+] Round #14: C6587E9A E175B1C7 368F0009 BD99C856
[+] Round #13: FD6BC0A9 C6587E9A E175B1C7 368F0009
[+] Round #12: 3E2E2921 FD6BC0A9 C6587E9A E175B1C7
[+] Round #11: 5A0C4D6B 3E2E2921 FD6BC0A9 C6587E9A
[+] Round #10: DFD81E41 5A0C4D6B 3E2E2921 FD6BC0A9
[+] Round #9: 0E090C26 DFD81E41 5A0C4D6B 3E2E2921
[+] Round #8: AAAC4B18 0E090C26 DFD81E41 5A0C4D6B
[+] Round #7: 763DD548 AAAC4B18 0E090C26 DFD81E41
[+] Round #6: D9613E03 763DD548 AAAC4B18 0E090C26
[+] Round #5: 6FB13351 D9613E03 763DD548 AAAC4B18
[+] Round #4: 05CF0485 6FB13351 D9613E03 763DD548
[+] Round #3: 63727970 05CF0485 6FB13351 D9613E03
[+] Round #2: 65206465 63727970 05CF0485 6FB13351
[+] Round #1: 20686176 65206465 63727970 05CF0485
[+] Round #0: 20596F75 20686176 65206465 63727970
[+] Decrypted message: 43 6F 6E 67 72 61 74 75 6C 61 74 69 6F 6E 73 21 20 59 6F 75 20 68 61 76 65 20 64 65 63 72 79 70
[+] Decrypted message: b'Congratulations! You have decryp'
[+] Decrypting message block: 5E 73 CB EC 3F FF B9 D1 99 44 1B 9A 79 79 EC D1
[+] Swapped cipher: 7979ECD1 99441B9A 3FFFB9D1 5E73CBEC
[+] Round #31: C948AEEC 7979ECD1 99441B9A 3FFFB9D1
[+] Round #30: 44CC9FAB C948AEEC 7979ECD1 99441B9A
[+] Round #29: 259F67F1 44CC9FAB C948AEEC 7979ECD1
[+] Round #28: CD4B692C 259F67F1 44CC9FAB C948AEEC
[+] Round #27: 5A10B455 CD4B692C 259F67F1 44CC9FAB
[+] Round #26: 5AFC77E0 5A10B455 CD4B692C 259F67F1
[+] Round #25: 6264A8D2 5AFC77E0 5A10B455 CD4B692C
[+] Round #24: D48A49A7 6264A8D2 5AFC77E0 5A10B455
[+] Round #23: 6D0E0760 D48A49A7 6264A8D2 5AFC77E0
[+] Round #22: C4F479B2 6D0E0760 D48A49A7 6264A8D2
[+] Round #21: 6C1169A0 C4F479B2 6D0E0760 D48A49A7
[+] Round #20: A223D453 6C1169A0 C4F479B2 6D0E0760
[+] Round #19: 122ED115 A223D453 6C1169A0 C4F479B2
[+] Round #18: D7C10D64 122ED115 A223D453 6C1169A0
[+] Round #17: C6BCFCD8 D7C10D64 122ED115 A223D453
[+] Round #16: 832DD477 C6BCFCD8 D7C10D64 122ED115
[+] Round #15: 7C8B3CF5 832DD477 C6BCFCD8 D7C10D64
[+] Round #14: 88726DC1 7C8B3CF5 832DD477 C6BCFCD8
[+] Round #13: A6E6A4D4 88726DC1 7C8B3CF5 832DD477
[+] Round #12: 2E452D6E A6E6A4D4 88726DC1 7C8B3CF5
[+] Round #11: 14490811 2E452D6E A6E6A4D4 88726DC1
[+] Round #10: 9EED7808 14490811 2E452D6E A6E6A4D4
[+] Round #9: 92B92E8D 9EED7808 14490811 2E452D6E
[+] Round #8: 71AE8EEB 92B92E8D 9EED7808 14490811
[+] Round #7: 53F130D8 71AE8EEB 92B92E8D 9EED7808
[+] Round #6: EFC6F44D 53F130D8 71AE8EEB 92B92E8D
[+] Round #5: 089C94BB EFC6F44D 53F130D8 71AE8EEB
[+] Round #4: ECB61CC9 089C94BB EFC6F44D 53F130D8
[+] Round #3: 3A205345 ECB61CC9 089C94BB EFC6F44D
[+] Round #2: 666C6167 3A205345 ECB61CC9 089C94BB
[+] Round #1: 74686520 666C6167 3A205345 ECB61CC9
[+] Round #0: 74656420 74686520 666C6167 3A205345
[+] Decrypted message: 43 6F 6E 67 72 61 74 75 6C 61 74 69 6F 6E 73 21 20 59 6F 75 20 68 61 76 65 20 64 65 63 72 79 70 74 65 64 20 74 68 65 20 66 6C 61 67 3A 20 53 45
[+] Decrypted message: b'Congratulations! You have decrypted the flag: SE'
[+] Decrypting message block: B4 FD EA 2B E2 F1 1A 70 76 3C 2E 7F 3F 3B 7B 66
[+] Swapped cipher: 3F3B7B66 763C2E7F E2F11A70 B4FDEA2B
[+] Round #31: 223F159D 3F3B7B66 763C2E7F E2F11A70
[+] Round #30: 9715F182 223F159D 3F3B7B66 763C2E7F
[+] Round #29: BA2E6FD9 9715F182 223F159D 3F3B7B66
[+] Round #28: 988BE897 BA2E6FD9 9715F182 223F159D
[+] Round #27: C5EACAF9 988BE897 BA2E6FD9 9715F182
[+] Round #26: A1CEDF5F C5EACAF9 988BE897 BA2E6FD9
[+] Round #25: 9624F9C8 A1CEDF5F C5EACAF9 988BE897
[+] Round #24: 2A2A45D1 9624F9C8 A1CEDF5F C5EACAF9
[+] Round #23: 68760334 2A2A45D1 9624F9C8 A1CEDF5F
[+] Round #22: C0E9542F 68760334 2A2A45D1 9624F9C8
[+] Round #21: 28BE9D60 C0E9542F 68760334 2A2A45D1
[+] Round #20: FA6A2496 28BE9D60 C0E9542F 68760334
[+] Round #19: 57A4109F FA6A2496 28BE9D60 C0E9542F
[+] Round #18: BEF75A6D 57A4109F FA6A2496 28BE9D60
[+] Round #17: D2EE67F4 BEF75A6D 57A4109F FA6A2496
[+] Round #16: 952480FA D2EE67F4 BEF75A6D 57A4109F
[+] Round #15: ECBCB4D0 952480FA D2EE67F4 BEF75A6D
[+] Round #14: 26295959 ECBCB4D0 952480FA D2EE67F4
[+] Round #13: CD3477EC 26295959 ECBCB4D0 952480FA
[+] Round #12: B2B63AAC CD3477EC 26295959 ECBCB4D0
[+] Round #11: 74FB87F1 B2B63AAC CD3477EC 26295959
[+] Round #10: DC5A9604 74FB87F1 B2B63AAC CD3477EC
[+] Round #9: A9D9E511 DC5A9604 74FB87F1 B2B63AAC
[+] Round #8: ADC7AD35 A9D9E511 DC5A9604 74FB87F1
[+] Round #7: 55A1BDE0 ADC7AD35 A9D9E511 DC5A9604
[+] Round #6: A2561F5C 55A1BDE0 ADC7AD35 A9D9E511
[+] Round #5: C5F918F5 A2561F5C 55A1BDE0 ADC7AD35
[+] Round #4: 1C27D52F C5F918F5 A2561F5C 55A1BDE0
[+] Round #3: 5F7A6875 1C27D52F C5F918F5 A2561F5C
[+] Round #2: 5F686532 5F7A6875 1C27D52F C5F918F5
[+] Round #1: 7B783836 5F686532 5F7A6875 1C27D52F
[+] Round #0: 43434F4E 7B783836 5F686532 5F7A6875
[+] Decrypted message: 43 6F 6E 67 72 61 74 75 6C 61 74 69 6F 6E 73 21 20 59 6F 75 20 68 61 76 65 20 64 65 63 72 79 70 74 65 64 20 74 68 65 20 66 6C 61 67 3A 20 53 45 43 43 4F 4E 7B 78 38 36 5F 68 65 32 5F 7A 68 75
[+] Decrypted message: b'Congratulations! You have decrypted the flag: SECCON{x86_he2_zhu'
[+] Decrypting message block: A3 4B 1B 5C 0F BE DD 98 5A 5B D0 0A 3D 7E 2C 10
[+] Swapped cipher: 3D7E2C10 5A5BD00A 0FBEDD98 A34B1B5C
[+] Round #31: 75A4989A 3D7E2C10 5A5BD00A 0FBEDD98
[+] Round #30: E7D52773 75A4989A 3D7E2C10 5A5BD00A
[+] Round #29: 72C55FCA E7D52773 75A4989A 3D7E2C10
[+] Round #28: F3D9CF8A 72C55FCA E7D52773 75A4989A
[+] Round #27: E3EB139B F3D9CF8A 72C55FCA E7D52773
[+] Round #26: 02C79FDF E3EB139B F3D9CF8A 72C55FCA
[+] Round #25: BAAB7480 02C79FDF E3EB139B F3D9CF8A
[+] Round #24: C7535C32 BAAB7480 02C79FDF E3EB139B
[+] Round #23: A4FF9D4C C7535C32 BAAB7480 02C79FDF
[+] Round #22: 1E4DE8C2 A4FF9D4C C7535C32 BAAB7480
[+] Round #21: F9B320E1 1E4DE8C2 A4FF9D4C C7535C32
[+] Round #20: 0F97CCBF F9B320E1 1E4DE8C2 A4FF9D4C
[+] Round #19: A2D6FF99 0F97CCBF F9B320E1 1E4DE8C2
[+] Round #18: 75EEBF5F A2D6FF99 0F97CCBF F9B320E1
[+] Round #17: 6E36A575 75EEBF5F A2D6FF99 0F97CCBF
[+] Round #16: 052277BE 6E36A575 75EEBF5F A2D6FF99
[+] Round #15: A6FB74B0 052277BE 6E36A575 75EEBF5F
[+] Round #14: 16083CE1 A6FB74B0 052277BE 6E36A575
[+] Round #13: FC4BB6F2 16083CE1 A6FB74B0 052277BE
[+] Round #12: 08DC51B6 FC4BB6F2 16083CE1 A6FB74B0
[+] Round #11: E9E9956B 08DC51B6 FC4BB6F2 16083CE1
[+] Round #10: F93DE66C E9E9956B 08DC51B6 FC4BB6F2
[+] Round #9: 4CB6020D F93DE66C E9E9956B 08DC51B6
[+] Round #8: F2BECB7A 4CB6020D F93DE66C E9E9956B
[+] Round #7: FC2C1E3F F2BECB7A 4CB6020D F93DE66C
[+] Round #6: 744DCC26 FC2C1E3F F2BECB7A 4CB6020D
[+] Round #5: 124424F9 744DCC26 FC2C1E3F F2BECB7A
[+] Round #4: 3C920A75 124424F9 744DCC26 FC2C1E3F
[+] Round #3: 5F6A6965 3C920A75 124424F9 744DCC26
[+] Round #2: 5F7A6934 5F6A6965 3C920A75 124424F9
[+] Round #1: 796F7533 5F7A6934 5F6A6965 3C920A75
[+] Round #0: 616E315F 796F7533 5F7A6934 5F6A6965
[+] Decrypted message: 43 6F 6E 67 72 61 74 75 6C 61 74 69 6F 6E 73 21 20 59 6F 75 20 68 61 76 65 20 64 65 63 72 79 70 74 65 64 20 74 68 65 20 66 6C 61 67 3A 20 53 45 43 43 4F 4E 7B 78 38 36 5F 68 65 32 5F 7A 68 75 61 6E 31 5F 79 6F 75 33 5F 7A 69 34 5F 6A 69 65
[+] Decrypted message: b'Congratulations! You have decrypted the flag: SECCON{x86_he2_zhuan1_you3_zi4_jie'
[+] Decrypting message block: 56 2A 10 87 5D D9 B9 7F 3E 2E 86 B7 17 04 DF B1
[+] Swapped cipher: 1704DFB1 3E2E86B7 5DD9B97F 562A1087
[+] Round #31: B7DFD398 1704DFB1 3E2E86B7 5DD9B97F
[+] Round #30: 441D6239 B7DFD398 1704DFB1 3E2E86B7
[+] Round #29: CC87C73F 441D6239 B7DFD398 1704DFB1
[+] Round #28: 3EAEB8F0 CC87C73F 441D6239 B7DFD398
[+] Round #27: 84D05616 3EAEB8F0 CC87C73F 441D6239
[+] Round #26: 430048D4 84D05616 3EAEB8F0 CC87C73F
[+] Round #25: 92A68D67 430048D4 84D05616 3EAEB8F0
[+] Round #24: 8675D49D 92A68D67 430048D4 84D05616
[+] Round #23: 65520D1E 8675D49D 92A68D67 430048D4
[+] Round #22: 814D9670 65520D1E 8675D49D 92A68D67
[+] Round #21: A297B229 814D9670 65520D1E 8675D49D
[+] Round #20: 02891566 A297B229 814D9670 65520D1E
[+] Round #19: 99569096 02891566 A297B229 814D9670
[+] Round #18: 06D8453B 99569096 02891566 A297B229
[+] Round #17: E8D6D408 06D8453B 99569096 02891566
[+] Round #16: 23CA7F15 E8D6D408 06D8453B 99569096
[+] Round #15: 30883D52 23CA7F15 E8D6D408 06D8453B
[+] Round #14: D6593D2A 30883D52 23CA7F15 E8D6D408
[+] Round #13: CF7A462B D6593D2A 30883D52 23CA7F15
[+] Round #12: F587C442 CF7A462B D6593D2A 30883D52
[+] Round #11: 379A0D26 F587C442 CF7A462B D6593D2A
[+] Round #10: 1FA97794 379A0D26 F587C442 CF7A462B
[+] Round #9: DCB77243 1FA97794 379A0D26 F587C442
[+] Round #8: E6D18C43 DCB77243 1FA97794 379A0D26
[+] Round #7: 4C774B06 E6D18C43 DCB77243 1FA97794
[+] Round #6: B148D245 4C774B06 E6D18C43 DCB77243
[+] Round #5: F0316FC5 B148D245 4C774B06 E6D18C43
[+] Round #4: 67EC9FE0 F0316FC5 B148D245 4C774B06
[+] Round #3: 34686532 67EC9FE0 F0316FC5 B148D245
[+] Round #2: 5F68756E 34686532 67EC9FE0 F0316FC5
[+] Round #1: 335F6465 5F68756E 34686532 67EC9FE0
[+] Round #0: 325F6D61 335F6465 5F68756E 34686532
[+] Decrypted message: 43 6F 6E 67 72 61 74 75 6C 61 74 69 6F 6E 73 21 20 59 6F 75 20 68 61 76 65 20 64 65 63 72 79 70 74 65 64 20 74 68 65 20 66 6C 61 67 3A 20 53 45 43 43 4F 4E 7B 78 38 36 5F 68 65 32 5F 7A 68 75 61 6E 31 5F 79 6F 75 33 5F 7A 69 34 5F 6A 69 65 32 5F 6D 61 33 5F 64 65 5F 68 75 6E 34 68 65 32
[+] Decrypted message: b'Congratulations! You have decrypted the flag: SECCON{x86_he2_zhuan1_you3_zi4_jie2_ma3_de_hun4he2'
[+] Decrypting message block: 27 C4 47 E2 D9 7A 9A 48 7C DB C6 1D 3C 00 A3 21
[+] Swapped cipher: 3C00A321 7CDBC61D D97A9A48 27C447E2
[+] Round #31: 71E080CB 3C00A321 7CDBC61D D97A9A48
[+] Round #30: C01285E2 71E080CB 3C00A321 7CDBC61D
[+] Round #29: 819D07F5 C01285E2 71E080CB 3C00A321
[+] Round #28: AC465C76 819D07F5 C01285E2 71E080CB
[+] Round #27: 1CEB2091 AC465C76 819D07F5 C01285E2
[+] Round #26: E33957F1 1CEB2091 AC465C76 819D07F5
[+] Round #25: 89B3A9C1 E33957F1 1CEB2091 AC465C76
[+] Round #24: 34BCCA8B 89B3A9C1 E33957F1 1CEB2091
[+] Round #23: E4CAC03B 34BCCA8B 89B3A9C1 E33957F1
[+] Round #22: 4B9057D9 E4CAC03B 34BCCA8B 89B3A9C1
[+] Round #21: 94FF6DE1 4B9057D9 E4CAC03B 34BCCA8B
[+] Round #20: EA0E7F6D 94FF6DE1 4B9057D9 E4CAC03B
[+] Round #19: 6057E5A3 EA0E7F6D 94FF6DE1 4B9057D9
[+] Round #18: 6A75BA84 6057E5A3 EA0E7F6D 94FF6DE1
[+] Round #17: BA5756CD 6A75BA84 6057E5A3 EA0E7F6D
[+] Round #16: 974E2A27 BA5756CD 6A75BA84 6057E5A3
[+] Round #15: 391BF138 974E2A27 BA5756CD 6A75BA84
[+] Round #14: C803CFEE 391BF138 974E2A27 BA5756CD
[+] Round #13: A5FCAE85 C803CFEE 391BF138 974E2A27
[+] Round #12: 1BD59056 A5FCAE85 C803CFEE 391BF138
[+] Round #11: 0D0F33D3 1BD59056 A5FCAE85 C803CFEE
[+] Round #10: 04CA9339 0D0F33D3 1BD59056 A5FCAE85
[+] Round #9: 483840F9 04CA9339 0D0F33D3 1BD59056
[+] Round #8: 7A258519 483840F9 04CA9339 0D0F33D3
[+] Round #7: E2D8F6B3 7A258519 483840F9 04CA9339
[+] Round #6: F8B35870 E2D8F6B3 7A258519 483840F9
[+] Round #5: 04DD4531 F8B35870 E2D8F6B3 7A258519
[+] Round #4: 47B307E8 04DD4531 F8B35870 E2D8F6B3
[+] Round #3: 0E0E0E0E 47B307E8 04DD4531 F8B35870
[+] Round #2: 0E0E0E0E 0E0E0E0E 47B307E8 04DD4531
[+] Round #1: 0E0E0E0E 0E0E0E0E 0E0E0E0E 47B307E8
[+] Round #0: 7D0A0E0E 0E0E0E0E 0E0E0E0E 0E0E0E0E
[+] Decrypted message: 43 6F 6E 67 72 61 74 75 6C 61 74 69 6F 6E 73 21 20 59 6F 75 20 68 61 76 65 20 64 65 63 72 79 70 74 65 64 20 74 68 65 20 66 6C 61 67 3A 20 53 45 43 43 4F 4E 7B 78 38 36 5F 68 65 32 5F 7A 68 75 61 6E 31 5F 79 6F 75 33 5F 7A 69 34 5F 6A 69 65 32 5F 6D 61 33 5F 64 65 5F 68 75 6E 34 68 65 32 7D 0A 0E 0E 0E 0E 0E 0E 0E 0E 0E 0E 0E 0E 0E 0E
[+] Decrypted message: b'Congratulations! You have decrypted the flag: SECCON{x86_he2_zhuan1_you3_zi4_jie2_ma3_de_hun4he2}\n\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'
[+] Program finished. Bye bye :)

ispo@ispo-glaptop2:~/ctf/seccon_quals_2023/xuyao$ ./xuyao
Message: Congratulations! You have decrypted the flag: SECCON{x86_he2_zhuan1_you3_zi4_jie2_ma3_de_hun4he2}
Correct! I think you got the flag now :)
"""
# ----------------------------------------------------------------------------------------

