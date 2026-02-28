#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Crackmes One CTF 2026 - Matryoshka v2 - (Hard - 912)
#
# This module runs the Feistel network in reverse to recover the license block given the
# target ciphertext found by the symbolic execution.
# ----------------------------------------------------------------------------------------
import struct


sub_444 = lambda a3, a4: a3 ^ (((a4 << 7) & 0xFFFFFFFF) | (a4 >> 25))


# ----------------------------------------------------------------------------------------
def sub_166(a4):
    """Main 32-round Feistel cipher network."""
    v8    = [0] * 36
    v8[0] = 0xEFB1957A
    v8[1] = 0x03BAECF7
    v8[2] = 0x8C982983
    v8[3] = 0x781BCDB6
    
    for i in range(32):  # Key expansion.
        v8[i + 4] = i ^ v8[i % 4]
        
    for j in range(32):  # 32 round Feistel.
        old_high = (a4 >> 32) & 0xFFFFFFFF
        old_low  = a4 & 0xFFFFFFFF
        
        # The F-function: F(old_low) ^ old_high
        f_res   = sub_444(v8[j + 4], old_low)
        new_low = f_res ^ old_high        
        new_high = old_low
        a4 = (new_high << 32) | new_low  # Make 64-bit again
        
    return a4

# ----------------------------------------------------------------------------------------
def encr_lic_blk(lic):
    """Encrypt a license block."""
    assert len(lic) == 32
    blocks = struct.unpack('<4Q', lic)  # Unpack 32 bytes into 4x64-bit integers.
    buf = [sub_166(blocks[j]) for j in range(4)]    
    return buf


# ----------------------------------------------------------------------------------------
def inverse_sub_166(a4, c1=0xEFB1957A, c2=0x03BAECF7, c3=0x8C982983, c4=0x781BCDB6):
    """The inverse function of sub_166."""
    v8 = [c1, c2, c3, c4] + [0]*32

    for i in range(32):  # Key expansion is the same.
        v8[i + 4] = i ^ v8[i % 4]

    for j in reversed(range(32)):  # 32 round Feistel in REVERSE
        new_high = (a4 >> 32) & 0xFFFFFFFF
        new_low  = a4 & 0xFFFFFFFF

        old_low = new_high
        
        # Recalculate the F-function.
        f_res = sub_444(v8[j + 4], old_low)
        old_high = new_low ^ f_res        
        a4 = (old_high << 32) | old_low
    return a4

# ----------------------------------------------------------------------------------------
def feistel_decrypt(trg_cipher, c1=0xEFB1957A, c2=0x03BAECF7, c3=0x8C982983, c4=0x781BCDB6):
    """Decrypts a trg_cipher to the original license block."""
    lic_blk = []
    for block in trg_cipher:
        lic_blk.append(inverse_sub_166(block, c1, c2, c3, c4))

    return struct.pack('<4Q', *lic_blk)


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    dummy_license = b'ISPOLEETMOREYEAHISPOLEETMOREYEAH' 
    result_buf = encr_lic_blk(dummy_license)
    
    print('[+] Encrypted license:')
    for idx, val in enumerate(result_buf):
        print(f'  buf[{idx}] = 0x{val:08X}')

    result_buf  = [0xfabbd91f04381f89, 0xd13f557d1b36e7cc, 0x501aeba922f2c44c, 0x857a1bea6419ce73]

    decr_lic = feistel_decrypt(result_buf)
    print(f'[+] Decrypted license: {decr_lic}')

# ----------------------------------------------------------------------------------------
