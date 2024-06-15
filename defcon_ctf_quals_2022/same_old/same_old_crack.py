#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# DEFCON CTF 2022 - Same old (MISC)
# ----------------------------------------------------------------------------------------
import random
import string
import zlib 


# Lookup table for CRC32.
_CRC32_TBL = [
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
	0xe963a535, 0x9e6495a3,	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
	0xf3b97148, 0x84be41de,	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,	0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5,	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,	0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940,	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
	0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,	0x76dc4190, 0x01db7106,
	0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
	0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
	0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
	0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
	0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
	0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
	0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
	0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
	0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
	0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
	0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
	0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
]


# ---------------------------------------------------------------------------------------
def crack_single_crc32(curr_crc32, trg_crc32):    
    """Cracks a single CRC32.

    We do the old-school approach (no Z3 solver).
    This function is based on:
        https://stackoverflow.com/questions/9285898/reversing-crc32/13394385#13394385

    Want to append bytes: X  Y  Z  W 
    Take for register: a3 a2 a1 a0  (a is the 'already calculated' crc for string)
    Note that a3 is the most significant byte and a0 the least.
     f is the wanted new CRC byte string, and xyzw is the modification pad
    I'll show it a little different way:
    a0 + X                  =(1)  points to  b3 b2 b1 b0  in table
    a1 + b0 + Y             =(2)  points to  c3 c2 c1 c0  in table
    a2 + b1 + c0 + Z        =(3)  points to  d3 d2 d1 d0  in table
    a3 + b2 + c1 + d0 + W   =(4)  points to  e4 e3 e2 e1  in table
         b3 + c2 + d1 + e0  =f0
              c3 + d2 + e1  =f1
                   d3 + e2  =f2
                        e3  =f3
        (1)  (2)  (3)  (4)
    (figure 4)
    This is reversed in the same way as the 16bit version.
    I shall give an example with real values.
    For the table values use the CRC-32 table in the appendix.
    
    Take for CRC register before, a3 a2 a1 a0 -> AB CD EF 66
    Take for CRC register after,  f3 f2 f1 f0 -> 56 33 14 78 (wanted value)
    Here we go:
    First byte of entries            entry   value
    e3=f3                     =56 -> 35h=(4) 56B3C423 for e3 e2 e1 e0
    d3=f2+e2      =33+B3      =E6 -> 4Fh=(3) E6635C01 for d3 d2 d1 d0
    c3=f1+e1+d2   =14+C4+63   =B3 -> F8h=(2) B3667A2E for c3 c2 c1 c0
    b3=f0+e0+d1+c2=78+23+5C+66=61 -> DEh=(1) 616BFFD3 for b3 b2 b1 b0
    Now we have all needed values, then
    X=(1)+         a0=         DE+66=B8
    Y=(2)+      b0+a1=      F8+D3+EF=C4
    Z=(3)+   c0+b1+a2=   4F+2E+FF+CD=53
    W=(4)+d0+c1+b2+a3=35+01+7A+6B+AB=8E
    (final computation)
    """
    get_bytes = lambda n : ((n & 0xFF000000) >> 24, (n & 0x00FF0000) >> 16,
                           (n & 0x0000FF00) >> 8,   (n & 0x000000FF))

    curr_crc32 = ~curr_crc32
    trg_crc32 = ~trg_crc32

    a3, a2, a1, a0 = get_bytes(curr_crc32)
    f3, f2, f1, f0 = get_bytes(trg_crc32)

    st = 0x0
    end = 0xff

    # Capture e3/e2/e1/e0/ (4) values.
    for i in range(st,end):
        if ((_CRC32_TBL[i] & 0xFF000000) == (trg_crc32 & 0xFF000000)):
            e3, e2, e1, e0 = get_bytes(_CRC32_TBL[i])
            four = i 
            break
            
    # d3=f2+e2      =33+B3      =E6 -> 4Fh=(3) E6635C01 for d3 d2 d1 d0
    d3 = f2^e2  # Lookup d3 and assign the values for d2/d1/d0/(3)
    for i in range(st, end):#($i = 0; $i < 256; $i++)
        if ((_CRC32_TBL[i] & 0xFF000000) == (d3 << 24)):
            _, d2, d1, d0 = get_bytes(_CRC32_TBL[i])
            three = i
            break
    
    # c3=f1+e1+d2   =14+C4+63   =B3 -> F8h=(2) B3667A2E for c3 c2 c1 c0
    c3 = f1^e1^d2;

    for i in range(st, end):#($i = 0; $i < 256; $i++)
        if ((_CRC32_TBL[i] & 0xFF000000) == (c3 << 24)):
            _, c2, c1, c0 = get_bytes(_CRC32_TBL[i])
            two = i
            break
    
    # b3=f0+e0+d1+c2=78+23+5C+66=61 -> DEh=(1) 616BFFD3 for b3 b2 b1 b0
    b3 = f0^e0^d1^c2;
    for i in range(st, end):
        if ((_CRC32_TBL[i] & 0xFF000000) == (b3 << 24)):
            _, b2, b1, b0 = get_bytes(_CRC32_TBL[i])
            one = i
            break
    '''
    Now we have all needed values, then
        X=(1)+         a0=         DE+66=B8
        Y=(2)+      b0+a1=      F8+D3+EF=C4
        Z=(3)+   c0+b1+a2=   4F+2E+FF+CD=53
        W=(4)+d0+c1+b2+a3=35+01+7A+6B+AB=8E
        (final computation)
    '''
    X = one ^ a0
    Y = two ^ b0 ^ a1
    Z = three ^ c0 ^ b1 ^ a2
    W = four ^ d0 ^ c1 ^ b2 ^ a3

    return [X, Y, Z, W]


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Same old crack started.')

    charset = string.ascii_uppercase + string.ascii_lowercase + string.digits
    trg_crc = zlib.crc32(b'the')

    print(f'[+] Target CRC32 is: {trg_crc:08X}')

    for i in range(1048576):
        rnd = ''.join(random.choices(charset, k=4))
        base = b'tasteless' + rnd.encode('utf-8')
        curr_crc = zlib.crc32(base)

        print(f'[+] Generating random string: tasteless{rnd}, with CRC32: {curr_crc:08X}')

        crack = crack_single_crc32(curr_crc, trg_crc)
        print('[+] CRC32 successfully cracked:', '-'.join('%02X' % c for c in crack))

        # Build target input.        
        trg_inp = '%s%c%c%c%c' % (rnd, crack[0], crack[1], crack[2], crack[3])

        # If the `crack` is not printable ASCII, try again with another `rnd`.
        # All must be printable so we don't have unicode issues ;)
        if len([x for x in crack if chr(x) in charset]) == 4:
            new_crc = zlib.crc32(bytes(trg_inp, 'utf-8'))

            print(f'[+] COLLISION FOUND: {trg_inp}')
            print(f'[+] Verifying CRC32: {new_crc:08X}')

            final_ans = 'tasteless' + trg_inp
            final_crc = zlib.crc32(final_ans.encode('utf-8'))

            print(f'[+] Final answer: {final_ans}')
            print(f'[+] Final CRC: {final_crc:08X} == {trg_crc:08X}')

            assert(final_crc == trg_crc)
            break

    
# ----------------------------------------------------------------------------------------
"""
ispo@ispo-glaptop:~/ctf/defcon_quals_2022/same_old$ ./same_old_crack.py 
[+] Same old crack started.
[+] Target CRC32 is: 3C456DE6
[+] Generating random string: tastelessARZA, with CRC32: 28499794
[+] CRC32 successfully cracked: B2-93-4B-42
[+] Generating random string: tastelessD1tP, with CRC32: 34B13B01
[+] CRC32 successfully cracked: 27-3F-B3-5E
[+] Generating random string: tasteless2Kmo, with CRC32: 0EE5ADE2
[+] CRC32 successfully cracked: C4-A9-E7-64
[+] Generating random string: tastelessT2t6, with CRC32: C23F16AA
[+] CRC32 successfully cracked: 8C-12-3D-A8
....
[+] Generating random string: tasteless93rM, with CRC32: 9B3C5C71
[+] CRC32 successfully cracked: 57-58-3E-F1
[+] Generating random string: tastelesssh17, with CRC32: 64F8A19D
[+] CRC32 successfully cracked: BB-A5-FA-0E
[+] Generating random string: tastelessDTrY, with CRC32: 552B2DE8
[+] CRC32 successfully cracked: CE-29-29-3F
[+] Generating random string: tastelessaX60, with CRC32: 6BA6D87D
[+] CRC32 successfully cracked: 5B-DC-A4-01
[+] Generating random string: tastelessTfBI, with CRC32: E02C6D1E
[+] CRC32 successfully cracked: 38-69-2E-8A
[+] Generating random string: tastelessEChD, with CRC32: 27D5697A
[+] CRC32 successfully cracked: 5C-6D-D7-4D
[+] Generating random string: tastelessjsy6, with CRC32: 163D0082
[+] CRC32 successfully cracked: A4-04-3F-7C
[+] Generating random string: tastelesseoc2, with CRC32: EC227402
[+] CRC32 successfully cracked: 24-70-20-86
[+] Generating random string: tastelessAlSj, with CRC32: 7BC21D07
[+] CRC32 successfully cracked: 21-19-C0-11
[+] Generating random string: tasteless1wVA, with CRC32: D145FC0F
[+] CRC32 successfully cracked: 29-F8-47-BB
[+] Generating random string: tastelessSdFd, with CRC32: 5FCC18B8
[+] CRC32 successfully cracked: 9E-1C-CE-35
[+] Generating random string: tasteless4lao, with CRC32: BA39ED57
[+] CRC32 successfully cracked: 71-E9-3B-D0
[+] Generating random string: tastelessEUIN, with CRC32: 53344A45
[+] CRC32 successfully cracked: 63-4E-36-39
[+] COLLISION FOUND: EUINcN69
[+] Verifying CRC32: 3FA88926
[+] Final answer: tastelessEUINcN69
[+] Final CRC: 3C456DE6 == 3C456DE6


Flag accepted with string: "tastelessR8wqvOTC"
"""
# ----------------------------------------------------------------------------------------

