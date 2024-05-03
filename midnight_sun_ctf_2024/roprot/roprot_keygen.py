#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Midnight Sun CTF 2024 - roprot (RE 200)
# ----------------------------------------------------------------------------------------
import random
import subprocess


# Copy this from roprot_seed_crack.py output.
valid_seeds = [
    538183840, 1345518218, 2973588323, 2438371556, 562022454, 2984624310, 1125593590, 1395313444,
    3819725501, 2760119933, 1685967536, 1956841705, 2494143538, 899781690, 3877712327, 2008972776,
    933641209, 1475285266, 411045332, 4190440759, 445902986, 2326450373, 2071003707, 2333784035,
    194363547, 1004420728, 1821095982, 3435999293, 1562580955, 1301982477, 1304361379, 3461275642
]

 
# ----------------------------------------------------------------------------------------
# Forward algorithm
# ----------------------------------------------------------------------------------------
def hash_license_key(lic_key):
    """Computes the 16-bit mini hash from license key."""
    chksum = 0

    for k in lic_key:
        if k >= ord('0') and k <= ord('9'):
            c = k - 0x30
        elif k >= ord('A') and k <= ord('Z'):
            c = k - 0x37
        else:
            continue  # Skip '-'
            
        chksum  = 36*chksum + c  # Base 36
        chksum &= 0xFFFFFFFFFFFFFFFF

    seed = (chksum >> 32) ^ (chksum & 0xFFFFFFFF)
    # If mini hash ss 0x2cc2, then license key is correct.
    return compute_minihash(seed)


def compute_minihash(num):
    """Computes the mini hash of a 32-bit number."""
    chksum = 0xFFFF
    for n in num.to_bytes(4, 'little'):
        chksum ^= n << 8
        chksum &= 0xFFFF

        for j in range(8):  # A Galois Field multiplication.
            if (chksum & 0x8000) == 0:
                chksum *= 2
            else:
                chksum = (2 * chksum) ^ 0x1021

        chksum &= 0xFFFF

    return chksum


# ----------------------------------------------------------------------------------------
def license_keygen(correct_seed, debug=True):
    """Generates a valid license key from a "correct" seed."""
    if debug:
        print(f'[+] Generating a valid license key for seed: 0x{correct_seed:08X}')

    rand = random.randint(0, 0x7FFFFFFF)
    xor = correct_seed ^ rand
    chksum = (rand << 32) | xor

    if debug:
        print(f'[+] Choosing a random number: {rand:08X}')
        print(f'[+] Reconstructing 64-bit checksum: 0x{chksum:016X}')

    # Run hash_license_key() in reverse.
    lic_key = ''

    for i in range(19):
        if i > 0 and (i+1) % 5 == 0:
            lic_key = '-' + lic_key
            continue
 
        c = chksum % 36
        chksum //= 36

        if c >= 0 and c <= 9:
            lic_key = chr(0x30 + c) + lic_key
        else:
            lic_key = chr(0x41 + c - 10) + lic_key
        
    if debug:
        print(f'[+] License Key: {lic_key}')

    return lic_key


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] roprot keygen  started.')
    print('[+] Generating valid license keys ...')

    for seed in valid_seeds:
        lic_key = license_keygen(seed, False)
        print(f'[+] Generated license key for seed 0x{seed:08X}: {lic_key}')
        assert(hash_license_key(lic_key.encode('utf-8')) == 0x2cc2)
    
        # Run program and grab the last line (FAIL/PASS).
        proc = subprocess.Popen(['./roprot', f'{lic_key}'], stdout=subprocess.PIPE)
        last_line = proc.stdout.read().splitlines()[-1]
        print(f'[+] Last line: {last_line}')

        if b'FAIL' in last_line:
            print(f'[+] Seed 0x{seed:08X} is incorrect. Moving on ...')
        else:
            print(f'[+] Correct seed FOUND: 0x{seed:08X}')
            print('[+] Generating valid license keys ...')

            for i in range(16):
                lic_key = license_keygen(seed, False)
                assert(hash_license_key(lic_key.encode('utf-8')) == 0x2cc2)
            
                print(f'[+] Valid license key: {lic_key}')

            exit()


    print('[+] Program finished successfully. Bye bye :)')

# ----------------------------------------------------------------------------------------
r"""
┌─[:(]─[15:27:25]─[ispo@ispo-glaptop2]─[~/ctf/midnight_sun_ctf_2024/roprot]
└──> time ./roprot_crack.py 
[+] roprot crack started.
[+] Test: mini hash of b'AAAA-BBBB-CCCC-DDDD' ~> 0xFA44
[+] Generating valid license keys ...
[+] Generated license key for seed 0x201408A0: 0000-GOB6-MA16-FI5U
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0x201408A0 is incorrect. Moving on ...
[+] Generated license key for seed 0x5032FA8A: 0000-VALN-PQ6W-0LK2
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0x5032FA8A is incorrect. Moving on ...
[+] Generated license key for seed 0xB13D5B63: 0000-Q91G-4DD5-45KK
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0xB13D5B63 is incorrect. Moving on ...
[+] Generated license key for seed 0x915698E4: 0001-QX3U-600T-2HWB
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0x915698E4 is incorrect. Moving on ...
[+] Generated license key for seed 0x217FC836: 0000-NI8J-373K-XUZS
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0x217FC836 is incorrect. Moving on ...
[+] Generated license key for seed 0xB1E5C0B6: 0001-QWVP-8HA1-RUTS
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0xB1E5C0B6 is incorrect. Moving on ...
[+] Generated license key for seed 0x431731F6: 0000-H3AE-6JE9-DQMB
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0x431731F6 is incorrect. Moving on ...
[+] Generated license key for seed 0x532ACB24: 0001-TOVP-5YP5-K2BL
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0x532ACB24 is incorrect. Moving on ...
[+] Generated license key for seed 0xE3AC62BD: 0000-AB3D-WLZT-LMEY
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0xE3AC62BD is incorrect. Moving on ...
[+] Generated license key for seed 0xA484167D: 0001-M40Y-L7EN-CG4U
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0xA484167D is incorrect. Moving on ...
[+] Generated license key for seed 0x647DD2B0: 0000-WHIH-SY2N-MLZX
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0x647DD2B0 is incorrect. Moving on ...
[+] Generated license key for seed 0x74A308E9: 0001-VJ2T-TOY7-PAK6
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0x74A308E9 is incorrect. Moving on ...
[+] Generated license key for seed 0x94A99C32: 0000-UTWQ-ENQZ-B0C2
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0x94A99C32 is incorrect. Moving on ...
[+] Generated license key for seed 0x35A1943A: 0001-VNVQ-E4OE-DVNJ
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0x35A1943A is incorrect. Moving on ...
[+] Generated license key for seed 0xE72131C7: 0001-EM5X-1O73-ONTV
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0xE72131C7 is incorrect. Moving on ...
[+] Generated license key for seed 0x77BE7DE8: 0000-3QVO-SZSW-D09Q
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0x77BE7DE8 is incorrect. Moving on ...
[+] Generated license key for seed 0x37A63BF9: 0000-RRPN-XOYC-APY9
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0x37A63BF9 is incorrect. Moving on ...
[+] Generated license key for seed 0x57EF1112: 0000-ASBL-AUZ0-4MKJ
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0x57EF1112 is incorrect. Moving on ...
[+] Generated license key for seed 0x18800DD4: 0001-KC50-Q7BZ-2YDR
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0x18800DD4 is incorrect. Moving on ...
[+] Generated license key for seed 0xF9C50D37: 0001-WQAQ-7FCL-HVZ9
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0xF9C50D37 is incorrect. Moving on ...
[+] Generated license key for seed 0x1A93F08A: 0000-QROZ-T1XL-J3P7
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0x1A93F08A is incorrect. Moving on ...
[+] Generated license key for seed 0x8AAAD0C5: 0000-JGER-HBS6-SLUT
[+] Last line: b'\x1b[?25h\x1b[1;31mFAIL:\x1b[0m Invalid license key.'
[+] Seed 0x8AAAD0C5 is incorrect. Moving on ...
[+] Generated license key for seed 0x7B71023B: 0000-KWKY-3XKQ-24LM
[+] Last line: b'\x1b[1;32mPASS:\x1b[0m Valid license key. midnight{r0pP1nG_7hr0uGh_rand()}'
[+] Correct seed FOUND: 0x7B71023B
[+] Generating valid license keys ...
[+] Valid license key: 0000-2K7I-01WO-S6ZD
[+] Valid license key: 0000-KV3T-E7KC-FIB3
[+] Valid license key: 0001-30SL-QD6C-X3NI
[+] Valid license key: 0001-HIMB-TUJX-SLHT
[+] Valid license key: 0000-H60O-TCI4-EVE7
[+] Valid license key: 0001-027O-WHPJ-3ZWU
[+] Valid license key: 0001-U5ED-RSI3-JC3J
[+] Valid license key: 0001-G8LO-C0KK-K2QX
[+] Valid license key: 0000-3HR7-30F0-4DU6
[+] Valid license key: 0000-GNNU-FM7L-HD2L
[+] Valid license key: 0000-VUP4-1GO9-3HTE
[+] Valid license key: 0001-53U0-PX3P-WBZ6
[+] Valid license key: 0000-36UF-ALJ6-I9PX
[+] Valid license key: 0001-P6CJ-LBLP-GL6H
[+] Valid license key: 0000-JYQE-ITTL-HWCW
[+] Valid license key: 0000-HXHR-GVAU-MV73

real	3m7.520s
user	0m37.432s
sys	0m1.632s

┌─[15:30:36]─[ispo@ispo-glaptop2]─[~/ctf/midnight_sun_ctf_2024/roprot]
└──> ./roprot 0001-HIMB-TUJX-SLHT
Verifying license key...

PASS: Valid license key. midnight{r0pP1nG_7hr0uGh_rand()}

┌─[15:30:55]─[ispo@ispo-glaptop2]─[~/ctf/midnight_sun_ctf_2024/roprot]
└──> ./roprot 0001-U5ED-RSI3-JC3J
Verifying license key...

PASS: Valid license key. midnight{r0pP1nG_7hr0uGh_rand()}
"""
# ----------------------------------------------------------------------------------------

