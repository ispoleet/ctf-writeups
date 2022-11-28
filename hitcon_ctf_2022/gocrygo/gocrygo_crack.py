#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# HITCON Quals CTF 2022 - gocryco (RE 274)
# ----------------------------------------------------------------------------------------
import struct
import os
import base64
from Crypto.Cipher import DES3
from Crypto.Util import Counter


# Encoded strings from main (it's not just base64). 
enc_strs = [
    'Q2hbZDBHUQ==',
    
    'QjVfOiNIIlYmJkcla0guQmwuM2ZCbFtjcEZEbDJG',
    
    'OmknXU9GKEhKN0ZgJj1EQlBETjFAVkteZ0VkOGRHREJNVmVES1Ux',

    'ODdkJmkrQSFcZERmLXFFK0VxNzNGPEdbRCtDXUEmQDtAITJEZnAoQ0FuYydtK0VN'
    'Z0xGQ2Y7QStBY2xjQDw2ISZAcmMtaEZDY1MnK0NvMixBUmZoI0VkOGNUL2healVA'
    'cmNqLURkUlslQHJ1RiU/WSFra0FSZmgjRWQ5I1RAO11UdUUsOHJtQUtZRHRDYG1o'
    'NUFLWVQhQ2g3WjFII0lnSkdAPkIyK0VWTkVBU3UhdUgjUmpKQmw1Ji1GPW0=',
    
    'Nlhha01EZmQrMUBxMChrRiEsIi1FYi9hJkRmVStHLVlJQC1FZDs7OT9acC1uRkQ1V'
    'CFBOC0ncUBydVgwR3BiV3FFK08nLEJsZT8wRGYtXC5BU3UzbkEs',

    'N1VeIklBUmxwKkRdaVYvQHJjajZGPERsUTNacjZdQHIkPzRII0loU0lL',
    
    'Ok4oMm4vMEs0VkZgSlU6QmwlPydGKlZoS0FTaVEnQDwzUSNBUyNhJUFTdSF1SCNSazpBMWQ=',
    
    'O2RqM1FHcTonY0I1XzojSCJWJUMrQ2ZQN0ViMC0xQ2pALjZEZTN1NERKc1Y+RSxvb'
    'D9CazFjdEA7Xj81QTddN2tII1JrPkRmLVw9QVREcy5AcUJeNg==',

    'PWA4RjFFYi1BKERmOUsoQTFldXBEZjkvL0NpczYnK0ZY',
    
    'L25dKjRFZDs7OQ==', # .gocrygo
    
    'L29iaw=='          # .qq
]


# ----------------------------------------------------------------------------------------
# DES implementation to verify encryption algorithm.
#
# Code Taken From: https://www.geeksforgeeks.org/data-encryption-standard-des-set-1/
# Table of Position of 64 bits at initial level: Initial Permutation Table
initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7]
 
# Expansion D-box Table
exp_d = [32, 1, 2, 3, 4, 5, 4, 5,
         6, 7, 8, 9, 8, 9, 10, 11,
         12, 13, 12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21, 20, 21,
         22, 23, 24, 25, 24, 25, 26, 27,
         28, 29, 28, 29, 30, 31, 32, 1]
 
# Straight Permutation Table
per = [16,  7, 20, 21,
       29, 12, 28, 17,
       1, 15, 23, 26,
       5, 18, 31, 10,
       2,  8, 24, 14,
       32, 27,  3,  9,
       19, 13, 30,  6,
       22, 11,  4, 25]
 
# S-box Table
sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
 
        [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
         [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
         [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
         [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
 
        [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
         [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
         [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
         [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
 
        [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
         [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
         [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
         [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
 
        [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
         [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
         [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
         [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
 
        [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
         [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
         [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
         [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
 
        [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
         [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
         [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
         [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
 
        [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
         [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
         [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
         [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]
 
# Final Permutation Table
final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25]


def hex2bin(s):
    mp = {'0': "0000",
          '1': "0001",
          '2': "0010",
          '3': "0011",
          '4': "0100",
          '5': "0101",
          '6': "0110",
          '7': "0111",
          '8': "1000",
          '9': "1001",
          'A': "1010",
          'B': "1011",
          'C': "1100",
          'D': "1101",
          'E': "1110",
          'F': "1111"}
    bin = ""
    for i in range(len(s)):
        bin = bin + mp[s[i]]
    return bin
 
def bin2hex(s):
    mp = {"0000": '0',
          "0001": '1',
          "0010": '2',
          "0011": '3',
          "0100": '4',
          "0101": '5',
          "0110": '6',
          "0111": '7',
          "1000": '8',
          "1001": '9',
          "1010": 'A',
          "1011": 'B',
          "1100": 'C',
          "1101": 'D',
          "1110": 'E',
          "1111": 'F'}
    hex = ""
    for i in range(0, len(s), 4):
        ch = ""
        ch = ch + s[i]
        ch = ch + s[i + 1]
        ch = ch + s[i + 2]
        ch = ch + s[i + 3]
        hex = hex + mp[ch]
 
    return hex
 
def bin2dec(binary):
    binary1 = binary
    decimal, i, n = 0, 0, 0
    while(binary != 0):
        dec = binary % 10
        decimal = decimal + dec * pow(2, i)
        binary = binary//10
        i += 1
    return decimal
 
def dec2bin(num):
    res = bin(num).replace("0b", "")
    if(len(res) % 4 != 0):
        div = len(res) / 4
        div = int(div)
        counter = (4 * (div + 1)) - len(res)
        for i in range(0, counter):
            res = '0' + res
    return res
 
def permute(k, arr, n):
    permutation = ""
    for i in range(0, n):
        permutation = permutation + k[arr[i] - 1]
    return permutation
 
def shift_left(k, nth_shifts):
    s = ""
    for i in range(nth_shifts):
        for j in range(1, len(k)):
            s = s + k[j]
        s = s + k[0]
        k = s
        s = ""
    return k
 
def xor(a, b):
    ans = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            ans = ans + "0"
        else:
            ans = ans + "1"
    return ans
 
def encrypt(pt, rkb, rk):
    pt = hex2bin(pt)
 
    # Initial Permutation
    pt = permute(pt, initial_perm, 64)
    print("After initial permutation", bin2hex(pt))
 
    # Splitting
    left = pt[0:32]
    right = pt[32:64]
    for i in range(0, 16):
        #  Expansion D-box: Expanding the 32 bits data into 48 bits
        right_expanded = permute(right, exp_d, 48)
 
        # XOR RoundKey[i] and right_expanded
        xor_x = xor(right_expanded, rkb[i])
 
        # S-boxex: substituting the value from s-box table by calculating row and column
        sbox_str = ""
        for j in range(0, 8):
            row = bin2dec(int(xor_x[j * 6] + xor_x[j * 6 + 5]))
            col = bin2dec(
                int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
            val = sbox[j][row][col]
            sbox_str = sbox_str + dec2bin(val)
 
        # Straight D-box: After substituting rearranging the bits
        sbox_str = permute(sbox_str, per, 32)
 
        # XOR left and sbox_str
        result = xor(left, sbox_str)
        left = result
 
        # Swapper
        if(i != 15):
            left, right = right, left
        print("Round ", i + 1, " ", bin2hex(left), " ", bin2hex(right), " ", rk[i])
 
    # Combination
    combine = left + right
 
    # Final permutation: final rearranging of bits to get cipher text
    cipher_text = permute(combine, final_perm, 64)
    return cipher_text

def des_encrypt_blk(pt, key):
    """End to end DES encryption."""
    # Key generation
    # --hex to binary
    key = hex2bin(key)
     
    # --parity bit drop table
    keyp = [57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4]
     
    # getting 56 bit key from 64 bit using the parity bits
    key = permute(key, keyp, 56)
     
    # Number of bit shifts
    shift_table = [1, 1, 2, 2,
                   2, 2, 2, 2,
                   1, 2, 2, 2,
                   2, 2, 2, 1]
     
    # Key- Compression Table : Compression of key from 56 bits to 48 bits
    key_comp = [14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32]
     
    # Splitting
    left = key[0:28]    # rkb for RoundKeys in binary
    right = key[28:56]  # rk for RoundKeys in hexadecimal
     
    rkb = []
    rk = []
    for i in range(0, 16):
        # Shifting the bits by nth shifts by checking from shift table
        left = shift_left(left, shift_table[i])
        right = shift_left(right, shift_table[i])
     
        print('LEFT :', left, bin2hex(left))
        print('RIGHT:', right, bin2hex(right))
        # Combination of left and right string
        combine_str = left + right
     
        print('Combine:', combine_str)
        # Compression of key from 56 to 48 bits
        round_key = permute(combine_str, key_comp, 48)
     
        print('ROUND KEY:', bin2hex(round_key))
        rkb.append(round_key)
        rk.append(bin2hex(round_key))
     
    print('Round Keys:', rk)
    cipher_text = bin2hex(encrypt(pt, rkb, rk))
    print("Cipher Text : ", cipher_text)


# ----------------------------------------------------------------------------------------
def enchanced_base64_decode(enc_str):
    """Base64 decodes and custom decodes an encoded string `enc_str."""
    b64dec = base64.b64decode(enc_str)

    plain = []
    leftover = 0

    # Decode in groups of 5.
    for i in range(0, len(b64dec), 5):
        decr = 0

        for k in range(5):
            if i + k >= len(b64dec):
                leftover = 1
                break
            decr = decr*85 + ((b64dec[i + k] - 0x21) & 0xFF)
    
        if leftover:
            # We have leftovers. Decode them too.
            for j in range(k, 5):
                decr = decr*85 + 84

            for j in range(0, k-1):
                plain.append((decr >> 24) & 0xFF)
                decr <<= 8
        else:
            plain += list(struct.pack('>L', decr))

    return plain


# ----------------------------------------------------------------------------------------
def triple_des_decrypt(ciphertext, key, iv):
    """Decrypts a ciphertext using 3DES in CTR mode."""
    print('[+] Decrypting Ciphertext:',
          '-'.join('%02X' % c for c in ciphertext[:32]),
          'using IV:',
          '-'.join('%02X' % c for c in iv))

    ctr = Counter.new(64, prefix=iv)

    plaintext = b''
    for i in range(9000000):
        # Counter Mode (CTR) doesn't work for some reason. I don't know why.
        # I give up.
        # I'll just implement CTR on my own.
        # I use OFB to decrypt 1 block then increment the counter (IV) and repeat.
#        cipher_decrypt = DES3.new(key, DES3.MODE_CTR, counter=ctr) 
        cipher_decrypt = DES3.new(key, DES3.MODE_OFB, iv)

        # Decrypt a single block 
        plaintext += cipher_decrypt.decrypt(ciphertext[8*i:8*i + 8])

        # Increment IV the stupid way :$
        ivl = list(iv)

        for j in range(7, -1, -1):
            # If last byte in counter becomes 255, reset and increment
            # previous byte. If not. increment and break
            if ivl[j] == 0xFF:
                ivl[j] = 0
            else:
                ivl[j] += 1
                break

        iv = bytes(ivl)

        if len(ciphertext[8*i:]) < 1:
            break

    return plaintext


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Checker Crack Started.')

    # Decode encoded strings (not related to get the flag).
    for enc in enc_strs:
        dec = enchanced_base64_decode(enc)            
        print(f'[+] Decoding: {enc[:20]}...{enc[-20:]} ~>',
               ''.join('%c' % d for d in dec))

    # Test encryption to verify that the intermediate steps work as expecting.
    # pt = "123456ABCD132536"
    # key = "4142434445464748"
    # des_encrypt_blk(pt, key)
    # exit()


    print('[+] Starting file decryption ...')

    # To find the key in core dump: 
    # Search for /dev/urandom string in stack. Key is 0x20 bytes before that.
    # (gdb) find $rsp, $rsp+0x10000, "/dev/urandom"
    # 0x7fecc3580060
    # 1 pattern found.
    # (gdb) x/8xg 0x7fecc3580060-0x20
    # 0x7fecc3580040:	0xbd349a8f52ae89b3	0x1b8566979b593598
    # 0x7fecc3580050:	0x18a320b78025b482	0x00706f746b736544
    # 0x7fecc3580060:	0x6172752f7665642f	0x000000006d6f646e
    # 0x7fecc3580070:	0x0000000000000000	0x0000000000000000
    # (gdb) x/24xb 0x7fecc3580040
    # 0x7fecc3580040:	0xb3	0x89	0xae	0x52	0x8f	0x9a	0x34	0xbd
    # 0x7fecc3580048:	0x98	0x35	0x59	0x9b	0x97	0x66	0x85	0x1b
    # 0x7fecc3580050:	0x82	0xb4	0x25	0x80	0xb7	0x20	0xa3	0x18
    key = [
        0xb3,0x89,0xae,0x52,0x8f,0x9a,0x34,0xbd,
        0x98,0x35,0x59,0x9b,0x97,0x66,0x85,0x1b,
        0x82,0xb4,0x25,0x80,0xb7,0x20,0xa3,0x18
    ]
    key = bytes(key)

    print('[+] 3DES Key:', '-'.join('%02X' % k for k in key))

    print('[+] Decrypting all files .....')

    # Save decrypted files.
    if not os.path.exists('decrypted_files'):
        os.mkdir('decrypted_files')

    currdir = os.getcwd()
    print(f'[+] Current directory: {currdir}')


    # Test key.
    #key = 'ABCDEFGH12345678ISPOLEET'   
    
    # Test decryption
    # contents = open(os.path.join(currdir, 'ispo2.txt.qq'), 'rb').read()
    # plain = triple_des_decrypt(contents[8:], key, contents[:8])
    # print('PLAIN:', plain.decode('utf-8'))
    # exit()

    for root, _, files in os.walk('gocrygo_victim_directory'):
        for file in files:
            if not file.endswith('.qq'):
                print(f"[+] Skipping file '{file}'")
                continue

            filename = os.path.join(root, file)
            print(f"[+] Decrypting '{file}' ...")

            contents = open(filename, 'rb').read()
            print(f'[+] {len(contents)} bytes read.')
            
            # First 8 bytes are the IV. The rest is the ciphertext.
            decrypted = triple_des_decrypt(contents[8:], key, contents[:8])

            if file == 'flаg.txt.qq':
                print('[+] Decrypted flag:\n', decrypted.decode('utf-8'))

            newfilename = os.path.join(currdir, 'decrypted_files', file[:-3])
            print(f"[+] Writing decrypted contents to '{newfilename}' ...")
            open(newfilename, 'wb').write(decrypted)
    
    print('[+] Program finished! Bye bye :)')


# ----------------------------------------------------------------------------------------
"""
ispo@ispo-glaptop2:~/ctf/hitcon_quals_2022/gocrygo$ time ./gocrygo_crack.py
[+] Checker Crack Started.
[+] Decoding: Q2hbZDBHUQ==...Q2hbZDBHUQ== ~> linux
[+] Decoding: QjVfOiNIIlYmJkcla0gu...QmwuM2ZCbFtjcEZEbDJG ~> gocrygo_victim_directory
[+] Decoding: OmknXU9GKEhKN0ZgJj1E...Z0VkOGRHREJNVmVES1Ux ~> Please run this binary on Linux
[+] Decoding: ODdkJmkrQSFcZERmLXFF...dUgjUmpKQmw1Ji1GPW0= ~> Hey! I don't want to break your file system. Please create a directory './gocrygo_victim_directory' and place all the files you want to encrypt in it.
[+] Decoding: Nlhha01EZmQrMUBxMChr...ZT8wRGYtXC5BU3UzbkEs ~> Cannot access directory 'gocrygo_victim_directory': permission denied
[+] Decoding: N1VeIklBUmxwKkRdaVYv...cjZdQHIkPzRII0loU0lL ~> Failed to encrypt %v: lucky you~~
[+] Decoding: Ok4oMm4vMEs0VkZgSlU6...JUFTdSF1SCNSazpBMWQ= ~> Oops, your file system has been encrypted.
[+] Decoding: O2RqM1FHcTonY0I1Xzoj...LVw9QVREcy5AcUJeNg== ~> Sadly, 'gocrygo' currently does not provide any decryption services.
[+] Decoding: PWA4RjFFYi1BKERmOUso...dXBEZjkvL0NpczYnK0ZY ~> You're doomed. Good luck ~
[+] Decoding: L25dKjRFZDs7OQ==...L25dKjRFZDs7OQ== ~> .gocrygo
[+] Decoding: L29iaw==...L29iaw== ~> .qq
[+] Starting file decryption ...
[+] 3DES Key: B3-89-AE-52-8F-9A-34-BD-98-35-59-9B-97-66-85-1B-82-B4-25-80-B7-20-A3-18
[+] Decrypting all files .....
[+] Current directory: /home/ispo/ctf/hitcon_quals_2022/gocrygo
[+] Skipping file '.gocrygo'
[+] Decrypting 'xor.patch.qq' ...
[+] 603 bytes read.
[+] Decrypting Ciphertext: FB-F7-34-A7-A2-BB-93-1C-20-D4-5C-8E-B7-2F-71-61-CF-01-34-F8-3C-E9-58-2C-7D-41-6E-03-A1-A6-AA-00 using IV: 86-E1-7F-0D-A2-9D-D0-2B
[+] Writing decrypted contents to '/home/ispo/ctf/hitcon_quals_2022/gocrygo/decrypted_files/xor.patch' ...
[+] Decrypting 'gocrygo.go.qq' ...
[+] 6326 bytes read.
[+] Decrypting Ciphertext: 97-C8-03-5E-25-05-07-4E-67-3D-0D-2A-14-9B-F4-34-28-8B-F3-00-B1-B3-D1-A6-CA-FD-56-B6-58-2C-F6-D2 using IV: 10-C5-FC-F4-2E-C8-9B-EB
[+] Writing decrypted contents to '/home/ispo/ctf/hitcon_quals_2022/gocrygo/decrypted_files/gocrygo.go' ...
[+] Decrypting 'README.md.qq' ...
[+] 327 bytes read.
[+] Decrypting Ciphertext: 68-46-75-3B-D1-B4-2C-63-4D-9F-FC-F4-63-EA-F2-D9-1F-8F-04-C5-AE-27-98-51-DA-D2-2E-5C-CC-9E-CE-CE using IV: 47-DE-4C-21-5B-BD-B1-E8
[+] Writing decrypted contents to '/home/ispo/ctf/hitcon_quals_2022/gocrygo/decrypted_files/README.md' ...
[+] Decrypting 'cute_kitten.mkv.qq' ...
[+] 1592273 bytes read.
[+] Decrypting Ciphertext: BF-76-C4-3A-3C-65-A0-5A-05-0A-FA-B0-CA-09-4E-CF-5E-66-C8-04-5A-8F-F2-5E-43-FD-48-DB-B5-B5-D4-A6 using IV: 30-58-CC-05-D3-FB-B8-47
[+] Writing decrypted contents to '/home/ispo/ctf/hitcon_quals_2022/gocrygo/decrypted_files/cute_kitten.mkv' ...
[+] Decrypting 'Wallpaper.jpg.qq' ...
[+] 84775 bytes read.
[+] Decrypting Ciphertext: D0-EE-CA-84-BE-4E-3A-58-C8-B1-F3-55-8E-FC-EB-A4-94-B7-64-50-6A-F6-81-36-F0-B6-54-00-F8-57-B1-DA using IV: 41-BB-29-4F-F5-0B-EB-F8
[+] Writing decrypted contents to '/home/ispo/ctf/hitcon_quals_2022/gocrygo/decrypted_files/Wallpaper.jpg' ...
[+] Decrypting 'rickroll.jpg.qq' ...
[+] 73957 bytes read.
[+] Decrypting Ciphertext: BA-AB-98-01-0A-4D-10-88-AA-6B-04-C6-93-D7-A5-A3-80-F9-1A-C8-90-7C-78-A8-9B-FF-6D-0F-E0-1D-3B-EF using IV: BD-4E-15-73-52-35-4C-6C
[+] Writing decrypted contents to '/home/ispo/ctf/hitcon_quals_2022/gocrygo/decrypted_files/rickroll.jpg' ...
[+] Decrypting 'flаg.txt.qq' ...
[+] 474 bytes read.
[+] Decrypting Ciphertext: AE-94-AE-6F-AD-2C-FD-95-C6-D5-DC-26-2A-F1-B0-F4-3B-18-01-1C-73-3B-0C-9E-76-A6-8B-B6-5F-37-95-C2 using IV: 58-7E-75-76-AA-07-F4-01
[+] Decrypted flag:
 Cyrillic letters are fun right?
First part: `HITCON{always_gonna_make_you_`
Hint: The second part is at `Pictures/rickroll.jpg`
 _    _.--.____.--._
( )=.-":;:;:;;':;:;:;"-._
 \\\:;:;:;:;:;;:;::;:;:;:\
  \\\:;:;:;:;:;;:;:;:;:;:;\
   \\\:;::;:;:;:;:;::;:;:;:\
    \\\:;:;:;:;:;;:;::;:;:;:\
     \\\:;::;:;:;:;:;::;:;:;:\
      \\\;;:;:_:--:_:_:--:_;:;\
       \\\_.-"             "-._\
        \\
         \\
          \\
           \\
            \\
             \\

[+] Writing decrypted contents to '/home/ispo/ctf/hitcon_quals_2022/gocrygo/decrypted_files/flаg.txt' ...
[+] Program finished! Bye bye :)

real	0m23.195s
user	0m21.743s
sys	0m1.454s
"""
# ----------------------------------------------------------------------------------------

