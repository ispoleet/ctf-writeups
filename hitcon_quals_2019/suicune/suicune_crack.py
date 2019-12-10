#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# HITCON CTF quals 2019 - suicune (RE 305)
# --------------------------------------------------------------------------------------------------
import os
import sys
import struct


# --------------------------------------------------------------------------------------------------
ror64 = lambda N, shift: (N >> shift) | ((N << (64 - shift)) % (1 << 64))
ror32 = lambda N, shift: (N >> shift) | ((N << (32 - shift)) % (1 << 32))


# --------------------------------------------------------------------------------------------------
def factorial(num):
    fact = 1
    for i in range(1, num+1):
        fact = fact * i

    return fact


# --------------------------------------------------------------------------------------------------
# Find the permutation order of an arbitrary array (start from 1)
def get_perm_order(array):
    perm = 1

    for i in xrange(len(array)):
        ctr_ord = len(filter(lambda x: x < array[i], array[i+1:]))

        perm = perm + ctr_ord*factorial(len(array)-1 - i)

    return perm


# --------------------------------------------------------------------------------------------------
# Find the k-th permutation of an array (start from 1)
def find_kth_permutation(N, k):
    array = [i for i in range(1, N+1)]
    perm  = [0]*N

    # if k is too large, give the sorted-in-reverse-order permutation
    k = min(k, factorial(N)) - 1

    for i in xrange(len(array)):
        fact = factorial(N-1-i)

        # find d, r such that: k = d*(n-1)! + r, subject to: d >= 0 and 0 < r <= n!
        d, r = k // fact, k % fact
        k = r

        perm[i] = array[d]
        array = array[:d] + array[d+1:]

    return perm

# --------------------------------------------------------------------------------------------------
# The simplified version of encryption algorithm.
def encrypt_simple(plaintext, seed):
    ciphertext = plaintext
    key = ((seed + 1) * 0x5851F42D4C957F2D + 1) % 2**64

    for i in xrange(16):
        sbox = [i for i in xrange(0x100)]

        for j in xrange(256, 0, -1):
            a = ror32(((key ^ (key >> 18)) >> 27) % (1 << 32), key >> 59)

            # swap element at [j - 1] with element [a % j]
            sbox[a % j], sbox[j - 1] = sbox[j - 1], sbox[a % j]

            # update key (except the last time)
            if j != 1:
                key = (key * 0x5851F42D4C957F2D + 1) % 2**64

        # find permutation order of the sbox
        curr_ord = get_perm_order(sbox[0:len(ciphertext)])

        sbox_ord = ror32(((key ^ (key >> 18)) >> 27) % (1 << 32), key >> 59)

        key = (key * 0x5851F42D4C957F2D + 1) % 2**64
        a = ror32(((key ^ (key >> 18)) >> 27) % (1 << 32), key >> 59)
        
        sbox_ord += (a << 32)
        sbox_ord += curr_ord
    
        key = (key * 0x5851F42D4C957F2D + 1) % 2**64

        stream = sorted(sbox[0:len(ciphertext)]) #, reverse=True)        

        # find the Kth permutation of the S-box
        perm = find_kth_permutation(len(stream), sbox_ord)
        S = [stream[p-1] for p in perm]

        ciphertext = [a[0] ^ a[1] for a in zip(ciphertext, S)]
        ciphertext.reverse()     

    return ''.join('%02x' % c for c in ciphertext)


# --------------------------------------------------------------------------------------------------
# Decryption and encryption are the same (stream cipher)
def decrypt_simple(ciphertext, seed):
    return encrypt_simple(ciphertext, seed)


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    print '[+] Suicune Crack started.'

    cipher = [
        0x04, 0xdd, 0x5a, 0x70, 0xfa, 0xea, 0x88, 0xb7, 0x6e, 0x47,
        0x33, 0xd0, 0xfa, 0x34, 0x6b, 0x08, 0x6e, 0x2c, 0x0e, 0xfd,
        0x7d, 0x28, 0x15, 0xe3, 0xb6, 0xca, 0x11, 0x8a, 0xb9, 0x45,
        0x71, 0x99, 0x70, 0x64, 0x2b, 0x29, 0x29, 0xb1, 0x8a, 0x71,
        0xb2, 0x8d, 0x87, 0x85, 0x57, 0x96, 0xe3, 0x44, 0xd8
    ]

    # brute force the key.
    for key in xrange(0, 65536):
        if key > 0 and key % 1000 == 0:
            print '[+] Iteration %d. Nothing found so far ...' % key

        # decrypt cipher with the given key and check if result is meaningful
        output = decrypt_simple(cipher, key)

        if output.startswith('hitcon'.encode('hex')):
            print "[+] Key found: %d" % key
            print "[+] Decrypting flag: '%s'" % output.decode('hex')
            break


# --------------------------------------------------------------------------------------------------
'''
ispo@nogirl:~/ctf/hitcon_ctf_2019/suicune$ time ./suicune_crack.py 
[+] Suicune Crack started.
[+] Iteration 1000. Nothing found so far ...
[+] Iteration 2000. Nothing found so far ...
[+] Iteration 3000. Nothing found so far ...
[+] Iteration 4000. Nothing found so far ...
[+] Iteration 5000. Nothing found so far ...
[+] Iteration 6000. Nothing found so far ...
[+] Iteration 7000. Nothing found so far ...
[+] Iteration 8000. Nothing found so far ...
[+] Iteration 9000. Nothing found so far ...
[+] Iteration 10000. Nothing found so far ...
[+] Iteration 11000. Nothing found so far ...
[+] Iteration 12000. Nothing found so far ...
[+] Iteration 13000. Nothing found so far ...
[+] Iteration 14000. Nothing found so far ...
[+] Iteration 15000. Nothing found so far ...
[+] Iteration 16000. Nothing found so far ...
[+] Iteration 17000. Nothing found so far ...
[+] Iteration 18000. Nothing found so far ...
[+] Iteration 19000. Nothing found so far ...
[+] Iteration 20000. Nothing found so far ...
[+] Iteration 21000. Nothing found so far ...
[+] Iteration 22000. Nothing found so far ...
[+] Iteration 23000. Nothing found so far ...
[+] Iteration 24000. Nothing found so far ...
[+] Iteration 25000. Nothing found so far ...
[+] Iteration 26000. Nothing found so far ...
[+] Iteration 27000. Nothing found so far ...
[+] Iteration 28000. Nothing found so far ...
[+] Iteration 29000. Nothing found so far ...
[+] Iteration 30000. Nothing found so far ...
[+] Iteration 31000. Nothing found so far ...
[+] Iteration 32000. Nothing found so far ...
[+] Iteration 33000. Nothing found so far ...
[+] Iteration 34000. Nothing found so far ...
[+] Iteration 35000. Nothing found so far ...
[+] Iteration 36000. Nothing found so far ...
[+] Iteration 37000. Nothing found so far ...
[+] Iteration 38000. Nothing found so far ...
[+] Iteration 39000. Nothing found so far ...
[+] Iteration 40000. Nothing found so far ...
[+] Iteration 41000. Nothing found so far ...
[+] Iteration 42000. Nothing found so far ...
[+] Iteration 43000. Nothing found so far ...
[+] Iteration 44000. Nothing found so far ...
[+] Iteration 45000. Nothing found so far ...
[+] Key found: 45193
[+] Decrypting flag: 'hitcon{nth_perm_Ruby_for_writing_X_C_for_running}'

real    9m27.362s
user    9m27.780s
sys 0m0.004s
'''
# --------------------------------------------------------------------------------------------------
