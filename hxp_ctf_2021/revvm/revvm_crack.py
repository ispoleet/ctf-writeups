#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# HXP CTF 2021 - revvm (RE - 833pt)
# ----------------------------------------------------------------------------------------
import struct
import numpy


# ----------------------------------------------------------------------------------------
# Code taken from:
# https://stackoverflow.com/questions/4287721/easiest-way-to-perform-modular-matrix-inversion-with-python
def generalizedEuclidianAlgorithm(a, b):
    if b > a:
        return generalizedEuclidianAlgorithm(b,a);
    elif b == 0:
        return (1, 0);
    else:
        (x, y) = generalizedEuclidianAlgorithm(b, a % b);
        return (y, x - (a // b) * y)

def inversemodp(a, p):
    a = a % p
    if (a == 0):
        return None
    if a > 1 and p % a == 0:
        return None
    (x,y) = generalizedEuclidianAlgorithm(p, a % p);
    inv = y % p
    assert (inv * a) % p == 1
    return inv

def identitymatrix(n):
    return [[int(x == y) for x in range(0, n)] for y in range(0, n)]

def inversematrix(matrix, q):
    n = len(matrix)
    A = numpy.matrix([[ matrix[j][i] for i in range(0,n)] for j in range(0, n)], dtype = int)
    Ainv = numpy.matrix(identitymatrix(n), dtype = int)
    for i in range(0, n):
        factor = inversemodp(A[i,i], q)
        if factor is None:
             raise ValueError("TODO: deal with this case")
        A[i] = A[i] * factor % q
        Ainv[i] = Ainv[i] * factor % q
        for j in range(0, n):
            if (i != j):
                factor = A[j, i]
                A[j] = (A[j] - factor * A[i]) % q
                Ainv[j] = (Ainv[j] - factor * Ainv[i]) % q
    return Ainv


# ----------------------------------------------------------------------------------------
def matrix_mult(A, B):
    """Multiply 2 matrices A and B using the vanilla algorithm."""
    C = [[0 for x in range(5)] for y in range(5)]

    for i in range(len(A)):
        for j in range(len(B[0])):
            for k in range(len(B)):
                C[i][j] = (C[i][j] + A[i][k] * B[k][j]) % 127
    return C


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Revvm crack started.')

    # Load VM global data into a bitvector.
    rbin = open('chall.rbin', 'rb').read()

    print('[+] Loading global data ...')
    inp_len, = struct.unpack("<Q", rbin[0:8])
    inp = rbin[8:inp_len]

    bitvec = ''.join([f'{b:#010b}'[2:] for b in inp][::-1])


    # Matrix starts from offset 360 (check asm file).
    bitvec = bitvec[:len(bitvec) - 360]

    print(f'[+] Matrix as bit vector: {bitvec}')

    A = [[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0],[0,0,0,0,0]]
    l = len(bitvec)-7

    # Extract 7-bit values from bit vector.
    for i in range(25):
        A[i % 5][i // 5] = int(bitvec[l:l+7], 2)
        print(f'[+] Extracting matrix value at ({i % 5}, {i // 5}) = {bitvec[l:l+7]}b = {A[i % 5][i // 5]}')

        l -= 7  # Move on to the next number

    print(f'[+] Original matrix: {A}')

    Ainv = inversematrix(A, 127).tolist()
    print(f'[+] Inverted matrix (A^-1): {Ainv}')

    for det in range(1, 127+1):
        print(f'[+] Trying det:{det:3d} ...')
        
        # Build identity matrix.
        I = [[det,0,0,0,0],[0,det,0,0,0],[0,0,det,0,0],[0,0,0,det,0],[0,0,0,0,det]]

        # Originally: A * FLAG = I*det
        # We multiply on the left by A^-1: A^-1 * A * FLAG = A^-1 * I*det
        # So: FLAG = A^-1 * I*det
        C = matrix_mult(Ainv, I)
        C = sum(C, [])  # Convert from list of lists to single list

        flag = ''.join(chr(x) for x in C)
        if flag[0:3] == 'hxp':
            print(f'[+] FLAG FOUND: {flag}')
            break

    print('[+] Program finished. Bye bye :)')


# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop:~/ctf/hxp_2021/revvm$ ./revvm_crack.py
[+] Revvm crack started.
[+] Loading global data ...
[+] Matrix as bit vector: 01010001010000100110001001011101101100101001001110001100111001010000100110001111100111011100101110000100100011001010001011000001110110101010000000010100001011010111100111000000
[+] Extracting matrix value at (0, 0) = 1000000b = 64
[+] Extracting matrix value at (1, 0) = 1110011b = 115
[+] Extracting matrix value at (2, 0) = 0110101b = 53
[+] Extracting matrix value at (3, 0) = 0100001b = 33
[+] Extracting matrix value at (4, 0) = 0000001b = 1
[+] Extracting matrix value at (0, 1) = 1010100b = 84
[+] Extracting matrix value at (1, 1) = 1110110b = 118
[+] Extracting matrix value at (2, 1) = 1100000b = 96
[+] Extracting matrix value at (3, 1) = 0100010b = 34
[+] Extracting matrix value at (4, 1) = 0011001b = 25
[+] Extracting matrix value at (0, 2) = 0010010b = 18
[+] Extracting matrix value at (1, 2) = 1011100b = 92
[+] Extracting matrix value at (2, 2) = 1011100b = 92
[+] Extracting matrix value at (3, 2) = 1110011b = 115
[+] Extracting matrix value at (4, 2) = 1100011b = 99
[+] Extracting matrix value at (0, 3) = 0000100b = 4
[+] Extracting matrix value at (1, 3) = 1100101b = 101
[+] Extracting matrix value at (2, 3) = 0011001b = 25
[+] Extracting matrix value at (3, 3) = 1001110b = 78
[+] Extracting matrix value at (4, 3) = 0010100b = 20
[+] Extracting matrix value at (0, 4) = 1011011b = 91
[+] Extracting matrix value at (1, 4) = 1001011b = 75
[+] Extracting matrix value at (2, 4) = 0011000b = 24
[+] Extracting matrix value at (3, 4) = 0100001b = 33
[+] Extracting matrix value at (4, 4) = 1010001b = 81
[+] Original matrix: [[64, 84, 18, 4, 91], [115, 118, 92, 101, 75], [53, 96, 92, 25, 24], [33, 34, 115, 78, 33], [1, 25, 99, 20, 81]]
[+] Inverted matrix (A^-1): [[85, 59, 72, 70, 65], [85, 106, 2, 52, 106], [52, 28, 48, 61, 71], [52, 80, 60, 83, 95], [39, 107, 121, 95, 35]]
[+] Trying det:  1 ...
[+] Trying det:  2 ...
[+] Trying det:  3 ...
[+] Trying det:  4 ...
....
[+] Trying det: 56 ...
[+] Trying det: 57 ...
[+] Trying det: 58 ...
[+] FLAG FOUND: hxp{Wh4t_4_dum6_D3s1gn!1}
[+] Program finished. Bye bye :)
ispo@ispo-glaptop:~/ctf/hxp_2021/revvm$ ./revvm chall.rbin
Key: hxp{Wh4t_4_dum6_D3s1gn!1}
:)
ispo@ispo-glaptop:~/ctf/hxp_2021/revvm$
'''
# ----------------------------------------------------------------------------------------

