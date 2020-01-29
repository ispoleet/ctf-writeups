#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Tokyo Westerns CTF 2019 - M Poly Cipher (RE 279pt)
# --------------------------------------------------------------------------------------------------
import struct
import sys


# --------------------------------------------------------------------------------------------------
# These functions find the modular inverse of a number.
def ext_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = ext_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = ext_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse (0x%x %% 0x%x) does not exist' % (a, m))
    else:
        return x % m


# --------------------------------------------------------------------------------------------------
# The following functions calculate the inverse of a matrix.
# Code copied from: https://stackoverflow.com/a/39881366
#
# However we have to make changes and replace all operations with modulo.
def transposeMatrix(m):
    return map(list, zip(*m))

def getMatrixMinor(m,i,j):
    return [row[:j] + row[j+1:] for row in (m[:i]+m[i+1:])]

def getMatrixDeterminant(m):
    # Base case for 2x2 matrix
    if len(m) == 2:
        # return m[0][0]*m[1][1]-m[0][1]*m[1][0]
        return (m[0][0] * m[1][1] - m[0][1] * m[1][0]) % 0xfffffffb

    determinant = 0
    for c in range(len(m)):
        determinant += ((-1)**c)*m[0][c] * getMatrixDeterminant(getMatrixMinor(m,0,c))

    return determinant % 0xfffffffb

def getMatrixInverse(m):
    determinant = getMatrixDeterminant(m)
    # Special case for 2x2 matrix:
    if len(m) == 2:
        # return [[m[1][1]/determinant, -1*m[0][1]/determinant],
#                 [-1*m[1][0]/determinant, m[0][0]/determinant]]
        return [ [(m[1][1]    * modinv(determinant, 0xfffffffb)) % 0xfffffffb, 
                  (-1*m[0][1] * modinv(determinant, 0xfffffffb)) % 0xfffffffb],
                 [(-1*m[1][0] * modinv(determinant, 0xfffffffb)) % 0xfffffffb, 
                  (m[0][0]    * modinv(determinant, 0xfffffffb)) % 0xfffffffb]]

    # Find matrix of co-factors
    cofactors = []

    for r in range(len(m)):
        cofactorRow = []

        for c in range(len(m)):
            minor = getMatrixMinor(m,r,c)
            # cofactorRow.append(((-1)**(r+c)) * getMatrixDeternminant(minor))
            cofactorRow.append((((-1)**(r+c)) * getMatrixDeterminant(minor)) % 0xfffffffb)

        cofactors.append(cofactorRow)
    cofactors = transposeMatrix(cofactors)
    for r in range(len(cofactors)):
        for c in range(len(cofactors)):
            # cofactors[r][c] = cofactors[r][c]/determinant
            cofactors[r][c] = (cofactors[r][c] * modinv(determinant, 0xfffffffb)) % 0xfffffffb

    return cofactors


# --------------------------------------------------------------------------------------------------
# Finds the inverse of a table (if exists). This function is actually a wrapper for
# getMatrixInverse(): It takes a single list, transforms it into a 2 dimensional table as input,
# and then invokes getMatrixInverse().
def matrix_mod_iverse(M, dim=8):
    matrix, row = [], []

    for i in xrange(len(M)):
        if i > 0 and i % dim == 0:
            matrix.append(row)
            row = []

        row.append(M[i])

    # TODO: Check if len(row) is consistent
    matrix.append(row)


    # Check determinant 
    det = getMatrixDeterminant(matrix)

    print '[+] Matrix determinant: 0x%x' % det

    if not det:
        raise Exception('Determinant is zero! Inverse table does not exists :(')

    # Find the inverse matrix and transform it back to 1-D
    invM = []

    for inv_row in getMatrixInverse(matrix):
        invM += inv_row

    return invM


# --------------------------------------------------------------------------------------------------
# Prints a matrix.
def multiply_matrix(A, B, dim=8):
    C = []
    
    for i in xrange(8):
        for j in xrange(8):
            #C.append(S)
            S = 0
            for k in xrange(8):
                S = ((A[i*8 + k] * B[j + k*8]) + S) % 0xfffffffb

            C.append(S)

    return C


# --------------------------------------------------------------------------------------------------
# Prints a matrix.
def print_matrix(M, name, dim=8):
    print '[+] Printing matrix %s:' % name
    for i in xrange(len(M)):
        if i > 0 and i % dim == 0:
            print

        print '%08x' % M[i],        
    print '\n'


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    print '[+] M Poly Cipher crack started.'

    # -------------------------------------------------------------------------
    # Step 1: Load public key and cipher text
    # -------------------------------------------------------------------------
    with open('public.key', 'rb') as fp:
        A, B, C = [], [], []

        for i in range(64):
            A.append(struct.unpack("<L", fp.read(4))[0])

        for i in range(64):
            B.append(struct.unpack("<L", fp.read(4))[0])

        for i in range(64):
            C.append(struct.unpack("<L", fp.read(4))[0])

    with open('flag.enc', 'rb') as fp:
        Q, R, cipher = [], [], []

        for i in range(64):
            Q.append(struct.unpack("<L", fp.read(4))[0])

        for i in range(64):
            R.append(struct.unpack("<L", fp.read(4))[0])

        for i in range(64):
            cipher.append(struct.unpack("<L", fp.read(4))[0])

    print_matrix(A, 'A')
    print_matrix(B, 'B')


    # -------------------------------------------------------------------------
    # Step 2: Calculate the negative tables for A and B
    # -------------------------------------------------------------------------
    negA = [(0xfffffffb - A[i]) for i in xrange(len(A))]
    negB = [(0xfffffffb - B[i]) for i in xrange(len(B))]

    print_matrix(negA, '-A')
    print_matrix(negB, '-B')


    # -------------------------------------------------------------------------
    # Step 3: Calculate (-A + -B)^-1
    # -------------------------------------------------------------------------
    negAB = [(negA[i] + negB[i]) % 0xfffffffb for i in xrange(len(B))]
 
    print_matrix(negAB, '(-A + -B)')

    negABinv = matrix_mod_iverse(negAB)
    
    print_matrix(negABinv, '(-A + -B)^-1')


    # -------------------------------------------------------------------------
    # Step 4: Calculate D = X^2
    # -------------------------------------------------------------------------
    X2 = multiply_matrix(negABinv, C)

    print_matrix(negABinv, 'X^2')
 

    # -------------------------------------------------------------------------
    # Step 5: Calculate Q + R
    # -------------------------------------------------------------------------
    QR = [(Q[i] + R[i]) % 0xfffffffb for i in xrange(len(Q))]

    print_matrix(QR, '(Q + R)')
 

    # -------------------------------------------------------------------------
    # Step 6: Calculate (Q + R)X^2
    # -------------------------------------------------------------------------
    QRX2 = multiply_matrix(QR, X2)

    print_matrix(QRX2, '(Q + R)*X^2')


    # -------------------------------------------------------------------------
    # Step 7: Calculate P = cipher + (Q + R)X^2 = P
    # -------------------------------------------------------------------------
    P = [(cipher[i] + QRX2[i]) % 0xfffffffb for i in xrange(len(cipher))]

    print_matrix(P, '(cipher + (Q + R)*X^2) = P')

    flag = ''.join(chr(x) for x in P)

    print '[+] Final flag:', flag


# --------------------------------------------------------------------------------------------------
'''
ispo@nogirl:~/ctf/tokyowesterns_ctf_2019$ ./m_poly_cipher_crack.py 
[+] M Poly Cipher crack started.
[+] Printing matrix A:
b678daf5 a67e3304 c969d50f dfec7fdd 93c76163 4d789742 65d239a2 d0e90da0
9445e0c4 c5f2a1e6 9e331860 b1f72c80 98826205 9de629bb c1a6db0b 685e7663
49193aca 61925ad1 8b3ea5b9 114aa798 21aea634 b4ffc705 98c48c49 2da74adc
1d64cd4b abcca3ff 49f061fe 8b15189a 849f0daa 7797fc16 3b2363be 0c08ba0f
428b67ef 4cc3ace1 d9f74275 622ad672 e4f28425 b11afd94 93cce244 99d386c5
27b63e86 c532a6fc e899780b 97c8dd25 a97a9d45 44acceec 596188cf 004b944e
a41134a8 c5804962 f03d0b06 5aaeeff4 d5a4b089 673a036c bcb9e0df 8388f001
85f2663b 555d5152 d573c650 3e0a4d15 5c748bda bf947415 1540e665 3d9508ff 

[+] Printing matrix B:
6fc16857 b5029fd1 fe4bae33 e3da04c7 975978ea a57c6e06 5ee93cc8 33293329
69614ce2 be648640 9f712666 ed67bc27 e2d51a11 e5dcc69d 4c60bbad c242981f
cdb17a73 33772b12 89a1dcf8 a81c0a61 f1a08c7b 68d9c5a0 b68ff0bc 82088113
4f214d9d 0385cf0e 53ff1574 f3d668ad c96db819 bc0b5925 353f7343 02792226
e513d244 3ec73d95 d3b1117e 0b921717 2d0de95b 40073992 4eb633ed 8ccda298
50e224a7 ad3cd205 eea70098 3ac29903 a686341b be049a7f 80092068 220eb39d
8359c4e2 64ca141b d00e7c73 27cfa1fc 2a700bc5 b0a79ada e0fb703c 852d5baf
c896e2e7 760a0416 222569cf 19cc6837 e6c52326 d78f8d89 5eabc9f8 9e1b1778 

[+] Printing matrix -A:
49872506 5981ccf7 36962aec 2013801e 6c389e98 b28768b9 9a2dc659 2f16f25b
6bba1f37 3a0d5e15 61cce79b 4e08d37b 677d9df6 6219d640 3e5924f0 97a18998
b6e6c531 9e6da52a 74c15a42 eeb55863 de5159c7 4b0038f6 673b73b2 d258b51f
e29b32b0 54335bfc b60f9dfd 74eae761 7b60f251 886803e5 c4dc9c3d f3f745ec
bd74980c b33c531a 2608bd86 9dd52989 1b0d7bd6 4ee50267 6c331db7 662c7936
d849c175 3acd58ff 176687f0 683722d6 568562b6 bb53310f a69e772c ffb46bad
5beecb53 3a7fb699 0fc2f4f5 a5511007 2a5b4f72 98c5fc8f 43461f1c 7c770ffa
7a0d99c0 aaa2aea9 2a8c39ab c1f5b2e6 a38b7421 406b8be6 eabf1996 c26af6fc 

[+] Printing matrix -B:
903e97a4 4afd602a 01b451c8 1c25fb34 68a68711 5a8391f5 a116c333 ccd6ccd2
969eb319 419b79bb 608ed995 129843d4 1d2ae5ea 1a23395e b39f444e 3dbd67dc
324e8588 cc88d4e9 765e2303 57e3f59a 0e5f7380 97263a5b 49700f3f 7df77ee8
b0deb25e fc7a30ed ac00ea87 0c29974e 369247e2 43f4a6d6 cac08cb8 fd86ddd5
1aec2db7 c138c266 2c4eee7d f46de8e4 d2f216a0 bff8c669 b149cc0e 73325d63
af1ddb54 52c32df6 1158ff63 c53d66f8 5979cbe0 41fb657c 7ff6df93 ddf14c5e
7ca63b19 9b35ebe0 2ff18388 d8305dff d58ff436 4f586521 1f048fbf 7ad2a44c
37691d14 89f5fbe5 ddda962c e63397c4 193adcd5 28707272 a1543603 61e4e883 

[+] Printing matrix (-A + -B):
d9c5bcaa a47f2d21 384a7cb4 3c397b52 d4df25a9 0d0afab3 3b448991 fbedbf2d
0258d255 7ba8d7d0 c25bc130 60a1174f 84a883e0 7c3d0f9e f1f8693e d55ef174
e9354ab9 6af67a18 eb1f7d45 46994e02 ecb0cd47 e2267351 b0ab82f1 5050340c
9379e513 50ad8cee 62108889 81147eaf b1f33a33 cc5caabb 8f9d28fa f17e23c6
d860c5c3 74751585 5257ac03 92431272 edff9276 0eddc8d5 1d7ce9ca d95ed699
87679cce 8d9086f5 28bf8753 2d7489d3 afff2e96 fd4e968b 269556c4 dda5b810
d895066c d5b5a279 3fb4787d 7d816e0b ffeb43a8 e81e61b0 624aaedb f749b446
b176b6d4 3498aa93 0866cfdc a8294aaf bcc650f6 68dbfe58 8c134f9e 244fdf84 

[+] Matrix determinant: 0xc77456e9
[+] Printing matrix (-A + -B)^-1:
0c272e88 c730e3fe d7631e14 e6870f01 68239ebc ba4c7ff2 29660145 dda4a077
71f440cf a6290aab e4bd953f 579214b3 ab230fa7 4bd2ad65 89d1b403 76700fe2
2547456a 54057b99 418953f4 e889f1d0 a9ac08e7 19ffbaa9 d0187a21 0743572c
1f8934d2 3fbd98c3 0b59ffdc 4b877fe2 9d5669fe c9289836 79159fe4 e24adbdb
e81cec36 7f086f1c d38bc9ff b0e0797e e00eb77f f99251f2 764567c6 253f5187
b00e38da 4e8a0d59 455b63d2 addb4767 3dedb761 46278bd4 5f817361 14076f2b
f9617873 c869d7fb 474cdffe 3008b61e 16d86135 c0f2d5d3 9b77d851 df1e2518
03008a87 1531a863 9e1ad124 83564b8e ce7f0821 503eb3ff 4cd5590c 4d092ac9 

[+] Printing matrix X^2:
0c272e88 c730e3fe d7631e14 e6870f01 68239ebc ba4c7ff2 29660145 dda4a077
71f440cf a6290aab e4bd953f 579214b3 ab230fa7 4bd2ad65 89d1b403 76700fe2
2547456a 54057b99 418953f4 e889f1d0 a9ac08e7 19ffbaa9 d0187a21 0743572c
1f8934d2 3fbd98c3 0b59ffdc 4b877fe2 9d5669fe c9289836 79159fe4 e24adbdb
e81cec36 7f086f1c d38bc9ff b0e0797e e00eb77f f99251f2 764567c6 253f5187
b00e38da 4e8a0d59 455b63d2 addb4767 3dedb761 46278bd4 5f817361 14076f2b
f9617873 c869d7fb 474cdffe 3008b61e 16d86135 c0f2d5d3 9b77d851 df1e2518
03008a87 1531a863 9e1ad124 83564b8e ce7f0821 503eb3ff 4cd5590c 4d092ac9 

[+] Printing matrix (Q + R):
9cc0030d 37746be0 98e65eb2 70043810 47d1765c 2450ff83 672fd722 3b001699
fb81e0cf 0f30cba2 2c1c61d3 af41297f 1e6629dd 4f0ff861 e17271d5 51cc9511
b767416b fe881997 5dbef594 67b4ddca cb48c8c4 2f52f2cd 5ffe1b12 5eb0e2c4
d4860a82 6d9b5452 fb65f35f 95e5da8d e31a2e74 1de7d027 750ef17e e395e674
393726f5 19ce9add 56bf1827 e1afba97 5715992b 67d7ee2e b439ac0b 12538679
0bb6d11a 0a4a6f30 8324bc86 37f2cea2 6b6de885 8118eba2 b77bf7d5 02952328
ec183578 c00c705a 6b15ee9c 4cbdde07 c2979ac1 82c80538 1e051fb6 f812277b
dfe6a5af c9200fd6 239a4e39 aa6f09d0 46558a0e c1b6c597 496b37d8 5638fd10 

[+] Printing matrix (Q + R)*X^2:
0b216cf8 3151bb87 8d93e8e6 8a6b2262 c686e895 4834994b fc1c5ddc 8fb5b425
f58f59ff 291e860d c65597bc 76f15e56 2670e190 e81e35c1 ee980c97 7a6d71d1
9630e784 caed6b75 c6b50df5 f39af9b6 dd2a9fd2 7ca8da2d 8e2d707f 4ee9bf20
f316cfe3 87e16a82 54135b16 2065942c 3119dff4 ccb5ffea e5f226d1 3ab50fbf
0a2bdc1a 759af1de b8b42104 6512110c 1d78f63f 3ce146f3 213ef399 34bdb2f3
7362acd7 5b32dd41 e879c345 85d95f59 9364108e 94e283d8 90959ed2 69fbbeba
282d0ce3 9ccb2360 b81f7ec3 847e52a7 cc335ae7 dc568629 404fe08e 0f4574f2
29f17b6c a27c774f 437eead9 7ac030b9 c3f08577 698df7e5 43f91a75 7d31102e 

[+] Printing matrix (cipher + (Q + R)*X^2) = P:
00000054 00000057 00000043 00000054 00000046 0000007b 00000070 00000061
0000002b 00000068 0000005f 00000074 00000030 0000005f 00000074 0000006f
0000006d 0000006f 00000072 00000072 00000030 00000077 0000007d 00000000
00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 

[+] Final flag: TWCTF{pa+h_t0_tomorr0w}
'''
# --------------------------------------------------------------------------------------------------
