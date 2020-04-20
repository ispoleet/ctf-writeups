#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Plaid CTF 2020 - reee (RE 150)
# --------------------------------------------------------------------------------------------------
from z3 import *

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    print '[+] reee crack started.'


    # -------------------------------------------------------------------------
    # Encrypt example
    # -------------------------------------------------------------------------    
    flag = [ord(f) for f in 'KYRIAKOS']

    key = 0x50
    for i in xrange(1337):
        for j in xrange(len(flag)):
            old_flag = flag[j]
            flag[j] ^= key
            key = old_flag

    print '[+] Encrypted flag:', ['%02X' % f for f in flag]

    
    # -------------------------------------------------------------------------
    # Crack the flag
    # -------------------------------------------------------------------------
    enc_flag = [
        0x48, 0x5F, 0x36, 0x35, 0x35, 0x25, 0x14, 0x2C, 0x1D, 0x01,
        0x03, 0x2D, 0x0C, 0x6F, 0x35, 0x61, 0x7E, 0x34, 0x0A, 0x44,
        0x24, 0x2C, 0x4A, 0x46, 0x19, 0x59, 0x5B, 0x0E, 0x78, 0x74,
        0x29, 0x13, 0x2C
    ]    
    # enc_flag = flag
   
    length = len(enc_flag)

    print '[+] Flag length:', length

    s = Solver()

    # we have len(flag)*1337 unknown variables (2D)
    X = [ BitVec('X_%d_%d' % (i, j), 32) for i in range(length) for j in range(1337+1)]
    K = [ BitVec('K_%d_%d' % (i, j), 32) for i in range(length) for j in range(1337+1)]
    

    # limit each variable to 8 bits
    print '[+] Constraining variables to 8 bits ...'
    
    for k in K: s.add( And(k >= 0, k <= 0xff) )
    for x in X: s.add( And(x >= 0, x <= 0xff) )

    # add flag and key equations
    print '[+] Adding flag and key equations ...'

    for i in xrange(1337):
        for j in xrange(length):
            s.add(X[length*i + j] ^ K[length*i + j] == X[length*(i+1) + j])

            # update key (w/ special cases)
            if j:
                s.add(K[length*i + j] == X[length*i + j-1])
            else:
                if i:
                    s.add(K[length*i] == X[length*i - 1])
                else:
                    s.add(K[0] == 0x50)

    print '[+] Adding the final equation ...'

    for j in xrange(length):
        s.add(X[length*(i+1) + j] == enc_flag[j])

 
    print '[+] Checking sat ...'
        
    if s.check() == sat: 
        print '[+] Valid solution found!'

        m = s.model()
        
        flag = ''
        for x in X[:length]: 
            v = m.evaluate(x).as_long()
            
            flag += chr(v)            

            print '[+]   %s = 0x%02x (%c)' % (x, v, chr(v))
        
        print '[+] Flag:', flag
   
# --------------------------------------------------------------------------------------------------
'''
ispo@leet:~/ctf/plaid_ctf_2020/reee$ time ./reee_crack.py 
[+] reee crack started.
[+] Encrypted flag: ['4C', '06', '1C', '49']
[+] Flag length: 33
[+] Constraining variables to 8 bits ...
[+] Adding flag and key equations ...
[+] Adding the final equation ...
[+] Checking sat ...
[+] Valid solution found!
[+]   X_0_0 = 0x70 (p)
[+]   X_0_1 = 0x63 (c)
[+]   X_0_2 = 0x74 (t)
[+]   X_0_3 = 0x66 (f)
[+]   X_0_4 = 0x7b ({)
[+]   X_0_5 = 0x6f (o)
[+]   X_0_6 = 0x6b (k)
[+]   X_0_7 = 0x5f (_)
[+]   X_0_8 = 0x6e (n)
[+]   X_0_9 = 0x6f (o)
[+]   X_0_10 = 0x74 (t)
[+]   X_0_11 = 0x68 (h)
[+]   X_0_12 = 0x69 (i)
[+]   X_0_13 = 0x6e (n)
[+]   X_0_14 = 0x67 (g)
[+]   X_0_15 = 0x5f (_)
[+]   X_0_16 = 0x74 (t)
[+]   X_0_17 = 0x6f (o)
[+]   X_0_18 = 0x6f (o)
[+]   X_0_19 = 0x5f (_)
[+]   X_0_20 = 0x66 (f)
[+]   X_0_21 = 0x61 (a)
[+]   X_0_22 = 0x6e (n)
[+]   X_0_23 = 0x63 (c)
[+]   X_0_24 = 0x79 (y)
[+]   X_0_25 = 0x5f (_)
[+]   X_0_26 = 0x74 (t)
[+]   X_0_27 = 0x68 (h)
[+]   X_0_28 = 0x65 (e)
[+]   X_0_29 = 0x72 (r)
[+]   X_0_30 = 0x65 (e)
[+]   X_0_31 = 0x21 (!)
[+]   X_0_32 = 0x7d (})
[+] Flag: pctf{ok_nothing_too_fancy_there!} 
'''
# --------------------------------------------------------------------------------------------------
