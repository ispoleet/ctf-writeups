#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Plaid CTF 2020 - YOU wa SHOCKWAVE (RE 250)
# --------------------------------------------------------------------------------------------------
from z3 import *

# --------------------------------------------------------------------------------------------------
def zz_helper(x, y, z):
    if y > z:
        return (1, z - x) 

    a, b = zz_helper(y, x + y, z)
  
    if b >= x:
        return (2*a + 1, b - x)
    
    return (2*a, b)
    
# --------------------------------------------------------------------------------------------------
def zz(x):
    return zz_helper(1, 1, x)[0]

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    print '[+] shockwave crack started.'

    zz_tbl = {}
    
    
    # We know that flag consists of printable characters, so we only calculate
    # all the possible inputs for zz.
    for i in xrange(0x20, 0x7e+1):
        for j in xrange(0x20, 0x7e+1):            
            zz_tbl[i*256 + j] = zz(i*256 + j)

    array = [
         [2, 5, 12, 19, 3749774],
         [2, 9, 12, 17, 694990],
         [1, 3, 4, 13, 5764],
         [5, 7, 11, 12, 299886],
         [4, 5, 13, 14, 5713094],
         [0, 6, 8, 14, 430088],
         [7, 9, 10, 17, 3676754],
         [0, 11, 16, 17, 7288576],
         [5, 9, 10, 12, 5569582],
         [7, 12, 14, 20, 7883270],
         [0, 2, 6, 18, 5277110],
         [3, 8, 12, 14, 437608],
         [4, 7, 12, 16, 3184334],
         [3, 12, 13, 20, 2821934],
         [3, 5, 14, 16, 5306888],
         [4, 13, 16, 18, 5634450],
         [11, 14, 17, 18, 6221894],
         [1, 4, 9, 18, 5290664],
         [2, 9, 13, 15, 6404568],
         [2, 5, 9, 12, 3390622]
     ]

    s = Solver()

    print '[+] Creating symbolic zz() function ...'

    # create a symbolic function for zz
    zz_fct = Function("zz_fct", BitVecSort(32), BitVecSort(32))

    # add all possible values for zz
    for i, z in zz_tbl.items():
        s.add(zz_fct(i) == z)

    
    print '[+] Initializing flag syms ...'

    X = [ BitVec('X_%d' % i, 32) for i in range(42+1)]
    for i in xrange(1, 42+1):        
        s.add( And(X[i] >= 0x21, X[i] <= 0x7e) )
 

    print '[+] Adding initial constraints'
    
    _sum = BitVecVal(0, 32)
    
    for i in range(1, 21+1):
        _sum ^= zz_fct( X[2*i - 1]*256 + X[2*i])
    
    s.add(_sum == 5803878)


    print '[+] Adding array constraints ...'
    for (i, j, k, l, target) in array[:]:
        print '[+] Adding constraint: i=%d, j=%d, k=%d, l=%d, target=%d' % (i, j, k, l, target)
        
        s.add(zz_fct(X[2*i + 1]*256 + X[2*i + 2]) ^
              zz_fct(X[2*j + 1]*256 + X[2*j + 2]) ^
              zz_fct(X[2*k + 1]*256 + X[2*k + 2]) ^
              zz_fct(X[2*l + 1]*256 + X[2*l + 2]) == target)
    
    print '[+] Checking sat....'



    print '[+] Checking sat ...'
        
    if s.check() == sat: 
        print '[+] Valid solution found!'

        m = s.model()
        
        flag = ''
        for x in X[1:-1]: 
            v = m.evaluate(x).as_long()            
            flag += chr(v)            

            print '[+]   %s = 0x%02x (%c)' % (x, v, chr(v))
        
        print '[+] Flag:', flag


# --------------------------------------------------------------------------------------------------
'''
ispo@leet:~/ctf/plaid_ctf_2020/YOU_wa_SHOCKWAVE$ ./shockwave_crack.py 
[+] shockwave crack started.
[+] Creating symbolic zz() function ...
[+] Initializing flag syms ...
[+] Adding initial constraints
[+] Adding array constraints ...
[+] Adding constraint: i=2, j=5, k=12, l=19, target=3749774
[+] Adding constraint: i=2, j=9, k=12, l=17, target=694990
[+] Adding constraint: i=1, j=3, k=4, l=13, target=5764
[+] Adding constraint: i=5, j=7, k=11, l=12, target=299886
[+] Adding constraint: i=4, j=5, k=13, l=14, target=5713094
[+] Adding constraint: i=0, j=6, k=8, l=14, target=430088
[+] Adding constraint: i=7, j=9, k=10, l=17, target=3676754
[+] Adding constraint: i=0, j=11, k=16, l=17, target=7288576
[+] Adding constraint: i=5, j=9, k=10, l=12, target=5569582
[+] Adding constraint: i=7, j=12, k=14, l=20, target=7883270
[+] Adding constraint: i=0, j=2, k=6, l=18, target=5277110
[+] Adding constraint: i=3, j=8, k=12, l=14, target=437608
[+] Adding constraint: i=4, j=7, k=12, l=16, target=3184334
[+] Adding constraint: i=3, j=12, k=13, l=20, target=2821934
[+] Adding constraint: i=3, j=5, k=14, l=16, target=5306888
[+] Adding constraint: i=4, j=13, k=16, l=18, target=5634450
[+] Adding constraint: i=11, j=14, k=17, l=18, target=6221894
[+] Adding constraint: i=1, j=4, k=9, l=18, target=5290664
[+] Adding constraint: i=2, j=9, k=13, l=15, target=6404568
[+] Adding constraint: i=2, j=5, k=9, l=12, target=3390622
[+] Checking sat....
[+] Checking sat ...
[+] Valid solution found!
[+]   X_1 = 0x50 (P)
[+]   X_2 = 0x43 (C)
[+]   X_3 = 0x54 (T)
[+]   X_4 = 0x46 (F)
[+]   X_5 = 0x7b ({)
[+]   X_6 = 0x47 (G)
[+]   X_7 = 0x72 (r)
[+]   X_8 = 0x34 (4)
[+]   X_9 = 0x70 (p)
[+]   X_10 = 0x68 (h)
[+]   X_11 = 0x31 (1)
[+]   X_12 = 0x43 (C)
[+]   X_13 = 0x53 (S)
[+]   X_14 = 0x5f (_)
[+]   X_15 = 0x44 (D)
[+]   X_16 = 0x33 (3)
[+]   X_17 = 0x53 (S)
[+]   X_18 = 0x69 (i)
[+]   X_19 = 0x47 (G)
[+]   X_20 = 0x6e (n)
[+]   X_21 = 0x5f (_)
[+]   X_22 = 0x49 (I)
[+]   X_23 = 0x73 (s)
[+]   X_24 = 0x5f (_)
[+]   X_25 = 0x74 (t)
[+]   X_26 = 0x52 (R)
[+]   X_27 = 0x55 (U)
[+]   X_28 = 0x6c (l)
[+]   X_29 = 0x59 (Y)
[+]   X_30 = 0x5f (_)
[+]   X_31 = 0x4d (M)
[+]   X_32 = 0x79 (y)
[+]   X_33 = 0x5f (_)
[+]   X_34 = 0x50 (P)
[+]   X_35 = 0x61 (a)
[+]   X_36 = 0x73 (s)
[+]   X_37 = 0x35 (5)
[+]   X_38 = 0x69 (i)
[+]   X_39 = 0x6f (o)
[+]   X_40 = 0x4e (N)
[+]   X_41 = 0x21 (!)
[+] Flag: PCTF{Gr4ph1CS_D3SiGn_Is_tRUlY_My_Pas5ioN!
'''
# --------------------------------------------------------------------------------------------------
