#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# HXP 2020 - .< (RE 417)
# ----------------------------------------------------------------------------------------
import hashlib
import z3
from Crypto.Cipher import AES
from Crypto.Util import Counter 


# ----------------------------------------------------------------------------------------
# The Linear Congruential Generator (LCG) of the program (generates pseudo-random
# numbers). Numbers are generated into blocks of 40. The number in each block transformed
# into a valid permutation of numbers 0-39. The `index` corresponds to which block to
# generate.
def lcg(index):
    seed = 44
    key = []

    # To get the i-th entry we need to get all previous i-1 entries first.
    for i in range(index+1):
        prng = []

        # First, generate 40 pseudo-random numbers.
        for j in range(40):
            y = ((seed*1337 + 42) % 400013)
            prng.append(y)
            seed = y
    
    # Then transform these numbers into a valid permutation.
    perm = []
    for nxt in sorted(prng):
        perm.append(prng.index(nxt))

    return perm


# ----------------------------------------------------------------------------------------
# Decrypts the AES countermode encrypted ciphertext using the winning permutation.
def decrypt_ciphertext(perm):
    print('[+] Decrypting ciphertext ...')

    key = b'[%s]' % b','.join(b'%d' % p for p in perm)
    print("[+] Permutation Key: '%s'" % key)


    aes_key = hashlib.sha256(bytearray(key))
    print('[+] AES key (SHA256 of the permutation key):', aes_key.hexdigest())

    cipher = (b"\xd7\xc8\x35\x14\xc4\x27\xcd\x6f\x78\x3a\x80\x57\x76\xb0\xfd\x42" +
              b"\x25\xe4\x87\x5f\x99\x28\x87\x0a\x06\xef\x63\x81\x44")

    ctr_fct=Counter.new(128, initial_value=0)
    crypto = AES.new(key=aes_key.digest(), mode=AES.MODE_CTR, counter=ctr_fct)
    plain = crypto.decrypt(cipher)
    print('[+] Decrypted plaintext:', plain)

    return plain


# ----------------------------------------------------------------------------------------
def test_generate_bool_array(inp):
    print('[+] Testing input permutation:', inp)

    bool_arr = []
    for j in range(40):
        for i in range(40):
            bool_arr.append(
                lcg(i).index(inp[i]) <= lcg(i).index(j) or
                inp[i] == j or
                lcg(40 + j).index(i) >= lcg(40 + j).index(inp.index(j))
            )

    print('[+] Bool Array:', ','.join("True" if b else "False" for b in bool_arr))


# ----------------------------------------------------------------------------------------
def test_generate_bool_array_entry(perm, index):
    print('[+] Testing array entry #%d ...' % index)
    print('[+] Input permutation:', perm)
    
    bool_entry = []
    for j in range(40):
        print('compare: %2d <= %2d || %2d == %2d || %2d >= %2d' % (
            lcg(index).index(perm[index]), lcg(index).index(j),
            perm[index], j,
            lcg(40 + j).index(index), lcg(40 + j).index(perm.index(j))
        ))

        bool_entry.append(            
           lcg(index).index(perm[index]) <= lcg(index).index(j) or
           perm[index] == j or
           lcg(40 + j).index(index) >= lcg(40 + j).index(perm.index(j))
        )

    print('[+] Array entry:', ','.join("True" if b else "False" for b in bool_entry))


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] HXP CTF 2020 .< crack started.')

    # --------------------------------------------------------------------------
    # This code is for testing to ensure that input permutation transformed
    # correctly into the 40x40 boolean array.
    # --------------------------------------------------------------------------
    if False:
        inp = [i for i in range(40)]
        inp = [27,37,2,16,34,18,35,0,24,39,7,19,31,23,5,28,12,10,4,6,17,26,36,33,3,38,32,
               9,14,25,1,13,22,21,8,30,15,29,20,11]

        test_generate_bool_array_entry(inp, 0)
        test_generate_bool_array(inp)
        exit()

    # --------------------------------------------------------------------------
    # Step 1: Add constraints to solution permutation to ensure that corresponds
    # to a valid permutation.
    # --------------------------------------------------------------------------
    smt = z3.Solver()

    print('[+] Creating symbolic permutation ...')

    perm_x = [z3.Int('p%d' % i) for i in range(40)]

    for i, p in enumerate(perm_x):
        smt.add(z3.And(p >= 0, p <= 39))
        smt.add(z3.And([p != pp for (j, pp) in enumerate(perm_x) if i < j]))

    # --------------------------------------------------------------------------
    # Step 2: Create a symbolic function for indices.
    # 
    # We want to use a symbolic variable as an index in the LCG. Since we are
    # using only the first 80 blocks from the LCG, we can enumerate all possible
    # values for indices in the LCG and create a symbolic function.
    # --------------------------------------------------------------------------
    print('[+] Adding constraints to make solution a valid permutation ...')

    def lcg_idx(i, j):
        return lcg(i).index(j)

    # create a symbolic function for zz
    sym_lcg_idx = z3.Function("lcg_idx", z3.IntSort(), z3.IntSort(), z3.IntSort())

    # add all possible values for zz
    for i in range(40):
        for j in range(40):
            smt.add(sym_lcg_idx(i, j) == lcg_idx(i, j))

    # --------------------------------------------------------------------------
    # Step 3: Add all the constraints.
    #
    # Here we have another problem: We want to find perm_x.index(j), where `j`
    # is a constant number. However `perm_x` is an array of symbolic variables.
    # To solve this problem we have to notice that if `perm_x.index(j) == k`
    # then it means that the symbolic variable P_j must be `k`.
    #
    # Since we do not know which is the correct value for `k`, we just have to
    # try them all (they are 40) and combine them with a logic OR. That is,
    # instead of adding a (a || b || c) constraint, we now add:
    #   P_j == 0 && (a || b || c) || P_j == 1 && (a' || b' || c') ...
    #
    # This blows up the number of equations by an order which means that we now
    # have to solve 40*40*40 = 64000 equations.
    # --------------------------------------------------------------------------
    for j in range(40):
        print('[+] Adding constraints for iteration %d/39 ...' % j)        
        for i in range(40):
            smt.add(
                z3.Or(
                    [z3.And(
                        # let perm_x.index(j) == k. Then Lx[k] == j.
                        perm_x[k] == j,
                        z3.Or(
                            sym_lcg_idx(i, perm_x[i]) <= lcg(i).index(j),
                            perm_x[i] == j,
                            lcg(40 + j).index(i) >= lcg(40 + j).index(k)
                        )
                    ) for k in range(40)])
                )

    # --------------------------------------------------------------------------
    # Step 4: Solve the constraints and find all solutions.
    # --------------------------------------------------------------------------
    print('[+] Checking satisfiability (will take a while) .....')

    # Check all valid solutions.
    while smt.check() == z3.sat: 
        print('[+] Valid solution found!')

        mdl = smt.model()

        # Extract the solution permutation
        key_perm = [mdl.evaluate(p).as_long() for p in perm_x]

        print('[+] Solution permutation:', ','.join(str(p) for p in key_perm))

        flag = decrypt_ciphertext(key_perm)
        print('[+] Final flag is:', flag)

        # make sure that current solution won't appear again
        smt.add(z3.Or([p != mdl.evaluate(p).as_long() for p in perm_x]))

    print('[+] Program finished! Bye bye :)')


# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop:~/ctf/hxp_2020/·<$ time ./crack.py 
[+] HXP CTF 2020 .< crack started.
[+] Creating symbolic permutation ...
[+] Adding constraints to make solution a valid permutation ...
[+] Adding constraints for iteration 0/39 ...
[+] Adding constraints for iteration 1/39 ...
[+] Adding constraints for iteration 2/39 ...
[+] Adding constraints for iteration 3/39 ...
[+] Adding constraints for iteration 4/39 ...
[+] Adding constraints for iteration 5/39 ...
[+] Adding constraints for iteration 6/39 ...
[+] Adding constraints for iteration 7/39 ...
[..... TRUNCATED FOR BREVITY .....]
[+] Adding constraints for iteration 37/39 ...
[+] Adding constraints for iteration 38/39 ...
[+] Adding constraints for iteration 39/39 ...
[+] Checking satisfiability (will take a while) .....
[+] Valid solution found!
[+] Solution permutation: 37,33,4,3,38,23,14,9,36,12,0,22,39,32,16,19,35,5,6,27,25,8,13,31,30,24,34,11,29,21,26,2,7,17,1,10,20,18,15,28
[+] Decrypting ciphertext ...
[+] Permutation Key: 'b'[37,33,4,3,38,23,14,9,36,12,0,22,39,32,16,19,35,5,6,27,25,8,13,31,30,24,34,11,29,21,26,2,7,17,1,10,20,18,15,28]''
[+] AES key (SHA256 of the permutation key): d906fcb5f324e486fdb4327c082e00d67653742e142f5a3a20c98349a661b03c
[+] Decrypted plaintext: b'hxp{r34dAb1liTy_1s_p01nTl3s5}'
[+] Final flag is: b'hxp{r34dAb1liTy_1s_p01nTl3s5}'
[+] Program finished! Bye bye :)

real	1m51.578s
user	1m51.462s
sys	0m0.079s
ispo@ispo-glaptop:~/ctf/hxp_2020/·<$ echo '[37,33,4,3,38,23,14,9,36,12,0,22,39,32,16,19,35,5,6,27,25,8,13,31,30,24,34,11,29,21,26,2,7,17,1,10,20,18,15,28]' | ./'·<.hs'
hxp{r34dAb1liTy_1s_p01nTl3s5}
'''
# ----------------------------------------------------------------------------------------

