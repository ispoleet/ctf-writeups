#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# HITCON QUALS 2024 - Penguin & Crab (RE 268)
# ----------------------------------------------------------------------------------------
import struct
import multiprocessing
import time
from sympy.ntheory import factorint


flag = b'hitcon{????????????????????????????????????????????????????????????????????????????????????????????}'
#flag = b'hitcon{<https://www.youtube.com/watch?v=FrX0ZfX8Dqs>&&<https://www.youtube.com/watch?v=LDU_Txk06tM>}'

tbl = [
    0xaec4f08c, 0x642c04ac, 0xa3607854, 0x2d393934,
    0x8e2c4f5a, 0xddd67d14, 0x7e005496, 0x3ed14a02,
    0x0a56a772, 0x466a4076, 0xd3a352a9, 0x495e93e3,
    0x67c44adf, 0x3aebe5ba, 0xed850da8, 0xd4b77198,
    0x51bdb6b2, 0x3a5f2448, 0x807889ca, 0x5b9d4d6e,
    0x8320efd6, 0x9e68e874, 0xba7fbea1, 0x827bc7e4,
    0x129f824a
]

rol = lambda a, b: ((a << b) | (a >> (32 - b))) & 0xffffffff
ror = lambda a, b: ((a >> b) | (a << (32 - b))) & 0xffffffff

count = 0 # Global counter for recursive fuctions.


# ----------------------------------------------------------------------------------------
def stage_1(flag_vec):
    """Stage #1: encryption with XOR and ROL."""
    print('[+] Encryption stage #1 ...')

    new_tbl = [0]*25
    for i, v in enumerate(flag_vec):
        r = 0xdeadbeef ^ v
        for j in range(0x19 + 1):
            r = rol(r, 0x19) ^ 0x14530451
        
        new_tbl[i] = tbl[i] ^ rol(r, 0x19) ^ 0xcafebabe
        print(f'[+]     v:{v:08x}, tbl[{i:2d}] = {tbl[i]:08x} ~> {new_tbl[i]:08x}')

    return new_tbl


# ----------------------------------------------------------------------------------------
def stage_2(new_tbl):
    """Stage #2: encryption to produce giant (64-bit) vecs."""
    print('[+] Encryption stage #2 ...')
    giant = [0]*12

    # Use the first 12 elements of `tbl`.
    for i in range(6):
        if new_tbl[2*i] >= new_tbl[2*i + 1]:
            pass  # Go to badboy message.

        giant[i] = new_tbl[2*i] * new_tbl[2*i + 1]
        print(f'[+]    giant[{i:2d}] = {giant[i]:016x}')

    # Use the last 12 elements of `tbl` (25 in total).
    for i in range(6):
        if tbl[0x1a - 2 - 2*i] >= tbl[0x1a - 2 - 2*i - 1]:
            pass  # Go to badboy message.

        giant[6 + i] = tbl[0x1a - 2 - 2*i] * tbl[0x1a - 2 - 2*i - 1]
        print(f'[+]    giant[{6 + i:2d}] = {giant[6 + i]:016x}')

    return giant


# ----------------------------------------------------------------------------------------
def stage_3(giant, tbl_12):
    """Stage #3: verification of `giant` (first part)."""
    print('[+] Verification stage #1 (div giant) ...')

    div_giant = [giant[i] // tbl_12 for i in range(12)]

    expected_div_giant = [
        0x000000001be3b694, 0x000000000ad42f89,
        0x00000001003913b7, 0x0000000037c23eb4,
        0x0000000064c07ef5, 0x000000000d7b4785,
        0x0000000049115944, 0x000000005241f45e,
        0x00000000829722e9, 0x000000006801ca71,
        0x00000000165020cf, 0x00000000e45f7ab1
    ]

    for a, b in zip(div_giant, expected_div_giant):
        if a != b:
            pass  # Go to badboy message.
            
        print(f'[+]    DIV giant: {a:016x} != {b:016x} (expected)')        

    return div_giant


# ----------------------------------------------------------------------------------------
def stage_4(giant, tbl_12):
    """Stage #4: verification of `giant` (second part)."""
    print('[+] Verification stage #2 (mod giant) ...')

    mod_giant = [0]*12

    for i in range(12):
        mod = giant[i] % tbl_12
        #print(f'init mod:{mod:08x}, giant:{giant[i]:016x}, tbl[12]:{tbl_12:08x}')
        if mod == 0:
            print('[+] Perfect modulo!')
            result = 1
        else:
            a = 0x56361E32
            result = 1
            old_mod = mod
            while old_mod >= 2:
                old_mod = mod
                if (mod & 1) != 0:
                    #print('mod 1!')
                    result = result*a - ((result*a * 0x8EF2C4468D568FF5) >> 95) * 0xE53ACEB5

                a = a*a - (a * a * 0x8EF2C4468D568FF5 >> 95) * 0xE53ACEB5
                mod >>= 1
                #print(f'a:{a:016x}, mod:{mod:016x} ~> result:{result:016x}')

            mod_giant[i] = result

    expected_mod_giant = [    
        0x00000000a2cc3f37, 0x00000000b8b0e2e6,
        0x000000009dea4fd6, 0x00000000897da0d6,
        0x0000000052b660e5, 0x000000007dbcdc09,
        0x00000000588e7836, 0x000000003ea786e5,
        0x000000005bc7bb33, 0x00000000a3959e86,
        0x000000005ab05a2f, 0x00000000b09e4a8c
    ]

    for a, b in zip(mod_giant, expected_mod_giant):
        if a != b:
            pass  # Go to badboy message.
            
        print(f'[+]    MOD giant: {a:016x} != {b:016x} (expected)')        
   
    return mod_giant 


# ----------------------------------------------------------------------------------------
def stage_5(tbl_12):
    """Stage #5: verification of tbl[12] .

        (remote) gef> x/64xg $rax
            0xffff88813bdbe800:	0x38ed550c61366b19	0x0000000000000000
            0xffff88813bdbe810:	0xa368d7f6f944ef95	0x0000000000000000
            .....
            0xffff88813bdbe9d0:	0x000154d52272bf8f	0x0000000000000000
            0xffff88813bdbe9e0:	0x7e416b359a0655cc	0x0000000000000000
            0xffff88813bdbe9f0:	0x6858e18b590d1a8f	0x0000000000000000
    """
    print('[+] Verification stage #3 (tbl[12]) ...')

    fin_tbl = [  # Final table.
        0x38ed550c61366b19, 0xa368d7f6f944ef95,
        0x7730e544811b003b, 0x0ba7b915f29478b8,
        0x4cf3c7a1444ddcd5, 0x6a1ee5d1cb932edd,
        0x1c653d0faa75cd04, 0x5129602cebb27cd3,
        0x8d3e0ddb822d166c, 0x7743085c81b563ca,
        0x1fd73d5b1682bec1, 0x49ca0c91d932e680,
        0x10ac7806fd7dc9e2, 0x939cb3d71dc3703e,
        0x3719c10efed548af, 0x091aad1f7fe14e4b,
        0x8fe8985576b03857, 0x376937bc0af64e77,
        0x26190529fd5f0437, 0x12cf894f2af71bf3,
        0x22e8f33e31870d59, 0x6842e8d2ed57a1f1,
        0x189ebe5a06e8334f, 0x591cea928108d643,
        0x4914740091a11c11, 0x3b1a8bb8cd64fae1,
        0x48009c01b6dc47ba, 0x6cc80ed5a2d94b80,
        0x3a41f29b470b9346, 0x000154d52272bf8f,
        0x7e416b359a0655cc, 0x6858e18b590d1a8f
    ]

    expected_chksum = 0x6b3312ec731522288  # Target number.
    
    # If i-th bit of tbl[12] is 1, then multiply `chksum` with fin_tbl[i].
    print(f'[+]    tbl[12] = {tbl_12:08x} = {bin(tbl_12)}')

    chksum = 0
    for i, bit in enumerate(bin(tbl_12)[2:][::-1]):  # Inverse bits.
        if bit == '1':
            chksum += fin_tbl[i]
            print(f'[+]    Use fin_tbl[{i:2d}] ~> {fin_tbl[i]:016x}')

    
    print(f'[+] Final    checksum: {chksum:016x}')
    print(f'[+] Expected checksum: {expected_chksum:016x}')

    if chksum != expected_chksum:
        pass  # Go to badboy message.

    # Else, print goodboy message.




# ----------------------------------------------------------------------------------------
def crack_stage_5():
    """To crack this stage you need to find which numbers to select from `fin_tbl` such
    that their sum is 0x6b3312ec731522288. This is obviously the subset sums problem
    which is NP-C. The values are fairly large for a Dynamic Programming solution.

    Instead we do a bruteforce. `tbl[12]` is 32-bits so we can brute-force all possible
    solutions. However, we have to be smart: a `for i in range(2**32): stage_5(i)` type
    of bruteforce will be very slow. Instead, we have to write a recursive function
    to build all possible solutions of depth 32. We can use multiple threads to make
    things faster.
    """
    print('[+] Crack stage #5: Finding tbl[12] ...')

    fin_tbl = [  # Final table.
        0x38ed550c61366b19, 0xa368d7f6f944ef95,
        0x7730e544811b003b, 0x0ba7b915f29478b8,
        0x4cf3c7a1444ddcd5, 0x6a1ee5d1cb932edd,
        0x1c653d0faa75cd04, 0x5129602cebb27cd3,
        0x8d3e0ddb822d166c, 0x7743085c81b563ca,
        0x1fd73d5b1682bec1, 0x49ca0c91d932e680,
        0x10ac7806fd7dc9e2, 0x939cb3d71dc3703e,
        0x3719c10efed548af, 0x091aad1f7fe14e4b,
        0x8fe8985576b03857, 0x376937bc0af64e77,
        0x26190529fd5f0437, 0x12cf894f2af71bf3,
        0x22e8f33e31870d59, 0x6842e8d2ed57a1f1,
        0x189ebe5a06e8334f, 0x591cea928108d643,
        0x4914740091a11c11, 0x3b1a8bb8cd64fae1,
        0x48009c01b6dc47ba, 0x6cc80ed5a2d94b80,
        0x3a41f29b470b9346, 0x000154d52272bf8f,
        0x7e416b359a0655cc, 0x6858e18b590d1a8f
    ]

    expected_chksum = 0x6b3312ec731522288  # Target number.
    
 
    def precompute(prefix):
        """Precomputes the checksum for a given `prefix`."""
        chksum = 0
        for i, bit in enumerate(prefix[::-1]):  # Inverse bits.
            if bit == '1':
                chksum += fin_tbl[i]
                #print(f'[+]    Use fin_tbl[{i:2d}] ~> {fin_tbl[i]:016x}')

        return chksum

    def bruteforce(chksum, bits, depth, tid):
        """Bruteforce on thread `tid` starting from `chksum` (tbl[12] = `bits`)."""
        global count
        count += 1
        if count % 0x1000000 == 0:
            print(f'[+]   Status: #{count:08x}, s:{chksum:016x}, b:{bits:32s}, d:{depth}, t:{tid}')
 
        if chksum == expected_chksum:
            print(f'[+]   Solution FOUND: #{count:08x}, s:{chksum:016x}, b:{bits:32s}, d:{depth}, t:{tid}')
            print(f'[+]   tbl[12] = 0x{int(bits, 2):08x}')
            return True  # Stop searching.

        elif chksum > expected_chksum:
            return False  # We have exceeeded the chksum, so there's no point continuing.        
        elif depth >= 32:
            return False  # We have exceeded max depth.

        # Recursively, try to take (and not take) the number at index `depth`.
        retn = bruteforce(chksum + fin_tbl[depth], '1' + bits, depth + 1, tid)
        if retn:
            return retn  # Propagate solution.
        return bruteforce(chksum,                  '0' + bits, depth + 1, tid)


    #p = precompute('10001111'); print(hex(p))
    #bruteforce(0x1b0582b8ab9dd5074, '10001111', 8, -1, {})
    t_start = time.perf_counter()
    threads = [  # Spawn 16 threads.
        multiprocessing.Process(
                target=bruteforce,
                args=(precompute(f'{tid:04b}'), f'{tid:04b}', 4, tid))
        for tid in range(16)
    ]

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    t_end = time.perf_counter()

    print(f'[+] Bruteforce finished in {t_end-t_start:.2f} seconds')

    # 1011 1110 1110 0110 0110 1111 1000 1111
    # b    e    e    6    6    f    8    f
    return 0xbee66f8f


# ----------------------------------------------------------------------------------------
def crack_stage_3(tbl_12):
    """Cracking this stage is straightforward."""
    print('[+] Crack stage #3: Finding `giant` (without moduli) ...')

    tbl_giant = [
        0x000000001be3b694, 0x000000000ad42f89,
        0x00000001003913b7, 0x0000000037c23eb4,
        0x0000000064c07ef5, 0x000000000d7b4785,
        0x0000000049115944, 0x000000005241f45e,
        0x00000000829722e9, 0x000000006801ca71,
        0x00000000165020cf, 0x00000000e45f7ab1
    ]

    crack_giant = [(t * tbl_12) for t in tbl_giant]
    print('[+] giant (w/o mod):', ', '.join(f'0x{g:016x}' for g in crack_giant))
    return crack_giant


# ----------------------------------------------------------------------------------------
def crack_stage_4(giant):
    """This is the most complicated stage to crack.

    We need to find the modulus for each giant. We bruteforce each modulo just
    like stage 5 crack. Please note that there may be >1 solutions so we don't stop once
    we find a solution. We only want the solutions where mod < 0xbee66f8f (tbl_12).
    """
    print('[+] Crack stage #4: Finding `giant` (with moduli) ...')

    tbl_giant_2 = [    
        0x00000000a2cc3f37, 0x00000000b8b0e2e6,
        0x000000009dea4fd6, 0x00000000897da0d6,
        0x0000000052b660e5, 0x000000007dbcdc09,
        0x00000000588e7836, 0x000000003ea786e5,
        0x000000005bc7bb33, 0x00000000a3959e86,
        0x000000005ab05a2f, 0x00000000b09e4a8c
    ]

    def precompute(mod):
        """Precomputes the `result` for a given `mod` as in stage #4."""
        a, result = 0x56361E32, 1
        old_mod = mod
        for i in range(4):#while old_mod >= 2:
            old_mod = mod
            if (mod & 1) != 0:
                result = result*a - ((result*a * 0x8EF2C4468D568FF5) >> 95) * 0xE53ACEB5
            a = a*a - (a * a * 0x8EF2C4468D568FF5 >> 95) * 0xE53ACEB5
            #print(f'a:{a:016x}, mod:{mod:016x} ~> result:{result:016x}')
            mod >>= 1

        return result, a

    def bruteforce(a, result, mod, depth, trg, tid):
        """Bruteforce on thread `tid` starting from `chksum` (tbl[12] = `bits`)."""
        global count
        count += 1
        if count % 0x1000000 == 0:
            print(f'[+]   Status (t:{trg:08x}): #{count:08x}, a:{a:08x}, r:{result:08x}, m:{mod:32s}, d:{depth}, t:{tid}')
 
        if result == trg:
            print(f'[+]   Solution FOUND (t:{trg:08x}): #{count:08x}, a:{a:08x}, r:{result:08x}, m:{mod:32s}, d:{depth}, t:{tid}')
            print(f'[+]   crack[0x{trg:08x}] = 0x{int(mod, 2):08x}')
            return  # Continue searching; we want all solutions.
        elif depth >= 32:
            return  # We have exceeded max depth.

        # Recursively, try to take (and not take) the number at index `depth`.
        nxt_a = a*a - (a * a * 0x8EF2C4468D568FF5 >> 95) * 0xE53ACEB5
        bruteforce(nxt_a, result, '0' + mod, depth + 1, trg, tid)

        nxt_result = result*a - ((result*a * 0x8EF2C4468D568FF5) >> 95) * 0xE53ACEB5
        bruteforce(nxt_a, nxt_result, '1' + mod, depth + 1, trg, tid)

    #bruteforce(0x56361E32, 1, '', 0, 0xa2cc3f37, 0)

    global count

    for trg in tbl_giant_2:  # ~10 mins for each number.
        print(f'[+] Starting bruteforce for target value: {trg:08x} ...')
        count = 0    
        t_start = time.perf_counter()
        threads = []
        for tid in range(16):  # Spawn 16 threads.
            result, a = precompute(tid)
            threads.append(
                multiprocessing.Process(
                    target=bruteforce,
                    args=(a, result, f'{tid:04b}', 4, trg, tid))
            )

        for t in threads:
            pass
            t.start()

        for t in threads:
            pass
            t.join()

        t_end = time.perf_counter()

        print(f'[+] Bruteforce finished in {t_end-t_start:.2f} seconds')


    # Collect (manually) all results from the bruteforce, into an array.
    mod_crack = [
        0x44476065,
        0xacd4feca,
        0xb14d4f2e,
        0xa33a5e31,
        0xb385631a,
        0x192112d0,
        0x3c07c8e3,
        0x110cf695,
        0x28aab06a,
        0x19c05014,
        0xb88df870,
        0x781aa68a
    ]

    # Add cracked moduli to giant:
    cracked_giant = [g + m for g, m in zip(giant, mod_crack)]
    print('[+] Recovered giant:', ' '.join(f'{g:016x}' for g in cracked_giant))
    
    return cracked_giant


# ----------------------------------------------------------------------------------------
def crack_stage_2(cracked_giant):
    """To crack this stage we need to find the original `tbl` used to create `giant`.

    The goal is to find which 32-bit numbers to multiply to get the target `giant` value.
    
    Don't use z3. It is very slow. Instead use factorization: Find all prime factors of
    the `giant`.
        * If we are lucky there are 2 32-bit prime numbers.
        * If we are not lucky, there are multiply prime factors. We have to select
          which factors go to each number without exceeding 32-bits,
        * If there is a prime factor >32-bits, means we did a mistake and `giant` value 
          is incorrect.
    """
    print('[+] Crack stage #2: Finding `tbl` ...')

    cracked_tbl = [0]*25

    for i in range(6):
        factors = factorint(cracked_giant[i])
        print(f'[+] #{i:2d} factorizing {cracked_giant[i]:016x} ~>', factors)

        assert len(factors) == 2 # Assume value is :1
        
        factors = list(factors.keys())
        cracked_tbl[2*i]     = min(factors)
        cracked_tbl[2*i + 1] = max(factors)

    cracked_tbl[12] = 0xbee66f8f

    for i in range(6):
        factors = factorint(cracked_giant[6 + i])
        print(f'[+] #{i:2d} factorizing {cracked_giant[6+i]:016x} ~>', factors)

        assert len(factors) == 2 # Assume value is :1
        
        factors = list(factors.keys())
        cracked_tbl[25-2 - 2*i]     = max(factors)
        cracked_tbl[25-2 - 2*i + 1] = min(factors)

    print(f'[+] Cracked tbl:'.join(f'{c:08x}' for c in cracked_tbl))
    
    return cracked_tbl 


# ----------------------------------------------------------------------------------------
def crack_stage_1(crack_tbl):
    """All operations are invertible, so inverting this step is straightforward."""
    print('[+] Cracking stage #1 ...')

    new_tbl = [0]*25
    for i, v in enumerate(crack_tbl):
        r = ror(v ^ tbl[i] ^ 0xcafebabe, 0x19)
        for j in range(0x19 + 1):
            r = ror(r ^ 0x14530451, 0x19) 
    
        new_tbl[i] = 0xdeadbeef ^ r
        tbl_ascii = struct.pack('>L', new_tbl[i])
        print(f'[+]     tbl[{i:2d}] = {tbl[i]:08x} ~> {new_tbl[i]:08x}, {tbl_ascii!r}')

    return new_tbl


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Penguin & Crab crack started.')

    # Convert ASCII flag into big-endian DWORDs.
    flag_dwords = [struct.unpack('>L', flag[i*4:i*4 + 4])[0] for i in range(0x19)]
    print('[+] Flag DWORDs:', '-'.join(f'{f:08x}' for f in flag_dwords))

    # ~ = ~ = ~ = ~ = ~ = ~ = ~ = ~ = ~ = ~ 
    # FORWARD ENCRYPTION
    # ~ = ~ = ~ = ~ = ~ = ~ = ~ = ~ = ~ = ~ 
    new_tbl = stage_1(flag_dwords)

    # tbl[12] goes into the middle; 
    # tbl[:12] used for giant[:6] and tbl[13:] used for giant[6:]
    print(f'[+] Middle: tbl[12] = {new_tbl[12]:08x}')

    giant = stage_2(new_tbl)
    stage_3(giant, new_tbl[12])
    stage_4(giant, new_tbl[12])
    stage_5(new_tbl[12])

    # ~ = ~ = ~ = ~ = ~ = ~ = ~ = ~ = ~ = ~ 
    # REVERSED ENCRYPTION (CRACK)
    # ~ = ~ = ~ = ~ = ~ = ~ = ~ = ~ = ~ = ~ 
    print('[+] * = * = * = * = * = RECOVERING FLAG = * = * = * = * = *')

    #tbl_12 = crack_stage_5()
    # Verify as: stage_5(0xbee66f8f)

    tbl_12 = 0xbee66f8f
    cracked_giant_div = crack_stage_3(tbl_12)
    cracked_giant_mod = crack_stage_4(cracked_giant_div)
    cracked_tbl       = crack_stage_2(cracked_giant_mod)

    flag_dwords = crack_stage_1(cracked_tbl)
    flag = b''.join(struct.pack('>L', f) for f in flag_dwords)
    
    print(f"[+] Cracked FLAG: {flag.decode('utf-8')}")
    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
r"""
┌─[17:42:08]─[ispo@ispo-glaptop2]─[~/ctf/hitcon_quals_2024/penguin_and_crab]
└──> time ./penguin_and_crab_crack.py 
[+] Penguin & Crab crack started.
[+] Flag DWORDs: 68697463-6f6e7b3f-3f3f3f3f-3f3f3f3f-3f3f3f3f-3f3f3f3f-3f3f3f3f-3f3f3f3f-3f3f3f3f-3f3f3f3f-3f3f3f3f-3f3f3f3f-3f3f3f3f-3f3f3f3f-3f3f3f3f-3f3f3f3f-3f3f3f3f-3f3f3f3f-3f3f3f3f-3f3f3f3f-3f3f3f3f-3f3f3f3f-3f3f3f3f-3f3f3f3f-3f3f3f7d
[+] Encryption stage #1 ...
[+]     v:68697463, tbl[ 0] = aec4f08c ~> 1726ef35
[+]     v:6f6e7b3f, tbl[ 1] = 642c04ac ~> e5f661f5
[+]     v:3f3f3f3f, tbl[ 2] = a3607854 ~> a0303d0f
[+]     v:3f3f3f3f, tbl[ 3] = 2d393934 ~> 2e697c6f
[+]     v:3f3f3f3f, tbl[ 4] = 8e2c4f5a ~> 8d7c0a01
[+]     v:3f3f3f3f, tbl[ 5] = ddd67d14 ~> de86384f
[+]     v:3f3f3f3f, tbl[ 6] = 7e005496 ~> 7d5011cd
[+]     v:3f3f3f3f, tbl[ 7] = 3ed14a02 ~> 3d810f59
[+]     v:3f3f3f3f, tbl[ 8] = 0a56a772 ~> 0906e229
[+]     v:3f3f3f3f, tbl[ 9] = 466a4076 ~> 453a052d
[+]     v:3f3f3f3f, tbl[10] = d3a352a9 ~> d0f317f2
[+]     v:3f3f3f3f, tbl[11] = 495e93e3 ~> 4a0ed6b8
[+]     v:3f3f3f3f, tbl[12] = 67c44adf ~> 64940f84
[+]     v:3f3f3f3f, tbl[13] = 3aebe5ba ~> 39bba0e1
[+]     v:3f3f3f3f, tbl[14] = ed850da8 ~> eed548f3
[+]     v:3f3f3f3f, tbl[15] = d4b77198 ~> d7e734c3
[+]     v:3f3f3f3f, tbl[16] = 51bdb6b2 ~> 52edf3e9
[+]     v:3f3f3f3f, tbl[17] = 3a5f2448 ~> 390f6113
[+]     v:3f3f3f3f, tbl[18] = 807889ca ~> 8328cc91
[+]     v:3f3f3f3f, tbl[19] = 5b9d4d6e ~> 58cd0835
[+]     v:3f3f3f3f, tbl[20] = 8320efd6 ~> 8070aa8d
[+]     v:3f3f3f3f, tbl[21] = 9e68e874 ~> 9d38ad2f
[+]     v:3f3f3f3f, tbl[22] = ba7fbea1 ~> b92ffbfa
[+]     v:3f3f3f3f, tbl[23] = 827bc7e4 ~> 812b82bf
[+]     v:3f3f3f7d, tbl[24] = 129f824a ~> 11cfc501
[+] Middle: tbl[12] = 64940f84
[+] Encryption stage #2 ...
[+]    giant[ 0] = 14cc1c402ed402b9
[+]    giant[ 1] = 1d0aac9e8fa4bd81
[+]    giant[ 2] = 7afbbeb8e5fd4e4f
[+]    giant[ 3] = 1e1b411a132e3345
[+]    giant[ 4] = 0270e6b302ea8e35
[+]    giant[ 5] = 3c726178a7f981f0
[+]    giant[ 6] = 097e0157c1e58fe8
[+]    giant[ 7] = 736744e5160c48f4
[+]    giant[ 8] = 2eed481d68886bf4
[+]    giant[ 9] = 1d4b0e27fb3d28d0
[+]    giant[10] = 43ebae2e47870bb0
[+]    giant[11] = 36ab0360311b3410
[+] Verification stage #1 (div giant) ...
[+]    DIV giant: 0000000034ef58c1 != 000000001be3b694 (expected)
[+]    DIV giant: 0000000049eb5229 != 000000000ad42f89 (expected)
[+]    DIV giant: 000000013906eae2 != 00000001003913b7 (expected)
[+]    DIV giant: 000000004ca11cf6 != 0000000037c23eb4 (expected)
[+]    DIV giant: 0000000006368c41 != 0000000064c07ef5 (expected)
[+]    DIV giant: 0000000099da9e19 != 000000000d7b4785 (expected)
[+]    DIV giant: 0000000018290aa0 != 0000000049115944 (expected)
[+]    DIV giant: 0000000125bbdd65 != 000000005241f45e (expected)
[+]    DIV giant: 0000000077712792 != 00000000829722e9 (expected)
[+]    DIV giant: 000000004a8f3045 != 000000006801ca71 (expected)
[+]    DIV giant: 00000000ace07fc7 != 00000000165020cf (expected)
[+]    DIV giant: 000000008b2536db != 00000000e45f7ab1 (expected)
[+] Verification stage #2 (mod giant) ...
[+]    MOD giant: 00000000513dbf7b != 00000000a2cc3f37 (expected)
[+]    MOD giant: 0000000022613f2b != 00000000b8b0e2e6 (expected)
[+]    MOD giant: 00000000451f3167 != 000000009dea4fd6 (expected)
[+]    MOD giant: 0000000025193c1b != 00000000897da0d6 (expected)
[+]    MOD giant: 000000003eac1dbf != 0000000052b660e5 (expected)
[+]    MOD giant: 000000001f223312 != 000000007dbcdc09 (expected)
[+]    MOD giant: 00000000cbfd5cbe != 00000000588e7836 (expected)
[+]    MOD giant: 00000000bf77b60d != 000000003ea786e5 (expected)
[+]    MOD giant: 00000000d49f3c16 != 000000005bc7bb33 (expected)
[+]    MOD giant: 00000000c8cc7a14 != 00000000a3959e86 (expected)
[+]    MOD giant: 00000000bc7e3f7d != 000000005ab05a2f (expected)
[+]    MOD giant: 000000000eeda496 != 00000000b09e4a8c (expected)
[+] Verification stage #3 (tbl[12]) ...
[+]    tbl[12] = 64940f84 = 0b1100100100101000000111110000100
[+]    Use fin_tbl[ 2] ~> 7730e544811b003b
[+]    Use fin_tbl[ 7] ~> 5129602cebb27cd3
[+]    Use fin_tbl[ 8] ~> 8d3e0ddb822d166c
[+]    Use fin_tbl[ 9] ~> 7743085c81b563ca
[+]    Use fin_tbl[10] ~> 1fd73d5b1682bec1
[+]    Use fin_tbl[11] ~> 49ca0c91d932e680
[+]    Use fin_tbl[18] ~> 26190529fd5f0437
[+]    Use fin_tbl[20] ~> 22e8f33e31870d59
[+]    Use fin_tbl[23] ~> 591cea928108d643
[+]    Use fin_tbl[26] ~> 48009c01b6dc47ba
[+]    Use fin_tbl[29] ~> 000154d52272bf8f
[+]    Use fin_tbl[30] ~> 7e416b359a0655cc
[+] Final    checksum: 39edee49d83a9e16d
[+] Expected checksum: 6b3312ec731522288
[+] * = * = * = * = * = RECOVERING FLAG = * = * = * = * = *
[+] Crack stage #3: Finding `giant` (without moduli) ...
[+] giant (w/o mod): 0x14cc1c3f315528ac, 0x08133aa27038f487, 0xbf10ff9167d85c39, 0x29945b5a4c69128c, 0x4b218f13a4b125db, 0x0a0da1b6f35d9e4b, 0x367ca5ae017d58fc, 0x3d56fe77dc404282, 0x6161b89ac5e58727, 0x4d8ef32e9f4d141f, 0x10a38e1050f614a1, 0xaa4c6e5c908e47df
[+] Crack stage #4: Finding `giant` (with moduli) ...
[+] Starting bruteforce for target value: a2cc3f37 ...
[+]   Status (t:a2cc3f37): #01000000, a:65c7ea0a, r:0a301b7e, m:00111111111111111111111000000111, d:32, t:7
[+]   Status (t:a2cc3f37): #01000000, a:65c7ea0a, r:7aa0e085, m:00111111111111111111111000001111, d:32, t:15
[+]   Status (t:a2cc3f37): #01000000, a:65c7ea0a, r:25d7bce5, m:00111111111111111111111000001011, d:32, t:11
......
[+]   Status (t:a2cc3f37): #0c000000, a:65c7ea0a, r:b08776e6, m:01111111111111111111111110101000, d:32, t:8
[+]   Status (t:a2cc3f37): #0c000000, a:65c7ea0a, r:69283c86, m:01111111111111111111111110100001, d:32, t:1
[+]   Status (t:a2cc3f37): #0c000000, a:65c7ea0a, r:870956a2, m:01111111111111111111111110101010, d:32, t:10
[+]   Solution FOUND (t:a2cc3f37): #0c0dc456, a:0daab7a4, r:a2cc3f37, m:1000100010001110110000001100101 , d:31, t:5
[+]   crack[0xa2cc3f37] = 0x44476065
[+]   Status (t:a2cc3f37): #0c000000, a:65c7ea0a, r:bf466dc7, m:01111111111111111111111110100100, d:32, t:4
[+]   Status (t:a2cc3f37): #0c000000, a:65c7ea0a, r:2108f398, m:01111111111111111111111110100011, d:32, t:3
......
[+]   Status (t:a2cc3f37): #1f000000, a:65c7ea0a, r:70d5e31f, m:11111111111111111111111011110100, d:32, t:4
[+]   Status (t:a2cc3f37): #1f000000, a:65c7ea0a, r:d4af69be, m:11111111111111111111111011111001, d:32, t:9
[+] Bruteforce finished in 805.11 seconds
[+] Starting bruteforce for target value: b8b0e2e6 ...
[+]   Status (t:b8b0e2e6): #01000000, a:65c7ea0a, r:0a301b7e, m:00111111111111111111111000000111, d:32, t:7
[+]   Status (t:b8b0e2e6): #01000000, a:65c7ea0a, r:8c257738, m:00111111111111111111111000001010, d:32, t:10
......
[+]   Status (t:b8b0e2e6): #07000000, a:0daab7a4, r:aa05a03d, m:1111111111111111111111011000101 , d:31, t:5
[+]   Status (t:b8b0e2e6): #07000000, a:0daab7a4, r:b8c37390, m:1111111111111111111111011001110 , d:31, t:14
[+]   Solution FOUND (t:b8b0e2e6): #06fe5676, a:65c7ea0a, r:b8b0e2e6, m:10101100110101001111111011001010, d:32, t:10
[+]   crack[0xb8b0e2e6] = 0xacd4feca
[+]   Status (t:b8b0e2e6): #07000000, a:0daab7a4, r:d6a88ba1, m:1111111111111111111111011000100 , d:31, t:4
[+]   Status (t:b8b0e2e6): #07000000, a:0daab7a4, r:c59a0438, m:1111111111111111111111011001011 , d:31, t:11
......
[+]   Status (t:9dea4fd6): #0a000000, a:0daab7a4, r:7efec1f9, m:1111111111111111111111100101100 , d:31, t:12
[+]   Status (t:9dea4fd6): #0a000000, a:0daab7a4, r:6fe1459c, m:1111111111111111111111100100101 , d:31, t:5
[+]   Solution FOUND (t:9dea4fd6): #09e56529, a:65c7ea0a, r:9dea4fd6, m:10110001010011010100111100101110, d:32, t:14
[+]   crack[0x9dea4fd6] = 0xb14d4f2e
[+]   Status (t:9dea4fd6): #0a000000, a:0daab7a4, r:91e43ebd, m:1111111111111111111111100101001 , d:31, t:9
[+]   Status (t:9dea4fd6): #0a000000, a:0daab7a4, r:e4cbf780, m:1111111111111111111111100100010 , d:31, t:2
......
[+] Recovered giant: 14cc1c3f759c8911 08133aa31d0df351 bf10ff921925ab67 29945b5aefa370bd 4b218f14583688f5 0a0da1b70c7eb11b 367ca5ae3d8521df 3d56fe77ed4d3917 6161b89aee903791 4d8ef32eb90d6433 10a38e1109840d11 aa4c6e5d08a8ee69
[+] Crack stage #2: Finding `tbl` ...
[+] # 0 factorizing 14cc1c3f759c8911 ~> {3858129389: 1, 388427573: 1}
[+] # 1 factorizing 08133aa31d0df351 ~> {443180917: 1, 1312947437: 1}
[+] # 2 factorizing bf10ff921925ab67 ~> {3959712277: 1, 3476966027: 1}
[+] # 3 factorizing 29945b5aefa370bd ~> {800768327: 1, 3741556699: 1}
[+] # 4 factorizing 4b218f14583688f5 ~> {4248325439: 1, 1274329291: 1}
[+] # 5 factorizing 0a0da1b70c7eb11b ~> {446181257: 1, 1623584387: 1}
[+] # 0 factorizing 367ca5ae3d8521df ~> {1247792387: 1, 3146513141: 1}
[+] # 1 factorizing 3d56fe77ed4d3917 ~> {2674966199: 1, 1652357281: 1}
[+] # 2 factorizing 6161b89aee903791 ~> {3663563383: 1, 1915373623: 1}
[+] # 3 factorizing 4d8ef32eb90d6433 ~> {1777878643: 1, 3143449409: 1}
[+] # 4 factorizing 10a38e1109840d11 ~> {279804379: 1, 4284987011: 1}
[+] # 5 factorizing aa4c6e5d08a8ee69 ~> {3029283473: 1, 4050893401: 1}
1726ef35[+] Cracked tbl:e5f661ed[+] Cracked tbl:1a6a6775[+] Cracked tbl:4e41fced[+] Cracked tbl:cf3e4a8b[+] Cracked tbl:ec046a15[+] Cracked tbl:2fbac147[+] Cracked tbl:df039fdb[+] Cracked tbl:4bf4b8cb[+] Cracked tbl:fd384d3f[+] Cracked tbl:1a982f89[+] Cracked tbl:60c5ee83[+] Cracked tbl:bee66f8f[+] Cracked tbl:f173ba59[+] Cracked tbl:b48f3291[+] Cracked tbl:ff67b683[+] Cracked tbl:10ad79db[+] Cracked tbl:bb5d3b41[+] Cracked tbl:69f84673[+] Cracked tbl:da5d8a77[+] Cracked tbl:722a4837[+] Cracked tbl:9f70beb7[+] Cracked tbl:627cf8a1[+] Cracked tbl:bb8bfaf5[+] Cracked tbl:4a5fcd03
[+] Cracking stage #1 ...
[+]     tbl[ 0] = aec4f08c ~> 68697463, b'hitc'
[+]     tbl[ 1] = 642c04ac ~> 6f6e7b3c, b'on{<'
[+]     tbl[ 2] = a3607854 ~> 68747470, b'http'
[+]     tbl[ 3] = 2d393934 ~> 733a2f2f, b's://'
[+]     tbl[ 4] = 8e2c4f5a ~> 7777772e, b'www.'
[+]     tbl[ 5] = ddd67d14 ~> 796f7574, b'yout'
[+]     tbl[ 6] = 7e005496 ~> 7562652e, b'ube.'
[+]     tbl[ 7] = 3ed14a02 ~> 636f6d2f, b'com/'
[+]     tbl[ 8] = 0a56a772 ~> 77617463, b'watc'
[+]     tbl[ 9] = 466a4076 ~> 683f763d, b'h?v='
[+]     tbl[10] = d3a352a9 ~> 46725830, b'FrX0'
[+]     tbl[11] = 495e93e3 ~> 5a665838, b'ZfX8'
[+]     tbl[12] = 67c44adf ~> 4471733e, b'Dqs>'
[+]     tbl[13] = 3aebe5ba ~> 26263c68, b'&&<h'
[+]     tbl[14] = ed850da8 ~> 74747073, b'ttps'
[+]     tbl[15] = d4b77198 ~> 3a2f2f77, b'://w'
[+]     tbl[16] = 51bdb6b2 ~> 77772e79, b'ww.y'
[+]     tbl[17] = 3a5f2448 ~> 6f757475, b'outu'
[+]     tbl[18] = 807889ca ~> 62652e63, b'be.c'
[+]     tbl[19] = 5b9d4d6e ~> 6f6d2f77, b'om/w'
[+]     tbl[20] = 8320efd6 ~> 61746368, b'atch'
[+]     tbl[21] = 9e68e874 ~> 3f763d4c, b'?v=L'
[+]     tbl[22] = ba7fbea1 ~> 44555f54, b'DU_T'
[+]     tbl[23] = 827bc7e4 ~> 786b3036, b'xk06'
[+]     tbl[24] = 129f824a ~> 744d3e7d, b'tM>}'
[+] Cracked FLAG: hitcon{<https://www.youtube.com/watch?v=FrX0ZfX8Dqs>&&<https://www.youtube.com/watch?v=LDU_Txk06tM>}
[+] Program finished. Bye bye :)
"""
# ----------------------------------------------------------------------------------------

