#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# HITCON CTF 2025 - Sharing is Caring (Reversing, Crypto 248)
# ----------------------------------------------------------------------------------------
DSA_p = 4144803293417776131310451317495228706499130241044716671850484110288180082374299088166459295448719  # func_1(0)
DSA_q = 2072401646708888065655225658747614353249565120522358335925242055144090041187149544083229647724359  # func_1(1)
DSA_g = 1402769202505631727601810730581776197716350949074282314174097681867464170562021714349605843278664  # func_1(2)
DSA_y = 1335174568503939352563889373190143608146136792487939183543780907770759908268721571509488188235873  # func_1(3)

# 3 known points that reconstruct the shared secret
mix_pairs = [
    (51966, 480442839669953990717445646260333383833736214883976558477525831992994289143305421629761482429714),
    (47806, 253717457675323180603201716971045682091261518437666533915787790782521696917056900361404824269689),
    (201527, 782319055923618868639890136618720319997476308047895888006842867173403800015590219030945524995543)
]


# ----------------------------------------------------------------------------------------
def f_ext_gcd(arg1, arg2):
    """This is extended GCD (non-recursive version)."""
    a, b = (1, 0)  # (func_1(17), func_1(18))
    r, prev_r = (arg1 % arg2, arg2)  # That looks like GCD!

    while r > 1:  # func_1(17) is 1
        quotient = prev_r // r
        x = b - a * quotient
        y = prev_r - r * quotient
        a, r, b, prev_r = (x, y, a, r)

    return a % arg2  # g


# ----------------------------------------------------------------------------------------
def find_y_coord(x): 
    """Finds the y coordinate on an already shared secret curve."""
    # (Almost) the same with SSS.
    w = 0
    for i, (h_i, u1_i) in enumerate(mix_pairs):
        t, v = (1, 1)
        for j, (h_j, u1_j) in enumerate(mix_pairs):
            if i == j:
                continue

            # Instead of computing the y-coordinate at x = 0, compute it at x = `x`.
            t = (t * (x   - h_j)) % DSA_q            
            v = (v * (h_i - h_j)) % DSA_q

        u = (t * f_ext_gcd(v, DSA_q)) % DSA_q
        w = (w + u1_i * u) % DSA_q

    # `w` now contains the y-coordinate of the shared secret.
    return w


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Sharing is caring crack started.')

    flag = ''
    for x in [4919, 57005, 48879]: # func_1(22), func_1(24), func_1(26)
        y = find_y_coord(x)
        f = y.to_bytes(40, 'little')[::-1]
        print(f'[+] y coordinate for x = {x:5}: {f}')
        flag += f.decode('utf8')

    print(f'[+] Flag: {flag}')

    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
"""
┌─[22:18:20]─[ispo@ispo-glaptop2]─[~/ctf/hitcon_quals_2025/Sharing_is_caring]
└──> ./sharing_is_caring_crack.py 
[+] Sharing is caring crack started.
[+] y coordinate for x =  4919: b'hitcon{Like_I_said_....._sharing_is_cari'
[+] y coordinate for x = 57005: b'ng_and_caring_is_finding_the_right_share'
[+] y coordinate for x = 48879: b'_4f63bf95789178799874ddf1c1bd6ad6b6297b}'
[+] Flag: hitcon{Like_I_said_....._sharing_is_caring_and_caring_is_finding_the_right_share_4f63bf95789178799874ddf1c1bd6ad6b6297b}
[+] Program finished. Bye bye :)
"""
# ----------------------------------------------------------------------------------------
