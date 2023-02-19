#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Insomni'Hack Teaser 2022 - License (RE 200)
# ----------------------------------------------------------------------------------------
import z3
import hashlib


# ----------------------------------------------------------------------------------------
def crack_thread_1():
    A = b'rev_insomnihack'
    B = b'\x3B\x2B\x25\x24\x2F\x1C\x40\x5C\x32\x2C\x5D\x0B\x2A\x27\x5B'
    C = ''.join(chr(a ^ b) for a, b in zip(A, B))

    # 'INS{Fr33_B4cKD0'
    return C


# ----------------------------------------------------------------------------------------
def crack_thread_2():
    smt = z3.Solver()

    a2 = [z3.BitVec('a%d' % i, 16) for i in range(15)]

    # Limit each variable to 16 bits
    for c in a2:
        smt.add( z3.And(c >= 0x20, c <= 0x7e) )

    smt.add(a2[7] - a2[8] == -2)
    smt.add(a2[8] + a2[0] + a2[10] == 264)
    smt.add(a2[5] == a2[13] + a2[4] - 89)
    smt.add(a2[12] == 95)
    smt.add(a2[12] - a2[0] == 47)
    smt.add(a2[4] == a2[1] - 19)
    smt.add(a2[14] - a2[13] - a2[2] == -28)
    smt.add(a2[0] + a2[7] + a2[8] == 248)
    smt.add(a2[8] - a2[11] + a2[0] == 48)
    smt.add(a2[3] - a2[14] == -11)
    smt.add(a2[12] + a2[6] - a2[8] == 99)
    smt.add(a2[9] - a2[4] == 15)
    smt.add(a2[6] + a2[12] - a2[0] == a2[1] + 38)
    smt.add(a2[2] == a2[9] + 54 - a2[4])
    smt.add(a2[2] == a2[9] - 41)
    smt.add(a2[9] + a2[0] + a2[0] + a2[5] == a2[10] + 167)

    if smt.check() == z3.sat:
        mdl = smt.model()
        flag = ''
        for i in range(15):
            c = mdl.evaluate(a2[i]).as_long()
            flag += chr(c)
        
        return flag
    else:
        raise Exception('No solution found :(')


# ----------------------------------------------------------------------------------------
def crack_thread_3():
    """ """
    hashes = [
        "06576556d1ad802f247cad11ae748be47b70cd9c",
        "e54a31693bcb9bf00ca2a26e0801404d14e68ddd",
        "7b52c1a1d67b94c7b4ad50b7227a8e67b66ed9e3",
        "728e22de533a58061655153156913c2d85c274d8",
        "a948b24c8ba4ae4f14b529b599601fd53a155994",
        "dfbf2d46353217af0a8a9031f974e9e29a4bfc56",
        "c1e2c5e19ad30a96baad6e2bb388923b430ad2cc",
        "b03da51041b519b7c12da6cc968bf1bc26de307c",
        "31c39beef6fa5a85ea07f89cfec704d947fcca48",
        "9c1e321a441214916556ad0cafa8953d786cb751",
        "908da3be8224819759a1397a309fc581fd806a0a",
        "4b3e25f59ed48b0c3330f0c3dbf740681c2c5010",
        "25321fea120a49aca98d9ebc835cc5247b1ffed3",
        "4a5e95179649555542ce2bc16b8c93ad84928afa",
        "a048299abe57311eacc14f1f3b4cdbfaf481f688",
    ]

    flag = ''
    for next_hash in hashes:
        for a in range(0x21, 0x7f):  # brute force next character.
            pt = flag + chr(a) 
            digest = hashlib.sha1(pt.encode('utf-8')).hexdigest()

            if digest == next_hash: 
                print(f'[+]     Character FOUND: {pt} ~> {flag}')
                flag += chr(a)
                break 

    return flag


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print("[+] Insomni'Hack Teaser CTF 2022 license crack started.")

    flag1 = crack_thread_1()
    print(f'[+] Cracked flag, part #1: {flag1}')

    flag2 = crack_thread_2()
    print(f'[+] Cracked flag, part #2: {flag2}')

    flag3 = crack_thread_3()
    print(f'[+] Cracked flag, part #3: {flag3}')

    flag = flag1 + flag2 + flag3
    print(f'[+] Final flag:', flag)
    

    # anakin:AAAABBBCCCCDDD}
    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop2:~/ctf/insomnihack_2022/License$ ./license_crack.py
[+] Insomni'Hack Teaser CTF 2022 license crack started.
[+] Cracked flag, part #1: INS{Fr33_B4cKD0
[+] Cracked flag, part #2: 0rEd_License_Fo
[+]     Character FOUND: R ~>
[+]     Character FOUND: R_ ~> R
[+]     Character FOUND: R_3 ~> R_
[+]     Character FOUND: R_3v ~> R_3
[+]     Character FOUND: R_3vE ~> R_3v
[+]     Character FOUND: R_3vEr ~> R_3vE
[+]     Character FOUND: R_3vEry ~> R_3vEr
[+]     Character FOUND: R_3vEry0 ~> R_3vEry
[+]     Character FOUND: R_3vEry0n ~> R_3vEry0
[+]     Character FOUND: R_3vEry0ne ~> R_3vEry0n
[+]     Character FOUND: R_3vEry0ne_ ~> R_3vEry0ne
[+]     Character FOUND: R_3vEry0ne_F ~> R_3vEry0ne_
[+]     Character FOUND: R_3vEry0ne_FF ~> R_3vEry0ne_F
[+]     Character FOUND: R_3vEry0ne_FFS ~> R_3vEry0ne_FF
[+]     Character FOUND: R_3vEry0ne_FFS} ~> R_3vEry0ne_FFS
[+] Cracked flag, part #3: R_3vEry0ne_FFS}
[+] Final flag: INS{Fr33_B4cKD00rEd_License_FoR_3vEry0ne_FFS}
[+] Program finished. Bye bye :)
'''
# ----------------------------------------------------------------------------------------

