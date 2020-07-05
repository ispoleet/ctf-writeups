#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# 0CTF 2020 - Happy Tree (RE 407)
# ----------------------------------------------------------------------------------------
import sys
import struct


# The target values that we want to match.
# (Using vim we can easily move form the code into this form; Visual Block mode + Join). 
target_codes = [
    "1 *2 *2 *2 *5 +1 *2 *2 *5 +1 *2 *2 *5 +1 *2 *2 *2 *2 *2 +1 *2 +1 *2 *2 *3 *3 *3 *3 +1 *2 *2 +1 *2",
    "1 *2 *3 *3 +1 *2 *5 +1 *2 *3 *5 +1 *2 *3 *3 +1 *2 *3 *3 *3 +1 *2",
    "1 *2 *5 +1 *2 +1 *2 *2 *3 +1 *2 *2 +1 *2 *2 *2 *5 *5 *5 *5 +1 *2 *2 *3 *5 *5 +1 *2",
    "1 *2 *5 +1 *2 +1 *2 *2 *2 *3 *3 +1 *2 *2 *2 *2 *2 *5 +1 *2 +1 *2 +1 *2 *3 +1 *2 *2 +1 *2 *2 *3 *3",
    "1 *2 *2 *3 +1 *2 *2 *3 *5 +1 *2 *5 +1 *2 *3 +1 *2 *3 +1 *2 *3 +1 *2 *5 +1 *2 +1 *2 *2 *5 +1 *2 *3 +1",
    "1 *2 *3 +1 *2 *2 *2 *2 +1 *2 +1 *2 *2 *2 *2 *2 *3 +1 *2 *2 +1 *2 *2 *2 *3 +1 *2 *2 +1 *2 *3 +1 *2 *2 +1 *3 *3",
    "1 *2 *3 *3 +1 *2 *2 *2 *5 +1 *2 *2 *2 +1 *2 +1 *2 *2 *3 *3 *3 *3 +1 *2 *3 +1 *2 *3 +1 *3",
    "1 *2 *3 +1 *2 *3 +1 *2 *2 *2 *5 +1 *2 +1 *2 *3 *5 +1 *2 *3 +1 *2 *2 +1 *2 +1 *2 *2 *3 *5 +1 *2 *2 *3 +1",
    "1 *2 *5 +1 *2 *2 *2 *3 *3 *3 +1 *2 *2 +1 *2 *2 *2 *2 *2 *2 *2 *2 *3 *3 *5 +1 *3 *3 *3"
]

# Keys to XOR flag before encryption.
xor_keys = [
    "0",
    "1 *2 *3 +1 *2 *3 +1 *2 *5 +1 *2 +1 *2 *3 *3 *3 +1 *2 *2 +1 *2 +1 *2 *2 *2 *2 *3 +1 *2 *2 *2 *2 +1 *2 *5",
    "0",
    "1 *2 *3 +1 *2 *3 +1 *2 *5 +1 *2 +1 *2 *3 *3 *3 +1 *2 *2 +1 *2 +1 *2 *2 *2 *2 *3 +1 *2 *2 *2 *2 +1 *2 *5",
    "0",
    "1 *2 *3 +1 *2 *3 +1 *2 *5 +1 *2 +1 *2 *3 *3 *3 +1 *2 *2 +1 *2 +1 *2 *2 *2 *2 *3 +1 *2 *2 *2 *2 +1 *2 *5",
    "0",
    "1 *2 *3 +1 *2 *3 +1 *2 *5 +1 *2 +1 *2 *3 *3 *3 +1 *2 *2 +1 *2 +1 *2 *2 *2 *2 *3 +1 *2 *2 *2 *2 +1 *2 *5",
    "0"
]


# ----------------------------------------------------------------------------------------
# Evaluate a long arithmetic expression (don't take into account operator priority).
def eval_expr(s):
    expr = s.split()
    num = int(expr[0])
    for n in expr[1:]:
        num = eval('num %s' % n)
    return num


# ----------------------------------------------------------------------------------------
# Crack a DWORD (4 bytes) from the flag.
#
# The original encryption algorithm is the following:
#    buf_1 = flag[i:i+4]
#    for i in range(100000):
#        a = (buf_1 ^ (buf_1 << 13)) 
#        b = a ^ (a >> 17)
#        buf_1 = b ^ (b << 5)
#
#    return buf_1 
#
def crack_dword(buf_i):
    for i in range(100000):
        # Recover b
        chunk = buf_i & 0x1F
        b = chunk 
        for pos in range(5, 31, 5):
            chunk = ((buf_i ^ (chunk << pos)) >> pos) & 0x1F
            b |= chunk << pos

        b &= 0xFFFFFFFF

        # Recover a
        a = b ^ (b >> 17) 

        # Recover buf_i-1
        chunk = a & 0x1FFF
        buf_i = chunk 
        for pos in range(13, 31, 13):
            chunk = ((a ^ (chunk << pos)) >> pos) & 0x1FFF
            buf_i |= chunk << pos

        buf_i &= 0xFFFFFFFF


    return buf_i


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Happy Tree crack started.')

    flag = ''

    for i in range(9):        
        target = eval_expr(target_codes[i])
        key = eval_expr(xor_keys[i])

        decr = crack_dword(target)
        decr ^= key

        flag += (chr(decr & 0xFF) + chr((decr >> 8) & 0xFF) +
                 chr((decr >> 16) & 0xFF) + chr((decr >> 24) & 0xFF))

        print('Iteration %d. Recovered flag: %s' % (i, flag))


# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop:~/ctf/0ctf/happy_tree/happy_tree$ ./CRACK.py 
[+] Happy Tree crack started.
Iteration 0. Recovered flag: flag
Iteration 1. Recovered flag: flag{HEY
Iteration 2. Recovered flag: flag{HEY!Lum
Iteration 3. Recovered flag: flag{HEY!Lumpy!!
Iteration 4. Recovered flag: flag{HEY!Lumpy!!W@tc
Iteration 5. Recovered flag: flag{HEY!Lumpy!!W@tcH_0u
Iteration 6. Recovered flag: flag{HEY!Lumpy!!W@tcH_0ut_My
Iteration 7. Recovered flag: flag{HEY!Lumpy!!W@tcH_0ut_My_TrE
Iteration 8. Recovered flag: flag{HEY!Lumpy!!W@tcH_0ut_My_TrEe!!}
'''
# ----------------------------------------------------------------------------------------

