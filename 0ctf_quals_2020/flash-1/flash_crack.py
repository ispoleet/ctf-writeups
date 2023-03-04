#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# 0CTF 2019 - J (RE 297)
# ----------------------------------------------------------------------------------------
from Crypto.Util import number

# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] flash crack started.')

    # The equation is: (flagN * 0x11) % 0xB248 == 0x72A9
    # Or:              17*flagN == 0x72A9 mod 0xB248
    #
    # To get the flagN: Find 17^-1 mod 0xB248 = 0x4969
    # Then: 17*flagN == 0x72A9 mod 0xB248 =>
    #       flagN == 0x72A9 * 17^-1 mod 0xB248 =>
    #       flagN == 0x72A9 * 0x4969 mod 0xB248 =>
    #       flagN = 0x6521 = '!e'
    inv = number.inverse(0x11, 0xB248)
    print(f'[+] Calculating 17^-1 mod 0xB248: 0x{inv:04X}')

    flag = ''
    for i, trg in enumerate([0x72A9,
                             0x097E,
                             0x5560,
                             0x4CA1,
                             0x0037,
                             0xAA71,
                             0x122C,
                             0x4536,
                             0x11E8,
                             0x1247,
                             0x76C7,
                             0x096D,
                             0x122C,
                             0x87CB,
                             0x09E4]):
        fl = (trg * inv) % 0xB248    
        s = chr(fl >> 8) + chr(fl & 0xFF)
        flag = s + flag
        print(f'[+] Recovering flag[{28-i*2}:{28-i*2 + 2}]: {fl:04X}h ~> {s}')
    
    print(f'[+] Final flag: flag{{{flag}}}')
    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop2:~/ctf/0ctf_2020/flash-1$ ./flash_crack.py 
[+] flash crack started.
[+] Calculating 17^-1 mod 0xB248: 0x4969
[+] Recovering flag[28:30]: 6521h ~> e!
[+] Recovering flag[26:28]: 696Eh ~> in
[+] Recovering flag[24:26]: 6368h ~> ch
[+] Recovering flag[22:24]: 6D61h ~> ma
[+] Recovering flag[20:22]: 735Fh ~> s_
[+] Recovering flag[18:20]: 6869h ~> hi
[+] Recovering flag[16:18]: 5F74h ~> _t
[+] Recovering flag[14:16]: 776Eh ~> wn
[+] Recovering flag[12:14]: 5F70h ~> _p
[+] Recovering flag[10:12]: 746Fh ~> to
[+] Recovering flag[8:10]: 655Fh ~> e_
[+] Recovering flag[6:8]: 696Dh ~> im
[+] Recovering flag[4:6]: 5F74h ~> _t
[+] Recovering flag[2:4]: 2773h ~> 's
[+] Recovering flag[0:2]: 6974h ~> it
[+] Final flag: flag{it's_time_to_pwn_this_machine!}
[+] Program finished. Bye bye :)
'''
# ----------------------------------------------------------------------------------------