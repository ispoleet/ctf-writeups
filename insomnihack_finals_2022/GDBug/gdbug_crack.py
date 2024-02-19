#!/usr/bin/env python3
# ---------------------------------------------------------------------------------------
charset = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789'
serial = '....-....-....-....-....'
target_sum = 2872-1337 - 0x2D*4

# ---------------------------------------------------------------------------------------
def recursion(serial, target_sum):
    if len(serial) > 24-4: return
    elif target_sum < 0: return
    elif target_sum == 0:
        insert_into = lambda s, l, c: s[:l] + c + s[l:]
        # Insert dashes into serial
        serial = insert_into(serial, 4, '-')
        serial = insert_into(serial, 9, '-')
        serial = insert_into(serial, 14, '-')
        serial = insert_into(serial, 19, '-')

        print(f'[+] Serial Found: {serial}')

    for c in charset:
        recursion(serial + c, target_sum - ord(c))

# ---------------------------------------------------------------------------------------
if __name__ == "__main__":
	recursion('', target_sum)

# ---------------------------------------------------------------------------------------
'''
ispo@leet:~/ctf/insomnihack_2022/GDBug$ ./gdbug_crack.py 
[+] Serial Found: AAAA-AAAA-AAAA-AAAA-AFZZ
[+] Serial Found: AAAA-AAAA-AAAA-AAAA-AGYZ
[+] Serial Found: AAAA-AAAA-AAAA-AAAA-AGZY
[+] Serial Found: AAAA-AAAA-AAAA-AAAA-AHXZ
[+] Serial Found: AAAA-AAAA-AAAA-AAAA-AHYY
[+] Serial Found: AAAA-AAAA-AAAA-AAAA-AHZX
[+] Serial Found: AAAA-AAAA-AAAA-AAAA-AJVZ
[+] Serial Found: AAAA-AAAA-AAAA-AAAA-AJWY
[+] Serial Found: AAAA-AAAA-AAAA-AAAA-AJXX
[+] Serial Found: AAAA-AAAA-AAAA-AAAA-AJYW
[+] Serial Found: AAAA-AAAA-AAAA-AAAA-AJZV
....

ispo@leet:~/ctf/insomnihack_2022/GDBug$ ./GDBug-fbb8d09b0f1d6a107327b6cfff2a63f19d398a7acba4efae26d56dcfe3c1ac4f AAAA-AAAA-AAAA-AAAA-AFZZ

      _/_/_/  _/_/_/    _/_/_/
   _/        _/    _/  _/    _/  _/    _/    _/_/_/
  _/  _/_/  _/    _/  _/_/_/    _/    _/  _/    _/
 _/    _/  _/    _/  _/    _/  _/    _/  _/    _/
  _/_/_/  _/_/_/    _/_/_/      _/_/_/    _/_/_/
                                             _/
                                        _/_/

[+] Checking serial AAAA-AAAA-AAAA-AAAA-AFZZ
   [-] Registration successful
   [-] Your flag is INS{AAAA-AAAA-AAAA-AAAA-AFZZ}
'''
# ---------------------------------------------------------------------------------------    
