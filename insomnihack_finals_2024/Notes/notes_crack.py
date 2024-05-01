#!/usr/bin/env python3
# ---------------------------------------------------------------------------------------
import base64
import hashlib
from Crypto.Cipher import AES


# ---------------------------------------------------------------------------------------
def decrypt(key):
    ciphertext = base64.b64decode('uS0D11dq3RM9QimRWfXcewwQdoxYwrZRNUGT205pDfQ=')

    assert (len(key) == 32)
    decryptor = AES.new(key=key, mode=AES.MODE_ECB)

    for i in range(313370):
        ciphertext = decryptor.decrypt(ciphertext)

    decryptor = AES.new(key=key, mode=AES.MODE_ECB)
    ciphertext = decryptor.decrypt(ciphertext)
    return ciphertext


# ---------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Notes crack started.')

    crackdict = open('rockyou.txt', 'rb').readlines()
    print('[+] rockyou.txt (first 10):', ', '.join(
        crackdict[i].strip().decode('utf-8') for i in range(10)))

    print('[+] rockyou.txt total passwords:', len(crackdict))

    for i, passphrase in enumerate(crackdict):
        passphrase = passphrase.strip()

        if len(passphrase) != 32:
            continue

        # 1st approach (wrong)
        #passphrase = hashlib.md5(passphrase).hexdigest().upper().encode('utf-8')
        #print(passphrase)

        plain = decrypt(passphrase)
        if b'FLAG1' in plain or b'INS{' in plain:
            print('[+] Passphrase FOUND:', passphrase)
            print('[+] Flag:', plain)
            break

    print('[+] Program finished. Bye bye :)')

# ---------------------------------------------------------------------------------------
'''
┌─[11:54:09]─[ispo@ispo-glaptop2]─[~/ctf/insomnihack_finals_2024/Notes]
└──> time ./notes_crack.py 
[+] Notes crack started.
[+] rockyou.txt (first 10): 123456, 12345, 123456789, password, iloveyou, princess, 1234567, rockyou, 12345678, abc123
[+] rockyou.txt total passwords: 14344391
[+] Passphrase FOUND: b'letsyouupdateyourfunNotesandmore'
[+] Flag: b'INS{H4PPY_H4CK1N6}\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e'
[+] Program finished. Bye bye :)

real    0m56.015s
user    0m55.815s
sys 0m0.197s
'''
# ---------------------------------------------------------------------------------------

