#!/usr/bin/env python3
# ---------------------------------------------------------------------------------------
import base64


# ---------------------------------------------------------------------------------------
def encrypt_example(password):
    assert(len(password) % 4 == 0)

    print(f'[+] Encryption example for: {password}')

    pw_arr = [0]*(len(password)*3 // 4)
    k = 0;

    for i in range(0, len(password), 4):
        sub_arr = [
            "ABCDEFINS_+*!{}0123456789abcdefghijklmnopqrstuvwxyz".index(password[i + j])
            for j in range(4)
        ]
            
        print(f'[+] Substitution array for index {k}: {sub_arr}')

        pw_arr[k]     = (sub_arr[0] << 2) | (sub_arr[1] >> 4 & 3)
        pw_arr[k + 1] = (sub_arr[1] & 15) << 4 | (sub_arr[2] >> 2 & 15)
        pw_arr[k + 2] = (sub_arr[2] & 3) << 6 | (sub_arr[3] & 0x3F)

        # These are not really used; they are overwritten above.
        sub_arr[0] = sub_arr[0] ^ 0x70
        sub_arr[1] = sub_arr[1] ^ 0xA4
        sub_arr[2] = sub_arr[2] ^ 0x30
        sub_arr[3] = sub_arr[3] ^ 0xC0

        k += 3
        
    print(f'[+] Password array: {pw_arr}')
    print(f'[+] Final ciphertext:', ''.join('%02x' % p for p in pw_arr))


# ---------------------------------------------------------------------------------------
if __name__ == "__main__":
    encrypt_example('ispoleet')
    
    print("[+] Pico's Garage crack started.")

    target = base64.b64decode('MTg3MjBkZGVhZDFjNjQ5ODZiMjU5YmM0YWNmOTVkMjhhMGE3OTlmYTkzYmVlZjBl')
    target = target.decode('utf-8') # should be: 18720ddead1c64986b259bc4acf95d28a0a799fa93beef0e

    print(f'[+] Target Hash: {target}')

    # Split target hash into a list.
    target = list(bytes.fromhex(str(target)))

    target[3] = 0x7A;
    target[4] = target[17] - 3;
    target[len(target) - 3] = 0xB2;
    target[len(target) - 2] = target[len(target) - 3] + 1;

    print('[+] Target Hash List:', '-'.join('%02X' % t for t in target))
    
    final_password = ''

    # Start recoving password backwards.
    pw_arr = target
    for k in range(len(target)-3, -1, -3):
        sub_arr = [0]*4

        print(f'[+] Cracking characters {k-4} ~> {k}')
        sub_arr[0]  =  (pw_arr[k]   & 0b11111100) >> 2  # we miss the 2 msb
        sub_arr[1]  =  (pw_arr[k]   & 0b00000011) << 4  #
        sub_arr[1] |=  (pw_arr[k+1] & 0b11110000) >> 4  # we miss bits 2, 3        
        sub_arr[2]  =  (pw_arr[k+1] & 0b00001111) << 2  # 
        sub_arr[2] |=  (pw_arr[k+2] & 0b11000000) >> 6  # we miss 2 msb
        sub_arr[3]  =   pw_arr[k+2] & 0b00111111        # we miss 2 msb

        # We miss 8 bits in total. However 3 of them are MSBits which we know are 0 (b/c we have
        # printable ASCIIs). Hence, we bruteforce 5 bits only.
        plain = [0]*4
        for i in range(32):
            plain[0] = sub_arr[0] | (((i & 0b00001)) << 6)
            plain[1] = sub_arr[1] | (((i & 0b00010) >> 1) << 2)
            plain[1] = sub_arr[1] | (((i & 0b00100) >> 2) << 3)
            plain[2] = sub_arr[2] | (((i & 0b01000) >> 3) << 6)
            plain[3] = sub_arr[3] | (((i & 0b10000) >> 4) << 6)
                        
            try:
                sub_pass = [0]*4
                for j in range(4):
                    sub_pass[j] = "ABCDEFINS_+*!{}0123456789abcdefghijklmnopqrstuvwxyz"[plain[j]]

                sub_pass = ''.join(sub_pass)                
                print(f'[+] Password found: {sub_pass}')
                final_password = sub_pass + final_password
                break
            except IndexError:
                pass

    print(f'[+] Final flag: {final_password}')

# ---------------------------------------------------------------------------------------
'''
[+] Encryption example for: ispoleet
[+] Substitution array for index 0: [33, 43, 40, 39]
[+] Substitution array for index 3: [36, 29, 29, 44]
[+] Password array: [134, 186, 39, 145, 215, 108]
[+] Final ciphertext: 86ba2791d76c
[+] Pico's Garage crack started.
[+] Target Hash: 18720ddead1c64986b259bc4acf95d28a0a799fa93beef0e
[+] Target Hash List: 18-72-0D-7A-A4-1C-64-98-6B-25-9B-C4-AC-F9-5D-28-A0-A7-99-FA-93-B2-B3-0E
[+] Cracking characters 17 ~> 21
[+] Password found: ts!}
[+] Cracking characters 14 ~> 18
[+] Password found: ngr4
[+] Cracking characters 11 ~> 15
[+] Password found: ++Co
[+] Cracking characters 8 ~> 12
[+] Password found: s0me
[+] Cracking characters 5 ~> 9
[+] Password found: _awE
[+] Cracking characters 2 ~> 6
[+] Password found: a_is
[+] Cracking characters -1 ~> 3
[+] Password found: fr1d
[+] Cracking characters -4 ~> 0
[+] Password found: INS{
[+] Final flag: INS{fr1da_is_awEs0me++Congr4ts!}
'''
# ---------------------------------------------------------------------------------------
