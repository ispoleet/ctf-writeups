#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
import base64
import struct


# ----------------------------------------------------------------------------------------
def my_xxtea(v, n, key, d=False):
    """(Slightly) modified implementation of XXTEA.
    Code taken from here: https://en.wikipedia.org/wiki/XXTEA
    """
    DELTA = 0x9e3779b9
    def MX():
        mx = (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum_^y) + (key[((p)&3)^e] ^ z)))
        return mx & 0xFFFFFFFF

    # With 2 blocks ~> 0x20 rounds
    #      3 blocks ~> 0x17 rounds
    rounds = 6 + 52 // n 

    # ~ ~ ~ ~ ~ Encryption ~ ~ ~ ~ ~
    if n > 1: 

      sum_ = 0
      z = v[n-1]
      while rounds > 0:
        if d: print(f"[+]  R:{rounds:2d}, SUM:{sum_:08X}, v:[{', '.join(f'{i:08X}' for i in v)}]")
        sum_ = (sum_ + DELTA) & 0xFFFFFFFF
        e = (sum_ >> 2) & 3

        for p in range(0, n, 1):
          y = v[(p + 1) % n]
          v[p] = (v[p] + MX()) & 0xFFFFFFFF
          z = v[p]
          if d: print(f'[+]    p:{p} y:{y:08X}, k:{key[(p&3)^e]:08X} MX:{MX():08X}, z:{z:08X}',
                      f"v:[{', '.join(f'{i:08X}' for i in v)}]")
        rounds -= 1

    # ~ ~ ~ ~ ~ Decryption ~ ~ ~ ~ ~
    elif n < -1:
      n = -n
      rounds = 6 + 52 // n 
      sum_ = rounds*DELTA
      y = v[0]
      while rounds > 0:
        if d: print(f"[+]  R:{rounds:2d}, SUM:{sum_:08X}, v:[{', '.join(f'{i:08X}' for i in v)}]")
        e = (sum_ >> 2) & 3
        for p in range(n-1, -1, -1):
          z = v[(p-1)]
          v[p] = (v[p] - MX()) & 0xFFFFFFFF
          y = v[p]
          if d: print(f'[+]    p:{p} y:{y:08X}, k:{key[(p&3)^e]:08X} MX:{MX():08X}, z:{z:08X}',
                      f"v:[{', '.join(f'{i:08X}' for i in v)}]")

        sum_ = (sum_ - DELTA) & 0xFFFFFFFF
        rounds -= 1
   
    return v
 

# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] InsoStasher crack started.')
    
    # Encryption key (in bytes an DWORDs).
    key = [0xA7, 0xCF, 0xC7, 0xAA, 0x17, 0x8B, 0x6A, 0xCB, 0x6D, 0xF7, 0x66, 0x3C, 0x89, 0x97, 0xC8, 0x30]
    key = [0xAAC7CFA7, 0xCB6A8B17, 0x3C66F76D, 0x30C89789]
  
    # Testing encryption first.
    plain = b'ispoleet~'
    print(f'[+] Testing encryption for: {plain}')

    if len(plain) < 8:
        plain += b'\x00'*(8 - len(plain))
    elif len(plain) % 4:
        plain += b'\x00'*(4 - len(plain) % 4)  # Pad with 0s to make it multiple of 4.
    

    # Split into DWORDs.
    plain = [struct.unpack('<L', plain[i:i+4])[0] for i in range(0, len(plain), 4)]
    print('[+] Plaintext DWORDs:', ' '.join(f'{p:08X}' for p in plain))

    # Encrypt.
    encr  = my_xxtea(plain, len(plain), key, d=True)
    encr2 = b''.join(e.to_bytes(4, 'little') for e in encr)
    print('[+] Ciphertext DWORDs:', ' '.join(f'{e:08X}' for e in encr))
    print('[+] Ciphertext bytes :', ' '.join(f'{e:02X}' for e in encr2))

    b64 = base64.b64encode(encr2).replace(b'/', b'_').replace(b'+', b'-')
    print(f'[+] Base64 ciphertext: {b64}')

    # Decrypt.
    print('[+] Decrypting ciphertext back to plantext ...')

    decr  = my_xxtea(encr, -len(encr), key, d=True)
    decr2 = b''.join(d.to_bytes(4, 'little') for d in decr)
    print('[+] Plaintext DWORDs:', ' '.join(f'{d:08X}' for d in decr))
    print('[+] Plaintext bytes :', ' '.join(f'{d:02X}' for d in decr2))
    print('[+] Plaintextx:', ''.join(chr(d) for d in decr2))

   
    # FLAG CRACK.
    cipher = 'A6OjAV2wj16tYkzefI029h0gVn5y_HTIw8n_iBeHk1FDIcJsBneho94FjL8='
    print(f'[+] Decrypting flag: {cipher}')
    cipher = cipher.replace('_', '/').replace('+', '-')
    cipher = base64.b64decode(cipher)
    cipher2 = [struct.unpack('<L', cipher[i:i+4])[0] for i in range(0, len(cipher), 4)]
    print('[+] Encrypted flag bytes :', ' '.join(f'{c:02X}' for c in cipher))
    print('[+] Encrypted flag DWORDs:', ' '.join(f'{c:08X}' for c in cipher2))

    flag  = my_xxtea(cipher2, -len(cipher2), key)
    flag2 = b''.join(f.to_bytes(4, 'little') for f in flag)

    print('[+] Decrypted flag DWORDs:', ' '.join(f'{f:08X}' for f in flag))
    print('[+] Decrypted flag bytes :', ' '.join(f'{f:02X}' for f in flag2))
    print('[+] Flag:', ''.join(chr(f) for f in flag2))

    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
r"""
[+] InsoStasher crack started.
[+] Testing encryption for: b'ispoleet'
[+] Plaintext DWORDs: 6F707369 7465656C
[+]  R:32, SUM:00000000, v:[6F707369, 7465656C]
[+]    p:0 y:7465656C, k:3C66F76D MX:D430D238, z:98B48B47 v:[98B48B47, 7465656C]
[+]    p:1 y:98B48B47, k:30C89789 MX:483477C6, z:C5DB06FE v:[98B48B47, C5DB06FE]
[+]  R:31, SUM:9E3779B9, v:[98B48B47, C5DB06FE]
[+]    p:0 y:C5DB06FE, k:AAC7CFA7 MX:08115411, z:D753F932 v:[D753F932, C5DB06FE]
[+]    p:1 y:D753F932, k:CB6A8B17 MX:C86CCCB6, z:92982260 v:[D753F932, 92982260]
[+]  R:30, SUM:3C6EF372, v:[D753F932, 92982260]
[+]    p:0 y:92982260, k:3C66F76D MX:3E0B6B86, z:554C47B9 v:[554C47B9, 92982260]
[+]    p:1 y:554C47B9, k:30C89789 MX:DDD34FA7, z:D5FFACE2 v:[554C47B9, D5FFACE2]
[+]  R:29, SUM:DAA66D2B, v:[554C47B9, D5FFACE2]
[+]    p:0 y:D5FFACE2, k:CB6A8B17 MX:A8EE94B8, z:B26E4309 v:[B26E4309, D5FFACE2]
[+]    p:1 y:B26E4309, k:AAC7CFA7 MX:36DACEBD, z:F588F298 v:[B26E4309, F588F298]
[+]  R:28, SUM:78DDE6E4, v:[B26E4309, F588F298]
[+]    p:0 y:F588F298, k:30C89789 MX:3BD20999, z:627E75DA v:[627E75DA, F588F298]
[+]    p:1 y:627E75DA, k:3C66F76D MX:ED7C16E9, z:5A9A12B7 v:[627E75DA, 5A9A12B7]
[+]  R:27, SUM:1715609D, v:[627E75DA, 5A9A12B7]
[+]    p:0 y:5A9A12B7, k:CB6A8B17 MX:252E9EF8, z:ECE6D7C8 v:[ECE6D7C8, 5A9A12B7]
[+]    p:1 y:ECE6D7C8, k:AAC7CFA7 MX:835C685B, z:71BF48D1 v:[ECE6D7C8, 71BF48D1]
[+]  R:26, SUM:B54CDA56, v:[ECE6D7C8, 71BF48D1]
[+]    p:0 y:71BF48D1, k:30C89789 MX:AB24E3AF, z:A56D9902 v:[A56D9902, 71BF48D1]
[+]    p:1 y:A56D9902, k:3C66F76D MX:7BF4D159, z:CEA3598D v:[A56D9902, CEA3598D]
[+]  R:25, SUM:5384540F, v:[A56D9902, CEA3598D]
[+]    p:0 y:CEA3598D, k:3C66F76D MX:67A842FC, z:A671CCFE v:[A671CCFE, CEA3598D]
[+]    p:1 y:A671CCFE, k:30C89789 MX:2A005976, z:CCE84240 v:[A671CCFE, CCE84240]
[+]  R:24, SUM:F1BBCDC8, v:[A671CCFE, CCE84240]
[+]    p:0 y:CCE84240, k:AAC7CFA7 MX:227CCFCF, z:4C07B1F0 v:[4C07B1F0, CCE84240]
[+]    p:1 y:4C07B1F0, k:CB6A8B17 MX:6EB0E2A5, z:84011515 v:[4C07B1F0, 84011515]
[+]  R:23, SUM:8FF34781, v:[4C07B1F0, 84011515]
[+]    p:0 y:84011515, k:3C66F76D MX:5C820644, z:522E1839 v:[522E1839, 84011515]
[+]    p:1 y:522E1839, k:30C89789 MX:2D9ED864, z:30274D24 v:[522E1839, 30274D24]
[+]  R:22, SUM:2E2AC13A, v:[522E1839, 30274D24]
[+]    p:0 y:30274D24, k:AAC7CFA7 MX:1B668F44, z:A4D7C8C0 v:[A4D7C8C0, 30274D24]
[+]    p:1 y:A4D7C8C0, k:CB6A8B17 MX:D4DA3381, z:583A7178 v:[A4D7C8C0, 583A7178]
[+]  R:21, SUM:CC623AF3, v:[A4D7C8C0, 583A7178]
[+]    p:0 y:583A7178, k:30C89789 MX:91647F41, z:1636A59F v:[1636A59F, 583A7178]
[+]    p:1 y:1636A59F, k:3C66F76D MX:699280D6, z:7523462E v:[1636A59F, 7523462E]
[+]  R:20, SUM:6A99B4AC, v:[1636A59F, 7523462E]
[+]    p:0 y:7523462E, k:CB6A8B17 MX:462CCC8A, z:25BEDEC9 v:[25BEDEC9, 7523462E]
[+]    p:1 y:25BEDEC9, k:AAC7CFA7 MX:0BC92F42, z:C0FD0D2F v:[25BEDEC9, C0FD0D2F]
[+]  R:19, SUM:08D12E65, v:[25BEDEC9, C0FD0D2F]
[+]    p:0 y:C0FD0D2F, k:30C89789 MX:6071220F, z:6BA74EC6 v:[6BA74EC6, C0FD0D2F]
[+]    p:1 y:6BA74EC6, k:3C66F76D MX:CC57D9C7, z:01AEB4D4 v:[6BA74EC6, 01AEB4D4]
[+]  R:18, SUM:A708A81E, v:[6BA74EC6, 01AEB4D4]
[+]    p:0 y:01AEB4D4, k:CB6A8B17 MX:0890231E, z:99CBE4DC v:[99CBE4DC, 01AEB4D4]
[+]    p:1 y:99CBE4DC, k:AAC7CFA7 MX:6A358B3C, z:FEADC20B v:[99CBE4DC, FEADC20B]
[+]  R:17, SUM:454021D7, v:[99CBE4DC, FEADC20B]
[+]    p:0 y:FEADC20B, k:AAC7CFA7 MX:AC2B339B, z:19DB7D46 v:[19DB7D46, FEADC20B]
[+]    p:1 y:19DB7D46, k:CB6A8B17 MX:F830AE68, z:CA1EF9A8 v:[19DB7D46, CA1EF9A8]
[+]  R:16, SUM:E3779B90, v:[19DB7D46, CA1EF9A8]
[+]    p:0 y:CA1EF9A8, k:3C66F76D MX:EC00B00B, z:BEDA29CA v:[BEDA29CA, CA1EF9A8]
[+]    p:1 y:BEDA29CA, k:30C89789 MX:F5258863, z:FEBEAEE1 v:[BEDA29CA, FEBEAEE1]
[+]  R:15, SUM:81AF1549, v:[BEDA29CA, FEBEAEE1]
[+]    p:0 y:FEBEAEE1, k:AAC7CFA7 MX:2C8CFB51, z:83773360 v:[83773360, FEBEAEE1]
[+]    p:1 y:83773360, k:CB6A8B17 MX:98D3B19F, z:D308DF3F v:[83773360, D308DF3F]
[+]  R:14, SUM:1FE68F02, v:[83773360, D308DF3F]
[+]    p:0 y:D308DF3F, k:3C66F76D MX:E4BFD877, z:ACA4112A v:[ACA4112A, D308DF3F]
[+]    p:1 y:ACA4112A, k:30C89789 MX:10601182, z:0BF533D1 v:[ACA4112A, 0BF533D1]
[+]  R:13, SUM:BE1E08BB, v:[ACA4112A, 0BF533D1]
[+]    p:0 y:0BF533D1, k:CB6A8B17 MX:92F1FB8B, z:A29D7959 v:[A29D7959, 0BF533D1]
[+]    p:1 y:A29D7959, k:AAC7CFA7 MX:801DB9D6, z:D7BC2F13 v:[A29D7959, D7BC2F13]
[+]  R:12, SUM:5C558274, v:[A29D7959, D7BC2F13]
[+]    p:0 y:D7BC2F13, k:30C89789 MX:EF74469B, z:4FC4D337 v:[4FC4D337, D7BC2F13]
[+]    p:1 y:4FC4D337, k:3C66F76D MX:EF1612A5, z:F3856F42 v:[4FC4D337, F3856F42]
[+]  R:11, SUM:FA8CFC2D, v:[4FC4D337, F3856F42]
[+]    p:0 y:F3856F42, k:CB6A8B17 MX:C857D1DE, z:9B63E1FA v:[9B63E1FA, F3856F42]
[+]    p:1 y:9B63E1FA, k:AAC7CFA7 MX:D8665CCB, z:2F72AE41 v:[9B63E1FA, 2F72AE41]
[+]  R:10, SUM:98C475E6, v:[9B63E1FA, 2F72AE41]
[+]    p:0 y:2F72AE41, k:30C89789 MX:C257CB6A, z:319A87E2 v:[319A87E2, 2F72AE41]
[+]    p:1 y:319A87E2, k:3C66F76D MX:CFDF3709, z:224ED1E0 v:[319A87E2, 224ED1E0]
[+]  R: 9, SUM:36FBEF9F, v:[319A87E2, 224ED1E0]
[+]    p:0 y:224ED1E0, k:3C66F76D MX:4847E81E, z:EF02B1F0 v:[EF02B1F0, 224ED1E0]
[+]    p:1 y:EF02B1F0, k:30C89789 MX:F93058DF, z:D314B68C v:[EF02B1F0, D314B68C]
[+]  R: 8, SUM:D5336958, v:[EF02B1F0, D314B68C]
[+]    p:0 y:D314B68C, k:AAC7CFA7 MX:AB625B9C, z:5EA8654D v:[5EA8654D, D314B68C]
[+]    p:1 y:5EA8654D, k:CB6A8B17 MX:8A54AE3C, z:6D4210AD v:[5EA8654D, 6D4210AD]
[+]  R: 7, SUM:736AE311, v:[5EA8654D, 6D4210AD]
[+]    p:0 y:6D4210AD, k:3C66F76D MX:AD37D1D3, z:A097141E v:[A097141E, 6D4210AD]
[+]    p:1 y:A097141E, k:30C89789 MX:A05EE01A, z:526A50FD v:[A097141E, 526A50FD]
[+]  R: 6, SUM:11A25CCA, v:[A097141E, 526A50FD]
[+]    p:0 y:526A50FD, k:AAC7CFA7 MX:B11476FD, z:2EDA86B8 v:[2EDA86B8, 526A50FD]
[+]    p:1 y:2EDA86B8, k:CB6A8B17 MX:760A2082, z:168DA8C3 v:[2EDA86B8, 168DA8C3]
[+]  R: 5, SUM:AFD9D683, v:[2EDA86B8, 168DA8C3]
[+]    p:0 y:168DA8C3, k:30C89789 MX:C6113432, z:E946C5F3 v:[E946C5F3, 168DA8C3]
[+]    p:1 y:E946C5F3, k:3C66F76D MX:59FE4851, z:6E7009DF v:[E946C5F3, 6E7009DF]
[+]  R: 4, SUM:4E11503C, v:[E946C5F3, 6E7009DF]
[+]    p:0 y:6E7009DF, k:CB6A8B17 MX:AEE50660, z:6C17C702 v:[6C17C702, 6E7009DF]
[+]    p:1 y:6C17C702, k:AAC7CFA7 MX:182C3561, z:3581474B v:[6C17C702, 3581474B]
[+]  R: 3, SUM:EC48C9F5, v:[6C17C702, 3581474B]
[+]    p:0 y:3581474B, k:30C89789 MX:91E425A3, z:5E1F6DCA v:[5E1F6DCA, 3581474B]
[+]    p:1 y:5E1F6DCA, k:3C66F76D MX:936F866B, z:895BFB9F v:[5E1F6DCA, 895BFB9F]
[+]  R: 2, SUM:8A8043AE, v:[5E1F6DCA, 895BFB9F]
[+]    p:0 y:895BFB9F, k:CB6A8B17 MX:F837E048, z:9FC3BD6D v:[9FC3BD6D, 895BFB9F]
[+]    p:1 y:9FC3BD6D, k:AAC7CFA7 MX:F39DF6D4, z:1128F6A7 v:[9FC3BD6D, 1128F6A7]
[+]  R: 1, SUM:28B7BD67, v:[9FC3BD6D, 1128F6A7]
[+]    p:0 y:1128F6A7, k:AAC7CFA7 MX:125255EA, z:6727A8B7 v:[6727A8B7, 1128F6A7]
[+]    p:1 y:6727A8B7, k:CB6A8B17 MX:F1601652, z:617CD56F v:[6727A8B7, 617CD56F]
[+] Ciphertext DWORDs: 6727A8B7 617CD56F
[+] Ciphertext bytes : B7 A8 27 67 6F D5 7C 61
[+] Base64 ciphertext: b't6gnZ2_VfGE='
[+] Decrypting ciphertext back to plantext ...
[+]  R:32, SUM:13C6EF3720, v:[6727A8B7, 617CD56F]
[+]    p:1 y:1128F6A7, k:CB6A8B17 MX:33EE985A, z:6727A8B7 v:[6727A8B7, 1128F6A7]
[+]    p:0 y:9FC3BD6D, k:AAC7CFA7 MX:95E50C93, z:1128F6A7 v:[9FC3BD6D, 1128F6A7]
[+]  R:31, SUM:28B7BD67, v:[9FC3BD6D, 1128F6A7]
[+]    p:1 y:895BFB9F, k:AAC7CFA7 MX:D85224F8, z:9FC3BD6D v:[9FC3BD6D, 895BFB9F]
[+]    p:0 y:5E1F6DCA, k:CB6A8B17 MX:A269FC08, z:895BFB9F v:[5E1F6DCA, 895BFB9F]
[+]  R:30, SUM:8A8043AE, v:[5E1F6DCA, 895BFB9F]
[+]    p:1 y:3581474B, k:3C66F76D MX:9D464507, z:5E1F6DCA v:[5E1F6DCA, 3581474B]
[+]    p:0 y:6C17C702, k:30C89789 MX:EC68F7EC, z:3581474B v:[6C17C702, 3581474B]
[+]  R:29, SUM:EC48C9F5, v:[6C17C702, 3581474B]
[+]    p:1 y:6E7009DF, k:AAC7CFA7 MX:CE5BC290, z:6C17C702 v:[6C17C702, 6E7009DF]
[+]    p:0 y:E946C5F3, k:CB6A8B17 MX:0AB8521E, z:6E7009DF v:[E946C5F3, 6E7009DF]
[+]  R:28, SUM:4E11503C, v:[E946C5F3, 6E7009DF]
[+]    p:1 y:168DA8C3, k:3C66F76D MX:D98754D6, z:E946C5F3 v:[E946C5F3, 168DA8C3]
[+]    p:0 y:2EDA86B8, k:30C89789 MX:AFF14143, z:168DA8C3 v:[2EDA86B8, 168DA8C3]
[+]  R:27, SUM:AFD9D683, v:[2EDA86B8, 168DA8C3]
[+]    p:1 y:526A50FD, k:CB6A8B17 MX:D3A72D4D, z:2EDA86B8 v:[2EDA86B8, 526A50FD]
[+]    p:0 y:A097141E, k:AAC7CFA7 MX:B47A91A5, z:526A50FD v:[A097141E, 526A50FD]
[+]  R:26, SUM:11A25CCA, v:[A097141E, 526A50FD]
[+]    p:1 y:6D4210AD, k:30C89789 MX:B9DA31F7, z:A097141E v:[A097141E, 6D4210AD]
[+]    p:0 y:5EA8654D, k:3C66F76D MX:F990AD6D, z:6D4210AD v:[5EA8654D, 6D4210AD]
[+]  R:25, SUM:736AE311, v:[5EA8654D, 6D4210AD]
[+]    p:1 y:D314B68C, k:CB6A8B17 MX:09CD18EC, z:5EA8654D v:[5EA8654D, D314B68C]
[+]    p:0 y:EF02B1F0, k:AAC7CFA7 MX:F1066D7E, z:D314B68C v:[EF02B1F0, D314B68C]
[+]  R:24, SUM:D5336958, v:[EF02B1F0, D314B68C]
[+]    p:1 y:224ED1E0, k:30C89789 MX:55E1C87A, z:EF02B1F0 v:[EF02B1F0, 224ED1E0]
[+]    p:0 y:319A87E2, k:3C66F76D MX:E884AD44, z:224ED1E0 v:[319A87E2, 224ED1E0]
[+]  R:23, SUM:36FBEF9F, v:[319A87E2, 224ED1E0]
[+]    p:1 y:2F72AE41, k:3C66F76D MX:FF092B4E, z:319A87E2 v:[319A87E2, 2F72AE41]
[+]    p:0 y:9B63E1FA, k:30C89789 MX:9C68E2E4, z:2F72AE41 v:[9B63E1FA, 2F72AE41]
[+]  R:22, SUM:98C475E6, v:[9B63E1FA, 2F72AE41]
[+]    p:1 y:F3856F42, k:AAC7CFA7 MX:EFF81D4E, z:9B63E1FA v:[9B63E1FA, F3856F42]
[+]    p:0 y:4FC4D337, k:CB6A8B17 MX:65CD5ECA, z:F3856F42 v:[4FC4D337, F3856F42]
[+]  R:21, SUM:FA8CFC2D, v:[4FC4D337, F3856F42]
[+]    p:1 y:D7BC2F13, k:3C66F76D MX:E39BA6FF, z:4FC4D337 v:[4FC4D337, D7BC2F13]
[+]    p:0 y:A29D7959, k:30C89789 MX:C3DF5C39, z:D7BC2F13 v:[A29D7959, D7BC2F13]
[+]  R:20, SUM:5C558274, v:[A29D7959, D7BC2F13]
[+]    p:1 y:0BF533D1, k:AAC7CFA7 MX:0C9230DB, z:A29D7959 v:[A29D7959, 0BF533D1]
[+]    p:0 y:ACA4112A, k:CB6A8B17 MX:EC06E04F, z:0BF533D1 v:[ACA4112A, 0BF533D1]
[+]  R:19, SUM:BE1E08BB, v:[ACA4112A, 0BF533D1]
[+]    p:1 y:D308DF3F, k:30C89789 MX:10E53B9B, z:ACA4112A v:[ACA4112A, D308DF3F]
[+]    p:0 y:83773360, k:3C66F76D MX:00F0C538, z:D308DF3F v:[83773360, D308DF3F]
[+]  R:18, SUM:1FE68F02, v:[83773360, D308DF3F]
[+]    p:1 y:FEBEAEE1, k:CB6A8B17 MX:0EF03FA1, z:83773360 v:[83773360, FEBEAEE1]
[+]    p:0 y:BEDA29CA, k:AAC7CFA7 MX:0D78F586, z:FEBEAEE1 v:[BEDA29CA, FEBEAEE1]
[+]  R:17, SUM:81AF1549, v:[BEDA29CA, FEBEAEE1]
[+]    p:1 y:CA1EF9A8, k:30C89789 MX:FBAAD0A7, z:BEDA29CA v:[BEDA29CA, CA1EF9A8]
[+]    p:0 y:19DB7D46, k:3C66F76D MX:8AFD8129, z:CA1EF9A8 v:[19DB7D46, CA1EF9A8]
[+]  R:16, SUM:E3779B90, v:[19DB7D46, CA1EF9A8]
[+]    p:1 y:FEADC20B, k:CB6A8B17 MX:8C50700B, z:19DB7D46 v:[19DB7D46, FEADC20B]
[+]    p:0 y:99CBE4DC, k:AAC7CFA7 MX:95E6D573, z:FEADC20B v:[99CBE4DC, FEADC20B]
[+]  R:15, SUM:454021D7, v:[99CBE4DC, FEADC20B]
[+]    p:1 y:01AEB4D4, k:AAC7CFA7 MX:E8FAE7AE, z:99CBE4DC v:[99CBE4DC, 01AEB4D4]
[+]    p:0 y:6BA74EC6, k:CB6A8B17 MX:3F845D82, z:01AEB4D4 v:[6BA74EC6, 01AEB4D4]
[+]  R:14, SUM:A708A81E, v:[6BA74EC6, 01AEB4D4]
[+]    p:1 y:C0FD0D2F, k:3C66F76D MX:1CA30253, z:6BA74EC6 v:[6BA74EC6, C0FD0D2F]
[+]    p:0 y:25BEDEC9, k:30C89789 MX:EE8F8D0B, z:C0FD0D2F v:[25BEDEC9, C0FD0D2F]
[+]  R:13, SUM:08D12E65, v:[25BEDEC9, C0FD0D2F]
[+]    p:1 y:7523462E, k:AAC7CFA7 MX:27810B1A, z:25BEDEC9 v:[25BEDEC9, 7523462E]
[+]    p:0 y:1636A59F, k:CB6A8B17 MX:71571B93, z:7523462E v:[1636A59F, 7523462E]
[+]  R:12, SUM:6A99B4AC, v:[1636A59F, 7523462E]
[+]    p:1 y:583A7178, k:3C66F76D MX:9431906D, z:1636A59F v:[1636A59F, 583A7178]
[+]    p:0 y:A4D7C8C0, k:30C89789 MX:1F9DBC7E, z:583A7178 v:[A4D7C8C0, 583A7178]
[+]  R:11, SUM:CC623AF3, v:[A4D7C8C0, 583A7178]
[+]    p:1 y:30274D24, k:CB6A8B17 MX:7D314BD4, z:A4D7C8C0 v:[A4D7C8C0, 30274D24]
[+]    p:0 y:522E1839, k:AAC7CFA7 MX:6846CE99, z:30274D24 v:[522E1839, 30274D24]
[+]  R:10, SUM:2E2AC13A, v:[522E1839, 30274D24]
[+]    p:1 y:84011515, k:30C89789 MX:49E4A618, z:522E1839 v:[522E1839, 84011515]
[+]    p:0 y:4C07B1F0, k:3C66F76D MX:67452594, z:84011515 v:[4C07B1F0, 84011515]
[+]  R: 9, SUM:8FF34781, v:[4C07B1F0, 84011515]
[+]    p:1 y:CCE84240, k:CB6A8B17 MX:C12F0B7F, z:4C07B1F0 v:[4C07B1F0, CCE84240]
[+]    p:0 y:A671CCFE, k:AAC7CFA7 MX:F65896EF, z:CCE84240 v:[A671CCFE, CCE84240]
[+]  R: 8, SUM:F1BBCDC8, v:[A671CCFE, CCE84240]
[+]    p:1 y:CEA3598D, k:30C89789 MX:6B566298, z:A671CCFE v:[A671CCFE, CEA3598D]
[+]    p:0 y:A56D9902, k:3C66F76D MX:D5C7A91E, z:CEA3598D v:[A56D9902, CEA3598D]
[+]  R: 7, SUM:5384540F, v:[A56D9902, CEA3598D]
[+]    p:1 y:71BF48D1, k:3C66F76D MX:A782438B, z:A56D9902 v:[A56D9902, 71BF48D1]
[+]    p:0 y:ECE6D7C8, k:30C89789 MX:B6A49E50, z:71BF48D1 v:[ECE6D7C8, 71BF48D1]
[+]  R: 6, SUM:B54CDA56, v:[ECE6D7C8, 71BF48D1]
[+]    p:1 y:5A9A12B7, k:AAC7CFA7 MX:07BA5A68, z:ECE6D7C8 v:[ECE6D7C8, 5A9A12B7]
[+]    p:0 y:627E75DA, k:CB6A8B17 MX:5838A4E4, z:5A9A12B7 v:[627E75DA, 5A9A12B7]
[+]  R: 5, SUM:1715609D, v:[627E75DA, 5A9A12B7]
[+]    p:1 y:F588F298, k:3C66F76D MX:4E30697D, z:627E75DA v:[627E75DA, F588F298]
[+]    p:0 y:B26E4309, k:30C89789 MX:7663A534, z:F588F298 v:[B26E4309, F588F298]
[+]  R: 4, SUM:78DDE6E4, v:[B26E4309, F588F298]
[+]    p:1 y:D5FFACE2, k:AAC7CFA7 MX:4B025028, z:B26E4309 v:[B26E4309, D5FFACE2]
[+]    p:0 y:554C47B9, k:CB6A8B17 MX:E4D4E308, z:D5FFACE2 v:[554C47B9, D5FFACE2]
[+]  R: 3, SUM:DAA66D2B, v:[554C47B9, D5FFACE2]
[+]    p:1 y:92982260, k:30C89789 MX:22A174E2, z:554C47B9 v:[554C47B9, 92982260]
[+]    p:0 y:D753F932, k:3C66F76D MX:31B71627, z:92982260 v:[D753F932, 92982260]
[+]  R: 2, SUM:3C6EF372, v:[D753F932, 92982260]
[+]    p:1 y:C5DB06FE, k:CB6A8B17 MX:6AB41F81, z:D753F932 v:[D753F932, C5DB06FE]
[+]    p:0 y:98B48B47, k:AAC7CFA7 MX:A054B23D, z:C5DB06FE v:[98B48B47, C5DB06FE]
[+]  R: 1, SUM:9E3779B9, v:[98B48B47, C5DB06FE]
[+]    p:1 y:7465656C, k:30C89789 MX:C9DA7364, z:98B48B47 v:[98B48B47, 7465656C]
[+]    p:0 y:6F707369, k:3C66F76D MX:3351A3ED, z:7465656C v:[6F707369, 7465656C]
[+] Plaintext DWORDs: 6F707369 7465656C
[+] Plaintext bytes : 69 73 70 6F 6C 65 65 74
[+] Plaintextx: ispoleet
[+] Decrypting flag: A6OjAV2wj16tYkzefI029h0gVn5y_HTIw8n_iBeHk1FDIcJsBneho94FjL8=
[+] Encrypted flag bytes : 03 A3 A3 01 5D B0 8F 5E AD 62 4C DE 7C 8D 36 F6 1D 20 56 7E 72 FC 74 C8 C3 C9 FF 88 17 87 93 51 43 21 C2 6C 06 77 A1 A3 DE 05 8C BF
[+] Encrypted flag DWORDs: 01A3A303 5E8FB05D DE4C62AD F6368D7C 7E56201D C874FC72 88FFC9C3 51938717 6CC22143 A3A17706 BF8C05DE
[+] Decrypted flag DWORDs: 7B534E49 6279346D 5F315F33 75306835 37276E6C 7634685F 34685F33 30636472 5F643364 5F336837 7D79336B
[+] Decrypted flag bytes : 49 4E 53 7B 6D 34 79 62 33 5F 31 5F 35 68 30 75 6C 6E 27 37 5F 68 34 76 33 5F 68 34 72 64 63 30 64 33 64 5F 37 68 33 5F 6B 33 79 7D
[+] Flag: INS{m4yb3_1_5h0uln'7_h4v3_h4rdc0d3d_7h3_k3y}
[+] Program finished. Bye bye :)
"""
# ----------------------------------------------------------------------------------------

