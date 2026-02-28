#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Crackmes One CTF 2026 - Matryoshka v2 - (Hard - 912)
# ----------------------------------------------------------------------------------------
import os
import pefile
import struct
from Crypto.Cipher import ARC4

# We've split the source into multiple files.
from replace_jcc import replace_opposite_jcc
from jmp_deobf import deobf_shellcode
from bit_checks import recover_ciphertext_from_bit_checks
from crack import feistel_decrypt


# ----------------------------------------------------------------------------------------
def extract_resources(dll):
    """Extracts "CHECK" and "MATRYOSHKA" resources from a DLL."""
    pe = pefile.PE(dll)

    res = {}
    for rsrc_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:  # Resource types.
        for rsrc_id in rsrc_type.directory.entries:  # Resource names/IDs.
            name = str(rsrc_id.name)
            if name not in ['CHECK', 'MATRYOSHKA']:
                continue

            print(f'[+] Found resource: {rsrc_id.name}')

            for rsrc_lang in rsrc_id.directory.entries:  # Resource languages (data leaf).            
                raw = pe.get_data(rsrc_lang.data.struct.OffsetToData,
                                  rsrc_lang.data.struct.Size)
                res[name] = bytearray(raw)

    if 'CHECK' not in res or 'MATRYOSHKA' not in res:  # We need both resources
        raise Exception('Cannot find resources')

    return res


# ----------------------------------------------------------------------------------------
def decrypt_matryoshka(matryoshka, key):
    """Decrypt a Matryoshka using RC4."""
    rc4 = ARC4.new(key)
    plaintext = rc4.decrypt(matryoshka)  # Ciphertext must be `bytes` type.
    print(f'[+] Decrypted message (20 bytes): {plaintext[:20]!r}')

    if not plaintext.startswith(b'MZ\x90\x00'):
        raise Exception('RC4 decryption failed')

    return plaintext


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Matryoshka v2 crack started.')

    try:
        os.mkdir('matryoshkas')
        os.mkdir('shellcodes')
    except FileExistsError:
        pass

    init_dll = 'Doll.dll'
    license = []

    for i in range(128):  # We don't know how many matryoshka's there are are.
        print(f'[+] ================ Decrypting Matryoshka #{i} ================')
        try:
            print(f'[+] Loading resources from {init_dll} ...')
            res = extract_resources(init_dll)
            CHECK, MATRYOSHKA = res['CHECK'], res['MATRYOSHKA']
        except Exception as e:
            # If there are no resources we've reached the last doll.
            break

        # Step 1: Replace obfuscated jumps in CHECK shellcode.
        #
        # Shellcode is full of blocks of opposite conditional jumps. For example:    
        #   seg000:000451EA         jge     loc_111766
        #   seg000:000451F0         push    rax
        #   seg000:000451F1         mov     rax, rdx
        #   seg000:000451F4         pop     rax
        #   seg000:000451F5         jl      loc_111766
        #
        # We replace them with `jmp loc_111766`.
        shellcode_1 = replace_opposite_jcc(CHECK)

        # Step 2: Deobfuscate shellcode. Remove all unnecessary jumps.
        shellcode_2 = deobf_shellcode(shellcode_1)

        sc_path = os.path.join('shellcodes', f'sc_{i}.bin')
        with open(sc_path, 'wb') as fp:
            fp.write(shellcode_2)

        # Step 3: Symbolically execute the shellcode to find the target
        # ciphertext from the bit checks.
        trg_cipher = recover_ciphertext_from_bit_checks(sc_path)
        print(f'[+] Target ciphertext:' + ' - '.join(f'{x:016X}' for x in trg_cipher))

        # Step 4: Invert Feistel network to decrypt trg_cipher
        # and find license block.
        
        # We also need the initial constants. Luckily they're stored at the
        # same place in every (deobfuscated) shellcode.
        # 
        # Let's see an example:
        #   buf[0] = 0xEFB1957A;
        #   buf[1] = 0x3BAECF7;
        #   buf[2] = 0x8C982983;
        #   buf[3] = 0x781BCDB6;
        #
        # The assembly is:
        #   seg000:0000166 48 89 4C 24 08              mov     [rsp+arg_0], rcx
        #   seg000:000016B 48 81 EC E8 00 00 00        sub     rsp, 0E8h
        #   seg000:0000172 48 B8 F7 EC BA 03 7A 95     mov     rax, 0EFB1957A03BAECF7h
        #   seg000:0000172 B1 EF
        #   seg000:000017C 48 89 44 24 40              mov     [rsp+0E8h+var_A8], rax
        #   seg000:0000181 48 B8 B6 CD 1B 78 83 29     mov     rax, 8C982983781BCDB6h
        #   seg000:0000181 98 8C
        #
        # So we can use the following offsets:
        c2 = struct.unpack('<L', shellcode_2[0x174:0x174 + 4])[0]
        c1 = struct.unpack('<L', shellcode_2[0x178:0x178 + 4])[0]
        c4 = struct.unpack('<L', shellcode_2[0x183:0x183 + 4])[0]
        c3 = struct.unpack('<L', shellcode_2[0x187:0x187 + 4])[0]
        print(f'[+] Init consts: {c1:08X}-{c2:08X}-{c3:08X}-{c4:08X}')

        # Step 4: Decrypt trg_cipher by running the Feistel network backwards.
        lic_blk = feistel_decrypt(trg_cipher, c1, c2, c3, c4)
        print(f'[+] License block FOUND: {lic_blk}')
        license.append(lic_blk.decode('utf8'))

        # Step 5: Use the license block to decrypt the next matryoshka.
        next_doll = decrypt_matryoshka(MATRYOSHKA, lic_blk)
        init_dll = os.path.join('matryoshkas', f'matryoshka_{i}.dll')
        with open(init_dll, 'wb') as fp:
            fp.write(next_doll)

        print(f'[+] License (so far):')
        for j, blk in enumerate(license):
            print(f'[+]     #{j}: {blk}')

    print("[+] Done. Writing license to 'license.bin' ...")
    with open('license.bin', 'w') as fp:
        fp.write(''.join(license))

    print('[+] Program finished successfully. Bye bye :)')

# ----------------------------------------------------------------------------------------
r"""
$ time ./main.py 
[+] Matryoshka v2 crack started.
[+] ================ Decrypting Matryoshka #0 ================
[+] Loading resources from Doll.dll ...
[+] Found resource: CHECK
[+] Found resource: MATRYOSHKA
[+] Replacing opposite jumps ...
[+] Loading shellcode into angr ...
[+] Exploring for goodboy address: 0x00100125 ...
[+] Goodboy FOUND! Extracting target ciphertext:
[+]     trg_cipher[0] = 0xFABBD91F04381F89
[+]     trg_cipher[1] = 0xD13F557D1B36E7CC
[+]     trg_cipher[2] = 0x501AEBA922F2C44C
[+]     trg_cipher[3] = 0x857A1BEA6419CE73
[+] Target ciphertext:FABBD91F04381F89 - D13F557D1B36E7CC - 501AEBA922F2C44C - 857A1BEA6419CE73
[+] Init consts: EFB1957A-03BAECF7-8C982983-781BCDB6
[+] License block FOUND: b'M0Oo8zjHkcPSWFzCxmw6jrj1RgNPucTH'
[+] Decrypted message (20 bytes): b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00'
[+] License (so far):
[+]     #0: M0Oo8zjHkcPSWFzCxmw6jrj1RgNPucTH
[+] ================ Decrypting Matryoshka #1 ================
[+] Loading resources from matryoshkas/matryoshka_0.dll ...
[+] Found resource: CHECK
[+] Found resource: MATRYOSHKA
[+] Replacing opposite jumps ...
[+] Loading shellcode into angr ...
[+] Exploring for goodboy address: 0x00100125 ...
[+] Goodboy FOUND! Extracting target ciphertext:
[+]     trg_cipher[0] = 0xB2439E2DD90A52E4
[+]     trg_cipher[1] = 0x2736DF7D495643D4
[+]     trg_cipher[2] = 0x1AD929AB0561F859
[+]     trg_cipher[3] = 0x4E4DA94DD2913E71
[+] Target ciphertext:B2439E2DD90A52E4 - 2736DF7D495643D4 - 1AD929AB0561F859 - 4E4DA94DD2913E71
[+] Init consts: 414BE18F-34158D5A-73A4CE13-3C7F6252
[+] License block FOUND: b'nE0OSzTLiLdrMGsKxaP34YlM8LHyOVtB'
[+] Decrypted message (20 bytes): b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00'
[+] License (so far):
[+]     #0: M0Oo8zjHkcPSWFzCxmw6jrj1RgNPucTH
[+]     #1: nE0OSzTLiLdrMGsKxaP34YlM8LHyOVtB
[+] ================ Decrypting Matryoshka #2 ================
[+] Loading resources from matryoshkas/matryoshka_1.dll ...
[+] Found resource: CHECK
[+] Found resource: MATRYOSHKA
[+] Replacing opposite jumps ...
[+] Loading shellcode into angr ...
[+] Exploring for goodboy address: 0x00100125 ...
[+] Goodboy FOUND! Extracting target ciphertext:
[+]     trg_cipher[0] = 0x18E18B27178CA4BD
[+]     trg_cipher[1] = 0x6644A906FED0177C
[+]     trg_cipher[2] = 0x59A055CFCCAF7348
[+]     trg_cipher[3] = 0x1D31564F1FC3A339
[+] Target ciphertext:18E18B27178CA4BD - 6644A906FED0177C - 59A055CFCCAF7348 - 1D31564F1FC3A339
[+] Init consts: 676B6F0A-27A491F1-9F8F5F73-5273E9D2
[+] License block FOUND: b'41PDnuoUhyOZQKi3VX9VBpSN1BwNwGgx'
[+] Decrypted message (20 bytes): b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00'
[+] License (so far):
[+]     #0: M0Oo8zjHkcPSWFzCxmw6jrj1RgNPucTH
[+]     #1: nE0OSzTLiLdrMGsKxaP34YlM8LHyOVtB
[+]     #2: 41PDnuoUhyOZQKi3VX9VBpSN1BwNwGgx
[+] ================ Decrypting Matryoshka #3 ================

[..... TRUNCATED FOR BREVITY ....]

[+] ================ Decrypting Matryoshka #49 ================
[+] Loading resources from matryoshkas/matryoshka_48.dll ...
[+] Found resource: CHECK
[+] Found resource: MATRYOSHKA
[+] Replacing opposite jumps ...
[+] Loading shellcode into angr ...
[+] Exploring for goodboy address: 0x00100125 ...
[+] Goodboy FOUND! Extracting target ciphertext:
[+]     trg_cipher[0] = 0x356129407901163D
[+]     trg_cipher[1] = 0x6DCF43A78C8986CA
[+]     trg_cipher[2] = 0x9BDEC1BFCB01072D
[+]     trg_cipher[3] = 0x64E52145E96AD8E3
[+] Target ciphertext:356129407901163D - 6DCF43A78C8986CA - 9BDEC1BFCB01072D - 64E52145E96AD8E3
[+] Init consts: E80BFB81-FB0566E4-0551F507-420AA395
[+] License block FOUND: b'5CLjB3Jp7TDRYQWzMVSRtW9NFgRhOv2y'
[+] Decrypted message (20 bytes): b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00'
[+] License (so far):
[+]     #0: M0Oo8zjHkcPSWFzCxmw6jrj1RgNPucTH
[+]     #1: nE0OSzTLiLdrMGsKxaP34YlM8LHyOVtB
[+]     #2: 41PDnuoUhyOZQKi3VX9VBpSN1BwNwGgx
[+]     #3: YoGsu8zPTrtnnJaYUgs63QFnztGi9jb3
[+]     #4: mpkxi4CzyLpaplSNfCsiXPKcfgxmDNbe
[+]     #5: fLMBmmOnGopH5ro5neXyk5XluG3MbAJw
[+]     #6: ShXHN8qMc6UziZc5RtGnUMZt3JQSZmPU
[+]     #7: iQRXaq0qMGx56kRI3acoaASBfRKU9Skl
[+]     #8: XShPoGDfsDGzSnVkFC8KjLrVPSFJvQqJ
[+]     #9: jPXuUkfonwGxayY4l4mUZegwQaf4HYYF
[+]     #10: nZh0RIr3gJeDTNzft0hf7atapmHHEXDc
[+]     #11: 8sVxrZ4p0HshMDnHD0us9WKc33OoQCAc
[+]     #12: 8iiOy81uP5b5slU7HQ0sKaqoXxNsaIBA
[+]     #13: VqGeUSX9wZ4mup7ycXaCegjSwjdKLuxj
[+]     #14: SDORjMnc5IQ4EqLqStDNN4EvdoMWAlAg
[+]     #15: CLeloR0UCrASNtwNtGIYXokxEFiN0Djl
[+]     #16: KJtvgdSC5opwW6VFSWDiyAfIeq1l7QS2
[+]     #17: 2i1Q99efyBoFHtISp1qxyMIGNS6J4vTD
[+]     #18: XliSiSCD0L0w30mPcNtKGvVywYDasg73
[+]     #19: vSFPwBQXMlLicHX9PPCkW9o6b3fOfnqe
[+]     #20: oxBgg3YdQ6hPveSp6Xi5JEf4YrwwPHER
[+]     #21: Cm7GwEiag3Z17NRj9M6dz96LMiUfXelX
[+]     #22: xJ63nXSQ0e9eELh5DyCU0nK7OKEfVT0f
[+]     #23: voa5soVi7A5ABF1T7Wi0nMV15Fe7rT0O
[+]     #24: LV6UpefmBZD3JjAArjCvVXbHRYyZOuIf
[+]     #25: 4qtihb4uCUCjFIprFfGr2LfBnnZghQsk
[+]     #26: uavSfoRzMwRjQuDH5ubgWaNlBBMk5Drc
[+]     #27: FMNQl5KlqOmNEuB3yA1DYl1BAKu8eA3q
[+]     #28: KNVPPm4eaWAK0hYHPzYyDL187mwVm57D
[+]     #29: vTsab5bGTfzZlSPIdnXFTai2Nl218tQB
[+]     #30: xc1xVHRKLSOfVhvVu6QyVx5T7OJe6jgm
[+]     #31: qXqeN8rR9g3vGBC5SNriUwe8KilrIU0R
[+]     #32: nxTlpPL88qoSRpfJWYdk0dHfTn1Y3mP1
[+]     #33: MOJDyqoLbIHoUpNreDUXHwsvJ8OCH9qg
[+]     #34: 34uOHadBAFvslwaJY6Kdq7AzJ6AFSPXM
[+]     #35: EXaT568QESzlVjYU1pjQENpMXy7qzuqX
[+]     #36: 2ESzWkblV1unRFZTavYKo9jT2HD6zDB5
[+]     #37: E3CCo36S7IlnJDCoI15eR8aRewZlTg3d
[+]     #38: C3F3m4qlsK7Xnm6KvimfyBO7NcvYik5u
[+]     #39: flTDjMXSK0DGCakF2a9GAEgIAQkMwy8Q
[+]     #40: NE6Y1DhvBl9c6s7SDrHkO0HIiOgWzZYJ
[+]     #41: vuUtBqiN6I4eJdeRBiamjiyUJvoWazij
[+]     #42: TGSRK9rVcH8Z7CN03j1tx6tqfK7rFheK
[+]     #43: hGtuwlJqu0v49GrrFkqJsfjpaFmQK0qv
[+]     #44: Oab8Ukhf4F2owFwdhzb9xwvg9Bnt3Wp6
[+]     #45: 0zrMTGICBbkYDCFHiyvH1N6SQiwdLKob
[+]     #46: oz4BdU3Yf4zLSQKVHFA1lAArgl7BJ8aC
[+]     #47: lz1W04LzQH4rQ6c4V42oWpPbFiXpoNzW
[+]     #48: lP7rg4GuNYlCdlKnmNQtXtmrdUUy2sPG
[+]     #49: 5CLjB3Jp7TDRYQWzMVSRtW9NFgRhOv2y
[+] ================ Decrypting Matryoshka #50 ================
[+] Loading resources from matryoshkas/matryoshka_49.dll ...
[+] Done. Writing license to 'license.bin' ...
[+] Program finished successfully. Bye bye :)

real    26m33.750s
user    26m31.109s
sys 0m2.376s

$ cat license.bin 
M0Oo8zjHkcPSWFzCxmw6jrj1RgNPucTHnE0OSzTLiLdrMGsKxaP34YlM8LHyOVtB41PDnuoUhyOZQKi3VX9VBpSN1BwNwGgxYoGsu8zPTrtnnJaYUgs63QFnztGi9jb3mpkxi4CzyLpaplSNfCsiXPKcfgxmDNbefLMBmmOnGopH5ro5neXyk5XluG3MbAJwShXHN8qMc6UziZc5RtGnUMZt3JQSZmPUiQRXaq0qMGx56kRI3acoaASBfRKU9SklXShPoGDfsDGzSnVkFC8KjLrVPSFJvQqJjPXuUkfonwGxayY4l4mUZegwQaf4HYYFnZh0RIr3gJeDTNzft0hf7atapmHHEXDc8sVxrZ4p0HshMDnHD0us9WKc33OoQCAc8iiOy81uP5b5slU7HQ0sKaqoXxNsaIBAVqGeUSX9wZ4mup7ycXaCegjSwjdKLuxjSDORjMnc5IQ4EqLqStDNN4EvdoMWAlAgCLeloR0UCrASNtwNtGIYXokxEFiN0DjlKJtvgdSC5opwW6VFSWDiyAfIeq1l7QS22i1Q99efyBoFHtISp1qxyMIGNS6J4vTDXliSiSCD0L0w30mPcNtKGvVywYDasg73vSFPwBQXMlLicHX9PPCkW9o6b3fOfnqeoxBgg3YdQ6hPveSp6Xi5JEf4YrwwPHERCm7GwEiag3Z17NRj9M6dz96LMiUfXelXxJ63nXSQ0e9eELh5DyCU0nK7OKEfVT0fvoa5soVi7A5ABF1T7Wi0nMV15Fe7rT0OLV6UpefmBZD3JjAArjCvVXbHRYyZOuIf4qtihb4uCUCjFIprFfGr2LfBnnZghQskuavSfoRzMwRjQuDH5ubgWaNlBBMk5DrcFMNQl5KlqOmNEuB3yA1DYl1BAKu8eA3qKNVPPm4eaWAK0hYHPzYyDL187mwVm57DvTsab5bGTfzZlSPIdnXFTai2Nl218tQBxc1xVHRKLSOfVhvVu6QyVx5T7OJe6jgmqXqeN8rR9g3vGBC5SNriUwe8KilrIU0RnxTlpPL88qoSRpfJWYdk0dHfTn1Y3mP1MOJDyqoLbIHoUpNreDUXHwsvJ8OCH9qg34uOHadBAFvslwaJY6Kdq7AzJ6AFSPXMEXaT568QESzlVjYU1pjQENpMXy7qzuqX2ESzWkblV1unRFZTavYKo9jT2HD6zDB5E3CCo36S7IlnJDCoI15eR8aRewZlTg3dC3F3m4qlsK7Xnm6KvimfyBO7NcvYik5uflTDjMXSK0DGCakF2a9GAEgIAQkMwy8QNE6Y1DhvBl9c6s7SDrHkO0HIiOgWzZYJvuUtBqiN6I4eJdeRBiamjiyUJvoWazijTGSRK9rVcH8Z7CN03j1tx6tqfK7rFheKhGtuwlJqu0v49GrrFkqJsfjpaFmQK0qvOab8Ukhf4F2owFwdhzb9xwvg9Bnt3Wp60zrMTGICBbkYDCFHiyvH1N6SQiwdLKoboz4BdU3Yf4zLSQKVHFA1lAArgl7BJ8aClz1W04LzQH4rQ6c4V42oWpPbFiXpoNzWlP7rg4GuNYlCdlKnmNQtXtmrdUUy2sPG5CLjB3Jp7TDRYQWzMVSRtW9NFgRhOv2y
"""
# ----------------------------------------------------------------------------------------
