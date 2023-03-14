#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# HXP 2022 - yor (Misc 116)
# ----------------------------------------------------------------------------------------
import random
import socket
import binascii


greets = [
    "Herzlich willkommen! Der Schlüssel ist {0}, und die Flagge lautet {1}.",
    "Bienvenue! Le clé est {0}, et le drapeau est {1}.",
    "Hartelĳk welkom! De sleutel is {0}, en de vlag luidt {1}.",
    "ようこそ！鍵は{0}、旗は{1}です。",
    "歡迎！鑰匙是{0}，旗幟是{1}。",
    "Witamy! Niestety nie mówię po polsku...",
]


# ----------------------------------------------------------------------------------------
def get_cipher_local(g=-1, key=''):
    """Challenge encryption algorithm."""
    # flag = open('flag.txt').read().strip()
    flag = 'hxp{' + 'A'*42 + '}'  # Use a dummy flag instead.
    assert set(flag.encode()) <= set(range(0x20,0x7f))

    if not key:
        key = bytes(random.randrange(256) for _ in range(16))

    hello = (greets[g] if g >= 0 else random.choice(greets)).format(key.hex(), flag).encode()
    output = bytes(y | key[i%len(key)] for i,y in enumerate(hello))

    # print(output.hex())
    return output #.hex()


# ----------------------------------------------------------------------------------------
def get_cipher():
    """Gets a ciphertext from the remote server."""
    sock = socket.create_connection(('167.235.26.48', 10101))
    cipher = sock.recv(1024)
    sock.close()

    return binascii.unhexlify(cipher.strip())


# ----------------------------------------------------------------------------------------
def crack_flag_bits(cipher, g, rec_flag):
    """Cracks the key from the `ciphertext` and recovers as many flag bits possible.

    We use a *3* step approach:
        1. We know the first characters from the plaintext. Use the 0 bits from plaintext
           to recover key bits.
        2. Substitute the recovered key digits back to the plaintext. Known plaintext now
           is larger.
        3. Repeat steps (1) and (2) until no new key bits are found.
        4. Use the cracked key to recover flag bits. A key bit of 0 reveals a bit from the
           flag.
        5. Substitute the already found flag characters back to the plaintext as well, to
           get even more know characters.
        6. Repeat as many times needed using different keys.
    """
    # Replace characters we don't know with '~' so we can ignore them.  
    # We also know how flag starts and ends.
    plain = greets[g].format('~'*32, 'hxp{' + rec_flag[4:-1] + '}' ).encode()
    assert len(cipher) == len(plain)
    

    # Find interesting locations of the plaintext.
    key_st   = plain.find(b'~'*32)*8     # Key start
    key_en   = key_st + 32*8             # Key end
    flag_st  = plain.find(b'hxp{')*8     # Flag start
    flag_en  = flag_st + len(rec_flag)*8 # Flag end    
    key_pos  = plain.find(b'~'*32)       # Key start (in bytes)
    flag_pos = plain.find(b'hxp{')       # Flag start (in bytes)
    
    blacklist = ([key_pos  + x for x in range(32)] +
                 [flag_pos + x for x in range(len(rec_flag))])

    # --------------------------------------------------------------------------
    # Step 1: Recover the key from the ciphertext.
    #
    # First we use the initially known characters from the plaintext, to recover
    # as many bits from the key as we can. For any full digit (4 bits) that we
    # recover from the key, we substitute it back to the plaintext. The new
    # plaintext now contains more known characters, so we repeat the whole
    # process to recover even more bits from the key. We repeat until now new
    # key bits are found.
    # --------------------------------------------------------------------------
    unknown_key_bits = 128
    for q in range(999):
        plain_bin  = ''.join(format((i), '08b') for i in plain)
        cipher_bin = ''.join(format((i), '08b') for i in cipher)

        # ----------------------------------------------------------------------
        # Step 1a: Use the known part of the plaintext to recover key bits from
        #         the ciphertext.
        # ----------------------------------------------------------------------
        # Initially all characters from the key are unknown
        key = ['?']*(16*8)
        for i, (p, c) in enumerate(zip(plain_bin, cipher_bin)):
            if ((i // 8) in blacklist):
                continue  # Ignore locations marked with '~'.

            # We have OR. If the plaintext bit is 0, we know a bit from the key.
            if p == '0':
                key[i % len(key)] = c

        # ----------------------------------------------------------------------
        # Step 1b: Replace the recovered key digits back to the known plaintext.
        # ----------------------------------------------------------------------    
        new_plain = list(plain)
        for i, d in enumerate(range(0, len(key), 4)):  # Iterate over digits.
            digit = ''.join(key[d:d + 4])
            if '?' in digit:
                continue    # There are missing bits from the digit.

            if new_plain[key_pos + i] == ord('~'):
                new_plain[key_pos + i] = ord(f'{int(digit, 2):1x}')

                blacklist.remove(key_pos + i)
            else:
                # The recovered digit should be consistent with the previously recovered ones.
                assert new_plain[key_pos + i] == ord(f'{int(digit, 2):1x}')
            
        # Update plaintext (we know more characters from it now).
        plain = bytes(new_plain)        
        print(f"[+] Unknown key bits: {key.count('?')}. Plaintext: {plain!r}")

        if unknown_key_bits == 0 or unknown_key_bits == key.count('?'):            
            break  # Nothing new found. Stop.

        unknown_key_bits = key.count('?')
    
    # --------------------------------------------------------------------------
    # Step 2: Use the cracked key to find characters from the flag.
    # --------------------------------------------------------------------------
    cracked_flag = ''
    for i, c in enumerate(cipher_bin):    
        if key[i % len(key)] == '0':
            cracked_flag += c
        else:
            cracked_flag += '?'

    return cracked_flag[flag_st:flag_en]

        
# ----------------------------------------------------------------------------------------
def get_greets_from_len(cipher, flag_len):
    """Finds the greet that corresponds to the ciphertext."""
    for i, g in enumerate(greets):
        greet_i = g.format('~'*32, 'hxp{'+'~'*(flag_len - 5)+'}').encode()
        if len(greet_i) == len(cipher): 
            return i

    raise Exception(f'Cannot find length for: {cipher}')


# ----------------------------------------------------------------------------------------
def flag_bits_to_str(flag_bits, detail=False):
    """Converts a list of bits to an ASCII string."""    
    flag = ''
    for i in range(0, len(flag_bits), 8):
        flag_byte = flag_bits[i:i+8]

        if '?' in flag_byte:
            # There are bits missing. Replace them with zeros and add a warning.
            nxt = chr(int(flag_byte.replace('?', '0'), 2)) + ' ?'
            flag += '~'
        else:
            # We know this character for sure
            nxt = chr(int(flag_byte, 2))
            flag += nxt

        if detail:
            print(f'[+] {flag_byte} ~> {nxt!r}')

    return flag


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] yor crack started.')

    # --------------------------------------------------------------------------
    print('[+] Computing flag length ...')    
    # Get a bunch of ciphertexts ...
    # The ciphertext with the max length *should* correspond to greets[0].    
    lens = [len(get_cipher()) for i in range(10)]
    max_len = max(lens)

    print(f'[+] Got ciphertext lengths:', lens)

    # Get length of greets[0] with a 0-length flag and subtract it from `max_len`.
    zero_len = len(greets[0].format((b'k'*16).hex(), '').encode())    
    flag_len = max_len - zero_len
    
    print(f'[+] Flag length: {flag_len}')

    # flag length should be: 47
    assert flag_len == 47

    # --------------------------------------------------------------------------
    # Flag in binary format. Initially all bits are unknown so we set them to '?'.
    flag_bits = ['?']*(8*flag_len)
    rec_flag = 'hxp{' + '~'*42 + '}'

    # Get a lot of ciphertexts.
    for i in range(999):
        print(f"[+] {'='*32} Iteration #{i} {'='*32}")

        # Get a ciphertext from server (or local).
        #cipher = get_cipher_local()
        cipher = get_cipher()
        
        g = get_greets_from_len(cipher, flag_len)
        print(f'[+] Ciphertext of length: {len(cipher)} ~> greets[{g}]')

        if len(cipher) == 41:
            print('[+] Skipping greets[5] ...')
            continue

        # Recover as many bits from the flag as you can.
        # Use the already found characters from the flag to find even more.
        rec_bits = crack_flag_bits(cipher, g, rec_flag)

        # Add the recovered bits to the flag.
        print(f'[+] Recovered bits: {rec_bits}')
        for j, r in enumerate(rec_bits):
            if r != '?':
                flag_bits[j] = r

        print(f"[+] Total unknown flag bits: {flag_bits.count('?')}")

        rec_flag = flag_bits_to_str(''.join(flag_bits), detail=True)
        print(f'[+] Recovered flag: {rec_flag!r}')

        if flag_bits.count('?') == 0:
            print(f'[+] All flag bits found! Final Flag: {rec_flag}')
            break

    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
r"""
ispo@ispo-glaptop2:~/ctf/hxp_2022/yor$ time ./yor_crack.py 
[+] yor crack started.
[+] Computing flag length ...
[+] Got ciphertext lengths: [112, 112, 123, 118, 131, 41, 41, 123, 41, 144]
[+] Flag length: 47
[+] ================================ Iteration #0 ================================
[+] Ciphertext of length: 123 ~> greets[1]
[+] Unknown key bits: 27. Plaintext: b'Bienvenue! Le cl\xc3\xa9 est ~~~~~4~~~1~~~5~~~4~2~a41~~~b~f~~, et le drapeau est hxp{~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~}.'
[+] Unknown key bits: 22. Plaintext: b'Bienvenue! Le cl\xc3\xa9 est db~~~4~~~1~~~5~~~4~2~a41~7~b~f~~, et le drapeau est hxp{~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~}.'
[+] Unknown key bits: 22. Plaintext: b'Bienvenue! Le cl\xc3\xa9 est db~~~4~~~1~~~5~~~4~2~a41~7~b~f~~, et le drapeau est hxp{~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~}.'
[+] Recovered bits: 0?10100?01?11???01?1?0???1??????0?????1???1??0??????100?????1?110???0??101?0010?0??10?0??0??0?1??1??1?0?00?10?11????11?101?0?1?00?11000?01?10???01?1?1???1??????0?????0???0??0??????111?????1?010???0??001?1111?0??11?0??0??0?0??1??0?0?01?11?11????00?100?1?1?00?10111?01?11???01?0?0???0??????0?????1???1??0??????111?????1?010???0??001?1001?0??11?1??0??1?1??0??1?1?00?11?11????11?1
[+] Total unknown flag bits: 207
[+] 0?10100? ~> '( ?'
[+] 01?11??? ~> 'X ?'
[+] 01?1?0?? ~> 'P ?'
[+] ?1?????? ~> '@ ?'
[+] 0?????1? ~> '\x02 ?'
[+] ??1??0?? ~> '  ?'
[+] ????100? ~> '\x08 ?'
[+] ????1?11 ~> '\x0b ?'
[+] 0???0??1 ~> '\x01 ?'
[+] 01?0010? ~> 'D ?'
[+] 0??10?0? ~> '\x10 ?'
[+] ?0??0?1? ~> '\x02 ?'
[+] ?1??1?0? ~> 'H ?'
[+] 00?10?11 ~> '\x13 ?'
[+] ????11?1 ~> '\r ?'
[+] 01?0?1?0 ~> 'D ?'
[+] 0?11000? ~> '0 ?'
[+] 01?10??? ~> 'P ?'
[+] 01?1?1?? ~> 'T ?'
[+] ?1?????? ~> '@ ?'
[+] 0?????0? ~> '\x00 ?'
[+] ??0??0?? ~> '\x00 ?'
[+] ????111? ~> '\x0e ?'
[+] ????1?01 ~> '\t ?'
[+] 0???0??0 ~> '\x00 ?'
[+] 01?1111? ~> '^ ?'
[+] 0??11?0? ~> '\x18 ?'
[+] ?0??0?0? ~> '\x00 ?'
[+] ?1??0?0? ~> '@ ?'
[+] 01?11?11 ~> '[ ?'
[+] ????00?1 ~> '\x01 ?'
[+] 00?1?1?0 ~> '\x14 ?'
[+] 0?10111? ~> '. ?'
[+] 01?11??? ~> 'X ?'
[+] 01?0?0?? ~> '@ ?'
[+] ?0?????? ~> '\x00 ?'
[+] 0?????1? ~> '\x02 ?'
[+] ??1??0?? ~> '  ?'
[+] ????111? ~> '\x0e ?'
[+] ????1?01 ~> '\t ?'
[+] 0???0??0 ~> '\x00 ?'
[+] 01?1001? ~> 'R ?'
[+] 0??11?1? ~> '\x1a ?'
[+] ?0??1?1? ~> '\n ?'
[+] ?0??1?1? ~> '\n ?'
[+] 00?11?11 ~> '\x1b ?'
[+] ????11?1 ~> '\r ?'
[+] Recovered flag: '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~'
[+] ================================ Iteration #1 ================================
[+] Ciphertext of length: 131 ~> greets[2]
[+] Unknown key bits: 27. Plaintext: b'Hartel\xc4\xb3k welkom! De sleutel is 92~d12~~~9~4~~~f~c~8~~~~~3~~~~~f, en de vlag luidt hxp{~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~}.'
[+] Unknown key bits: 23. Plaintext: b'Hartel\xc4\xb3k welkom! De sleutel is 92~d12~3~9~4~~~f~c~8~~~~~3~~~~~f, en de vlag luidt hxp{~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~}.'
[+] Unknown key bits: 23. Plaintext: b'Hartel\xc4\xb3k welkom! De sleutel is 92~d12~3~9~4~~~f~c~8~~~~~3~~~~~f, en de vlag luidt hxp{~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~}.'
[+] Recovered bits: ?1??10??01???00?0???0?00???1?????1?1????0?????0001?1?0010????1??00?1??0????001???????1?00????11??????????01?00?101????1?011?01?0?0??00??01???01?0???1?11???1?????0?1????0?????1001?1?1110????0??01?0??1????111???????0?10????00??????????10?11?101????1?001?01?0?1??11??01???11?0???1?00???1?????1?1????0?????1101?1?1110????0??00?1??0????100???????1?10????11??????????01?11?101????0?
[+] Total unknown flag bits: 113
[+] 0110100? ~> 'h ?'
[+] 01?1100? ~> 'X ?'
[+] 01?10000 ~> 'P ?'
[+] ?1?1???? ~> 'P ?'
[+] 01?1??1? ~> 'R ?'
[+] 0?1??000 ~> '  ?'
[+] 01?11001 ~> 'Y ?'
[+] 0???1111 ~> '\x0f ?'
[+] 00?10?01 ~> '\x11 ?'
[+] 01?0010? ~> 'D ?'
[+] 0??10100 ~> '\x14 ?'
[+] 00??011? ~> '\x06 ?'
[+] ?1??1?0? ~> 'H ?'
[+] 00110011 ~> '3'
[+] 01??1111 ~> 'O ?'
[+] 011001?0 ~> 'd ?'
[+] 0011000? ~> '0 ?'
[+] 01?1001? ~> 'R ?'
[+] 01?11111 ~> '_ ?'
[+] ?1?1???? ~> 'P ?'
[+] 00?1??0? ~> '\x10 ?'
[+] 0?0??010 ~> '\x02 ?'
[+] 01?11111 ~> '_ ?'
[+] 0???1001 ~> '\t ?'
[+] 01?00?10 ~> 'B ?'
[+] 01?1111? ~> '^ ?'
[+] 0??11001 ~> '\x19 ?'
[+] 00??000? ~> '\x00 ?'
[+] ?1??0?0? ~> '@ ?'
[+] 01011111 ~> '_'
[+] 01??0011 ~> 'C ?'
[+] 001101?0 ~> '4 ?'
[+] 0110111? ~> 'n ?'
[+] 01?1111? ~> '^ ?'
[+] 01?01000 ~> 'H ?'
[+] ?0?1???? ~> '\x10 ?'
[+] 01?1??1? ~> 'R ?'
[+] 0?1??011 ~> '# ?'
[+] 01?11111 ~> '_ ?'
[+] 0???1001 ~> '\t ?'
[+] 00?10?00 ~> '\x10 ?'
[+] 01?1001? ~> 'R ?'
[+] 0??11111 ~> '\x1f ?'
[+] 00??111? ~> '\x0e ?'
[+] ?0??1?1? ~> '\n ?'
[+] 00111111 ~> '?'
[+] 01??1101 ~> 'M ?'
[+] Recovered flag: '~~~~~~~~~~~~~3~~~~~~~~~~~~~~~_~~~~~~~~~~~~~~~?~'
[+] ================================ Iteration #2 ================================
[+] Ciphertext of length: 118 ~> greets[3]
[+] Unknown key bits: 30. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xaf~~~a~6~~~3~~~b~~~~~~~~~~~~~e~~~~\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{~~~~~~~~~3~~~~~~~~~~~~~~~_~~~~~~~~~~~~~~~?}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 23. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xaf1~~ad6~~~3~~~b~~19~~c0~~~~~ef~~~\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{~~~~~~~~~3~~~~~~~~~~~~~~~_~~~~~~~~~~~~~~~?}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 16. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xaf1~aad6~~~3e53b~~19bcc0~~~~~ef~~~\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{~~~~~~~~~3~~~~~~~~~~~~~~~_~~~~~~~~~~~~~~~?}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 13. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xaf1~aad6~~~3e53b3e19bcc0~~~~~ef~~~\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{~~~~~~~~~3~~~~~~~~~~~~~~~_~~~~~~~~~~~~~~~?}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 11. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xaf1~aad69~c3e53b3e19bcc0~~~~~ef~~~\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{~~~~~~~~~3~~~~~~~~~~~~~~~_~~~~~~~~~~~~~~~?}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 9. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xaf1~aad69~c3e53b3e19bcc0e~~~~ef~~~\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{~~~~~~~~~3~~~~~~~~~~~~~~~_~~~~~~~~~~~~~~~?}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 9. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xaf1~aad69~c3e53b3e19bcc0e~~~~ef~~~\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{~~~~~~~~~3~~~~~~~~~~~~~~~_~~~~~~~~~~~~~~~?}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Recovered bits: ????????0???100?011?000??1?1?0?1??0?0??1?11?100???0110?????11?1?00???1??01?????1011??10??0????11??001100???1????????1????1?????0????????0???001?010?111??1?1?0?0??1?0??0?10?001???0111?????01?0?01???1??01?????1011??00??0????00??110101???1????????0????0?????0????????0???111?011?100??0?1?1?0??1?0??0?01?001???0111?????11?0?00???0??01?????0001??11??0????11??111111???1????????1???
[+] Total unknown flag bits: 56
[+] 0110100? ~> 'h ?'
[+] 01?1100? ~> 'X ?'
[+] 01110000 ~> 'p'
[+] ?1?1?0?1 ~> 'Q ?'
[+] 01010?11 ~> 'S ?'
[+] 011?1000 ~> 'h ?'
[+] 01011001 ~> 'Y'
[+] 0??11111 ~> '\x1f ?'
[+] 00?10101 ~> '\x15 ?'
[+] 01?00101 ~> 'E ?'
[+] 01110100 ~> 't'
[+] 00??0111 ~> '\x07 ?'
[+] ?1001100 ~> 'L ?'
[+] 00110011 ~> '3'
[+] 01??1111 ~> 'O ?'
[+] 011001?0 ~> 'd ?'
[+] 0011000? ~> '0 ?'
[+] 01?1001? ~> 'R ?'
[+] 01011111 ~> '_'
[+] ?1?1?0?0 ~> 'P ?'
[+] 00110?00 ~> '0 ?'
[+] 010?0010 ~> 'B ?'
[+] 01011111 ~> '_'
[+] 0??01001 ~> '\t ?'
[+] 01?00110 ~> 'F ?'
[+] 01?11111 ~> '_ ?'
[+] 01111001 ~> 'y'
[+] 00??0000 ~> '\x00 ?'
[+] ?1110101 ~> 'u ?'
[+] 01011111 ~> '_'
[+] 01??0011 ~> 'C ?'
[+] 001101?0 ~> '4 ?'
[+] 0110111? ~> 'n ?'
[+] 01?1111? ~> '^ ?'
[+] 01101000 ~> 'h'
[+] ?0?1?1?0 ~> '\x14 ?'
[+] 01110?10 ~> 'r ?'
[+] 001?0011 ~> '# ?'
[+] 01011111 ~> '_'
[+] 0??11001 ~> '\x19 ?'
[+] 00?10000 ~> '\x10 ?'
[+] 01?10010 ~> 'R ?'
[+] 00111111 ~> '?'
[+] 00??1111 ~> '\x0f ?'
[+] ?0111111 ~> '? ?'
[+] 00111111 ~> '?'
[+] 01??1101 ~> 'M ?'
[+] Recovered flag: '~~p~~~Y~~~t~~3~~~~_~~~_~~~y~~_~~~~h~~~_~~~?~~?~'
[+] ================================ Iteration #3 ================================
[+] Ciphertext of length: 123 ~> greets[1]
[+] Unknown key bits: 27. Plaintext: b'Bienvenue! Le cl\xc3\xa9 est ~~~~~d~~~a~~~9~~~0~e~113~~~8~8~~, et le drapeau est hxp{~~Y~~~t~~3~~~~_~~~_~~~y~~_~~~~h~~~_~~~?~~?}.'
[+] Unknown key bits: 23. Plaintext: b'Bienvenue! Le cl\xc3\xa9 est ~e~~~d~~~a~~~9~~~0~e~113~2~8~8~~, et le drapeau est hxp{~~Y~~~t~~3~~~~_~~~_~~~y~~_~~~~h~~~_~~~?~~?}.'
[+] Unknown key bits: 22. Plaintext: b'Bienvenue! Le cl\xc3\xa9 est de~~~d~~~a~~~9~~~0~e~113~2~8~8~~, et le drapeau est hxp{~~Y~~~t~~3~~~~_~~~_~~~y~~_~~~~h~~~_~~~?~~?}.'
[+] Unknown key bits: 22. Plaintext: b'Bienvenue! Le cl\xc3\xa9 est de~~~d~~~a~~~9~~~0~e~113~2~8~8~~, et le drapeau est hxp{~~Y~~~t~~3~~~~_~~~_~~~y~~_~~~~h~~~_~~~?~~?}.'
[+] Recovered bits: 011?10???1??10?001???00001?1?0110??????1??1????0?1?1?00????1??1?0???0?01?????1?10??10??00????11??1????00????0011?1?????10???011?001?00???1??00?001???11101?1?0000??????0??0????0?1?1?11????0??0?0???0?10?????1?10??11??10????00??1????01????1111?1?????10???010?011?11???1??11?101???00000?1?1000??????0??1????1?1?1?11????1??0?0???0?00?????0?00??11??10????11??0????11????1111?1?????1
[+] Total unknown flag bits: 45
[+] 0110100? ~> 'h ?'
[+] 01?11000 ~> 'X ?'
[+] 01110000 ~> 'p'
[+] 01?1?011 ~> 'S ?'
[+] 01010?11 ~> 'S ?'
[+] 011?1000 ~> 'h ?'
[+] 01011001 ~> 'Y'
[+] 0??11111 ~> '\x1f ?'
[+] 00?10101 ~> '\x15 ?'
[+] 01?00101 ~> 'E ?'
[+] 01110100 ~> 't'
[+] 00??0111 ~> '\x07 ?'
[+] ?1001100 ~> 'L ?'
[+] 00110011 ~> '3'
[+] 01??1111 ~> 'O ?'
[+] 01100110 ~> 'f'
[+] 0011000? ~> '0 ?'
[+] 01?10010 ~> 'R ?'
[+] 01011111 ~> '_'
[+] 01?1?000 ~> 'P ?'
[+] 00110?00 ~> '0 ?'
[+] 010?0010 ~> 'B ?'
[+] 01011111 ~> '_'
[+] 0??01001 ~> '\t ?'
[+] 01?00110 ~> 'F ?'
[+] 01?11111 ~> '_ ?'
[+] 01111001 ~> 'y'
[+] 00??0000 ~> '\x00 ?'
[+] ?1110101 ~> 'u ?'
[+] 01011111 ~> '_'
[+] 01??0011 ~> 'C ?'
[+] 00110100 ~> '4'
[+] 0110111? ~> 'n ?'
[+] 01?11111 ~> '_ ?'
[+] 01101000 ~> 'h'
[+] 00?1?100 ~> '\x14 ?'
[+] 01110?10 ~> 'r ?'
[+] 001?0011 ~> '# ?'
[+] 01011111 ~> '_'
[+] 0??11001 ~> '\x19 ?'
[+] 00?10000 ~> '\x10 ?'
[+] 01?10010 ~> 'R ?'
[+] 00111111 ~> '?'
[+] 00??1111 ~> '\x0f ?'
[+] ?0111111 ~> '? ?'
[+] 00111111 ~> '?'
[+] 01??1101 ~> 'M ?'
[+] Recovered flag: '~~p~~~Y~~~t~~3~f~~_~~~_~~~y~~_~4~~h~~~_~~~?~~?~'
[+] ================================ Iteration #4 ================================
[+] Ciphertext of length: 118 ~> greets[3]
[+] Unknown key bits: 30. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xaf~~~8~1~~~9~~~2~~~~~~~~~~~~~4~~~~\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{~~Y~~~t~~3~f~~_~~~_~~~y~~_~4~~h~~~_~~~?~~?}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 23. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xafdb~871~~~9~~~2~~8b~~b~~~~~~46~~~\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{~~Y~~~t~~3~f~~_~~~_~~~y~~_~4~~h~~~_~~~?~~?}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 17. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xafdb5871~~~92c32~~8bd~b~~~~~~46~~~\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{~~Y~~~t~~3~f~~_~~~_~~~y~~_~4~~h~~~_~~~?~~?}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 13. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xafdb5871~~~92c32d78bd~b~~~~~~46~~2\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{~~Y~~~t~~3~f~~_~~~_~~~y~~_~4~~h~~~_~~~?~~?}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 10. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xafdb5871c2392c32d78bd~b~~~~~~46~~2\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{~~Y~~~t~~3~f~~_~~~_~~~y~~_~4~~h~~~_~~~?~~?}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 6. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xafdb5871c2392c32d78bd~b~9~89~46~~2\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{~~Y~~~t~~3~f~~_~~~_~~~y~~_~4~~h~~~_~~~?~~?}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 6. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xafdb5871c2392c32d78bd~b~9~89~46~~2\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{~~Y~~~t~~3~f~~_~~~_~~~y~~_~4~~h~~~_~~~?~~?}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Recovered bits: 0??0?0???1??10?0??1??0??0?1??0110???011???1010?001???00?01?1??1100??01?1??1?0????111?1????1?01???1???10??01??????101?11?01?00?100??1?0???1??00?0??0??1??0?0??0000???000???0100?001???11?01?0??0101??01?0??0?1????111?0????1?00???1???10??10??????100?01?00?10?000??0?1???1??11?1??1??0??0?1??1000???011???1100?101???11?01?1??0100??00?0??0?0????011?1????1?11???0???11??01??????111?10?
[+] Total unknown flag bits: 21
[+] 0110100? ~> 'h ?'
[+] 01?11000 ~> 'X ?'
[+] 01110000 ~> 'p'
[+] 0111?011 ~> 's ?'
[+] 01010111 ~> 'W'
[+] 01101000 ~> 'h'
[+] 01011001 ~> 'Y'
[+] 01?11111 ~> '_ ?'
[+] 00?10101 ~> '\x15 ?'
[+] 01100101 ~> 'e'
[+] 01110100 ~> 't'
[+] 001?0111 ~> "' ?"
[+] ?1001100 ~> 'L ?'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01100110 ~> 'f'
[+] 0011000? ~> '0 ?'
[+] 01?10010 ~> 'R ?'
[+] 01011111 ~> '_'
[+] 0101?000 ~> 'P ?'
[+] 00110000 ~> '0'
[+] 01010010 ~> 'R'
[+] 01011111 ~> '_'
[+] 01?01001 ~> 'I ?'
[+] 01?00110 ~> 'F ?'
[+] 01011111 ~> '_'
[+] 01111001 ~> 'y'
[+] 001?0000 ~> '  ?'
[+] ?1110101 ~> 'u ?'
[+] 01011111 ~> '_'
[+] 01000011 ~> 'C'
[+] 00110100 ~> '4'
[+] 0110111? ~> 'n ?'
[+] 01?11111 ~> '_ ?'
[+] 01101000 ~> 'h'
[+] 0011?100 ~> '4 ?'
[+] 01110110 ~> 'v'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01?11001 ~> 'Y ?'
[+] 00?10000 ~> '\x10 ?'
[+] 01010010 ~> 'R'
[+] 00111111 ~> '?'
[+] 001?1111 ~> '/ ?'
[+] ?0111111 ~> '? ?'
[+] 00111111 ~> '?'
[+] 01111101 ~> '}'
[+] Recovered flag: '~~p~WhY~~et~~3_f~~_~0R_~~_y~~_C4~~h~v3_~~R?~~?}'
[+] ================================ Iteration #5 ================================
[+] Ciphertext of length: 144 ~> greets[0]
[+] Unknown key bits: 21. Plaintext: b'Herzlich willkommen! Der Schl\xc3\xbcssel ist ~5~c~d~3~2~d~d~e~79a~~~7~~3e~~~2, und die Flagge lautet hxp{WhY~~et~~3_f~~_~0R_~~_y~~_C4~~h~v3_~~R?~~?}.'
[+] Unknown key bits: 19. Plaintext: b'Herzlich willkommen! Der Schl\xc3\xbcssel ist ~5~cdd~3~2~d~d~e~79a~~~7~~3e~~~2, und die Flagge lautet hxp{WhY~~et~~3_f~~_~0R_~~_y~~_C4~~h~v3_~~R?~~?}.'
[+] Unknown key bits: 19. Plaintext: b'Herzlich willkommen! Der Schl\xc3\xbcssel ist ~5~cdd~3~2~d~d~e~79a~~~7~~3e~~~2, und die Flagge lautet hxp{WhY~~et~~3_f~~_~0R_~~_y~~_C4~~h~v3_~~R?~~?}.'
[+] Recovered bits: 0???1?0?01?1??00??1???0??1??10??0???01?10?10??0????1??0??1?1???10??10????11??1?1????01?????10???0??01?0?00?????1???11?11????01?00???0?0?01?1??10??0???1??1??10??0???00?00?01??1????1??1??1?0???10??00????10??1?1????10?????10???0??10?0?01?????1???00?11????01?00???1?1?01?1??11??1???0??0??01??0???01?00?11??1????1??1??1?1???10??10????10??0?0????11?????11???0??11?1?00?????1???11?01
[+] Total unknown flag bits: 12
[+] 0110100? ~> 'h ?'
[+] 01?11000 ~> 'X ?'
[+] 01110000 ~> 'p'
[+] 01111011 ~> '{'
[+] 01010111 ~> 'W'
[+] 01101000 ~> 'h'
[+] 01011001 ~> 'Y'
[+] 01?11111 ~> '_ ?'
[+] 00?10101 ~> '\x15 ?'
[+] 01100101 ~> 'e'
[+] 01110100 ~> 't'
[+] 00110111 ~> '7'
[+] 01001100 ~> 'L'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01100110 ~> 'f'
[+] 0011000? ~> '0 ?'
[+] 01?10010 ~> 'R ?'
[+] 01011111 ~> '_'
[+] 01011000 ~> 'X'
[+] 00110000 ~> '0'
[+] 01010010 ~> 'R'
[+] 01011111 ~> '_'
[+] 01?01001 ~> 'I ?'
[+] 01?00110 ~> 'F ?'
[+] 01011111 ~> '_'
[+] 01111001 ~> 'y'
[+] 00110000 ~> '0'
[+] 01110101 ~> 'u'
[+] 01011111 ~> '_'
[+] 01000011 ~> 'C'
[+] 00110100 ~> '4'
[+] 0110111? ~> 'n ?'
[+] 01?11111 ~> '_ ?'
[+] 01101000 ~> 'h'
[+] 00110100 ~> '4'
[+] 01110110 ~> 'v'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01?11001 ~> 'Y ?'
[+] 00?10000 ~> '\x10 ?'
[+] 01010010 ~> 'R'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 01111101 ~> '}'
[+] Recovered flag: '~~p{WhY~~et7L3_f~~_X0R_~~_y0u_C4~~h4v3_~~R????}'
[+] ================================ Iteration #6 ================================
[+] Ciphertext of length: 123 ~> greets[1]
[+] Unknown key bits: 27. Plaintext: b'Bienvenue! Le cl\xc3\xa9 est ~~~~~8~~~0~~~1~~~b~5~0bb~~~1~4~~, et le drapeau est hxp{WhY~~et7L3_f~~_X0R_~~_y0u_C4~~h4v3_~~R????}.'
[+] Unknown key bits: 22. Plaintext: b'Bienvenue! Le cl\xc3\xa9 est 00~~~8~~~0~~~1~~~b~5~0bb~4~1~4~~, et le drapeau est hxp{WhY~~et7L3_f~~_X0R_~~_y0u_C4~~h4v3_~~R????}.'
[+] Unknown key bits: 21. Plaintext: b'Bienvenue! Le cl\xc3\xa9 est 00~~~8~~~0~~~1~9~b~5~0bb~4~1~4~~, et le drapeau est hxp{WhY~~et7L3_f~~_X0R_~~_y0u_C4~~h4v3_~~R????}.'
[+] Unknown key bits: 21. Plaintext: b'Bienvenue! Le cl\xc3\xa9 est 00~~~8~~~0~~~1~9~b~5~0bb~4~1~4~~, et le drapeau est hxp{WhY~~et7L3_f~~_X0R_~~_y0u_C4~~h4v3_~~R????}.'
[+] Recovered bits: ?1???0??01??1?000???000????11?11????0??10110100001??????0??1?111???10?0?01??01010??10?0000??011????0?10??????0??????1?1??1?00110?0???0??01??0?100???111????11?00????0??00101001001??????0??0?001???00?1?01??11110??11?0100??000????1?10??????1??????0?1??0?10100?1???1??01??1?110???100????10?00????0??00011001101??????0??1?001???10?0?01??00100??11?1100??111????1?11??????1??????1?0?
[+] Total unknown flag bits: 12
[+] 0110100? ~> 'h ?'
[+] 01?11000 ~> 'X ?'
[+] 01110000 ~> 'p'
[+] 01111011 ~> '{'
[+] 01010111 ~> 'W'
[+] 01101000 ~> 'h'
[+] 01011001 ~> 'Y'
[+] 01?11111 ~> '_ ?'
[+] 00?10101 ~> '\x15 ?'
[+] 01100101 ~> 'e'
[+] 01110100 ~> 't'
[+] 00110111 ~> '7'
[+] 01001100 ~> 'L'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01100110 ~> 'f'
[+] 0011000? ~> '0 ?'
[+] 01?10010 ~> 'R ?'
[+] 01011111 ~> '_'
[+] 01011000 ~> 'X'
[+] 00110000 ~> '0'
[+] 01010010 ~> 'R'
[+] 01011111 ~> '_'
[+] 01?01001 ~> 'I ?'
[+] 01?00110 ~> 'F ?'
[+] 01011111 ~> '_'
[+] 01111001 ~> 'y'
[+] 00110000 ~> '0'
[+] 01110101 ~> 'u'
[+] 01011111 ~> '_'
[+] 01000011 ~> 'C'
[+] 00110100 ~> '4'
[+] 0110111? ~> 'n ?'
[+] 01?11111 ~> '_ ?'
[+] 01101000 ~> 'h'
[+] 00110100 ~> '4'
[+] 01110110 ~> 'v'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01?11001 ~> 'Y ?'
[+] 00?10000 ~> '\x10 ?'
[+] 01010010 ~> 'R'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 01111101 ~> '}'
[+] Recovered flag: '~~p{WhY~~et7L3_f~~_X0R_~~_y0u_C4~~h4v3_~~R????}'
[+] ================================ Iteration #7 ================================
[+] Ciphertext of length: 123 ~> greets[1]
[+] Unknown key bits: 27. Plaintext: b'Bienvenue! Le cl\xc3\xa9 est ~~~~~f~~~0~~~2~~~d~e~2e7~~~c~f~~, et le drapeau est hxp{WhY~~et7L3_f~~_X0R_~~_y0u_C4~~h4v3_~~R????}.'
[+] Unknown key bits: 22. Plaintext: b'Bienvenue! Le cl\xc3\xa9 est 07~~~f~~~0~~~2~~~d~e~2e7~3~c~f~~, et le drapeau est hxp{WhY~~et7L3_f~~_X0R_~~_y0u_C4~~h4v3_~~R????}.'
[+] Unknown key bits: 21. Plaintext: b'Bienvenue! Le cl\xc3\xa9 est 07~~~f~~~0~~~2~f~d~e~2e7~3~c~f~~, et le drapeau est hxp{WhY~~et7L3_f~~_X0R_~~_y0u_C4~~h4v3_~~R????}.'
[+] Unknown key bits: 21. Plaintext: b'Bienvenue! Le cl\xc3\xa9 est 07~~~f~~~0~~~2~f~d~e~2e7~3~c~f~~, et le drapeau est hxp{WhY~~et7L3_f~~_X0R_~~_y0u_C4~~h4v3_~~R????}.'
[+] Recovered bits: ???01???01?110???1?1??0001?1???????????101101???0????00?01?1????0??1???10??001010??10?0?00??01?101??????00????1?0??1???1????01?0???10???01?100???1?1??1101?1???????????001010???0????11?01?0????0??0???00??111110??11?0?00??00?001??????01????1?0??0???1????01?0???01???01?111???1?0??0000?1???????????000110???0????11?01?1????0??1???00??100100??11?1?00??11?100??????00????1?0??1???1
[+] Total unknown flag bits: 12
[+] 0110100? ~> 'h ?'
[+] 01?11000 ~> 'X ?'
[+] 01110000 ~> 'p'
[+] 01111011 ~> '{'
[+] 01010111 ~> 'W'
[+] 01101000 ~> 'h'
[+] 01011001 ~> 'Y'
[+] 01?11111 ~> '_ ?'
[+] 00?10101 ~> '\x15 ?'
[+] 01100101 ~> 'e'
[+] 01110100 ~> 't'
[+] 00110111 ~> '7'
[+] 01001100 ~> 'L'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01100110 ~> 'f'
[+] 0011000? ~> '0 ?'
[+] 01?10010 ~> 'R ?'
[+] 01011111 ~> '_'
[+] 01011000 ~> 'X'
[+] 00110000 ~> '0'
[+] 01010010 ~> 'R'
[+] 01011111 ~> '_'
[+] 01?01001 ~> 'I ?'
[+] 01?00110 ~> 'F ?'
[+] 01011111 ~> '_'
[+] 01111001 ~> 'y'
[+] 00110000 ~> '0'
[+] 01110101 ~> 'u'
[+] 01011111 ~> '_'
[+] 01000011 ~> 'C'
[+] 00110100 ~> '4'
[+] 0110111? ~> 'n ?'
[+] 01?11111 ~> '_ ?'
[+] 01101000 ~> 'h'
[+] 00110100 ~> '4'
[+] 01110110 ~> 'v'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01?11001 ~> 'Y ?'
[+] 00?10000 ~> '\x10 ?'
[+] 01010010 ~> 'R'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 01111101 ~> '}'
[+] Recovered flag: '~~p{WhY~~et7L3_f~~_X0R_~~_y0u_C4~~h4v3_~~R????}'
[+] ================================ Iteration #8 ================================
[+] Ciphertext of length: 131 ~> greets[2]
[+] Unknown key bits: 27. Plaintext: b'Hartel\xc4\xb3k welkom! De sleutel is c0~f89~~~e~6~~~8~f~7~~~~~d~~~~~c, en de vlag luidt hxp{WhY~~et7L3_f~~_X0R_~~_y0u_C4~~h4v3_~~R????}.'
[+] Unknown key bits: 24. Plaintext: b'Hartel\xc4\xb3k welkom! De sleutel is c0~f89~~~e~6~~~8~f~7~~~~~d~~~~~c, en de vlag luidt hxp{WhY~~et7L3_f~~_X0R_~~_y0u_C4~~h4v3_~~R????}.'
[+] Unknown key bits: 24. Plaintext: b'Hartel\xc4\xb3k welkom! De sleutel is c0~f89~~~e~6~~~8~f~7~~~~~d~~~~~c, en de vlag luidt hxp{WhY~~et7L3_f~~_X0R_~~_y0u_C4~~h4v3_~~R????}.'
[+] Recovered bits: ????1?0?0??1???0???10??0????1?110??1?1110??0????????1???0??1?1??0???0???01????0????1???00??1?1?????0??00??110011?????????110?11?????0?0?0??1???0???11??1????1?000??1?0000??1????????1???0??0?0??0???0???01????1????1???10??1?0?????1??01??011111?????????011?10?????1?1?0??1???1???01??0????0?000??1?1100??1????????1???0??1?0??0???0???01????1????1???10??1?1?????1??11??111111????????
[+] Total unknown flag bits: 12
[+] 0110100? ~> 'h ?'
[+] 01?11000 ~> 'X ?'
[+] 01110000 ~> 'p'
[+] 01111011 ~> '{'
[+] 01010111 ~> 'W'
[+] 01101000 ~> 'h'
[+] 01011001 ~> 'Y'
[+] 01?11111 ~> '_ ?'
[+] 00?10101 ~> '\x15 ?'
[+] 01100101 ~> 'e'
[+] 01110100 ~> 't'
[+] 00110111 ~> '7'
[+] 01001100 ~> 'L'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01100110 ~> 'f'
[+] 0011000? ~> '0 ?'
[+] 01?10010 ~> 'R ?'
[+] 01011111 ~> '_'
[+] 01011000 ~> 'X'
[+] 00110000 ~> '0'
[+] 01010010 ~> 'R'
[+] 01011111 ~> '_'
[+] 01?01001 ~> 'I ?'
[+] 01?00110 ~> 'F ?'
[+] 01011111 ~> '_'
[+] 01111001 ~> 'y'
[+] 00110000 ~> '0'
[+] 01110101 ~> 'u'
[+] 01011111 ~> '_'
[+] 01000011 ~> 'C'
[+] 00110100 ~> '4'
[+] 0110111? ~> 'n ?'
[+] 01?11111 ~> '_ ?'
[+] 01101000 ~> 'h'
[+] 00110100 ~> '4'
[+] 01110110 ~> 'v'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01?11001 ~> 'Y ?'
[+] 00?10000 ~> '\x10 ?'
[+] 01010010 ~> 'R'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 01111101 ~> '}'
[+] Recovered flag: '~~p{WhY~~et7L3_f~~_X0R_~~_y0u_C4~~h4v3_~~R????}'
[+] ================================ Iteration #9 ================================
[+] Ciphertext of length: 131 ~> greets[2]
[+] Unknown key bits: 27. Plaintext: b'Hartel\xc4\xb3k welkom! De sleutel is 0b~556~~~6~c~~~1~8~7~~~~~a~~~~~0, en de vlag luidt hxp{WhY~~et7L3_f~~_X0R_~~_y0u_C4~~h4v3_~~R????}.'
[+] Unknown key bits: 24. Plaintext: b'Hartel\xc4\xb3k welkom! De sleutel is 0b~556~~~6~c~~~1~8~7~~~c~a~~~~~0, en de vlag luidt hxp{WhY~~et7L3_f~~_X0R_~~_y0u_C4~~h4v3_~~R????}.'
[+] Unknown key bits: 24. Plaintext: b'Hartel\xc4\xb3k welkom! De sleutel is 0b~556~~~6~c~~~1~8~7~~~c~a~~~~~0, en de vlag luidt hxp{WhY~~et7L3_f~~_X0R_~~_y0u_C4~~h4v3_~~R????}.'
[+] Recovered bits: 01?01?00???11??0?1?1??00???11?1?0??1011?0??0?000?1?11????????1????????01?1?0?1?1???1??000??1????01?011000011?0??01?11?1?0?1?0??000?10?00???10??0?1?1??11???11?0?0??1000?0??1?010?1?11????????0????????10?1?1?1?1???1??010??1????01?101010101?1??01?00?1?0?1?0??001?01?10???11??1?1?0??00???10?0?0??1011?0??1?011?1?11????????0????????00?1?1?0?0???1??110??1????00?111110011?1??01?11?0?
[+] Total unknown flag bits: 9
[+] 01101000 ~> 'h'
[+] 01?11000 ~> 'X ?'
[+] 01110000 ~> 'p'
[+] 01111011 ~> '{'
[+] 01010111 ~> 'W'
[+] 01101000 ~> 'h'
[+] 01011001 ~> 'Y'
[+] 01?11111 ~> '_ ?'
[+] 00?10101 ~> '\x15 ?'
[+] 01100101 ~> 'e'
[+] 01110100 ~> 't'
[+] 00110111 ~> '7'
[+] 01001100 ~> 'L'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01100110 ~> 'f'
[+] 00110000 ~> '0'
[+] 01?10010 ~> 'R ?'
[+] 01011111 ~> '_'
[+] 01011000 ~> 'X'
[+] 00110000 ~> '0'
[+] 01010010 ~> 'R'
[+] 01011111 ~> '_'
[+] 01?01001 ~> 'I ?'
[+] 01?00110 ~> 'F ?'
[+] 01011111 ~> '_'
[+] 01111001 ~> 'y'
[+] 00110000 ~> '0'
[+] 01110101 ~> 'u'
[+] 01011111 ~> '_'
[+] 01000011 ~> 'C'
[+] 00110100 ~> '4'
[+] 01101110 ~> 'n'
[+] 01?11111 ~> '_ ?'
[+] 01101000 ~> 'h'
[+] 00110100 ~> '4'
[+] 01110110 ~> 'v'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01?11001 ~> 'Y ?'
[+] 00?10000 ~> '\x10 ?'
[+] 01010010 ~> 'R'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 01111101 ~> '}'
[+] Recovered flag: 'h~p{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}'
[+] ================================ Iteration #10 ================================
[+] Ciphertext of length: 118 ~> greets[3]
[+] Unknown key bits: 30. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xaf~~~0~a~~~d~~~1~~~~~~~~~~~~~f~~~~\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 22. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xaf55~03a~~~d~~~1~~3e~~d~~~~~~fb3~~\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 15. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xaf55603a~~~dfcf1~~3e77d~~~~~~fb3~~\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 11. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xaf55603a~~~dfcf1f13e77d~~~~~~fb3~e\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 8. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xaf55603af73dfcf1f13e77d~~~~~~fb3~e\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 4. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xaf55603af73dfcf1f13e77d~efb~~fb3~e\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 3. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xaf55603af73dfcf1f13e77d~efb0~fb3~e\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 3. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xaf55603af73dfcf1f13e77d~efb0~fb3~e\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Recovered bits: ?1??10?????1???00?1?0?0?0??1101101???1?1????1???01????0???????11????010?????010?01?????00???0?????0?1??????1?????1??11110????????0??00?????1???00?0?1?1?0??1100000???0?0????0???01????1???????01????011?????111?01?????10???0?????1?0??????1?????1??00110????????1??11?????1???10?1?1?0?0??1010001???1?0????0???01????1???????01????000?????001?00?????10???1?????1?1??????1?????1??1101
[+] Total unknown flag bits: 9
[+] 01101000 ~> 'h'
[+] 01?11000 ~> 'X ?'
[+] 01110000 ~> 'p'
[+] 01111011 ~> '{'
[+] 01010111 ~> 'W'
[+] 01101000 ~> 'h'
[+] 01011001 ~> 'Y'
[+] 01?11111 ~> '_ ?'
[+] 00?10101 ~> '\x15 ?'
[+] 01100101 ~> 'e'
[+] 01110100 ~> 't'
[+] 00110111 ~> '7'
[+] 01001100 ~> 'L'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01100110 ~> 'f'
[+] 00110000 ~> '0'
[+] 01?10010 ~> 'R ?'
[+] 01011111 ~> '_'
[+] 01011000 ~> 'X'
[+] 00110000 ~> '0'
[+] 01010010 ~> 'R'
[+] 01011111 ~> '_'
[+] 01?01001 ~> 'I ?'
[+] 01?00110 ~> 'F ?'
[+] 01011111 ~> '_'
[+] 01111001 ~> 'y'
[+] 00110000 ~> '0'
[+] 01110101 ~> 'u'
[+] 01011111 ~> '_'
[+] 01000011 ~> 'C'
[+] 00110100 ~> '4'
[+] 01101110 ~> 'n'
[+] 01?11111 ~> '_ ?'
[+] 01101000 ~> 'h'
[+] 00110100 ~> '4'
[+] 01110110 ~> 'v'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01?11001 ~> 'Y ?'
[+] 00?10000 ~> '\x10 ?'
[+] 01010010 ~> 'R'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 01111101 ~> '}'
[+] Recovered flag: 'h~p{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}'
[+] ================================ Iteration #11 ================================
[+] Ciphertext of length: 112 ~> greets[4]
[+] Unknown key bits: 41. Plaintext: b'\xe6\xad\xa1\xe8\xbf\x8e\xef\xbc\x81\xe9\x91\xb0\xe5\x8c\x99\xe6\x98\xaf~4~~~~~~~~~~~~~~~~~~~~~e~1~1~7~~\xef\xbc\x8c\xe6\x97\x97\xe5\xb9\x9f\xe6\x98\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x80\x82'
[+] Unknown key bits: 34. Plaintext: b'\xe6\xad\xa1\xe8\xbf\x8e\xef\xbc\x81\xe9\x91\xb0\xe5\x8c\x99\xe6\x98\xaf~4~~~~~6~~~~~~~~~~~~~~~e~141~76~\xef\xbc\x8c\xe6\x97\x97\xe5\xb9\x9f\xe6\x98\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x80\x82'
[+] Unknown key bits: 31. Plaintext: b'\xe6\xad\xa1\xe8\xbf\x8e\xef\xbc\x81\xe9\x91\xb0\xe5\x8c\x99\xe6\x98\xaf34~~~~~6~~~~~~~~~~~d~~~e9141~76~\xef\xbc\x8c\xe6\x97\x97\xe5\xb9\x9f\xe6\x98\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x80\x82'
[+] Unknown key bits: 27. Plaintext: b'\xe6\xad\xa1\xe8\xbf\x8e\xef\xbc\x81\xe9\x91\xb0\xe5\x8c\x99\xe6\x98\xaf34~~~~~6~~6~~~~~~~~d~~~e9141~76~\xef\xbc\x8c\xe6\x97\x97\xe5\xb9\x9f\xe6\x98\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x80\x82'
[+] Unknown key bits: 27. Plaintext: b'\xe6\xad\xa1\xe8\xbf\x8e\xef\xbc\x81\xe9\x91\xb0\xe5\x8c\x99\xe6\x98\xaf34~~~~~6~~6~~~~~~~~d~~~e9141~76~\xef\xbc\x8c\xe6\x97\x97\xe5\xb9\x9f\xe6\x98\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x80\x82'
[+] Recovered bits: ?11?1???0??110?001??0?00???1??1?0??101??01??1??0?1????0?0??11???????0????11???????1101???0????1?010?1???00?????1?10?111?0?10011??01?0???0??100?001??1?11???1??0?0??100??01??0??0?1????1?0??01???????0????10???????1110???0????0?011?0???01?????1?10?001?0?11010??11?1???0??111?101??1?00???1??0?0??101??00??0??1?1????1?0??11???????0????10???????1111???0????1?001?1???00?????1?11?110?
[+] Total unknown flag bits: 9
[+] 01101000 ~> 'h'
[+] 01?11000 ~> 'X ?'
[+] 01110000 ~> 'p'
[+] 01111011 ~> '{'
[+] 01010111 ~> 'W'
[+] 01101000 ~> 'h'
[+] 01011001 ~> 'Y'
[+] 01?11111 ~> '_ ?'
[+] 00?10101 ~> '\x15 ?'
[+] 01100101 ~> 'e'
[+] 01110100 ~> 't'
[+] 00110111 ~> '7'
[+] 01001100 ~> 'L'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01100110 ~> 'f'
[+] 00110000 ~> '0'
[+] 01?10010 ~> 'R ?'
[+] 01011111 ~> '_'
[+] 01011000 ~> 'X'
[+] 00110000 ~> '0'
[+] 01010010 ~> 'R'
[+] 01011111 ~> '_'
[+] 01?01001 ~> 'I ?'
[+] 01?00110 ~> 'F ?'
[+] 01011111 ~> '_'
[+] 01111001 ~> 'y'
[+] 00110000 ~> '0'
[+] 01110101 ~> 'u'
[+] 01011111 ~> '_'
[+] 01000011 ~> 'C'
[+] 00110100 ~> '4'
[+] 01101110 ~> 'n'
[+] 01?11111 ~> '_ ?'
[+] 01101000 ~> 'h'
[+] 00110100 ~> '4'
[+] 01110110 ~> 'v'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01?11001 ~> 'Y ?'
[+] 00?10000 ~> '\x10 ?'
[+] 01010010 ~> 'R'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 01111101 ~> '}'
[+] Recovered flag: 'h~p{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}'
[+] ================================ Iteration #12 ================================
[+] Ciphertext of length: 123 ~> greets[1]
[+] Unknown key bits: 27. Plaintext: b'Bienvenue! Le cl\xc3\xa9 est ~~~~~1~~~6~~~0~~~1~c~d4a~~~7~e~~, et le drapeau est hxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}.'
[+] Unknown key bits: 23. Plaintext: b'Bienvenue! Le cl\xc3\xa9 est 9~~~~1~~~6~~~0~~~1~c~d4a~c~7~e~~, et le drapeau est hxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}.'
[+] Unknown key bits: 22. Plaintext: b'Bienvenue! Le cl\xc3\xa9 est 9~~~~1~~~6~~~0~5~1~c~d4a~c~7~e~~, et le drapeau est hxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}.'
[+] Unknown key bits: 22. Plaintext: b'Bienvenue! Le cl\xc3\xa9 est 9~~~~1~~~6~~~0~5~1~c~d4a~c~7~e~~, et le drapeau est hxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}.'
[+] Recovered bits: 0?10?0?00??1??00???10??????????1???1??1??11????0????10??????111?0??10????1?00??10?????0??0?10111????1?0?0???001?0?????11?1?0??1?0?11?0?00??1??10???11??????????0???1??0??10????0????11??????100?0??00????1?11??10?????0??0?10000????0?0?0???111?0?????11?0?1??0?0?10?1?00??1??11???01??????????0???1??1??01????1????11??????100?0??10????1?10??00?????1??0?11111????1?1?0???111?0?????01
[+] Total unknown flag bits: 9
[+] 01101000 ~> 'h'
[+] 01?11000 ~> 'X ?'
[+] 01110000 ~> 'p'
[+] 01111011 ~> '{'
[+] 01010111 ~> 'W'
[+] 01101000 ~> 'h'
[+] 01011001 ~> 'Y'
[+] 01?11111 ~> '_ ?'
[+] 00?10101 ~> '\x15 ?'
[+] 01100101 ~> 'e'
[+] 01110100 ~> 't'
[+] 00110111 ~> '7'
[+] 01001100 ~> 'L'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01100110 ~> 'f'
[+] 00110000 ~> '0'
[+] 01?10010 ~> 'R ?'
[+] 01011111 ~> '_'
[+] 01011000 ~> 'X'
[+] 00110000 ~> '0'
[+] 01010010 ~> 'R'
[+] 01011111 ~> '_'
[+] 01?01001 ~> 'I ?'
[+] 01?00110 ~> 'F ?'
[+] 01011111 ~> '_'
[+] 01111001 ~> 'y'
[+] 00110000 ~> '0'
[+] 01110101 ~> 'u'
[+] 01011111 ~> '_'
[+] 01000011 ~> 'C'
[+] 00110100 ~> '4'
[+] 01101110 ~> 'n'
[+] 01?11111 ~> '_ ?'
[+] 01101000 ~> 'h'
[+] 00110100 ~> '4'
[+] 01110110 ~> 'v'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01?11001 ~> 'Y ?'
[+] 00?10000 ~> '\x10 ?'
[+] 01010010 ~> 'R'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 01111101 ~> '}'
[+] Recovered flag: 'h~p{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}'
[+] ================================ Iteration #13 ================================
[+] Ciphertext of length: 118 ~> greets[3]
[+] Unknown key bits: 30. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xaf~~~3~8~~~9~~~c~~~~~~~~~~~~~f~~~~\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 23. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xafc8~368~~~9~~~c~~d~~~df~~~~~f7~~~\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 16. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xafc87368~~~920cc~~d~bbdf~~~~~f7~~~\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 12. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xafc87368~~~920cc12d~bbdf~~~~~f7~~d\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 10. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xafc87368c~d920cc12d~bbdf~~~~~f7~~d\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 8. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xafc87368c~d920cc12d~bbdff~~~~f7~~d\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 7. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xafc87368c~d920cc12d~bbdff2~~~f7~~d\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 5. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xafc87368c~d920cc12d~bbdff2aa~f7~~d\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 5. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xafc87368c~d920cc12d~bbdff2aa~f7~~d\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~~et7L3_f0~_X0R_~~_y0u_C4n~h4v3_~~R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Recovered bits: 0????????1????0???11?0000???10??0??1?111??10100???0??00?01?11111??11??01011?01?1??1?0??0?0???1????0?????????00?1?1?1?1?1????????0????????1????1???01?1110???10??0??1?000??01001???0??11?01?01001??00??10010?11?1??1?1??1?0???0????1?????????11?1?1?0?0?1????????0????????1????1???10?0000???01??0??1?110??11001???0??11?01?11001??11??00010?00?0??1?1??1?0???1????1?????????11?1?1?1?1?1
[+] Total unknown flag bits: 6
[+] 01101000 ~> 'h'
[+] 01?11000 ~> 'X ?'
[+] 01110000 ~> 'p'
[+] 01111011 ~> '{'
[+] 01010111 ~> 'W'
[+] 01101000 ~> 'h'
[+] 01011001 ~> 'Y'
[+] 01?11111 ~> '_ ?'
[+] 00110101 ~> '5'
[+] 01100101 ~> 'e'
[+] 01110100 ~> 't'
[+] 00110111 ~> '7'
[+] 01001100 ~> 'L'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01100110 ~> 'f'
[+] 00110000 ~> '0'
[+] 01?10010 ~> 'R ?'
[+] 01011111 ~> '_'
[+] 01011000 ~> 'X'
[+] 00110000 ~> '0'
[+] 01010010 ~> 'R'
[+] 01011111 ~> '_'
[+] 01?01001 ~> 'I ?'
[+] 01000110 ~> 'F'
[+] 01011111 ~> '_'
[+] 01111001 ~> 'y'
[+] 00110000 ~> '0'
[+] 01110101 ~> 'u'
[+] 01011111 ~> '_'
[+] 01000011 ~> 'C'
[+] 00110100 ~> '4'
[+] 01101110 ~> 'n'
[+] 01?11111 ~> '_ ?'
[+] 01101000 ~> 'h'
[+] 00110100 ~> '4'
[+] 01110110 ~> 'v'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01?11001 ~> 'Y ?'
[+] 00110000 ~> '0'
[+] 01010010 ~> 'R'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 01111101 ~> '}'
[+] Recovered flag: 'h~p{WhY~5et7L3_f0~_X0R_~F_y0u_C4n~h4v3_~0R????}'
[+] ================================ Iteration #14 ================================
[+] Ciphertext of length: 41 ~> greets[5]
[+] Skipping greets[5] ...
[+] ================================ Iteration #15 ================================
[+] Ciphertext of length: 118 ~> greets[3]
[+] Unknown key bits: 30. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xaf~~~e~1~~~f~~~9~~~~~~~~~~~~~1~~~~\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~5et7L3_f0~_X0R_~F_y0u_C4n~h4v3_~0R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 23. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xafa~~ec1~~~f~~~9~~da~~6~~~~~~1ed~~\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~5et7L3_f0~_X0R_~F_y0u_C4n~h4v3_~0R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 17. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xafa~3ec1~~~f8aa9~~da9~6~~~~~~1ed~~\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~5et7L3_f0~_X0R_~F_y0u_C4n~h4v3_~0R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 14. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xafa~3ec1~~~f8aa96~da9~6~~~~~~1ed~d\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~5et7L3_f0~_X0R_~F_y0u_C4n~h4v3_~0R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 11. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xafa~3ec1552f8aa96~da9~6~~~~~~1ed~d\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~5et7L3_f0~_X0R_~F_y0u_C4n~h4v3_~0R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 8. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xafa~3ec1552f8aa96~da9~6~a~6~~1ed~d\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~5et7L3_f0~_X0R_~F_y0u_C4n~h4v3_~0R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Unknown key bits: 8. Plaintext: b'\xe3\x82\x88\xe3\x81\x86\xe3\x81\x93\xe3\x81\x9d\xef\xbc\x81\xe9\x8d\xb5\xe3\x81\xafa~3ec1552f8aa96~da9~6~a~6~~1ed~d\xe3\x80\x81\xe6\x97\x97\xe3\x81\xafhxp{WhY~5et7L3_f0~_X0R_~F_y0u_C4n~h4v3_~0R????}\xe3\x81\xa7\xe3\x81\x99\xe3\x80\x82'
[+] Recovered bits: ???0??0????1??0??1?1000?01?????1??01011?0?1?1?0?01?1?????101?1?1?0?1?10?0??001????1??1?0?01?????0??0??0??0?100??0??1?1???1??011????1??0????1??1??1?1111?01?????0??11000?0?0?0?1?01?1?????110?0?1?1?0?11?0??111????1??0?1?01?????0??1??0??1?111??0??0?0???0??010????0??1????1??1??1?0100?00?????0??11011?0?1?0?1?01?1?????101?0?1?0?1?00?0??100????1??1?1?01?????0??1??1??0?111??0??1?1??
[+] Total unknown flag bits: 3
[+] 01101000 ~> 'h'
[+] 01?11000 ~> 'X ?'
[+] 01110000 ~> 'p'
[+] 01111011 ~> '{'
[+] 01010111 ~> 'W'
[+] 01101000 ~> 'h'
[+] 01011001 ~> 'Y'
[+] 01011111 ~> '_'
[+] 00110101 ~> '5'
[+] 01100101 ~> 'e'
[+] 01110100 ~> 't'
[+] 00110111 ~> '7'
[+] 01001100 ~> 'L'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01100110 ~> 'f'
[+] 00110000 ~> '0'
[+] 01?10010 ~> 'R ?'
[+] 01011111 ~> '_'
[+] 01011000 ~> 'X'
[+] 00110000 ~> '0'
[+] 01010010 ~> 'R'
[+] 01011111 ~> '_'
[+] 01101001 ~> 'i'
[+] 01000110 ~> 'F'
[+] 01011111 ~> '_'
[+] 01111001 ~> 'y'
[+] 00110000 ~> '0'
[+] 01110101 ~> 'u'
[+] 01011111 ~> '_'
[+] 01000011 ~> 'C'
[+] 00110100 ~> '4'
[+] 01101110 ~> 'n'
[+] 01?11111 ~> '_ ?'
[+] 01101000 ~> 'h'
[+] 00110100 ~> '4'
[+] 01110110 ~> 'v'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01011001 ~> 'Y'
[+] 00110000 ~> '0'
[+] 01010010 ~> 'R'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 01111101 ~> '}'
[+] Recovered flag: 'h~p{WhY_5et7L3_f0~_X0R_iF_y0u_C4n~h4v3_Y0R????}'
[+] ================================ Iteration #16 ================================
[+] Ciphertext of length: 41 ~> greets[5]
[+] Skipping greets[5] ...
[+] ================================ Iteration #17 ================================
[+] Ciphertext of length: 41 ~> greets[5]
[+] Skipping greets[5] ...
[+] ================================ Iteration #18 ================================
[+] Ciphertext of length: 41 ~> greets[5]
[+] Skipping greets[5] ...
[+] ================================ Iteration #19 ================================
[+] Ciphertext of length: 112 ~> greets[4]
[+] Unknown key bits: 41. Plaintext: b'\xe6\xad\xa1\xe8\xbf\x8e\xef\xbc\x81\xe9\x91\xb0\xe5\x8c\x99\xe6\x98\xaf~f~~~~~~~~~~~~~~~~~~~~~8~3~0~a~~\xef\xbc\x8c\xe6\x97\x97\xe5\xb9\x9f\xe6\x98\xafhxp{WhY_5et7L3_f0~_X0R_iF_y0u_C4n~h4v3_Y0R????}\xe3\x80\x82'
[+] Unknown key bits: 33. Plaintext: b'\xe6\xad\xa1\xe8\xbf\x8e\xef\xbc\x81\xe9\x91\xb0\xe5\x8c\x99\xe6\x98\xaf~f~~~~~b~~~~~~~~~~~~~~~8~3c0~a0e\xef\xbc\x8c\xe6\x97\x97\xe5\xb9\x9f\xe6\x98\xafhxp{WhY_5et7L3_f0~_X0R_iF_y0u_C4n~h4v3_Y0R????}\xe3\x80\x82'
[+] Unknown key bits: 28. Plaintext: b'\xe6\xad\xa1\xe8\xbf\x8e\xef\xbc\x81\xe9\x91\xb0\xe5\x8c\x99\xe6\x98\xaf4f~~~~~b~~~~~~~~~~~2~~~8d3c0~a0e\xef\xbc\x8c\xe6\x97\x97\xe5\xb9\x9f\xe6\x98\xafhxp{WhY_5et7L3_f0~_X0R_iF_y0u_C4n~h4v3_Y0R????}\xe3\x80\x82'
[+] Unknown key bits: 21. Plaintext: b'\xe6\xad\xa1\xe8\xbf\x8e\xef\xbc\x81\xe9\x91\xb0\xe5\x8c\x99\xe6\x98\xaf4f~~~c~b~~f~~~~~~~~22a~8d3c0~a0e\xef\xbc\x8c\xe6\x97\x97\xe5\xb9\x9f\xe6\x98\xafhxp{WhY_5et7L3_f0~_X0R_iF_y0u_C4n~h4v3_Y0R????}\xe3\x80\x82'
[+] Unknown key bits: 15. Plaintext: b'\xe6\xad\xa1\xe8\xbf\x8e\xef\xbc\x81\xe9\x91\xb0\xe5\x8c\x99\xe6\x98\xaf4f~~~c~b~~f~5~f3~~~22a~8d3c0~a0e\xef\xbc\x8c\xe6\x97\x97\xe5\xb9\x9f\xe6\x98\xafhxp{WhY_5et7L3_f0~_X0R_iF_y0u_C4n~h4v3_Y0R????}\xe3\x80\x82'
[+] Unknown key bits: 13. Plaintext: b'\xe6\xad\xa1\xe8\xbf\x8e\xef\xbc\x81\xe9\x91\xb0\xe5\x8c\x99\xe6\x98\xaf4f~~~c~b~~f~5~f3~~~22a~8d3c03a0e\xef\xbc\x8c\xe6\x97\x97\xe5\xb9\x9f\xe6\x98\xafhxp{WhY_5et7L3_f0~_X0R_iF_y0u_C4n~h4v3_Y0R????}\xe3\x80\x82'
[+] Unknown key bits: 13. Plaintext: b'\xe6\xad\xa1\xe8\xbf\x8e\xef\xbc\x81\xe9\x91\xb0\xe5\x8c\x99\xe6\x98\xaf4f~~~c~b~~f~5~f3~~~22a~8d3c03a0e\xef\xbc\x8c\xe6\x97\x97\xe5\xb9\x9f\xe6\x98\xafhxp{WhY_5et7L3_f0~_X0R_iF_y0u_C4n~h4v3_Y0R????}\xe3\x80\x82'
[+] Recovered bits: 01???0?00111???00?11?????1?1?0??01?1??11?????0???101????????????0?1?01?1????01????1?0?0??0?101?101?0?1?0???1?011??0?11????10011000???0?00111???00?01?????1?1?0??00?1??00?????0???101????????????0?0?01?0????11????1?1?0??0?100?001?1?1?1???1?111??0?00????11010001???1?00101???10?10?????0?1?1??01?1??10?????0???101????????????0?1?00?0????00????1?1?1??0?111?100?1?1?1???1?111??1?11??
[+] Total unknown flag bits: 0
[+] 01101000 ~> 'h'
[+] 01111000 ~> 'x'
[+] 01110000 ~> 'p'
[+] 01111011 ~> '{'
[+] 01010111 ~> 'W'
[+] 01101000 ~> 'h'
[+] 01011001 ~> 'Y'
[+] 01011111 ~> '_'
[+] 00110101 ~> '5'
[+] 01100101 ~> 'e'
[+] 01110100 ~> 't'
[+] 00110111 ~> '7'
[+] 01001100 ~> 'L'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01100110 ~> 'f'
[+] 00110000 ~> '0'
[+] 01110010 ~> 'r'
[+] 01011111 ~> '_'
[+] 01011000 ~> 'X'
[+] 00110000 ~> '0'
[+] 01010010 ~> 'R'
[+] 01011111 ~> '_'
[+] 01101001 ~> 'i'
[+] 01000110 ~> 'F'
[+] 01011111 ~> '_'
[+] 01111001 ~> 'y'
[+] 00110000 ~> '0'
[+] 01110101 ~> 'u'
[+] 01011111 ~> '_'
[+] 01000011 ~> 'C'
[+] 00110100 ~> '4'
[+] 01101110 ~> 'n'
[+] 01011111 ~> '_'
[+] 01101000 ~> 'h'
[+] 00110100 ~> '4'
[+] 01110110 ~> 'v'
[+] 00110011 ~> '3'
[+] 01011111 ~> '_'
[+] 01011001 ~> 'Y'
[+] 00110000 ~> '0'
[+] 01010010 ~> 'R'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 00111111 ~> '?'
[+] 01111101 ~> '}'
[+] Recovered flag: 'hxp{WhY_5et7L3_f0r_X0R_iF_y0u_C4n_h4v3_Y0R????}'
[+] All flag bits found! Final Flag: hxp{WhY_5et7L3_f0r_X0R_iF_y0u_C4n_h4v3_Y0R????}
[+] Program finished. Bye bye :)

real    0m21.436s
user    0m0.143s
sys 0m0.019s
"""
# ----------------------------------------------------------------------------------------
