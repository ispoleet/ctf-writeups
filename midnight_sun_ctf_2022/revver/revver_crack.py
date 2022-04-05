#!/usr/bin/env python3
# ---------------------------------------------------------------------------------------
# Midnight Sun CTF 2022 - REVVER (RE 588)
# ---------------------------------------------------------------------------------------
import binascii
import socket
import re
import string
import capstone
import sys
import random
import zlib 


# Blacklisted constant strings in "data section" of the shellcode.
# We exclude these strings from our computations.
_RODATA_BLACKLIST = [
    '', 
    'swag.key',
    'Error! Could not open file\n',
    'recv failed',
    'accept failed',
    'Waiting for incoming connections...',
    'Could not create socket',
    'Connection accepted',
    'Client disconnected',
    'Bind failed',
    'flag.txt',
    '/midnightsunctf-2022/quals/revver/answer3.bin',
    'Error!\n',
    '%s',
    '\n',
    'Error! Not enough arguments\n'
]

# Lookup table for CRC32.
_CRC32_TBL = [
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
	0xe963a535, 0x9e6495a3,	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
	0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
	0xf3b97148, 0x84be41de,	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,	0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5,	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
	0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,	0x35b5a8fa, 0x42b2986c,
	0xdbbbc9d6, 0xacbcf940,	0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
	0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,	0x76dc4190, 0x01db7106,
	0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
	0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
	0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
	0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
	0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
	0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
	0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
	0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
	0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
	0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
	0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
	0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
	0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
	0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
	0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
	0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
	0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
	0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
	0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
	0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
]


# ---------------------------------------------------------------------------------------
# Helper Routines
# ---------------------------------------------------------------------------------------
def recv_until(*trg_strs):
    """Receive until you encounter any of the target string(s)."""
    recv_buf = bytes()
    while not any(trg in recv_buf for trg in trg_strs):
        recv_buf += sock.recv(8192)
        if len(recv_buf) > 65536:
            print('[!] Warning. Receiving buffer limit reached.')
            break

    return recv_buf


# ---------------------------------------------------------------------------------------
def parse_server_input(inp):
    """Parse server input and extract binary name and shellcode."""
    inp = inp.decode('utf-8')
    index, shellcode = None, None

    for line in inp.split('\n'):
        match = re.search(r'RANDOM BINARY (.*)', line)
        if match:
            index = match.group(1)            
        
        match = re.search(r'^([0-9a-f]+)$', line)
        if match:
            shellcode = binascii.unhexlify(match.group(1))

    return index, shellcode


# ---------------------------------------------------------------------------------------
def extract_const_strs_from_shellcode(shellcode):
    """Extract non-blacklisted constant strings, located at the end of the shellcode.

    There are two ways that a shellcode ends:

    A)  seg000:0000037B C9    leave
        seg000:0000037C 5F    pop     edi
        seg000:0000037D 5E    pop     esi
        seg000:0000037E 5B    pop     ebx
        seg000:0000037F C3    retn

    B)  seg000:0000059C C9    leave
        seg000:0000059D C3    retn

    We scan shellcode backwards until we hit the C9/C3 pattern.
    (we may be very unlucky that this pattern is part of a ciphertext; in that case
     just rerun the program ;)).
    """
    print('[+] Extracting constant strings from shellcode ...')
    data = []
    buf = ''

    for idx, char in reversed(list(enumerate(shellcode))):
        if char == 0xC3:
            # We hit a `retn` instrction. Scan backwards for `leave`.
            if shellcode[idx - 1] == 0xC9 or shellcode[idx - 4] == 0xC9:
                break
                
        if char == 0:
            data.append(buf[::-1]) # NULL byte found. Reverse string and add it to list.
            buf = ''
        else:
            buf += chr(char)

    if buf:
        data.append(buf[::-1])  # Add leftovers (if any).

    is_printable = lambda a: len(a) == len([c for c in a if c in string.printable])
    p, np = [], []

    # Look for black listed strings.
    for s in data:
        if s in _RODATA_BLACKLIST:
            print('[+] Found blacklisted string:', repr(s))
        elif is_printable(s):
            print('[+] Found printable string:', repr(s))
            p.append(s)
        else:
            print('[+] Found non-printable string:', repr(s))
            np.append(s)

    return p, np


# ---------------------------------------------------------------------------------------
def extract_const_from_insn(code, insn_regex, nearby=-1):
    """Extract a constant value from an assembly instruction."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    consts = []
    last_loc = -1

    for insn in md.disasm(code, 0):
        # NOTE: We can extract constant from `insn` fields. What we do is a bad way.
        match = re.search(insn_regex, insn.mnemonic + ' ' + insn.op_str)
        if match and (nearby < 0 or insn.address > nearby and (insn.address - nearby < 0x10)):
            # Assume we have only 1 group.
            const = int(match.group(1), 16)

            # All instructions should have some proximity.
            if insn.address - last_loc > 0x10:
                consts = []

            last_loc = insn.address        
            consts.append(const)

    return consts, last_loc


# ---------------------------------------------------------------------------------------
# Shellcode Categories
# ---------------------------------------------------------------------------------------
def const_str_in_rodata(shellcode):
    """The answer is simply a const, printable string in .rodata."""
    print('[+] Shellcode category: Const string in .rodata')
    p, _ = extract_const_strs_from_shellcode(shellcode)
    assert(len(p) == 1) # We should have exactly 1 non-blacklisted string.

    return p[0]


def crypto_in_insn(shellcode):
    """Answer is the XOR between the bytes of `mov` insructions with an 1-byte key."""
    print('[+] Shellcode category: Crypto in instructions')
    cipher, _ = extract_const_from_insn(shellcode, r'mov byte ptr \[ebp - .*\], [0x]*([0-9a-f]+)$')
    key,    _ = extract_const_from_insn(shellcode, r'xor cl, [0x]*([0-9a-f]+)$')
    assert(len(key) == 1)

    plain = [c ^ key[0] for c in cipher]
    print(f'[+] Plaintext: {plain}')

    return ''.join('%c' % p for p in plain)


def crypto_in_insn_word(shellcode):
    """Answer is the difference between the words of `mov` insructions."""
    print('[+] Shellcode category: Difference between words in instructions')
    nums, _ = extract_const_from_insn(shellcode, r'mov word ptr \[ebp - .*\], [0x]*([0-9a-f]+)$')
    
    print('[+] Total number of ciphers:', len(nums))
    
    plain = []
    for i in range(len(nums) >> 1):
        diff = (nums[(len(nums) >> 1) + i] - nums[i]) & 0xFFFF

        print('[+] Computing diff: %X - %X = %X' % (nums[(len(nums) >> 1) + i], nums[i], diff ))
        plain.append(diff >> 8)
        plain.append(diff & 0xFF)

    return ''.join('%c' % p for p in plain)


def rc4_decryption(shellcode):
    """The answer the rc4 decryption. printable key, non printalbe ciphertext."""
    print('[+] Shellcode category: RC4 decryption')
    p, np = extract_const_strs_from_shellcode(shellcode)
    assert(len(p) == 1)  # We should have exactly 1 key.
    key = p[0]

    # It's very unlikely to have a printable ciphertext/
    # (if this happens, just rerun the script).
    ciphertext = np[0]

    # if a ciphertext has a NULL byte, then we it will be split across `np` array. Concat.
    if len(np) > 1:
        print(f'[+] {len(np)} ciphertexts found. Merging ...')
        ciphertext = '\x00'.join(r for r in reversed(np))

    print('[+] RC4 decryption key:', key)
    print('[+] RC4 ciphertext:', '-'.join('%02X' % ord(c) for c in ciphertext))

    # NOTE: Crypto.Cipher.ARC4 seems to not give the expected result,
    # so we implement RC4 on our own.
    S = list(range(256))
    j = 0

    for i in range(256):
        j = (j + S[i] + ord(key[i % len(key)])) % 256
        S[i], S[j] = S[j], S[i]

    plaintext = ''
    i, j = 0, 0

    for c in ciphertext:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]

        plaintext += chr(ord(c) ^ K)

    print('[+] RC4 plaintext:', plaintext)

    return plaintext


def crack_single_crc32(curr_crc32, trg_crc32):
    """Cracks a single CRC32.

    We do the old-school approach (no Z3 solver).

    This function is based on:
        https://stackoverflow.com/questions/9285898/reversing-crc32/13394385#13394385

    Want to append bytes: X  Y  Z  W 
    Take for register  a3 a2 a1 a0  (a is the 'already calculated' crc for string)
    Note that a3 is the most significant byte and a0 the least.
     f is the wanted new CRC byte string, and xyzw is the modification pad

    I'll show it a little different way:
    a0 + X                  =(1)  points to  b3 b2 b1 b0  in table
    a1 + b0 + Y             =(2)  points to  c3 c2 c1 c0  in table
    a2 + b1 + c0 + Z        =(3)  points to  d3 d2 d1 d0  in table
    a3 + b2 + c1 + d0 + W   =(4)  points to  e4 e3 e2 e1  in table
         b3 + c2 + d1 + e0  =f0
              c3 + d2 + e1  =f1
                   d3 + e2  =f2
                        e3  =f3
        (1)  (2)  (3)  (4)
    (figure 4)

    This is reversed in the same way as the 16bit version.
    I shall give an example with real values.
    For the table values use the CRC-32 table in the appendix.
    
    Take for CRC register before, a3 a2 a1 a0 -> AB CD EF 66
    Take for CRC register after,  f3 f2 f1 f0 -> 56 33 14 78 (wanted value)
    Here we go:

    First byte of entries            entry   value
    e3=f3                     =56 -> 35h=(4) 56B3C423 for e3 e2 e1 e0
    d3=f2+e2      =33+B3      =E6 -> 4Fh=(3) E6635C01 for d3 d2 d1 d0
    c3=f1+e1+d2   =14+C4+63   =B3 -> F8h=(2) B3667A2E for c3 c2 c1 c0
    b3=f0+e0+d1+c2=78+23+5C+66=61 -> DEh=(1) 616BFFD3 for b3 b2 b1 b0

    Now we have all needed values, then
    X=(1)+         a0=         DE+66=B8
    Y=(2)+      b0+a1=      F8+D3+EF=C4
    Z=(3)+   c0+b1+a2=   4F+2E+FF+CD=53
    W=(4)+d0+c1+b2+a3=35+01+7A+6B+AB=8E
    (final computation)
    """
    get_bytes = lambda n : ((n & 0xFF000000) >> 24, (n & 0x00FF0000) >> 16,
                           (n & 0x0000FF00) >> 8,   (n & 0x000000FF))

    curr_crc32 = ~curr_crc32
    trg_crc32 = ~trg_crc32

    a3, a2, a1, a0 = get_bytes(curr_crc32)
    f3, f2, f1, f0 = get_bytes(trg_crc32)

    st = 0x0
    end = 0xff

    # Capture e3/e2/e1/e0/ (4) values.
    for i in range(st,end):
        if ((_CRC32_TBL[i] & 0xFF000000) == (trg_crc32 & 0xFF000000)):
            e3, e2, e1, e0 = get_bytes(_CRC32_TBL[i])
            four = i 
            break
            
    # d3=f2+e2      =33+B3      =E6 -> 4Fh=(3) E6635C01 for d3 d2 d1 d0
    d3 = f2^e2  # Lookup d3 and assign the values for d2/d1/d0/(3)
    for i in range(st, end):#($i = 0; $i < 256; $i++)
        if ((_CRC32_TBL[i] & 0xFF000000) == (d3 << 24)):
            _, d2, d1, d0 = get_bytes(_CRC32_TBL[i])
            three = i
            break
    
    # c3=f1+e1+d2   =14+C4+63   =B3 -> F8h=(2) B3667A2E for c3 c2 c1 c0
    c3 = f1^e1^d2;

    for i in range(st, end):#($i = 0; $i < 256; $i++)
        if ((_CRC32_TBL[i] & 0xFF000000) == (c3 << 24)):
            _, c2, c1, c0 = get_bytes(_CRC32_TBL[i])
            two = i
            break
    
    # b3=f0+e0+d1+c2=78+23+5C+66=61 -> DEh=(1) 616BFFD3 for b3 b2 b1 b0
    b3 = f0^e0^d1^c2;
    for i in range(st, end):
        if ((_CRC32_TBL[i] & 0xFF000000) == (b3 << 24)):
            _, b2, b1, b0 = get_bytes(_CRC32_TBL[i])
            one = i
            break
    '''
    Now we have all needed values, then
        X=(1)+         a0=         DE+66=B8
        Y=(2)+      b0+a1=      F8+D3+EF=C4
        Z=(3)+   c0+b1+a2=   4F+2E+FF+CD=53
        W=(4)+d0+c1+b2+a3=35+01+7A+6B+AB=8E

        (final computation)
    '''
    X = one ^ a0
    Y = two ^ b0 ^ a1
    Z = three ^ c0 ^ b1 ^ a2
    W = four ^ d0 ^ c1 ^ b2 ^ a3

    return [X, Y, Z, W]


def crc32_crack(shellcode):
    print('[+] Shellcode category: Crack CRC32')
    trg_crc, addr = extract_const_from_insn(shellcode, r'mov esi, 0x([0-9a-f]+)$')
    sz, _ = extract_const_from_insn(shellcode, r'push [0x]*([0-9a-f]+)$', addr)

    assert(len(trg_crc) == 1 and len(sz) == 1)

    trg_crc = trg_crc[-1]
    sz = sz[-1]

    print(f'[+] Target CRC32: {trg_crc:08X}h')
    print(f'[+] Input size: {sz}')

    for i in range(1048576):
        '''The server is not happy with non-ASCII answer when encoded to UTF-8:

        Traceback (most recent call last):
          File "./challenge.py", line 245, in <module>
            main()
          File "./challenge.py", line 241, in main
            play()
          File "./challenge.py", line 206, in play
            if len(xxx) == value[1] and value[0] == (zlib.crc32(bytes(xxx,'utf-8')) & 0xffffffff):
        UnicodeEncodeError: 'utf-8' codec can't encode character '\udca6' in position 21: surrogates not allowed

        
        Therefore the generated answer must be ASCII printable. So we generate
        random strings of size `sz - 4`, until the missing 4 bytes are also ASCII printable.
        '''
        rnd = ''.join(random.choices(string.ascii_uppercase + string.digits, k=sz-4))
        base = rnd.encode('utf-8')
        curr_crc = zlib.crc32(base)

        print('[+] Generating random string:', rnd)
        print(f'[+] Current CRC32: {curr_crc:08X}')

        crack = crack_single_crc32(curr_crc, trg_crc)
        print('[+] CRC32 successfully cracked:', '-'.join('%02X' % c for c in crack))

        # Build target input.        
        trg_inp = '%s%c%c%c%c' % (rnd, crack[0], crack[1], crack[2], crack[3])

        # If the `crack` is not printable ASCII, try again with another `rnd`.
        # All must be printable so we don't have unicode issues ;)
        if len([x for x in crack if x > 0x20 and x < 0x80]) == 4:
            new_crc = zlib.crc32(bytes(trg_inp, 'utf-8'))

            print('[+] Collison found:', repr(trg_inp))
            print(f'[+] Verifying CRC32: {new_crc:08X}')

            assert(new_crc == trg_crc)

            return trg_inp      

    print('[!] Error. CRC32 ASCII collision cannot be found')
    exit()


# ---------------------------------------------------------------------------------------
# Lambdas for the 20 different binaries
# (we only have 5 different binary types; each type appears 4 times)
# ---------------------------------------------------------------------------------------
one      = lambda shellcode: crypto_in_insn(shellcode)
two      = lambda shellcode: crc32_crack(shellcode)
three    = lambda shellcode: rc4_decryption(shellcode)
four     = lambda shellcode: crypto_in_insn_word(shellcode)
five     = lambda shellcode: const_str_in_rodata(shellcode)
six      = lambda shellcode: crypto_in_insn(shellcode)
seven    = lambda shellcode: crc32_crack(shellcode)
eight    = lambda shellcode: rc4_decryption(shellcode)
nine     = lambda shellcode: crypto_in_insn_word(shellcode)
ten      = lambda shellcode: const_str_in_rodata(shellcode)
eleven   = lambda shellcode: crypto_in_insn(shellcode)
twelve   = lambda shellcode: crc32_crack(shellcode)
thirteen = lambda shellcode: rc4_decryption(shellcode)
fourteen = lambda shellcode: crypto_in_insn_word(shellcode)
fiveteen = lambda shellcode: const_str_in_rodata(shellcode)
sixteen  = lambda shellcode: crypto_in_insn(shellcode)
seventeen= lambda shellcode: crc32_crack(shellcode)
eighteen = lambda shellcode: rc4_decryption(shellcode)
nineteen = lambda shellcode: crypto_in_insn_word(shellcode)
twenty   = lambda shellcode: const_str_in_rodata(shellcode)

    
# ---------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] REVVER simulator started.')

    if len(sys.argv) == 2:
        index = sys.argv[1]

        print('[+] Running in local mode for shellcode:', index)

        shellcode = open(f'shellcodes/{index}.sc', 'rb').read()
        answer = eval(f'{index}(shellcode)')

        print('[+] Answer:', repr(answer))
        exit()

    # ---------------------------------------------------------------
    # Remote Mode
    # ---------------------------------------------------------------
    sock = socket.create_connection(('revver-01.hfsc.tf', 3320))

    recv_until(b' 2) Play')
    sock.send(b'2\n')
    
    for i in range(1, 21+1):
        print(f'================ {i} ================')
        serv_inp = recv_until(b'ANSWER: ', b'YOU FAIL', b'midnight{')

        if b'FAIL' in serv_inp:
            print('[!] Error. Invalid answer!')
            print('[+] Please re-run program.')
            exit()
        elif b'midnight{' in serv_inp:
            print('[+] Got Flag!', serv_inp)
            exit()

        print(f'[+] Received {len(serv_inp)} bytes from server')

        index, shellcode = parse_server_input(serv_inp)

        print(f"[+] Operating for shellcode: '{index}'")

        try:
            answer = eval(f'{index}(shellcode)')
        except NameError:
            print('[!] Error. Cannot process shellcode:', index)
            print('[+] Storing it locally under `shellcodes/` for offline processing ...')

            open(f'shellcodes/{index}.sc', 'wb').write(shellcode)
            exit()

        print(f"[+] Shellcode answer ({len(answer):X}h bytes): '{answer}'")
        sock.send(answer.encode('utf-8') + b'\n')

    print('[+] Program finished. Bye bye :)')

# ---------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop:~/ctf/midnight_sun_ctf_2022/revver$ ./revver_crack.py
[+] REVVER simulator started.
================ 1 ================
[+] Received 3291 bytes from server
[+] Operating for shellcode: 'one'
[+] Shellcode category: Crypto in instructions
[+] Plaintext: [48, 59, 102, 61, 81, 91, 104, 123, 108, 76]
[+] Shellcode answer (Ah bytes): '0;f=Q[h{lL'
================ 2 ================
[+] Received 3974 bytes from server
[+] Operating for shellcode: 'eleven'
[+] Shellcode category: Crypto in instructions
[+] Plaintext: [65, 76, 55, 42, 83, 72, 78, 60, 45, 98]
[+] Shellcode answer (Ah bytes): 'AL7*SHN<-b'
================ 3 ================
[+] Received 613 bytes from server
[+] Operating for shellcode: 'seventeen'
[+] Shellcode category: Crack CRC32
[+] Target CRC32: EC73187Ch
[+] Input size: 17
[+] Generating random string: TQNDAIPTDZ6TM
[+] Current CRC32: C698D8F1
[+] CRC32 successfully cracked: A4-BF-78-70
[+] Generating random string: CYYSY1ZBOUHUT
[+] Current CRC32: 5EA16C4C
[+] CRC32 successfully cracked: 19-0B-41-E8
[+] Generating random string: 7YX2G631VSDS9
[+] Current CRC32: 02C0C55B
[+] CRC32 successfully cracked: 0E-A2-20-B4
[+] Generating random string: XD5DU9UTGFJCN
[+] Current CRC32: 86D055F4
[+] CRC32 successfully cracked: A1-32-30-30
[+] Generating random string: OMAZMMFKO4OI4
[+] Current CRC32: 83978746
[+] CRC32 successfully cracked: 13-E0-77-35
[+] Generating random string: 1V49D0F3LG5UE
[+] Current CRC32: D114C627
[+] CRC32 successfully cracked: 72-A1-F4-67
[+] Generating random string: WDANJPBO83Z8Q
[+] Current CRC32: F54A7E59
[+] CRC32 successfully cracked: 0C-19-AA-43
[+] Generating random string: 318NBOMILSBFB
[+] Current CRC32: 2C97100A
[+] CRC32 successfully cracked: 5F-77-77-9A
[+] Generating random string: DX8UDF60BKZ3Z
[+] Current CRC32: 563EDA15
[+] CRC32 successfully cracked: 40-BD-DE-E0
[+] Generating random string: MDWQEDH6M6KOW
[+] Current CRC32: D6F485C1
[+] CRC32 successfully cracked: 94-E2-14-60
[+] Generating random string: UBLVBG8O8VUKB
[+] Current CRC32: 8770DC41
[+] CRC32 successfully cracked: 14-BB-90-31
[+] Generating random string: ZV9D3LEYX35GC
[+] Current CRC32: E71D2FF8
[+] CRC32 successfully cracked: AD-48-FD-51
[+] Generating random string: K9X42F10Y2NOL
[+] Current CRC32: 87209362
[+] CRC32 successfully cracked: 37-F4-C0-31
[+] Generating random string: GFAOTBV2QGBJH
[+] Current CRC32: 272D47DE
[+] CRC32 successfully cracked: 8B-20-CD-91
[+] Generating random string: C2KLVS08O3WV8
[+] Current CRC32: 8948641C
[+] CRC32 successfully cracked: 49-03-A8-3F
[+] Generating random string: GO0Y91FLOZ20M
[+] Current CRC32: FA75AA2E
[+] CRC32 successfully cracked: 7B-CD-95-4C
[+] Generating random string: Z96Z29HFG8IR1
[+] Current CRC32: 963C2347
[+] CRC32 successfully cracked: 12-44-DC-20
[+] Generating random string: ZNW0QURRILP0D
[+] Current CRC32: 170C8026
[+] CRC32 successfully cracked: 73-E7-EC-A1
[+] Generating random string: 540FB66B7JTT9
[+] Current CRC32: 8EE929B1
[+] CRC32 successfully cracked: E4-4E-09-38
[+] Generating random string: 2QOLP3UQK9CXT
[+] Current CRC32: 0F2EA573
[+] CRC32 successfully cracked: 26-C2-CE-B9
[+] Generating random string: PN93HPUBNLU2O
[+] Current CRC32: 5B3B8397
[+] CRC32 successfully cracked: C2-E4-DB-ED
[+] Generating random string: SFN0CEY8ZAKUE
[+] Current CRC32: BC1FF30E
[+] CRC32 successfully cracked: 5B-94-FF-0A
[+] Generating random string: FC3DLREM9UXTR
[+] Current CRC32: 90975210
[+] CRC32 successfully cracked: 45-35-77-26
[+] Collison found: 'FC3DLREM9UXTRE5w&'
[+] Verifying CRC32: EC73187C
[+] Shellcode answer (11h bytes): 'FC3DLREM9UXTRE5w&'
================ 4 ================
[+] Received 2927 bytes from server
[+] Operating for shellcode: 'six'
[+] Shellcode category: Crypto in instructions
[+] Plaintext: [112, 59, 116, 77, 96, 76, 83, 70, 62, 56]
[+] Shellcode answer (Ah bytes): 'p;tM`LSF>8'
================ 5 ================
[+] Received 3047 bytes from server
[+] Operating for shellcode: 'seven'
[+] Shellcode category: Crack CRC32
[+] Target CRC32: 27A958F9h
[+] Input size: 30
[+] Generating random string: D2OE0OGSMKG2GWG0J2QO1BE1B0
[+] Current CRC32: DACD2BFE
[+] CRC32 successfully cracked: 15-1A-6F-A8
[+] Generating random string: Z1FCWEMM8I778KP4MXCO3OPI1Q
[+] Current CRC32: 4BF6B65E
[+] CRC32 successfully cracked: B5-87-54-39
[+] Generating random string: FG66WX4RSYYVB9OAZ73VOETACR
[+] Current CRC32: CF8EC255
[+] CRC32 successfully cracked: BE-F3-2C-BD
[+] Generating random string: H137V3M5R2EC9BBP32WFJB7J31
[+] Current CRC32: AC121E12
[+] CRC32 successfully cracked: F9-2F-B0-DE
[+] Generating random string: IKEYIDU5OM5TFZT8V8Y4S0GB9C
[+] Current CRC32: 7E445EDD
[+] CRC32 successfully cracked: 36-6F-E6-0C
[+] Generating random string: I3Q0B6LLHW7886RRZLVCEJJHWX
[+] Current CRC32: 7A42C6BB
[+] CRC32 successfully cracked: 50-F7-E0-08
[+] Generating random string: OVO8WCVD707KZ09Y46XESJIB6E
[+] Current CRC32: 31EBC77A
[+] CRC32 successfully cracked: 91-F6-49-43
[+] Generating random string: O5TNILZ62BG9WUU1V2DU7XUE18
[+] Current CRC32: 9555F5CE
[+] CRC32 successfully cracked: 25-C4-F7-E7
[+] Generating random string: SRBXN1D3X8AK5D2FEEU6ZI7NCH
[+] Current CRC32: 3E924181
[+] CRC32 successfully cracked: 6A-70-30-4C
[+] Collison found: 'SRBXN1D3X8AK5D2FEEU6ZI7NCHjp0L'
[+] Verifying CRC32: 27A958F9
[+] Shellcode answer (1Eh bytes): 'SRBXN1D3X8AK5D2FEEU6ZI7NCHjp0L'
================ 6 ================
[+] Received 4818 bytes from server
[+] Operating for shellcode: 'fiveteen'
[+] Shellcode category: Const string in .rodata
[+] Extracting constant strings from shellcode ...
[+] Found blacklisted string: ''
[+] Found printable string: 'sTpG378ZBrA9snf70Vcq9m0MkbdULHuJw2lzzeSiezG7nQsNdCqkjS2C6VGKntGzQujruqhpWhiRcIl'
[+] Found blacklisted string: 'recv failed'
[+] Found blacklisted string: 'accept failed'
[+] Found blacklisted string: 'Waiting for incoming connections...'
[+] Found blacklisted string: 'Could not create socket'
[+] Found blacklisted string: 'Connection accepted'
[+] Found blacklisted string: 'Client disconnected'
[+] Found blacklisted string: 'Bind failed'
[+] Found blacklisted string: '%s'
[+] Found blacklisted string: '\n'
[+] Shellcode answer (4Fh bytes): 'sTpG378ZBrA9snf70Vcq9m0MkbdULHuJw2lzzeSiezG7nQsNdCqkjS2C6VGKntGzQujruqhpWhiRcIl'
================ 7 ================
[+] Received 3149 bytes from server
[+] Operating for shellcode: 'ten'
[+] Shellcode category: Const string in .rodata
[+] Extracting constant strings from shellcode ...
[+] Found blacklisted string: ''
[+] Found printable string: 'cXz5zeR4buf9Mg49UxQGpVU9spQJBfDnu4PJllIRWeDyh19EP22P7SRFrtK'
[+] Found blacklisted string: 'Error!\n'
[+] Shellcode answer (3Bh bytes): 'cXz5zeR4buf9Mg49UxQGpVU9spQJBfDnu4PJllIRWeDyh19EP22P7SRFrtK'
================ 8 ================
[+] Received 3377 bytes from server
[+] Operating for shellcode: 'two'
[+] Shellcode category: Crack CRC32
[+] Target CRC32: B6923162h
[+] Input size: 29
[+] Generating random string: UOSTHUEOLZ3DKW55F758K2SL4
[+] Current CRC32: 2ED2029A
[+] CRC32 successfully cracked: 62-ED-08-A4
[+] Generating random string: WSIMZZ83MXWOB8BL1R2KIM7CD
[+] Current CRC32: CAB3119B
[+] CRC32 successfully cracked: 63-FE-69-40
[+] Generating random string: N3P78IBXJXU632IA2GLS3U802
[+] Current CRC32: ABA25261
[+] CRC32 successfully cracked: 99-BD-78-21
[+] Generating random string: V6CJOFDO034CJO4FEQRUVKEN8
[+] Current CRC32: E51D53E5
[+] CRC32 successfully cracked: 1D-BC-C7-6F
[+] Generating random string: WMTJOHKPXEG046U4TLJ1KS3H5
[+] Current CRC32: 74B52B29
[+] CRC32 successfully cracked: D1-C4-6F-FE
[+] Generating random string: L6PGF0XUYXGPFL22NW73H6VPI
[+] Current CRC32: D4E923AF
[+] CRC32 successfully cracked: 57-CC-33-5E
[+] Generating random string: 6OV168RAJ5NLDG3OF39TBTHWO
[+] Current CRC32: 0A7C0C24
[+] CRC32 successfully cracked: DC-E3-A6-80
[+] Generating random string: 53O8UL3BHOINURI6UXGNFO2W8
[+] Current CRC32: 55ECB7F1
[+] CRC32 successfully cracked: 09-58-36-DF
[+] Generating random string: B1LPTMGYU6AXTXS7D1LCTUJK5
[+] Current CRC32: CB9CDBA9
[+] CRC32 successfully cracked: 51-34-46-41
[+] Collison found: 'B1LPTMGYU6AXTXS7D1LCTUJK5Q4FA'
[+] Verifying CRC32: B6923162
[+] Shellcode answer (1Dh bytes): 'B1LPTMGYU6AXTXS7D1LCTUJK5Q4FA'
================ 9 ================
[+] Received 4155 bytes from server
[+] Operating for shellcode: 'eight'
[+] Shellcode category: RC4 decryption
[+] Extracting constant strings from shellcode ...
[+] Found blacklisted string: ''
[+] Found printable string: 'NbpMzcLzTGwiksqqK'
[+] Found blacklisted string: 'Error! Not enough arguments\n'
[+] Found non-printable string: '9ùþh¨ÔÎQhS>e¯Ï-F\x19çéùðq'
[+] RC4 decryption key: NbpMzcLzTGwiksqqK
[+] RC4 ciphertext: 39-F9-FE-68-A8-D4-CE-51-68-53-3E-65-AF-CF-2D-46-19-E7-E9-F9-F0-71
[+] RC4 plaintext: VkKzxLMSHUowJgormfNZhj
[+] Shellcode answer (16h bytes): 'VkKzxLMSHUowJgormfNZhj'
================ 10 ================
[+] Received 1908 bytes from server
[+] Operating for shellcode: 'eighteen'
[+] Shellcode category: RC4 decryption
[+] Extracting constant strings from shellcode ...
[+] Found blacklisted string: ''
[+] Found non-printable string: '\x8bö\x9aû[\x15<fªÿ\nW\x03×¨\x1f/ºVf7u'
[+] Found printable string: 'SEyGAPzghOnKAKxRd'
[+] RC4 decryption key: SEyGAPzghOnKAKxRd
[+] RC4 ciphertext: 8B-F6-9A-FB-5B-15-3C-66-AA-FF-0A-57-03-D7-A8-1F-2F-BA-56-66-37-75
[+] RC4 plaintext: fitkKdadaEIOeMdxvwPmZt
[+] Shellcode answer (16h bytes): 'fitkKdadaEIOeMdxvwPmZt'
================ 11 ================
[+] Received 1062 bytes from server
[+] Operating for shellcode: 'twenty'
[+] Shellcode category: Const string in .rodata
[+] Extracting constant strings from shellcode ...
[+] Found blacklisted string: ''
[+] Found printable string: '7LGd5mwXnNDJkvu7HsBe9fhL4xhuNNvBakS3smdjqD7PkYCGR4giNdGSZ7RCarm3zq2BCEBAp7k65cPWZXXzrr3'
[+] Shellcode answer (57h bytes): '7LGd5mwXnNDJkvu7HsBe9fhL4xhuNNvBakS3smdjqD7PkYCGR4giNdGSZ7RCarm3zq2BCEBAp7k65cPWZXXzrr3'
================ 12 ================
[+] Received 3704 bytes from server
[+] Operating for shellcode: 'nine'
[+] Shellcode category: Difference between words in instructions
[+] Total number of ciphers: 32
[+] Computing diff: 4F87 - E924 = 6663
[+] Computing diff: 67B4 - FD5F = 6A55
[+] Computing diff: 30FC - E58C = 4B70
[+] Computing diff: 3B43 - CAD8 = 706B
[+] Computing diff: 597F - EA32 = 6F4D
[+] Computing diff: 36FE - ED93 = 496B
[+] Computing diff: 784A - FDD8 = 7A72
[+] Computing diff: 5B92 - F523 = 666F
[+] Computing diff: 40F8 - CA87 = 7671
[+] Computing diff: 6126 - F4D2 = 6C54
[+] Computing diff: 5756 - FCF0 = 5A66
[+] Computing diff: 4C16 - D4A9 = 776D
[+] Computing diff: 2BC1 - D175 = 5A4C
[+] Computing diff: 38EC - F19E = 474E
[+] Computing diff: 26E9 - D472 = 5277
[+] Computing diff: 420B - D5A1 = 6C6A
[+] Shellcode answer (20h bytes): 'fcjUKppkoMIkzrfovqlTZfwmZLGNRwlj'
================ 13 ================
[+] Received 4184 bytes from server
[+] Operating for shellcode: 'twelve'
[+] Shellcode category: Crack CRC32
[+] Target CRC32: EBFA834Dh
[+] Input size: 20
[+] Generating random string: EXWO6S8EAXHUW725
[+] Current CRC32: FE1638CF
[+] CRC32 successfully cracked: 79-AC-F3-44
[+] Generating random string: TZO8I3CGCAISOWQ0
[+] Current CRC32: BD59205D
[+] CRC32 successfully cracked: EB-B4-BC-07
[+] Generating random string: UNUVPXBRLCJ5LNIV
[+] Current CRC32: 8FBF490B
[+] CRC32 successfully cracked: BD-DD-5A-35
[+] Generating random string: EPXVNBCF64DGBAK9
[+] Current CRC32: 6912C57D
[+] CRC32 successfully cracked: CB-51-F7-D3
[+] Generating random string: PWH7ZNOMNLH045KB
[+] Current CRC32: 00AE53FA
[+] CRC32 successfully cracked: 4C-C7-4B-BA
[+] Generating random string: HNEEYPLSYGZ0PLIX
[+] Current CRC32: D4A4BB69
[+] CRC32 successfully cracked: DF-2F-41-6E
[+] Generating random string: BIYBE1OI724TYNBA
[+] Current CRC32: 1CDD2762
[+] CRC32 successfully cracked: D4-B3-38-A6
[+] Generating random string: R1XCH780I0IONZQN
[+] Current CRC32: E4410568
[+] CRC32 successfully cracked: DE-91-A4-5E
[+] Generating random string: 7BCQE94EOAT08J7L
[+] Current CRC32: E619F8BE
[+] CRC32 successfully cracked: 08-6C-FC-5C
[+] Generating random string: 25DMUMKMUUS17808
[+] Current CRC32: FDA4F6C3
[+] CRC32 successfully cracked: 75-62-41-47
[+] Collison found: '25DMUMKMUUS17808ubAG'
[+] Verifying CRC32: EBFA834D
[+] Shellcode answer (14h bytes): '25DMUMKMUUS17808ubAG'
================ 14 ================
[+] Received 4615 bytes from server
[+] Operating for shellcode: 'three'
[+] Shellcode category: RC4 decryption
[+] Extracting constant strings from shellcode ...
[+] Found blacklisted string: ''
[+] Found printable string: 'oHkAdQZfDLeWngmKD'
[+] Found blacklisted string: 'Error! Could not open file\n'
[+] Found non-printable string: '<ê\x19\x9d.f¼YÏïCÂg(\x84õÜÄë¿·\x81'
[+] Found blacklisted string: '/midnightsunctf-2022/quals/revver/answer3.bin'
[+] RC4 decryption key: oHkAdQZfDLeWngmKD
[+] RC4 ciphertext: 3C-EA-19-9D-2E-66-BC-59-CF-EF-43-C2-67-28-84-F5-DC-C4-EB-BF-B7-81
[+] RC4 plaintext: OpwyGUBePAtCTxmbtRUNMV
[+] Shellcode answer (16h bytes): 'OpwyGUBePAtCTxmbtRUNMV'
================ 15 ================
[+] Received 5396 bytes from server
[+] Operating for shellcode: 'thirteen'
[+] Shellcode category: RC4 decryption
[+] Extracting constant strings from shellcode ...
[+] Found blacklisted string: ''
[+] Found non-printable string: '»ä>Ü\x1a\x96\r÷\x84íwÿBîê\x03i\x06P\x05»ª'
[+] Found blacklisted string: 'recv failed'
[+] Found printable string: 'hTJTTRHuTEycoaIgL'
[+] Found blacklisted string: 'accept failed'
[+] Found blacklisted string: 'Waiting for incoming connections...'
[+] Found blacklisted string: 'Could not create socket'
[+] Found blacklisted string: 'Connection accepted'
[+] Found blacklisted string: 'Client disconnected'
[+] Found blacklisted string: 'Bind failed'
[+] Found blacklisted string: '\n'
[+] RC4 decryption key: hTJTTRHuTEycoaIgL
[+] RC4 ciphertext: BB-E4-3E-DC-1A-96-0D-F7-84-ED-77-FF-42-EE-EA-03-69-06-50-05-BB-AA
[+] RC4 plaintext: gDQZibaLRUIwvzpnComCvG
[+] Shellcode answer (16h bytes): 'gDQZibaLRUIwvzpnComCvG'
================ 16 ================
[+] Received 717 bytes from server
[+] Operating for shellcode: 'sixteen'
[+] Shellcode category: Crypto in instructions
[+] Plaintext: [34, 96, 74, 114, 69, 93, 71, 92, 42, 95]
[+] Shellcode answer (Ah bytes): '"`JrE]G\*_'
================ 17 ================
[+] Received 5140 bytes from server
[+] Operating for shellcode: 'fourteen'
[+] Shellcode category: Difference between words in instructions
[+] Total number of ciphers: 52
[+] Computing diff: 3A0B - E293 = 5778
[+] Computing diff: 1786 - CB17 = 4C6F
[+] Computing diff: 203B - D4D7 = 4B64
[+] Computing diff: 2B89 - DB20 = 5069
[+] Computing diff: 258C - D034 = 5558
[+] Computing diff: 4DC0 - F979 = 5447
[+] Computing diff: 2E77 - E50C = 496B
[+] Computing diff: 27BF - D84C = 4F73
[+] Computing diff: 4791 - FF26 = 486B
[+] Computing diff: 2A38 - E2C5 = 4773
[+] Computing diff: 39BC - D74B = 6271
[+] Computing diff: 32FA - C98F = 696B
[+] Computing diff: 3CBD - DA5C = 6261
[+] Computing diff: 1C5B - C7F6 = 5465
[+] Computing diff: 64E6 - ED7A = 776C
[+] Computing diff: 2FB0 - C061 = 6F4F
[+] Computing diff: 3B5F - CE0E = 6D51
[+] Computing diff: 75FB - FFB7 = 7644
[+] Computing diff: 27B3 - D442 = 5371
[+] Computing diff: 4BF2 - E18D = 6A65
[+] Computing diff: 1231 - CDE6 = 444B
[+] Computing diff: 5DA1 - E353 = 7A4E
[+] Computing diff: 5BAE - F057 = 6B57
[+] Computing diff: 42C9 - EE7F = 544A
[+] Computing diff: 24C1 - DE6C = 4655
[+] Computing diff: 272C - C1DB = 6551
[+] Shellcode answer (34h bytes): 'WxLoKdPiUXTGIkOsHkGsbqikbaTewloOmQvDSqjeDKzNkWTJFUeQ'
================ 18 ================
[+] Received 1402 bytes from server
[+] Operating for shellcode: 'nineteen'
[+] Shellcode category: Difference between words in instructions
[+] Total number of ciphers: 46
[+] Computing diff: 2A31 - D5BB = 5476
[+] Computing diff: 3AAE - D94D = 6161
[+] Computing diff: 2E80 - CA27 = 6459
[+] Computing diff: 69B0 - F969 = 7047
[+] Computing diff: 635A - FAED = 686D
[+] Computing diff: 393E - D6DB = 6263
[+] Computing diff: 50ED - E4A1 = 6C4C
[+] Computing diff: 3A99 - D148 = 6951
[+] Computing diff: 35FF - EE97 = 4768
[+] Computing diff: 5020 - E0AD = 6F73
[+] Computing diff: 5113 - E1CD = 6F46
[+] Computing diff: 3126 - DEC5 = 5261
[+] Computing diff: 61CA - EE70 = 735A
[+] Computing diff: 5344 - EEE0 = 6464
[+] Computing diff: 4036 - D6EB = 694B
[+] Computing diff: 239F - DE57 = 4548
[+] Computing diff: 3959 - EEFF = 4A5A
[+] Computing diff: 6A21 - F5AA = 7477
[+] Computing diff: 3148 - E3E4 = 4D64
[+] Computing diff: 3797 - F250 = 4547
[+] Computing diff: 3521 - E9CF = 4B52
[+] Computing diff: 38AF - F464 = 444B
[+] Computing diff: 4082 - EA35 = 564D
[+] Shellcode answer (2Eh bytes): 'TvaadYpGhmbclLiQGhosoFRasZddiKEHJZtwMdEGKRDKVM'
================ 19 ================
[+] Received 3710 bytes from server
[+] Operating for shellcode: 'five'
[+] Shellcode category: Const string in .rodata
[+] Extracting constant strings from shellcode ...
[+] Found blacklisted string: ''
[+] Found blacklisted string: 'swag.key'
[+] Found printable string: 'c4ZQCT0s20MrXAN2slY2MOsF7GDORA0VXIxeirAOxS0JGQbqPiSWQC8IXj7ldIaMih5X6nQYnhkuo1'
[+] Found blacklisted string: 'Error! Could not open file\n'
[+] Shellcode answer (4Eh bytes): 'c4ZQCT0s20MrXAN2slY2MOsF7GDORA0VXIxeirAOxS0JGQbqPiSWQC8IXj7ldIaMih5X6nQYnhkuo1'
================ 20 ================
[+] Received 4868 bytes from server
[+] Operating for shellcode: 'four'
[+] Shellcode category: Difference between words in instructions
[+] Total number of ciphers: 96
[+] Computing diff: 3E74 - C51A = 795A
[+] Computing diff: 66CF - ED77 = 7958
[+] Computing diff: 239B - D84D = 4B4E
[+] Computing diff: 471E - E1CF = 654F
[+] Computing diff: 2C31 - E8E6 = 434B
[+] Computing diff: 44FB - EFA4 = 5557
[+] Computing diff: 1F6E - D1FF = 4D6F
[+] Computing diff: 3CCF - CD8C = 6F43
[+] Computing diff: 617F - F827 = 6958
[+] Computing diff: 72E - C2BD = 4471
[+] Computing diff: 1C5D - D81A = 4443
[+] Computing diff: 338C - D120 = 626C
[+] Computing diff: 366D - D1F3 = 647A
[+] Computing diff: 5A95 - ED44 = 6D51
[+] Computing diff: 6574 - EC08 = 796C
[+] Computing diff: 71C3 - FE69 = 735A
[+] Computing diff: 1784 - D30B = 4479
[+] Computing diff: 4800 - F7B9 = 5047
[+] Computing diff: 16B3 - CB6F = 4B44
[+] Computing diff: 5F80 - EB0D = 7473
[+] Computing diff: 64CB - F05B = 7470
[+] Computing diff: 31C1 - CB69 = 6658
[+] Computing diff: 438C - E22B = 6161
[+] Computing diff: 3D53 - EBEE = 5165
[+] Computing diff: 4758 - D80B = 6F4D
[+] Computing diff: 3D08 - F2BB = 4A4D
[+] Computing diff: 94D - C0D8 = 4875
[+] Computing diff: 61F5 - E8B3 = 7942
[+] Computing diff: 743A - FAF2 = 7948
[+] Computing diff: 44BD - D476 = 7047
[+] Computing diff: 2A59 - E110 = 4949
[+] Computing diff: 23F1 - E080 = 4371
[+] Computing diff: 4947 - FBF2 = 4D55
[+] Computing diff: 19A6 - CA5A = 4F4C
[+] Computing diff: 1143 - CBDD = 4566
[+] Computing diff: 43C6 - D758 = 6C6E
[+] Computing diff: 70D2 - F982 = 7750
[+] Computing diff: 6FA1 - FC34 = 736D
[+] Computing diff: 4365 - EB04 = 5861
[+] Computing diff: 2538 - CBCD = 596B
[+] Computing diff: 30D3 - EF72 = 4161
[+] Computing diff: 2BB3 - D268 = 594B
[+] Computing diff: 3383 - E419 = 4F6A
[+] Computing diff: 7093 - FF2A = 7169
[+] Computing diff: 2AA3 - D633 = 5470
[+] Computing diff: 15D6 - CF66 = 4670
[+] Computing diff: 2652 - C30B = 6347
[+] Computing diff: 3E81 - EB35 = 534C
[+] Shellcode answer (60h bytes): 'yZyXKNeOCKUWMooCiXDqDCbldzmQylsZDyPGKDtstpfXaaQeoMJMHuyByHpGIICqMUOLEflnwPsmXaYkAaYKOjqiTpFpcGSL'
================ 21 ================
[+] Got Flag! b" \nb'midnight{Reversing_got_alot_easier_with_backup_cameras}'\n \n"
'''
# ---------------------------------------------------------------------------------------

