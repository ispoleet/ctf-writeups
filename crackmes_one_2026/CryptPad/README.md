## Crackmes One CTF 2026 - CryptPad - (Easy - 100)
### 14-21/02/2026 (7d)
___

## Description

*We found this on an old machine. Can you decrypt it?*
___


### Solution

This is a very simple Windows application that encrypts text using a custom encryption and saves
it into a file. Our goal is to decrypt the `flag.enc`:
```
$ cat flag.enc | hexdump -C
00000000  c9 98 8f c7 a6 1c 02 6b  e2 06 f3 52 49 16 27 59  |.......k...RI.'Y|
00000010  45 5c 4c 47 bc 4e 28 a6  2f 71 c7 d8 06 85 42 03  |E\LG.N(./q....B.|
00000020  08 50 7d 93 f5 fe e5 99  48 4e 82 2b e2 00 57 26  |.P}.....HN.+..W&|
00000030  16 f6 b4 1c 00 00 00 e8  17 1b f4 50 3f 3d 70 08  |...........P?=p.|
00000040
```

Function `sub_4011A0()` handles all messages (i.e., menu options):
```c
LRESULT __stdcall sub_4011A0(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
  /* ... */
  if ( Msg == 273 )
  {
    switch ( (unsigned __int16)wParam )
    {
      case 'e':
        SendMessageA(dword_4024D1, 0xCu, (WPARAM)Caption, 0);
        nullsub_1();
        SetWindowTextA((HWND)hInstance, Caption);
        String[0] = 0;
        return 0;
      case 'p':
        return MessageBoxA(::hWnd, aCryptpad10IsAn, Caption, 0);// CryptPad 1.0 is an encrypted notepad that uses a custom encryption ....
      case 'o':
        return MessageBoxA(::hWnd, aToRegisterSend, Caption, 0);// To register, send $100,000,000,000 to ...
      case 'f':
        return sub_4013A2(v6, v7);              // This option is only available in the full version.
      case 'g':
        result = sub_401718(::hWnd);
        if ( result )
        {
          SetWindowTextA(::hWnd, String);
          u_do_encrypt();
          return 0;
        }
        return result;
    }
    /* ... */
}
```

The program has a decrypt option, but it is "not supported".

`u_do_encrypt()` at `004013BDh` extracts the text and encrypts it:
```c
BOOL u_do_encrypt() {
  /* ... */
  if ( ProcessHeap
    && (hHeap = ProcessHeap,
        NumberOfBytesWritten = GetWindowTextLengthA(dword_4024D1) + 1,
        RandomBufferLength = 64 - NumberOfBytesWritten % 0x40,
        (v1 = (CHAR *)HeapAlloc(hHeap, 0, NumberOfBytesWritten + RandomBufferLength)) != 0)
    && (lpMem = v1, (FileA = CreateFileA(String, 0x40000000u, 0, 0, 2u, 0x80u, 0)) != 0) )
  {
    hObject = FileA;
    GetWindowTextA(dword_4024D1, lpMem, NumberOfBytesWritten);
    sub_40166B(&lpMem[NumberOfBytesWritten], RandomBufferLength);
    sub_40166B(glo_random_xor_key, 8u);
    LOBYTE(v3) = u_encrypt(lpMem, NumberOfBytesWritten, 1);
    WriteFile(hObject, lpMem, v3, &NumberOfBytesWritten, 0);
    CloseHandle(hObject);
  }
  /* ... */
}
```

The actual encryption is implemented in `u_encrypt()` at `0x004014EB`:
```c
char __stdcall u_encrypt(_BYTE *a1_plain, int a2_outlen, int a3_always_1) {
  /* ... */
  else // a3_always_1 is 0
  {
    v3 = *(_DWORD *)&a1_plain[a2_outlen - 1];
    v4 = &a1_plain[a2_outlen - 1 - v3];
    qmemcpy(glo_random_xor_key, v4, v3);
    v5 = *((_DWORD *)v4 - 1);
    *((_DWORD *)v4 - 1) = 0;
    a2_outlen = v5;
  }
  pl = a1_plain;
  key = glo_random_xor_key;
  len = NumberOfBytesWritten;
REWIND_KEY:
  i = 0;
  // XOR text using key (first 8 bytes random, then overflows)
  do {
    *pl++ ^= *key++;
    if ( ++i == 8 )
      goto REWIND_KEY;
    --len;
  } while ( len );
  ii = 256;
  do {                                            // build S array [0, 1, 2, ... 255]
    glo_S[(unsigned __int8)-(char)ii] = -(char)ii;
    --ii;
  } while ( ii );
  v12 = glo_buf;
  v13 = 256;
  v14 = 0;
  do {                                          // expand the random_xor_key to 256 bytes
    if ( v14 >= 8 )
      v14 = 0;
    *v12++ = glo_random_xor_key[v14++];
    --v13;
  } while ( v13 );
  v15 = 0;
  v16 = v12 - 256;
  i_ = 0;
  j_ = 256;
  do {                                           // looks like rc4 ....
    LOBYTE(v15) = glo_S[i_] + v16[i_] + v15;
    v19 = glo_S[i_];
    glo_S[i_] = glo_S[v15];
    glo_S[v15] = v19;
    ++i_;
    --j_;
  } while ( j_ );
  v20 = a1_plain;
  v21 = 0;
  v22 = 0;
  v23 = a2_outlen;
  do {                                          // yes it's rc4!
    v33 = v23;
    v24 = (unsigned __int8)(v21 + 1);
    v32 = v20;
    v25 = glo_S[v24];
    LOBYTE(v22) = v25 + v22;
    v26 = glo_S[v22];
    glo_S[v24] = v26;
    glo_S[v22] = v25;
    LOBYTE(v24) = glo_S[(unsigned __int8)(v25 + v26)] ^ a1_plain[v21];
    v20 = v32;
    v32[v21++] = v24;
    v23 = v33 - 1;
  } while ( v33 != 1 );
  v27 = a1_plain;
  v28 = glo_random_xor_key;
  v29 = NumberOfBytesWritten;
LABEL_20:
  v30 = 0;
  do {                               // xor ciphertext with random key+overflow (as we xored it with plaintext)
    result = *v28 ^ *v27;
    *v27++ = result;
    ++v28;
    if ( ++v30 == 8 )
      goto LABEL_20;
    --v29;
  } while ( v29 );
  if ( a3_always_1 == 1 ) {
    v31 = &a1_plain[a2_outlen - 13 + RandomBufferLength];
    *(_DWORD *)v31 = a2_outlen;
    v31 += 4;
    qmemcpy(v31, glo_random_xor_key, 8u);       // append key to the output
    v31[8] = 8;                                 // append key size (always 0)
    return RandomBufferLength + a2_outlen;
  }
  return result;
}
```

This is basically an [RC4](https://en.wikipedia.org/wiki/RC4) encryption combined with some extra
XORs. The key is randomly generated and stored alongside with the ciphertext. Let's rewrite this
in python:
```python
plaintext = b'ispoleetmore\0'

# Pick something random.
random_xor_key = [0xC4, 0x93, 0xDA, 0xD1, 0x7A, 0xE4, 0xB7, 0x71]
xor_key = random_xor_key + [
    0xAF, 0x00, 0x53, 0x00, 0x58, 0x02, 0x1E, 0x00, 0x64, 0x02,
    0x17, 0x00, 0xBC, 0x08, 0x0A, 0xE4] + [0x00]*50

p1 = [p ^ k for p, k in zip(plaintext, xor_key)]
print(' '.join(f'{x:02X}' for x in p1))  # AD E0 AA BE 16 81 D2 05 C2 6F 21 65 58

from Crypto.Cipher import ARC4
rc4 = ARC4.new(bytes(random_xor_key*32))
enc = rc4.encrypt(bytes(p1))
print(' '.join(f'{x:02X}' for x in enc))  # 4D FE B4 63 1F CF C9 DA 6C 30 DE 00 26

p2 = [p ^ k for p, k in zip(enc, xor_key)]
print(' '.join(f'{x:02X}' for x in p2))  # 89 6D 6E B2 65 2B 7E AB C3 30 8D 00 7E

ciphertext = p2 + [0]*4 + random_xor_key + [8]
print(' '.join(f'{x:02X}' for x in ciphertext))  # 89 6D 6E B2 65 2B 7E AB C3 30 8D 00 7E 00 00 00 00 C4 93 DA D1 7A E4 B7 71 08
```

Decrypting the flag is now straightforward:
```python
ciphertext = open('flag.enc', 'rb').read()
rc4_key = ciphertext[-9:-1]  # Drop last byte -01
ciphertext = ciphertext[:-8 -4]

pp = [p ^ k for p, k in zip(ciphertext, rc4_key*32)]
print(' '.join(f'{x:02X}' for x in pp))

from Crypto.Cipher import ARC4
rc4 = ARC4.new(bytes(rc4_key))
plaintext = rc4.decrypt(bytes(pp))
print(' '.join(f'{x:02X}' for x in plaintext))

pp = [p ^ k for p, k in zip(plaintext, rc4_key*32)]
print(' '.join(f'{x:02X}' for x in pp))
print('Flag:', ''.join(f'{x:c}' for x in pp))
``` 

So the flag is: `CMO{r0ll_y0ur_0wn_b4d_c0d3}`
___
