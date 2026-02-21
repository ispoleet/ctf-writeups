## Crackmes One CTF 2026 - FLRSCRNSVR.SCR - (Easy - 252)
### 14-21/02/2026 (7d)
___

## Description

*Password: flare*
___


### Solution

This challenge is a screen saver with frogs:

![alt text](screensaver.png "")

We will solve this challenge statically without running it. I started to look into the functions
until I noticed an [RC4](https://en.wikipedia.org/wiki/RC4) Key-Scheduling mixed with the registry
operations in function `1400010D0h`:
```c
BOOL __fastcall u_rc4_key_sched_1400010D0(char *a1_buf, char *a2_key, int a3_keylen) {
  /* ... */
  ii = 0;
  array = a1_buf;
  for ( i = 0; i < 256; ++i ) {
    QueryPerformanceCounter(&PerformanceCount);
    *array++ = i;
  }
  val = 0;
  a1_nxt = a1_buf;
  // cur = buf[i] 
  // val = (val + curr + key[i % len]]) % 256
  // swap values
  do {
    GetSystemMetrics(2);
    val = ((unsigned __int8)*a1_nxt + (unsigned __int8)a2_key[ii % a3_keylen] + val) % 256;
    if ( !RegOpenKeyExW(HKEY_CURRENT_USER, L"Control Panel\\Desktop", 0, 0x20019u, (PHKEY)&PerformanceCount) )
      RegCloseKey((HKEY)PerformanceCount.QuadPart);
    curr = *a1_nxt;
    StockObject = GetStockObject(4);
    GetObjectW(StockObject, 16, pv);
    *a1_nxt = a1_buf[val];
    if ( GetWindowsDirectoryW(Buffer, 0x104u) ) {
      wcscat_s(Buffer, 0x104uLL, L"*.dll");
      FirstFileW = FindFirstFileW(Buffer, &FindFileData);
      if ( FirstFileW != (HANDLE)-1LL )
        FindClose(FirstFileW);
    }
    ++ii;
    a1_buf[val] = curr;                         // swap values!
    ++a1_nxt;
  } while ( ii < 256 );
  a1_buf[256] = 0;
  result = QueryPerformanceCounter(&v18);
  a1_buf[257] = 0;
  return result;
}
```

Now we can start working backwards from there to see what is going on. The caller is `140003500h`:
```c
LRESULT __fastcall u_important_do_RC4_140003500(HWND a1, UINT a2, WPARAM a3, LPARAM a4) {
  /* ... */
        if ( byte_140008899 )
        {
          v16 = GetStockObject(0);
          ObjectW = GetObjectW(v16, 16, &pv);
          left = pv.left;
          if ( ObjectW )
            left = 0;
          pv.left = left;
          if ( !RegOpenKeyExW(HKEY_CURRENT_USER, L"Control Panel\\Desktop", 0, 0x20019u, &hKey) )
            RegCloseKey(hKey);
          *(_QWORD *)&PtNumOfCharConverted.left = 0LL;
          nSize = GetSystemMetrics(0);
          wcstombs_s((size_t *)&PtNumOfCharConverted, RC4_KEY, 0x100uLL, L"Crackmes.one", 0xFFFFFFFFFFFFFFFFuLL);
          /* ... */
          *(_WORD *)&RC4_CIPHER[16] = word_140008290;
          *(_OWORD *)RC4_CIPHER = xmmword_140008280;
          if ( GetWindowsDirectoryW(Destination, 0x104u) )
          {
            wcscat_s(Destination, 0x104uLL, L"*.dll");
            v21 = FindFirstFileW(Destination, (LPWIN32_FIND_DATAW)RC4_S);
            if ( v21 != (HANDLE)-1LL )
              FindClose(v21);
          }
          v22 = u_search_for_dlls_in_cwd_140001010();
          u_rc4_key_sched_1400010D0((char *)RC4_S, RC4_KEY, PtNumOfCharConverted.left - v22 - 1);
          /**
           *  .....
           */
          do {                              // This is RC4!
            v33 = v32 + 1;
            v34 = 5LL;
            RC4_S_256 = v33;
            PerformanceCount.LowPart = 0;
            do {
              ++PerformanceCount.LowPart;
              --v34;
            } while ( v34 );
            v35 = (char *)&RC4_S[v33];
            RC4_S_257 = *v35 + v30;
            v36 = RC4_S_257;
            v37 = GetDesktopWindow();
            IsWindow(v37);
            v38 = *v35;
            *v35 = RC4_S[v36];
            v39 = GetStockObject(4);
            GetObjectW(v39, 16, v99);
            RC4_S[RC4_S_257] = v38;
            v30 = RC4_S_257;
            v32 = RC4_S_256;
            RC4_CIPHER[ii] ^= RC4_S[(unsigned __int8)(RC4_S[RC4_S_256] + RC4_S[RC4_S_257])];
            v40 = 5LL;
            PerformanceCount.LowPart = 0;
            do {
              ++PerformanceCount.LowPart;
              --v40;
            } while ( v40 );
            ++ii;
          } while ( ii < 18 );
          if ( !RegOpenKeyExW(HKEY_CURRENT_USER, L"Control Panel\\Desktop", 0, 0x20019u, &v94) )
            RegCloseKey(v94); 
          v106 = 0;
          if ( (unsigned __int8)RC4_CIPHER[0] == (unsigned __int8)byte_140008898 + 'E'
            && (unsigned __int8)RC4_CIPHER[1] == (unsigned __int8)byte_140008898 + 'K'
            && (unsigned __int8)RC4_CIPHER[2] == 'S' - (unsigned __int8)byte_140008898 )
          {
            nSize = GetSystemMetrics(0);
            mbstowcs_s((size_t *)&PtNumOfCharConverted, DstBuf, 0x100uLL, RC4_CIPHER, 0xFFFFFFFFFFFFFFFFuLL);
            v41 = GetDC(0LL);
            v42 = CreateCompatibleDC(v41);
            v43 = CreateCompatibleBitmap(v41, 1, 1);
            DeleteObject(v43);
            DeleteDC(v42);
            ReleaseDC(0LL, v41);
            v44 = &DstBuf[3];
          } else {
            nSize = GetSystemMetrics(0);
            v44 = L"Crackmes.one";
            QueryPerformanceCounter(&PerformanceCount);
          }
          /* ... */
}
```

Okay we have found the RC4 decryption. We now need to find the **ciphertext** and the **key**.
The key is read from the registry (`HKCU\\Control Panel\\Desktop`). If it is not found, it defaults
to `Crackmes.one` (obviously this is not the correct key we want).

To verify the decrypted `RC4_CIPHER`, function checks if it starts with `EKS` + `byte_140008898`
(if it is `1`, then `RC4_CIPHER` needs to begin with `FLR`).

The **ciphertext** is copied from `xmmword_140008280` and it is **18-bytes**:
```
    0xFB, 0xF9, 0x28, 0x26, 0x96, 0x41, 0xA3, 0x60,
    0xDE, 0xD6, 0x59, 0xF5, 0x4D, 0x8B, 0x01, 0xB3,
    0x6D, 0x34
```

We still need to find the correct key. We look at the other functions. First we find `140001890h`
that stores an encrypted buffer into `HKCU\\Software\\FLRSCRNSVR\\Quak`:
```c
int __fastcall sub_140001890(wchar_t *Destination) {
  /* ... */
  SetLastError(dwErrCodeb);
  if ( RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\FLRSCRNSVR", 0, 0x20019u, &hKey) ) {
    wcscpy_s(Destination, 0x100uLL, L"Crackmes.one");
  }
  else {
    /* ... */
    if ( RegQueryValueExW(hKey, L"Quak", 0LL, &Type, (LPBYTE)Destination, &cbData) ) {
      wcscpy_s(Destination, 0x100uLL, SECRET_BUF);
      v9 = GetDC(0LL);
      v10 = CreateCompatibleDC(v9);
      v11 = CreateCompatibleBitmap(v9, 1, 1);
      DeleteObject(v11);
      DeleteDC(v10);
      ReleaseDC(0LL, v9);
    }
    /* ... */
}
```

`SECRET_BUF` is located at `1400064D0h` and it is unicode:
```
  0x3C, 0x00, 0x51, 0x00, 0x6A, 0x00, 0x09, 0x00, 0x02, 0x00, 
  0x07, 0x00, 0x25, 0x00, 0x03, 0x00, 0x30, 0x00, 0x08, 0x00, 
  0x04, 0x00, 0x29, 0x00, 0x68, 0x00, 0x24, 0x00, 0x01, 0x00, 
  0x24, 0x00, 0x18, 0x00, 0x6B, 0x00, 0x77, 0x00, 0x0F, 0x00, 
  0x70, 0x00, 0x36, 0x00, 0x02, 0x00, 0x0E, 0x00, 0x0B, 0x00, 
  0x00, 0x00
```

This buffer is decrypted at `140001300h`:
```c
__int16 __fastcall u_SECRET_KEY_140001300(char *a1_crackmesone) {
  /* ... */
  dwErrCode[0] = GetTickCount() % 0x64 + 5;
  SetLastError(dwErrCode[0]);
  wcscpy_s(KEYMAP_1, 0x50uLL, L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP");
  DesktopWindow = GetDesktopWindow();
  IsWindow(DesktopWindow);
  wcscat_s(KEYMAP_1, 0x50uLL, L"QRSTUVWXYZ0123456789}_{=-");
  nSize = 32;
  if ( GetComputerNameW((LPWSTR)Buffer, &nSize) )
    dwErrCode[0] = (unsigned __int16)Buffer[0];
  wcscpy_s((wchar_t *)v43, 0x50uLL, L"-={_}9876543210ZYXWVUTSRQPONMLKJIHGF");
  /* ... */
  wcscat_s((wchar_t *)v43, 0x50uLL, L"EDCBAzyxwvutsrqponmlkjihgfedcba");
  StockObject = GetStockObject(4);
  GetObjectW(StockObject, 16, pv);
  v10 = -1LL;
  v11 = -1LL;
  do
    ++v11;
  while ( *(_WORD *)&a1_crackmesone[2 * v11] );
  v12 = 0LL;
  v13 = 5LL;
  dwErrCode[0] = 0;
  v14 = 5LL;
  /* ... */
  for ( i = 0LL; i < v11; ++i ) {
    v16 = GetDesktopWindow();
    IsWindow(v16);
    v17 = wcschr(KEYMAP_1, *(_WORD *)&a1_crackmesone[2 * i]);
    if ( v17 ) {
      dwErrCode[0] = 0;
      v18 = 5LL;
      do {
        ++dwErrCode[0];
        --v18;
      } while ( v18 );
      *(_WORD *)&a1_crackmesone[2 * i] = v43[v17 - KEYMAP_1];
    }
    if ( !RegOpenKeyExW(HKEY_CURRENT_USER, L"Control Panel\\Desktop", 0, 0x20019u, &hKey) )
      RegCloseKey(hKey);
  }
  v19 = GetStockObject(4);
  GetObjectW(v19, 16, v38);
  SECRET[0] = 'L\0F';
  dwErrCode[0] = 0;
  /* ... */
  SECRET[1] = 'R\0A';
  SECRET[2] = 'R\0E';
  /* ... */
  SECRET[3] = 'L\0A';
  SECRET[4] = 'F';
  /* ... */
  do
    ++v10;
  while ( *((_WORD *)SECRET + v10) );
  v25 = RegOpenKeyExW(HKEY_CURRENT_USER, L"Control Panel\\Desktop", 0, 0x20019u, &v35);
  if ( !v25 )
    LOWORD(v25) = RegCloseKey(v35);
  for ( j = 0LL; j < v11; ++j ) {
    /* ... */
    LOWORD(v25) = *((_WORD *)SECRET + j % v10) + j;     // <---- !
    *(_WORD *)&a1_crackmesone[2 * j] ^= v25;
  }
  if ( v11 >> 1 ) {
    v28 = &a1_crackmesone[2 * v11 - 2];
    do {
      if ( !RegOpenKeyExW(HKEY_CURRENT_USER, L"Control Panel\\Desktop", 0, 0x20019u, &hKey) )
        RegCloseKey(hKey);
      v29 = *(_WORD *)&a1_crackmesone[2 * v12];
      /* ... */
      *(_WORD *)&a1_crackmesone[2 * v12] = *(_WORD *)v28;
      *(_WORD *)v28 = v29;
      v25 = RegOpenKeyExW(HKEY_CURRENT_USER, L"Control Panel\\Desktop", 0, 0x20019u, (PHKEY)dwErrCode);
      if ( !v25 )
        LOWORD(v25) = RegCloseKey(*(HKEY *)dwErrCode);
      ++v12;
      v28 -= 2;
    } while ( v12 < v11 >> 1 );
  /* ... */
}
```

Let's rewrite this in python:
```python
SECRET_BUF = [  # Drop NULL
    0x3C, 0x51, 0x6A, 0x09, 0x02, 0x07, 0x25, 0x03, 0x30, 0x08, 
    0x04, 0x29, 0x68, 0x24, 0x01, 0x24, 0x18, 0x6B, 0x77, 0x0F, 
    0x70, 0x36, 0x02, 0x0E, 0x0B
]
SECRET_BUF.reverse()

keymap1 = list('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789}_{=-')
keymap2 = list('-={_}9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba')

key = 'FLARERALF'

flag = []
for i in range(len(SECRET_BUF)):
    xor  = ord(key[i % len(key)]) + i
    decr = SECRET_BUF[i] ^ xor
    
    try:
        idx = table2.index(chr(decr))
        flag.append(keymap1[idx])
    except ValueError:
        flag.append(chr(decr))

print('Flag: ' + ''.join(flag))
```

This gives us `Flag: CMO{frogt4s7ic_r3vers1ng}` which is also our flag.

However, let's also decrypt the ciphertext:
```python
enc = bytes([
    0xFB, 0xF9, 0x28, 0x26, 0x96, 0x41, 0xA3, 0x60,
    0xDE, 0xD6, 0x59, 0xF5, 0x4D, 0x8B, 0x01, 0xB3,
    0x6D, 0x34])

from Crypto.Cipher import ARC4
rc4 = ARC4.new(b'CMO{frogt4s7ic_r3vers1ng}')
plain = rc4.decrypt(enc)
print(''.join(chr(x) for x in plain))
```
This gives us: `FLRVery well done!`, which also starts with `FLR`.

So the flag is: `CMO{frogt4s7ic_r3vers1ng}`
___
