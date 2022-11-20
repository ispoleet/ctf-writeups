## EKO Party CTF 2022 - EKOLang (RE 200)
##### 02/11 - 04/11/2022 (50hr)

___

### Solution

We start from `main`:
```c
int __cdecl main(int argc, const char **argv, const char **envp) {
  /* ... */
  encryptedText = Array.init()(&type metadata for UInt8);
  v3 = _allocateUninitializedArray<A>(_:)(17LL, &type metadata for UInt8);
  *buf = 0x66;
  buf[1] = 0x5B;
  buf[2] = 0x12;
  buf[3] = 0xCE;
  buf[4] = 0x98;
  buf[5] = 0x60;
  buf[6] = 0xA7;
  buf[7] = 0x5E;
  buf[8] = 0x46;
  buf[9] = 0x27;
  buf[10] = 0xD2;
  buf[11] = 0xB5;
  buf[12] = 0x61;
  buf[13] = 0x95;
  buf[14] = 0x7C;
  buf[15] = 2;
  buf[16] = 0x4C;
  v8 = _finalizeUninitializedArray<A>(_:)(v3, &type metadata for UInt8);
  swift_beginAccess(&encryptedText);
  v5 = encryptedText;
  encryptedText = v8;
  swift_bridgeObjectRelease(v5);
  swift_endAccess(v13);
  swift_beginAccess(&encryptedText);
  v9 = encryptedText;
  swift_bridgeObjectRetain(encryptedText);
  swift_endAccess(v12);
  v10 = Decryption(cypherText:)(v9);
  v11 = v6;
  swift_bridgeObjectRelease(v9);
  decryptedText = v10;
  unk_100008030 = v11;
  return 0;
}
```

Decryption takes place in `Decryption`:
```c
__int64 __fastcall Decryption(cypherText:)(__int64 a1) {
  /* ... */
  *key = 0x31;
  key[1] = 0x33;
  key[2] = 0x73;
  key[3] = 0xBA;
  key[4] = 0xDC;
  key[5] = 0xF;
  key[6] = 0xFE;
  /* ... */
  v7 = __swift_instantiateConcreteTypeFromMangledName(&demangling cache variable for type metadata for EnumeratedSequence<[UInt8]>);
  EnumeratedSequence.makeIterator()(v7);
  while ( 1 )
  {
    v8 = __swift_instantiateConcreteTypeFromMangledName(&demangling cache variable for type metadata for EnumeratedSequence<[UInt8]>.Iterator);
    EnumeratedSequence.Iterator.next()(v8);
    v27 = v47[1];
    v28 = v48;
    if ( (v49 & 1) != 0 )
      break;
    v25 = v27;
    v26 = v28;
    v23 = v28;
    v24 = v27;
    v45 = v27;
    v46 = v28;
    if ( keylen )
    {
      if ( v24 != 0x8000000000000000LL )
      {
        v22 = 0;
        goto LABEL_10;
      }
    }
    else
    {
      _assertionFailure(_:_:file:line:flags:)(v35, 11LL, 2LL, v38, 39LL, 2LL, v37);
      __break(1u);
    }
    v22 = keylen == -1;
LABEL_10:
    if ( v22 )
    {
      _assertionFailure(_:_:file:line:flags:)(v35, 11LL, 2LL, v36, 54LL, 2LL, v37);
      __break(1u);
      break;
    }
    v20 = v24 % keylen;
    swift_bridgeObjectRetain(v29);
    Array.subscript.getter(v20, v29, v41);
    v21 = (unsigned __int8)v44[1];
    swift_bridgeObjectRelease(v29);
    v44[0] = v23 ^ v21;  // XOR!
    Array.append(_:)(v44, v31);
  }

  /* ... */
}
```

Program simply XORs the ciphertext with a repeated key. Getting the flag is simple:
```python
A = [0x66, 0x5B, 0x12, 0xCE, 0x98, 0x60, 0xA7, 0x5E,
     0x46, 0x27, 0xD2, 0xB5, 0x61, 0x95, 0x7C, 0x02, 0x4C]
B = [0x31, 0x33, 0x73, 0xBA, 0xDC, 0xF, 0xFE]

F = ''.join(chr(a^b) for a, b in zip(A, B*3))
```

So the flag is: `EKO{WhatDoYouThinkM1?}`

___
