## Hack Lu CTF 2022 - Finger Food (RE 177)
##### 28/10 - 30/10/2022 (24hr)
___

### Description

*Reversing Finger Food with a twist.*
___

### Solution

We start from `main` at `0x404CC0` (we do some renaming first):
```c
int __fastcall u_main(int argc, char **argv) {
  /* ... */
  buf[38] = 0xD6;
  buf[37] = 0xE9;
  buf[36] = 0xFC;
  buf[35] = 0x1F;
  buf[34] = 0x93;
  buf[33] = 0x28;
  buf[32] = 0xC6;
  buf[31] = 0x62;
  buf[30] = 0x6D;
  buf[29] = 0x84;
  buf[28] = 0xF5;
  buf[27] = 0x46;
  buf[26] = 0xC4;
  buf[25] = 0x56;
  buf[24] = 0x13;
  buf[23] = 0xA1;
  buf[22] = 0x80;
  buf[21] = 0x5D;
  buf[20] = 0x91;
  buf[19] = 0x79;
  buf[18] = 0x91;
  buf[17] = 6;
  buf[16] = 0x89;
  buf[15] = 0xD8;
  buf[14] = 0x68;
  buf[13] = 0x40;
  buf[12] = 0x64;
  buf[11] = 0xAE;
  buf[10] = 0x18;
  buf[9] = 0x67;
  buf[8] = 0xB3;
  buf[7] = 0xBC;
  buf[6] = 0x89;
  buf[5] = 0x7A;
  buf[4] = 0xBB;
  buf[3] = 0xFF;
  buf[2] = 0xF7;
  buf[1] = 0x9B;
  buf[0] = 0xA;
  buf[77] = 0xCC;
  buf[76] = 0x6C;
  buf[75] = 0xCA;
  buf[74] = 0xB9;
  buf[73] = 0x31;
  buf[72] = 0xC3;
  buf[71] = 0x60;
  buf[70] = 0x2D;
  buf[69] = 0x3B;
  buf[68] = 0x4E;
  buf[67] = 0x93;
  buf[66] = 0x11;
  buf[65] = 0x8D;
  buf[64] = 0x20;
  buf[63] = 0xAE;
  buf[62] = 0x3B;
  buf[61] = 0x4A;
  buf[60] = 0xFC;
  buf[59] = 0x2D;
  buf[58] = 0x41;
  buf[57] = 0x2B;
  buf[56] = 0xD1;
  buf[55] = 0x51;
  buf[54] = 0x75;
  buf[53] = 6;
  buf[52] = 0xDF;
  buf[51] = 0x33;
  buf[50] = 0x7D;
  buf[49] = 0xE5;
  buf[48] = 0x2F;
  buf[47] = 0x7E;
  buf[46] = 0x85;
  buf[45] = 0x52;
  buf[44] = 0x44;
  buf[43] = 0x40;
  buf[42] = 0x98;
  buf[41] = 0x96;
  buf[40] = 0x2F;
  buf[39] = 0xA4;
  u_obj_ctor((__int64)fin);
  argv_1 = argv[1];
  //     typedef unsigned int openmode;
  //     static const openmode app    = 0x01;
  //     static const openmode ate    = 0x02;
  //     static const openmode binary = 0x04;
  //     static const openmode in     = 0x08;
  //     static const openmode out    = 0x10;
  //     static const openmode trunc  = 0x20;
  mode = u_OR(4, 8);                            // binary | in
  ZNSt14basic_ifstreamIcSt11char_traitsIcEE4openEPKcSt13_Ios_Openmode(fin, argv_1, mode);
  i = 0;
  while ( (u_feof_maybe((__int64)fin + *(_QWORD *)(fin[0] - 24)) & 1) == 0 )
  {
    nxt_chr = 0;
    u_istream_get(fin, &nxt_chr);
    nxt_chr_ = nxt_chr;
    if ( nxt_chr_ != u_decrypt_character(buf, i) )
    {
      retv = 1;
      goto END;
    }
    ++i;
  }
  retv = 0;
END:
  f_close(fin);
  if ( __readfsqword(0x28u) != canary )
    u_canary_failed();
  return retv;
}
```

Program takes as input a flag file and verifies it character by character.
The goal is to decrypt `buf`. Let's look at `u_decrypt_character` at `0x405080`:
```c
unsigned __int8 __fastcall u_decrypt_character(char *buf, int pos) {
  char *v2; // rax
  _BYTE *v3; // rax
  char v5; // [rsp+Ch] [rbp-24h]

  *(_DWORD *)qword_5CE518 = 0x90909090;
  if ( (unsigned int)pos >= 0x27uLL )
    return 0;
  // ''.join(chr((a - b) % 256) for a, b in zip(buf, buf[39:]))
  LODWORD(v2) = _ZN23QDefaultAnimationDriverC1EP13QUnifiedTimer((int)buf, pos);
  v5 = *v2;
  LODWORD(v3) = _ZN23QDefaultAnimationDriverC1EP13QUnifiedTimer((_DWORD)buf + 39, pos);
  return v5 - *v3;
}
```

`_ZN23QDefaultAnimationDriverC1EP13QUnifiedTimer` is a function from QT framework and it
actually returns a character from `buf` that is located at index `pos`. Here we get the
character at position `i` and the character at position `i+39` and we subtract them. Hence,
to get the flag all we have to do, is to run the following command:
```

buf = [
  0x0A, 0x9B, 0xF7, 0xFF, 0xBB, 0x7A, 0x89, 0xBC, 0xB3, 0x67, 
  0x18, 0xAE, 0x64, 0x40, 0x68, 0xD8, 0x89, 0x06, 0x91, 0x79, 
  0x91, 0x5D, 0x80, 0xA1, 0x13, 0x56, 0xC4, 0x46, 0xF5, 0x84, 
  0x6D, 0x62, 0xC6, 0x28, 0x93, 0x1F, 0xFC, 0xE9, 0xD6, 0xA4, 
  0x2F, 0x96, 0x98, 0x40, 0x44, 0x52, 0x85, 0x7E, 0x2F, 0xE5, 
  0x7D, 0x33, 0xDF, 0x06, 0x75, 0x51, 0xD1, 0x2B, 0x41, 0x2D, 
  0xFC, 0x4A, 0x3B, 0xAE, 0x20, 0x8D, 0x11, 0x93, 0x4E, 0x3B, 
  0x2D, 0x60, 0xC3, 0x31, 0xB9, 0xCA, 0x6C, 0xCC
]
print(''.join(chr((a - b) % 256) for a, b in zip(buf, buf[39:])))
```

Which gives us the flag: `flag{67758311abc85f8da6fe675b625febf2}`
___
