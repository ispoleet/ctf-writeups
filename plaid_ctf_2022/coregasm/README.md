
## Plaid CTF 2022 - coregasm (RE)
##### 08-09/04/2022 (24hr)
___

### Description: 

When you get a core file, you're usually pretty sad. Hopefully this one makes you happy.

___

### Solution


This challenge consists of a binary that contains **4** different flags.
We start by opening the [coregasm](./coregasm.e07b31ed874fad9158b5d7c0053298335360ec69a922dd362cad6dfd3a30728b.tgz) binary, which is very simple:
```c
int __cdecl main(int argc, const char **argv, const char **envp) {
  int v3; // ebx
  unsigned int v4; // edx
  const char *v5; // rdi

  puts("Would you like to see a magic trick?");
  puts("Printing all the flags...");
  fflush(0LL);
  v3 = open("/dev/urandom", 0);
  if ( read(v3, globalbuf, 0x40uLL) != 64 )
  {
    v4 = 187;
    v5 = "x == 64";
    goto LABEL_5;
  }
  close(v3);
  flag4(globalbuf);
  flag3(globalbuf);
  flag2(globalbuf);
  flag1(globalbuf);
  puts("///time for core///");
  fflush(0LL);
  if ( strcmp("///time for core///", *argv) )
  {
    v4 = 197;
    v5 = "strcmp(\"///time for core///\", argv[0]) == 0";
LABEL_5:
    __assert_fail(v5, "./main.c", v4, "main");
  }
  return 0;
}
```

Program loads a random buffer into memory and then does several modifications to derive the flags.
**To recover the flags we need to work backwards.**
The first task is to locate the the `globalbuf`. We open the 
[core](./coregasm.e07b31ed874fad9158b5d7c0053298335360ec69a922dd362cad6dfd3a30728b.tgz) file and we check the
registers before the crash:
```
r12            0x55fa6cf08014      0x55fa6cf08014
r13            0x55fa6cf080a8      0x55fa6cf080a8
```

These registers point to `.bss` section, so we look for a random, continuous sequence of **64**
bytes, surrounded by zeros, nearby this address:
```
000055FA6CF0A0A0  F5 E6 F1 E3 DE C7 C4 CB  C4 CB C4 FA C7 C4 CB C4
000055FA6CF0A0B0  CB C4 D8 A5 85 85 85 85  85 85 85 85 85 85 85 85
000055FA6CF0A0C0  85 85 85 85 85 85 85 85  85 85 85 85 85 85 85 85
000055FA6CF0A0D0  85 85 85 85 85 85 85 85  85 85 85 85 85 85 85 85
```

### Flag #1

Recovering the 1st flag is very simple:
```c
void __fastcall flag1(char *globalbuf) {
  __int64 i; // rax

  *globalbuf ^= 0x80083ED7E794313BLL;
  *(globalbuf + 1) ^= 0x75136EBBBF60734FuLL;
  *(globalbuf + 2) ^= 0x6C46A704AF4D8380uLL;
  *(globalbuf + 3) ^= 0xC1991AB8C1674BBFLL;
  *(globalbuf + 4) ^= 0xDC0B819132401105LL;
  *(globalbuf + 5) ^= 0xAF4464465D7D4DC0LL;
  *(globalbuf + 6) ^= 0x9EAD54BD51956632LL;
  *(globalbuf + 7) ^= 0xC4D2C981312F974uLL;
  puts("Flag 1:");
  puts(globalbuf);
  fflush(0LL);
  for ( i = 0LL; i != 64; ++i )
    globalbuf[i] ^= 0xA5u;
}
```

We know the contents of `globalbuf` at the moment of the crash, so
we just have to XOR them with `A5h` to recover the first flag:
```python
    flag1 = [g ^ 0xA5 for g in globalbuf]
```

So, the first flag is: `PCTF{banana_banana}`.

### Flag #2

To recover the 2nd flag we continue working backwards. After XORing with `A5h`, we
XOR `globalbuf` with the constants at the top of `flag1` (`0x80083ED7E794313B`, and so on).
Then we look at the contents of `flag2`:
```
void __fastcall flag2(char *globalbuf) {
  FILE *fp; // rax
  __int64 i; // rdx
  __int64 j; // rax
  _BYTE stack_buf[152]; // [rsp+0h] [rbp-98h] BYREF

  fp = fopen("./otp", "r");
  if ( fread(stack_buf, 0x80uLL, 1uLL, fp) != 1 )
    __assert_fail("items == 1", "./main.c", '*', "flag2");
  for ( i = 0LL; i != 64; ++i )
    globalbuf[i] ^= stack_buf[i];
  *globalbuf ^= 0x6301641F2866C34BuLL;
  *(globalbuf + 1) ^= 0x1EB4DEF5AC740DCFuLL;
  *(globalbuf + 2) ^= 0x4F490B1C93DF4671uLL;
  *(globalbuf + 3) ^= 0x9F82C6EC691CA0B0LL;
  *(globalbuf + 4) ^= 0xC2D142FCAF5DCA6BLL;
  *(globalbuf + 5) ^= 0xFA68305EB42FCB00LL;
  *(globalbuf + 6) ^= 0x62212646A9E04B61uLL;
  *(globalbuf + 7) ^= 0xBB73AD9A9992C6BuLL;
  puts("Flag 2:");
  puts(globalbuf);
  fflush(0LL);
  for ( j = 0LL; j != 64; ++j )
    globalbuf[j] ^= stack_buf[j + 64];
}
```

Function loads a random **128** byte buffer onto stack and uses it to XOR the flag.
To locate the `otp` we go back to the
[core](./coregasm.e07b31ed874fad9158b5d7c0053298335360ec69a922dd362cad6dfd3a30728b.tgz)
file and we look for a continuous, random sequence of **128** bytes on stack (this was easy to find):
```
000055FA6D3054A0  1B 80 32 DA 78 8C 0D F2  65 C6 A0 32 97 BF DA 7F
000055FA6D3054B0  1F 27 FB F1 7D 65 28 DE  D1 81 7E 08 82 A7 EC 01
000055FA6D3054C0  0A 40 10 F5 38 17 63 67  EA 4E BA 20 7F 10 48 DA
000055FA6D3054D0  40 6B C0 89 6E 86 24 72  4B 0C B9 89 81 4C A3 39
000055FA6D3054E0  3B 31 94 E7 D7 3E 08 80  4F 73 60 CA BB 6E 13 75
000055FA6D3054F0  80 83 14 CD 45 E9 07 22  FE 4A 25 80 F6 5B D7 80
000055FA6D305500  58 31 40 32 91 81 0B DC  C0 4D 7D 5D 46 64 44 AF
000055FA6D305510  32 66 95 51 BD 54 AD 9E  74 F9 12 13 98 2C 4D 0C
```

Once, we recover the `otp` we use the last **64** bytes to XOR and recover the flag:

```python
    flag2 = [globalbuf[i] ^ 0xA5 ^ A[i] ^ otp[i + 64] for i in range(64)]
```

So, the second flag is: `PCTF{banana*banana$banana!banana}`.


### Flag #3

Before we move on, we first XOR the `globalbuf` (again) with the constants at
the top of `flag2` (`0x6301641F2866C34B`, and so on) and then with the first
**64** bytes of the `otp`. Function `flag3` runs some random computations:
```c
void __fastcall flag3(unsigned int *globalbuf) {
  unsigned int g_0; // ecx
  unsigned int g_1_add_0; // ecx
  unsigned int g_4_sub_3; // r9d
  unsigned int g_7; // edi
  unsigned int g_10_div_9; // eax
  unsigned int g_13; // esi
  unsigned int g_6_mul_7; // edi
  unsigned int g_12_xor_13; // esi

  *globalbuf ^= 0x2F01D6F7C8701DA9uLL;
  *(globalbuf + 1) ^= 0x230ED5E2EC453098uLL;
  *(globalbuf + 2) ^= 0x2F01DAE2EF4A3F97uLL;
  *(globalbuf + 3) ^= 0x2301DAE2EC45309BuLL;
  *(globalbuf + 4) ^= 0x230ED5E2EC4A3F97uLL;
  *(globalbuf + 5) ^= 0x2002D5E2EC4A3F97uLL;
  *(globalbuf + 6) ^= 0x200ED5E2EF4A3F97uLL;
  *(globalbuf + 7) ^= 0x6140948CF3453C97uLL;
  puts("Flag 3:");
  puts(globalbuf);
  fflush(0LL);
  //  0 ~> 0xB4000000
  //  1 ~> 0xFF6D8A1C
  //  2 ~> 0xB4B5A5CB
  //  3 ~> 0x00000000
  //  4 ~> 0x00000000
  //  5 ~> 0xFF000000
  //  6 ~> 0x00000000
  //  7 ~> 0xFF000000
  //  8 ~> 0x7A6D8A1C
  //  9 ~> 0x859275E4
  // 10 ~> 0xB4B5A5CA
  // 11 ~> 0x00000001
  // 12 ~> 0x00000001
  // 13 ~> 0x30258008
  // 14 ~> 0x00000000
  // 15 ~> 0x12345678
  g_0 = *globalbuf;
  globalbuf[15] = 0x12345678;
  g_1_add_0 = globalbuf[1] + g_0;
  g_4_sub_3 = globalbuf[4] - globalbuf[3];
  g_7 = globalbuf[7];
  g_10_div_9 = globalbuf[10] / globalbuf[9];
  g_13 = globalbuf[13];
  globalbuf[2] = g_1_add_0; 
  g_6_mul_7 = globalbuf[6] * g_7;
  g_12_xor_13 = globalbuf[12] ^ g_13;
  globalbuf[5] = g_4_sub_3;
  globalbuf[8] = g_6_mul_7;
  globalbuf[14] = g_12_xor_13;
  globalbuf[11] = g_10_div_9;
  *globalbuf = g_4_sub_3 & g_1_add_0;
  globalbuf[1] = g_6_mul_7 | g_4_sub_3;
  globalbuf[4] = g_12_xor_13 * g_10_div_9;
  globalbuf[3] = g_6_mul_7 % g_10_div_9;
  globalbuf[6] = g_12_xor_13 / g_1_add_0;
  globalbuf[7] = g_4_sub_3 + g_12_xor_13;
  globalbuf[9] = g_12_xor_13 - g_6_mul_7;
  globalbuf[10] = g_10_div_9 ^ g_1_add_0;
  globalbuf[13] = g_6_mul_7 & g_1_add_0;
  globalbuf[12] = g_10_div_9 % g_4_sub_3;
}
```

The problem here is that we cannot move backwards and recover the `globalbuf` before
the computations take place. If we look at the computations, we will see that the
values of `globalbuf[2]`, `[5]`, `[8]`, `[11]`, `[14]` and `[15]` do not participate in the
computations, but instead they are being overwritten. That is, they can have any value.


To find the solution here, we need to look 1 more step back, at the end of `flag4`:
```c
void __fastcall flag4(unsigned __int8 *globuf) {
  /* .... */
  do
    *&globuf[8 * i++] = prod;
  while ( i != 8 );
}
```

The `globalbuf` gets the same **8** byte value, repeated **8** times. So, if we can recover
*any* **8** bytes from the flag, we can recover the whole flag. To find a partial flag, we
go back to the [core](./coregasm.e07b31ed874fad9158b5d7c0053298335360ec69a922dd362cad6dfd3a30728b.tgz)
file and we take a look at all strings:
```
000055FA6D304260  2F 2F 2F 74 69 6D 65 20  66 6F 72 20 63 6F 72 65  ///time for core
000055FA6D304270  2F 2F 2F 0A 62 61 6E 61  6E 61 7D 0A 61 6E 61 6E  ///.banana}.anan
000055FA6D304280  61 21 62 61 6E 61 6E 61  7D 0A 6E 62 6E 61 6E 62  a!banana}.nbnanb
000055FA6D304290  6E 61 6E 62 6E 61 62 61  6E 61 6E 61 6E 61 6E 61  nanbnabanananana
000055FA6D3042A0  6E 62 61 7D 0A 00 00 00  00 00 00 00 00 00 00 00  nba}............
```

This string is somewhere inside the stdout buffer and we see that it has been overwritten
by subsequent flags. However, we can get the last bytes of the third flag:
`nbnanbnanbnabanananananba}`.

If we XOR (with respect to the proper alignment of course) the last bytes of the flag,
with the 3rd set of constants from `flag3` (`0x2F01D6F7C8701DA9`, and so on) we can
recover the original contents of `globalbuf` before the computations take place:
```python
    C = (
        list(0x2F01D6F7C8701DA9.to_bytes(8, 'little')) +
        list(0x230ED5E2EC453098.to_bytes(8, 'little')) +
        list(0x2F01DAE2EF4A3F97.to_bytes(8, 'little')) +
        list(0x2301DAE2EC45309B.to_bytes(8, 'little')) +
        list(0x230ED5E2EC4A3F97.to_bytes(8, 'little')) +
        list(0x2002D5E2EC4A3F97.to_bytes(8, 'little')) +
        list(0x200ED5E2EF4A3F97.to_bytes(8, 'little')) +
        list(0x6140948CF3453C97.to_bytes(8, 'little')))

    # Recovered from `core` at address 0x55FA6D304260.
    half_flag = 'PCTF{.............................nbnanbnanbnabanananananba}' 

    print(f'[+] Half flag from core: {half_flag}')

    globuf_stage4 = [ord(h) ^ c for h, c in zip(half_flag, C)]

    print('[+] globuf stage #4 (as QWORDs):')
    for i in range(0, 64, 8):
        print(f'[+] {i:2d} ~> {make_hex(globuf_stage4[i:i + 8])}')
```

We split the result into **8** byte chunks (since the contents are the same QWORD repreated **8** times):
```
     0 ~> F9 5E 24 8E 8C F8 2F 01
     8 ~> B6 1E 6B C2 CC FB 20 0D
    16 ~> B9 11 64 C1 CC F4 2F 01
    24 ~> B5 1E 6B C2 CC F4 2F 0D
    32 ~> B9 11 24 8E 8C B4 60 41
    40 ~> F9 5E 24 8E 8C B4 60 41
    48 ~> F9 5E 24 8E 8C B4 60 41
    56 ~> F9 5E 24 8E
```

As you can see, after offset **40** the same QWORD gets repeated (this is because we know the last bytes
of the flag). So the contents of `globalbuf` before the computations at `flag3` take place are 
`F9 5E 24 8E 8C B4 60 41` repeated **8** times.

To recover the flag all we have to do, is to XOR the 3rd set of constants from `flag3` with the repeated
sequence:
```python
    secret = globuf_stage4[40: 48]
    print(f'[+] Repeated secret: {make_hex(secret)}')

    flag3 = [s ^ c for s, c in zip(secret*8, C)]
```

So, the third flag is: `PCTF{bananabnanbnanannanbnabnnabnanbnanbnanbnabanananananba}`.


### Flag #4

The last part is also the hardest one:
```c
void __fastcall flag4(unsigned __int8 *globuf) {
  long double a; // fst7
  long double b; // fst6
  long double c; // fst5
  long double d; // fst4
  long double e; // fst3
  long double f; // fst2
  __int64 i; // rax
  long double prod; // fst7
  double g; // [rsp+8h] [rbp-10h]

  *globuf ^= 0xBC019EE23A6BF6BFLL;
  *(globuf + 1) ^= 0xE9483020414B589CLL;
  *(globuf + 2) ^= 0x217B7D11E6C9A8A3uLL;
  *(globuf + 3) ^= 0x3B3924CE775A8541uLL;
  *(globuf + 4) ^= 0x6BBDB2171BAD0EC8uLL;
  *(globuf + 5) ^= 0xB0B0429F1F0242E9LL;
  *(globuf + 6) ^= 0x5DE514AB5ABE8132uLL;
  *(globuf + 7) ^= 0x50789E90A63C152EuLL;
  puts("Flag 4:");
  puts(globuf);
  fflush(0LL);
  // To make things simple in debugger:
  // for i in range(64): ida_bytes.patch_word(0x5555555580A0+i, (0x10+i))

  // a = 0x3FFF151413121110 = 0x3FFF << 48 | glo[0:6]
  a = COERCE_DOUBLE((*(globuf + 2) << 32) | *globuf | 0x3FFF000000000000LL);
  // b = 0x3FFF1B1A19181716 = 0x3FFF << 48 | glo[6:12]
  b = COERCE_DOUBLE((*(globuf + 5) << 32) | *(globuf + 6) | (*(globuf + 2) << 32) & 0xC000000000000000LL | 0x3FFF000000000000LL)
    + a;
  // c = 0x3FFF21201F1E1D1C = 0x3FFF << 48 | glo[12:18]
  c = COERCE_DOUBLE((*(globuf + 8) << 32) | *(globuf + 3) | (*(globuf + 5) << 32) & 0xFFFF000000000000LL | (*(globuf + 2) << 32) & 0xC000000000000000LL | 0x3FFF000000000000LL)
    + b;
  // d = 0x3FFF272625242322 = 0x3FFF << 48 | glo[18:24]
  d = COERCE_DOUBLE((*(globuf + 11) << 32) | *(globuf + 18) | (*(globuf + 8) << 32) & 0xFFFF000000000000LL | (*(globuf + 5) << 32) & 0xC000000000000000LL | 0x3FFF000000000000LL)
    + c;
  // e = 0x3FFF2D2C2B2A2928 = 0x3FFF << 48 | glo[24:30]
  e = COERCE_DOUBLE((*(globuf + 14) << 32) | *(globuf + 6) | (*(globuf + 11) << 32) & 0xFFFF000000000000LL | (*(globuf + 8) << 32) & 0xFFFF000000000000LL | (*(globuf + 5) << 32) & 0xC000000000000000LL | 0x3FFF000000000000LL)
    + d;
  // f = 0x3FFF333231302F2E = 0x3FFF << 48 | glo[30:36]
  f = COERCE_DOUBLE((*(globuf + 17) << 32) | *(globuf + 30) | (*(globuf + 14) << 32) & 0xFFFF000000000000LL | (*(globuf + 11) << 32) & 0xFFFF000000000000LL | (*(globuf + 8) << 32) & 0xC000000000000000LL | 0x3FFF000000000000LL)
    + e;
  // g = 0x3FFF393837363534 = 0x3FFF << 48 | glo[36:40]
  *&g = (*(globuf + 20) << 32) | *(globuf + 9) | (*(globuf + 17) << 32) & 0xFFFF000000000000LL | (*(globuf + 14) << 32) & 0xFFFF000000000000LL | (*(globuf + 11) << 32) & 0xFFFF000000000000LL | (*(globuf + 8) << 32) & 0xC000000000000000LL | 0x3FFF000000000000LL;
  i = 0LL;
  prod = a
       * (b
        * (c
         * (d
          * (e
           * (f
            * ((g + f)
             // next double = 0x3FFF3F3E3D3C3B3A = 0x3FFF << 48 | glo[40:46]
             * (COERCE_DOUBLE((*(globuf + 23) << 32) | *(globuf + 42) | (*(globuf + 20) << 32) & 0xFFFF000000000000LL | (*(globuf + 17) << 32) & 0xFFFF000000000000LL | (*(globuf + 14) << 32) & 0xFFFF000000000000LL | (*(globuf + 11) << 32) & 0xC000000000000000LL | 0x3FFF000000000000LL)
              + g
              + f)))))));
  do
    *&globuf[8 * i++] = prod;
  while ( i != 8 );
}
```

The first part is to recover the values of `a`, `b`, ..., `g`. A quick n' dirty way is to execute
[coregasm](./coregasm) and set a breakpoint at:
```assembly
.text:00005555555554ED                 mov     edi, [rbx]
```

Then set the contents of `globalbuf` as `10 11 12 ... 3F 40`. Then set a breakpoint before every `fld`
instruction which is used to convert the QWORD into a double:
```assembly
.text:0000555555555524                 fld     [rsp+18h+g]
```

And then inspect the contents of `[rsp-8]`. That way we can quickly find what bytes of `globalbuf`
are used for each variable:
```
// a = 0x3FFF151413121110 = 0x3FFF << 48 | glo[0:6]
// b = 0x3FFF1B1A19181716 = 0x3FFF << 48 | glo[6:12]
// c = 0x3FFF21201F1E1D1C = 0x3FFF << 48 | glo[12:18]
// d = 0x3FFF272625242322 = 0x3FFF << 48 | glo[18:24]
// e = 0x3FFF2D2C2B2A2928 = 0x3FFF << 48 | glo[24:30]
// f = 0x3FFF333231302F2E = 0x3FFF << 48 | glo[30:36]
// g = 0x3FFF393837363534 = 0x3FFF << 48 | glo[36:40]
// next double = 0x3FFF3F3E3D3C3B3A = 0x3FFF << 48 | glo[40:46]
```

The `prod` variable is computed as follows:
```
prod = a * b * c * d * e * f * g * h
     = a * b * c * d * e * f * g * (g + C8)
     = a * b * c * d * e * f * (f + C7) * (f + C7 + C8)
     = a * b * c * d * e * (e + C6) * (e + C6 + C7) * (e + C6 + C7 + C8)
     = a * b * c * d * (d + C5) * (d + C5 + C6) * (d + C5 + C6 + C7) * (d + C5 + C6 + C7 + C8)
     = a * b * c * (c + C4) * (c + C4 + C5) * (c + C4 + C5 + C6) * (c + C4 + C5 + C6 + C7) * (c + C4 + C5 + C6 + C7 + C8)
     = a * b * (b + C3) * (b + C3 + C4) * (b + C3 + C4 + C5) * (b + C3 + C4 + C5 + C6) * (b + C3 + C4 + C5 + C6 + C7) * (b + C3 + C4 + C5 + C6 + C7 + C8)
     = a * (a + C2) * (a + C2 + C3) * (a + C2 + C3 + C4) * (a + C2 + C3 + C4 + C5) * (a + C2 + C3 + C4 + C5 + C6) * (a + C2 + C3 + C4 + C5 + C6 + C7) * (a + C2 + C3 + C4 + C5 + C6 + C7 + C8)
     = C1 * (C1 + C2) * (C1 + C2 + C3) * (C1 + C2 + C3 + C4) * (C1 + C2 + C3 + C4 + C5) * (C1 + C2 + C3 + C4 + C5 + C6) * (C1 + C2 + C3 + C4 + C5 + C6 + C7) * (C1 + C2 + C3 + C4 + C5 + C6 + C7 + C8)

where,

C1 = double(0x3FFF << 48 | globalbuf[0:6]
...
C8 = double(0x3FFF << 48 | globalbuf[36:40]
```

So all we have to do, is to find an assignment for `C1`, `C2`, ..., `C8` to make the following equation hold:
```
C1*(C1+C2)*(C1+C2+C3)*(C1+C2+C3+C4)*(C1+C2+C3+C4+C5)*(C1+C2+C3+C4+C5+C6)*(C1+C2+C3+C4+C5+C6+C7)*(C1+C2+C3+C4+C5+C6+C7+C8) = double(0xF95E248E8CB46041)
```

The first attempt was to use z3, but it was very slow. Furthermore, this equation seems to have an infinite number of solutions
when it comes to real numbers, so we need to narrow down the search. If we look at the 
[core](./coregasm.e07b31ed874fad9158b5d7c0053298335360ec69a922dd362cad6dfd3a30728b.tgz)
dump, we see it contains the values of the FPU stack:
```
gef➤  info reg all
st0            15.6579354707501636756 (raw 0x4002fa86e7581c014d00)
st1            214.831820219884093451 (raw 0x4006d6d4f22b808dbff5)
st2            2526.22752352315034186 (raw 0x400a9de3a3efb4b005ce)
st3            24751.5189151917131252 (raw 0x400dc15f09af40839c63)
st4            193984.053677134516846 (raw 0x4010bd70036f723852be)
st5            1139716.96293101242827 (raw 0x40138b2027b4152cb578)
st6            4457828.61824004405162 (raw 0x4015880ac93c89f5848f)
st7            8758372.44193981720582 (raw 0x401685a4647122f7c5b3)
fctrl          0x37f               0x37f
fstat          0x20                0x20
ftag           0xffff              0xffff
fiseg          0x55fa              0x55fa
fioff          0x6cf07636          0x6cf07636
foseg          0x0                 0x0
fooff          0x0                 0x0
fop            0x0                 0x0
```

Let's see how the FPU is modified inside `flag4`:
```assembly
.text:0000555555555524     fld     [rsp+18h+g]                 ; st0 = a
.text:0000555555555528     or      rax, rdx
...
.text:0000555555555544     fld     [rsp+18h+g]                 ; st0 = b, st1 = a
.text:0000555555555548     fadd    st, st(1)                   ; st0 = b + a, st1 = a
...
.text:0000555555555566     fld     [rsp+18h+g]                 ; st0 = c, st1 = a + b, st2 = a
.text:000055555555556A     fadd    st, st(1)                   ; st0 = a + b + c, st1 = a + b, st2 = a
...
.text:0000555555555588     fld     [rsp+18h+g]                 ; st0 = d, st1 = a+b+c, st2 = a+b, st3 = a
.text:000055555555558C     fadd    st, st(1)                   ; st0 = a+b+c+d, st1=a+b+c, st2=a+b, st3 = a

...

.text:0000555555555614     fld     [rsp+18h+g]                 ; st0 = h, st1 = a+b+c...
.text:0000555555555618     xor     eax, eax
.text:000055555555561A     fadd    st, st(1)                   ; st0 = a+b+c+...+h, st1= ...
.text:000055555555561C ; After mul
.text:000055555555561C st0 = (a+b+...+h)
.text:000055555555561C st1 = (a+b+...+h)*(a+b+...+g)
.text:000055555555561C st2 = (a+b+...+f)
.text:000055555555561C ...
.text:000055555555561C st7 = a
.text:000055555555561C ; After pop
.text:000055555555561C st0 = (a+b+...+h)*(a+b+...+g)
.text:000055555555561C st1 = (a+b+...+f)
.text:000055555555561C st2 = ...
.text:000055555555561C st7 = (a+b+...+h)
.text:000055555555561C     fmulp   st(1), st
.text:000055555555561E     fmulp   st(1), st
.text:0000555555555620     fmulp   st(1), st
.text:0000555555555622     fmulp   st(1), st
.text:0000555555555624     fmulp   st(1), st
.text:0000555555555626     fmulp   st(1), st
.text:0000555555555628 ; After mul
.text:0000555555555628 st0 = (a+b+...+h)*(a+b+...+g)*...*(a+b)
.text:0000555555555628 st1 = (a+b+...+h)*(a+b+...+g)*...*(a+b) * a
.text:0000555555555628 st2 = (a+b+...+h)*(a+b+...+g)*...*(a+b+c)
.text:0000555555555628 ...
.text:0000555555555628 ; After pop
.text:0000555555555628 st0 = (a+b+...+h)*(a+b+...+g)*...*(a+b) * a
.text:0000555555555628 st1 = (a+b+...+h)*(a+b+...+g)*...*(a+b+c)
.text:0000555555555628 st2 = ...
.text:0000555555555628 st7 = (a+b+...+h)*(a+b+...+g)*...*(a+b)
.text:0000555555555628     fmulp   st(1), st
.text:000055555555562A
.text:000055555555562A loc_55555555562A:                       ; CODE XREF: flag4+1D9↓j
.text:000055555555562A     fst     qword ptr [rbx+rax*8]
.text:000055555555562D     inc     rax
.text:0000555555555630     cmp     rax, 8
.text:0000555555555634     jnz     short loc_55555555562A
.text:0000555555555636     fstp    st                          ; roll FPU stack again
```

After all additions take place (at `0x55555555561C`) the FPU stack is as follows:
```
st0: h + f + g + e + d + c + b + a = H
st1: g + f + e + d + c + b + a = G
st2: f + e + d + e + b + a = F
st3: e + d + c + b + a = E
st4: d + c + b + a = D
st5: c + b + a = C
st6: b + a = B
st7: a = A
```

The we have the `fmulp` instructions that mutliply `st1` with `st0`, store the result into `st1` and the pop the stack.
However, according to [here](https://en.wikibooks.org/wiki/X86_Assembly/Floating_Point), 
*pushing or popping items to or from the stack will only change the top index and store or wipe data respectively*, so
the `fmulp` rotates the contents of the `st*` registers by **1**. We have **7** `fmulp` instructions, so the FPU stack
over time is shown below:
```
st0: H    H*G    H*G*F     H*G*F*E            H*G*F*E*D*C*B*A                   H
st1: G    F      E         D                  H                                 H*G              
st2: F    E      D         C                  H*G                               H*G*F            
st3: E ~> D   ~> C      ~> B        ~> ... ~> H*G*F           ~~ final fstp ~~> H*G*F*E           
st4: D    C      B         A                  H*G*F*E                           H*G*F*E*D        
st5: C    B      A         H                  H*G*F*E*D                         H*G*F*E*D*C      
st6: B    A      H         H*G                H*G*F*E*D*C                       H*G*F*E*D*C*B    
st7: A    H      H*G       H*G*F              H*G*F*E*D*C*B                     H*G*F*E*D*C*B*A  
```

So, to recover `A` (=`a`) we have to divide `st7` with `st6` (`8758372.44193981720582 / 4457828.61824004405162`).
To recover `B` (=`a + b`) we have to divide `st6` with `st5`. After we find `B`, we can substract `a` from it and
recover `b`. We repeat this process until we recover all `a`, `b`, ..., `h`. 


```python
    fpu_stack = [
        15.6579354707501636756,
        214.831820219884093451,
        2526.22752352315034186,
        24751.5189151917131252,
        193984.053677134516846,
        1139716.96293101242827,
        4457828.61824004405162,
        8758372.44193981720582,
        1  # We need an extra element for the last iteration to avoid corner cases.
    ]

    flag4 = []
    abcdefgh = [0]*8

    for i in range(8):
        abcdefgh[i] = fpu_stack[7 - i] / fpu_stack[7 - i - 1]

        print(f"[+] Recovering {'ABCDEFGH'[i]} = {abcdefgh[i]}")

        if i > 0:
            abcdefgh[i] -= sum(abcdefgh[:i])
        
        ieee = IEEE754(abcdefgh[i])[0]
        print(f"[+] Recovering {'abcdefgh'[i]} = {abcdefgh[i]:.16f} ({ieee})")
        

        flag4.append(bytes.fromhex(ieee[6:]).decode('utf-8'))

    # Invert each double as we copy it in big endian.
    flag4 = ''.join(f[::-1] for f in flag4)
```

So, the fourth flag is: `PCTF{orange%~ou&glXd$i!dpdn't^pay#bahana*apain}`

___

