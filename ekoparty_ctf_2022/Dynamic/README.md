## EKO Party CTF 2022 - EKOLang (RE 490)
##### 02/11 - 04/11/2022 (50hr)

___

### Solution

We start from `main`:
```c
__int64 __fastcall u_main(int argc, char **argv)
{
  unsigned __int8 *pwd; // [rsp+68h] [rbp-8h]

  if ( argc != 2 )
    return 1LL;
  pwd = (unsigned __int8 *)argv[1];
  if ( u_get_pwd_len(pwd) != 76 )
    return 1LL;
  if ( (*pwd ^ (unsigned __int8)sub_400BFF()) != byte_6C0100 )
    return 1LL;
  if ( (pwd[1] ^ (unsigned __int8)sub_400CAD()) != byte_6C0101 )
    return 1LL;
  if ( (pwd[2] ^ (unsigned __int8)sub_400D5B()) != byte_6C0102 )
    return 1LL;
  if ( (pwd[3] ^ (unsigned __int8)sub_400E07()) != byte_6C0103 )
    return 1LL;
  if ( (pwd[4] ^ (unsigned __int8)sub_400EB5()) != byte_6C0104 )
    return 1LL;
  if ( (pwd[5] ^ (unsigned __int8)sub_400F62()) != byte_6C0105 )
    return 1LL;
  if ( (pwd[6] ^ (unsigned __int8)sub_40100F()) != byte_6C0106 )
    return 1LL;
  if ( (pwd[7] ^ (unsigned __int8)sub_4010BE()) != byte_6C0107 )
    return 1LL;
  if ( (pwd[8] ^ (unsigned __int8)sub_40116C()) != byte_6C0108 )
    return 1LL;
  if ( (pwd[9] ^ (unsigned __int8)sub_401218()) != byte_6C0109 )
    return 1LL;
  if ( (pwd[10] ^ (unsigned __int8)sub_4012C6()) != byte_6C010A )
    return 1LL;
  if ( (pwd[11] ^ (unsigned __int8)sub_401375()) != byte_6C010B )
    return 1LL;
  if ( (pwd[12] ^ (unsigned __int8)sub_401423()) != byte_6C010C )
    return 1LL;
  if ( (pwd[13] ^ (unsigned __int8)sub_4014D0()) != byte_6C010D )
    return 1LL;
  if ( (pwd[14] ^ (unsigned __int8)sub_40157D()) != byte_6C010E )
    return 1LL;
  if ( (pwd[15] ^ (unsigned __int8)sub_401627()) != byte_6C010F )
    return 1LL;
  if ( (pwd[16] ^ (unsigned __int8)sub_4016D5()) != byte_6C0110 )
    return 1LL;
  if ( (pwd[17] ^ (unsigned __int8)sub_401782()) != byte_6C0111 )
    return 1LL;
  if ( (pwd[18] ^ (unsigned __int8)sub_401831()) != byte_6C0112 )
    return 1LL;
  if ( (pwd[19] ^ (unsigned __int8)sub_4018DE()) != byte_6C0113 )
    return 1LL;
  if ( (pwd[20] ^ (unsigned __int8)sub_40198C()) != byte_6C0114 )
    return 1LL;
  if ( (pwd[21] ^ (unsigned __int8)sub_401A3B()) != byte_6C0115 )
    return 1LL;
  if ( (pwd[22] ^ (unsigned __int8)sub_401AEA()) != byte_6C0116 )
    return 1LL;
  if ( (pwd[23] ^ (unsigned __int8)sub_401B98()) != byte_6C0117 )
    return 1LL;
  if ( (pwd[24] ^ (unsigned __int8)sub_401C47()) != byte_6C0118 )
    return 1LL;
  if ( (pwd[25] ^ (unsigned __int8)sub_401CF5()) != byte_6C0119 )
    return 1LL;
  if ( (pwd[26] ^ (unsigned __int8)sub_401DA4()) != byte_6C011A )
    return 1LL;
  if ( (pwd[27] ^ (unsigned __int8)sub_401E50()) != byte_6C011B )
    return 1LL;
  if ( (pwd[28] ^ (unsigned __int8)sub_401EFD()) != byte_6C011C )
    return 1LL;
  if ( (pwd[29] ^ (unsigned __int8)sub_401FA9()) != byte_6C011D )
    return 1LL;
  if ( (pwd[30] ^ (unsigned __int8)sub_402059()) != byte_6C011E )
    return 1LL;
  if ( (pwd[31] ^ (unsigned __int8)sub_402107()) != byte_6C011F )
    return 1LL;
  if ( (pwd[32] ^ (unsigned __int8)sub_4021B7()) != byte_6C0120 )
    return 1LL;
  if ( (pwd[33] ^ (unsigned __int8)sub_402266()) != byte_6C0121 )
    return 1LL;
  if ( (pwd[34] ^ (unsigned __int8)sub_402313()) != byte_6C0122 )
    return 1LL;
  if ( (pwd[35] ^ (unsigned __int8)sub_4023C1()) != byte_6C0123 )
    return 1LL;
  if ( (pwd[36] ^ (unsigned __int8)sub_402471()) != byte_6C0124 )
    return 1LL;
  if ( (pwd[37] ^ (unsigned __int8)sub_40251D()) != byte_6C0125 )
    return 1LL;
  if ( (pwd[38] ^ (unsigned __int8)sub_4025CD()) != byte_6C0126 )
    return 1LL;
  if ( (pwd[39] ^ (unsigned __int8)sub_40267C()) != byte_6C0127 )
    return 1LL;
  if ( (pwd[40] ^ (unsigned __int8)sub_40272A()) != byte_6C0128 )
    return 1LL;
  if ( (pwd[41] ^ (unsigned __int8)sub_4027DA()) != byte_6C0129 )
    return 1LL;
  if ( (pwd[42] ^ (unsigned __int8)sub_402885()) != byte_6C012A )
    return 1LL;
  if ( (pwd[43] ^ (unsigned __int8)sub_402935()) != byte_6C012B )
    return 1LL;
  if ( (pwd[44] ^ (unsigned __int8)sub_4029E1()) != byte_6C012C )
    return 1LL;
  if ( (pwd[45] ^ (unsigned __int8)sub_402A8F()) != byte_6C012D )
    return 1LL;
  if ( (pwd[46] ^ (unsigned __int8)sub_402B3D()) != byte_6C012E )
    return 1LL;
  if ( (pwd[47] ^ (unsigned __int8)sub_402BE9()) != byte_6C012F )
    return 1LL;
  if ( (pwd[48] ^ (unsigned __int8)sub_402C96()) != byte_6C0130 )
    return 1LL;
  if ( (pwd[49] ^ (unsigned __int8)sub_402D45()) != byte_6C0131 )
    return 1LL;
  if ( (pwd[50] ^ (unsigned __int8)sub_402DF4()) != byte_6C0132 )
    return 1LL;
  if ( (pwd[51] ^ (unsigned __int8)sub_402EA3()) != byte_6C0133 )
    return 1LL;
  if ( (pwd[52] ^ (unsigned __int8)sub_402F50()) != byte_6C0134 )
    return 1LL;
  if ( (pwd[53] ^ (unsigned __int8)sub_402FFE()) != byte_6C0135 )
    return 1LL;
  if ( (pwd[54] ^ (unsigned __int8)sub_4030AD()) != byte_6C0136 )
    return 1LL;
  if ( (pwd[55] ^ (unsigned __int8)sub_403158()) != byte_6C0137 )
    return 1LL;
  if ( (pwd[56] ^ (unsigned __int8)sub_403206()) != byte_6C0138 )
    return 1LL;
  if ( (pwd[57] ^ (unsigned __int8)sub_4032B5()) != byte_6C0139 )
    return 1LL;
  if ( (pwd[58] ^ (unsigned __int8)sub_403365()) != byte_6C013A )
    return 1LL;
  if ( (pwd[59] ^ (unsigned __int8)sub_403413()) != byte_6C013B )
    return 1LL;
  if ( (pwd[60] ^ (unsigned __int8)sub_4034C3()) != byte_6C013C )
    return 1LL;
  if ( (pwd[61] ^ (unsigned __int8)sub_403572()) != byte_6C013D )
    return 1LL;
  if ( (pwd[62] ^ (unsigned __int8)sub_403621()) != byte_6C013E )
    return 1LL;
  if ( (pwd[63] ^ (unsigned __int8)sub_4036CD()) != byte_6C013F )
    return 1LL;
  if ( (pwd[64] ^ (unsigned __int8)sub_40377D()) != byte_6C0140 )
    return 1LL;
  if ( (pwd[65] ^ (unsigned __int8)sub_40382B()) != byte_6C0141 )
    return 1LL;
  if ( (pwd[66] ^ (unsigned __int8)sub_4038D7()) != byte_6C0142 )
    return 1LL;
  if ( (pwd[67] ^ (unsigned __int8)sub_403985()) != byte_6C0143 )
    return 1LL;
  if ( (pwd[68] ^ (unsigned __int8)sub_403A33()) != byte_6C0144 )
    return 1LL;
  if ( (pwd[69] ^ (unsigned __int8)sub_403AE2()) != byte_6C0145 )
    return 1LL;
  if ( (pwd[70] ^ (unsigned __int8)sub_403B91()) != byte_6C0146 )
    return 1LL;
  if ( (pwd[71] ^ (unsigned __int8)sub_403C3E()) != byte_6C0147 )
    return 1LL;
  if ( (pwd[72] ^ (unsigned __int8)sub_403CEE()) != byte_6C0148 )
    return 1LL;
  if ( (pwd[73] ^ (unsigned __int8)sub_403D9B()) != byte_6C0149 )
    return 1LL;
  if ( (pwd[74] ^ (unsigned __int8)sub_403E4A()) != byte_6C014A )
    return 1LL;
  if ( (pwd[75] ^ (unsigned __int8)sub_403EF7()) != byte_6C014B )
    return 1LL;
  sub_414380("Good!");
  return 0LL;
}
```

Each of these functions, invokes other functions and performs some random operations. For example:
```c
__int64 sub_400BFF()
{
  return (unsigned int)sub_400BD5() >> 12;
}

__int64 sub_400BD5()
{
  return (((unsigned int)sub_400BAB() >> 9) ^ 0x13) << 12;
}

__int64 sub_400BAB()
{
  return (((unsigned int)sub_400B81() >> 18) ^ 0x17) << 9;
}

__int64 sub_400B81()
{
  return (((unsigned int)sub_400B6D() >> 5) ^ 0x28) << 18;
}

__int64 sub_400B6D()
{
  return 6560LL;
}
```


### Cracking the Code

To get the flag, we have to get the return values of each top level function (e.g., `sub_400BFF()`)
and XOR them with the values of `byte_6C0100` array. Although we can do this manually (it's boring),
we will use Qiling to emulate the program and collect the values of the `xor` operations (there is
only one XOR operation per check; all checks have the same pattern):
```assembly
.text:0000000000403F89
.text:0000000000403F89 loc_403F89:                             ; CODE XREF: u_main+68↑j
.text:0000000000403F89         mov     eax, 0
.text:0000000000403F8E         call    sub_400CAD
.text:0000000000403F93         mov     [rbp+var_53], al
.text:0000000000403F96         mov     rax, [rbp+pwd]
.text:0000000000403F9A         add     rax, 1
.text:0000000000403F9E         movzx   eax, byte ptr [rax]
.text:0000000000403FA1         xor     [rbp+var_53], al
.text:0000000000403FA4         movzx   eax, cs:byte_6C0101
.text:0000000000403FAB         cmp     [rbp+var_53], al
.text:0000000000403FAE         jz      short loc_403FBA
.text:0000000000403FB0         mov     eax, 1
.text:0000000000403FB5         jmp     locret_404DEC
```

For more details, please refer to the [dynamic_crack.py](./dynamic_crack.py) file.


The flag is: `EKO{AFLFTW_b2379f00aa927b1372e8af7cc5c89200d9da229fe183c8cd01dc1969164d99f9}`

We try it and it works:
```
ispo@ispo-glaptop2:~/ctf/ekoparty_ctf_2022/Dynamic$ ./dynamic EKO{AFLFTW_b2379f00aa927b1372e8af7cc5c89200d9da229fe183c8cd01dc1969164d99f9}
Good!
```

___
