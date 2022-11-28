## HITCON CTF 2022 - Meow Way (RE 238)
##### 24-26/11/2022 (48hr)
___

### Description
 
*Reverse-engineering like the meow way!*

```
meow_way-d3c58f1d74aae3647cfb5c5bb2791da4d900dc16.zip
```

*Author: Hank Chen*
___


This challenge was quite weird. Let's start from `main` at `401380h`:
```c
int __cdecl main(int argc, const char **argv, const char **envp) {
  /* ... */
  if ( argc < 2 ) {
    printf("Usage: %s <flag>\n", (char)*argv);
    exit(1);
  }

  if ( strlen(argv[1]) != 48 ){
    printf("Wrong length\n", v4);
    exit(1);
  }

  flag = (char *)argv[1];
  off_40544C(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xC4, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053A8(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x16, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053B4(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x8E, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053F0(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x77, 0, v7, (int)v7 >> 31);
  ++flag;
  off_405448(flag, (int)flag >> 31, flag, (int)flag >> 31, 5, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053FC(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xB9, 0, v7, (int)v7 >> 31);
  ++flag;
  off_405400(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xD, 0, v7, (int)v7 >> 31);
  ++flag;
  off_405410(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x6B, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053F8(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x24, 0, v7, (int)v7 >> 31);
  ++flag;
  off_405430(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x55, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053D0(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x12, 0, v7, (int)v7 >> 31);
  ++flag;
  off_405434(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x35, 0, v7, (int)v7 >> 31);
  ++flag;
  off_40545C(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x76, 0, v7, (int)v7 >> 31);
  ++flag;
  off_405454(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xE7, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053C0(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xFB, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053E4(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xA0, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053C4(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xDA, 0, v7, (int)v7 >> 31);
  ++flag;
  off_405440(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x34, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053BC(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x84, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053AC(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xB4, 0, v7, (int)v7 >> 31);
  ++flag;
  off_405408(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xC8, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053D8(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x9B, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053B8(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xEF, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053C8(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xB4, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053E0(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xB9, 0, v7, (int)v7 >> 31);
  ++flag;
  off_405418(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xA, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053EC(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x57, 0, v7, (int)v7 >> 31);
  ++flag;
  off_405414(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x5C, 0, v7, (int)v7 >> 31);
  ++flag;
  off_405450(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xFE, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053E8(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xC5, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053D4(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x6A, 0, v7, (int)v7 >> 31);
  ++flag;
  off_40541C(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x73, 0, v7, (int)v7 >> 31);
  ++flag;
  off_40542C(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x49, 0, v7, (int)v7 >> 31);
  ++flag;
  off_405444(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xBD, 0, v7, (int)v7 >> 31);
  ++flag;
  off_405458(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x11, 0, v7, (int)v7 >> 31);
  ++flag;
  off_405420(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xD6, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053B0(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x8F, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053DC(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x6B, 0, v7, (int)v7 >> 31);
  ++flag;
  off_405464(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xA, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053CC(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x97, 0, v7, (int)v7 >> 31);
  ++flag;
  off_405424(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xAB, 0, v7, (int)v7 >> 31);
  ++flag;
  off_40543C(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x4E, 0, v7, (int)v7 >> 31);
  ++flag;
  off_405404(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xED, 0, v7, (int)v7 >> 31);
  ++flag;
  off_405428(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xFE, 0, v7, (int)v7 >> 31);
  ++flag;
  off_405460(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x97, 0, v7, (int)v7 >> 31);
  ++flag;
  off_40540C(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xF9, 0, v7, (int)v7 >> 31);
  ++flag;
  off_4053F4(flag, (int)flag >> 31, flag, (int)flag >> 31, 0x98, 0, v7, (int)v7 >> 31);
  off_405438(flag + 1, (int)(flag + 1) >> 31, flag + 1, (int)(flag + 1) >> 31, 0x65, 0, v7, (int)v7 >> 31);

  v5 = memcmp(glo_trg_buf, argv[1], 0x30u);
  if ( v5 ) {
    printf("Wrong\n", v5);
    exit(-1);
  }
  printf("I know you know the flag!\n", 0);

  return 0;
}
```

```assembly
.data:00405018 glo_trg_buf db 96h, 50h, 0CFh, 2Ch, 0EBh, 9Bh, 0AAh, 0FBh, 53h, 0ABh, 73h
.data:00405018                                         ; DATA XREF: _main+885↑o
.data:00405018         db 0DDh, 6Ch, 9Eh, 0DBh, 0BCh, 0EEh, 0ABh, 23h, 0D6h, 16h, 0FDh
.data:00405018         db 0F1h, 0F0h, 0B9h, 75h, 0C3h, 28h, 0A2h, 74h, 7Dh, 0E3h, 27h
.data:00405018         db 0D5h, 95h, 5Ch, 0F5h, 76h, 75h, 0C9h, 8Ch, 0FBh, 42h, 0Eh, 0BDh
.data:00405018         db 51h, 0A2h, 98h
```

Program takes as input (`argv[1]`) a **48** byte flag and encrypts it character-by-character.
At the end it compares it against `glo_trg_buf`.
Each of these `off_405*` function pointers is initialized in SEH:
```assembly
.rdata:004030CC 00 00 00 00 glo_init_array dd 0                     ; DATA XREF: __scrt_common_main_seh(void)+72↑o
.rdata:004030D0 0E 1D 40 00         dd offset sub_401D0E
.rdata:004030D4 00 10 40 00         dd offset sub_401000
.rdata:004030D8 10 10 40 00         dd offset sub_401010
.rdata:004030DC 20 10 40 00         dd offset sub_401020
......
.rdata:00403188 D0 12 40 00         dd offset sub_4012D0
.rdata:0040318C E0 12 40 00         dd offset sub_4012E0
.rdata:00403190 F0 12 40 00         dd offset sub_4012F0
```

We start with `off_40544C` (the first one; we have **48** of them):
```assembly
.text:00401000  sub_401000 proc near                    ; DATA XREF: .rdata:004030D4↓o
.text:00401000      push    ebp
.text:00401001      mov     ebp, esp
.text:00401003      mov     off_40544C, offset sub_4031C0
.text:0040100D      pop     ebp
.text:0040100E      retn
.text:0040100E  sub_401000 endp
```

Function `sub_4031C0` simply slides to the next function (using `retf` is suspicious)
```assembly
.rdata:004031C0             var_8   = dword ptr  0
.rdata:004031C0
.rdata:004031C0 6A 33               push    33h ; '3'
.rdata:004031C2 E8 00 00 00 00      call    $+5
.rdata:004031C7 83 04 24 05         add     dword ptr [esp+0], 5
.rdata:004031CB CB                  retf
.rdata:004031CB             sub_4031C0 endp ; sp-analysis failed
```

```assembly
.rdata:004031CC u_func_1 proc far
.rdata:004031CC
.rdata:004031CC var_4   = dword ptr -4
.rdata:004031CC arg_4   = dword ptr  0Ch
.rdata:004031CC
.rdata:004031CC         dec     eax
.rdata:004031CD         xor     eax, eax                ; eax = pointer to next character in flag
.rdata:004031CF         db      65h
.rdata:004031CF         dec     eax
.rdata:004031D1         mov     eax, [eax+60h]
.rdata:004031D4         dec     eax
.rdata:004031D5         movzx   eax, byte ptr [eax+2]
.rdata:004031D9         mov     ecx, [si+24h]
.rdata:004031DD         sbb     al, 67h ; 'g'
.rdata:004031DF         mov     [ecx], eax
.rdata:004031E1         test    eax, eax
.rdata:004031E3         jnz     short loc_4031FD
.rdata:004031E5         mov     edi, [si+24h]
.rdata:004031E9         add     al, 67h ; 'g'
.rdata:004031EB         mov     esi, [esp+arg_4]
.rdata:004031EF         mov     ecx, [si+24h]
.rdata:004031F3         adc     al, 67h ; 'g'
.rdata:004031F5         add     cl, [esi]
.rdata:004031F7         xor     cl, 0BAh
.rdata:004031FA         mov     [bx], cl
.rdata:004031FD
.rdata:004031FD loc_4031FD:                             ; CODE XREF: u_func_1+17↑j
.rdata:004031FD         call    $+5
.rdata:00403202         mov     dword ptr [esp+4], 23h ; '#'
.rdata:0040320A         add     [esp+4+var_4], 0Dh
.rdata:0040320E         retf
.rdata:0040320E u_func_1 endp ; sp-analysis failed
```

Although disassembly looks weird (e.g., at `4031CFh`), the decompiled code makes sense:
```c
void __usercall u_func_1(unsigned __int16 a1@<bx>, __int16 a2@<si>, int a3, int a4) {
  int v4; // eax
  void *retaddr[2]; // [esp+4h] [ebp+0h]

  v4 = (unsigned __int8)(*(_BYTE *)(MEMORY[0x5F] - 1 + 2) - 103);
  **(_DWORD **)(a2 + 36) = v4;
  if ( !v4 )
    *(_BYTE _ds *)a1 = (*(_BYTE *)a4 + *(_DWORD _ds *)(a4 + 36)) ^ 0xBA;
  retaddr[0] = (void *)35;
  JUMPOUT(0x4352FF);
}
```

This function is invoked as:
```c
  off_40544C(flag, (int)flag >> 31, flag, (int)flag >> 31, 0xC4, 0, v7, (int)v7 >> 31);
```

That is, function computes: `(arg1 + arg5) ^ 0xBA`, which should be equal to
`glo_trg_buf[0]`. That is:
```
    (flag[0] + 0xC4) ^ 0xBA == 0x96
```

The value `0xC4` is the parameter and changes for each of the **48** functions.
The constant `0xBA` is hardcoded in the function and is different for each
function as well.


Besides the constants that change in each function, the signs also change:
```c
void __usercall sub_403224(unsigned __int16 a1@<bx>, __int16 a2@<si>, int a3, int a4)
{
  int v4; // eax
  void *retaddr[2]; // [esp+4h] [ebp+0h]

  v4 = (unsigned __int8)(*(_BYTE *)(MEMORY[0x5F] - 1 + 2) - 103);
  **(_DWORD **)(a2 + 36) = v4;
  if ( !v4 )
    *(_BYTE _ds *)a1 = (*(_BYTE *)a4 + *(_DWORD _ds *)(a4 + 36)) ^ 0x2F;
  retaddr[0] = (void *)35;
  JUMPOUT(0x4358D7);
}
```

```c
void __usercall sub_4033AC(unsigned __int16 a1@<bx>, __int16 a2@<si>, int a3, int a4)
{
  int v4; // eax
  void *retaddr[2]; // [esp+4h] [ebp+0h]

  v4 = (unsigned __int8)(*(_BYTE *)(MEMORY[0x5F] - 1 + 2) - 103);
  **(_DWORD **)(a2 + 36) = v4;
  if ( !v4 )
    *(_BYTE _ds *)a1 = (*(_DWORD _ds *)(a4 + 36) - *(_BYTE *)a4) ^ 0xD0;
  retaddr[0] = (void *)35;
  JUMPOUT(0x4372DF);
}
```

Here, in `sub_403224` we have an addition, but in `sub_4033AC` a subtraction.
That is, the equation is:
```
    (0xB9 - flag[5]) ^ 0xD0 == 0x9B
```


### Cracking the Code

To decrypt the flag, we need to know the constants and the sign for
each function (functions are invoked in order, which makes reversing
easy). Then we can solve each equation and find the target value for
each flag character.
```python
func_consts = [
    0xBA, 0x2F, 0xCD, 0xF6, 0x9F, 0xD0, 0x22, 0xF7, 0xD0, 0x1F,
    0xA8, 0x3D, 0xC7, 0xA5, 0x47, 0x68, 0xD7, 0x4A, 0x96, 0x91,
    0x2E, 0x19, 0xC5, 0xE3, 0x88, 0xBD, 0x4E, 0x93, 0x13, 0xF1,
    0xCC, 0x47, 0xAB, 0xC9, 0x48, 0x2B, 0x09, 0x50, 0x4F, 0xE9,
    0xC0, 0x5E, 0xEF, 0x8B, 0x85, 0xCB, 0x55, 0x70
]

param_consts = [
    0xC4, 0x16, 0x8E, 0x77, 0x05, 0xB9, 0x0D, 0x6B, 0x24, 0x55,
    0x12, 0x35, 0x76, 0xE7, 0xFB, 0xA0, 0xDA, 0x34, 0x84, 0xB4,
    0xC8, 0x9B, 0xEF, 0xB4, 0xB9, 0xA,  0x57, 0x5C, 0xFE, 0xC5,
    0x6A, 0x73, 0x49, 0xBD, 0x11, 0xD6, 0x8F, 0x6B, 0x0A, 0x97,
    0xAB, 0x4E, 0xED, 0xFE, 0x97, 0xF9, 0x98, 0x65
]
```

To find the signs, we simply `grep` on the decompiled functions:
```c
*(_BYTE _ds *)a1 = (*(_BYTE *)a4 + *(_DWORD _ds *)(a4 + 36)) ^ 0xBA;
*(_BYTE _ds *)a1 = (*(_BYTE *)a4 + *(_DWORD _ds *)(a4 + 36)) ^ 0x2F;
*(_BYTE _ds *)a1 = (*(_BYTE *)a4 + *(_DWORD _ds *)(a4 + 36)) ^ 0xCD;
*(_BYTE _ds *)a1 = (*(_BYTE *)a5 + *(_DWORD _ds *)(a5 + 36)) ^ 0xF6;
*(_BYTE _ds *)a1 = (*(_BYTE *)a4 + *(_DWORD _ds *)(a4 + 36)) ^ 0x9F;
*(_BYTE _ds *)a1 = (*(_DWORD _ds *)(a4 + 36) - *(_BYTE *)a4) ^ 0xD0;
*(_BYTE _ds *)a1 = (*(_BYTE *)a5 + *(_DWORD _ds *)(a5 + 36)) ^ 0x22;
*(_BYTE _ds *)a1 = (*(_DWORD _ds *)(a5 + 36) - *(_BYTE *)a5) ^ 0xF7;
*(_BYTE _ds *)a1 = (*(_BYTE *)a4 + *(_DWORD _ds *)(a4 + 36)) ^ 0xD0;
*(_BYTE _ds *)a1 = (*(_BYTE *)a4 + *(_DWORD _ds *)(a4 + 36)) ^ 0x1F;
*(_BYTE _ds *)a1 = (*(_DWORD _ds *)(a5 + 36) - *(_BYTE *)a5) ^ 0xA8;
*(_BYTE _ds *)a1 = (*(_DWORD _ds *)(a4 + 36) - *(_BYTE *)a4) ^ 0x3D;
*(_BYTE _ds *)a1 = (*(_BYTE *)a5 + *(_DWORD _ds *)(a5 + 36)) ^ 0xC7;
*(_BYTE _ds *)a1 = (*(_BYTE *)a4 + *(_DWORD _ds *)(a4 + 36)) ^ 0xA5;
*(_BYTE _ds *)a1 = (*(_DWORD _ds *)(a4 + 36) - *(_BYTE *)a4) ^ 0x47;
*(_BYTE _ds *)a1 = (*(_BYTE *)a4 + *(_DWORD _ds *)(a4 + 36)) ^ 0x68;
*(_BYTE _ds *)a1 = (*(_BYTE *)a4 + *(_DWORD _ds *)(a4 + 36)) ^ 0xD7;
*(_BYTE _ds *)a1 = (*(_DWORD _ds *)(a4 + 36) - *(_BYTE *)a4) ^ 0x4A;
*(_BYTE _ds *)a1 = (*(_BYTE *)a5 + *(_DWORD _ds *)(a5 + 36)) ^ 0x96;
*(_BYTE _ds *)a1 = (*(_DWORD _ds *)(a5 + 36) - *(_BYTE *)a5) ^ 0x91;
*(_BYTE _ds *)a1 = (*(_BYTE *)a5 + *(_DWORD _ds *)(a5 + 36)) ^ 0x2E;
*(_BYTE _ds *)a1 = (*(_BYTE *)a5 + *(_DWORD _ds *)(a5 + 36)) ^ 0x19;
*(_BYTE _ds *)a1 = (*(_BYTE *)a5 + *(_DWORD _ds *)(a5 + 36)) ^ 0xC5;
*(_BYTE _ds *)a1 = (*(_BYTE *)a5 + *(_DWORD _ds *)(a5 + 36)) ^ 0xE3;
*(_BYTE _ds *)a1 = (*(_BYTE *)a5 + *(_DWORD _ds *)(a5 + 36)) ^ 0x88;
*(_BYTE _ds *)a1 = (*(_DWORD _ds *)(a4 + 36) - *(_BYTE *)a4) ^ 0xBD;
*(_BYTE _ds *)a1 = (*(_BYTE *)a4 + *(_DWORD _ds *)(a4 + 36)) ^ 0x4E;
*(_BYTE _ds *)a1 = (*(_BYTE *)a4 + *(_DWORD _ds *)(a4 + 36)) ^ 0x93;
*(_BYTE _ds *)a1 = (*(_DWORD _ds *)(a4 + 36) - *(_BYTE *)a4) ^ 0x13;
*(_BYTE _ds *)a1 = (*(_DWORD _ds *)(a5 + 36) - *(_BYTE *)a5) ^ 0xF1;
*(_BYTE _ds *)a1 = (*(_BYTE *)a5 + *(_DWORD _ds *)(a5 + 36)) ^ 0xCC;
*(_BYTE _ds *)a1 = (*(_BYTE *)a5 + *(_DWORD _ds *)(a5 + 36)) ^ 0x47;
*(_BYTE _ds *)a1 = (*(_BYTE *)a5 + *(_DWORD _ds *)(a5 + 36)) ^ 0xAB;
*(_BYTE _ds *)a1 = (*(_BYTE *)a4 + *(_DWORD _ds *)(a4 + 36)) ^ 0xC9;
*(_BYTE _ds *)a1 = (*(_DWORD _ds *)(a4 + 36) - *(_BYTE *)a4) ^ 0x48;
*(_BYTE _ds *)a1 = (*(_DWORD _ds *)(a4 + 36) - *(_BYTE *)a4) ^ 0x2B;
*(_BYTE _ds *)a1 = (*(_BYTE *)a5 + *(_DWORD _ds *)(a5 + 36)) ^ 9;
*(_BYTE _ds *)a1 = (*(_DWORD _ds *)(a4 + 36) - *(_BYTE *)a4) ^ 0x50;
*(_BYTE _ds *)a1 = (*(_BYTE *)a5 + *(_DWORD _ds *)(a5 + 36)) ^ 0x4F;
*(_BYTE _ds *)a1 = (*(_DWORD _ds *)(a4 + 36) - *(_BYTE *)a4) ^ 0xE9;
*(_BYTE _ds *)a1 = (*(_DWORD _ds *)(a5 + 36) - *(_BYTE *)a5) ^ 0xC0;
*(_BYTE _ds *)a1 = (*(_BYTE *)a4 + *(_DWORD _ds *)(a4 + 36)) ^ 0x5E;
*(_BYTE _ds *)a1 = (*(_DWORD _ds *)(a5 + 36) - *(_BYTE *)a5) ^ 0xEF;
*(_BYTE _ds *)a1 = (*(_DWORD _ds *)(a5 + 36) - *(_BYTE *)a5) ^ 0x8B;
*(_BYTE _ds *)a1 = (*(_DWORD _ds *)(a4 + 36) - *(_BYTE *)a4) ^ 0x85;
*(_BYTE _ds *)a1 = (*(_DWORD _ds *)(a5 + 36) - *(_BYTE *)a5) ^ 0xCB;
*(_BYTE _ds *)a1 = (*(_BYTE *)a5 + *(_DWORD _ds *)(a5 + 36)) ^ 0x55;
*(_BYTE _ds *)a1 = (*(_DWORD _ds *)(a4 + 36) - *(_BYTE *)a4) ^ 0x70;
```

So, the signs are: `+++++-+-++--++-++-+-+++++-++--++++--+-+--+----+-`


Since we know all these, we can decrypt the flag:

```python
func_consts = [
    0xBA, 0x2F, 0xCD, 0xF6, 0x9F, 0xD0, 0x22, 0xF7, 0xD0, 0x1F,
    0xA8, 0x3D, 0xC7, 0xA5, 0x47, 0x68, 0xD7, 0x4A, 0x96, 0x91,
    0x2E, 0x19, 0xC5, 0xE3, 0x88, 0xBD, 0x4E, 0x93, 0x13, 0xF1,
    0xCC, 0x47, 0xAB, 0xC9, 0x48, 0x2B, 0x09, 0x50, 0x4F, 0xE9,
    0xC0, 0x5E, 0xEF, 0x8B, 0x85, 0xCB, 0x55, 0x70
]

param_consts = [
    0xC4, 0x16, 0x8E, 0x77, 0x05, 0xB9, 0x0D, 0x6B, 0x24, 0x55,
    0x12, 0x35, 0x76, 0xE7, 0xFB, 0xA0, 0xDA, 0x34, 0x84, 0xB4,
    0xC8, 0x9B, 0xEF, 0xB4, 0xB9, 0xA,  0x57, 0x5C, 0xFE, 0xC5,
    0x6A, 0x73, 0x49, 0xBD, 0x11, 0xD6, 0x8F, 0x6B, 0x0A, 0x97,
    0xAB, 0x4E, 0xED, 0xFE, 0x97, 0xF9, 0x98, 0x65
]

cipher = [
    0x96, 0x50, 0xCF, 0x2C, 0xEB, 0x9B, 0xAA, 0xFB, 0x53, 0xAB, 
    0x73, 0xDD, 0x6C, 0x9E, 0xDB, 0xBC, 0xEE, 0xAB, 0x23, 0xD6, 
    0x16, 0xFD, 0xF1, 0xF0, 0xB9, 0x75, 0xC3, 0x28, 0xA2, 0x74, 
    0x7D, 0xE3, 0x27, 0xD5, 0x95, 0x5C, 0xF5, 0x76, 0x75, 0xC9, 
    0x8C, 0xFB, 0x42, 0x0E, 0xBD, 0x51, 0xA2, 0x98
]

signs = '+++++-+-++--++-++-+-+++++-++--++++--+-+--+----+-'

flag = ''
for a, b, c, s in zip(func_consts, param_consts, cipher, signs):
    if s == '+':
        flag += chr(((c ^ a) - b) & 0xff)
    else:        
        flag += chr((b - (c ^ a)) & 0xff)

print(flag)
```

So the flag is: `hitcon{___7U5T_4_S1mpIE_xB6_M@G1C_4_mE0w_W@y___}`

___
