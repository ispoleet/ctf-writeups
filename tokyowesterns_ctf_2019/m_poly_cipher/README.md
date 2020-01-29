
## TokyoWesterns CTF 5th 2019 - M Poly Cipher (RE 276)
##### 31-02/09/2019 (48hr)
___

### Solution

Binary was huge with a lot of repeating code (inlined code and unrolled loops were common patterns).
Let's start with some basic analysis:

Crypto algorithm operates on 32-bits. Random numbers are generated from `/dev/urandom`. Each time
that we want to generate a random dword, the following (inline) function is executed:
```C
uint32_t rand() {
    uint32_t num;
    FILE *fp = fopen("/dev/urandom", "rb");

    if (!fp) { /* handle error */ }

    do {
        // In assembly, this loop is unrolled
        for (int i=0; i<8; ++i) {
            fread(&num, 1, 4, fp);
            if (num <= 0xfffffffa) break;

            // if num > 0xfffffffa give it another try
        }
    while (num > 0xfffffffa);

    fclose(fp);
    return num; 
}
```

Please note that `0xfffffffb` is the greater prime number that can fit in 32-bits (this is
important, so let's keep it in mind).

Binary performs 3 operations: Key generation, encryption and decryption. Let's see them one by one.

### Key Generation

First, all keys are `bzeroed`:
```assembly
.text:0000555555554822         rep stosq                       ; bzero memory
.text:0000555555554825         lea     rdi, [rsp+0E08h+pubkey_B_888]
.text:000055555555482D         mov     rcx, rsi
.text:0000555555554830         mov     [rsp+0E08h+pubkey_B_ptr_E00], rdi
.text:0000555555554835         rep stosq
.text:0000555555554838         lea     rdi, [rsp+0E08h+privkey_X_688]
.text:0000555555554840         mov     rcx, rsi
.text:0000555555554843         mov     [rsp+0E08h+privkey_X_ptr_9E8], rdi
.text:000055555555484B         rep stosq
.text:000055555555484E         lea     rdi, [rsp+0E08h+key_D_588]
.text:0000555555554856         mov     rcx, rsi
.text:0000555555554859         mov     [rsp+0E08h+key_D_ptr_DE0], rdi
.text:000055555555485E         rep stosq
.text:0000555555554861         lea     rdi, [rsp+0E08h+key_E_288]
.text:0000555555554869         mov     rcx, rsi
.text:000055555555486C         mov     [rsp+0E08h+key_E_ptr_9E0], rdi
.text:0000555555554874         rep stosq
.text:0000555555554877         lea     rdi, [rsp+0E08h+key_F_188]
.text:000055555555487F         mov     rcx, rsi
.text:0000555555554882         mov     [rsp+0E08h+key_F_ptr_9D8], rdi
.text:000055555555488A         rep stosq
.text:000055555555488D
```

The algorithm uses the following keys at the following addresses:
```
tmp: 0x7FFFFFFFCF30
I_0: 0x7FFFFFFFD128

pubkey A : 0x7FFFFFFFD3A0 (128 byte) + A_i (128 byte)
pubkey B : 0x7FFFFFFFD4A0 (128 byte) + B_i (128 byte)
pubkey C : 0x7FFFFFFFD5A0 (128 byte)
privkey X: 0x7FFFFFFFD6A0 (256 byte)

key D: 0x7FFFFFFFD7A0
key G: 0x7FFFFFFFD8A0
key E: 0x7FFFFFFFDAA0
key F: 0x7FFFFFFFDBA0
```

Key generation consists of **7** loops. The first loop generates 2 128-byte random keys **A**
and **B** from `/dev/urandom` (both are public) as follows:
```C
    for (int i=0x20; i<0xa0; i+=0x20) {
        for (int j=0; j<0x20; j+=4) {
            *(uint32_t*) &A[j] = rand();
            *(uint32_t*) &B[j] = rand();
        }
    }
```

Consider the following randomly generated keys:
```
Public Key A:
  466E5873 738A6CC3 BF3374DE DA6DE6FB FF96A1C8 F860E573 21A745BA 030CBED8
  9E931602 A5BE0CC6 D1689F87 7542016A 7B020175 D4994AB2 BA4B99E2 65322AFB
  CF9C0285 7AC91C3C 13BA3606 6A601E54 DF215320 C940A009 31BA70EB 78AE20A5
  C30B5257 42E616E9 7A46DB7C 65BE8B5B 751257A6 4685E36C 20EE6ABD F1F5A798

Public Key B:
  3D34C3AC 9AA963C7 F2CD30CA 944AE027 1C858041 869E9AC2 77403C89 DD9A8B7B
  D87EAF68 E634F00E FDC210E0 B1184F1E ACD8A27E ABD65A8A 8ED09EED 35C12F03
  226A0E43 119AEEA7 74F64DA6 51C426AB 3E503AF8 6E534A55 ACE4C8B5 16B7E80C
  BE56F7D3 58DD12FC DD03F5F1 3A516C1C 35FD2F87 36A1536F 4CC4516C 589A0733
```

The second loop generates an "extended" version of public keys **A** and **B**. as follows:
```assembly
.text:0000555555554DE8         mov     ecx, dword ptr [rsp+0E08h+rand1_DF0] ; ecx = a = rand()
.text:0000555555554DEC         mov     edi, [rbp+0]
.text:0000555555554DEF         mov     r9d, [r12+80h]
.text:0000555555554DF7         mov     r10, [rsp+0E08h+rand2_DF8]
.text:0000555555554DFC         mov     r11d, [rsp+0E08h+rand_98C] ; r11 = b = rand()
.text:0000555555554E04         mov     ebx, [r14+80h]
.text:0000555555554E0B         imul    rdi, rcx                ; rdi = a * A[0]
.text:0000555555554E0F         mov     esi, [r10]              ; esi = B[0]
.text:0000555555554E12         add     rdi, r9                 ; rdi = a * A[0] + A_i[0] = x
.text:0000555555554E15         mov     rax, rdi
.text:0000555555554E18         mul     r15                     ; rax = x * 0x800000028000000d
.text:0000555555554E1B         imul    rsi, r11                ; rsi = b * B[0]
.text:0000555555554E1F         shr     rdx, 1Fh                ; rdx = (x * 0x800000028000000d) >> (64 + 31 =95) = I_0
.text:0000555555554E23         mov     r8, rdx                 ; modulo ?
.text:0000555555554E26         add     rsi, rbx                ; rsi = b * B[0] + B_i[0] = y
.text:0000555555554E29         shl     r8, 1Eh                 ; r8 = I_0 << 30
.text:0000555555554E2D         mov     rax, rsi
.text:0000555555554E30         sub     r8, rdx                 ; r8 = (I_0 << 30) - I_0
.text:0000555555554E33         shl     r8, 2
.text:0000555555554E37         sub     r8, rdx                 ; r8 = ((I_0 << 30) - I_0) << 2 = this leaves 3 bits
.text:0000555555554E3A         mul     r15                     ; N = 2**95 / (0x800000028000000d - 8) = 0xfffffffb = prime!
.text:0000555555554E3D         sub     rdi, r8                 ; rdi = x - ((I_0 << 30) - I_0) << 2  = we subtract from x so indeed a modulo
.text:0000555555554E40         mov     r8d, [r12+84h]          ; r8 = j
.text:0000555555554E48         mov     [r12+80h], edi          ; A_i[0] = (a * A[0] + A_i[0]) % 0xfffffffb
.text:0000555555554E50         mov     r9d, [rbp+4]            ; same story
.text:0000555555554E54         shr     rdx, 1Fh
.text:0000555555554E58         mov     rdi, rdx
.text:0000555555554E5B         imul    r9, rcx
....
```

Let's decompile this:
```Python
    A_i = [0] * 32
    B_i = [0] * 32

    for k in range(0, 0x20, 8):
        a, b = rand(), rand()

        for i in range(0, 0x20, 8):
            for j in range(8):
                A_i[k + j] = (a * A[i + j] + A_i[k + j]) % 0xfffffffb
                B_i[k + j] = (b * B[i + j] + B_i[k + j]) % 0xfffffffb
```

For our example, consider also the following key extensions:
```
Extended Public Key A_i:
    4248ABFC B326F28D AE555625 0A1CC5DE D5680F09 899EDD20 3226FC5E 3216FE03
    99E7D5F7 AF2938EC 9E16D97A 9FBC03E7 B65583D8 2B29ACC2 02E77B98 1A71D54B
    B9289BE6 1BC5E050 C4CC7FA9 AF9EE679 8A00BC07 F451D70A 7CAD99D7 376E028B
    3D435AD0 1E2F7E96 8CF6C9FE 66AA0D6F 2A07F20F D5938B81 7B3361CC 13321E94

Extended Public Key B_i:
    D87A267C 305C7677 11B0A68C 5D1A1D5F CB207795 A5775961 7762EFC2 87E6A98C
    F5C9F411 DFE1B3FC 71BCC30A B4CACED9 969BF2DC BCD920A2 2E90C5B3 3FE58BD1
    5A5484B8 F6EE8EA9 67E36F77 B1A02F39 914B3810 523BFD17 36DF2247 056A5ECF
    69819864 45DB3D15 446BE15C 21BA346D FE598FF2 A09EF3BE 39FE7D36 62F2C869
```

Please note that **A_i** and **B_i** are part of **A** and **B** respectively.

The third loop generates the 256-byte private key from `/dev/urandom` as follows:
```C
    for (int i=0x20; i<0x120; i+=0x20) {
        for (int j=0; j<0x20; j+=4) {
            *(uint32_t*) &X[j] = rand();
        }
    }
```

Before the fourth loop there is a "shuffling" step that extends and permutes the private key:
```assembly
.text:000055555555532B         mov     r9d, [rsp+0E08h+privkey_X_688]
.text:0000555555555333         mov     r8d, [rsp+0E08h+var_668]
.text:000055555555533B         mov     ecx, [rsp+0E08h+var_628]
.text:0000555555555342         mov     r11d, [rsp+0E08h+var_608]
.text:000055555555534A         mov     eax, [rsp+0E08h+var_5E8]
.text:0000555555555351         mov     edx, [rsp+0E08h+var_5C8]
.text:0000555555555358         mov     edi, [rsp+0E08h+var_5A8]
.text:000055555555535F         mov     ebx, [rsp+0E08h+var_684]
.text:0000555555555366         mov     r12d, [rsp+0E08h+var_664]
.text:000055555555536E         mov     r15d, [rsp+0E08h+var_644]
.text:0000555555555376         mov     ebp, [rsp+0E08h+var_624]
.text:000055555555537D         mov     r10d, [rsp+0E08h+var_604]
.text:0000555555555385         mov     [rsp+0E08h+privkey_sub_tmpX_C00], r9
.text:000055555555538D         mov     [rsp+0E08h+var_C08], r8
.text:0000555555555395         mov     r9d, [rsp+0E08h+var_5E4]
.text:000055555555539D         mov     r8d, [rsp+0E08h+var_5C4]
.text:00005555555553A5         mov     esi, [rsp+0E08h+var_648]
.text:00005555555553AC         mov     [rsp+0E08h+var_C18], rcx
.text:00005555555553B4         mov     [rsp+0E08h+var_C20], r11
.text:00005555555553BC         mov     [rsp+0E08h+var_C28], rax
.text:00005555555553C4         mov     [rsp+0E08h+var_C30], rdx
.text:00005555555553CC         mov     [rsp+0E08h+var_C38], rdi
.text:00005555555553D4         mov     [rsp+0E08h+var_C40], rbx
.text:00005555555553DC         mov     [rsp+0E08h+var_C48], r12
.text:00005555555553E4         mov     [rsp+0E08h+var_C50], r15
....
```

This is similar to an S-box substitution in DES. The new private key (let's call it `sub-X`)
is located at `0x7FFFFFFFCF30`. To find the permutation let's observe the input/output:
```
Original Private Key X:
    DF2243A0 D10C9396 249E2E1B 138EC85F 7DDF621C F654F036 C2BC840A D682CBE5
    E0045B46 CCF5E9EE 1B5B6878 CB79B9D9 BBBC16A3 272F6082 A0DC8C4C 1FD43E4F
    92E35E85 486CCCDF 9D12BA36 7E0361BA CD1EE522 1DF2733E 4728B9C5 345FC712
    CED4DE5F EA3E2192 E8BBE1BF 93B9C980 23ABBC9F 86CDE4EC 4E53320D 02ECAE08
    27E9130F 36E6209E BA7702E6 70017548 D7674A9F EA68CEBB E3BC01FB 5741B36D
    AA1BCC27 6DDE23FE E31AABFB E29E33BE 5F78BA02 6D049E60 DF2D5D2E B6A0DE7B
    C8DA2AF7 8CBA8DF3 3FAFEAF2 E970800C B7F6F950 AAB93219 956E617A 3A0F0036
    0E566B03 03F903FC 0FAB842D 368D5F6D D55C3073 987DF0F0 C9895A74 9A86426E

Substituted Key subX:
    5741B36D 00000000 B6A0DE7B 00000000 C9895A74 00000000 956E617A 00000000
    3A0F0036 00000000 DF2D5D2E 00000000 E3BC01FB 00000000 9A86426E 00000000
    4E53320D 00000000 4728B9C5 00000000 A0DC8C4C 00000000 C2BC840A 00000000
    987DF0F0 00000000 AAB93219 00000000 6D049E60 00000000 EA68CEBB 00000000
    86CDE4EC 00000000 1DF2733E 00000000 272F6082 00000000 F654F036 00000000
    D55C3073 00000000 B7F6F950 00000000 5F78BA02 00000000 D7674A9F 00000000
    23ABBC9F 00000000 CD1EE522 00000000 BBBC16A3 00000000 7DDF621C 00000000
    368D5F6D 00000000 E970800C 00000000 E29E33BE 00000000 70017548 00000000
    93B9C980 00000000 7E0361BA 00000000 CB79B9D9 00000000 138EC85F 00000000
    0FAB842D 00000000 3FAFEAF2 00000000 E31AABFB 00000000 BA7702E6 00000000
    E8BBE1BF 00000000 9D12BA36 00000000 1B5B6878 00000000 249E2E1B 00000000
    03F903FC 00000000 8CBA8DF3 00000000 6DDE23FE 00000000 36E6209E 00000000
    EA3E2192 00000000 486CCCDF 00000000 CCF5E9EE 00000000 D10C9396 00000000
    0E566B03 00000000 C8DA2AF7 00000000 AA1BCC27 00000000 27E9130F 00000000
    CED4DE5F 00000000 92E35E85 00000000 E0045B46 00000000 DF2243A0 00000000
```

We see that it's indeed a permutation since each number appeared once. We also see that the
columns in `X` become rows in the reverse order, but with some small exceptions. So we write
some python code to find the substitution box:
```python
# Finds the applied substitution box given the input and the output tables.
def find_sub_tbl(X, subX):
    print '[+] Calculating substitution:'

    sub_tbl = [[], [], [], [], [], [], [], []]    
    
    for i in xrange(len(X)):
        if i > 0 and i % 8 == 0: print

        sub = subX.index(X[i]) >> 1

        print '%02d --> %02d, ' % (i, sub),

        sub_tbl[i % 8].append(sub)

    print

    return sub_tbl
```

The substitution box is:
```
00 --> 63,  01 --> 55,  02 --> 47,  03 --> 39,  04 --> 31,  05 --> 23,  06 --> 15,  07 --> 00,  
08 --> 62,  09 --> 54,  10 --> 46,  11 --> 38,  12 --> 30,  13 --> 22,  14 --> 14,  15 --> 01,  
16 --> 61,  17 --> 53,  18 --> 45,  19 --> 37,  20 --> 29,  21 --> 21,  22 --> 13,  23 --> 02,  
24 --> 60,  25 --> 52,  26 --> 44,  27 --> 36,  28 --> 28,  29 --> 20,  30 --> 12,  31 --> 03,  
32 --> 59,  33 --> 51,  34 --> 43,  35 --> 35,  36 --> 27,  37 --> 19,  38 --> 10,  39 --> 04,  
40 --> 58,  41 --> 50,  42 --> 42,  43 --> 34,  44 --> 26,  45 --> 18,  46 --> 09,  47 --> 05,  
48 --> 57,  49 --> 49,  50 --> 41,  51 --> 33,  52 --> 25,  53 --> 17,  54 --> 07,  55 --> 08,  
56 --> 56,  57 --> 48,  58 --> 40,  59 --> 32,  60 --> 24,  61 --> 16,  62 --> 06,  63 --> 11,
```

We see that it's indeed almost a column to rows in reverse order transformation, but with some
little custom modifications. In any case we have an 1-1 mapping which is important.

The fourth loop initializes key **D** at `0x7FFFFFFFD7A0`:
```assembly
.text:0000555555555700 CREATEKEY_LOOP_4_555555555700:          ; CODE XREF: main+1AB0j
.text:0000555555555700         mov     ecx, [r13+0]            ; ecx = privkey X
.text:0000555555555704         mov     rsi, [rsp+0E08h+privkey_subX_C00] ; rsi = last value of subX
.text:000055555555570C         mov     r12d, [r13+4]           ; read 32 bytes from X
.text:0000555555555710         mov     ebx, [r13+8]
.text:0000555555555714         mov     r11d, [r13+0Ch]
.text:0000555555555718         mov     r10d, [r13+10h]
.text:000055555555571C         mov     r9d, [r13+14h]
.text:0000555555555720         mov     r8d, [r13+18h]
.text:0000555555555724         imul    rsi, rcx                ; rsi = X[0] * subX[-1]
.text:0000555555555728         mov     edi, [r13+1Ch]
.text:000055555555572C         mov     rax, rsi
.text:000055555555572F         mul     rbp                     ; rbp = 0x800000028000000D
.text:0000555555555732         shr     rdx, 1Fh
.text:0000555555555736         mov     rax, rdx
.text:0000555555555739         shl     rax, 1Eh
.text:000055555555573D         sub     rax, rdx
.text:0000555555555740         shl     rax, 2
.text:0000555555555744         sub     rax, rdx
.text:0000555555555747         mov     rdx, [rsp+0E08h+var_C08]
.text:000055555555574F         sub     rsi, rax                ; rsi = X[0] * subX[-1] % 0xfffffffb = i0
.text:0000555555555752         imul    rdx, r12                ; rdx = X[1] * subX[-2]
.text:0000555555555756         add     rsi, rdx
.text:0000555555555759         mov     rax, rsi
.text:000055555555575C         mul     rbp
.text:000055555555575F         shr     rdx, 1Fh
.text:0000555555555763         mov     rax, rdx
.text:0000555555555766         shl     rax, 1Eh
.text:000055555555576A         sub     rax, rdx
.text:000055555555576D         shl     rax, 2
.text:0000555555555771         sub     rax, rdx
.text:0000555555555774         mov     rdx, [rsp+0E08h+var_C10]
.text:000055555555577C         sub     rsi, rax                ; rsi = X[1] * subX[-2] % 0xfffffffb + i0 = i1
.text:000055555555577F         imul    rdx, rbx
.text:0000555555555783         add     rsi, rdx
.text:0000555555555786         mov     rax, rsi
.text:0000555555555789         mul     rbp
.text:000055555555578C         shr     rdx, 1Fh
.text:0000555555555790         mov     rax, rdx
.text:0000555555555793         shl     rax, 1Eh
.text:0000555555555797         sub     rax, rdx
.text:000055555555579A         shl     rax, 2
.text:000055555555579E         sub     rax, rdx
.text:00005555555557A1         mov     rdx, [rsp+0E08h+var_C18]
.text:00005555555557A9         sub     rsi, rax                ; rsi =  X[j] * subX[-j] % 0xfffffffb + i_(j-1) = i_j
.text:00005555555557AC         imul    rdx, r11
....
.text:0000555555555882         sub     rsi, rax
.text:0000555555555885         mov     [r14], esi              ; D[0] = SUM(X[i] * subX[-i]) % 0xfffffffb for i in [0,8]
.text:0000555555555888 ---------------------------
.text:0000555555555888         mov     rsi, [rsp+0E08h+var_C40]
.text:0000555555555890         imul    rsi, rcx
.text:0000555555555894         mov     rax, rsi
.text:0000555555555897         mul     rbp
.text:000055555555589A         shr     rdx, 1Fh
.text:000055555555589E         mov     rax, rdx
.text:00005555555558A1         shl     rax, 1Eh
.text:00005555555558A5         sub     rax, rdx
.text:00005555555558A8         shl     rax, 2
.text:00005555555558AC         sub     rax, rdx
.text:00005555555558AF         mov     rdx, [rsp+0E08h+var_C48]
.text:00005555555558B7         sub     rsi, rax
.text:00005555555558BA         imul    rdx, r12
.text:00005555555558BE         add     rsi, rdx
.text:00005555555558C1         mov     rax, rsi
.text:00005555555558C4         mul     rbp
.text:00005555555558C7         shr     rdx, 1Fh
.text:00005555555558CB         mov     rax, rdx
.text:00005555555558CE         shl     rax, 1Eh
.text:00005555555558D2         sub     rax, rdx
.text:00005555555558D5         shl     rax, 2
.text:00005555555558D9         sub     rax, rdx
.text:00005555555558DC         mov     rdx, [rsp+0E08h+var_C50]
.text:00005555555558E4         sub     rsi, rax                ; rsi = (X[i] * subX[8 + i]) % 0xfffffffb + S_i-1
....
.text:00005555555559EA         sub     rsi, rax
.text:00005555555559ED         mov     [r14+4], esi            ; D[1] = SUM(X[i] * subX[-8-i]) % 0xfffffffb for i in [0,8]
....
.text:0000555555556226         sub     rcx, rdi
.text:0000555555556229         mov     [r14-4], ecx
.text:000055555555622D         cmp     r15, r13
.text:0000555555556230         jnz     CREATEKEY_LOOP_4_555555555700 ; ecx = privkey X
```

We can decompile the whole thing into this cute loop:

```python
    sub_tbl_X = find_sub_tbl(X, subX)

    print '[+] Calculating Key D:'
    D = []

    for k in xrange(0, 0x40, 8):
        for j in xrange(8):
            S = 0
            for i in xrange(8):
                S = (X[k + i] * subX[sub_tbl_X[j][i] << 1] + S) % 0xfffffffb
                
            print '%08X' % S,

            D.append(S)

        print
    print
```

This whole thing looks a lot like a **matrix multiplication**! Let's keep this in mind.


where sub_tbl is the substitution table that we found above. For our example **D** will be:
```
    E56DC736 95DABF87 9E74A18C EFF74AA8 B8914E00 2C036DF9 51C88DDF 3A0B7DBC
    A9CEF9F9 9C5EFA42 19215043 25FC6610 FEE0D8C5 E1486786 6B541DA9 A6269A2D
    F07B4C1A 9F9D48CF 9D8684FD BF2F6E8D B2DD7CEF 49177639 263EAB1D CE84D842
    125165F7 AAB81A21 A223D4B0 5DAF939D 306EC103 531DDAB6 CBBEEFD5 F7E2FECB
    CB031F68 6C21E049 F61601E3 FC0D94A0 F7F317B9 07ABE34A 161F0E53 F8529786
    F97779C6 8B8C5A9F 4EC808F2 8E17AE0C 32B60A9B 1C5CA253 A6AEE656 4CE28BCA
    A8DEE40D 60E6EFCC E23C4348 4ED90337 586418D4 A4F48E99 C5C346EB 66EC685A
    99842D5D 586823BE E3E7919D 0E64DD7B 895A6B22 97E13C18 DD88DBA6 CB84CF66
```

The fifth loop starts with another long initialization:
```assembly
.text:0000555555556236         mov     r13d, [rsp+0E08h+pubkey_A_988] ; find inverse of public keys A and A_i
.text:000055555555623E         mov     r14d, 0FFFFFFFBh
.text:0000555555556244         xor     edx, edx
.text:0000555555556246         mov     rax, r14
.text:0000555555556249         mov     ebp, [rsp+0E08h+var_984]
.text:0000555555556250         mov     r15d, [rsp+0E08h+var_980]
.text:0000555555556258         mov     ecx, [rsp+0E08h+var_97C]
.text:000055555555625F         mov     esi, [rsp+0E08h+var_978]
.text:0000555555556266         mov     r12d, [rsp+0E08h+var_974]
.text:000055555555626E         mov     r11d, [rsp+0E08h+var_970]
.text:0000555555556276         sub     rax, r13                ; rax = 0xfffffffb - A[0]
.text:0000555555556279         mov     r10d, [rsp+0E08h+var_96C]
.text:0000555555556281         mov     r9d, [rsp+0E08h+var_968]
.text:0000555555556289         div     r14                     ; rdx = (0xfffffffb - A[0]) % 0xfffffffb
.text:000055555555628C         mov     rax, r14
.text:000055555555628F         mov     r8d, [rsp+0E08h+var_964]
.text:0000555555556297         mov     edi, [rsp+0E08h+var_960]
.text:000055555555629E         sub     rax, rbp                ; rax = 0xfffffffb - A[1]
.text:00005555555562A1         mov     r13d, [rsp+0E08h+var_95C]
.text:00005555555562A9         mov     ebp, [rsp+0E08h+var_958]
.text:00005555555562B0         mov     [rsp+0E08h+var_488], edx
.text:00005555555562B7         xor     edx, edx
.text:00005555555562B9         div     r14
.text:00005555555562BC         mov     rax, r14
.text:00005555555562BF         sub     rax, r15
.text:00005555555562C2         mov     r15d, [rsp+0E08h+var_954]
.text:00005555555562CA         mov     [rsp+0E08h+var_484], edx
.text:00005555555562D1         xor     edx, edx
....

```

The above code finds the inverses (modulo our prime `0xfffffffb`) tables **A** and **A_i** and
stores at key **G** at `0x7FFFFFFFD8A0`:
```python
print '[+] Finding the inverse tables of A and A_i:'
for i in xrange(len(A)):
    if i > 0 and i % 8 == 0: print

    print '%08X' % ((0xfffffffb - A[i]) % 0xfffffffb),
```

The key **G** will be:
```
    B991A788 8C759338 40CC8B1D 25921900 00695E33 079F1A88 DE58BA41 FCF34123
    616CE9F9 5A41F335 2E976074 8ABDFE91 84FDFE86 2B66B549 45B46619 9ACDD500
    3063FD76 8536E3BF EC45C9F5 959FE1A7 20DEACDB 36BF5FF2 CE458F10 8751DF56
    3CF4ADA4 BD19E912 85B9247F 9A4174A0 8AEDA855 B97A1C8F DF11953E 0E0A5863
    BDB753FF 4CD90D6E 51AAA9D6 F5E33A1D 2A97F0F2 766122DB CDD9039D CDE901F8
    66182A04 50D6C70F 61E92681 6043FC14 49AA7C23 D4D65339 FD188463 E58E2AB0
    46D76415 E43A1FAB 3B338052 50611982 75FF43F4 0BAE28F1 83526624 C891FD70
    C2BCA52B E1D08165 730935FD 9955F28C D5F80DEC 2A6C747A 84CC9E2F ECCDE167
```

Then we have another substitution box for key **D**:
```assembly
.text:0000555555556F19         mov     [rsp+0E08h+var_28C], edx ; shuffle (rows to columns in reverse (almost))
.text:0000555555556F20         mov     r15, [rsp+0E08h+key_E_ptr_9E0]
.text:0000555555556F28         mov     ebx, [rsp+0E08h+key_D_588]
.text:0000555555556F2F         mov     r9d, [rsp+0E08h+var_568]
.text:0000555555556F37         mov     r8d, [rsp+0E08h+var_548]
.text:0000555555556F3F         mov     edi, [rsp+0E08h+var_528]
.text:0000555555556F46         mov     ebp, [rsp+0E08h+var_508]
.text:0000555555556F4D         mov     ecx, [rsp+0E08h+var_4E8]
.text:0000555555556F54         mov     esi, [rsp+0E08h+var_4C8]
.text:0000555555556F5B         mov     r12d, [rsp+0E08h+var_4A8]
.text:0000555555556F63         mov     r11d, [rsp+0E08h+var_584]
.text:0000555555556F6B         mov     eax, [rsp+0E08h+var_564]
.text:0000555555556F72         mov     edx, [rsp+0E08h+var_544]
.text:0000555555556F79         mov     [rsp+0E08h+var_9F0], rbx
.text:0000555555556F81         mov     [rsp+0E08h+var_9F8], r9
.text:0000555555556F89         mov     ebx, [rsp+0E08h+var_524]
.text:0000555555556F90         mov     r9d, [rsp+0E08h+var_504]
.text:0000555555556F98         mov     [rsp+0E08h+var_A00], r8
.text:0000555555556FA0         mov     [rsp+0E08h+var_A08], rdi
.text:0000555555556FA8         mov     r8d, [rsp+0E08h+var_4E4]
.text:0000555555556FB0         mov     edi, [rsp+0E08h+var_4C4]
.text:0000555555556FB7         mov     [rsp+0E08h+var_A10], rbp
....
```

The new key subD will be:
```
    3A0B7DBC 00000000 A6269A2D 00000000 CE84D842 00000000 F7E2FECB 00000000
    F8529786 00000000 4CE28BCA 00000000 66EC685A 00000000 CB84CF66 00000000
    DD88DBA6 00000000 C5C346EB 00000000 A6AEE656 00000000 161F0E53 00000000
    CBBEEFD5 00000000 263EAB1D 00000000 6B541DA9 00000000 51C88DDF 00000000
    97E13C18 00000000 A4F48E99 00000000 1C5CA253 00000000 07ABE34A 00000000
    531DDAB6 00000000 49177639 00000000 E1486786 00000000 2C036DF9 00000000
    895A6B22 00000000 586418D4 00000000 32B60A9B 00000000 F7F317B9 00000000
    306EC103 00000000 B2DD7CEF 00000000 FEE0D8C5 00000000 B8914E00 00000000
    0E64DD7B 00000000 4ED90337 00000000 8E17AE0C 00000000 FC0D94A0 00000000
    5DAF939D 00000000 BF2F6E8D 00000000 25FC6610 00000000 EFF74AA8 00000000
    E3E7919D 00000000 E23C4348 00000000 4EC808F2 00000000 F61601E3 00000000
    A223D4B0 00000000 9D8684FD 00000000 19215043 00000000 9E74A18C 00000000
    586823BE 00000000 60E6EFCC 00000000 8B8C5A9F 00000000 6C21E049 00000000
    AAB81A21 00000000 9F9D48CF 00000000 9C5EFA42 00000000 95DABF87 00000000
    99842D5D 00000000 A8DEE40D 00000000 F97779C6 00000000 CB031F68 00000000
    125165F7 00000000 F07B4C1A 00000000 A9CEF9F9 00000000 E56DC736 00000000
```

We follow the same approach to find the new substitution box:
```
00 --> 63,  01 --> 55,  02 --> 47,  03 --> 39,  04 --> 31,  05 --> 23,  06 --> 15,  07 --> 00, 
08 --> 62,  09 --> 54,  10 --> 46,  11 --> 38,  12 --> 30,  13 --> 22,  14 --> 14,  15 --> 01, 
16 --> 61,  17 --> 53,  18 --> 45,  19 --> 37,  20 --> 29,  21 --> 21,  22 --> 13,  23 --> 02, 
24 --> 60,  25 --> 52,  26 --> 44,  27 --> 36,  28 --> 28,  29 --> 20,  30 --> 12,  31 --> 03, 
32 --> 59,  33 --> 51,  34 --> 43,  35 --> 35,  36 --> 27,  37 --> 19,  38 --> 11,  39 --> 04, 
40 --> 58,  41 --> 50,  42 --> 42,  43 --> 34,  44 --> 26,  45 --> 18,  46 --> 10,  47 --> 05, 
48 --> 57,  49 --> 49,  50 --> 41,  51 --> 33,  52 --> 25,  53 --> 17,  54 --> 09,  55 --> 06, 
56 --> 56,  57 --> 48,  58 --> 40,  59 --> 32,  60 --> 24,  61 --> 16,  62 --> 08,  63 --> 07,
```

Now we enter on the fifth loop, which is the same (functional-wise) with the fourth loop, but this
time for key **E** at `0x7FFFFFFFDAA0`:
```assembly
.text:0000555555557318 CREATEKEY_LOOP_5_555555557318:          ; CODE XREF: main+36F2j
.text:0000555555557318         mov     ecx, [r13+0]            ; same story with loop 4
.text:000055555555731C         mov     rsi, [rsp+0E08h+var_9F0]
.text:0000555555557324         mov     r12d, [r13+4]
.text:0000555555557328         mov     ebx, [r13+8]
.text:000055555555732C         mov     r11d, [r13+0Ch]
.text:0000555555557330         mov     r10d, [r13+10h]
.text:0000555555557334         mov     r9d, [r13+14h]
.text:0000555555557338         mov     r8d, [r13+18h]
.text:000055555555733C         imul    rsi, rcx
....
.text:0000555555557E5E         sub     rdi, rdx
.text:0000555555557E61         shl     rdi, 2
.text:0000555555557E65         sub     rdi, rdx
.text:0000555555557E68         sub     rcx, rdi
.text:0000555555557E6B         mov     [r15-4], ecx
.text:0000555555557E6F         cmp     r14, r13
.text:0000555555557E72         jnz     CREATEKEY_LOOP_5_555555557318 ; same story with loop 4
```

This loop is a little bit tricky:
```python
    sub_tbl_D = find_sub_tbl(D, subD)
    print
 
    print '[+] Calculating Key E:'
    E = []

    for k in xrange(0, 0x40, 8):
        for j in xrange(8):
            S = 0
            for i in xrange(8):
                S = (Ainv[k + i] * subD[sub_tbl_D[j][i] << 1] + S) % 0xfffffffb
                
            print '%08X' % S,

            E.append(S)

        print
    print
```

For our case, **E** will be:
```

    034B84F2 2FC67DCB 02D0892E 7F2A4D63 7D023E7D 6F035A0F 234CE3D1 01B0A3B0
    DD7503E4 A29508C2 BB412CD9 BB249673 3B596748 065F3B2A ED0F8208 26ED5277
    87EDDBF7 FA379759 7594E152 4B1B4189 7B9AD2C2 3BA186A2 8FA57B64 2223C032
    008491EE F0F00AFA 5BAE0490 2B8F774D 8F58E3B5 0733ED3D B7C12B3B 00FE2A6C
    531B4874 9B334F5B F937B733 178BB1E4 CBE850B8 58E165B7 F7D64A3E 3D1ACC17
    A4D243D0 292F836C 0C992791 4773C685 B587515A 8C5634ED 06280508 5E0C34ED
    5FC8D653 142F977F EC6C1FE4 B71D197C 5EFCD196 3E270725 6A8C6C8F 773B03C5
    2627B51D 16BA11B9 A4332551 2FA75C97 B9897AE3 38FF1603 A0EE1A46 0F0F3DD3
```

Then is the sixth loop which also the same with fourth and fifth loops, but it calculates key **F**
at `0x7FFFFFFFDBA0`:
```assembly
.text:0000555555557E78         mov     r15, [rsp+0E08h+key_F_ptr_9D8]
.text:0000555555557E80         mov     r14, [rsp+0E08h+var_9D0]
.text:0000555555557E88         lea     rcx, [rsp+0E08h+key_E_288]
.text:0000555555557E90         lea     r13, [rsp+0E08h+WAT_388]
.text:0000555555557E98         mov     rbp, 800000028000000Dh
.text:0000555555557EA2         mov     rsi, r15
.text:0000555555557EA5         mov     [rsp+0E08h+var_BE8], r15
.text:0000555555557EAD         mov     [rsp+0E08h+var_BE0], r14
.text:0000555555557EB5         mov     r15, rcx
.text:0000555555557EB8         mov     r14, rsi
.text:0000555555557EBB         nop     dword ptr [rax+rax+00h]
.text:0000555555557EC0 CREATEKEY_LOOP_6_555555557EC0:          ; CODE XREF: main+4270j
.text:0000555555557EC0         mov     ecx, [r13+0]            ; same store with loop 5
.text:0000555555557EC4         mov     rsi, [rsp+0E08h+privkey_subX_C00]
.text:0000555555557ECC         mov     r12d, [r13+4]
.text:0000555555557ED0         mov     ebx, [r13+8]
.text:0000555555557ED4         mov     r11d, [r13+0Ch]
.text:0000555555557ED8         mov     r10d, [r13+10h]
.text:0000555555557EDC         mov     r9d, [r13+14h]
.text:0000555555557EE0         mov     r8d, [r13+18h]
.text:0000555555557EE4         imul    rsi, rcx
.text:0000555555557EE8         mov     edi, [r13+1Ch]
.text:0000555555557EEC         mov     rax, rsi
.text:0000555555557EEF         mul     rbp
.text:0000555555557EF2         shr     rdx, 1Fh
.text:0000555555557EF6         mov     rax, rdx
.text:0000555555557EF9         shl     rax, 1Eh
.text:0000555555557EFD         sub     rax, rdx
.text:0000555555557F00         shl     rax, 2
.text:0000555555557F04         sub     rax, rdx
.text:0000555555557F07         mov     rdx, [rsp+0E08h+var_C08]
.text:0000555555557F0F         sub     rsi, rax
.text:0000555555557F12         imul    rdx, r12
....
.text:00005555555589E3         sub     rdi, rdx
.text:00005555555589E6         sub     rcx, rdi
.text:00005555555589E9         mov     [r14-4], ecx
.text:00005555555589ED         cmp     r15, r13
.text:00005555555589F0         jnz     CREATEKEY_LOOP_6_555555557EC0 ; same store with loop 5
```

Back to our example, **F** will be:
```
    2617F6C0 D6D6CC02 D5EFB84F 161780D1 AF7B9AD6 D7706B8E 71A5BC8A 32D81734
    07F65DDA 6DF50F7B AD23D61C 1BDBBCE5 01C7FEC4 2E0ECE1E 3557267D 1FE5C034
    386A8C9A F6CF695A 859E5D13 D4668774 FEFE7545 13467445 DCACAFAD CBD0E2E3
    AF2E748F 031447B0 57B4DE4E 58E5F720 D99A9715 2C872637 2E1C3C5C E2D45AD7
    4CF9CFDA 2AC1C4D2 9A6E6714 8D910A0E 78680D98 F9B36DC6 61410EA7 9DD30F09
    0CE68BD6 E294F531 0CD50F4B 04B60D42 80DDF79D A7058153 5AFC16A8 27123147
    43223425 BB2B3634 540A03A6 0C87CD5E 2FC6C71D 3A309D46 97C46C4D A0924808
    0AE504FA 59EC2D42 5247906B 27516904 1071B666 3BC911DC FB3F54D0 A813DF3D
```

Finally, the seventh loop is a small loop that calculates public key **C** at `0x7FFFFFFFD5A0`
from keys **E** and **F**:
```assembly
.text:00005555555589F6         mov     rcx, [rsp+0E08h+key_E_ptr_9E0]
.text:00005555555589FE         lea     r15, [rsp+0E08h+pubkey_C_788]
.text:0000555555558A06         mov     r13, [rsp+0E08h+var_BE8]
.text:0000555555558A0E         mov     rbp, [rsp+0E08h+var_BE0]
.text:0000555555558A16         mov     r12, 800000028000000Dh
.text:0000555555558A20         mov     r14, r15
.text:0000555555558A23         add     rcx, 100h
.text:0000555555558A2A         nop     word ptr [rax+rax+00h]
.text:0000555555558A30
.text:0000555555558A30 CREATEKEY_LOOP_7_555555558A30:          ; CODE XREF: main+4422j
.text:0000555555558A30         mov     esi, [rbp+0]            ; esi = key E[0]
.text:0000555555558A33         mov     ebx, [r13+0]            ; ebx = key F[0]
.text:0000555555558A37         mov     r10d, [rbp+4]
.text:0000555555558A3B         mov     r9d, [r13+4]
.text:0000555555558A3F         mov     edi, [rbp+8]
.text:0000555555558A42         add     rsi, rbx                ; rsi = E[0] + F[0]
.text:0000555555558A45         mov     rax, rsi
.text:0000555555558A48         add     r10, r9                 ; r10 = E[1] + F[1]
.text:0000555555558A4B         mul     r12                     ; modulo again
.text:0000555555558A4E         mov     rax, r10
.text:0000555555558A51         shr     rdx, 1Fh
.text:0000555555558A55         mov     r11, rdx
.text:0000555555558A58         shl     r11, 1Eh
.text:0000555555558A5C         sub     r11, rdx
.text:0000555555558A5F         shl     r11, 2
.text:0000555555558A63         sub     r11, rdx
.text:0000555555558A66         mul     r12
.text:0000555555558A69         sub     rsi, r11
.text:0000555555558A6C         mov     r11d, [rbp+0Ch]
.text:0000555555558A70         mov     [r14], esi
.text:0000555555558A73         mov     esi, [r13+8]
.text:0000555555558A77         shr     rdx, 1Fh
.text:0000555555558A7B         mov     r8, rdx
.text:0000555555558A7E         add     rdi, rsi
.text:0000555555558A81         shl     r8, 1Eh
.text:0000555555558A85         mov     rax, rdi
.text:0000555555558A88         sub     r8, rdx
.text:0000555555558A8B         shl     r8, 2
.text:0000555555558A8F         sub     r8, rdx
.text:0000555555558A92         mul     r12
.text:0000555555558A95         sub     r10, r8
.text:0000555555558A98         mov     r8d, [rbp+10h]
.text:0000555555558A9C         mov     [r14+4], r10d
.text:0000555555558AA0         mov     r10d, [r13+0Ch]
.text:0000555555558AA4         shr     rdx, 1Fh
.text:0000555555558AA8         mov     rbx, rdx
.text:0000555555558AAB         add     r11, r10
.text:0000555555558AAE         shl     rbx, 1Eh
.text:0000555555558AB2         mov     rax, r11
.text:0000555555558AB5         sub     rbx, rdx
.text:0000555555558AB8         shl     rbx, 2
.text:0000555555558ABC         sub     rbx, rdx
.text:0000555555558ABF         mul     r12
.text:0000555555558AC2         sub     rdi, rbx
.text:0000555555558AC5         mov     ebx, [rbp+14h]
.text:0000555555558AC8         mov     [r14+8], edi
.text:0000555555558ACC         mov     edi, [r13+10h]
.text:0000555555558AD0         shr     rdx, 1Fh
.text:0000555555558AD4         mov     r9, rdx
.text:0000555555558AD7         shl     r9, 1Eh
.text:0000555555558ADB         sub     r9, rdx
.text:0000555555558ADE         shl     r9, 2
.text:0000555555558AE2         sub     r9, rdx
.text:0000555555558AE5         sub     r11, r9
.text:0000555555558AE8         add     r8, rdi
.text:0000555555558AEB         mov     r9d, [rbp+18h]
.text:0000555555558AEF         mov     rax, r8
.text:0000555555558AF2         mov     [r14+0Ch], r11d
.text:0000555555558AF6         mov     r11d, [r13+14h]
.text:0000555555558AFA         mul     r12
.text:0000555555558AFD         add     rbx, r11
.text:0000555555558B00         shr     rdx, 1Fh
.text:0000555555558B04         mov     rax, rbx
.text:0000555555558B07         mov     rsi, rdx
.text:0000555555558B0A         shl     rsi, 1Eh
.text:0000555555558B0E         sub     rsi, rdx
.text:0000555555558B11         shl     rsi, 2
.text:0000555555558B15         sub     rsi, rdx
.text:0000555555558B18         mul     r12
.text:0000555555558B1B         sub     r8, rsi
.text:0000555555558B1E         mov     esi, [rbp+1Ch]
.text:0000555555558B21         mov     [r14+10h], r8d
.text:0000555555558B25         mov     r8d, [r13+18h]
.text:0000555555558B29         shr     rdx, 1Fh
.text:0000555555558B2D         mov     r10, rdx
.text:0000555555558B30         add     r9, r8
.text:0000555555558B33         shl     r10, 1Eh
.text:0000555555558B37         mov     rax, r9
.text:0000555555558B3A         sub     r10, rdx
.text:0000555555558B3D         shl     r10, 2
.text:0000555555558B41         sub     r10, rdx
.text:0000555555558B44         mul     r12
.text:0000555555558B47         sub     rbx, r10
.text:0000555555558B4A         mov     [r14+14h], ebx
.text:0000555555558B4E         mov     ebx, [r13+1Ch]
.text:0000555555558B52         shr     rdx, 1Fh
.text:0000555555558B56         mov     rdi, rdx
.text:0000555555558B59         add     rsi, rbx
.text:0000555555558B5C         shl     rdi, 1Eh
.text:0000555555558B60         mov     rax, rsi
.text:0000555555558B63         sub     rdi, rdx
.text:0000555555558B66         shl     rdi, 2
.text:0000555555558B6A         sub     rdi, rdx
.text:0000555555558B6D         mul     r12
.text:0000555555558B70         sub     r9, rdi
.text:0000555555558B73         mov     [r14+18h], r9d
.text:0000555555558B77         shr     rdx, 1Fh
.text:0000555555558B7B         mov     r11, rdx
.text:0000555555558B7E         shl     r11, 1Eh
.text:0000555555558B82         sub     r11, rdx
.text:0000555555558B85         shl     r11, 2
.text:0000555555558B89         sub     r11, rdx
.text:0000555555558B8C         sub     rsi, r11
.text:0000555555558B8F         add     rbp, 20h
.text:0000555555558B93         add     r13, 20h
.text:0000555555558B97         mov     [r14+1Ch], esi
.text:0000555555558B9B         add     r14, 20h
.text:0000555555558B9F         cmp     rcx, rbp
.text:0000555555558BA2         jnz     CREATEKEY_LOOP_7_555555558A30 ; esi = key E[0]
```

The last loop simply adds keys **E** and **F** modulo our prime `0xfffffffb`. Let's decompile this:
```python
print '[+] Calculating Public Key C:'
C = []

for i in xrange(len(E)):
    if i > 0 and i % 8 == 0: print

    S = (E[i] + F[i]) % 0xfffffffb
    print '%08X' % S,

    C.append(S)

print
```

Finally, out public key **C** will be:
```
    29637BB2 069D49D2 D8C0417D 9541CE34 2C7DD958 4673C5A2 94F2A05B 3488BAE4
    E56B61BE 108A1842 686502FA D7005358 3D21660C 346E0948 2266A88A 46D312AB
    C0586891 F10700B8 FB333E65 1F81C902 7A99480C 4EE7FAE7 6C522B16 EDF4A315
    AFB3067D F40452AA B362E2DE 84756E6D 68F37ACF 33BB1374 E5DD6797 E3D28543
    A015184E C5F5142D 93A61E4C A51CBBF2 44505E55 5294D382 591758EA DAEDDB20
    B1B8CFA6 0BC478A2 196E36DC 4C29D3C7 366548FC 335BB645 61241BB0 851E6634
    A2EB0A78 CF5ACDB3 4076238F C3A4E6DA 8EC398B3 7857A46B 0250D8E1 17CD4BD2
    310CBA17 70A63EFB F67AB5BC 56F8C59B C9FB3149 74C827DF 9C2D6F1B B7231D10
```

The last part is to simply write our keys to the file. The public key is the triplet `(A, B, C)`
and the private key is `X`:
```assembly
.text:0000555555558BA8         mov     r13, [rsp+0E08h+argv_BF8]
.text:0000555555558BB0         lea     rsi, aWb                ; "wb"
.text:0000555555558BB7         mov     rdi, [r13+10h]          ; filename
.text:0000555555558BBB         call    _fopen
.text:0000555555558BC0         test    rax, rax
.text:0000555555558BC3         mov     rbp, rax
.text:0000555555558BC6         jz      FOPEN_ERROR_FATAL_55555555AEB8
.text:0000555555558BCC         mov     rdi, [rsp+0E08h+pubkey_A_ptr_E08] ; ptr
.text:0000555555558BD0         mov     rcx, rax                ; s
.text:0000555555558BD3         mov     edx, 100h               ; n
.text:0000555555558BD8         mov     esi, 1                  ; size
.text:0000555555558BDD         call    _fwrite
.text:0000555555558BE2         mov     rdi, [rsp+0E08h+pubkey_B_ptr_E00] ; ptr
.text:0000555555558BE7         mov     rcx, rbp                ; s
.text:0000555555558BEA         mov     edx, 100h               ; n
.text:0000555555558BEF         mov     esi, 1                  ; size
.text:0000555555558BF4         call    _fwrite
.text:0000555555558BF9         mov     rcx, rbp                ; s
.text:0000555555558BFC         mov     edx, 100h               ; n
.text:0000555555558C01         mov     esi, 1                  ; size
.text:0000555555558C06         mov     rdi, r15                ; ptr
.text:0000555555558C09         call    _fwrite                 ; pubkey C
.text:0000555555558C0E         mov     rdi, rbp                ; stream
.text:0000555555558C11         call    _fclose
.text:0000555555558C16         mov     r15, [rsp+0E08h+argv_BF8]
.text:0000555555558C1E         lea     rsi, aWb                ; "wb"
.text:0000555555558C25         mov     rdi, [r15+18h]          ; filename
.text:0000555555558C29         call    _fopen
.text:0000555555558C2E         test    rax, rax
.text:0000555555558C31         mov     r14, rax
.text:0000555555558C34         jz      FOPEN_ERROR_FATAL_55555555AEB8
.text:0000555555558C3A         mov     rdi, [rsp+0E08h+privkey_X_ptr_9E8] ; ptr
.text:0000555555558C42         mov     rcx, rax                ; s
.text:0000555555558C45         mov     edx, 100h               ; n
.text:0000555555558C4A         mov     esi, 1                  ; size
.text:0000555555558C4F         call    _fwrite
.text:0000555555558C54         mov     rdi, r14                ; stream
.text:0000555555558C57         call    _fclose
.text:0000555555558C5C         jmp     END_OF_MAIN_558129D0AECF
```
___


### Plaintext Encryption

The encryption algorithm consists of **5** loops. It uses the public key `(A, B, C)` to encrypt
an arbitrary plaintext. It uses the following keys (let's use different names to avoid the
confusion):
```
K: 0x7FFFFFFFDAA0 (same address with E in key generation)
P: 0x7FFFFFFFDBA0 (same address with F in key generation)
```

In the first loop, encryption algorithm generates a random 256-byte
key **K** from `/dev/urandom`, similar to the generation of private key **X**:
```C
    for (int i=0x20; i<0x120; i+=0x20) {
        for (int j=0; j<0x20; j+=4) {
            *(uint32_t*) &X[j] = rand();
        }
    }
```

Consider the following (random) **K**:
```
    96F9FE43 8435852E 4D049055 B9698698 43CCE658 DFD9F037 86720402 B694F5C1
    1953E2A1 27FBEC27 847AD9FF 3A4D35BD 293DC239 4E169F51 F96C775B BC3660A1
    600A3D91 FB7964C8 F462CFBB 18DE4562 F560E9B0 801276AC F5F0C967 1C92D353
    0674279E B8DEBC22 3E5B507C 919459F7 9124A116 5299A040 70CC029B D09E5D11
    DFF94C07 3049BA1B 453230E2 D1DFEBD5 838F7C43 635C78A6 197C8CEA 340E1618
    B0F57057 0A189313 D0043E29 9FA10951 E532B929 F2F32C6C 65DC9F55 FFA42B0C
    6461B6F6 BB932AA9 CBA48C82 C324C9A2 9A42058D 8025F7F2 2AE1C0EF DC3F97C1
    84C22121 8E1C873E 10E190AC A5395B7F 42FDF760 EF809AEF E691302B E1C89191
```

The second loop, expands the plaintext characters into dwords and stores into key **P** at
`0x7FFFFFFFDBA0`:
```assembly
.text:0000555555558FA2 ENCRYPT_LOOP_1_555555558FA2:            ; CODE XREF: main+48C6j
.text:0000555555558FA2         movzx   r8d, byte ptr [r11+4]   ; expand plaintext to dwords
.text:0000555555558FA7         movzx   eax, byte ptr [r11+5]
.text:0000555555558FAC         add     r9, 20h
.text:0000555555558FB0         movzx   edi, byte ptr [r11+6]
.text:0000555555558FB5         movzx   ecx, byte ptr [r11+7]
.text:0000555555558FBA         add     r11, 8
.text:0000555555558FBE         movzx   r12d, byte ptr [r11-8]
.text:0000555555558FC3         movzx   edx, byte ptr [r11-7]
.text:0000555555558FC8         movzx   ebp, byte ptr [r11-6]
.text:0000555555558FCD         movzx   r14d, byte ptr [r11-5]
.text:0000555555558FD2         mov     dword ptr [rsp+0E08h+pubkey_A_ptr_E08], r8d
.text:0000555555558FD6         mov     dword ptr [rsp+0E08h+pubkey_B_ptr_E00], eax
.text:0000555555558FDA         mov     dword ptr [rsp+0E08h+rand2_DF8], edi
.text:0000555555558FDE         mov     dword ptr [rsp+0E08h+rand1_DF0], ecx
.text:0000555555558FE2         movd    xmm1, dword ptr [rsp+0E08h+rand2_DF8]
.text:0000555555558FE8         movd    xmm3, dword ptr [rsp+0E08h+rand1_DF0]
.text:0000555555558FEE         mov     dword ptr [rsp+0E08h+rand2_DF8], ebp
.text:0000555555558FF2         movd    xmm0, dword ptr [rsp+0E08h+pubkey_A_ptr_E08]
.text:0000555555558FF7         mov     dword ptr [rsp+0E08h+rand1_DF0], r14d
.text:0000555555558FFC         movd    xmm4, dword ptr [rsp+0E08h+pubkey_B_ptr_E00]
.text:0000555555559002         mov     dword ptr [rsp+0E08h+pubkey_A_ptr_E08], r12d
.text:0000555555559006         mov     dword ptr [rsp+0E08h+pubkey_B_ptr_E00], edx
.text:000055555555900A         movd    xmm2, dword ptr [rsp+0E08h+rand2_DF8]
.text:0000555555559010         movd    xmm5, dword ptr [rsp+0E08h+rand1_DF0]
.text:0000555555559016         punpckldq xmm1, xmm3
.text:000055555555901A         movd    xmm7, dword ptr [rsp+0E08h+pubkey_A_ptr_E08]
.text:000055555555901F         punpckldq xmm0, xmm4
.text:0000555555559023         movd    xmm6, dword ptr [rsp+0E08h+pubkey_B_ptr_E00]
.text:0000555555559029         punpckldq xmm2, xmm5
.text:000055555555902D         punpckldq xmm7, xmm6
.text:0000555555559031         punpcklqdq xmm0, xmm1
.text:0000555555559035         punpcklqdq xmm7, xmm2
.text:0000555555559039         movaps  xmmword ptr [r9-10h], xmm0
.text:000055555555903E         movaps  xmmword ptr [r9-20h], xmm7
.text:0000555555559043         cmp     r9, r10
.text:0000555555559046         jnz     ENCRYPT_LOOP_1_555555558FA2 ; expand plaintext to dwords
```

This can be decompiled into 1 line of python:
```python
P = [ord(p) for p in plain]
```

The second loop starts by finding the substitution table for public key **A** and then it performs
a "round" using the random key **K**:
```assembly
.text:0000555555559444         mov     [rsp+0E08h+var_BE0], r10
.text:000055555555944C         lea     rdi, [rax+4]
.text:0000555555559450         lea     rcx, [rax+8]
.text:0000555555559454         mov     [rsp+0E08h+var_BD8], r9
.text:000055555555945C         mov     [rsp+0E08h+var_BD0], r8
.text:0000555555559464         mov     r15, rax
.text:0000555555559467         mov     [rsp+0E08h+var_BC8], rdi
.text:000055555555946F         mov     [rsp+0E08h+var_BC0], rcx
.text:0000555555559477
.text:0000555555559477 ENCRYPT_LOOP_2_555555559477:                ; CODE XREF: main+5231j
.text:0000555555559477         mov     rax, [rsp+0E08h+var_BD8]    ; rax = A[0]
.text:000055555555947F         mov     ecx, [r13+r12+0]            ; rcx = K[0]
.text:0000555555559484         mov     rdx, [rsp+0E08h+var_C08]
.text:000055555555948C         mov     rsi, [rsp+0E08h+privkey_subX_C00]
.text:0000555555559494         mov     ebx, [r14+r12]              ; ebx = K[1]
.text:0000555555559498         mov     r9, [rsp+0E08h+var_BE8]
.text:00005555555594A0         mov     edi, [rax+r12]              ; edi = K[7]
.text:00005555555594A4         mov     rax, [rsp+0E08h+var_D68]
.text:00005555555594AC         mov     r11d, [rdx+r12]             ; r11 = K[2]
.text:00005555555594B0         mov     rdx, [rsp+0E08h+var_BD0]
.text:00005555555594B8         mov     r10d, [rsi+r12]             ; r10 = K[3]
.text:00005555555594BC         mov     r9d, [r9+r12]               ; r9 = K[4]
.text:00005555555594C0         imul    rax, rcx                    ; rax = A[0] * K[0]
.text:00005555555594C4         mov     r8, [rsp+0E08h+var_BE0]
.text:00005555555594CC         mov     esi, [rdx+r12]
.text:00005555555594D0         xor     edx, edx
.text:00005555555594D2         mov     r8d, [r8+r12]
.text:00005555555594D6         div     rbp                         ; rdx = (A[0] * K[0]) % 0xffffffffb
.text:00005555555594D9         mov     rax, [rsp+0E08h+var_D70]
.text:00005555555594E1         imul    rax, rbx
.text:00005555555594E5         add     rax, rdx
....
.text:000055555555999C         xor     edx, edx
.text:000055555555999E         div     rbp
.text:00005555555599A1         mov     [r15+r12+1Ch], edx
.text:00005555555599A6         add     r12, 20h
.text:00005555555599AA         cmp     r12, 100h
.text:00005555555599B1         jnz     ENCRYPT_LOOP_2_555555559477 ; rax = A[0]
```

The decompiled version of the above code (wrapped into a function) is shown below for key **Q**:
```python
def round(A, B, subB, name='?'):
    sub_tbl_B = find_sub_tbl(B, subB)
    print

    print '[+] Calculating Key %s:' % name
    X = []

    for k in xrange(0, 0x40, 8):
        for j in xrange(8):
            S = 0
            for i in xrange(8):
                S = (A[k + i] * subB[sub_tbl_B[j][i] << 1] + S) % 0xfffffffb
                
            print '%08X' % S,

            X.append(S)
        print
    print        

    return X
```

The third and fourth loops are the same, but they apply the round function to public keys **B**
and **C**:
```python
R = round(K, B, subB, 'R')
S = round(K, C, subC, 'S')
```

Back to our example we get the following keys:
```
Key Q:
    FCE16360 77E95321 431B934B 1711F847 A3D60228 BA135820 BBB02FFA E7B0B2A0
    60798C67 94FD4AE9 92A70424 2397C6B8 5CFD687A 9C840335 7F2459A8 2C682A80
    31BF5C75 8F50A3E1 3673C31B 38ADBDDC BD5ECF70 62F095EC 5982E9D5 D8A20AAD
    54497A3E CBFF49CE 943AA22B F85FAFED FED3CA6D 9250809A 0012FA1F 18B0E385
    82205D26 12B51380 DBC07906 3B84144F CFBA2009 348AAA47 30F290BC 29EA286A
    3A39C577 B7885497 EC41C1CD 24DDA674 DF6BAE9C A3517879 0D526145 3BA0A522
    DF12738E 776910DB 9FD9BFF4 36218286 2B99A680 141A1695 F639F374 2D24EEAD
    9B2F5634 300384FF 0BC6D08E 401B6DEC A4152AAC 92715FC8 486771BB 13869F1D

Key R:
    10286242 BF2C33E9 D71C37CE 8A36D0BB 8793425D 7C6DF8D1 CC7C6E24 499B8657
    B2875A14 B0C0D85E 21214604 83997A7C F5535960 7C31C57F 10FBDA30 74377A0B
    29C88BD3 EFAD2A07 91883B1D ABFB536E D76D4A58 1953011F FDB09550 F35EFA12
    C0523AD2 A858DE00 CE2DEF41 6AAE706E 39F54C6A 77B6AE27 9A2F7C3C 99535076
    DC7C6CF5 6F7742EC E012ACA6 34C0DE05 CF49070D 26D49027 C732D496 12CF0E30
    560412E9 8C8BD552 08FC4332 D757084A 38BEC80C 284D65D0 1B800309 88AE5410
    239636EB 28AE8703 3F01A646 A22C4510 A58B2851 85B35BE3 3CD8271E 9F8592CB
    B70728B8 2E8B7B50 43BEB6AE 04E6A831 A1461E69 7D896E3B 6993117B 6AF293EB

Key S:
    303D9E55 125C3451 5B6F61AA BE542785 764986CE 564EE5F8 C8F7344D 462F5DF7
    8A9B8349 8677AD51 9FDBA022 37F7A60B 5D62F8B9 A800A821 84874EA3 F05E1283
    FFE944EF 492755D2 91FAA693 2D34CBFE E91530AB BD6787D1 8438B862 0959C4B2
    BDA56081 927450EB 62FB4C49 907E5B30 7F5E5B48 8D8AA195 851248C3 24950903
    CA7CA06F 03372390 D0CAD159 56131434 A694ABF7 2998E7FF 7C7A2B79 B2256961
    4692974F 3083C6B0 1D2E870C B812B764 C6214119 B7BDFE09 89E051D2 CD4CBD51
    58DDE74F 582343F5 B1655BA9 4A6C2739 83B650D2 23F4B21D 9B359609 FB3127B7
    02C31A66 6725230B 52F710E5 D907E903 530938F4 92FB85BD 94B9E886 7E702337
```


Finally, the fifth loop uses key **S** to compute the final ciphertext:
```assembly
.text:000055555555ACCD ENCRYPT_LOOP_5_55555555ACCD:                ; CODE XREF: main+6606j
.text:000055555555ACCD         mov     edx, [r13+rcx+0]            ; edx = plain[0]
.text:000055555555ACD2         mov     eax, [r15+rcx]              ; eax = Z[0]
.text:000055555555ACD6         add     rax, rdx                    ; rax = Z[0] + plain[0]
.text:000055555555ACD9         xor     edx, edx
.text:000055555555ACDB         div     rsi                         ; rdx = (Z[0] + plain[0]) % 0xfffffffb
.text:000055555555ACDE         mov     eax, [r9+rcx]
.text:000055555555ACE2         mov     [r10+rcx], edx              ; Cipher[0] = (Z[[0] + plain[0]) % 0xfffffffb
.text:000055555555ACE6         mov     edx, [r8+rcx]
.text:000055555555ACEA         add     rax, rdx
.text:000055555555ACED         xor     edx, edx
.text:000055555555ACEF         div     rsi
.text:000055555555ACF2         mov     rax, [rsp+0E08h+pubkey_A_ptr_E08]
.text:000055555555ACF6         mov     [rax+rcx], edx
.text:000055555555ACF9         mov     edx, [rbx+rcx]
.text:000055555555ACFC         mov     eax, [r11+rcx]
.text:000055555555AD00         add     rax, rdx
.text:000055555555AD03         xor     edx, edx
.text:000055555555AD05         div     rsi
.text:000055555555AD08         mov     eax, [r14+rcx]
.text:000055555555AD0C         mov     [rdi+rcx], edx
.text:000055555555AD0F         mov     edx, [r12+rcx]
.text:000055555555AD13         add     rax, rdx
.text:000055555555AD16         xor     edx, edx
.text:000055555555AD18         div     rsi
.text:000055555555AD1B         mov     eax, [r15+rcx+10h]
.text:000055555555AD20         mov     [rbp+rcx+0], edx
.text:000055555555AD24         mov     edx, [r13+rcx+10h]
.text:000055555555AD29         add     rax, rdx
.text:000055555555AD2C         xor     edx, edx
.text:000055555555AD2E         div     rsi
.text:000055555555AD31         mov     eax, [r15+rcx+14h]
.text:000055555555AD36         mov     [r10+rcx+10h], edx
.text:000055555555AD3B         mov     edx, [r13+rcx+14h]
.text:000055555555AD40         add     rax, rdx
.text:000055555555AD43         xor     edx, edx
.text:000055555555AD45         div     rsi
.text:000055555555AD48         mov     eax, [r15+rcx+18h]
.text:000055555555AD4D         mov     [r10+rcx+14h], edx
.text:000055555555AD52         mov     edx, [r13+rcx+18h]
.text:000055555555AD57         add     rax, rdx
.text:000055555555AD5A         xor     edx, edx
.text:000055555555AD5C         div     rsi
.text:000055555555AD5F         mov     eax, [r15+rcx+1Ch]
.text:000055555555AD64         mov     [r10+rcx+18h], edx
.text:000055555555AD69         mov     edx, [r13+rcx+1Ch]
.text:000055555555AD6E         add     rax, rdx
.text:000055555555AD71         xor     edx, edx
.text:000055555555AD73         div     rsi
.text:000055555555AD76         mov     [r10+rcx+1Ch], edx
.text:000055555555AD7B         add     rcx, 20h
.text:000055555555AD7F         cmp     rcx, 100h
.text:000055555555AD86         jnz     ENCRYPT_LOOP_5_55555555ACCD ; edx = plain[0]
```

The decompiled version of the above code is:
```python
print '[+] Calculating Ciphertext:'
cipher = []

for i in xrange(len(S)):
    if i > 0 and i % 8 == 0: print

    Sum = (S[i] + P[i]) % 0xfffffffb
    print '%08X' % Sum,

    cipher.append(Sum)

print
print    
```

Our example ciphertext will be:
```
    303D9EA9 125C34B9 5B6F6213 BE5427F8 764986EE 564EE661 C8F734C0 462F5E17
    8A9B83B2 8677ADC4 9FDBA092 37F7A67A 5D62F928 A800A890 84874F12 F05E12F2
    FFE9455E 49275641 91FAA702 2D34CC6D E91530AB BD6787D1 8438B862 0959C4B2
    BDA56081 927450EB 62FB4C49 907E5B30 7F5E5B48 8D8AA195 851248C3 24950903
    CA7CA06F 03372390 D0CAD159 56131434 A694ABF7 2998E7FF 7C7A2B79 B2256961
    4692974F 3083C6B0 1D2E870C B812B764 C6214119 B7BDFE09 89E051D2 CD4CBD51
    58DDE74F 582343F5 B1655BA9 4A6C2739 83B650D2 23F4B21D 9B359609 FB3127B7
    02C31A66 6725230B 52F710E5 D907E903 530938F4 92FB85BD 94B9E886 7E702337
```


Which is simply the addition of the plaintext to **S**. The final ciphertext will be the
tuple `(Q, R, cipher)`:
```assembly
.text:000055555555AD9F         call    _fopen
.text:000055555555ADA4         test    rax, rax
.text:000055555555ADA7         mov     r14, rax
.text:000055555555ADAA         jz      FOPEN_ERROR_FATAL_55555555AEB8
.text:000055555555ADB0         mov     rdi, [rsp+0E08h+ptr]        ; ptr
.text:000055555555ADB8         mov     rcx, rax                    ; s
.text:000055555555ADBB         mov     edx, 100h                   ; n
.text:000055555555ADC0         mov     esi, 1                      ; size
.text:000055555555ADC5         call    _fwrite                     ; write 0x7FFFFFFFD6A0 (X)
.text:000055555555ADCA         mov     rdi, [rsp+0E08h+var_BA0]    ; ptr
.text:000055555555ADD2         mov     rcx, r14                    ; s
.text:000055555555ADD5         mov     edx, 100h                   ; n
.text:000055555555ADDA         mov     esi, 1                      ; size
.text:000055555555ADDF         call    _fwrite                     ; write 0x7FFFFFFFD7A0 (Y)
.text:000055555555ADE4         mov     rdi, [rsp+0E08h+var_BB0]    ; ptr
.text:000055555555ADEC         mov     rcx, r14                    ; s
.text:000055555555ADEF         mov     edx, 100h                   ; n
.text:000055555555ADF4         mov     esi, 1                      ; size
.text:000055555555ADF9         call    _fwrite                     ; write 0x7FFFFFFFD9A0 (Cipher)
.text:000055555555ADFE         mov     rdi, r14                    ; stream
.text:000055555555AE01         call    _fclose
.text:000055555555AE06         jmp     END_OF_MAIN_558129D0AECF
```
___


### Cipher Decryption

Decryption consists of **6** loops. The first loop starts by calculating the substitution table
for the private key **X**:
```assembly
.text:000055555555B0D9         mov     esi, [rsp+0E08h+pubkey_C_788] ; create substitution table for private key X
.text:000055555555B0E0         mov     edx, [rsp+0E08h+var_768]
.text:000055555555B0E7         mov     r8d, [rsp+0E08h+var_748]
.text:000055555555B0EF         mov     eax, [rsp+0E08h+var_728]
.text:000055555555B0F6         mov     r9d, [rsp+0E08h+var_708]
.text:000055555555B0FE         mov     ecx, [rsp+0E08h+var_6C8]
.text:000055555555B105         mov     r10d, [rsp+0E08h+var_6A8]
.text:000055555555B10D         mov     r12d, [rsp+0E08h+var_784]
.text:000055555555B115         mov     r11d, [rsp+0E08h+var_764]
.text:000055555555B11D         mov     r14d, [rsp+0E08h+var_744]
.text:000055555555B125         mov     [rsp+0E08h+var_DB0], rsi
.text:000055555555B12A         mov     [rsp+0E08h+var_DA8], rdx
.text:000055555555B12F         mov     esi, [rsp+0E08h+var_724]
....
```

Then it performs a "round" on a private key **X** using substitution table for **X**:
```assembly
.text:000055555555B509 DECRYPT_LOOP_1_55555555B509:                ; CODE XREF: main+72E8j
.text:000055555555B509         mov     r10, [rsp+0E08h+var_BE0]
.text:000055555555B511         mov     rax, [rsp+0E08h+var_BB0]
.text:000055555555B519         mov     rdx, [rsp+0E08h+var_BC0]
.text:000055555555B521         mov     r12, [rsp+0E08h+var_BD8]
.text:000055555555B529         mov     r11, [rsp+0E08h+var_BD0]
.text:000055555555B531         mov     rsi, [rsp+0E08h+var_BC8]
.text:000055555555B539         mov     ecx, [r10+r14]              ; ecx = X[0]
.text:000055555555B53D         mov     edi, [rax+r14]              ; edi = X[6]
.text:000055555555B541         mov     rax, [rsp+0E08h+var_DB0]
.text:000055555555B546         mov     r9d, [rdx+r14]              ; r9 = X[5]
.text:000055555555B54A         xor     edx, edx
.text:000055555555B54C         mov     r12d, [r12+r14]             ; r12 = X[1]
.text:000055555555B550         mov     r11d, [r11+r14]             ; r11 = X[2]
.text:000055555555B554         mov     r10d, [rsi+r14]             ; r10 = X[3]
.text:000055555555B558         mov     r8, [rsp+0E08h+var_BB8]
.text:000055555555B560         imul    rax, rcx                    ; X[0] * X[0] % 0xfffffffb ?
.text:000055555555B564         mov     rsi, [rsp+0E08h+ptr]
.text:000055555555B56C         mov     r8d, [r8+r14]
.text:000055555555B570         mov     esi, [rsi+r14]
.text:000055555555B574         div     r13
.text:000055555555B577         mov     rax, [rsp+0E08h+var_DA8]
.text:000055555555B57C         imul    rax, r12                    ; rax = X[1] * X[9]
.text:000055555555B580         add     rax, rdx
.text:000055555555B583         xor     edx, edx
.text:000055555555B585         div     r13
.text:000055555555B588         mov     rax, [rsp+0E08h+var_DA0]
.text:000055555555B58D         imul    rax, r11                    ; rax = X[2] * X[16]
.text:000055555555B591         add     rax, rdx
....
.text:000055555555BA58         mov     [rbx+r14+1Ch], edx
.text:000055555555BA5D         add     r14, 20h
.text:000055555555BA61         cmp     r14, 100h
.text:000055555555BA68         jnz     DECRYPT_LOOP_1_55555555B509
```

That is:
```python
X2 = round(X, X, subX, 'X^2')
```

That is, our example **X^2** will be:
```
    E56DC736 95DABF87 9E74A18C EFF74AA8 B8914E00 2C036DF9 51C88DDF 3A0B7DBC
    A9CEF9F9 9C5EFA42 19215043 25FC6610 FEE0D8C5 E1486786 6B541DA9 A6269A2D
    F07B4C1A 9F9D48CF 9D8684FD BF2F6E8D B2DD7CEF 49177639 263EAB1D CE84D842
    125165F7 AAB81A21 A223D4B0 5DAF939D 306EC103 531DDAB6 CBBEEFD5 F7E2FECB
    CB031F68 6C21E049 F61601E3 FC0D94A0 F7F317B9 07ABE34A 161F0E53 F8529786
    F97779C6 8B8C5A9F 4EC808F2 8E17AE0C 32B60A9B 1C5CA253 A6AEE656 4CE28BCA
    A8DEE40D 60E6EFCC E23C4348 4ED90337 586418D4 A4F48E99 C5C346EB 66EC685A
    99842D5D 586823BE E3E7919D 0E64DD7B 895A6B22 97E13C18 DD88DBA6 CB84CF66
```

The second loop is similar to the first loop but it creates the substitution table of X2 first
and then performs a round between key **Q** and **X^2**:
```python
M = round(Q, X2, subX2, 'M')
```

The third loop is similar to the previous ones and performs a "round" on private key **X** and
intermediate key **R**:
```python
N = round(R, X, subX, 'N')
```

Back to our example, **M** and **N** will be:
```
Key M:
    DD5E9B2C 205D27E7 8FF76D26 E3906E3C 5F2F0F28 68AB1816 D6221D73 A89BA3A1
    EDAFA486 36A6A5B7 658D2370 FF1908DA A7FDFECA B773E6A2 35D1640A 8B5678D9
    75E1D612 1E1CA334 250BAB20 3CF49C03 B5B668E7 0362884A E3DF52E0 0B6F21DB
    E919BF09 47DCE532 D117F2E6 6DAA0CBF 5A670D31 6937636A B4ECCFE4 59310B3E
    4E17082C 11177BE2 E2618419 F26BFB71 3B4F4025 BFC6D3C2 C5F924FB 1BD42F85
    94FFD1FE 61ED956B E55624F8 F1D50B5E FDD711CE E0BF424A 4DB666E8 A8678501
    20C8264D 874C59F7 65E56217 C5C845DB 36C98A71 B6E025E9 23FC3FEA 13EE12A3
    448EDFC8 539DD637 7C17C8D1 8AB091BE A7C2133D FD810BA6 89DDFCF1 573F7BC3

Key N:
    F263C675 CD46A3C3 1499312B 5E1B6A35 2A876A05 410601ED 60E6AE36 1134FE63
    87B4D827 42E1ACF3 FA973C64 C8EF5111 FA9F0873 A08B7133 45A74D4E 844B749A
    8A34E4F5 98BC06F5 48F9AE48 95D697FA 61346664 3F35EFE0 97E7F4B4 EB37196E
    5940E06C 25AEC9DE CBECC0C7 01D7980C 263A9782 093DFAFC C600E74F 8239EBBA
    E76C575B EBB16089 4CD3AA84 B780F051 1E1C13DF 16A0443A BD8CAF82 32066715
    246D96AE 6D8EA3E0 FD7B53F2 56183D34 3C07AD0F 6782BFA3 28694741 8A4BBDA4
    8659F25F 2090620F E8B54236 EFCB92E2 458024B8 252B27F5 40CE2A08 F0E0C59C
    B8AE05CD 453D06B9 30F12645 9C478535 0534B3CA 6F836E93 E1681A7F 2A506101
```

The fourth loop adds keys **N** and **M** to get key **O**:
```assembly
.text:000055555555CA6E DECRYPT_LOOP_4_55555555CA6E:                ; CODE XREF: main+83A0j
.text:000055555555CA6E         mov     edx, [r15+rcx]
.text:000055555555CA72         mov     eax, [rbp+rcx+0]
.text:000055555555CA76         add     rax, rdx
.text:000055555555CA79         xor     edx, edx
.text:000055555555CA7B         div     rsi
.text:000055555555CA7E         mov     eax, [r9+rcx]
.text:000055555555CA82         mov     [rbx+rcx], edx
.text:000055555555CA85         mov     edx, [r8+rcx]
.text:000055555555CA89         add     rax, rdx
....
.text:000055555555CB11         mov     [rbx+rcx+1Ch], edx
.text:000055555555CB15         add     rcx, 20h
.text:000055555555CB19         cmp     rcx, 100h
.text:000055555555CB20         jnz     DECRYPT_LOOP_4_55555555CA6E
```

Let's decompile this:
```python 
print '[+] Calculating O:'
O = []

for i in xrange(len(N)):
    if i > 0 and i % 8 == 0: print

    S = (N[i] + M[i]) % 0xfffffffb
    print '%08X' % S,

    O.append(S)

print '\n'
```

Key **O** will be:
```
    CFC261A6 EDA3CBAA A4909E51 41ABD876 89B6792D A9B11A03 3708CBAE B9D0A204
    75647CB2 798852AA 60245FD9 C80859F0 A29D0742 57FF57DA 7B78B158 0FA1ED78
    0016BB0C B6D8AA29 6E055968 D2CB33FD 16EACF50 4298782A 7BC74799 F6A63B49
    425A9F7A 6D8BAF10 9D04B3B2 6F81A4CB 80A1A4B3 72755E66 7AEDB738 DB6AF6F8
    35835F8C FCC8DC6B 2F352EA2 A9ECEBC7 596B5404 D66717FC 8385D482 4DDA969A
    B96D68AC CF7C394B E2D178EF 47ED4897 39DEBEE2 484201F2 761FAE29 32B342AA
    A72218AC A7DCBC06 4E9AA452 B593D8C2 7C49AF29 DC0B4DDE 64CA69F2 04CED844
    FD3CE595 98DADCF0 AD08EF16 26F816F8 ACF6C707 6D047A3E 6B461775 818FDCC4
```

The fifth loop is identical to the previous once and adds key **O** to the ciphertext to get
decrypted message **M**:
```python
print '[+] Calculating M:'
M = []

for i in xrange(len(N)):
    if i > 0 and i % 8 == 0: print

    S = (O[i] + cipher[i]) % 0xfffffffb
    print '%08X' % S,

    M.append(S)

print '\n'   
```

Following our example, **M** will be:
```
    00000054 00000068 00000069 00000073 00000020 00000069 00000073 00000020
    00000069 00000073 00000070 0000006F 0000006F 0000006F 0000006F 0000006F
    0000006F 0000006F 0000006F 0000006F 00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
    00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
```


At this point we have recovered the dwords of the plaintext. As you can guess the sixth loop
casts the dwords back to characters to reconstruct the actual plaintext:
```assembly
.text:000055555555CC22 DECRYPT_LOOP_6_55555555CC22:                ; CODE XREF: main+85B6j
.text:000055555555CC22         lea     r9, [rbp+1]
.text:000055555555CC26         mov     esi, ebp
.text:000055555555CC28         mov     rcx, rbp
.text:000055555555CC2B         sar     esi, 3
.text:000055555555CC2E         and     ecx, 7
.text:000055555555CC31         lea     r15, [rbp+2]
.text:000055555555CC35         mov     r8, r9
.text:000055555555CC38         sar     r9d, 3
.text:000055555555CC3C         movsxd  r12, esi
.text:000055555555CC3F         and     r8d, 7
.text:000055555555CC43         movsxd  rdi, r9d
.text:000055555555CC46         lea     r11, [rcx+r12*8]
.text:000055555555CC4A         lea     r13, [r8+rdi*8]
.text:000055555555CC4E         lea     r12, [rbp+3]
.text:000055555555CC52         lea     rdi, [rbp+4]
.text:000055555555CC56         mov     r10d, [rsp+r11*4+0E08h+key_F_188]
.text:000055555555CC5E         mov     rax, r15
.text:000055555555CC61         sar     r15d, 3
.text:000055555555CC65         mov     r14d, [rsp+r13*4+0E08h+key_F_188]
.text:000055555555CC6D         mov     r11, r12
.text:000055555555CC70         mov     r13, rdi
.text:000055555555CC73         sar     r12d, 3
.text:000055555555CC77         sar     edi, 3
.text:000055555555CC7A         and     eax, 7
.text:000055555555CC7D         movsxd  rdx, r15d
.text:000055555555CC80         and     r11d, 7
.text:000055555555CC84         and     r13d, 7
.text:000055555555CC88         mov     [rbx+rbp], r10b
.text:000055555555CC8C         mov     [rbx+rbp+1], r14b
.text:000055555555CC91         movsxd  r10, r12d
.text:000055555555CC94         movsxd  r14, edi
.text:000055555555CC97         lea     rcx, [rax+rdx*8]
.text:000055555555CC9B         lea     r9, [r11+r10*8]
.text:000055555555CC9F         lea     r15, [r13+r14*8+0]
.text:000055555555CCA4         lea     rdx, [rbp+5]
.text:000055555555CCA8         lea     r10, [rbp+6]
.text:000055555555CCAC         mov     esi, [rsp+rcx*4+0E08h+key_F_188]
.text:000055555555CCB3         mov     r8d, [rsp+r9*4+0E08h+key_F_188]
.text:000055555555CCBB         lea     r14, [rbp+7]
.text:000055555555CCBF         mov     eax, [rsp+r15*4+0E08h+key_F_188]
.text:000055555555CCC7         mov     rcx, rdx
.text:000055555555CCCA         mov     r9, r10
.text:000055555555CCCD         sar     edx, 3
.text:000055555555CCD0         sar     r10d, 3
.text:000055555555CCD4         mov     r15, r14
.text:000055555555CCD7         sar     r14d, 3
.text:000055555555CCDB         and     ecx, 7
.text:000055555555CCDE         mov     [rbx+rbp+2], sil
.text:000055555555CCE3         mov     [rbx+rbp+3], r8b
.text:000055555555CCE8         mov     [rbx+rbp+4], al
.text:000055555555CCEC         movsxd  rsi, edx
.text:000055555555CCEF         and     r9d, 7
.text:000055555555CCF3         and     r15d, 7
.text:000055555555CCF7         movsxd  r8, r10d
.text:000055555555CCFA         movsxd  rax, r14d
.text:000055555555CCFD         lea     r12, [rcx+rsi*8]
.text:000055555555CD01         lea     rdi, [r9+r8*8]
.text:000055555555CD05         lea     rdx, [r15+rax*8]
.text:000055555555CD09         mov     r11d, [rsp+r12*4+0E08h+key_F_188]
.text:000055555555CD11         mov     r13d, [rsp+rdi*4+0E08h+key_F_188]
.text:000055555555CD19         mov     ecx, [rsp+rdx*4+0E08h+key_F_188]
.text:000055555555CD20         mov     [rbx+rbp+5], r11b
.text:000055555555CD25         mov     [rbx+rbp+6], r13b
.text:000055555555CD2A         mov     [rbx+rbp+7], cl
.text:000055555555CD2E         add     rbp, 8
.text:000055555555CD32         cmp     rbp, 40h
.text:000055555555CD36         jnz     DECRYPT_LOOP_6_55555555CC22
```

The recovered plaintext will be `This is ispooooooooo`.

Once we recover the plaintext we simply dump it to a file:
```assembly
.text:000055555555CD3C         mov     rbp, [rsp+0E08h+argv_BF8]
.text:000055555555CD44         lea     rsi, aWb                    ; "wb"
.text:000055555555CD4B         mov     rdi, [rbp+20h]              ; filename
.text:000055555555CD4F         call    _fopen
.text:000055555555CD54         test    rax, rax
.text:000055555555CD57         mov     r12, rax
.text:000055555555CD5A         jz      FOPEN_ERROR_FATAL_55555555AEB8
.text:000055555555CD60         mov     rdi, rbx                    ; ptr
.text:000055555555CD63         mov     rcx, rax                    ; s
.text:000055555555CD66         mov     edx, 40h                    ; n
.text:000055555555CD6B         mov     esi, 1                      ; size
.text:000055555555CD70         call    _fwrite
.text:000055555555CD75         mov     rdi, r12                    ; stream
.text:000055555555CD78         call    _fclose
.text:000055555555CD7D         jmp     END_OF_MAIN_558129D0AECF
```

The whole crypto algorithm is shown in [m_poly_cipher_algo.py](./m_poly_cipher_algo.py) script.

___


### Breaking the algorithm

After all we can conclude that the `round` function is nothing more than a matrix multiplication!
The columns are sometimes shuffled -which adds a some confusion- but since the order of the
addition does not matter, the result is the same.

Let's go back and recap the crypto algorithm:

Key Generation:
```
    A = Random 128 bytes
    B = Random 128 bytes
    X = Random 256 bytes

    D = X * X = X^2
    E = -A * D = -A * X * X = -A * X^2
    F = -B * D = -B * X * X = -B * X^2

    C = E + F = -A * X^2 + -B * X^2 = (-A + -B) * X^2

    Public Key Pair: (A, B, C)
    Private Key: X
```

Encryption:
```
    K = Random 256 bytes

    Q = K * A
    R = K * B
    S = K * C = K * (-A + -B) * X^2

    cipher = S + P = K*C + P = K*(-A + -B)*X^2 + P

    Encrypted Message: (Q, R, cipher)
```

Decryption:
``` 
    D = X * X = X^2
    M = Q * D = Q * X^2
    N = R * D = R * X^2

    O = M + N = Q*X^2 + R*X^2 = (Q + R)*X^2 = (K*A + K*B)*X^2 = K*(A + B)*X^2
    P = O + cipher = K*(A + B)*X^2 + K*(-A + -B)*X^2 + P = K*(A + B + -A + -B)*X^2 + P = P

    Decrypted Message: P
```

What we have is the encrypted flag `(Q, R, cipher)` and the public key `(A, B, C)` and we want to
find either the plaintext `P` or the private key `X`.

By looking at the encyption, is we can recover `K`, then we can recover `X^2`. We can easily
recover `K`, by multiplying `Q` with `A^-1`. However, matrix `A` is **NOT** invertible as it has
a determinant of zero. This should be no surprise to us, if we look back on how `A` and `B`
are created: The first half of `A` gets random values and the second half gets values
`(0xfffffffb - A[i])`, which should we expect to give a modular determinant of `0`.


So let's try another approach: First we calculate `(-A + -B)^-1` (we can since we know both `A`
and `B`). Then we multiply that with `C` and we get `X^2`. At this point we can either get the
square root (we should, since `X` is totally random), or try to recover `P` (let's do that).
The next step is to find `(Q + R)*X^2`, which is easy since we have all of them. Once we know
`(Q + R)*X^2`, we essentially know `K*(A + B)*X^2`. If we add this to the cipher text, we get
the original plaintext `P` back, which gives us the flag: `TWCTF{pa+h_t0_tomorr0w}`.


For more details please look at the [m_poly_cipher_crack.py](./m_poly_cipher_crack.py) script.

___
