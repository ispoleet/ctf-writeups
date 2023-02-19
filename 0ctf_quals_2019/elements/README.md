## 0CTF 2019 - Elements (Reversing 107)
##### 22/03 - 24/03/2019 (48hr)
___


### Description


```
http://111.186.63.17/Elements
```
___


### Solution


Binary is fairly small and straightforward to understand:
```c
int __fastcall main(int argc, char **argv, char **argp) {
  /* ... */
  fgets(flag, 256, stdin);
  flag_0 = flag[0];
  if ( flag[0] ) {
    tolower = __ctype_tolower_loc();
    flag_1 = &flag[1];
    do {                                        // cast to lowercase    
      *(flag_1 - 1) = (*tolower)[flag_0];
      flag_0 = *flag_1++;
    } while ( flag_0 );
  }
  len = strlen(flag);
  result = 0;
  // flag{......................................}
  if ( len >= 44 && (*(_QWORD *)flag & 0xFFFFFFFFFFLL) == '{galf' && flag[43] == '}' ) {
    flag[43] = 0;
    // flag{ABCDEFGHIJKL-MNOPQRSTUVWX-YZ0123456789}
    elt = strtok(&flag[5], "-");                // get 1st element
    elt_id = 0LL;
    if ( elt ) {
      while ( strlen(elt) == 12 ) {             // convert hex string to num
        elt_cur_ch = *elt;
        hash = 0LL;
        if ( *elt ) {
          isalnum = *__ctype_b_loc();           // __isalnum_l
          ii = 1LL;
          hash = 0LL;
          do {
            elt1_0_ = elt_cur_ch;
            v15 = isalnum[elt_cur_ch];          // convert to hex
            if ( (char)elt1_0_ <= 'f' && (v15 & 0x400) != 0 ) {
              v16 = elt1_0_ - 0x57;             // 0x57 + 10 = 0x61 = 'a'
            } else {
              if ( (v15 & 0x800) == 0 )
                return -1;
              v16 = elt1_0_ - '0';
            }
            hash = v16 | (0x10 * hash);
            if ( ii > 11 )
              break;
            elt_cur_ch = elt[ii++];
          } while ( elt_cur_ch );
        }
        // flag{391BC2164F0A-123456789012-34567890abcd}
        if ( !elt_id && hash != 0x391BC2164F0ALL )
          break;
        dblnum = (__m128i)_mm_sub_pd(
                            // https://www.officedaytime.com/simd512e/simdimg/unpack.php?f=punpckldq
                            (__m128d)_mm_unpacklo_epi32((__m128i)(unsigned __int64)hash, (__m128i)xmmword_400BD0),
                            (__m128d)xmmword_400BE0);
        M[elt_id++] = *(double *)_mm_shuffle_epi32(dblnum, 78).m128i_i64 + *(double *)dblnum.m128i_i64;
        elt_next = strtok(0LL, "-");
        elt = elt_next;
        if ( elt_id > 2 || !elt_next ) {
          if ( M[1] <= M[0] || M[2] <= M[1] || M[0] + M[1] <= M[2] )
            return -1;
          D = M[1] * M[1] + M[0] * M[0] - M[2] * M[2];
          E = sqrt(4.0 * M[0] * M[0] * M[1] * M[1] - D * D) * 0.25;
          Z = (E + E) / (M[0] + M[1] + M[2]) + -1.940035480806554e13;
          // since we have floating point numbers, result may not be exactly 0.
          if ( Z < 0.00001 && Z > -0.00001 ) {
            H = M[0] * M[1] * M[2] / (E * 4.0) + -4.777053952827391e13;
            if ( H < 0.00001 && H > -0.00001 )
              puts("Congratz, input is your flag");
          }
          return 0;
        }
      }
    }
    return -1;
  }
  return result;
}
```

Program takes a flag as input. The flag must consists of **3** parts separated by
dashes (`-`). Each part should be **12** characters and contain hex numbers only.
For example:
```
  flag{391BC2164F0A-123456789012-34567890abcd}
```

Let `A`, `B` and `C` be these **3** parts. The first part (i.e., element) should be `391BC2164F0A`:
```c
  if ( !elt_id && hash != 0x391BC2164F0ALL )
```

Then we have the following checks:
```c
  if ( M[1] <= M[0] || M[2] <= M[1] || M[0] + M[1] <= M[2] )
  // if B <= A || C <= B || A + B <= C then abort

  D = M[1] * M[1] + M[0] * M[0] - M[2] * M[2];
  // D = B^2 + A^2 - C^2

  E = sqrt(4.0 * M[0] * M[0] * M[1] * M[1] - D * D) * 0.25;
  // E = sqrt(4*A^2*B^2 - D^2) / 4

  Z = (E + E) / (M[0] + M[1] + M[2]) + -1.940035480806554e13;
  if ( Z < 0.00001 && Z > -0.00001 )
  // Z = 2*E / (A + B + C) == 1.940035480806554e13

  H = M[0] * M[1] * M[2] / (E * 4.0) + -4.777053952827391e13;
  if ( H < 0.00001 && H > -0.00001 )
  // H = A*B*C / 4*E == 4.777053952827391e13
```

That is, we have to find the values `B` and `C` such that:
```
A < B
B < C
A + B > C

D = B^2 + A^2 - C^2
E = sqrt(4*A^2*B^2 - D^2) / 4

Z = 2*E / (A + B + C) == 1.940035480806554e13
A*B*C / 4*E == 4.777053952827391e13
```

It is clear that we have to solve a math problem here. The first **3** inequalities are the
[Triangle Inequality](https://en.wikipedia.org/wiki/Triangle_inequality), so the other
equations have to do something with triangles. After some searching we find out that these
equations correspond to the **inradius** and **circumradius** of a triangle
(see [here](https://www.cuemath.com/measurement/area-of-triangle-with-3-sides/) for more details).
That is, we need to find the the lengths of the **2** sides of a triangle (the third side
has to be `391BC2164F0A`) such that the **inradius is `1940035480806554`** and the
**circumradius is `477705395282739`**.


I initially tried to use `z3` but it failed due to the precision errors. Thus I had to follow
the mathematical approach and solve the equations:
```
From the law of sines:
  A / sinA = 2*circumradius = 2*C1 => sinA = 2*C1 / A     (1)

From the law of cosines:
  cosA = (B^2 + C^2 - A^2) / 2BC  (2)

Substitute (2) in the following equation:
  4*C0*C1*cosA/A + 4*C0*C1/A => (2)
  4*C0*C1*(B^2 + C^2 - A^2)/2ABC + 4*C0*C1/A => (substitute Z & H)
  4*2E/(A + B + C)*ABC/4E*(B^2 + C^2 - A^2)/2ABC + 4*2E/(A + B + C)*ABC/4E/A => (drop E)
  2*ABC/(A + B + C)*(B^2 + C^2 - A^2)/2ABC + 2*ABC/(A + B + C)/A =>
  (B^2 + C^2 - A^2)/(A + B + C) + 2ABC/(A + B + C)/A => (mul 2nd fraction with 2BC)
  (B^2 + C^2 - A^2)/(A + B + C) + 2ABC*2BC/(A + B + C)/A*2BC =>
  (B^2 + C^2 - A^2)/(A + B + C) + 2BC/(A + B + C) =>
  (B^2 + C^2 - A^2 + 2BC)/(A + B + C) =>
  (B^2 + C^2 + 2BC - A^2)/(A + B + C) =>
  ((B + C)^2 - A^2)/(A + B + C) =>
  (B + C + A)*(B + C - A)/(A + B + C) =>
   B + C - A.

That is:
  4*C0*C1*cosA/A + 4*C0*C1/A + A = Q1 = B + C  (3)

Combine (Z) and (H) equations:
  (Z): 2E / (A + B + C) = C0 => E = C0 / 2(A + B + C)
  (H): ABC / 4E = C1         => E = ABC / 4C1

  C0 / 2(A + B + C) = ABC / 4C1 =>
  ABC = 2*C0*C1(A + B + C) =>
  BC = 2*C0*C1(A + B + C)/A =>
  BC = 2*C0*C1(A + Q1)/A = Q2.    (4)

We know B + C, so we need to compute C - B:
  C - B =>
  sqrt((C - B)^2) =>
  sqrt(C^2 + B^2 - 2BC + 2BC - 2BC) =>
  sqrt((B + C)^2 - 4BC) =>
  sqrt(Q1^2 - 4Q2).   (5)

That is, we end up with 2 equations with 2 unknowns:
  B + C = Q1                  (6)
  C - B = sqrt(Q1^2 - 4Q2).   (7)

Where:
  Q1 = 4*C0*C1*cosA/A + 4*C0*C1/A + A
  Q2 = 2*C0*C1*(A + Q1)/A
```

We compute the values of `Q1` and `Q2` (`166325872560350.97` and `6.763283056335451e+27`
respectively) and then we use them to find the values of `B` and `C`:
```
B = 70802074077033.0 
C = 95523798483317.97
```

However, we are not done yet. We need to convert these numbers back to hex format.
This is not very simple due to the
[punpckldq](https://www.officedaytime.com/simd512e/simdimg/unpack.php?f=punpckldq)
instruction. The following assembly code converts a **12** hex digit number into a floating point:
```Assembly
    movq        xmm0, rax
    punpckldq   xmm0, xmmword ptr [rip+0x210]
    subpd       xmm0, xmmword ptr [rip+0x218]
    pshufd      xmm1, xmm0, 4Eh
    addpd       xmm1, xmm0
    movlpd      qword ptr [rsp+r14*8+0x20], xmm1
```

We apply the inverse operation and we isolate the **12** least significant digits from `xmm2`:
```Assembly
    movq        xmm1, rax
    movlhps     xmm2, xmm1
    por         xmm2, xmm1
    nop 
    addpd       xmm0, xmmword ptr [rip+0x218]
    addpd       xmm2, xmm0
```

We set `rax` to the floating point value and we emulate the above code (using unicorn) to get the
desired hex values:
```
B = 70802074077033.0   ~> 4064e4798769
C = 95523798483317.97  ~> 56e0de138176
```

So, the flag is: `flag{391bc2164f0a-4064e4798769-56e0de138176}`

We try it out:
```
ispo@ispo-glaptop2:~/ctf/0ctf_2019/elements$ ./Elements 
flag{391bc2164f0a-4064e4798769-56e0de138176}
Congratz, input is your flag
```

For more details, please refer to the [elements_crack.py](./elements_crack.py) script.

___
