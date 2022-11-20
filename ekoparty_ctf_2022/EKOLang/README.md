## EKO Party CTF 2022 - EKOLang (RE 476)
##### 02/11 - 04/11/2022 (50hr)

___

### Solution


Let's focus on the most important parts of `main`:
```c
void __fastcall u_main() {
  /* ... */ 
  u_get_argv_list(argv);
  v0 = _mm_loadu_si128((const __m128i *)argv);
  *(__m128i *)&args.field_10 = _mm_loadu_si128((const __m128i *)&argv[2]);
  *(__m128i *)&args.field_0 = v0;
  // Function returns: List with args followed by sizes:

  // [heap]:00005555555ABC60     dq offset aHomeIspoCtfEko           ; "/home/ispo/ctf/ekoparty_ctf_2022/EKOLan"...
  // [heap]:00005555555ABC68     dq 30h
  // [heap]:00005555555ABC70     dq 30h
  // [heap]:00005555555ABC78     dq offset aIspoLeet2                ; "ISPO-LEET2"
  // [heap]:00005555555ABC80     dq 0Ah
  // [heap]:00005555555ABC88     dq 0Ah
  // [heap]:00005555555ABC90     dq offset aMore                     ; "MORE"
  // [heap]:00005555555ABC98     dq 4
  // [heap]:00005555555ABCA0     dq 4
  // [heap]:00005555555ABCA8     dq offset aWay                      ; "WAY"
  // [heap]:00005555555ABCB0     dq 3
  // [heap]:00005555555ABCB8     dq 3
  // [heap]:00005555555ABCC0     dq offset aMore_0                   ; "MORE"
  // [heap]:00005555555ABCC8     dq 4
  // [heap]:00005555555ABCD0     dd 4
  u_buld_args_struct((__int64)&main_args, (my_string *)&args);
  argc_ = main_args.args2;
  if ( main_args.args2 != 2 )
    goto ABORT;
  v2 = main_args.args;
  v61 = main_args.args + 1;
  argc_ = 2LL;
  if ( main_args.args[1].len2 != 10 )           // strlen: 10
    goto ABORT;
  args.field_0 = main_args.args[1].ptr;         // argv[1]
  args.field_8 = args.field_0 + 10;
  args.field_10 = 4LL;
  sub_55555555DA10((__int64)v62, (__int64)&args);// split argv[1] on '-'
  v3 = v2[1].ptr + v2[1].len2;
  args.field_0 = v2[1].ptr;
  args.field_8 = v3;
  *(__m128i *)&args.field_10 = _mm_load_si128((const __m128i *)&xmmword_555555598300);
  sub_55555555DC60((__int64)&out, (__int64)&args);// get character at location
  v4 = v2[1].ptr + v2[1].len2;
  args.field_0 = v2[1].ptr;
  args.field_8 = v4;
  *(__m128i *)&args.field_10 = _mm_load_si128((const __m128i *)&xmmword_555555598310);
  sub_55555555DC60((__int64)ptr, (__int64)&args);// get string after '-' 
  if ( v60 != 1 || *(_BYTE *)out != '-' )
  {
      /* ... */ 
  }
  /* ... */ 
  pw_pt1[pw_pt1_len] = 1;
  u_REVERSE_ME(&args, pw_pt1, pw_pt1_len);
  v19 = _mm_loadu_si128((const __m128i *)&args);
  v20 = _mm_loadu_si128((const __m128i *)&args.field_10);
  v21 = _mm_loadu_si128((const __m128i *)&args.field_20);
  v49 = *(_OWORD *)&args.field_30;
  v48 = v21;
  v47 = v20;
  v46 = v19;
  u_custom_encrypt(&args, (my_struc *)&a2, v46.m128i_i8);
  v22 = _mm_loadu_si128((const __m128i *)&args.field_40);
  v23 = _mm_loadu_si128((const __m128i *)&args.field_50);
  v24 = _mm_loadu_si128((const __m128i *)&args.field_60);
  v49 = *(_OWORD *)&args.field_70;
  v48 = v24;
  v47 = v23;
  v46 = v22;
  u_custom_encrypt(&args, (my_struc *)&a2, v46.m128i_i8);
  if ( _mm_movemask_epi8(                       // we need to pass this check
         _mm_or_si128(
           _mm_xor_si128(
             _mm_cmpeq_epi8(_mm_loadu_si128((const __m128i *)&v53), (__m128i)glo_xmmword_trg_B),
             (__m128i)-1LL),
           _mm_xor_si128(
             _mm_cmpeq_epi8(_mm_loadu_si128((const __m128i *)&v54), (__m128i)glo_xmmword_trg_A),
             (__m128i)-1LL))) )
  {
      /* ... */ 
  }

  /* ... */ 
  pw_pt1[v34] = 1;
  u_REVERSE_ME(&args, pw_pt1, v34);
  v35 = _mm_loadu_si128((const __m128i *)&args);
  v36 = _mm_loadu_si128((const __m128i *)&args.field_10);
  v37 = _mm_loadu_si128((const __m128i *)&args.field_20);
  v49 = *(_OWORD *)&args.field_30;
  v48 = v37;
  v47 = v36;
  v46 = v35;
  u_custom_encrypt(&args, (my_struc *)&a2, v46.m128i_i8);
  v38 = _mm_loadu_si128((const __m128i *)&args.field_40);
  v39 = _mm_loadu_si128((const __m128i *)&args.field_50);
  v40 = _mm_loadu_si128((const __m128i *)&args.field_60);
  v49 = *(_OWORD *)&args.field_70;
  v48 = v40;
  v47 = v39;
  v46 = v38;
  u_custom_encrypt(&args, (my_struc *)&a2, v46.m128i_i8);
  v41 = _mm_loadu_si128((const __m128i *)&v52);
  v42 = _mm_loadu_si128((const __m128i *)&v53);
  v46 = _mm_loadu_si128((const __m128i *)&v51);
  v47 = v41;
  v48 = v42;
  v49 = v54;
  ii = 1LL;
  while ( ii != 65 )
  {
    if ( (glo_target_ciphertext[2 * ii - 2] ^ glo_target_ciphertext[2 * ii - 1]) == *(&v45 + ii) )
    {
      end = (glo_target_ciphertext[2 * ii] ^ glo_target_ciphertext[2 * ii + 1]) == v46.m128i_i8[ii];
      ii += 2LL;
      if ( end )
        continue;
    }
    goto END_AS_WELL;
  }
  /* ... */ 
```

Program takes as input a password in `argv[1]`. Password needs to be **10** characters long
and the **5**-th character needs to be `-`. Then it splits password into **2** parts.
It first uses `u_custom_encrypt` and `u_REVERSE_ME` (which is also invokes `u_custom_encrypt`)
to encrypt the first **4** characters. Program invokes `u_custom_encrypt` **3** times we have
a triple encryption. Ciphertext comes in **64** byte blocks. After the encryption of the first
part, program compares the last **32** bytes of the ciphertext with the values of 
`glo_xmmword_trg_A` and `glo_xmmword_trg_B`:
```
    glo_xmmword_trg_A = E7734458252B79BA2F91F29AB99CA1D9h
    glo_xmmword_trg_B = 3C426553CC2088BF4E1FE5E8CAC6CD79h
```

After that, it does the same for the second part of the password (after the dash) which is **5**
characters long. The only differences are:

* The seed value byte is `0x28` instead of `0x20`
* The initial output is full of `0`s instead of `1`s. The ciphertext is XORed with it.


### Reversing Custom Encryption

After some polishing in the decompiled code, we can understand what the encryption
works (`glo_tbl_*` variables are global tables with **256** QWORD constants):

```c
void __fastcall u_custom_encrypt(my_struc *a1_out, my_struc *a2, char *a3_inp) {
  /* ... */
  *k_A = _mm_xor_ps(*&a2->field_0, *&a1_out[1].field_0);
  *k_B = _mm_xor_ps(*&a2->field_10, *&a1_out[1].field_10);
  *k_C = _mm_xor_ps(*&a2->field_20, *&a1_out[1].field_20);
  *k_D = _mm_xor_ps(*&a2->field_30, *&a1_out[1].field_30);
  first_B = glo_tbl_A[k_D[8] + 0x700] ^ glo_tbl_A[k_D[0] + 0x600] ^ glo_tbl_A[k_C[8] + 0x500] ^ glo_tbl_A[k_C[0] + 0x400] ^ glo_tbl_A[k_B[8] + 0x300] ^ glo_tbl_A[k_B[0] + 0x200] ^ glo_tbl_A[k_A[0]] ^ glo_tbl_A[k_A[8] + 0x100];
  v5 = glo_tbl_A[k_D[11] + 0x700] ^ glo_tbl_A[k_D[3] + 0x600] ^ glo_tbl_A[k_C[11] + 0x500] ^ glo_tbl_A[k_C[3] + 0x400] ^ glo_tbl_A[k_B[11] + 0x300] ^ glo_tbl_A[k_B[3] + 0x200] ^ glo_tbl_A[k_A[11] + 0x100] ^ glo_tbl_A[k_A[3]];
  v6 = glo_tbl_A[k_D[12] + 0x700] ^ glo_tbl_A[k_D[4] + 0x600] ^ glo_tbl_A[k_C[12] + 0x500] ^ glo_tbl_A[k_C[4] + 0x400] ^ glo_tbl_A[k_B[12] + 0x300] ^ glo_tbl_A[k_B[4] + 0x200] ^ glo_tbl_A[k_A[12] + 0x100] ^ glo_tbl_A[k_A[4]];
  v7 = glo_tbl_A[k_D[13] + 0x700] ^ glo_tbl_A[k_D[5] + 0x600] ^ glo_tbl_A[k_C[13] + 0x500] ^ glo_tbl_A[k_C[5] + 0x400] ^ glo_tbl_A[k_B[13] + 0x300] ^ glo_tbl_A[k_B[5] + 0x200] ^ glo_tbl_A[k_A[13] + 0x100] ^ glo_tbl_A[k_A[5]];
  *large_val_A = *a3_inp;
  *&large_val_A[16] = *(a3_inp + 1);
  *&large_val_A[32] = *(a3_inp + 2);
  *&large_val_A[48] = *(a3_inp + 3);
  v8 = glo_tbl_A[k_D[14] + 1792] ^ glo_tbl_A[k_D[6] + 1536] ^ glo_tbl_A[k_C[14] + 1280] ^ glo_tbl_A[k_C[6] + 1024] ^ glo_tbl_A[k_B[14] + 768] ^ glo_tbl_A[k_B[6] + 512] ^ glo_tbl_A[k_A[14] + 256] ^ glo_tbl_A[k_A[6]];
  v9 = glo_tbl_A[k_D[15] + 1792] ^ glo_tbl_A[k_D[7] + 1536] ^ glo_tbl_A[k_C[15] + 1280] ^ glo_tbl_A[k_C[7] + 1024] ^ glo_tbl_A[k_B[15] + 768] ^ glo_tbl_A[k_B[7] + 512] ^ glo_tbl_A[k_A[15] + 256] ^ glo_tbl_A[k_A[7]];
  *large_val_B = first_B;
  *&large_val_B[8] = glo_tbl_A[k_D[9] + 1792] ^ glo_tbl_A[k_D[1] + 1536] ^ glo_tbl_A[k_C[9] + 1280] ^ glo_tbl_A[k_C[1] + 1024] ^ glo_tbl_A[k_B[9] + 768] ^ glo_tbl_A[k_B[1] + 512] ^ glo_tbl_A[k_A[1]] ^ glo_tbl_A[k_A[9] + 256];
  *&large_val_B[16] = glo_tbl_A[k_D[10] + 1792] ^ glo_tbl_A[k_D[2] + 1536] ^ glo_tbl_A[k_C[10] + 1280] ^ glo_tbl_A[k_C[2] + 1024] ^ glo_tbl_A[k_B[10] + 768] ^ glo_tbl_A[k_B[2] + 512] ^ glo_tbl_A[k_A[10] + 256] ^ glo_tbl_A[k_A[2]];
  *&large_val_B[24] = v5;
  *&large_val_B[32] = v6;
  *&large_val_B[40] = v7;
  *&large_val_B[48] = v8;
  *&large_val_B[56] = v9;
  new_ii = 0x30LL;
  do                                            // originally nxt is inp
  {
    ii = new_ii;
    *v11 = _mm_xor_ps(*&large_val_A[1], *&large_val_B[1]);
    *v12 = _mm_xor_ps(*&large_val_A[17], *&large_val_B[17]);
    *v13 = _mm_xor_ps(*&large_val_A[33], *&large_val_B[33]);
    *&large_val_A[49] ^= *&large_val_B[49];
    *&large_val_A[57] ^= *&large_val_B[57];
    *&large_val_A[61] ^= *&large_val_B[61];
    first_A = glo_tbl_A[large_val_A[56] + 0x700] ^ glo_tbl_A[v13[15] + 0x600] ^ glo_tbl_A[v13[7] + 0x500] ^ glo_tbl_A[v12[15] + 1024] ^ glo_tbl_A[v12[7] + 768] ^ glo_tbl_A[v11[15] + 512] ^ glo_tbl_A[(first_B ^ large_val_A[0])] ^ glo_tbl_A[v11[7] + 256];
    v38 = glo_tbl_A[large_val_A[57] + 0x700] ^ glo_tbl_A[large_val_A[49] + 0x600] ^ glo_tbl_A[v13[8] + 0x500] ^ glo_tbl_A[v13[0] + 1024] ^ glo_tbl_A[v12[8] + 768] ^ glo_tbl_A[v12[0] + 512] ^ glo_tbl_A[v11[0]] ^ glo_tbl_A[v11[8] + 256];
    v37 = glo_tbl_A[large_val_A[58] + 0x700] ^ glo_tbl_A[large_val_A[50] + 0x600] ^ glo_tbl_A[v13[9] + 0x500] ^ glo_tbl_A[v13[1] + 1024] ^ glo_tbl_A[v12[9] + 768] ^ glo_tbl_A[v12[1] + 512] ^ glo_tbl_A[v11[9] + 256] ^ glo_tbl_A[v11[1]];
    v14 = glo_tbl_A[large_val_A[59] + 0x700] ^ glo_tbl_A[large_val_A[51] + 0x600] ^ glo_tbl_A[v13[10] + 0x500] ^ glo_tbl_A[v13[2] + 1024] ^ glo_tbl_A[v12[10] + 768] ^ glo_tbl_A[v12[2] + 512] ^ glo_tbl_A[v11[10] + 256] ^ glo_tbl_A[v11[2]];
    v15 = glo_tbl_A[large_val_A[60] + 0x700] ^ glo_tbl_A[large_val_A[52] + 0x600] ^ glo_tbl_A[v13[11] + 0x500] ^ glo_tbl_A[v13[3] + 1024] ^ glo_tbl_A[v12[11] + 768] ^ glo_tbl_A[v12[3] + 512] ^ glo_tbl_A[v11[11] + 256] ^ glo_tbl_A[v11[3]];
    v16 = glo_tbl_A[large_val_A[61] + 0x700] ^ glo_tbl_A[large_val_A[53] + 0x600] ^ glo_tbl_A[v13[12] + 0x500] ^ glo_tbl_A[v13[4] + 1024] ^ glo_tbl_A[v12[12] + 768] ^ glo_tbl_A[v12[4] + 512] ^ glo_tbl_A[v11[12] + 256] ^ glo_tbl_A[v11[4]];
    v17 = glo_tbl_A[large_val_A[62] + 0x700] ^ glo_tbl_A[large_val_A[54] + 0x600] ^ glo_tbl_A[v13[13] + 0x500] ^ glo_tbl_A[v13[5] + 1024] ^ glo_tbl_A[v12[13] + 768] ^ glo_tbl_A[v12[5] + 512] ^ glo_tbl_A[v11[13] + 256] ^ glo_tbl_A[v11[5]];
    v18 = glo_tbl_A[(large_val_B[63] ^ large_val_A[63]) + 0x700] ^ glo_tbl_A[large_val_A[55] + 0x600] ^ glo_tbl_A[v13[14] + 1280] ^ glo_tbl_A[v13[6] + 1024] ^ glo_tbl_A[v12[14] + 768] ^ glo_tbl_A[v12[6] + 512] ^ glo_tbl_A[v11[14] + 256] ^ glo_tbl_A[v11[6]];
    *large_val_B = _mm_xor_ps(*(&glo_tbl_I[-6] + new_ii), *large_val_B);
    *&large_val_B[16] = _mm_xor_ps(*(&glo_tbl_I[-4] + new_ii), *&large_val_B[16]);
    *v19 = _mm_xor_ps(*(&glo_tbl_I[-2] + new_ii), *&large_val_B[32]);
    *v20 = _mm_xor_ps(*(glo_tbl_I + new_ii), *&large_val_B[48]);
    first_B = glo_tbl_A[v20[8] + 1792] ^ glo_tbl_A[v20[0] + 1536] ^ glo_tbl_A[v19[8] + 1280] ^ glo_tbl_A[v19[0] + 1024] ^ glo_tbl_A[large_val_B[24] + 768] ^ glo_tbl_A[large_val_B[16] + 512] ^ glo_tbl_A[large_val_B[0]] ^ glo_tbl_A[large_val_B[8] + 256];
    v21 = glo_tbl_A[v20[9] + 1792] ^ glo_tbl_A[v20[1] + 1536] ^ glo_tbl_A[v19[9] + 1280] ^ glo_tbl_A[v19[1] + 1024] ^ glo_tbl_A[large_val_B[25] + 768] ^ glo_tbl_A[large_val_B[17] + 512] ^ glo_tbl_A[large_val_B[1]] ^ glo_tbl_A[large_val_B[9] + 256];
    v22 = glo_tbl_A[v20[10] + 1792] ^ glo_tbl_A[v20[2] + 1536] ^ glo_tbl_A[v19[10] + 1280] ^ glo_tbl_A[v19[2] + 1024] ^ glo_tbl_A[large_val_B[26] + 768] ^ glo_tbl_A[large_val_B[18] + 512] ^ glo_tbl_A[large_val_B[2]] ^ glo_tbl_A[large_val_B[10] + 256];
    v23 = glo_tbl_A[v20[11] + 1792] ^ glo_tbl_A[v20[3] + 1536] ^ glo_tbl_A[v19[11] + 1280] ^ glo_tbl_A[v19[3] + 1024] ^ glo_tbl_A[large_val_B[27] + 768] ^ glo_tbl_A[large_val_B[19] + 512] ^ glo_tbl_A[large_val_B[3]] ^ glo_tbl_A[large_val_B[11] + 256];
    v24 = glo_tbl_A[v20[12] + 1792] ^ glo_tbl_A[v20[4] + 1536] ^ glo_tbl_A[v19[12] + 1280] ^ glo_tbl_A[v19[4] + 1024] ^ glo_tbl_A[large_val_B[28] + 768] ^ glo_tbl_A[large_val_B[20] + 512] ^ glo_tbl_A[large_val_B[12] + 256] ^ glo_tbl_A[large_val_B[4]];
    v25 = glo_tbl_A[v20[13] + 1792] ^ glo_tbl_A[v20[5] + 1536] ^ glo_tbl_A[v19[13] + 1280] ^ glo_tbl_A[v19[5] + 1024] ^ glo_tbl_A[large_val_B[29] + 768] ^ glo_tbl_A[large_val_B[21] + 512] ^ glo_tbl_A[large_val_B[13] + 256] ^ glo_tbl_A[large_val_B[5]];
    *large_val_A = first_A;
    *&large_val_A[8] = v38;
    *&large_val_A[16] = v37;
    *&large_val_A[24] = v14;
    *&large_val_A[32] = v15;
    *&large_val_A[40] = v16;
    *&large_val_A[48] = v17;
    *&large_val_A[56] = v18;
    v26 = glo_tbl_A[v20[14] + 1792] ^ glo_tbl_A[v20[6] + 1536] ^ glo_tbl_A[v19[14] + 1280] ^ glo_tbl_A[v19[6] + 1024] ^ glo_tbl_A[large_val_B[30] + 768] ^ glo_tbl_A[large_val_B[22] + 512] ^ glo_tbl_A[large_val_B[14] + 256] ^ glo_tbl_A[large_val_B[6]];
    v27 = glo_tbl_A[v20[15] + 1792] ^ glo_tbl_A[v20[7] + 1536] ^ glo_tbl_A[v19[15] + 1280] ^ glo_tbl_A[v19[7] + 1024] ^ glo_tbl_A[large_val_B[31] + 768] ^ glo_tbl_A[large_val_B[23] + 512] ^ glo_tbl_A[large_val_B[15] + 256] ^ glo_tbl_A[large_val_B[7]];
    *large_val_B = first_B;
    *&large_val_B[8] = v21;
    *&large_val_B[16] = v22;
    *&large_val_B[24] = v23;
    *&large_val_B[32] = v24;
    *&large_val_B[40] = v25;
    *&large_val_B[48] = v26;
    *&large_val_B[56] = v27;
    new_ii = ii + 0x40;
  }
  while ( ii != 0x2F0 );                        // generate keystream
  LOBYTE(a1_out[1].field_0) ^= *a3_inp ^ first_A ^ first_B;
  v28 = *(&a1_out[1].field_10 + 1);
  v29 = *(&a1_out[1].field_20 + 1);
  *(&a1_out[1].field_0 + 1) = _mm_xor_ps(
                                _mm_xor_ps(*(&a1_out[1].field_0 + 1), *(a3_inp + 1)),
                                _mm_xor_ps(*&large_val_A[1], *&large_val_B[1]));
  *(&a1_out[1].field_10 + 1) = _mm_xor_ps(
                                 _mm_xor_ps(*(a3_inp + 17), v28),
                                 _mm_xor_ps(*&large_val_A[17], *&large_val_B[17]));
  *(&a1_out[1].field_20 + 1) = _mm_xor_ps(
                                 _mm_xor_ps(*(a3_inp + 33), v29),
                                 _mm_xor_ps(*&large_val_A[33], *&large_val_B[33]));
  *(&a1_out[1].field_30 + 1) ^= *(a3_inp + 0x31) ^ *&large_val_A[49] ^ *&large_val_B[49];
  *(&a1_out[1].field_38 + 1) ^= *(a3_inp + 0x39) ^ (v18 >> 8) ^ (v27 >> 8);
  *(&a1_out[1].field_38 + 5) ^= *(a3_inp + 0x3D) ^ (HIDWORD(v18) >> 8) ^ (HIDWORD(v27) >> 8);
  HIBYTE(a1_out[1].field_38) ^= a3_inp[63] ^ HIBYTE(v18) ^ HIBYTE(v27);
}
```

The seed here is split into bytes, each byte is used as an index to get different constants
from the constant tables and the result is XORed again and again. This generates two **64**
byte keystreams which are used to XOR the input with the existing output. That is:
```
  output = output ^ input ^ keystream_A ^ keystream_B
```


### Cracking the Code

Cracking the code is straightforward as we can bruteforce the password (first part is only
**4** characters and second part is only **5** characters). After bruteforcing we find
the correct password which is `easy-peasy`. We try it and it works:
```
ispo@ispo-glaptop2:~/ctf/ekoparty_ctf_2022/EKOLang$ ./ekolang easy-peasy
Flag: EKO{easy-peasy}
```

For more details, please refer to the [ekolang_crack.py](./ekolang_crack.py) file.

So, the flag is: `EKO{easy-peasy}`

___
