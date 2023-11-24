## SEECON quals 2023 - xuyao (RE 176)
#### 16/09 - 17/09/2023 (24 hrs)

### Description

*X86-64 Unbreakable Yet Another Obfuscation*

```
xuyao.tar.gz 16233233cbca9895ab3573e781c62c402b13a0d9
```
___

### Solution

This challenge accesses memory through a weird data struct:
```
00000000 struc_1         struc ; (sizeof=0x10, mappedto_8)
00000000 ptr             dq ?                    ; XREF: encrypt_block+5B/w
00000008 idx             dd ?                    ; XREF: encrypt_block+60/w
0000000C len             dd ?                    ; XREF: encrypt_block+68/w
00000010 struc_1         ends
```

That is to access a memory address it uses instructions like `ptr->ptr[ptr->idx]`.
Furthermore, some functions like `kls` take as input the whole structure: `ptr`
goes into `rdi` and `len << 32 | idx` goes into `rsi`.
Based on that, we clean up the decompiled code so it makes sense:

```c
int __fastcall main(int argc, const char **argv, const char **envp) {
  /* ... */
  canary = __readfsqword(0x28u);
  buf = mmap(0LL, 0x1000uLL, 3, 34, -1, 0LL);
  if ( buf == -1LL )
    exit(1);
  buf_ = buf;
  ptr = arr_inp;
  ptr_ = arr_inp;
  for ( i = 0; i != 112; ++i )                  // fill in array
  {
    ptr_->ptr = buf_;
    ptr_->idx = i;
    ptr_->len = 1;
    ++ptr_;
  }
  ptr2 = arr_out;
  ptr2_ = arr_out;
  do
  {
    ptr2_->ptr = buf_;
    ptr2_->idx = i;
    ptr2_->len = 1;
    ++i;
    ++ptr2_;
  }
  while ( i != 224 );
  __printf_chk(1LL, "Message: ", ptr2_);
  if ( !fgets(flag, 100, _bss_start) )
    exit(1);
  buf_->len = 0;
  flag_char = flag[0];
  if ( flag[0] )
  {
    nxt_flag = &flag[1];
    do                                          // copy flag to mmap buf using this struct
    {
      size = ptr->len;
      switch ( size )
      {
        case 1:
          ptr->ptr[ptr->idx] = flag_char;
          break;
        case 2:
          *&ptr->ptr[ptr->idx] = flag_char;
          break;
        case 4:
          *&ptr->ptr[ptr->idx] = flag_char;
          break;
        case 8:
          *&ptr->ptr[ptr->idx] = flag_char;
          break;
        default:
          BUG();
      }
      ++buf_->len;
      flag_char = *nxt_flag;
      ++ptr;
      ++nxt_flag;
    }
    while ( flag_char );
  }
  flag_len = buf_->len;
  flag_len_roundup = (flag_len + 16) & 0xFFFFFFF0;
  buf_->len_roundup = flag_len_roundup;
  buf_->pad_len = flag_len_roundup - flag_len;
  buf_->pad_len_byte = flag_len_roundup - flag_len;
  // pad flag to be multiple of 16
  // append remaining len bytes: ISPOLEETMORE\n\x03\x03\x03
  for ( j = flag_len; j < buf_->len_roundup; buf_->len = j )
  {
    if ( arr_inp[j].len != 1 )
      BUG();
    arr_inp[j].ptr[arr_inp[j].idx] = buf_->pad_len_byte;
    j = buf_->len + 1;
  }
  encrypt(arr_inp, buf_->flag, 0x4000000E4uLL, "SECCON CTF 2023!", arr_out);
  enc = ::enc;
  do                                            // compare
  {
    len = ptr2->len;
    if ( len == 1 )
    {
      if ( ptr2->ptr[ptr2->idx] != *enc )
        goto BADBOY;
    }
    else
    {
      switch ( len )
      {
        case 2:
          v18 = *&ptr2->ptr[ptr2->idx] != *enc;
          break;
        case 4:
          v18 = *&ptr2->ptr[ptr2->idx] != *enc;
          break;
        case 8:
          v18 = *&ptr2->ptr[ptr2->idx] != *enc;
          break;
        default:
          BUG();
      }
      if ( v18 )
      {
BADBOY:
        puts("Wrong...");
        goto TEARDOWN;
      }
    }
    ++ptr2;
    ++enc;
  }
  while ( ptr2 != flag );
  puts("Correct! I think you got the flag now :)");
TEARDOWN:
  munmap(buf_, 0x1000uLL);
  return 0;
}
```

```c
void __fastcall encrypt(struc_1 **a1_in, char *a2_flag, unsigned __int64 a3_wat, char *a4_key, struc_1 **a5_out) {
  /* ... */
  *&wat_hi = HIDWORD(a3_wat);
  wat_lo = a3_wat;
  buf = mmap(0LL, 0x1000uLL, 3, 34, -1, 0LL);
  if ( buf == -1LL )
    exit(1);
  buf_ = buf;
  arr[0].ptr = buf;
  arr[0].idx = 12;
  arr[0].len = 4;
  arr[1].ptr = buf;
  arr[1].idx = 16;
  arr[1].len = 4;
  arr[2].ptr = buf;
  arr[2].idx = 20;
  arr[2].len = 4;
  arr[3].ptr = buf;
  arr[3].idx = 24;
  arr[3].len = 4;
  arr[4].ptr = buf;
  arr[4].idx = 28;
  arr[4].len = 4;
  arr[5].ptr = buf;
  arr[5].idx = 32;
  arr[5].len = 4;
  arr[6].ptr = buf;
  arr[6].idx = 36;
  arr[6].len = 4;
  arr[7].ptr = buf;
  arr[7].idx = 40;
  arr[7].len = 4;
  from_arr8 = &arr[8];
  ptr = &arr[8];
  for ( i = 52; i != 68; i += 4 )               // init objects
  {
    ptr->ptr = buf_;
    ptr->idx = i;
    ptr->len = 4;
    ++ptr;
  }
  from_12 = &arr[12];
  ptr2 = &arr[12];
  do
  {
    ptr2->ptr = buf_;
    ptr2->idx = i;
    ptr2->len = 4;
    i += 4;
    ++ptr2;
  }
  while ( i != 196 );
  // Offset 0x34 (52) has 4 DWORDs: key ^ fish (big endian)
  // Entries: 8, 9, 10, 11

  // arr[8] = fish[0] ^ bigendian(key[0])
  // ....
  // arr[11] = fish[3] ^ bigendian(key[3])
  for ( j = 0LL; j != 4; ++j )                  // key xor
  {
    v14 = fish[j] ^ _byteswap_ulong(*&a4_key[j * 4]);
    buf_->tmp = v14;
    if ( from_arr8->len != 4 )
      BUG();
    *&from_arr8->ptr[from_arr8->idx] = v14;
    ++from_arr8;
  }
  cat = ::cat;
  do
  {
    if ( arr[9].len != 4 )
      BUG();
    word9 = &arr[9].ptr[arr[9].idx];
    word9_p = *word9;
    buf_->tmp = *word9;
    if ( arr[10].len != 4 )
      BUG();
    word10 = &arr[10].ptr[arr[10].idx];
    xor9_10 = *word10 ^ word9_p;
    buf_->tmp = xor9_10;
    if ( arr[11].len != 4 )
      BUG();
    word11 = &arr[11].ptr[arr[11].idx];
    buf_->tmp = *cat ^ *word11 ^ xor9_10;       // tmp = arr[9] ^ arr[10] ^ arr[11] ^ cat[j]
    // This actually passes a 16 byte struc_1 into 2 params
    ks(buf_, 0x40000002CLL, buf_, 0x400000030uLL);
    if ( arr[8].len != 4 )
      BUG();
    word8 = &arr[8].ptr[arr[8].idx];
    nxt = buf_->accumulator ^ *word8;           // acc ^= arr[8]
    buf_->tmp = nxt;
    if ( from_12->len != 4 )
      BUG();
    *&from_12->ptr[from_12->idx] = nxt;         // arr[12] = acc ^ arr[8]
    *word8 = *word9;                            // arr[8] = arr[9]
    *word9 = *word10;                           // arr[9] = arr[10]
    *word10 = *word11;                          // arr[10] = arr[11]
    *word11 = buf_->tmp;                        // arr[11] = acc ^ arr[8]
    ++from_12;
    ++cat;
  }
  while ( from_12 != &arr_end );
  buf_->idx_16 = 0;
  if ( wat_hi != 4 )
    BUG();
  v23 = a1_in - 8;
  while ( 1 )
  {
    idx16 = buf_->idx_16;
    if ( idx16 >= *&a2_flag[wat_lo] )
      break;
    arr_ = arr;
    idx32 = 2LL * idx16;
    flag_ = &v23[idx32];                        // start from offset 0x1C
    // copy flag to offst 0x1C = arr[4]
    do                                          // get next 16 characters from flag
    {
      buf_->j = 0;
      flag__ = flag_;
      flag_ += 4;
      flag = flag_;
      do                                        // get a big endian DWORD from flag
      {
        if ( flag[3].len != 1 )
          BUG();
        flag_ch = flag[3].ptr[flag[3].idx];
        *buf_->nxt_flag_dword = flag_ch;
        flag_dword = flag_ch | (buf_->j << 8);
        buf_->j = flag_dword;
        --flag;
      }
      while ( flag__ != flag );
      if ( arr_->len != 4 )
        BUG();
      *&arr_->ptr[arr_->idx] = flag_dword;
      ++arr_;
    }
    while ( &arr[4] != arr_ );
    encr_blk = &arr[4];
    // arg1: flag (copied to arr)
    // arg2: arr[12]
    // arg3: 0 (OUT)
    encrypt_block(arr, &arr[12], &arr[4]);
    v33 = &a5_out[idx32 + 8];
    do                                          // copy encrypted block
    {
      if ( encr_blk->len != 4 )
        BUG();
      buf_->j = *&encr_blk->ptr[encr_blk->idx];
      v34 = v33 - 4;
      do
      {
        v35 = buf_->j;
        *buf_->nxt_flag_dword = buf_->j;
        if ( v34->len != 1 )
          BUG();
        v34->ptr[v34->idx] = v35;               // encrypted flag goes here
        buf_->j = buf_->j >> 8;
        ++v34;
      }
      while ( v33 != v34 );
      ++encr_blk;
      v33 += 4;
    }
    while ( &arr[8] != encr_blk );
    buf_->idx_16 += 16;
  }
  munmap(buf_, 0x1000uLL);
}
```

```c
int __fastcall ks(__int64 a1, __int64 a2, __int64 a3, unsigned __int64 a4) {
  buf = mmap(0LL, 0x1000uLL, 3, 34, -1, 0LL);
  if ( buf == -1LL )
    exit(1);
  buf_ = buf;
  tnls(a1, a2, buf, 0x400000000uLL);
  kls(buf_, 0x400000000LL, a3, a4);
  return munmap(buf_, 0x1000uLL);
}
```

```c
// Apply sbox to each byte of the DWORD
int __fastcall tnls(struc_1 *a1, __int64 a2, struc_1 *a3, unsigned __int64 a4) {
  /* ... */
  v6 = a4;
  v13 = a4;
  size = HIDWORD(a4);
  buf = mmap(0LL, 0x1000uLL, 3, 34, -1, 0LL);
  if ( buf == -1LL )
    exit(1);
  buf_ = buf;
  switch ( size )                               // init
  {
    case 1:
      *(&a3->ptr + v6) = 0;
      break;
    case 2:
      *(&a3->ptr + v6) = 0;
      break;
    case 4:
      *(&a3->ptr + v6) = 0;
      break;
    case 8:
      *(&a3->ptr + v6) = 0LL;
      break;
    default:
      BUG();
  }
  for ( i = 0; i != 32; i += 8 )
  {
    if ( HIDWORD(a2) != 4 )
      BUG();
    v11 = sbox[(*(&a1->ptr + a2) >> i)] << i;
    *(buf_ + 1) = v11;
    if ( size != 4 )
      BUG();
    *(&a3->ptr + v13) |= v11;
  }
  return munmap(buf_, 0x1000uLL);
}
```

```c
int __fastcall kls(struc_1 *a1, __int64 a2, struc_1 *a3, unsigned __int64 a4) {
  /* ... */
  idx = a4;
  len = HIDWORD(a4);
  buf = mmap(0LL, 0x1000uLL, 3, 34, -1, 0LL);
  if ( buf == -1LL )
    exit(1);
  buf_ = buf;
  if ( HIDWORD(a2) != len )
    BUG();
  if ( len == 1 )
  {
    *(&a3->ptr + idx) = *(&a1->ptr + a2);
    goto LABEL_11;
  }
  if ( len == 2 )
  {
    *(&a3->ptr + idx) = *(&a1->ptr + a2);
    goto LABEL_11;
  }
  if ( len != 4 )
  {
    if ( len != 8 )
      BUG();
    *(&a3->ptr + idx) = *(&a1->ptr + a2);
LABEL_11:
    BUG();
  }
  v_x = (a1 + a2);
  v_y = (a3 + idx);
  *v_y = *v_x;                                  // arr[7] = v_x
  x_rol_11 = __ROL4__(*v_x, 11);
  *buf_ = x_rol_11;
  *v_y ^= x_rol_11;                             // v_y = x ^ ROL(x, 11)
  x_rol_7 = __ROR4__(*v_x, 7);
  *buf_ = x_rol_7;
  *v_y ^= x_rol_7;                              // v_y = x ^ ROL(x, 11) ^ ROL(x, 7)
  return munmap(buf_, 0x1000uLL);
}
```

```c
void __fastcall encrypt_block(struc_1 *a1, __int64 *a2, __int64 a3) {
  buf = mmap(0LL, 0x1000uLL, 3, 34, -1, 0LL);
  if ( buf == -1LL )
    exit(1);
  buf_ = buf;
  arr[0].ptr = buf;
  arr[0].idx = 4;
  arr[0].len = 4;
  arr[1].ptr = buf;
  arr[1].idx = 8;
  arr[1].len = 4;
  arr[2].ptr = buf;
  arr[2].idx = 12;
  arr[2].len = 4;
  arr[3].ptr = buf;
  arr[3].idx = 16;
  arr[3].len = 4;
  arr_ = arr;
  arr__ = arr;
  // init copy flag in big endian DWORDs
  for ( i = 0; i != 4; ++i )
  {
    len = arr__->len;
    if ( len != a1->len )
      BUG();
    if ( len == 1 )
    {
      arr[i].ptr[arr[i].idx] = a1->ptr[a1->idx];
      goto ABORT;
    }
    if ( len == 2 )
    {
      *&arr[i].ptr[arr[i].idx] = *&a1->ptr[a1->idx];
      goto ABORT;
    }
    if ( len != 4 )
    {
      if ( len != 8 )
        BUG();
      *&arr[i].ptr[arr[i].idx] = *&a1->ptr[a1->idx];
ABORT:
      BUG();
    }
    *&arr__->ptr[arr__->idx] = _byteswap_ulong(*&a1->ptr[a1->idx]);
    ++arr__;
    ++a1;
  }
  nxt = a2;
  end = a2 + 64;                                // do 64 rounds
  do
  {
    r(arr, *nxt, nxt[1], buf_, 0x400000000uLL); // encrypt 1 DWORD
    v24 = arr[1].len;
    if ( arr[0].len != arr[1].len )
      BUG();
    if ( arr[0].len == 1 )
    {
      v13 = &arr[1].ptr[arr[1].idx];
      arr[0].ptr[arr[0].idx] = *v13;
      v14 = arr[2].len;
      if ( v24 == arr[2].len )
      {
        v15 = &arr[2].ptr[arr[2].idx];
        *v13 = *v15;
        if ( arr[3].len == v14 )
        {
          *v15 = arr[3].ptr[arr[3].idx];
          goto ABORT___;
        }
        goto ABORT_;
      }
      goto ABORT__;
    }
    if ( arr[0].len == 2 )
    {
      v16 = &arr[1].ptr[arr[1].idx];
      *&arr[0].ptr[arr[0].idx] = *v16;
      v17 = arr[2].len;
      if ( v24 == arr[2].len )
      {
        v18 = &arr[2].ptr[arr[2].idx];
        *v16 = *v18;
        if ( arr[3].len == v17 )
        {
          *v18 = *&arr[3].ptr[arr[3].idx];
          goto ABORT___;
        }
ABORT_:
        BUG();
      }
ABORT__:
      BUG();
    }
    if ( arr[0].len != 4 )
    {
      if ( arr[0].len != 8 )
        BUG();
      v25 = &arr[1].ptr[arr[1].idx];
      *&arr[0].ptr[arr[0].idx] = *v25;
      v26 = arr[2].len;
      if ( v24 == arr[2].len )
      {
        v27 = &arr[2].ptr[arr[2].idx];
        *v25 = *v27;
        if ( v26 == arr[3].len )
        {
          *v27 = *&arr[3].ptr[arr[3].idx];
ABORT___:
          BUG();
        }
        goto ABORT_;
      }
      goto ABORT__;
    }
    // rotate left
    arr_1 = &arr[1].ptr[arr[1].idx];
    *&arr[0].ptr[arr[0].idx] = *arr_1;
    arr2_len = arr[2].len;
    if ( v24 != arr[2].len )
      goto ABORT__;
    arr_2 = &arr[2].ptr[arr[2].idx];
    *arr_1 = *arr_2;
    arr3_len = arr[3].len;
    if ( arr[3].len != arr2_len )
      goto ABORT_;
    arr_3 = &arr[3].ptr[arr[3].idx];
    *arr_2 = *arr_3;
    if ( arr3_len != 4 )
      goto ABORT___;
    *arr_3 = *buf_;
    nxt += 2;
  }
  while ( nxt != end );                         // 64 iterations
  // copy result to arr (out) in reverse order
  a3_ = a3;
  do
  {
    v30 = a3_->len;
    if ( v30 != arr_[3].len )
      BUG();
    switch ( v30 )
    {
      case 1:
        a3_->ptr[a3_->idx] = arr_[3].ptr[arr_[3].idx];
        break;
      case 2:
        *&a3_->ptr[a3_->idx] = *&arr_[3].ptr[arr_[3].idx];
        break;
      case 4:
        *&a3_->ptr[a3_->idx] = *&arr_[3].ptr[arr_[3].idx];
        break;
      case 8:
        *&a3_->ptr[a3_->idx] = *&arr_[3].ptr[arr_[3].idx];
        break;
      default:
        BUG();
    }
    if ( a3_->len != 4 )
      BUG();
    v29 = &a3_->ptr[a3_->idx];
    *v29 = _byteswap_ulong(*v29);               // swap byte order!
    ++a3_;
    --arr_;
  }
  while ( arr_ != &arr[-4] );
  munmap(buf_, 0x1000uLL);
}
```

```c
int __fastcall r(struc_1 *a1, struc_1 *a2, __int64 a3, struc_1 *a4, unsigned __int64 a5) {
  /* ... */
  v8 = HIDWORD(a5);
  buf = mmap(0LL, 0x1000uLL, 3, 34, -1, 0LL);
  if ( buf == -1LL )
    exit(1);
  buf_ = buf;
  if ( a1[1].len != 4 )
    BUG();
  a1_1 = *&a1[1].ptr[a1[1].idx];
  *buf_ = a1_1;
  if ( a1[2].len != 4 )
    BUG();
  a1_1_xor_2 = *&a1[2].ptr[a1[2].idx] ^ a1_1;
  *buf_ = a1_1_xor_2;
  if ( a1[3].len != 4 )
    BUG();
  a1_1_xor_2_xor_3 = *&a1[3].ptr[a1[3].idx] ^ a1_1_xor_2;
  *buf_ = a1_1_xor_2_xor_3;
  if ( HIDWORD(a3) != 4 )
    BUG();
  // flag[1] ^ flag[2] ^ flag[3] ^ arr[12]
  *buf_ = *(&a2->ptr + a3) ^ a1_1_xor_2_xor_3;
  u_some_func(buf_, 0x400000000LL, a4, a5);
  if ( v8 != a1->len )
    BUG();
  switch ( v8 )
  {
    case 1:
      *(&a4->ptr + a5) ^= a1->ptr[a1->idx];
      break;
    case 2:
      *(&a4->ptr + a5) ^= *&a1->ptr[a1->idx];
      break;
    case 4:
      // arr[0] ^= some_func result
      *(&a4->ptr + a5) ^= *&a1->ptr[a1->idx];
      break;
    case 8:
      *(&a4->ptr + a5) = (*(&a4->ptr + a5) ^ *&a1->ptr[a1->idx]);
      break;
    default:
      BUG();
  }
  return munmap(buf_, 0x1000uLL);
}
```

```c
int __fastcall u_some_func(struc_1 *a1, __int64 a2, __int64 a3, unsigned __int64 a4) {
  /* ... */
  buf = mmap(0LL, 0x1000uLL, 3, 34, -1, 0LL);
  if ( buf == -1LL )
    exit(1);
  buf_ = buf;
  tnls(a1, a2, buf, 0x400000000uLL);
  els(buf_, 0x400000000LL, a3, a4);
  return munmap(buf_, 0x1000uLL);
}
```

```c
int __fastcall els(struc_1 *a1, __int64 a2, struc_1 *a3, unsigned __int64 a4) {
  /* ... */
  a4_lo = a4;
  a4_hi = HIDWORD(a4);
  buf = mmap(0LL, 0x1000uLL, 3, 34, -1, 0LL);
  if ( buf == -1LL )
    exit(1);
  buf_ = buf;
  if ( HIDWORD(a2) != a4_hi )
    BUG();
  if ( a4_hi == 1 )
  {
    *(&a3->ptr + a4_lo) = *(&a1->ptr + a2);
    goto LABEL_11;
  }
  if ( a4_hi == 2 )
  {
    *(&a3->ptr + a4_lo) = *(&a1->ptr + a2);
    goto LABEL_11;
  }
  if ( a4_hi != 4 )
  {
    if ( a4_hi != 8 )
      BUG();
    *(&a3->ptr + a4_lo) = *(&a1->ptr + a2);
LABEL_11:
    BUG();
  }
  tmp = (a1 + a2);
  key = (a3 + a4_lo);                           // actual value
  *key = *tmp;
  rol_3 = __ROL4__(*tmp, 3);
  *buf_ = rol_3;
  *key ^= rol_3;
  rol_14 = __ROL4__(*tmp, 14);
  *buf_ = rol_14;
  *key ^= rol_14;
  rol_15 = __ROL4__(*tmp, 15);
  *buf_ = rol_15;
  *key ^= rol_15;
  rol_9 = __ROL4__(*tmp, 9);
  *buf_ = rol_9;
  *key ^= rol_9;
  return munmap(buf_, 0x1000uLL);
}
```

The `fish`, `cat`, `sbox` and `enc` are global constants.

Once we have the full encryption we can run it in inverse to decrypt the 
`enc` and get the hidden message. We try it and it works:
```
ispo@ispo-glaptop2:~/ctf/seccon_quals_2023/xuyao$ ./xuyao
Message: Congratulations! You have decrypted the flag: SECCON{x86_he2_zhuan1_you3_zi4_jie2_ma3_de_hun4he2}
Correct! I think you got the flag now :)
```

For more details, please refer to the [xuyao_crack.py](./xuyao_crack.py) file.

So, the flag is: `SECCON{x86_he2_zhuan1_you3_zi4_jie2_ma3_de_hun4he2}`
___

