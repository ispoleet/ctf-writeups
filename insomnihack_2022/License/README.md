
## Insomni'Hack Teaser 2023 - Artscii (Misc 200)
##### 21/01 - 22/01/2023 (24hr)
___

### Description: 

*Can you generate a valid activation code ?*

```
license
```
___


### Solution

We start from `main`:
```c
__int64 __fastcall main(int argc, char **argv, char **argp) {
  /* ... */
  v3 = std::operator<<<std::char_traits<char>>(&std::cout, "Enter license: ");
  std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
  lic_id = (char *)malloc(0x64uLL);
  if ( !lic_id )
    exit(1);
  std::istream::getline((std::istream *)&std::cin, lic_id, 100LL);
  // check if license contains colon ':'
  pos = strchr(lic_id, ':');
  if ( pos ) {
    // license contains a ':'. Split it
    firstlen = (_DWORD)pos - (_DWORD)lic_id;
    first = (char *)malloc((int)pos - (int)lic_id);
    if ( !first )
      exit(1);
    strncpy(first, lic_id, firstlen);
    liclen = strlen(lic_id);
    second = (char *)malloc(liclen - firstlen - 1);
    liclen_ = strlen(lic_id);
    strncpy(second, &lic_id[firstlen + 1], liclen_ - firstlen - 1);
    u_myobj_ctor(&myobj, first, second);
    // verify the first part of the hash
    if ( u_sha1_hash_first_n_compare(&myobj, first, v6)
      && (v7 = std::operator<<<std::char_traits<char>>(&std::cout, "License identifier correct"),
          std::ostream::operator<<(v7, &std::endl<char,std::char_traits<char>>),
          u_verify_license(&myobj)) ) {
      v8 = std::operator<<<std::char_traits<char>>(
             &std::cout,
             "You can activate your license with the following code: ");
      v9 = std::operator<<<std::char_traits<char>>(v8, second);
      std::ostream::operator<<(v9, &std::endl<char,std::char_traits<char>>);
    } else {
      // verification successful. Generate a license for the second part
      u_string_ctor_maybe((__int64)a1, (__int64)lic_id, (__int64)lic_id);
      u_gen_usr_specific_lic_code((__int64)v21, (__int64)a1);
      std::string::operator=(v20, v21);
      std::string::~string(v21);
      v10 = std::operator<<<std::char_traits<char>>(
              &std::cout,
              "You can activate your license with the following code: ");
      v11 = std::operator<<<char>(v10, v20);
      std::ostream::operator<<(v11, &std::endl<char,std::char_traits<char>>);
      u_string_dtor((__int64)a1);
    }
  } else {
    // license doesn't contain a ':'
    u_string_ctor_maybe((__int64)&myobj, (__int64)lic_id, (__int64)lic_id);
    u_gen_usr_specific_lic_code((__int64)a1, (__int64)&myobj);
    std::string::operator=(v20, a1);
    std::string::~string(a1);
    v12 = std::operator<<<std::char_traits<char>>(&std::cout, "You can activate your license with the following code: ");
    v13 = std::operator<<<char>(v12, v20);
    std::ostream::operator<<(v13, &std::endl<char,std::char_traits<char>>);
    u_string_dtor((__int64)&myobj);
  }
  /* ... */
}
```

Function reads a license and check if it contains a colon `:`. If so it splits it into 
**2** parts and verifies them independently. Output message are kinda misleading as
it's not clear if the right path was followed or not.

We start with the first part: Function `u_sha1_hash_first_n_compare` simply checks 
if the **SHA1** checksum of the first part of the license matches with
`7951276d108732f685ad39766351430a193de32d`. To find which string gives this specific
hash, we use [crackstation](https://crackstation.net/):
```
7951276d108732f685ad39766351430a193de32d	sha1	anakin
```

So the license should start with `anakin:`.


Then there's function `u_gen_usr_specific_lic_code` that generates a valid license
code. However, this function is a decoy and it's not used to compute the flag.
The license is verified inside `u_verify_license`. Let's focus on the most important
part:
```c
bool __fastcall u_verify_license(my_struct *myobj) {
  /* ... */
  for ( j = 0; j <= 2; ++j ) {
    start_time = std::chrono::_V2::system_clock::now((std::chrono::_V2::system_clock *)p_a5);
    a5 = (__int64)&second[j];
    a3 = (__int64)myobj;
    // spawn threads with fptrs in myobj
    u_spawn_threads((__int64)&a1, (char *)myobj + 16 * j, (__int64)&a3, (__int64)&second[16 * j + 3], (__int64)&a5);
    std::thread::operator=((std::thread *)((char *)v18 + 8 * j), (std::thread *const)&a1);
    std::thread::~thread((std::thread *const)&a1);
    a3 = std::chrono::_V2::system_clock::now((std::chrono::_V2::system_clock *)&a1);
    a1 = u_ignore_me_1((__int64)&a3, (__int64)&start_time);
    a5 = u_ignore_me_2((__int64)&a1);
    p_a5 = (__int64)&a5;
    if ( u_ignore_me_3((__int64)&a5) > 800 )
      return 0;
  }

  for ( k = 0; k <= 2; ++k )
    std::thread::join((std::thread *)((char *)v18 + 8 * k));

  /* ... */
}
```

Function takes as input a special object (we call it `my_struct`) which is initialized in
`u_myobj_ctor` as follows:
```c
void __fastcall u_myobj_ctor(my_struct *a1, char *a2, char *a3) {
  a1->fptr1 = u_thread_routine_1;
  a1->field_8 = 0LL;
  a1->fptr2 = u_thread_routine_2;
  a1->field_18 = 0LL;
  a1->fptr3 = u_thread_routine_3;
  a1->field_28 = 0LL;
  a1->field_30 = 0;
  a1->str_second = a3;
  a1->str_first = a2;
}
```

The important part here are the **3** `fptr*` fields that contain function pointers.
Going back to `u_verify_license`, we see it invokes `u_spawn_thread` and a function
pointer is passed as input parameter:
```c
void __fastcall u_spawn_thread(__int64 a1, void *a2, __int64 a3, __int64 a4, __int64 a5) {
  /* ... */
  v5 = (tcmalloc::Span *)operator new(0x30uLL);
  v6 = sub_55555555BC5C(a5);
  v7 = sub_55555555BC4E(a4);
  v8 = sub_55555555BC40(a3);
  v9 = sub_55555555BC32((__int64)a2);
  sub_55555555BC84(v5, v9, v8, v7, v6);
  tcmalloc::TList<tcmalloc::Span>::prepend((tcmalloc::TList<tcmalloc::Span> *const)v13, v5);
  std::thread::_M_start_thread(a1, v13, 0LL);
  std::unique_ptr<tcmalloc::tcmalloc_internal::AllocationProfilingTokenBase>::~unique_ptr((std::unique_ptr<tcmalloc::tcmalloc_internal::AllocationProfilingTokenBase> *const)v13);
}
```

That is, program spawns **3** threads to verify the license code.


#### Verify License Code: Thread #1

The verification in the first thread is actually very simple:
```c
void __fastcall u_thread_routine_1(__int64 a1, const char *a2, _BYTE *a3) {
  /* ... */
  strcpy(key1, "rev_insomnihack");
  v8[0] = 0x5C401C2F24252B3BLL;
  v8[1] = 0x5B272A0B5D2C32LL;
  xored = xor_with_expansion(a2, key1);
  v3 = strlen(a2);
  if ( v3 == strlen(key1) )
  {
    for ( i = 0LL; i < strlen(a2); ++i )
    {
      if ( xored[i] != *((_BYTE *)v8 + i) )
      {
        *a3 = 0;
        return;
      }
    }
    *a3 = 1;
  }
}
```

The key `rev_insomnihack` is XORed with a random key and it's compared against the input.
We XOR the **2** keys and we get the first part of the flag:
```python
A = b'rev_insomnihack'
B = b'\x3B\x2B\x25\x24\x2F\x1C\x40\x5C\x32\x2C\x5D\x0B\x2A\x27\x5B'
C = ''.join(chr(a ^ b) for a, b in zip(A, B))
```

`C` is `INS{Fr33_B4cKD0`.

#### Verify License Code: Thread #2

Verification in the second thread is more complicated:
```c
void __fastcall u_thread_routine_2(__int64 a1, char *a2, _BYTE *a3) {
  *a3 = a2[7] - a2[8] == -2
     && a2[8] + *a2 + a2[10] == 264
     && a2[5] == a2[13] + a2[4] - 89
     && a2[12] == 95
     && a2[12] - *a2 == 47
     && a2[4] == a2[1] - 19
     && a2[14] - a2[13] - a2[2] == -28
     && *a2 + a2[7] + a2[8] == 248
     && a2[8] - a2[11] + *a2 == 48
     && a2[3] - a2[14] == -11
     && a2[12] + a2[6] - a2[8] == 99
     && a2[9] - a2[4] == 15
     && a2[6] + a2[12] - *a2 == a2[1] + 38
     && a2[2] == a2[9] + 54 - a2[4]
     && a2[2] == a2[9] - 41
     && a2[9] + *a2 + *a2 + a2[5] == a2[10] + 167;
}
```

Here we have a set of linear equations. We use an SMT solver to
find the correct solution: `0rEd_License_Fo`.


#### Verify License Code: Thread #3

Verification in the last thread uses SHA1 checksums:
```c
void __fastcall u_thread_routine_3(__int64 a1, _BYTE *a2, _BYTE *a3) {
  /* ... */
  key1 = 0;
  LOBYTE(key1) = *a2;
  key2 = 0;
  v10 = 0;
  key2 = *(_WORD *)a2;
  key3 = 0;
  LOWORD(key3) = *(_WORD *)a2;
  BYTE2(key3) = a2[2];
  key4 = 0;
  v13 = 0;
  key4 = *(_DWORD *)a2;
  key5 = 0;
  v15 = 0;
  key5 = *(_DWORD *)a2;
  LOBYTE(v15) = a2[4];
  memset(key6, 0, sizeof(key6));
  /* ... */
  key14[8] = a2[8];
  key14[9] = a2[9];
  key14[10] = a2[10];
  key14[11] = a2[11];
  key14[12] = a2[12];
  key14[13] = a2[13];
  key15 = 0LL;
  v29 = 0LL;
  key15 = *(_QWORD *)a2;
  LODWORD(v29) = *((_DWORD *)a2 + 2);
  WORD2(v29) = *((_WORD *)a2 + 6);
  BYTE6(v29) = a2[14];
  *a3 = 1;
  u_sha1_init_str((__int64)sha1, (__int64)a2, (__int64)a3);
  std::allocator<char>::allocator(&v4);
  u_str_ctor_maybe2((__int64)v6, (__int64)&key5, (__int64)&v4);
  u_sha1_update((__int64)sha1, (__int64)v6);
  std::string::~string(v6);
  std::allocator<char>::~allocator(&v4);
  u_sha1_final((__int64)v5, (__int64)sha1);
  if ( std::operator!=<JsonBox::Value,JsonBox::Value const&,JsonBox::Value const*>(
         (const std::_Deque_iterator<JsonBox::Value,const JsonBox::Value&,const JsonBox::Value*> *const)v5,
         (const std::_Deque_iterator<JsonBox::Value,const JsonBox::Value&,const JsonBox::Value*> *const)"a948b24c8ba4ae4f14b529b599601fd53a155994") )
  {
    *a3 = 0;
  }
  std::allocator<char>::allocator(&v4);
  u_str_ctor_maybe2((__int64)v6, (__int64)&key15, (__int64)&v4);
  u_sha1_update((__int64)sha1, (__int64)v6);
  std::string::~string(v6);
  std::allocator<char>::~allocator(&v4);
  u_sha1_final((__int64)v6, (__int64)sha1);
  std::string::operator=(v5, v6);
  std::string::~string(v6);
  if ( std::operator!=<JsonBox::Value,JsonBox::Value const&,JsonBox::Value const*>(
         (const std::_Deque_iterator<JsonBox::Value,const JsonBox::Value&,const JsonBox::Value*> *const)v5,
         (const std::_Deque_iterator<JsonBox::Value,const JsonBox::Value&,const JsonBox::Value*> *const)"a048299abe57311eacc14f1f3b4cdbfaf481f688") )
  {
    *a3 = 0;
  }
  /* ... */
  std::allocator<char>::allocator(&v4);
  u_str_ctor_maybe2((__int64)v6, (__int64)&key8, (__int64)&v4);
  u_sha1_update((__int64)sha1, (__int64)v6);
  std::string::~string(v6);
  std::allocator<char>::~allocator(&v4);
  u_sha1_final((__int64)v6, (__int64)sha1);
  std::string::operator=(v5, v6);
  std::string::~string(v6);
  if ( std::operator!=<JsonBox::Value,JsonBox::Value const&,JsonBox::Value const*>(
         (const std::_Deque_iterator<JsonBox::Value,const JsonBox::Value&,const JsonBox::Value*> *const)v5,
         (const std::_Deque_iterator<JsonBox::Value,const JsonBox::Value&,const JsonBox::Value*> *const)"b03da51041b519b7c12da6cc968bf1bc26de307c") )
  {
    *a3 = 0;
  }
  std::string::~string(v5);
  u_str_dtor2((__int64)sha1);
}
```

What does this function do? It takes the first character of the license code and
computes its SHA1 checksum and compares it against `06576556d1ad802f247cad11ae748be47b70cd9c` 
(the order is random).
If it doesn't match it sets `*a3 = 0` and function fails. Otherwise it takes the first **2**
characters from the license code, generates their SHA1 checksum and compares the result with
`e54a31693bcb9bf00ca2a26e0801404d14e68ddd`, and so on.


We can easily brute-force the last part of the flag character by character (we try all
character until the generated hash matches with the desired one: 
```
R
R_
R_3
R_3v 
R_3vE 
R_3vEr
R_3vEry
R_3vEry0
R_3vEry0n
R_3vEry0ne
R_3vEry0ne_ 
R_3vEry0ne_F 
R_3vEry0ne_FF
R_3vEry0ne_FFS
R_3vEry0ne_FFS}
```

So, the final flag is: `INS{Fr33_B4cKD00rEd_License_FoR_3vEry0ne_FFS}`

We verify it:
```
ispo@ispo-glaptop2:~/ctf/insomnihack_2022/License$ ./license-3321c4ba9df5aa508a14ba410bba4d87aa7735d2ed75ad6f6b6c361eb245ecfe 
Enter license: 
anakin:INS{Fr33_B4cKD00rEd_License_FoR_3vEry0ne_FFS}
License identifier correct
Your provided license: INS{Fr33_B4cKD00rEd_License_FoR_3vEry0ne_FFS}
You can activate your license with the following code: INS{Fr33_B4cKD00rEd_License_FoR_3vEry0ne_FFS}
```

For more details please take a look at the [license_crack.py](./license_crack.py) file.

___

