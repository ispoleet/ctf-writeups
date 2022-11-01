## Hack Lu CTF 2022 - Coctail Bar (RE 257)
##### 28/10 - 30/10/2022 (24hr)
___

### Description

*Every fancy restaurant needs an even fancier cocktail bar. Due to the recent labor shortage, we struggled to find a bartender to mix all that booze. In a very desperate attempt to fill the position, we hired FluxHorst. Unfortunately, his skills behind the bar leave a lot to be desired, as he gets constantly caught up in all that mixing, as well as the occasional flirt with a customer.*

*We would appreciate if you could briefly help Flux Horst with our most expensive flagship drink, priced at $23, to ensure that our customers can get properly drunk, and we make a profit.*
___

### Solution


In this challenge we're given a rust binary. Let's play with it:
```
ispo@ispo-glaptop2:~/ctf/hack.lu_ctf_2022/CocktailBar$ public/cocktailbar 
Welcome to the bar!

Please choose what you want to do:
1: Let's have the the house's flagship drink
2: Evaluate your own creation
q: Leave the bar
1
Wise choice! Now creating our flagship drink. This may take a while...
Now thinking about: LimeSlice(LimeSlice(Stirr(Mix(1024, AddVodka(2, 10))), Stirr(Mix(3072, Shake(22)))), Stirr(Mix(666, AddVodka(Shake(3), 13))), LimeSlice(Stirr(Mix(999, Shake(Mix(1024, FlirtWithCustomer(16, 0))))), AddSyrup(2, 5), Stirr(Mix(420, AddVodka(Mix(1337, AddVodka(Shake(0), 529)), 7))),  LimeSlice(Stirr(Mix(2048, Shake(Shake(118)))), Stirr(Mix(666, FlirtWithCustomer(17, 0)))), Stirr(Mix(9999, LimeSlice(3, 3))), Stirr(Mix(1337, FlirtWithCustomer(12, 0))), LimeSlice(LimeSlice(Stirr(Mix(4096, Shake(Shake(Shake(AddVodka(1, 7))))))), AddSyrup(1, LimeSlice(Mix(5000, Shake(Shake(18))))))))
[..... MANY MANY MORE LINES .....]
```

It is very easy to understand what's going on. The program has a default "recipe"
(i.e., a complex function) which *evaluates*. However, the computations here seem
to take exponential time, so program takes forever to finish. Let's look at the
evaluation:
```
LimeSlice(
    LimeSlice(
        Stirr(Mix(1024, AddVodka(2,10))),
        Stirr(Mix(3072, Shake(22)))),
    Stirr(Mix(666, AddVodka(Shake(3), 13))),
    LimeSlice(
        Stirr(Mix(999, Shake(Mix(1024, FlirtWithCustomer(16, 0))))),
        AddSyrup(2,5),
        Stirr(Mix(420, AddVodka(Mix(1337, AddVodka(Shake(0), 529)),7))),
        LimeSlice(
            Stirr(Mix(2048, Shake(Shake(118)))),
            Stirr(Mix(666, FlirtWithCustomer(17, 0)))),
        Stirr(Mix(9999, LimeSlice(3, 3))),
        Stirr(Mix(1337, FlirtWithCustomer(12, 0))), 
        LimeSlice(
            LimeSlice(
                Stirr(Mix(4096, Shake(Shake(Shake(AddVodka(1, 7))))))
            ),
            AddSyrup(1, 
                LimeSlice(
                    Mix(5000, Shake(Shake(18))))
                )
        )
    )
)
```

We have **7** functions here: `LimeSlice`, `Stirr`, `Mix`, `AddVodka`, `Shake`, `AddSyrup`
and `FlirtWithCustomer`. Let's now see what each function does. Program also provides a
second option to evaluate your own recipe, which is very helpful to understand the functions:
```
ispo@ispo-glaptop2:~/ctf/hack.lu_ctf_2022/CocktailBar$ public/cocktailbar 
Welcome to the bar!

Please choose what you want to do:
1: Let's have the the house's flagship drink
2: Evaluate your own creation
q: Leave the bar
2

What do you want me to do for you?
Stirr(5)
Now thinking about: Stirr(5)
Now thinking about: F
Finished! This yields: F
```

Since the binary is not stripped, we can easily locate the binary functions for each
component (they called `::compute::` under `cocktailbar` class):
```
_$LT$cocktailbar..Mix$u20$as$u20$cocktailbar..Rule$GT$::compute::h9c7633f43457163f
_$LT$cocktailbar..Mix$u20$as$u20$cocktailbar..Rule$GT$::get_args::hcd4d1ef5cd43d07d
_$LT$cocktailbar..Mix$u20$as$u20$cocktailbar..Rule$GT$::get_name::h1e7caac0fdab2864
_$LT$cocktailbar..Shake$u20$as$u20$cocktailbar..Rule$GT$::compute::hdf437684ce5d89e0
_$LT$cocktailbar..Shake$u20$as$u20$cocktailbar..Rule$GT$::get_name::h9482d429591a8818
_$LT$cocktailbar..Flirt$u20$as$u20$cocktailbar..Rule$GT$::compute::h0c602aba8d999bb2
_$LT$cocktailbar..Flirt$u20$as$u20$cocktailbar..Rule$GT$::get_name::ha01ca4524f53bbb3
_$LT$cocktailbar..Syrup$u20$as$u20$cocktailbar..Rule$GT$::compute::h90bb71dc02215aa9
_$LT$cocktailbar..Syrup$u20$as$u20$cocktailbar..Rule$GT$::get_name::hc8a5b8ede731f597
_$LT$cocktailbar..Stirr$u20$as$u20$cocktailbar..Rule$GT$::compute::hb1ed8c3869035833
_$LT$cocktailbar..Stirr$u20$as$u20$cocktailbar..Rule$GT$::get_name::h1b98eb0531db1670
_$LT$cocktailbar..Vodka$u20$as$u20$cocktailbar..Rule$GT$::compute::h889194abc8f04e6f
_$LT$cocktailbar..Vodka$u20$as$u20$cocktailbar..Rule$GT$::get_name::hb78e4b74cf396695
_$LT$cocktailbar..Lime$u20$as$u20$cocktailbar..Rule$GT$::compute::h122690878e049d76
_$LT$cocktailbar..Lime$u20$as$u20$cocktailbar..Rule$GT$::get_name::h60e51beb3abbbe54
```

Let's look them at one by one.


#### Function: Mix

```c
__int64 __fastcall _$LT$cocktailbar..Mix$u20$as$u20$cocktailbar..Rule$GT$::compute::h9c7633f43457163f(
        __int64 a1,
        __int64 a2)
{
  /* ... */
  // get the 1st argument
  core::num::_$LT$impl$u20$core..str..traits..FromStr$u20$for$u20$u32$GT$::from_str::h68b330402fad63de();
  if ( (arg1_raw & 1) != 0 )                    // actual value is on 32 MSBits of rax
  {
    LOBYTE(v13) = BYTE1(arg1_raw);
    goto FAILURE;
  }
  if ( v2 <= 1 )
PANIC:
    core::panicking::panic::hb3ad04c589a0e3c8();
  arg1_raw_ = arg1_raw;
  // get the 2nd argument
  core::num::_$LT$impl$u20$core..str..traits..FromStr$u20$for$u20$u32$GT$::from_str::h68b330402fad63de();
  if ( (arg2_raw & 1) != 0 )                    // actual value is on 32 MSBits of rax
  {
    LOBYTE(v13) = BYTE1(arg2_raw);
FAILURE:
    core::result::unwrap_failed::h42ad8e915aa0a906();
  }
  arg1 = HIDWORD(arg1_raw_);
  arg2 = HIDWORD(arg2_raw);


  if ( (unsigned int)arg1 <= 1 )                // when arg1 is 0 or 1
  {
    v10 = (unsigned int)arg2 % 0x17;            // return arg2 % 0x17
    *(_QWORD *)&v18 = &v10;
    *((_QWORD *)&v18 + 1) = core::fmt::num::imp::_$LT$impl$u20$core..fmt..Display$u20$for$u20$u32$GT$::fmt::h5e0024fc9c833791;
    /* ... */
  }
  else
  {
    v11 = arg1 - 1;
    v12 = arg1 - 1;
    v10 = (unsigned int)arg2 % 0x17;
    /* ... */
  }
  *(_OWORD *)a1 = v8;
  return a1;
}
```

This function has a recursive definition:
```
Mix(i, j) ~> Mix(i-1, Mix(i-i, j)),  if i >= 1
             j % 0x17             ,  otherwise
```

The 2nd argument never gets modified and eventually gets returned, we can simplify
the function as follows:
```
Mix(x, y) ~> y % 0x17
```


#### Function: Shake

```c
__int64 __fastcall _$LT$cocktailbar..Shake$u20$as$u20$cocktailbar..Rule$GT$::compute::hdf437684ce5d89e0(
        __int64 a1,
        __int64 a2)
{
  /* ... */
  if ( !*(_QWORD *)(a2 + 16) )
    core::panicking::panic::hb3ad04c589a0e3c8();
  core::num::_$LT$impl$u20$core..str..traits..FromStr$u20$for$u20$u32$GT$::from_str::h68b330402fad63de();
  if ( (arg1_raw & 1) != 0 )
  {
    LOBYTE(v8) = v2;
    core::result::unwrap_failed::h42ad8e915aa0a906();
  }
  v6 = arg1 + 24;
  v7[0] = (__int64)&v6;
  v7[1] = (__int64)core::fmt::num::imp::_$LT$impl$u20$core..fmt..Display$u20$for$u20$u32$GT$::fmt::h5e0024fc9c833791;
  v8 = &off_5555556A0E80;
  v9 = 1LL;
  v10 = 0LL;
  v11 = v7;
  v12 = 1LL;
  alloc::fmt::format::format_inner::he64427ffd3996818();
  return a1;
}
```

This function is much simpler:
```
Shake(x) ~> x + 24
```

#### Function: FlirtWithCustomer

This is the most complicated one:
```c
__int64 __fastcall _$LT$cocktailbar..Flirt$u20$as$u20$cocktailbar..Rule$GT$::compute::h0c602aba8d999bb2(
        __int64 a1,
        __int64 a2)
{
  /* ... */
  if ( *(_QWORD *)(a2 + 16) <= 1uLL )
    core::panicking::panic::hb3ad04c589a0e3c8();
  core::num::_$LT$impl$u20$core..str..traits..FromStr$u20$for$u20$u32$GT$::from_str::h68b330402fad63de();
  arg1_raw_ = arg1_raw;
  if ( (arg1_raw & 1) != 0 )
  {
    LOBYTE(v13) = BYTE1(arg1_raw);
    goto LABEL_11;
  }
  core::num::_$LT$impl$u20$core..str..traits..FromStr$u20$for$u20$u32$GT$::from_str::h68b330402fad63de();
  if ( (arg2_raw_ & 1) != 0 )
  {
    LOBYTE(v13) = BYTE1(arg2_raw_);
LABEL_11:
    core::result::unwrap_failed::h42ad8e915aa0a906();
  }
  arg2 = HIDWORD(arg1_raw_);
  arg1 = HIDWORD(arg2_raw_);
  v10 = arg1;
  if ( (_DWORD)arg2 == 23 )
  {
    result = arg1 + 25;
    *(_QWORD *)&v21 = &result;
    *((_QWORD *)&v21 + 1) = core::fmt::num::imp::_$LT$impl$u20$core..fmt..Display$u20$for$u20$u32$GT$::fmt::h5e0024fc9c833791;
    v13 = (int *)&off_5555556A0E80;
    v14 = 1LL;
    v15 = 0LL;
    v17 = &v21;
    v18 = 1LL;
    alloc::fmt::format::format_inner::he64427ffd3996818();
    *(_QWORD *)(a1 + 16) = v24;
    v7 = v23;
  }
  else
  {
    v11 = arg1 + 1;
    v12 = arg2 + 1;
    result = arg2 + 1;
    v13 = &v11;
    v14 = (__int64)core::fmt::num::imp::_$LT$impl$u20$core..fmt..Display$u20$for$u20$u32$GT$::fmt::h5e0024fc9c833791;
    v15 = &v12;
    v16 = core::fmt::num::imp::_$LT$impl$u20$core..fmt..Display$u20$for$u20$u32$GT$::fmt::h5e0024fc9c833791;
    v17 = (__int128 *)&v10;
    v18 = (__int64)core::fmt::num::imp::_$LT$impl$u20$core..fmt..Display$u20$for$u20$u32$GT$::fmt::h5e0024fc9c833791;
    v19 = &result;
    v20 = core::fmt::num::imp::_$LT$impl$u20$core..fmt..Display$u20$for$u20$u32$GT$::fmt::h5e0024fc9c833791;
    *(_QWORD *)&v23 = &off_5555556A0F08;
    *((_QWORD *)&v23 + 1) = 5LL;
    v24 = 0LL;
    v25 = (__int64 *)&v13;
    v26 = 4LL;
    alloc::fmt::format::format_inner::he64427ffd3996818();
    *(_QWORD *)(a1 + 16) = v22;
    v7 = v21;
  }
  *(_OWORD *)a1 = v7;
  return a1;
}
```

Function checks if `arg2` is **23**. If so it returns `arg1 + 25`.
Otherwise it re-evaluates to (`arg1 + 1`, `arg2 + 1`):
```
FlirtWithCustomer(a, b, c) ~> FlirtWithCustomer(a+1, b+1,
                                                FlirtWithCustomer(a, b+1)),  if b < 23
                              a + 25                                      , otherwise
  
Example:
  FlirtWithCustomer(2, 22)                           =>
  FlirtWithCustomer(3, 23, FlirtWithCustomer(2, 23)) =>
  FlirtWithCustomer(3, 23, 27)                       =>
  3 + 25 = 28
```

#### Function: AddSyrup

This function is simpler to understand using a black box analysis from the I/O of the program.
Consider for example: `AddSyrup(3,4)`
```
LimeSlice(
    Stirr(Mix(1000, AddVodka(4, 187))),
    Stirr(Mix(1000, AddVodka(4, 215))),
    Stirr(Mix(1000, AddVodka(4, 243)))
)
```

Another example for `AddSyrup(7, 1337)`:
```
LimeSlice(
  Stirr(Mix(1000, AddVodka(1337, 187))),
  Stirr(Mix(1000, AddVodka(1337, 215))),
  Stirr(Mix(1000, AddVodka(1337, 243))),
  Stirr(Mix(1000, AddVodka(1337, 271))),
  Stirr(Mix(1000, AddVodka(1337, 299))),
  Stirr(Mix(1000, AddVodka(1337, 327))),
  Stirr(Mix(1000, AddVodka(1337, 355)))
)
```

It is quite easy to understand the pattern. `AddSyrup(x, y)` gets substituted with a `LimeSlice`
that has `x` parameters. Each parameter is `Stirr(Mix(1000, AddVodka(y, 187 + i*0x1C)))`.

#### Function: Stirr

```c
__int64 __fastcall _$LT$cocktailbar..Stirr$u20$as$u20$cocktailbar..Rule$GT$::compute::hb1ed8c3869035833(
        __int64 a1,
        __int64 a2)
{
  /* ... */
  if ( !*(_QWORD *)(a2 + 16) )
    goto LABEL_8;
  core::num::_$LT$impl$u20$core..str..traits..FromStr$u20$for$u20$u32$GT$::from_str::h68b330402fad63de();
  if ( (arg1_raw_ & 1) != 0 )
  {
    LOBYTE(v8) = v2;
    core::result::unwrap_failed::h42ad8e915aa0a906();
  }
  if ( ((arg1 + 65) ^ 0xD800u) - 1114112 < 0xFFEF0800 || arg1 == 1114047 )
LABEL_8:
    core::panicking::panic::hb3ad04c589a0e3c8();
  result = arg1 + 65;                           // Add + 'A' and make it a chr()
  v7[0] = (__int64)&result;
  v7[1] = (__int64)_$LT$char$u20$as$u20$core..fmt..Display$GT$::fmt::ha0794c24cf3be43b;
  v8 = &off_5555556A0E80;
  v9 = 1LL;
  v10 = 0LL;
  v11 = v7;
  v12 = 1LL;
  alloc::fmt::format::format_inner::he64427ffd3996818();
  return a1;
}
```

This is also very simple:
```
Stirr(x) ~> chr(x + 65)
```

#### Function: AddVodka

```c
__int64 __fastcall _$LT$cocktailbar..Vodka$u20$as$u20$cocktailbar..Rule$GT$::compute::h889194abc8f04e6f(
        __int64 a1,
        __int64 a2)
{
  /* ... */
  v2 = *(_QWORD *)(a2 + 16);
  if ( !v2 )
    goto LABEL_8;
  core::num::_$LT$impl$u20$core..str..traits..FromStr$u20$for$u20$u32$GT$::from_str::h68b330402fad63de();
  if ( (v5 & 1) != 0 )
  {
    LOBYTE(v12) = v3;
    goto LABEL_10;
  }
  if ( v2 <= 1 )
LABEL_8:
    core::panicking::panic::hb3ad04c589a0e3c8();
  arg1_raw_ = arg1_raw;
  core::num::_$LT$impl$u20$core..str..traits..FromStr$u20$for$u20$u32$GT$::from_str::h68b330402fad63de();
  if ( (v9 & 1) != 0 )
  {
    LOBYTE(v12) = v7;
LABEL_10:
    core::result::unwrap_failed::h42ad8e915aa0a906();
  }
  v11 = arg1_raw_ + arg2 + 46;                  // add the 2 args plus 46
  v17[0] = (__int64)&v11;
  v17[1] = (__int64)core::fmt::num::imp::_$LT$impl$u20$core..fmt..Display$u20$for$u20$u32$GT$::fmt::h5e0024fc9c833791;
  v12 = &off_5555556A0E80;
  v13 = 1LL;
  v14 = 0LL;
  v15 = v17;
  v16 = 1LL;
  alloc::fmt::format::format_inner::he64427ffd3996818();
  return a1;
}
```

This is also very simple:
```
AddVodka(x, y) ~> x + y + 46
```

#### Function: LimeSlice

Finally we have `LimeSlice` that iterates over all arguments:
```c
__int64 __fastcall _$LT$cocktailbar..Lime$u20$as$u20$cocktailbar..Rule$GT$::compute::h122690878e049d76(__int64 a1)
{
  /* ... */
  _$LT$alloc..vec..Vec$LT$T$C$A$GT$$u20$as$u20$core..clone..Clone$GT$::clone::h815e5594c4a31478(v6);
  v1 = v6[0];
  v2 = v7;
  alloc::str::join_generic_copy::h7417463af85af57e(&v8, v6[0], v7, "", 0LL);
  *(_QWORD *)(a1 + 16) = v9;
  *(_OWORD *)a1 = v8;
  if ( v2 )
  {
    v3 = 0x18 * v2;
    ptr = 0LL;
    do
    {
      if ( *(_QWORD *)(v1 + ptr + 8) )
        _rust_dealloc();
      ptr += 0x18LL;
    }
    while ( v3 != ptr );
  }
  if ( v6[1] )
    _rust_dealloc();
  return a1;
}
```

If we do a black box analysis, we can easily understand that it simply concatenates all
parameters together:
```
LimeSlice(1, 2)         ~> 12
LimeSlice(98878, 31337) ~> 9887831337
LimeSlice(1,2,3,4,5,6)  ~> 123456
LimeSlice(i, s, p, o)   ~> ispo
```

### Evaluating the Recipe

Since we have simplified the functions, all we have to do, is to evaluate them and get
the flag. We use the script [cocktail_bar_crack.py](./cocktail_bar_crack.py) to 
do the evaluation.

So, the flag is: `flag{MARTINIFTKOLA}`

___
