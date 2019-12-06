## Codegate CTF 2018 - easy_serial (RE 350pts)
##### 03-04/02/2018 (24hr)
___

### Description: 


find the flag
Download

___
### Solution


Binary contains a lot of code which means that is probably an emulator or something similar.
A quick google search of one of the function (for example `performMajorGC`), quickly reveals
that is Haskell. So we have a Haskell binary that we have to crack.

Luckily for us a Haskell decompiler **does** exists:
[https://github.com/gereeter/hsdecomp](https://github.com/gereeter/hsdecomp). Trying to decompile 
the program: `hsdecomp easy` seems to not work:
```
Traceback (most recent call last):
  File "/usr/local/bin/hsdecomp", line 11, in <module>
    load_entry_point('hsdecomp==0.1.0', 'console_scripts', 'hsdecomp')()
  File "/home/ispo/.local/lib/python3.6/site-packages/pkg_resources/__init__.py", line 489, in load_entry_point
    return get_distribution(dist).load_entry_point(group, name)
  File "/home/ispo/.local/lib/python3.6/site-packages/pkg_resources/__init__.py", line 2852, in load_entry_point
    return ep.load()
  File "/home/ispo/.local/lib/python3.6/site-packages/pkg_resources/__init__.py", line 2443, in load
    return self.resolve()
  File "/home/ispo/.local/lib/python3.6/site-packages/pkg_resources/__init__.py", line 2449, in resolve
    module = __import__(self.module_name, fromlist=['__name__'], level=0)
  File "/usr/local/lib/python3.6/dist-packages/hsdecomp-0.1.0-py3.6.egg/hsdecomp/__init__.py", line 3, in <module>
  File "/usr/local/lib/python3.6/dist-packages/hsdecomp-0.1.0-py3.6.egg/hsdecomp/metadata.py", line 4, in <module>
ModuleNotFoundError: No module named 'hsdecomp.parse'
```

However, we can easily fix that by adding the missing module (`hsdecomp.parse`) in `setup.py`:
```python
packages = ['hsdecomp', 'hsdecomp.parse'],
```

Then we run again and we get the decompiled version of the binary
(full code at [easy_serial.hs](easy_serial.hs)):
```Haskell
Main_main_closure = >> $fMonadIO
    (putStrLn (unpackCString# "Input Serial Key >>> "))
    (>>= $fMonadIO
        getLine
        (\s1dZ_info_arg_0 ->
            >> $fMonadIO
                (putStrLn (++ (unpackCString# "your serial key >>> ") (++ s1b7_info (++ (unpackCString# "_") (++ s1b9_info (++ (unpackCString# "_") s1bb_info))))))
                (case && (== $fEqInt (ord (!! s1b7_info loc_7172456)) (I# 70)) (&& (== $fEqInt (ord (!! s1b7_info loc_7172472)) (I# 108)) (&& (== $fEqInt (ord (!! s1b7_info loc_7172488)) (I# 97)) (&& (== $fEqInt (ord (!! s1b7_info loc_7172504)) (I# 103)) (&& (== $fEqInt (ord (!! s1b7_info loc_7172520)) (I# 123)) (&& (== $fEqInt (ord (!! s1b7_info loc_7172536)) (I# 83)) (&& (== $fEqInt (ord (!! s1b7_info loc_7172552)) (I# 48)) (&& (== $fEqInt (ord (!! s1b7_info loc_7172568)) (I# 109)) (&& (== $fEqInt (ord (!! s1b7_info loc_7172584)) (I# 101)) (&& (== $fEqInt (ord (!! s1b7_info loc_7172600)) (I# 48)) (&& (== $fEqInt (ord (!! s1b7_info (I# 10))) (I# 102)) (&& (== $fEqInt (ord (!! s1b7_info (I# 11))) (I# 85)) (== $fEqInt (ord (!! s1b7_info (I# 12))) (I# 53))))))))))))) of
                    <tag 1> -> putStrLn (unpackCString# ":p"),
                    c1ni_info_case_tag_DEFAULT_arg_0@_DEFAULT -> case == ($fEq[] $fEqChar) (reverse s1b9_info) (: (C# 103) (: (C# 110) (: (C# 105) (: (C# 107) (: loc_7168872 (: loc_7168872 (: (C# 76) (: (C# 51) (: (C# 114) (: (C# 52) [])))))))))) of
                        False -> putStrLn (unpackCString# ":p"),
                        True -> case && (== $fEqChar (!! s1bb_info loc_7172456) (!! s1b3_info loc_7172456)) (&& (== $fEqChar (!! s1bb_info loc_7172472) (!! s1b4_info (I# 19))) (&& (== $fEqChar (!! s1bb_info loc_7172488) (!! s1b3_info (I# 19))) (&& (== $fEqChar (!! s1bb_info loc_7172504) (!! s1b4_info loc_7172568)) (&& (== $fEqChar (!! s1bb_info loc_7172520) (!! s1b2_info loc_7172488)) (&& (== $fEqChar (!! s1bb_info loc_7172536) (!! s1b3_info (I# 18))) (&& (== $fEqChar (!! s1bb_info loc_7172552) (!! s1b4_info (I# 19))) (&& (== $fEqChar (!! s1bb_info loc_7172568) (!! s1b2_info loc_7172504)) (&& (== $fEqChar (!! s1bb_info loc_7172584) (!! s1b4_info (I# 17))) (== $fEqChar (!! s1bb_info loc_7172600) (!! s1b4_info (I# 18))))))))))) of
                            <tag 1> -> putStrLn (unpackCString# ":p"),
                            c1tb_info_case_tag_DEFAULT_arg_0@_DEFAULT -> putStrLn (unpackCString# "Correct Serial Key! Auth Flag!")
                )
        )
    )
s1b4_info = unpackCString# "abcdefghijklmnopqrstuvwxyz"
loc_7172600 = I# 9
s1bb_info = !! s1b5_info loc_7172488
loc_7172488 = I# 2
s1b5_info = splitOn $fEqChar (unpackCString# "#") s1dZ_info_arg_0
loc_7172584 = I# 8
loc_7172504 = I# 3
s1b2_info = unpackCString# "1234567890"
loc_7172568 = I# 7
loc_7172552 = I# 6
s1b3_info = unpackCString# "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
loc_7172536 = I# 5
loc_7172520 = I# 4
loc_7172472 = I# 1
loc_7172456 = I# 0
loc_7168872 = C# 48
s1b9_info = !! s1b5_info loc_7172472
s1b7_info = !! s1b5_info loc_7172456
```


Ok that looks like a mess, but if we clean it up, rename the variables and add some comments,
we can easily figure out what's going on:
```Haskell

Main_main_closure = >> $fMonadIO
    -- Print banner
    (putStrLn (unpackCString# "Input Serial Key >>> "))
    
    -- Declare a Monad
    (>>= $fMonadIO
        getLine

        -- Define a lambda function 
        (\lambda_validate_serial -> >> $fMonadIO
                -- Concatenate the following strings and print them to stdout:
                -- "your serial key >>> ${serial_key_1}_${serial_key_2}_${serial_key_3}"
                (putStrLn                     
                    (++ (unpackCString# "your serial key >>> ") 
                    (++ serial_key_1 (++ (unpackCString# "_") 
                    (++ serial_key_2 (++ (unpackCString# "_") serial_key_3)))))
                )

                (case && 
                    -- Check whether serial_key_1 is "Flag{S0me0fU5" 
                    (== $fEqInt (ord (!! serial_key_1 loc_int_0)) (I# 70))  (&& 
                    (== $fEqInt (ord (!! serial_key_1 loc_int_1)) (I# 108)) (&& 
                    (== $fEqInt (ord (!! serial_key_1 loc_int_2)) (I# 97))  (&&
                    (== $fEqInt (ord (!! serial_key_1 loc_int_3)) (I# 103)) (&&
                    (== $fEqInt (ord (!! serial_key_1 loc_int_4)) (I# 123)) (&& 
                    (== $fEqInt (ord (!! serial_key_1 loc_int_5)) (I# 83))  (&& 
                    (== $fEqInt (ord (!! serial_key_1 loc_int_6)) (I# 48))  (&& 
                    (== $fEqInt (ord (!! serial_key_1 loc_int_7)) (I# 109)) (&& 
                    (== $fEqInt (ord (!! serial_key_1 loc_int_8)) (I# 101)) (&& 
                    (== $fEqInt (ord (!! serial_key_1 loc_int_9)) (I# 48))  (&& 
                    (== $fEqInt (ord (!! serial_key_1 (I# 10)))   (I# 102)) (&& 
                    (== $fEqInt (ord (!! serial_key_1 (I# 11)))   (I# 85)) 
                    (== $fEqInt (ord (!! serial_key_1 (I# 12)))   (I# 53))))))))))))) 
                 of
                    <tag 1> 

                    -> putStrLn (unpackCString# ":p"), c1ni_info_case_tag_DEFAULT_arg_0@_DEFAULT 
                    ->  -- Check whether serial_key_2 is "4r3L00king"
                        -- (append "gnik00L3r4" to the head (i.e., in reverse order): "4r3L00king")
                        case == ($fEq[] $fEqChar) (reverse serial_key_2) 
                        (: (C# 103) (: (C# 110) (: (C# 105) (: (C# 107) (: loc_chr_zero
                        (: loc_chr_zero (: (C# 76) (: (C# 51) (: (C# 114) (: (C# 52) []))))))))))
                    of
                        False -> putStrLn (unpackCString# ":p"),
                        True  -> case && 
                            -- Check whethr serial_key_3 is "AtTh3St4rs"
                            (== $fEqChar (!! serial_key_3 loc_int_0) (!! str_uppercase loc_int_0)) (&&
                            (== $fEqChar (!! serial_key_3 loc_int_1) (!! str_lowercase (I# 19)))   (&&
                            (== $fEqChar (!! serial_key_3 loc_int_2) (!! str_uppercase (I# 19)))   (&&
                            (== $fEqChar (!! serial_key_3 loc_int_3) (!! str_lowercase loc_int_7)) (&&
                            (== $fEqChar (!! serial_key_3 loc_int_4) (!! str_numbers   loc_int_2)) (&&
                            (== $fEqChar (!! serial_key_3 loc_int_5) (!! str_uppercase (I# 18)))   (&&
                            (== $fEqChar (!! serial_key_3 loc_int_6) (!! str_lowercase (I# 19)))   (&&
                            (== $fEqChar (!! serial_key_3 loc_int_7) (!! str_numbers   loc_int_3)) (&&
                            (== $fEqChar (!! serial_key_3 loc_int_8) (!! str_lowercase (I# 17)))
                            (== $fEqChar (!! serial_key_3 loc_int_9) (!! str_lowercase (I# 18))))))))))) 
                            of
                            <tag 1> -> putStrLn (unpackCString# ":p"),
                            c1tb_info_case_tag_DEFAULT_arg_0@_DEFAULT ->
                                putStrLn (unpackCString# "Correct Serial Key! Auth Flag!")
                )
        )
    )

-- Variable assignments
str_lowercase = unpackCString# "abcdefghijklmnopqrstuvwxyz"
str_numbers   = unpackCString# "1234567890"
str_uppercase = unpackCString# "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

loc_int_0 = I# 0
loc_int_1 = I# 1
loc_int_2 = I# 2
loc_int_3 = I# 3
loc_int_4 = I# 4
loc_int_5 = I# 5
loc_int_6 = I# 6
loc_int_7 = I# 7
loc_int_8 = I# 8
loc_int_9 = I# 9
loc_chr_zero = C# 48

-- Get serial and split it on '#' (3 parts)
all_serials = splitOn $fEqChar (unpackCString# "#") lambda_validate_serial

-- Get the 3 indexes of "all_serials"
-- (if not 3 indices you get the "Prelude.!!: index too large" error).
serial_key_1 = !! all_serials loc_int_0
serial_key_2 = !! all_serials loc_int_1
serial_key_3 = !! all_serials loc_int_2
```

The above code takes a serial and splits it into `#`. It expects to find 3 pieces. If not, we
get the error: `easy: Prelude.!!: index too large`. If we give a serial with 3 pound signs, we
program executes with no errors:
```
ispo@nogirl:~/ctf/ctf-writeups/codegate_quals_2018/easy_serial$ ./easy 
    Input Serial Key >>> 
    1#2#3
    your serial key >>> 1_2_3
    :p
```

By looking at the code we can easily extract the flag: `Flag{S0me0fU5_4r3L00king_AtTh3St4rs`
```
ispo@nogirl:~/ctf/ctf-writeups/codegate_quals_2018/easy_serial$ ./easy 
    Input Serial Key >>> 
    Flag{S0me0fU5#4r3L00king#AtTh3St4rs
    your serial key >>> Flag{S0me0fU5_4r3L00king_AtTh3St4rs
    Correct Serial Key! Auth Flag!

ispo@nogirl:~/ctf/ctf-writeups/codegate_quals_2018/easy_serial$ ./easy 
    Input Serial Key >>> 
    Flag{S0me0fU5#4r3L00king#AtTh3St4rs}
    your serial key >>> Flag{S0me0fU5_4r3L00king_AtTh3St4rs}
    Correct Serial Key! Auth Flag!
```

As you can see it doesn't matter if we omit the final `}` or if we append any number of characters.

___
