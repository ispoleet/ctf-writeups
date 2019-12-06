
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
