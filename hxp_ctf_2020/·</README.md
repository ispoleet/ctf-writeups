## HXP CTF 2020 - ·< (Reversing 417)
##### 18/12 - 20/12/2020 (48hr)
___

### Description

**Difficulty estimate:** `medium`

**Points:** `round(1000 · min(1, 10 / (9 + [15 solves]))) = 417 points`

*I must admit that this challenge is rather pointless.*

*Note: Due to reasons, the program accepts more than one input. Please contact us on IRC if you run into this. Sorry.*

```
Download: ·<-e1336e9e0f9f61b1.tar.xz (928 Bytes)
```
___

### Solution

In this challenge we are given the following obfuscated Haskell program:
```haskell
#!/usr/bin/env runhaskell
{-# LANGUAGE OverloadedStrings #-}
import Prelude hiding (replicate, putStrLn)
import Data.List hiding (replicate)
import Data.Tuple
import Data.Ord
import Data.Function
import Data.ByteString (replicate)
import Data.ByteString.Char8 (putStrLn, pack)
import Control.Monad
import Control.Arrow
import Control.Applicative
import Crypto.Cipher.AES
import Crypto.Hash.SHA256
import Unsafe.Coerce

c = "\xd7\xc8\x35\x14\xc4\x27\xcd\x6f\x78\x3a\x80\x57\x76\xb0\xfd\x42\x25\xe4\x87\x5f\x99\x28\x87\x0a\x06\xef\x63\x81\x44"

main
  = (>>=) getContents $ read >>> putStrLn <<< ( <<< unsafeCoerce . and <<< flip
    `liftM` flip liftM2 `uncurry` (fmap unsafeCoerce $ swap <**> (<>) $ (&) <$>
    [0..39] & pure) <<< ((.) or <<<) . (<$>) (flip (<$>) >>> (.) $ (>>> \[x] ->
    x) . flip elemIndices & \(??) -> (.) . (>>>) . (. flip (??)) . ((.) (>=) .)
    . (>>>) <*> (.) (<**>) . (<*>) . (.) (??) & \t -> [(&) $ id $ fst <$> (flip
    sortBy [0..39] . comparing . (!!) *** drop 40 <<< return . snd ^>> (<>) <*>
    swap) `iterate` pure (tail $ flip iterate 44 $ flip mod 400013 <$> (+) 42 .
    (*) 1337) & tail & (!!)] <*> [(<<^) flip <<< t >>> ((!!) >>>), (.) (==) <$>
    (!!) & return, (>>>) (??) . t <<< (. (+) 40)]) . (>>>) (.) . (.) <<< ( >>>)
    . (&)) . maybe "wrong" <$> (>>>) pure (>>> initAES . hash .
```

### Running the program

Getting the program to run is a challenge by itself. We first need to find and install the
right packages. To do that we use [Hoogle](https://hoogle.haskell.org/).
First we need to find the appropriate crypto package (there are many), so we search for
[decryptCTR](https://hoogle.haskell.org/?hoogle=decryptCTR). The required package **cipher-aes**.

Before installing this package we have to find all the dependencies:
```
https://hackage.haskell.org/package/byteable
https://hackage.haskell.org/package/crypto-cipher-types
https://hackage.haskell.org/package/securemem
```

And install them:
```
runhaskell Setup configure
runhaskell Setup build
sudo runhaskell Setup install
```

Then we install `cipher-aes` package. We also need to install
[cryptohash-sha256](https://hackage.haskell.org/package/cryptohash-sha256) package.

After installing all required packages, we get program to run:
```
ispo@ispo-glaptop:~/ctf/hxp_2020/·<$ ./deobf.hs 
ispo
deobf.hs: Prelude.read: no parse
```

### Understanding the code

An excellent resource for learning haskel is the
[Learn You a Haskell for Great Good](http://learnyouahaskell.com/) book (available online for
free). Although, this book does not cover
[arrows](https://en.wikibooks.org/wiki/Haskell/Understanding_arrows), there is a good tutorial
[here](https://stackoverflow.com/questions/4191424/what-are-arrows-and-how-can-i-use-them).
Below is the program with comments that explain what it does:
```haskell
#!/usr/bin/env runhaskell
{-# LANGUAGE OverloadedStrings #-}
import Prelude hiding (replicate, putStrLn)
import Data.List hiding (replicate)
import Data.Tuple
import Data.Ord
import Data.Function
import Data.ByteString (replicate)
import Data.ByteString.Char8 (putStrLn, pack)
import Control.Monad
import Control.Arrow
import Control.Applicative
import Crypto.Cipher.AES
import Crypto.Hash.SHA256
import Unsafe.Coerce

c = "\xd7\xc8\x35\x14\xc4\x27\xcd\x6f\x78\x3a\x80\x57\x76\xb0\xfd\x42\x25\xe4\x87\x5f\x99\x28\x87\x0a\x06\xef\x63\x81\x44"

{- main =
 - (>>=) getContents $ read >>> 
 -   putStrLn <<< (... key verification function ...) . maybe "wrong" <$> (>>>) pure (
 -        >>> initAES . hash . pack . show >>> decryptCTR (replicate 16 0) c) <*> id
 - 
 - Bind function (>>=) works directly with monadic values inside their context: 
 -    Just 4 >>= (\x -> Just (x + 1)) == (>>=) (Just 4) (\x -> Just (x + 1)) => Just 5
 -
 - Rewrite as:
 -
 - Operator associativity (e.g., ":i >>="):
 -    .     infixr 9
 -    <$>   infixl 4
 -    <*>   infixl 4
 -    >>>   infixr 1
 -    <<<   infixr 1
 -    >>=   infixl 1
 -    $     infixr 0
 -
 - getContents with >>= takes a function and returns a monad:
 -
 - getContents >>= (\x -> return (x ++ " foo"))
 -
 - putStrLn $ pack "foo"                              --> foo
 - putStrLn <<< (\x -> pack (x ++ " ispo")) $ "foo"   --> foo ispo
 -
 - We rewrite as:
 -  main =
 -     getContents >>=  
 -          (read >>> (putStrLn <<< ($KEY_VER ...) . maybe "wrong")
 -              <$> (>>>) 
 -              pure (>>> (initAES . hash . pack . show) >>> (decryptCTR (replicate 16 0) c))
 -              <*> id))
 -
 - The input here is a list of integers: [Int]
 -}
main
  -- getContents returns an IO String. Use >>= to get the string from the IO context.
  = (>>=) getContents $ read 
    >>> putStrLn 
    <<< ( -- Key verification. Type is: (b -> c) -> [Int] -> c

        -- unsafeCoerce converts a value from any type to any other type
        -- ((unsafeCoerce 1) :: Float --> 1.0e-45).
        -- and [True, False]    --> False
        <<< unsafeCoerce . and 
        {-
         - :t (+)                           --> Num a => a -> a -> a
         - :t uncurry (+)                   --> Num c => (c, c) -> c
         - :t curry (\(x, y) -> x + y)      --> Num c => c -> c -> c 
         -
         - curry (\(x, y) -> x + y) 1 2     --> 3
         - uncurry (+) (1, 2)               --> 3
         -
         - liftM (+3) (Just 4)              --> Just 7
         - liftM2 (+) (Just 4) (Just 7)     --> Just 11
         -
         - (-) 7 3                          --> 4
         - flip (-) 7 3                     --> -4
         -
         - Rewrite as:
         -      flip `liftM` flip liftM2 `uncurry`
         -      ((flip `liftM` (flip liftM2)) `uncurry`)
         -      uncurry ((flip `liftM` (flip liftM2)))
         -      uncurry (liftM flip (flip liftM2))
         -
         - This takes as input a pair of monads a 2 parameter function.
         - It lifts up the function to a monad and applies it to the input pair:
         -      uncurry (liftM flip (flip liftM2)) (Just 10, Just 20) (+)   --> Just 30
         -
         - fmap (+3) [1, 2, 3]   --> [4,5,6]
         -
         - <**> is the same as <*> but with parameters flipped:
         -      Just (+3) <*> Just 5        --> Just 8
         -      Just 5 <**> Just (+3)       --> Just 8
         - 
         - (<>) is an alias for mappend
         -
         - Just (+) <*> Just 5 <*> Just 9    --> Just 14
         - (+) <$> Just 5 <*> Just 9         --> Just 14
         -
         - (&) is a reverse application operator. & can be nested in $: 4 & (+3) == (&) 4 (+3) --> 7
         -
         - Rewrite the 2nd part as:
         -      fmap unsafeCoerce $ swap <**> mappend $ (&) <$> [0..39] & pure
         -      fmap unsafeCoerce $ swap <**> mappend $ ((&) <$> [0..39]) & pure
         -      fmap unsafeCoerce $ swap <**> mappend $ pure ((&) <$> [0..39])
         -      fmap unsafeCoerce $ mappend <*> swap $ pure ((&) <$> [0..39])
         -      fmap unsafeCoerce (mappend <*> swap $ pure ((&) <$> [0..39]))
         -
         - swap <**> mappend == mappend <*> swap (see below what it does). It yields
         - a pair of monads (e.g., Just [1], Just [2]) (no input).
         -
         - The 2nd part: (mappend <*> swap $ pure ((&) <$> [0..39])) yields a pair of
         - lists: ([(a -> b) -> b], [(a -> b) -> b]). Each element contains a curried
         - function which is partially applied with a number in the range 0..39. For example:
         -      fst (mappend <*> swap $ pure ((&) <$> [0..39])) !! 0 $ id       --> 0
         -      fst (mappend <*> swap $ pure ((&) <$> [0..39])) !! 1 $ id       --> 1
         -      snd (mappend <*> swap $ pure ((&) <$> [0..39])) !! 12 $ (*2)    --> 24
         -      fst (mappend <*> swap $ pure ((&) <$> [0..39])) !! 12 $ (*2)    --> 24
         -
         - Adding the fmap unsafeCoerce cast it to type: `([(a -> b1) -> b1], b2)`
         -
         - Combining the 2 parts, the 2nd part supplies the pair that the 1st part requires
         - (curried function). What's the left is the function to be applied between the pair
         - elements. Hence the type of this line is:
         -      (((a -> b) -> b) -> a2 -> r) -> [r]
         -}
        <<< flip `liftM` flip liftM2 `uncurry` (
                fmap unsafeCoerce $ swap <**> (<>) $ (&) <$> [0..39] & pure) 
        {- Let's start with the type of ((.) or <<<):
         -      (a1 -> a2 -> t Bool) -> a1 -> a2 -> Bool
         -
         - It takes as input a 2 parameter function that returns a list of booleans, 
         - and 2 parameters. Then it applies these 2 parameters to the function to
         - get the list and finally applies the logic or. For example:
         -      ((.) or <<<) (\x y -> [x, y]) True False    --> True
         -      ((.) or <<<) (\x y -> [x, y]) False False   --> False
         -
         - Remember that `(<$>) (+2) (Just 5)` returns `Just 7` and (<$>) has type
         - `(a -> b) -> f a -> f b`. Then, `((.) or <<<) . (<$>)` has type:
         -      (a1 -> t Bool) -> (a2 -> a1) -> a2 -> Bool
         -
         - That is, it takes as input a parameter a2, a function that takes a2 and transforms
         - it to a1, and a function that takes a1 and transforms it to a boolean list. The final
         - result is a boolean.
         -}
        <<< ((.) or <<<) . (<$>) 
        (flip (<$>)
            -- This has type: `f a1 -> (a2 -> a1 -> b) -> a2 -> f b`.
            -- Example: (flip (<$>) >>> (.) ) (+100) (*) 2 3    --> 206
            >>> (.) $
            -- This simply returns the index of an element:
            --  ((>>> \[x] -> x) . flip elemIndices) [10..20] 15    --> 5
            --  ((>>> \[x] -> x) . flip elemIndices) [10..20] 10    --> 0
            (>>> \[x] -> x) . flip elemIndices 
            & 
            {- This is a lambda with ?? being the function parameter. Treat (??) as `x`.
             - For example: `4  & \(??) -> (??) + 9` returns `13`.
             - 
             - The input to this lambda function, is:
             -  ?? = (>>> \[x] -> x) . flip elemIndices = !!
             - 
             - So we can substitute (??) with (!!) in the functions below.
             -
             - NOTE: If element is not in the list, we get the following error:
             -      "Non-exhaustive patterns in lambda"
             -}
            \(??) -> 
                (.) . (>>>) . (. flip (??)) . ((.) (>=) .) . (>>>) 
                <*>
                (.) (<**>) . (<*>) . (.) (??) & 
                {- [(+1), (*9)] <*> [1, 2, 3]       --> [2,3,4,9,18,27]
                 -
                 - This returns a list of type: `[[Int] -> Int -> Int -> Bool]` and size 3
                 -
                 - We start from the first part. Rewrite as:
                 -      (.) . (>>>) . (. flip (??)) . ((.) (>=) .) . (>>>)
                 -      (.) . (>>>) . (. flip (!!)) . ((.) (>=) .) . (>>>)
                 -
                 -
                 - ((.) (>=) .) => Takes a function with 2 parameters, applies it to the next 2
                 -                 parameters and compares the result with the last parameter:
                 -                      ((.) (>=) .) (+) 2 2 4  --> True
                 -                      ((.) (>=) .) (+) 1 2 4  --> False
                 - (. flip (!!)) => Has type: (([c1] -> c1) -> c2) -> Int -> c2
                 -                  Example: (. flip (!!)) id 5 [10..20]    --> 15
                 -
                 - Let's combine the first line together:
                 -      (.) . (>>>) . (. flip (??)) . ((.) (>=) .) . (>>>) 
                 -
                 - Its type is quite complicated:
                 -      (a2 -> [a1]) -> (a3 -> (a2 -> Int -> Bool) -> c) -> a3 -> a1 -> c
                 -
                 - However by feeding some `id` functions we can simplify it a little bit:
                 -      :t ((.) . (>>>) . (. flip (??)) . ((.) (>=) .) . (>>>)) id id id
                 -          a -> [a] -> Int -> Bool
                 -
                 - The input here is an element of a list `x`, a list `L` and an index `i` to
                 - compare. Function checks whether: L.index(x) >= `i`. Examples:
                 -      (...) id id id 15 [10..20] 7     --> False
                 -      (...) id id id 15 [10..20] 4     --> True
                 -      (...) id id id 15 [10..20] 2     --> True
                 -
                 - Now let's combine all of it:
                 -  ((.) . (>>>) . (. flip (??)) . ((.) (>=) .) . (>>>) <*> 
                 -  (.) (<**>) . (<*>) . (.) (??))
                 -
                 - <**>: A variant of <*> with the arguments reversed.
                 -
                 - Type is: (a2 -> [a1]) -> (a2 -> a1) -> a1 -> a2 -> Bool
                 - The (Int -> [Int]) funtion, is actually the first element of the list
                 - declared in the \t lambda below (it contains the PRNs). It takes an
                 - index as input and returns a list with a valid permutation of [0..39].
                 -
                 - Let's see some simple examples:
                 -      fmap ((t (\x -> [12, 11, 10]) id) 10) [10..12]  --> [True,True,True]
                 -      fmap ((t (\x -> [12, 11, 10]) id) 11) [10..12]  --> [False,True,True]
                 -      fmap ((t (\x -> [12, 11, 10]) id) 12) [10..12]  --> [False,False,True]
                 -      fmap ((t (\x -> [12, 11, 10]) (+10)) 12) [0..2] --> [False,False,True]
                 -
                 - This function takes as input a function that yields a list (e.g., [12, 11, 10]),
                 - a function and 2 numbers. The function is applied to the last number. Then
                 - function searches for these 2 numbers in the list. For instance:
                 -     t (\x -> [12, 11, 10]) id 12 10      --> False
                 -
                 - 12 is in index 0 and 10 is on index 2. These 2 indices are compared with the <=
                 - operator. In our example, 0 (=12) > 2 (=10) so the answer is false.
                 -
                 - Note that this function will be the value of `t` in the lambda below. Thus we
                 - can substitute it.
                 -}
                \t -> [
                    {- (&) is the flipped version of ($): (&) 3 (*8) == 3 & (*8) --> 24
                     -
                     - A returns a function that takes a pair of lists and returns another pair of
                     -      lists: ([1,2,3..], [4,5,6])
                     - B returns a list of PRNs: [58870,306684,...]
                     -
                     - The second part `pure B & tail & (!!)` can be re-written as: `tail B !! $IDX`
                     -      
                     - `iterate (\(x,y) -> (x, y++[x])) (1, [7])`
                     -      [(1,[7]),
                     -       (1,[7,1]),
                     -       (1,[7,1,1]),
                     -       (1,[7,1,1,1]), 
                     -       ...]
                     -
                     - Rewrite as: 
                     -      [(&) $ id $ fst <$> A `iterate` pure B & tail & (!!)]
                     -      [(&) $ fst <$> A `iterate` pure B & tail & (!!)]
                     -      [(&) $ (fst <$> (iterate A pure B)) & tail & (!!)]
                     -
                     - iterate A pure B returns a list of pairs of lists:
                     -      [([], B[0:]), (perm of B[0:40], B[40:]),
                     -       (perm of B[40:80], B[80:]), ...]
                     -
                     - To understand why this happens, consider this:
                     -      (\(x,y) -> (x,y)) $ pure [0..10] --> ((),[0,1,2,3,4,5,6,7,8,9,10])
                     -
                     - This takes a list and puts in a default context ((), [[$LIST]). The first
                     - element is the context, which is initially empty (). The definition for
                     - this relies in GHC.Base:
                     -      instance Monoid a => Applicative ((,) a) where
                     -          pure x = (mempty, x)
                     -          ...
                     -
                     - That is, to make a list [a] applicative a function that takes a pair, pure
                     - gets it transformed into ((), [a]).
                     -
                     - Now consider this:
                     -      take 3 $ iterate (\(x,y) -> (x++y,y)) $ (pure [0..10]) -->
                     -          [([],[0,1,2,3,4,5,6,7,8,9,10]),
                     -           ([0,1,2,3,4,5,6,7,8,9,10],[0,1,2,3,4,5,6,7,8,9,10]),
                     -           ([0,1,2,3,4,5,6,7,8,9,10,0,1,2,3,4,5,6,7,8,9,10],
                     -            [0,1,2,3,4,5,6,7,8,9,10])]
                     -
                     - The first element of the list holds the context while the second one remains
                     - the same.
                     -
                     - For example: 
                     - take 40 $ fst ((aaa `iterate` pure bbb) !! 2) ==
                     - take 40 $ (fst <$> (aaa `iterate` pure bbb)) !! 2
                     -      [18,2,24,13,21,17,33,19,26,3,22,11,20,0,23,39,16,9,5,4,29,10,15,6,8,30,
                     -       1,31,27,12,32,35,38,37,14,25,28,7,34,36]
                     - take 40 $ snd ((aaa `iterate` pure bbb) !! 1)
                     -      [121646,235466,7853,99165,179344,175183,212108,379234,219429,167086,
                     -       186770,103420,268097,34083,367544,190406,164596,57744,1261,85947,
                     -       107450,56025,103036,154702,29895,368370,94729,248607,376811,179982,
                     -       228163,244067,307026,80466,379600,308758,396085,348488,313366,156773]
                     -
                     - As you can see, the smallest element in B[40:80] is "1261" which is located
                     - at the 18th (starting from 0) position. The next element is "7853" at 3rd
                     - position and so on. The first list contains the indices of elements sorted in
                     - ascending order.
                     - 
                     - After that, we do a `tail` to drop the item of the list (as it's the empty
                     - list) and then we do a `fst` to get the first list of each pair (i.e., the
                     - one with the permutation). Finally we use the list indexing (!!) to select
                     - the i-th permutation from this set which is a list of 40 integers. That is,
                     - the:
                     -      `(&) $ (fst <$> (iterate A pure B)) & tail & (!!)]`
                     -
                     - is a function `Int -> [Int]` that takes an index `i` and returns the i-th
                     - permutation of this list of pairs of lists.
                     -
                     - However, the use of (&) makes this function an input as it now has a type of:
                     -      `((Int -> [Int]) -> b) -> b`
                     -
                     - Please note that this list has infinity elements!
                     -}
                    (&) $ id $ fst <$> 
                    {- comparing (+1) 2 3 == compare (2+1) (3+1)
                     - Rewrite as: sortBy (comparing ((!!) $_40_ELT_ARRAY_INP)) [0..39]
                     - 
                     - Example: sortBy (comparing ((!!) [2,0,5,0,1,0])) [0..5]  --> [1,3,5,4,0,2]
                     -     Third element (2) goes to the rightmost position
                     -          (it has the biggest index: 5)
                     -     First element (0) goes to the 2nd rightmost position
                     -          (it has the 2nd biggest index: 2)
                     -     Fifth element (4) goes to the 3rd rightmost position
                     -          (it has the 3rd biggest index: 1)
                     -
                     - That is, it yields a valid permutation of numbers 0..39
                     - 
                     - `const 1 ^>> total` is shorthand for `arr (const 1) >>> total`
                     - (<>) is an alias for mappend
                     -
                     - Operator associativity (e.g., ":i >>="):
                     -    .     infixr 9
                     -    <>    infixr 6
                     -    <*>   infixl 4
                     -    ***   infixr 3 
                     -    ^>>   infixr 1
                     -    <<<   infixr 1
                     -    $     infixr 0
                     -
                     - return . snd => (a1, a2) -> m a2
                     - mappend <*> swap $ (Just [1], Just [2]) -> (Just [1,2], Just [2,1])
                     -      --> Explained: `mappend` for functions defined as:
                     -              `h >>= f = \w -> f (h w) w`
                     -          Therefore, when we apply swap to mappend we get:
                     -              mappend (swap (Just [1], Just [2])) (Just [1], Just [2]) =>
                     -              mappend (Just [2], Just [1]) (Just [1], Just [2]) =>
                     -              (Just [1,2], Just [2,1])
                     -          
                     - Rewrite `return . snd ^>> (<>) <*> swap` as:
                     -      arr (return . snd) >>> mappend <*> swap =>
                     -      mappend <*> swap <<< arr (return . snd)
                     -
                     - This code simply duplicates and returns the 2nd element of the pair:
                     -      mappend <*> swap <<< arr (return . snd) $ ([1], [2]) --> ([2],[2])
                     -
                     - All together this line takes a pair ([a], [b]), it duplicates the second
                     - element to create a new pair ([b], [b]). Then it passes it to 2 arrows: The
                     - `drop 40` that drops the first 40 elements from the list and the permutation
                     - arrow. The result from the `***` operator is a pair ([c], [d]), where [c] is
                     - a valid permutation of the first 40 elements of [b] and [d] contains all the
                     - remaining elements from [b]. [a] is totally ignored (due to snd), so we can
                     - consider its presence as an obfuscation attempt. Example:
                     -
                     - (flip sortBy [0..39] . comparing . (!!) *** drop 40 <<< return . snd 
                     -      ^>> (<>) <*> swap) 
                     -          $ ([0..], [7]++[0..6]++[8..49])
                     -              --> ([1,2,3,4,5,6,7,0,8,9,10,...,38,39],
                     -                   [40,41,42,43,44,45,46,47,48,49])
                     -}
                    (flip sortBy [0..39] . comparing . (!!) *** drop 40 
                        <<< return . snd ^>> (<>) <*> swap) -- =A
                    `iterate`
                    {- take 10 (iterate (2*) 1) --> [1,2,4,8,16,32,64,128,256,512]
                     -
                     - Rewrite as:
                     -     (tail $ flip iterate 44 $ flip mod 400013 <$> (+) 42 . (*) 1337)
                     -     (tail (flip iterate 44 $ flip mod 400013 <$> (+) 42 . (*) 1337))
                     -     (tail (flip iterate 44 (flip mod 400013 <$> (+) 42 . (*) 1337)))
                     -     (tail (iterate (flip mod 400013 <$> (+) 42 . (*) 1337) 44))
                     -     (tail (iterate (flip mod 400013 <$> (+42) . (*1337)) 44))
                     -     (tail (iterate (flip mod 400013 <$> (\x -> x*1337 + 42)) 44))
                     -     (tail (iterate (flip mod 400013 <$> (\x -> x*1337 + 42)) 44))
                     -     (tail (iterate (\x -> (x*1337 + 42) `mod` 400013) 44))
                     -
                     - This generates an infinity list of a pseudo-random numbers: Starting from 44,
                     - we generate the next number as x' = 1337*x + 42 mod 400013. We finally drop
                     - the first element which is 44. The first 10 output elements are:
                     -     [58870,306684,23225,250866,196990,167118,229554,103769,334697,275397]
                     -}
                    pure (tail $ flip iterate 44 $ flip mod 400013 <$> (+) 42 . (*) 1337) -- =B
                    & tail & (!!)
                ] <*> [
                    {- t is the lambda parameter. It is defined as (see the definition of \t above):
                     -      t = (.) . (>>>) . (. flip (??)) . ((.) (>=) .) . (>>>) <*> 
                     -          (.) (<**>) . (<*>) . (.) (??)
                     -
                     - Type: (Int -> [a1]) -> [a1] -> Int -> a1 -> Bool
                     -  (the first part: (Int -> [a1]), is the output of previous list that returns
                     -   the PRNs. Let `func` be this function).
                     -
                     - Let's see some examples. We first start with `func 0` which returns the 1st
                     - list of PRNs: [27,37,2,16,34,18,35,0,24,39,7,19,31,23,5,28,12,10,4,6,17,26,
                     -                36,33,3,38,32,9,14,25,1,13,22,21,8,30,15,29,20,11]
                     -
                     - Then we say: `(fmap (t func id) [0..39]) <*> [0]`
                     - That is, we test all values from 0 to 39 in the first parameter and we keep
                     - the 2nd parameter always 0. The output is:
                     -      [True,True,False,True,True,True,True,True,True,True,True,True,True,
                     -       True,True,True,False,True,False,True,True,True,True,True,True,True,
                     -       True,False,True,True,True,True,True,True,False,False,True,False,True,
                     -       True]
                     - 
                     - Function: fmap (((<<^) flip <<< t >>> ((!!) >>>)) func [0..39] 0) [0..39]
                     - give us the exact same result.
                     -
                     - As you can see only 7 values are False, which the number of elements before
                     - 0 (located at the 7-th position). Let's take the 2nd element (True): We take
                     - the index where 0 is located, which is 7 and we compare it (using <=) with
                     - the index where 1 is located, which is 30. The result is True (7 <= 30).
                     - Then we take the 3rd element (False): We compare 7 (where 0 is located) with
                     - 2 (where 2 is located). The result is False (7 > 2). 
                     -
                     - Overall, function takes a list `L` and 2 numbers `i` and `j` and checks if:
                     -      PRN_i.index(L[i]) <= PRN_i.index(j)
                     -}
                    (<<^) flip <<< t >>> ((!!) >>>), 
                    {- Rewrite as:
                     -      (.) (==) <$> (!!) & return
                     -      return ((.) (==) <$> (!!))
                     -      return (((.) (==)) <$> (!!))
                     -
                     - ((.) (==)) (*2) 1 4      --> False
                     - ((.) (==)) (*2) 2 4      --> True
                     - Same as: (==) . (*2) 
                     - That is, the first parameter of == gets multiplied by 2 before the
                     - comparison.
                     -
                     - To understand what (.) (==) <$> (!!) does, we have to look at the definition
                     - of applicative for functions:
                     -      instance Applicative ((->) a) where
                     -          pure = const
                     -          g <*> h = \x -> g x (h x)
                     -
                     - This is similar to function composition: First we apply the input to (!!)
                     - function (h in our case) which returns the index of a list. Then we do the
                     - comparison (f is the (==) .). 
                     -
                     - In a nutshell, this function takes as input a list `L`, an index `i` to that
                     - list and a number `C` and checks if L[i] == C. For Example:
                     -      ((.) (==) <$> (!!)) [1, 2, 3, 4] 0 1        --> True
                     -      ((.) (==) <$> (!!)) [1, 2, 3, 4] 0 2        --> False
                     -      ((.) (==) <$> (!!)) [1, 2, 30, 4] 2 30      --> True
                     -
                     - Finally, the result is wrapped into a monad (with a return).
                     -
                     - Type: m ([a] -> Int -> a -> Bool)
                     -}
                    (.) (==) <$> (!!) & return,
                    {- (??) is the lambda parameter. It is defined as:
                     -      ?? = (>>> \[x] -> x) . flip elemIndices
                     - Which is essentially the indexing operation `!!`.
                     -
                     - Rewrite as:
                     -      (>>>) (??) . t <<< (. (+40))
                     -      ((>>>) (??) . t) <<< (. (+40))
                     -
                     - The last part (. (+40)) is a curried function composition:
                     -      (. (+40)) (*2) 3 == ((*2) . (+40)) 3    --> 86
                     - The input to this is a function (a -> b) and a number `a`.
                     -
                     - The +40 is applied to the index. That is instead of selecting the i-th PRN
                     - block, we select the i+40 PRN.
                     -
                     - To understand why this is true, we use Debug.Trace.trace. First we redefine
                     - the PRNs (i.e. LCG) as follows:
                     -      let lcg i = trace("LCG: " ++ show i) (fst <$> (flip sortBy [0..39] .
                     -          comparing . (!!) *** drop 40 <<< return . snd ^>> (<>) <*> swap)
                     -          `iterate` pure (tail $ flip iterate 44 $ flip mod 400013
                     -          <$> (+) 42 .  (*) 1337) & tail & (!!)) i
                     -
                     - And then we redefine the output of \t (it returns a list with 3 elements,
                     - but we only get the last one):
                     -      let m = ([(&) $ id $ lcg] <*> [(>>>) (??) . t <<< (. (+) 40)]) !! 0
                     - 
                     - m has type: [Int] -> Int -> Int -> Bool
                     - 
                     - Let's play with it:
                     - m [0..39] 2 12
                     -      LCG: 52
                     -      LCG: 52
                     -      False
                     -
                     - As you can see we access twice the 40+12=52 PRN. We do this twice.
                     -
                     - Putting everything together, this function takes as input a list `L` and two
                     - numbers `i` and `j` and checks if:
                     -      PRN_(40 + j).index(i) >= PRNG_40 + j).index(L.index(j))
                     -}
                    (>>>) (??) . t <<< (. (+) 40)
                ]
            )
        {-
         - (.) has type:       (b -> c) -> (a -> b) -> a -> c
         - (.) . (.) has type: (b -> c) -> (a1 -> a2 -> b) -> a1 -> a2 -> c
         -
         - Hence: ((.) . (.) $ (+1)) (*) 4 5     --> 21
         -}
        . (>>>) (.) . (.) <<< (>>>)
        . (&) 
    ) 
    {-
     - maybe is a function (not to be confused with Maybe type)
     - maybe :: b -> (a -> b) -> Maybe a -> b
     -    Ex1: maybe "foo" show (Just 10) --> "10"
     -    Ex2: maybe "foo" show (Nothing) --> "foo"
     -
     - The maybe function takes a default value, a function, and a Maybe value. If the Maybe value
     - is Nothing, the function returns the default value. Otherwise, it applies the function to the
     - value inside the Just and returns the result.
     -
     - maybe "wrong" returns: (a -> [Char]) -> Maybe a -> [Char]
     - pure is Just in Maybe
     -
     - :t initAES         --> :: Data.Byteable.Byteable b => b -> AES
     - :t (>>> initAES)   --> :: Data.Byteable.Byteable b => (a -> b) -> a -> AES
     -
     - let a = initAES $ pack "123"
     - let b = (>>> initAES) (\x -> pack $ show x ++ " ispo") 123
     - let c = (>>> initAES . pack) (\x -> show x ++ " ispo") 123
     -
     - All this returns a function: Maybe a -> [Char]
     - maybe "wrong"
     -       (>>>)
     -       pure (>>> initAES(hash(pack(show a))) >>> decryptCTR (replicate 16 0) c)
     -       id
     -}
    . maybe
        "wrong"
        <$> (>>>) pure (
          {- initAES: Initialize a new AES context with a key (input: key): Byteable b => b -> AES
           - hash   : Hash a bytestring into a digest bytestring (SHA 256): ByteString -> ByteString
           - pack   : Convert String to ByteString                        : String -> ByteString
           - show   : Convert something to String                         : Show a => a -> String
           -
           - Rewrite as: initAES(hash(pack(show K)))
           - We get a key K derived from above. We cast it String, then to ByteString,
           - then we SHA256 it and then we use it as a key for an AES256.
           -}
          >>> initAES . hash . pack . show 
          {- decryptCTR: Counter-mode AES decrypt:
           -        Byteable iv => AES -> iv -> B.ByteString -> B.ByteString
           - args: AES context, IV, ciphertext (IN), plaintext (OUT)
           - flip: Reverses the first 2 arguments of a function: (a -> b -> c) -> b -> a -> c
           -   Example: flip (++) "1" "2" == ((++) `flip` "1") "2" == (++) "2" "1" => "21"
           -
           - Rewrite as: flip decryptCTR flip replicate 16 0 c =>
           -             flip decryptCTR c (replicate 16 0) =>
           -             decryptCTR (replicate 16 0) c
           - We use AES256-CTR to decrypt the ciphertext `c` using IV=0. 
           -}
          >>> decryptCTR `flip` replicate 16 0 `flip` c)
        <*> id
```

### Cracking the code

This code takes as input a list `perm` of 40 numbers that correspond to a valid permutation in the
range `0-39`. It then generates a boolean matrix of `40x40`. Verification succeeds if and only if
all entries are `True`. Each entry is the **logic OR** of `3` expressions:
```
1. LCG_i.index(perm[i]) <= LCG_i.index(j)
2. perm[i] == j
3. LCG_{40 + j}.index(i) >= LCG_{40 + j}.index(perm.index(j))
```

That is, we essentially have a [3-SAT](https://en.wikipedia.org/wiki/Boolean_satisfiability_problem) 
problem, which is the base problems for the NP-Completeness. Below is exactly how the `40x40`
boolean array for a given permutation `inp` is generated:
```python
def test_generate_bool_array(inp):
    bool_arr = []
    for j in range(40):
        for i in range(40):
            bool_arr.append(
                lcg(i).index(inp[i]) <= lcg(i).index(j) or
                inp[i] == j or
                lcg(40 + j).index(i) >= lcg(40 + j).index(inp.index(j))
            )

    return bool_arr
```

Since we are dealing with an NPC problem we cannot do anything else that using an SMT solver (z3).
The unknown variables will be the `40` numbers in the input equation. We add further constraints
to ensure that the correspond to a valid permutation:
```python
perm_x = [z3.Int('p%d' % i) for i in range(40)]

for i, p in enumerate(perm_x):
    smt.add(z3.And(p >= 0, p <= 39))
    smt.add(z3.And([p != pp for (j, pp) in enumerate(perm_x) if i < j]))
```

However we have a problem here: In the last equation, we want to calculate `perm_x.index(j)`, 
where `j` is a constant number. However `perm_x` is an array of symbolic variables. To solve this
problem we have to notice that if `perm_x.index(j) == k` then it means that the symbolic variable
`P_j` (located at the `j`-th position of the array must be `k`.

Since we do not know which is the correct value for `k`, we just have to try them all possible
values (they are `40`) and combine them with a logic OR. That is, instead of adding a
`(a || b || c)`constraint, we now add:
`P_j == 0 && (a || b || c) || P_j == 1 && (a' || b' || c') ...`

This blows up the number of equations by an order which means that we now have `40*40*40` or 
`64000` equations. Although this slows down the solution, we can still get the solution in `~2`
minutes. The correct permutation is:
```
37,33,4,3,38,23,14,9,36,12,0,22,39,32,16,19,35,5,6,27,25,8,13,31,30,24,34,11,29,21,26,2,7,17,1,10,20,18,15,28
```

To get the flag, we first convert the permutation into a string:
```
"[37,33,4,3,38,23,14,9,36,12,0,22,39,32,16,19,35,5,6,27,25,8,13,31,30,24,34,11,29,21,26,2,7,17,1,10,20,18,15,28]"
```

And then we supply it to `SHA256` to get the AES key:
```
d906fcb5f324e486fdb4327c082e00d67653742e142f5a3a20c98349a661b03c
```

Then we feed this key into AES countermode along with the ciphertext:
```
\xd7\xc8\x35\x14\xc4\x27\xcd\x6f\x78\x3a\x80\x57\x76\xb0\xfd\x42
\x25\xe4\x87\x5f\x99\x28\x87\x0a\x06\xef\x63\x81\x44
```

And we get the flag: `hxp{r34dAb1liTy_1s_p01nTl3s5}'`

For more details, please take a look at the [crack](./crack) file.

___
