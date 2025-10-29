## HITCON CTF 2025 - Sharing is caring (Reversing, Crypto 248)
##### 22/08 - 24/08/2025 (48hr)
___

### Description

I just want to share my flag with you. I'm sooo kind.

```
https://github.com/hitconctf/ctf2025.hitcon.org/releases/download/v1.0.0/sharing-is-caring-43396ecc7c0bec3f84a6f42bdf9c085fde9916f6.tar.gz
```
___

### Solution

We use [PyLingual](https://pylingual.io/) to decompile `chal.pyc`. However it is heavily obfuscated:
```python
def \r\r\n (continue):
    if continue in (17, 18):
        return 18 - continue
    from fractions import Fraction as F
    \r \r\n = len(\r\r\r\t)
    \r\n\n  = F(0, 1)
    \r\r\n\t = F(1, 1)
    for \r\r\t\n in range(\r \r\n):
        \r\n\n  += F(\r\r\r\t[\r\r\t\n], return[\r\r\t\n]) * \r\r\n\t
        \r\r\n\t *= F(continue - \r\r\t\n, 1)
    return int(\r\n\n )
try = \r\r\n (0)
else = \r\r\n (1)
\r\r\t\r = \r\r\n (2)
\r\n\r\t = \r\r\n (3)
async = [\r\r\n (4), \r\r\n (5), \r\r\n (6)]
\r  \n = [(\r\r\n (7), \r\r\n (8), \r\r\n (9)), (\r\r\n (10), \r\r\n (11), \r\r\n (12)), (\r\r\n (13), \r\r\n (14), \r\r\n (15))]
while = \r\r\n (16)
# ....    
```

The first problem is the variable names. They consist of whitespaces (e.g., `\r\r\n `) or python
keywords (e.g., `try`). So our first step is to rename all variables:
```python
from fractions import Fraction as F

def func_1(arg):
    if arg in (17, 18):
        return 18 - arg
    
    sz = len(ARRAY)
    s = F(0, 1)
    b = F(1, 1)
    for i in range(sz):
        s += F(ARRAY[i], return_[i]) * b
        b *= F(arg - i, 1)
    return int(s)

A = func_1(0)
B = func_1(1)
C = func_1(2)
D = func_1(3)
E = [func_1(4), func_1(5), func_1(6)]
FF = [(func_1(7), func_1(8), func_1(9)), (func_1(10), func_1(11), func_1(12)), (func_1(13), func_1(14), func_1(15))]
G = func_1(16)    
```

### Fixing the Decompiled Output

Unfortunately, renaming all variables is not enough: the `return` array is used in `\r\r\n ()` but
it is not defined anywhere in the decompiled code! But it should be defined somewhere right?
Let's have a look at the original bytecode:
```
8 BUILD_LIST 0

10 LOAD_CONST 1 ((1, 1, 2, 2, 12, 15, 10, 240, 40320, 362880, 403200, 7983360, 11975040, 37065600, 12454041600L, 43589145600L, 3487131648000L, 302455296000L, 213412456857600L, 20274183401472000L, 2432902008176640000L, 12772735542927360000L, 281000181944401920000L, 738629049682427904000L, 26976017466662584320000L, 5170403347776995328000000L, 16803810880275234816000000L, 640521732377550127104000000L))
12 LIST_EXTEND 1
14 STORE_NAME 1 (return)
16 LOAD_CONST 2 (code object
```

So the `return` array is a factorial-style array as shown below:
```python
return_ = (1, 1, 2, 2, 12, 15, 10, 240, 40320, 362880, 403200, 7983360, 11975040, 37065600, 12454041600, 43589145600, 3487131648000, 302455296000, 213412456857600, 20274183401472000, 2432902008176640000, 12772735542927360000, 281000181944401920000, 738629049682427904000, 26976017466662584320000, 5170403347776995328000000, 16803810880275234816000000, 640521732377550127104000000)
```

There is also another problem: Let's look at function `\r\t\n\r()` (after clean-up):
```python
def func_7(arg):
    if not isinstance(arg, (list, tuple)) or len(arg) < func_1(19):
        return False
    a = {b: (d1, d2) for b, d1, d2 in FF}
    for i1, i2,i3 in arg:
        a[i1] = (i2,i3)
    if len(a)!= func_1(20):
        return False
    for i1, (j, k) in a.items():
        if not func_5(i1, j, k):
            return False
    else:  # inserted
        q = {a for a, b, c in arg[:func_1(19)]}
        p = [(e, a[e][func_1(18)]) for e in sorted(q) if e in a]
        r = [(f1, f2) for f1, f2, f3 in FF if f1 not in q]
        arr = []
        if p:
            arr.append(p[func_1(18)])
        arr.extend(r[:func_1(21)])
        if len(arr) < func_1(19):
            arr = list(((o, u) for o, (u, s) in sorted(a.items())))[:func_1(19)]
        w = func_1(18)
        for ii, (jj, kk) in enumerate(arr):
            t, v = (func_1(17), func_1(17))
            for o, (x, y) in enumerate(arr):
                if ii == o:
                    continue
                t = func_3(t, -x) % B
                v = func_3(v, jj - x) % B
            u = func_3(t, func_6(v, B)) % B
```

This function does not return `True`. And the `else:` branch is after the `for` loop, which does not
seem to compute anything which is used. To get the goodboy messsage, `func_7()` needs to return
`True`:
```python
if __name__ == '__main__':
    inp1 = int.from_bytes(input('1:').strip().encode())
    inp2 = int.from_bytes(input('2:').strip().encode())
    inp3 = int.from_bytes(input('3:').strip().encode())
    if func_7(
        (
            [func_1(22), inp1, func_1(23)],
            [func_1(24), inp2, func_1(25)],
            [func_1(26), inp3, func_1(27)]
        )
    ):
        print('Success!')
    else:  # inserted
        print('Fail')
```

The decompiler did not do a good job here. There is probably more information in the bytecode.
Let's try to find the last instruction from `func_7()` in the bytecode, which is:
```python
u = func_3(t, func_6(v, B)) % B

# Or, with the original names:
\r\t\r = \n\r\r\n(\r\n\n\n, class(False, else)) % else
```

The bytecode for the above instruction is shown below:
```
542 LOAD_GLOBAL 25 (NULL +   )
544 LOAD_FAST 25 (   )
546 LOAD_GLOBAL 29 (NULL + class)
548 LOAD_FAST 26 (False)
550 LOAD_GLOBAL 26 (else)
552 CALL 2
554 CALL 2
556 LOAD_GLOBAL 26 (else)
558 BINARY_OP 6 (%)
560 STORE_FAST 30 (  )
```

> **NOTE:** Calling convention in Python is **left-to-right** order. That is, the **1st** parameter
pushed onto the stack is the first argument of the function.

However, there is a lot of code **after** this instruction which is not shown in the decompiled
output:
```
562 LOAD_FAST 21 (   )              # `438 STORE_FAST 21` is right before 1st enumerate() => co_varnames[21] = w
                                    # push w
564 LOAD_GLOBAL 25 (NULL +   )      # push co_names[25 >> 1] = \n\r\r\n() or func_3()
566 LOAD_FAST 24 (if)               # push `if` or kk
568 LOAD_FAST 30 (  )               # push `\r\t\r` (output from last instruction)
570 CALL 2                          # func_3(kk, u)
572 BINARY_OP 0 (+)                 # w + func_3(kk, u)
574 LOAD_GLOBAL 26 (else)           # push `else` or B
576 BINARY_OP 6 (%)                 # 
578 STORE_FAST 21 (   )             # w = (w + func_3(kk, u)) % B
580 JUMP_BACKWARD 157 (to 446)      #
582 END_FOR                         # first for loop ends (`for ii, (jj, kk) in enumerate(arr):`)

584 LOAD_GLOBAL 31 (NULL + elif)    # push func `elif()`or func_4()
586 LOAD_GLOBAL 32 (   )            # push one of the global vars with whitespaces;
                                    # it's not an array, or function, so it's `\r\r\t\r` or `\r\n\r\t`
                                    # we look at .__code__.co_names and only `\r\r\t\r` is there
                                    # push `\r\r\t\r` or C
588 LOAD_FAST 21 (   )              # push w
590 LOAD_GLOBAL 34 (try)            # push `try` or A
592 CALL 3                          # func_4(C, w, A)
594 LOAD_GLOBAL 36 (while)          # push `while` or G
596 COMPARE_OP 40 (==)              # 
598 RETURN_VALUE                    # return G == func_4(C, w, A)

600 SWAP 2                          # We don't need these instructions (they're garbage).
602 POP_TOP                         # Perhaps that's the reason why decompiler fails.
604 SWAP 4                          #
606 STORE_FAST 3 (yield)            #
608 STORE_FAST 2 (   )              #
610 STORE_FAST 1 (  )               #
612 RERAISE 0                       #
614 SWAP 2                          #
616 POP_TOP                         #
618 SWAP 4                          #
620 STORE_FAST 12 ( )               #
622 STORE_FAST 11 (raise)           #
624 STORE_FAST 10 (and)             #
626 RERAISE 0                       #
628 SWAP 2                          #
630 POP_TOP                         #
632 SWAP 2                          #
634 STORE_FAST 14 (   )             #
636 RERAISE 0                       #
638 SWAP 2                          #
640 POP_TOP                         #
642 SWAP 4                          #
644 STORE_FAST 18 (   )             #
646 STORE_FAST 17 (  )              #
648 STORE_FAST 16 (  )              #
650 RERAISE 0                       #
```

One challenge we have here, is the instruction `LOAD_GLOBAL 32 (   )`. We do not know which global
variable is being loaded because the name is obfuscated with whitespaces. The index **32** is
function specific, so we cannot search for other global references in the bytecode. However, there
are only **2** global variables with whitespaces: `\r\r\t\r` and `\r\n\r\t`. We run the following
little script to get the `co_names` from all functions:
```python
import importlib.util
import types 

spec   = importlib.util.spec_from_file_location('ispo', 'dist/chal.pyc')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

# Iterate over all functions.
for name, obj in module.__dict__.items():
    if isinstance(obj, types.FunctionType):
        print(f'[+] function {name!r}. co_names: {obj.__code__.co_names}')
```

> **NOTE:** We use **Python 3.12** to run the script. Otherwise we get a bad magic number error.
> Magic number is `\xcb\r\r\n` so the `*.pyc` was compiled with **Python 3.12**. You can install
> it as `apt install python3.12`

```
[+] function '\r\r\n '. co_names: ('fractions', 'Fraction', 'len', '\r\r\r\t', 'range', 'return', 'int')
[+] function '\r \t\n'. co_names: ('\r\r\n ',)
[+] function '\n\r\r\n'. co_names: ('\r\r\n ', '\n\r\r\n')
[+] function 'elif'. co_names: ('\r\r\n ', '\n\r\r\n')
[+] function 'await'. co_names: ('\n\r\r\n', 'elif', '\r\r\t\r', 'try', '\r\n\r\t', '\r\r\n ', 'async', 'else')
[+] function 'class'. co_names: ('\r\r\n ', '\n\r\r\n')
[+] function '\r\t\n\r'. co_names: ('isinstance', 'list', 'tuple', 'len', '\r\r\n ', '\r  \n', 'items', 'await', 'sorted', 'append', 'extend', 'enumerate', '\n\r\r\n', 'else', 'class', 'elif', '\r\r\t\r', 'try', 'while')
```

The function `func_7()` is originally named `\r\t\n\r`. We see that only the global `\r\r\t\r` is
presented in the `co_names`, os the variable we are looking for is `C`.

After all, the **2** missing instructions of `func_7()` are:
```python
    for ii, (jj, kk) in enumerate(arr):
        # ....
        u = func_3(t, func_6(v, B)) % B
        w = (w + func_3(kk, u)) % B  # <-- this

    return G == func_4(C, w, A)  # <-- and this
```

### Understanding the Code

At this point we have reconstructed and decompiled the original python script. Let's now try to
understand what all these functions are doing and give them meaningful names. We start with
`\r\r\n ` or `func_1()`:
```python
\r\r\r\t = [ ... ]

def \r\r\n (continue):
    if continue in (17, 18):
        return 18 - continue
    from fractions import Fraction as F
    \r \r\n = len(\r\r\r\t)
    \r\n\n  = F(0, 1)
    \r\r\n\t = F(1, 1)
    for \r\r\t\n in range(\r \r\n):
        \r\n\n  += F(\r\r\r\t[\r\r\t\n], return[\r\r\t\n]) * \r\r\n\t  # return is defined in *.pyc
        \r\r\n\t *= F(continue - \r\r\t\n, 1)
    return int(\r\n\n )

# ----------------------------------------------------------
from fractions import Fraction as F

def func_1(arg):
    if arg in (17, 18):
        return 18 - arg
    
    sz = len(ARRAY)
    s = F(0, 1)
    b = F(1, 1)
    for i in range(sz):
        s += F(ARRAY[i], return_[i]) * b
        b *= F(arg - i, 1)  # Factorial until arg == i then b always 0
    return int(s)
```

This function computes from constant values, given an input `arg`. The maximum argument for
`func_1()` in the program is **27**. That is, we can just dump all input-output pairs:
```
func_1(0) = 4144803293417776131310451317495228706499130241044716671850484110288180082374299088166459295448719
func_1(1) = 2072401646708888065655225658747614353249565120522358335925242055144090041187149544083229647724359
func_1(2) = 1402769202505631727601810730581776197716350949074282314174097681867464170562021714349605843278664
func_1(3) = 1335174568503939352563889373190143608146136792487939183543780907770759908268721571509488188235873
func_1(4) = 442427645836698445267007097625472942305363362863130591746066528455945891079759637465163543741507
func_1(5) = 1132891618999846053017541510085320021631035459029704515373044135313614915469753666299478525789537
func_1(6) = 3440625422497330758356285966425842805899353260932540945262402832827054563258418833844309632149096
func_1(7) = 51966
func_1(8) = 480442839669953990717445646260333383833736214883976558477525831992994289143305421629761482429714
func_1(9) = 680701978345522085049694956190292511497787092168524280991013677878931201637910598103187515536181
func_1(10) = 47806
func_1(11) = 253717457675323180603201716971045682091261518437666533915787790782521696917056900361404824269689
func_1(12) = 99768326317759269813131181172947299870925613919195157126671930387206518545837120733862757382354
func_1(13) = 201527
func_1(14) = 782319055923618868639890136618720319997476308047895888006842867173403800015590219030945524995543
func_1(15) = 944213788775446264472010893716848921879528565854393198519311752189219209422386607874556309845161
func_1(16) = 865967982817260602973374066425323583617367103807916127263320767485154348516392723060969424214055
func_1(17) = 1
func_1(18) = 0
func_1(19) = 3
func_1(20) = 6
func_1(21) = 2
func_1(22) = 4919
func_1(23) = 132146363252892079238955852043754382244951307426448497798760465957265430114543661757753602857394
func_1(24) = 57005
func_1(25) = 775309903033854570882823603825659470664893675806480830434450057789819902048494192286724670375083
func_1(26) = 48879
```

Please note that values **17** to **21** are very small and used to obfuscated constants in the
program.

Then we have `\r \t\n`  or `func_2()` which implements an **adder**:
```python
def \r \t\n(with, \n\r\r ):
    while \n\r\r :
        \r\n\r  = with & \n\r\r 
        with = with ^ \n\r\r 
        \n\r\r  = \r\n\r  << \r\r\n (17)
    return with

# ----------------------------------------------------------
def f_add(arg1, arg2):
    """This is an adder."""
    while arg2:
        carry = arg1 & arg2
        arg1  = arg1 ^ arg2
        arg2  = carry << 1  # func_1(17) is 1

    return arg1
```

Then we move on to the next function which implements a **multiplier**:
```python
def \n\r\r\n(\r\r \r, \r\n\t\n):
    if \r\n\t\n < \r\r\n (18):
        return -\r\r\n (17) * \n\r\r\n(\r\r \r, -\r\n\t\n)
    \r\n   = \r\r\n (18)
    while \r\n\t\n:
        \r\n   += \r\r \r if \r\n\t\n & \r\r\n (17) else \r\r\n (18)
        \r\r \r <<= \r\r\n (17)
        \r\n\t\n >>= \r\r\n (17)
    return \r\n  

# ----------------------------------------------------------
def f_mul(arg1, arg2):
    """This is integer multiplication."""
    # func_1(17) is 1 and func_1(18) is 0. Replace accordingly.
    if arg2 < 0:
        return -f_mul(arg1, -arg2)

    prod = 0
    while arg2:
        prod += arg1 if arg2 & 1 else 0
        arg1 <<= 1
        arg2 >>= 1

    return prod    
```

The next function is a `pow()` (**power (fast exponentiation) with modulo**):
```python
def elif(\r \r\r, \r\r\t , nonlocal):
    \r \n\n = \r \r\r
    \n\r\n\n = \r\r\n (17)
    while \r\r\t :
        if \r\r\t  & \r\r\n (17):
            \n\r\n\n = \n\r\r\n(\n\r\n\n, \r \n\n)
        \n\r\n\n %= nonlocal
        \r \n\n = \n\r\r\n(\r \n\n, \r \n\n)
        \r \n\n %= nonlocal
        \r\r\t  >>= \r\r\n (17)
    return \n\r\n\n

# ----------------------------------------------------------
def f_pow(arg1, arg2, arg3):
    """This is fast exponentiation: arg1^^arg2 % arg3"""
    # func_1(17) is 1. Replace accordingly.
    e = arg1
    p = 1

    while arg2:
        if arg2 & 1:  # If LSBit is set, multiply product with e.
            p = f_mul(p, e)

        p %= arg3
        e = f_mul(e, e)  # e^^X 
        e %= arg3
        arg2 >>= 1  # Move on to the next bit

    return p
```

Next we have `await()`, that implements a
**[Digital Signature Algorithm (DSA)](https://en.wikipedia.org/wiki/Digital_Signature_Algorithm)
verification** on **3** messages, that uses some global constants:
```python
try = \r\r\n (0)
else = \r\r\n (1)
\r\r\t\r = \r\r\n (2)
\r\n\r\t = \r\r\n (3)
async = [\r\r\n (4), \r\r\n (5), \r\r\n (6)]


def await(\r\n \r, \n\r\r\r, \r\t\t\t):
    \r\r\n\r = \n\r\r\n(elif(\r\r\t\r, \n\r\r\r, try), elif(\r\n\r\t, \r\t\t\t, try)) % try
    pass = \r\r\n (17)
    \r\n\n\t = \r\r\n (17)
    for \r\t\t\r in async:
        pass = \n\r\r\n(pass, elif(\r\t\t\r, \r\n\n\t, try)) % try
        \r\n\n\t = \n\r\r\n(\r\n\n\t, \r\n \r) % else
    return \r\r\n\r == pass

# ----------------------------------------------------------
DSA_p = func_1(0)
DSA_q = func_1(1)
DSA_g = func_1(2)
DSA_y = func_1(3)
DSA_M = [func_1(4), func_1(5), func_1(6)]

def f_dsa(h, u1, u2):
    """This is DSA (Digital Signature Verification)."""
    # https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
    # u = g^u1 * y^u2 mod p
    u = f_mul(f_pow(DSA_g, u1, DSA_p), f_pow(DSA_y, u2, DSA_p)) % DSA_p
    r = 1  # func_1(17) is 1
    c = 1  # func_1(17) is 1

    for m in DSA_M:  # Verify each (fixed) message.
        r = f_mul(r, f_pow(m, c, DSA_p)) % DSA_p  # r *= m^c % p
        c = f_mul(c, h) % DSA_q                   # c *= h % q

    return u == r 
```

Then we have `class()` that implements an
**[Extended GCD](https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm)** without recursion:
```python
def class(in, finally):
    \n\r\n\r, \r\r\n\n = (\r\r\n (17), \r\r\n (18))
    \r\t\r\n, \r\t\n\t = (in % finally, finally)
    while \r\t\r\n > \r\r\n (17):
        \r\n\t\r = \r\t\n\t // \r\t\r\n
        \r \t\r, \r\t   = (\r\r\n\n - \n\r\r\n(\n\r\n\r, \r\n\t\r), \r\t\n\t - \n\r\r\n(\r\t\r\n, \r\n\t\r))
        \n\r\n\r, \r\t\r\n, \r\r\n\n, \r\t\n\t = (\r \t\r, \r\t  , \n\r\n\r, \r\t\r\n)
    return \n\r\n\r % finally

# ----------------------------------------------------------
def f_ext_gcd(arg1, arg2):
    """This is extended GCD (non-recursive version)."""
    a, b = (1, 0)  # (func_1(17), func_1(18))
    r, prev_r = (arg1 % arg2, arg2)  # That looks like GCD!

    while r > 1:  # func_1(17) is 1
        quotient = prev_r // r
        x = b - f_mul(a, quotient)
        y = prev_r - f_mul(r, quotient)
        a, r, b, prev_r = (x, y, a, r)

    return a % arg2  # g
```

Finally, we have a custom function `\r\t\n\r` that does the actual check of the input:
```python
\r  \n = [(\r\r\n (7), \r\r\n (8), \r\r\n (9)), (\r\r\n (10), \r\r\n (11), \r\r\n (12)), (\r\r\n (13), \r\r\n (14), \r\r\n (15))]
while = \r\r\n (16)

def \r\t\n\r(\r  \t):
    if not isinstance(\r  \t, (list, tuple)) or len(\r  \t) < \r\r\n (19):
        return False
    import = {\r\n \n: (\n\r\t\r, yield) for \r\n \n, \n\r\t\r, yield in \r  \n}
    for \n\r\n , \r\r\r\r, \r\t \t in \r  \t:
        import[\n\r\n ] = (\r\r\r\r, \r\t \t)
    if len(import)!= \r\r\n (20):
        return False
    for \n\r\n , (assert, \n\r\t\n) in import.items():
        if not await(\n\r\n , assert, \n\r\t\n):
            return False
    else:  # inserted
        \r\r\r  = {and for and, raise, \r\t\t  in \r  \t[:\r\r\n (19)]}
        \r \t  = [(\r\t\r\r, import[\r\t\r\r][\r\r\n (18)]) for \r\t\r\r in sorted(\r\r\r ) if \r\t\r\r in import]
        global = [(\r \r\t, \r\t\t\n) for \r \r\t, \r\t\t\n, \r \n\r in \r  \n if \r \r\t not in \r\r\r ]
        \r\n\r\n = []
        if \r \t :
            \r\n\r\n.append(\r \t [\r\r\n (18)])
        \r\n\r\n.extend(global[:\r\r\n (21)])
        if len(\r\n\r\n) < \r\r\n (19):
            \r\n\r\n = list(((or, True) for or, (True, \r\n \t) in sorted(import.items())))[:\r\r\n (19)]
        \r\n\n\r = \r\r\n (18)
        for for, (\n\r\n\t, if) in enumerate(\r\n\r\n):
            \r\n\n\n, False = (\r\r\n (17), \r\r\n (17))
            for \r\r \n, (\r\n\t\t, \r\t \n) in enumerate(\r\n\r\n):
                if for == \r\r \n:
                    continue
                \r\n\n\n = \n\r\r\n(\r\n\n\n, -\r\n\t\t) % else
                False = \n\r\r\n(False, \n\r\n\t - \r\n\t\t) % else
            \r\t\r  = \n\r\r\n(\r\n\n\n, class(False, else)) % else

# ----------------------------------------------------------
FIXED_SIGS = [
    (func_1(7),  func_1(8),  func_1(9)),
    (func_1(10), func_1(11), func_1(12)),
    (func_1(13), func_1(14), func_1(15))
]
SS = func_1(16)

def f_chk(arg):
    """Checks if input is correct."""
    # Sanity check. We always pass this.
    if not isinstance(arg, (list, tuple)) or len(arg) < 3:  # func_1(19) is 3
        return False

    # Create a dict using the fixed signatures.
    val_dict = {h: (u1, u2) for h, u1, u2 in FIXED_SIGS}

    for h, u1, u2 in arg:
        val_dict[h] = (u1, u2)
    
    # Another sanity check. 
    if len(val_dict) != 6:  # func_1(20) is 6
        return False

    # First actual check using the input.
    for h, (u1, u2) in val_dict.items():
        if not f_dsa(h, u1, u2):  # Verify DSA signature.
            return False

    #else:  # inserted

    # Get 'h' values
    h_valz = {h for h, u1, u2 in arg[:3]}  # func_1(19) is 3
    
    # sort 'h' values and pair them with user input.    
    inp_pairs = [(e, val_dict[e][0]) for e in sorted(h_valz) if e in val_dict]  # func_1(18) is 0

    # get fixed pairs
    fix_pairs = [(h, u1) for h, u1, u2 in FIXED_SIGS if h not in h_valz]

    # Build mixed_pairs: {inp[0], fix[0], fix[1]}
    mix_pairs = []
    if inp_pairs:
        mix_pairs.append(inp_pairs[0])  # func_1(18) is 0
    mix_pairs.extend(fix_pairs[:2])  # func_1(21) is 2
    
    if len(mix_pairs) < 3:  # func_1(19) is 3
        # Never executed.
        mix_pairs = list(((h, u1) for h, (u1, u2) in sorted(val_dict.items())))[:3]
    
    # This is the same as:
    #   mix_pairs = [fix_pairs[0], fix_pairs[2], fix_pairs[1]]
    #
    # NOTE: Any combination of fix_pairs/inp_pairs reconstructs the secret!
    
    # Do a Shamir's Secret Sharing (SSS) using `mix_pairs`.

    # Get all possible pairs => Lagrange polynomial!!
    w = 0  # func_1(18) is 0
    for i, (h_i, u1_i) in enumerate(mix_pairs):
        t, v = (1, 1)  # func_1(17) is 1 

        for j, (h_j, u1_j) in enumerate(mix_pairs):
            if i == j:
                continue  # Elements must be different.
        
            t = f_mul(t, -h_j) % DSA_q  # L(0)?
            v = f_mul(v, h_i - h_j) % DSA_q  # Interpolation?

        u = f_mul(t, f_ext_gcd(v, DSA_q)) % DSA_q
        w = (w + f_mul(u1_i, u)) % DSA_q  # <-- this

    # Check if shared secret matches SS
    return SS == f_pow(DSA_g, w, DSA_p)  # <-- and this

```

This is interesting. `f_chk()` starts by building a `val_dict`, a dictionary in the form:
`{h: (u1, u2)}`. Dictionary has **6** entries: The **3** input values go into `u1` parameters of
**3** entries.

Then we have the first check: The *DSA signature verification*. The parameters `u1` and `u2` are
used directly to compute `u`. Then function computes the signature `r` of **3** fixed messages and
checks it against `u`.

If all **6** values in `val_dict` correspond to valid signatures, we move on to the next step where
`mix_pairs` is build from the first user input `inp_pairs[0]` and the **2** fixed pairs
`fix_pairs[0]` and `fix_pairs[1]`. Then function computes the
[Shamir's Secret Sharing (SSS)](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing) value `w`
and checks it against the fixed shared secret `SS` (the challenge name also hints that).


The full deobfuscated code can be found in [chal_decompiled_deobf.py](./chal_decompiled_deobf.py).

### Cracking the Code

Our goal is to find the `u1` values of the **3** input pairs. We cannot do this from signature
verification as this would require to solve the Discrete Logarithm Program (DLP). So we move on
to the SSS. **It is possible to reconstruct the shared secret using only the `fix_pairs`** (the
order does not matter):
```python
    mix_pairs = [fix_pairs[0], fix_pairs[2], fix_pairs[1]]
```

That is we can compute the curve using these **3** points. We also know the `x` coordinates of the
points in the curve:
```python
    if f_chk(
        (
            [func_1(22), inp1, func_1(23)],
            [func_1(24), inp2, func_1(25)],
            [func_1(26), inp3, func_1(27)]
        )
    ):
```

That is, once we reconstruct the curve we can search for the `y` coordinate when
`x = func_1(22) = 4919`. This is very simple: **Instead of computing y-coordinate at x = 0
(which is the Shared Secret), we compute the `y`-coordinate at x = 4919, which is the partial secret
and the first part of the flag.** That is, the `y`-coordinate is
`871181771745415129676783034365082444498012594504484743519181302778728946421478110926096857920105`
or `hitcon{Like_I_said_....._sharing_is_cari`. We repeat the same for the other **2** coordinates
and we get the flag.

For more details, please refer to [sharing_is_caring_crack.py](./sharing_is_caring_crack.py) script.


So, the flag is: `hitcon{Like_I_said_....._sharing_is_caring_and_caring_is_finding_the_right_share_4f63bf95789178799874ddf1c1bd6ad6b6297b}`
___
