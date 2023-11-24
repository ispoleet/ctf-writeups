## SEECON quals 2023 - optinimize (RE 152)
#### 16/09 - 17/09/2023 (24 hrs)

### Description

```
Nim is good at bignum arithmetic.
```
___

### Solution

This challenge was written in [Nim](https://nim-lang.org/). Symbols are not
stripped so we can understand the program without any problems. Below is the
decompiled version:
```python
trg_nums = [
    74, 85, 111, 121, 128, 149, 174, 191, 199,
    213, 774, 6856, 9402, 15616, 17153, 22054, 27353, 28931, 36891,
    40451, 1990582, 2553700, 3194270, 4224632,
    5969723, 7332785, 7925541, 8752735, 10012217, 11365110, 17301654,
    26085581, 29057287, 32837617, 39609127, 44659126, 47613075, 56815808,
    58232493, 63613165
]

key = [
    0x3C, 0xF4, 0x1A, 0xD0, 0x8A, 0x17, 0x7C, 0x4C, 0xDF, 0x21,
    0xDF, 0xB0, 0x12, 0xB8, 0x4E, 0xFA, 0xD9, 0x2D, 0x66, 0xFA,
    0xD4, 0x95, 0xF0, 0x66, 0x6D, 0xCE, 0x69, 0x00, 0x7D, 0x95,
    0xEA, 0xD9, 0x0A, 0xEB, 0x27, 0x63, 0x75, 0x11, 0x37, 0xD4
]

def P(n):
    if n == 0:
        return 3
    elif n == 1:
        return 0
    elif n == 2:
        return 2

    a, b, c = 3, 0, 2
    for z in range(n, 2, -1):
        a, b, c = b, c, a + b
        
    return c

def Q(param):
  a, b = 0, 0

  prev = 0
  while a < param:
    b += 1
    z = P(b) % b
    if z == 0:
      prev = b
      a += 1

  return b

for i, nxt in enumerate(trg_nums):
    x = Q(nxt) % 256
    print(f'[+] #{i} x = {x:02X} ~> {chr(x ^ key[i])!r}')
```

When we run the program, it prints the flag character by character, however it is very
slow after **11th** character: `SECCON{3b42`. Function `P` computes a number sequence
like Fibonacci, but it is not Fibonacci. Function `Q` tries to find the `i-th` number
whose `P(i)` is divisible by `i`.

There is no way to optimize this unless we know some mathematical property about it.
After some searching (using the constants), we find that these are actually 
[Perrin Numbers](https://en.wikipedia.org/wiki/Perrin_number). There is a very
interesting section about them:
```
Primes and divisibility
Perrin pseudoprimes
It has been proven that for all primes p, p divides P(p). However, the converse is not true: for some composite numbers n, n may still divide P(n). If n has this property, it is called a "Perrin pseudoprime".

The first few Perrin pseudoprimes are

271441, 904631, 16532714, 24658561, 27422714, 27664033, 46672291, 102690901, 130944133, 196075949, 214038533, 517697641, 545670533, 801123451, 855073301, 903136901, 970355431, ... (sequence A013998 in the OEIS)
```

Therefore, instead of computing `Q(i)`, we compute the number of prime numbers before `i`.
However, there is an exception: The **Perrin pseudoprimes**, which we have to take into
account. We run the program and after **~7** minutes we get the flag.

For more details, please refer to the [optinimize_crack.py](./optinimize_crack.py).

So, the flag is: `SECCON{3b4297373223a58ccf3dc06a6102846f}`
___

