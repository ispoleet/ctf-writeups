#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# SECCON Quals 2023 - optinimize (RE 152)
# ----------------------------------------------------------------------------------------

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

perrin_pseudo = [
    271441, 904631, 16532714, 24658561, 27422714, 27664033, 46672291, 102690901,
    130944133, 196075949, 214038533, 517697641, 545670533, 801123451, 855073301,
    903136901, 970355431, 1091327579,1133818561, 1235188597,1389675541,1502682721,
    2059739221
]


# ----------------------------------------------------------------------------------------
def P(n):
    """This function computes Perrin numbers:
    
    https://en.wikipedia.org/wiki/Perrin_number
    https://de.wikipedia.org/wiki/Perrin-Folge
    """
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


# ----------------------------------------------------------------------------------------
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


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Optinimize crack started.')

    print('[+] Testing direct computation (10 iterations) ...')
    for i, nxt in enumerate(trg_nums):
        x = Q(nxt) % 256
        print(f'[+] #{i} x = {x:02X} ~> {chr(x ^ key[i])!r}')

        if i >= 10: break

    print('[+] Computing prime numbers (will take some minutes) ............')
    n = 1999999999
    # Code taken form stackoverflow.
    is_prime = [False, False] + [True] * (n - 1)
    primes = [2]

    for j in range(4, n + 1, 2):
        is_prime[j] = False

    for i in range(3, n + 1, 2):
        if is_prime[i]:
            primes.append(i)
            for j in range(i * i, n + 1, i):
                is_prime[j] = False

    print(f'[+] Done. {len(primes)} primes found.')
    print('[+] Last 10 primes:', primes[len(primes)-10:])

    flag = ''
    for i, a in enumerate(trg_nums):
        z = primes[a - 2]
        c = len(list(filter(lambda a: a < z, perrin_pseudo))) # Count pseudo primes
       
        if c > 0:
            z = primes[a - 2 - c]  # Adjust.

        y = z % 256
        flag += chr(y ^ key[i])
        print(f'[+] #{i} a = {a}, z = {z}, y = 0x{y:02X}, c = {c}, flag = {flag}')

    print(f'[+] Flag is: {flag}')
    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop2:~/ctf/seccon_quals_2023/optinimize$ ./optinimize_crack.py
[+] Optinimize crack started.
[+] Testing direct computation (10 iterations) ...
[+] #0 x = 6F ~> 'S'
[+] #1 x = B1 ~> 'E'
[+] #2 x = 59 ~> 'C'
[+] #3 x = 93 ~> 'C'
[+] #4 x = C5 ~> 'O'
[+] #5 x = 59 ~> 'N'
[+] #6 x = 07 ~> '{'
[+] #7 x = 7F ~> '3'
[+] #8 x = BD ~> 'b'
[+] #9 x = 15 ~> '4'
[+] #10 x = ED ~> '2'
[+] Computing prime numbers (will take some minutes) ............
[+] Done. 98222287 primes found.
[+] Last 10 primes: [1999999817, 1999999829, 1999999853, 1999999861, 1999999871, 1999999873, 1999999913, 1999999927, 1999999943, 1999999973]
[+] #0 a = 74, z = 367, y = 0x6F, c = 0, flag = S
[+] #1 a = 85, z = 433, y = 0xB1, c = 0, flag = SE
[+] #2 a = 111, z = 601, y = 0x59, c = 0, flag = SEC
[+] #3 a = 121, z = 659, y = 0x93, c = 0, flag = SECC
[+] #4 a = 128, z = 709, y = 0xC5, c = 0, flag = SECCO
[+] #5 a = 149, z = 857, y = 0x59, c = 0, flag = SECCON
[+] #6 a = 174, z = 1031, y = 0x07, c = 0, flag = SECCON{
[+] #7 a = 191, z = 1151, y = 0x7F, c = 0, flag = SECCON{3
[+] #8 a = 199, z = 1213, y = 0xBD, c = 0, flag = SECCON{3b
[+] #9 a = 213, z = 1301, y = 0x15, c = 0, flag = SECCON{3b4
[+] #10 a = 774, z = 5869, y = 0xED, c = 0, flag = SECCON{3b42
[+] #11 a = 6856, z = 69001, y = 0x89, c = 0, flag = SECCON{3b429
[+] #12 a = 9402, z = 97829, y = 0x25, c = 0, flag = SECCON{3b4297
[+] #13 a = 15616, z = 171403, y = 0x8B, c = 0, flag = SECCON{3b42973
[+] #14 a = 17153, z = 189817, y = 0x79, c = 0, flag = SECCON{3b429737
[+] #15 a = 22054, z = 250057, y = 0xC9, c = 0, flag = SECCON{3b4297373
[+] #16 a = 27353, z = 316907, y = 0xEB, c = 1, flag = SECCON{3b42973732
[+] #17 a = 28931, z = 336671, y = 0x1F, c = 1, flag = SECCON{3b429737322
[+] #18 a = 36891, z = 439381, y = 0x55, c = 1, flag = SECCON{3b4297373223
[+] #19 a = 40451, z = 486043, y = 0x9B, c = 1, flag = SECCON{3b4297373223a
[+] #20 a = 1990582, z = 32290273, y = 0xE1, c = 6, flag = SECCON{3b4297373223a5
[+] #21 a = 2553700, z = 42106541, y = 0xAD, c = 6, flag = SECCON{3b4297373223a58
[+] #22 a = 3194270, z = 53430163, y = 0x93, c = 7, flag = SECCON{3b4297373223a58c
[+] #23 a = 4224632, z = 71926277, y = 0x05, c = 7, flag = SECCON{3b4297373223a58cc
[+] #24 a = 5969723, z = 103839499, y = 0x0B, c = 8, flag = SECCON{3b4297373223a58ccf
[+] #25 a = 7332785, z = 129151741, y = 0xFD, c = 8, flag = SECCON{3b4297373223a58ccf3
[+] #26 a = 7925541, z = 140250893, y = 0x0D, c = 9, flag = SECCON{3b4297373223a58ccf3d
[+] #27 a = 8752735, z = 155813731, y = 0x63, c = 9, flag = SECCON{3b4297373223a58ccf3dc
[+] #28 a = 10012217, z = 179656781, y = 0x4D, c = 9, flag = SECCON{3b4297373223a58ccf3dc0
[+] #29 a = 11365110, z = 205471907, y = 0xA3, c = 10, flag = SECCON{3b4297373223a58ccf3dc06
[+] #30 a = 17301654, z = 320518027, y = 0x8B, c = 11, flag = SECCON{3b4297373223a58ccf3dc06a
[+] #31 a = 26085581, z = 494588399, y = 0xEF, c = 11, flag = SECCON{3b4297373223a58ccf3dc06a6
[+] #32 a = 29057287, z = 554258491, y = 0x3B, c = 13, flag = SECCON{3b4297373223a58ccf3dc06a61
[+] #33 a = 32837617, z = 630613979, y = 0xDB, c = 13, flag = SECCON{3b4297373223a58ccf3dc06a610
[+] #34 a = 39609127, z = 768531989, y = 0x15, c = 13, flag = SECCON{3b4297373223a58ccf3dc06a6102
[+] #35 a = 44659126, z = 872167259, y = 0x5B, c = 15, flag = SECCON{3b4297373223a58ccf3dc06a61028
[+] #36 a = 47613075, z = 933088577, y = 0x41, c = 16, flag = SECCON{3b4297373223a58ccf3dc06a610284
[+] #37 a = 56815808, z = 1124023591, y = 0x27, c = 18, flag = SECCON{3b4297373223a58ccf3dc06a6102846
[+] #38 a = 58232493, z = 1153586513, y = 0x51, c = 19, flag = SECCON{3b4297373223a58ccf3dc06a6102846f
[+] #39 a = 63613165, z = 1266125737, y = 0xA9, c = 20, flag = SECCON{3b4297373223a58ccf3dc06a6102846f}
[+] Flag is: SECCON{3b4297373223a58ccf3dc06a6102846f}
[+] Program finished. Bye bye :)

real	7m36.964s
user	7m32.808s
sys	0m4.120s
'''
# ----------------------------------------------------------------------------------------

