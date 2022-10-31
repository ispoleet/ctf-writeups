## Hack Lu CTF 2022 - Linear Starter (Crypto 106)
##### 28/10 - 30/10/2022 (24hr)
___

### Description:

*Every delicious meal needs a starter and I have great news for you: This one is even linear! A mathematical dream, so delicious!*
___

### Solution

The code for this challenge is pretty small:
```python
from os import urandom
import binascii
import time

flag = r'flag{fake_flag}'

######### Public
m = int(binascii.hexlify(urandom(16)), 16)

######### Secret
a = int(binascii.hexlify(urandom(4)), 16) % m
b = int(binascii.hexlify(urandom(4)), 16) % m

######### Encrypt
otp = []
otp.append(int(time.time()) % m)

for _ in range(50):
    next = (a * otp[-1] + b) % m
    otp.append(next)

enc = ""
for i in range(len(flag)):
    enc += str(ord(flag[i]) ^ otp[i+1]) + " "

print("######### Output #########")
print("m ", m)
print("enc ", enc)
print("######### End #########")
```

Let's derive the equations used to produce the ciphertext:
```
otp[0] = $__RANDOM__                              mod m
otp[1] = a * $__RANDOM__ + b                      mod m
otp[2] = a * (a * $__RANDOM__ + b) + b            mod m
otp[3] = a * (a * (a * $___RANDOM__ + b) + b) + b mod m
...

enc[0] = flag[0] ^ otp[1]
enc[1] = flag[1] ^ (a * otp[1] + b)
enc[2] = flag[2] ^ (a * otp[2] + b)
...
```

If we find the secret keys `a` and `b` (`m` is known), then we can re-generate the `otp`
and therefore recover the plaintext. We re-write the equations as follows:
```
enc[0] ^ flag[0] = otp[1]
enc[1] ^ flag[1] = otp[2] = a * otp[1] + b mod m
enc[2] ^ flag[2] = otp[3] = a * otp[2] + b mod m
...
```

Since we know that the flag starts with `flag`, we have here a linear system with **2**
equations and **2** unknown variables (`a` and `b`), so it is possible to solve it:
```
# Subtract the equations
enc[2] ^ flag[2] - enc[1] ^ flag[1] = a * otp[2] + b - a * otp[1] - b mod m =>
enc[2] ^ flag[2] - enc[1] ^ flag[1] = a * (otp[2] - otp[1]) mod m 	        =>

a = (enc[2] ^ flag[2] - enc[1] ^ flag[1]) * modular_inverse(otp[2] - otp[1]) mod m

# and 
b = enc[1] ^ flag[1] - a * otp[1] mod m
```

We substitute all known variables from *out.txt* and we get:
```
a = 2184173277
b = 1390630283
```

We use them to recover the `otp`:
```
otp[0] = 3640950455282009483
otp[1] = 7952466687307948613019816074
otp[2] = 17369565224650736430247096541676484781
otp[3] = 22953297873638676928488877237515460537
otp[4] = 6789459926483754181974800398181847040
otp[5] = 23594281354816491687755064935408616862
...
```

Finally, we XOR it with the `enc` to get the flag: `flag{lin3ar_congru3nce_should_only_be_4_s1de_dish}`

For more details, please take a look at the [linearstarter_crack.py](./linearstarter_crack.py).
___

