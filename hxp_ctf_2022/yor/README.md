## HXP CTF 2022 - yor (Misc 116)
### 10-12/03/2023 (48hr)
___

## Description
 
**Difficulty estimate:** easy - easy

**Points:** round(1000 · min(1, 10 / (9 + [83 solves]))) = 116 points

**Description:**

*XOR is so last year (just like this CTF).*

*Introducing YOR.*

**Download:**
```
yor-de99ca0309bcf72b.tar.xz (12.7 KiB)
```

**Connection (mirrors):**
```
nc 167.235.26.48 10101
```
___

## Solution

Let's look at the challenge code (`vuln.py`):
```python
#!/usr/bin/env python3
import random

greets = [
        "Herzlich willkommen! Der Schlüssel ist {0}, und die Flagge lautet {1}.",
        "Bienvenue! Le clé est {0}, et le drapeau est {1}.",
        "Hartelĳk welkom! De sleutel is {0}, en de vlag luidt {1}.",
        "ようこそ！鍵は{0}、旗は{1}です。",
        "歡迎！鑰匙是{0}，旗幟是{1}。",
        "Witamy! Niestety nie mówię po polsku...",
    ]

flag = open('flag.txt').read().strip()
assert set(flag.encode()) <= set(range(0x20,0x7f))

key = bytes(random.randrange(256) for _ in range(16))
hello = random.choice(greets).format(key.hex(), flag).encode()

output = bytes(y | key[i%len(key)] for i,y in enumerate(hello))
print(output.hex())
```

Please refer to [yor_crack.py](./yor_crack.py) for more details.


So the flag is: `hxp{WhY_5et7L3_f0r_X0R_iF_y0u_C4n_h4v3_Y0R????}`
___
