#!/usr/bin/env python3
# ---------------------------------------------------------------------------------------
'''
To keep things simple, the first step is to isolate all `if` statements with their
assignment on the previous line:
    cat main.c | grep -B 1 'if ( !password' > main_dump.txt

This will give us something like:
      v408 = 0xAACA3AC8AF39AF5LL;
      if ( !password[1] || (v408 ^ password[1]) != 0xAACA3AC8AF39A91LL )
    --
      v412 = 0x7FAF173AFFD30096LL;
      if ( !password[2] || (v412 ^ password[2]) != 0x7FAF173AFFD300A7LL )
    --
    ...

We will miss however the very first check because it uses `*password` instead of
`password[0]`, but we can prepend that manually.

This script operates on main_dump.txt.
'''
# ---------------------------------------------------------------------------------------
import re

# ---------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Echo crack started.')

    lines = open('main_dump.txt', 'r').readlines()
    p = ''
    nums = [0x18, 0x21]         # Start with password[0].
    for line in lines:
        match = re.search(r'v.* = (0x.*)LL;', line)
        if match:
            a = match.group(1)            
            nums.append(int(a, 0) & 0xff)

        match2 = re.search(r'if .* (0x.*)LL', line)
        if match2:
            b = match2.group(1)
            nums.append(int(b, 0) & 0xff)

    print(f'[+] All numbers have been extracted (size: {len(nums)}): {nums}')
    
    xors = []
    for i in range(0, len(nums), 2):
        print(f'[+] XOR at #{i//2}: {nums[i] ^ nums[i +1]}')
        xors.append(nums[i] ^ nums[i+1])
    
    print('[+] Final Password:', ''.join(chr(x) for x in xors))

# ---------------------------------------------------------------------------------------
'''
ispo@leet:~/ctf/insomnihack_2022/echo$ ./echo_dump.py 
[+] Echo crack started.
[+] All numbers have been extracted (size: 800): [24, 33, 245, 145, 150, ..., 193, 27, 127]
[+] XOR at #0: 57
[+] XOR at #1: 100
[+] XOR at #2: 49
...
[+] XOR at #395: 100
[+] XOR at #396: 100
[+] XOR at #397: 56
[+] XOR at #398: 101
[+] XOR at #399: 100
[+] Final Password: 9d1b26b0e8a7f0cfd00ad2914789b7e177c672d21c0e3cd40ce26b2327cb2558a7dc49f17cc23315e2b2660dc1ca697f036b0fe01a39e5b7855d807a9fc31fd2fe3c2d8c18010d69e54efcceb277a0cbd03b6a920ab0ce227829649e44dec7218638c283ca13f96a1a0684576545ca900e991db8f4653f1e7b730ee7cb03191775c66414decfbdb84bf4fdd3bbdef9d66b8d8c11bc1df5160c8be4a619c91ed0e45ad1c8248e223a84ef2604ee1520adc23127e87d767f2315292e2b0782f06b9f71a364bfadd8ed

ispo@leet:~/ctf/insomnihack_2022/echo$ nc echo.insomnihack.ch 6666
9d1b26b0e8a7f0cfd00ad2914789b7e177c672d21c0e3cd40ce26b2327cb2558a7dc49f17cc23315e2b2660dc1ca697f036b0fe01a39e5b7855d807a9fc31fd2fe3c2d8c18010d69e54efcceb277a0cbd03b6a920ab0ce227829649e44dec7218638c283ca13f96a1a0684576545ca900e991db8f4653f1e7b730ee7cb03191775c66414decfbdb84bf4fdd3bbdef9d66b8d8c11bc1df5160c8be4a619c91ed0e45ad1c8248e223a84ef2604ee1520adc23127e87d767f2315292e2b0782f06b9f71a364bfadd8ed
INS{__0h_My_D34r!__D33p3R__d4ddy!$}^C
'''
# ---------------------------------------------------------------------------------------
