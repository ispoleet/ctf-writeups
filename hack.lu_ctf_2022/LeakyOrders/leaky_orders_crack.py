#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Hack.Lu CTF 2022 - Leaky Orders (RE 277)
# ----------------------------------------------------------------------------------------
import socket
import subprocess
import re
import time
import random


SHELLSCRIPT = b'''#!/bin/bash
/chal/sigs &
PID=$!

echo "$> pid: $PID"

timestamp=$(date +%s)
for ((i=0; i<15; i++))
do    
    NUMS=`/tmp/rand $((timestamp + 0))`
    echo "$> Generate Numbers: $NUMS ~> (Iteration #$i)"

    ARR=($NUMS)
    echo "$> Array: ${ARR[0]} ${ARR[1]} ${ARR[2]}"

    # We need to play around with the sleep delay
    sleep 0.90

    timestamp=$(date +%s)

    kill -${ARR[0]} $PID
    kill -${ARR[2]} $PID
    kill -${ARR[1]} $PID

    echo '$> --------------------'
done

echo 'finito!'
sleep 2
'''
# ---------------------------------------------------------------------------------------
def recv_until(*trg_strs):
    """Receive until you encounter any of the target string(s)."""
    recv_buf = bytes()
    while not any(trg in recv_buf for trg in trg_strs):
        recv_buf += sock.recv(8192)
        if len(recv_buf) > 65536:
            print('[!] Warning. Receiving buffer limit reached.')
            break

    return recv_buf


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Leaky Orders Crack Started.')

    shell = ''.join('\\x%02X' % s for s in SHELLSCRIPT)
    print(f'[+] Encoding Shell Script: {shell[:64]}...')

    print('[+] Connecting to server ...')
    sock = socket.create_connection(('flu.xxx', 11201))

    recv_until(b':/chal$ ')    
    print('[+] Connected!')
   
    print('[+] Moving to /tmp')
    sock.send(b'cd /tmp' + b'\n')

    rand = open('rand', 'rb').read()
    
    print(f'[+] Sending `rand` binary to server (size: {len(rand)} bytes) ')
    for i in range(0, len(rand), 512):
        print(f'[+] Sending chunk at offset: {i}', i)
        resp = recv_until(b':/tmp$ ')

        rand_chunk = rand[i:min(len(rand), i+512)]
        chunk = ''.join('\\x%02X' % r for r in rand_chunk)

        cmd = f'python3 -c "open(\'rand\', \'a+b\').write(b\'{chunk}\')"'.encode('utf-8')
        print(f"[+] Sending command: {cmd[:64].decode('utf-8')}...")
        sock.send(cmd + b'\n')

    recv_until(b':/tmp$ ')

    print('[+] `rand` binary sent. Verifying its integrity ...')
    sock.send(b'md5sum rand' + b'\n')
    resp = recv_until(b':/tmp$ ')
    print('[+] MD5 digest of `rand`:', resp.decode('utf-8'))

    cmd = f'python3 -c "print(\'{shell} \')" > crack.sh'.encode('utf-8')
    sock.send(cmd + b'\n')
    resp = recv_until(b':/tmp$ ')
    print(f"[+] Writing shell script: {resp[:64].decode('utf-8')}...")

    print('[+] Giving executable permission to `rand` and `crack.sh` ...')

    sock.send(b'chmod +x rand crack.sh' + b'\n')
    recv_until(b':/tmp$ ')

    print('[+] Listing /tmp contents:')
    sock.send(b'ls -la' + b'\n')
    resp = recv_until(b':/tmp$ ')
    print(resp.decode('utf-8'))


    print('[+] Running crack script on remote server ...')
    for i in range(100):
        print(f'[+] = ~ = ~ = ~ = ~ = Run crack: Iteration #{i} = ~ = ~ = ~ = ~ =')
        sock.send(b'./crack.sh' + b'\n')
        while True:
            resp = sock.recv(1024).decode('utf-8')
            print(f'[+] Script output: {resp}')

            if 'flag' in resp:
                print(f'[+] FLAG FOUND: {resp}')
                sock.close()
            
                print('[+] Program finished! Bye bye :)')
                exit()

            elif 'finito' in resp:
                print('[+] Crack script finished (no solution found)')
                break

            elif 'No such process' in resp:
                # Send Ctrl+C.
                print('[+] Crack script failed. Trying again ...')
                sock.send(b'\x03' + b'\n')
                break

    print('[+] Program finished! Bye bye :)')

# ----------------------------------------------------------------------------------------
r"""
ispo@ispo-glaptop2:~/ctf/hack.lu_ctf_2022/LeakyOrders$ ./leaky_orders_crack.py 
[+] Leaky Orders Crack Started.
[+] Encoding Shell Script: \x23\x21\x2F\x62\x69\x6E\x2F\x62\x61\x73\x68\x0A\x2F\x63\x68\x61...
[+] Connecting to server ...
[+] Connected!
[+] Moving to /tmp
[+] Sending `rand` binary to server (size: 16224 bytes) 
[+] Sending chunk at offset: 0 0
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x7F\x45\x4C\x46\x02\x01...
[+] Sending chunk at offset: 512 512
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x04\x00\x00\x00\x04\x00...
[+] Sending chunk at offset: 1024 1024
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x00\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 1536 1536
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\xD0\x3D\x00\x00\x00\x00...
[+] Sending chunk at offset: 2048 2048
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x00\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 2560 2560
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x00\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 3072 3072
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x00\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 3584 3584
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x00\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 4096 4096
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x48\x83\xEC\x08\x48\x8B...
[+] Sending chunk at offset: 4608 4608
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\xFE\xFF\xFF\x8B\x55\xFC...
[+] Sending chunk at offset: 5120 5120
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x00\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 5632 5632
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x00\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 6144 6144
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x00\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 6656 6656
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x00\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 7168 7168
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x00\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 7680 7680
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x00\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 8192 8192
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x01\x00\x02\x00\x25\x64...
[+] Sending chunk at offset: 8704 8704
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x00\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 9216 9216
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x00\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 9728 9728
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x00\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 10240 10240
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x00\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 10752 10752
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x00\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 11264 11264
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x00\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 11776 11776
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x0D\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 12288 12288
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x36\x10\x00\x00\x00\x00...
[+] Sending chunk at offset: 12800 12800
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\xE8\x3F\x00\x00\x00\x00...
[+] Sending chunk at offset: 13312 13312
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x00\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 13824 13824
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x69\x67\x72\x74\x6D\x69...
[+] Sending chunk at offset: 14336 14336
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x1C\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 14848 14848
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x30\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 15360 15360
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x0E\x00\x00\x00\x00\x00...
[+] Sending chunk at offset: 15872 15872
[+] Sending command: python3 -c "open('rand', 'a+b').write(b'\x10\x00\x00\x00\x00\x00...
[+] `rand` binary sent. Verifying its integrity ...
[+] MD5 digest of `rand`: md5sum rand
265553720477838c6f27284c20ae7bd0  rand
ctf@c2b4c245c7bb:/tmp$ 
73\x6riting shell script:  python3 -c "print('\x23\x21\x2F\x62\x69\x6E\x2F\x62\x61\x7
[+] Giving executable permission to `rand` and `crack.sh` ...
[+] Listing /tmp contents:
ls -la
total 8
drwxrwxrwt  2 root root     4 Oct 31 06:23 .
drwxr-xr-x 18 root root    26 Oct 31 06:23 ..
-rwxr-xr-x  1 ctf  ctf    507 Oct 31 06:23 crack.sh
-rwxr-xr-x  1 ctf  ctf  16224 Oct 31 06:23 rand
ctf@c2b4c245c7bb:/tmp$ 
[+] Running crack script on remote server ...
[+] = ~ = ~ = ~ = ~ = Run crack: Iteration #0 = ~ = ~ = ~ = ~ =
[+] Script output: ./crack.sh

[+] Script output: $> pid: 46

[+] Script output: 51 54 50

[+] Script output: $> Generate Numbers: 51 54 50 ~> (Iteration #0)
$> Array: 51 54 50
[+] Script output: 

[+] Script output: $> --------------------
44 64 36

[+] Script output: $> Generate Numbers: 44 64 36 ~> (Iteration #1)
$> Array: 44 64 36

[+] Script output: $> --------------------
43 57 59

[+] Script output: $> Generate Numbers: 43 57 59 ~> (Iteration #2)
$> Array: 43 57 59

[+] Script output: $> --------------------
43 57 59

[+] Script output: $> Generate Numbers: 43 57 59 ~> (Iteration #3)
$> Array: 43 57 59

[+] Script output: $> --------------------
48 60 54
$> Generate Numbers: 48 60 54 ~> (Iteration #4)
$> Array: 48 60 54

[+] Script output: $> --------------------
56 48 60

[+] Script output: $> Generate Numbers: 56 48 60 ~> (Iteration #5)
$> Array: 56 48 60

[+] Script output: $> --------------------
59 47 34

[+] Script output: $> Generate Numbers: 59 47 34 ~> (Iteration #6)
$> Array: 59 47 34

[+] Script output: $> --------------------
61 53 52
$> Generate Numbers: 61 53 52 ~> (Iteration #7)
$> Array: 61 53 52

[+] Script output: $> --------------------
59 41 46
$> Generate Numbers: 59 41 46 ~> (Iteration #8)
$> Array: 59 41 46

[+] Script output: $> --------------------
57 36 45

[+] Script output: $> Generate Numbers: 57 36 45 ~> (Iteration #9)
$> Array: 57 36 45

[+] Script output: $> --------------------
64 37 51

[+] Script output: $> Generate Numbers: 64 37 51 ~> (Iteration #10)
$> Array: 64 37 51

[+] Script output: ./crack.sh: line 22: kill: (46) - No such process
./crack.sh: line 23: kill: (46) - No such process
$> --------------------

[+] Crack script failed. Trying again ...
[+] = ~ = ~ = ~ = ~ = Run crack: Iteration #1 = ~ = ~ = ~ = ~ =
[+] Script output: $> Generate Numbers: 53 34 38 ~> (Iteration #11)
$> Array: 53 34 38

[+] Script output: ^C

ctf@c2b4c245c7bb:/tmp$ 
ctf@c2b4c245c7bb:/tmp$ 
[+] Script output: ./crack.sh
$> pid: 84
53 34 38
$> Generate Numbers: 53 34 38 ~> (Iteration #0)
$> Array: 53 34 38

[+] Script output: $> --------------------
$> Generate Numbers: 42 49 36 ~> (Iteration #1)
$> Array: 42 49 36

[+] Script output: ./crack.sh: line 21: kill: (84) - No such process
./crack.sh: line 22: kill: (84) - No such process
./crack.sh: line 23: kill: (84) - No such process
$> --------------------
$> Generate Numbers: 64 49 50 ~> (Iteration #2)
$> Array: 64 49 50

[+] Crack script failed. Trying again ...
[+] = ~ = ~ = ~ = ~ = Run crack: Iteration #2 = ~ = ~ = ~ = ~ =
[+] Script output: ^C

ctf@c2b4c245c7bb:/tmp$ 
ctf@c2b4c245c7bb:/tmp$ 
[+] Script output: ./crack.sh
$> pid: 95
34 38 44
$> Generate Numbers: 34 38 44 ~> (Iteration #0)
$> Array: 34 38 44

[+] Script output: $> --------------------
34 38 44
$> Generate Numbers: 34 38 44 ~> (Iteration #1)
$> Array: 34 38 44

[+] Script output: $> --------------------
44 61 43
$> Generate Numbers: 44 61 43 ~> (Iteration #2)
$> Array: 44 61 43

[+] Script output: $> --------------------
56 62 46

[+] Script output: $> Generate Numbers: 56 62 46 ~> (Iteration #3)
$> Array: 56 62 46

[+] Script output: $> --------------------
59 38 52
$> Generate Numbers: 59 38 52 ~> (Iteration #4)
$> Array: 59 38 52

[+] Script output: $> --------------------
57 45 38
$> Generate Numbers: 57 45 38 ~> (Iteration #5)
$> Array: 57 45 38

[+] Script output: $> --------------------
54 38 49

[+] Script output: $> Generate Numbers: 54 38 49 ~> (Iteration #6)
$> Array: 54 38 49

[+] Script output: $> --------------------
49 46 63

[+] Script output: $> Generate Numbers: 49 46 63 ~> (Iteration #7)
$> Array: 49 46 63

[+] Script output: $> --------------------
60 59 64
$> Generate Numbers: 60 59 64 ~> (Iteration #8)
$> Array: 60 59 64

[+] Script output: $> --------------------
47 39 49
$> Generate Numbers: 47 39 49 ~> (Iteration #9)
$> Array: 47 39 49

[+] Script output: $> --------------------
58 49 35
$> Generate Numbers: 58 49 35 ~> (Iteration #10)
$> Array: 58 49 35

[+] Script output: $> --------------------
58 49 35
$> Generate Numbers: 58 49 35 ~> (Iteration #11)
$> Array: 58 49 35

[+] Script output: $> --------------------
51 41 60
$> Generate Numbers: 51 41 60 ~> (Iteration #12)
$> Array: 51 41 60

[+] Script output: $> --------------------
51 50 45
$> Generate Numbers: 51 50 45 ~> (Iteration #13)
$> Array: 51 50 45

[+] Script output: $> --------------------
44 56 43
$> Generate Numbers: 44 56 43 ~> (Iteration #14)
$> Array: 44 56 43

[+] Script output: $> --------------------
flag{y0u_s3nt_s0_m4ny_s1ng4ls_1m_fl4tt3rd}

finito!

[+] FLAG FOUND: $> --------------------
flag{y0u_s3nt_s0_m4ny_s1ng4ls_1m_fl4tt3rd}

finito!

[+] Program finished! Bye bye :)
ispo@ispo-glaptop2:~/ctf/hack.lu_ctf_2022/LeakyOrders$ 
"""
# ----------------------------------------------------------------------------------------
