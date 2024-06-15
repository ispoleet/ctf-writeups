#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# DEFCON CTF 2022 - MIC CHECK 1 (MISC)
# ----------------------------------------------------------------------------------------
import socket


TICKET = b'ticket{HeadGull3549n22:tqs97T1B2KVTsoOr4K8-QZfJU_4ieWmakF0jnHULwTeAfWgc}'

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
    print('[+] MIC CHECK 1 crack started.')

    sock = socket.create_connection(('simple-service-c45xrrmhuc5su.shellweplayaga.me', 31337))

    recv_until(b'Ticket please:')
    sock.send(TICKET + b'\n')

    calc = sock.recv(1024)
    print(f'[+] Calculation: {calc}')

    res = eval(calc[:len(calc)-2])
    sock.send(f'{res}\n'.encode('utf-8'))

    ans = sock.recv(1024)
    print(f'[+] Response: {ans}')
        
    
# ----------------------------------------------------------------------------------------
"""
ispo@ispo-glaptop:~/ctf/defcon_quals_2022/mic_check_1$ ./mic_check_1_crack.py
[+] MIC CHECK 1 crack started.
[+] Calculation: b'1793828632 + 1939500988 = '
[+] Response: b"Correct!\nHere's your flag:\nflag{HeadGull3549n22:bRYbDUGbWzB97Xv3ppJAe7E5FNn3bzihwpg4UdGG9Z1kRflMxVkYNSbND85i4wIM9frNZ3hmrduDAjHDceioiw}\n"
"""
# ----------------------------------------------------------------------------------------

