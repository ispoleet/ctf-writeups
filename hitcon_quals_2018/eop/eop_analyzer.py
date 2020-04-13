#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# HITCON CTF quals 2018 - EOP (RE 257)
# --------------------------------------------------------------------------------------------------
import os
import sys
import struct
import idaapi
import idc


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    print '[+] EOP analyzer started.'


    nodes = {}
    i = 0

    # Iterate over all functions from `func_tbl_5555557671E0`
    for addr in range(0x5555557671E0, 0x5555557675C0, 8):
        ptr1 = Qword(addr)

        # Skip entry 0x1D (it's NULL)
        if not ptr1:
            i += 1            
            continue
        
        ptr2 = Qword(ptr1)
        func = Qword(ptr2)

        # Rename function
        idaapi.set_name(func, 'func_%02x_%lx' % (i, func))

        print '[+] Processing: %lx %lx %lx %lx' % (addr, ptr1, ptr2, func), GetFunctionName(func)

        # functions end at `call ___cxa_throw` instrucion.
        # extend endEA to `call __Unwind_Resume`
        for x in Heads(func, func+512):
            if GetDisasm(x) == 'call    __Unwind_Resume':
                SetFunctionEnd(func,  idaapi.next_head(x, func+512))
                break

        # Find next hop. Look for instruction: `mov dword ptr [rax], XXh`
        # where XX is the func_tbl_5555557671E0 entry of the next function.
        end = GetFunctionAttr(func, FUNCATTR_END)
        node = {'id': i, 'ea':func, 'next': -1, 'insns': []}
        start_log = False

        # for each instruction in function
        for insn in Heads(func, end):
            # Check for next hop instruction
            if idc.GetMnem(insn) == 'mov':
                if idc.GetOpnd(insn, 0) == 'dword ptr [rax]':
                    node['next'] = idc.GetOperandValue(insn, 1)
                    print '\tNext hop found: %x -> %x' % (i, node['next'])


            # The actual code is between `call ___cxa_begin_catch` and 
            # `mov edi, 4; call ___cxa_allocate_exception` instructions:
            #   .text:000055555555A344         call    ___cxa_begin_catch      ; Node: 0x36
            #   .text:000055555555A349         mov     rax, cs:tbl_A_555555767150
            #   .text:000055555555A350         mov     edx, [rax+10h]
            #   .text:000055555555A353         mov     eax, cs:tmp_C_5555557671C8
            #   .text:000055555555A359         xor     eax, edx
            #   .text:000055555555A35B         mov     cs:tmp_C_5555557671C8, eax ; tmp_C ^= tbl_A[4]
            #   .text:000055555555A361         mov     edi, 4
            #   .text:000055555555A366         call    ___cxa_allocate_exception            
            if GetMnem(insn) == "call" and idc.GetOpnd(insn, 0) == "___cxa_begin_catch":
                # Start logging instructions (ignore call)
                start_log = True
                
                AddBpt(insn)
                MakeComm(insn, "Node: 0x%02x" % i)
                continue

            elif GetMnem(insn) == "call" and idc.GetOpnd(insn, 0) == "___cxa_allocate_exception":
                # Stop loggin
                start_log = False
                continue

            if start_log:
                node['insns'].append(GetDisasm(insn))
                

        # last instruction (`mov edi, 4`) is the first argument to ___cxa_allocate_exception
        # drop it.
        node['insns'].pop() 

        nodes[i] = node
        i += 1


    # Display the nodes in the right order
    start = 0x31
    end = 0x1D

    cur_node = nodes[start]

    while True:
        print '; ---------------- Node %X at 0x%LX. Next: %X ----------------' % (
                cur_node['id'], cur_node['ea'], cur_node['next'])

        for insn in cur_node['insns']:
            print '    %s' % insn

        if cur_node['next'] == end:
            break

        cur_node = nodes[cur_node['next']]

# --------------------------------------------------------------------------------------------------
'''
[+] EOP analyzer started.
[+] Processing: 5555557671e0 55555577a3d0 555555764f90 55555555a1e6 func_00_55555555a1e6
    Next hop found: 0 -> c
[+] Processing: 5555557671e8 555555779ef0 555555764720 55555555dfc4 func_01_55555555dfc4
    Next hop found: 1 -> 23
[+] Processing: 5555557671f0 55555577a690 555555764630 55555555e620 func_02_55555555e620
    Next hop found: 2 -> 6d
....
[+] Processing: 5555557675b8 55555577a670 5555557647c8 55555555db16 func_7b_55555555db16
    Next hop found: 7b -> 2a
; ---------------- Node 31 at 0x555555559ADC. Next: 3A ----------------
    mov     [rbp+iter_14], 0
    cmp     [rbp+iter_14], 0Fh
    jg      short END_XOR_555555559B66
    mov     eax, [rbp+iter_14]
    movsxd  rdx, eax
    lea     rax, pwd_1_5555557671A0
    movzx   ecx, byte ptr [rdx+rax]     ; ecx = pwd[0]
    mov     eax, [rbp+iter_14]
    movsxd  rdx, eax
    lea     rax, enc_blk_1_5555557671B0
    movzx   eax, byte ptr [rdx+rax]
    xor     ecx, eax                    ; pwd[0:16] ^= enc_blk_1/2[0:16]
    mov     eax, [rbp+iter_14]
    movsxd  rdx, eax
    lea     rax, pwd_1_5555557671A0
    mov     [rdx+rax], cl
    add     [rbp+iter_14], 1
    jmp     short XOR_LOOP_555555559B26
; ---------------- Node 3A at 0x55555555AE98. Next: 3B ----------------
    movzx   eax, byte ptr cs:pwd_1_5555557671A0
    movzx   eax, al
    movzx   edx, byte ptr cs:pwd_1_5555557671A0+1
    movzx   edx, dl
    shl     edx, 8
    or      edx, eax
    movzx   eax, byte ptr cs:pwd_1_5555557671A0+2
    movzx   eax, al
    shl     eax, 10h
    or      edx, eax
    movzx   eax, byte ptr cs:pwd_1_5555557671A0+3
    movzx   eax, al
    shl     eax, 18h
    or      edx, eax                    ; edx = atoi(pwd_1[0:4])
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax]
    xor     eax, edx
    mov     cs:tmp_A_5555557671C0, eax  ; tmp_A = atoi(pwd_1[0:4]) ^ tbl_A[0]
.....
; ---------------- Node B at 0x55555555A398. Next: 1C ----------------
    mov     eax, cs:tmp_B_5555557671C4
    shr     eax, 10h
    mov     byte ptr cs:enc_blk_2_5555557671B8+6, al
; ---------------- Node 1C at 0x55555555CEC0. Next: 1D ----------------
    mov     eax, cs:tmp_B_5555557671C4
    shr     eax, 18h
    mov     byte ptr cs:enc_blk_2_5555557671B8+7, al
'''
# --------------------------------------------------------------------------------------------------
