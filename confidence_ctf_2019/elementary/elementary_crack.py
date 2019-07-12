#!/usr/bin/env python2
# -------------------------------------------------------------------------------------------------
# Google CTF 2019 - layz (RE 500)
#
# Get all segments that correspond to the Stack Machine.
# -------------------------------------------------------------------------------------------------
import struct
import sys
import os
import time
from capstone import *
from capstone.x86 import *
from pwn import *


# PIN constants  
INSCOUNT_FILE = 'inscount.out'
PIN_BIN       = '/home/ispo/bin/pin-3.10-97971-gc5e41af74-gcc-linux/pin'
INSTR_SO      = '/home/ispo/bin/pin-3.10-97971-gc5e41af74-gcc-linux/' \
                 'source/tools/ManualExamples/obj-intel64/inscount0.so'
LAYZ_BIN      = './elementary'


# -------------------------------------------------------------------------------------------------
# Given a number, flip a specific bit
bit_flip = lambda num, bit: num ^ (1 << bit)


# -------------------------------------------------------------------------------------------------
# Make a string from a list.
#
def stringify(flag_list):
    return ''.join([chr(ch) for ch in flag_list])


# -------------------------------------------------------------------------------------------------
# Extract the order of bits that are compared in checkFlag(). checkFlags consists of 831 "blocks"
# that each block checks a bit from flag in arbitrary order. Each block has the exact same format:
#
#       .text:00000000000CEBB4        mov     rax, [rbp+var_18]
#       .text:00000000000CEBB8        add     rax, 40h
#       .text:00000000000CEBBC        movzx   eax, byte ptr [rax]
#       .text:00000000000CEBBF        movsx   eax, al
#       .text:00000000000CEBC2        sar     eax, 2
#       .text:00000000000CEBC5        and     eax, 1
#       .text:00000000000CEBC8        mov     [rbp+var_4], eax
#       .text:00000000000CEBCB        mov     eax, [rbp+var_4]
#       .text:00000000000CEBCE        mov     edi, eax
#       .text:00000000000CEBD0        call    function1
#       .text:00000000000CEBD5        test    eax, eax
#       .text:00000000000CEBD7        jz      short loc_CEBE3
#       .text:00000000000CEBD9        mov     eax, 0
#       .text:00000000000CEBDE        jmp     locret_D8284
#
# First we "add" a constant to the flag to pick a character. Then we do a right shift (sar) and a
# logic AND to that character to isolate a specific bit (if we want the LSBit, we skip the sar;
# if we want the first byte, we skip add). Then we invoke function[1-831] to check this bit.
#
def extract_bits_order(code_segm, base_addr):
    bits_order = []
    byte_index = 0                              # initialize properly
    bit_index  = 0

    for insn in md.disasm(code_segm, base_addr):
        # print "\t.text:%016x\t\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str)

        # 1: Look for checked byte (add instruction)
        if insn.insn_name() == "add":
            if insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_IMM:
                reg = insn.operands[0].reg
                imm = insn.operands[1].value.imm

                if insn.reg_name(reg) == "rax":
                    byte_index = imm

        # 2: Look for checked bit (shift instruction)
        if insn.insn_name() == "sar":
            if insn.operands[0].type == X86_OP_REG and insn.operands[1].type == X86_OP_IMM:
                reg = insn.operands[0].reg
                imm = insn.operands[1].value.imm

                if insn.reg_name(reg) == "eax":
                    bit_index = imm

        # 3: Look for the end of the block
        elif insn.insn_name() == "jmp":
            if insn.operands[0].type == X86_OP_IMM and insn.operands[0].value.imm == 0xd8284:
                bits_order.append((byte_index, bit_index))

                byte_index = 0
                bit_index  = 0

    return bits_order


# -------------------------------------------------------------------------------------------------
# Run elementary program with a given flag and count the number of executed instructions.
#
def instrument(flag):
    # Delete inscount file (if exists)
    if os.path.exists(INSCOUNT_FILE):
        os.remove(INSCOUNT_FILE)

    # It is possible that the flag contains quotes. This is safer.
    # If flag contains spaces we're screwed up. 
    fp = open('flag', 'w')
    fp.write(flag)
    fp.close()

    # Run elementary with pin instrumentation to count instructions
    #os.system("echo '%s' | %s -t %s -- %s > /dev/null" % (flag, PIN_BIN, INSTR_SO, LAYZ_BIN))
    os.system("cat flag | %s -t %s -- %s > /dev/null" % (PIN_BIN, INSTR_SO, LAYZ_BIN))

    # Instrumentation creates a file with the instruction count. Read it.
    # File contains a single line: 'Count 2565752526'
    try:
        fp = open(INSCOUNT_FILE, 'r')
        line = fp.readline()
        insn_ctr = int(line[line.find('Count ') + 6:])
        fp.close()

    except IOError:
        print 'ERROR: FLAG', flag
        print repr(flag)
        exit()

    # print '[+]\t Instruction Count: %d. Key so far: %s' % (insn_ctr, flag)

    return insn_ctr


# -------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    print '[+] Layz Stack Machine segment printing started.'

    layz = ELF('elementary')
    text = layz.section('.text')    

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    text_base      = 0x00000610
    checkFlag_addr = 0x000CEB7C
    

    # Skip the first 3 instructions from checkFlag() (prolog):
    #   .text:00000000000CEB7C                 push    rbp
    #   .text:00000000000CEB7D                 mov     rbp, rsp
    #   .text:00000000000CEB80                 sub     rsp, 18h    
    entry = checkFlag_addr + 0xC

    # get the order that bits are checked
    bits_order = extract_bits_order(text[entry-text_base:entry-text_base+0x9709], entry)

    # Initialize flag list with 0xff (hoping that no flip will result to space character)
    flag_list = [0xff]*110                      # assume a length big enough

    ctr = 0

    for byte_idx, bit_idx in bits_order:        
        bkp = flag_list[byte_idx]               # get a backup of current character

        # count instructions with the current bit value
        insn_1 = instrument(stringify(flag_list))

        # flip bit and count instructions again
        flag_list[byte_idx] = bit_flip(flag_list[byte_idx], bit_idx)
    
        insn_2 = instrument(stringify(flag_list))
        
        # check which run went through the check (i.e., had more instructions)
        if insn_1 > insn_2:
            flag_list[byte_idx] = bkp
        elif insn_1 < insn_2:
            pass
        else:
            print '[-] Error! byte:%d, bit:%d, insn: %d' % (byte_idx, bit_idx, insn_1)
            print '[-] Flag1: %s' % stringify(flag_list)

            flag_list[byte_idx] = bit_flip(flag_list[byte_idx], bit_idx)    
            print '[-] Flag2: %s' % stringify(flag_list)
            exit(0)

        ctr += 1

        flag_printable = ''.join([chr(ch & 0x7f) if ch != 0xFF else '-' for ch in flag_list])

        print '[+] %d Byte:%d, bit:%d, Flag: %s' % (ctr, byte_idx, bit_idx, flag_printable)

    print '[+] Program finished successfully. Bye bye :)'

# -------------------------------------------------------------------------------------------------
'''
ispo@nogirl:~/ctf/ctf-writeups/confidence_ctf_2019/elementary$ time ./elementary_crack.py 
[+] Layz Stack Machine segment printing started.
[*] '/home/ispo/ctf/ctf-writeups/confidence_ctf_2019/elementary/elementary'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] 1 Byte:64, bit:0, Flag: --------------------------------------------------------------------------------------------------------------
[+] 2 Byte:64, bit:2, Flag: --------------------------------------------------------------------------------------------------------------
[+] 3 Byte:64, bit:5, Flag: --------------------------------------------------------------------------------------------------------------
[+] 4 Byte:64, bit:4, Flag: ----------------------------------------------------------------o---------------------------------------------
[+] 5 Byte:64, bit:6, Flag: ----------------------------------------------------------------o---------------------------------------------
[+] 6 Byte:64, bit:7, Flag: ----------------------------------------------------------------o---------------------------------------------
[+] 7 Byte:64, bit:3, Flag: ----------------------------------------------------------------g---------------------------------------------
[+] 8 Byte:64, bit:1, Flag: ----------------------------------------------------------------e---------------------------------------------
[+] 9 Byte:38, bit:0, Flag: ----------------------------------------------------------------e---------------------------------------------
[+] 10 Byte:38, bit:7, Flag: --------------------------------------\x7f-------------------------e---------------------------------------------
[.... TRUNCATED FOR BREVITY .....]
[+] 100 Byte:6, bit:1, Flag: ------}--------------a--------------s-me------------------------e--_b--------r----------o-t----m-----l--------
[+] 101 Byte:6, bit:2, Flag: ------}--------------a--------------s-me------------------------e--_b--------r----------o-t----m-----l--------
[+] 102 Byte:6, bit:4, Flag: ------m--------------a--------------s-me------------------------e--_b--------r----------o-t----m-----l--------
[+] 103 Byte:6, bit:3, Flag: ------e--------------a--------------s-me------------------------e--_b--------r----------o-t----m-----l--------
[+] 104 Byte:6, bit:5, Flag: ------e--------------a--------------s-me------------------------e--_b--------r----------o-t----m-----l--------
[+] 105 Byte:48, bit:0, Flag: ------e--------------a--------------s-me--------~---------------e--_b--------r----------o-t----m-----l--------
[+] 106 Byte:48, bit:6, Flag: ------e--------------a--------------s-me--------~---------------e--_b--------r----------o-t----m-----l--------
[+] 107 Byte:48, bit:2, Flag: ------e--------------a--------------s-me--------z---------------e--_b--------r----------o-t----m-----l--------
[+] 108 Byte:48, bit:3, Flag: ------e--------------a--------------s-me--------r---------------e--_b--------r----------o-t----m-----l--------
[+] 109 Byte:48, bit:1, Flag: ------e--------------a--------------s-me--------r---------------e--_b--------r----------o-t----m-----l--------
[+] 110 Byte:48, bit:4, Flag: ------e--------------a--------------s-me--------r---------------e--_b--------r----------o-t----m-----l--------
[.... TRUNCATED FOR BREVITY .....]
[+] 500 Byte:74, bit:2, Flag: ---I-rea-l--hop-_y---a-t-m--ed----s-someh--_ot-er---e---_mi-h-_-e_a_bit_---strating_t-_-o_th-s-m-nu--ly}------
[+] 501 Byte:74, bit:1, Flag: ---I-rea-l--hop-_y---a-t-m--ed----s-someh--_ot-er---e---_mi-h-_-e_a_bit_--}strating_t-_-o_th-s-m-nu--ly}------
[+] 502 Byte:74, bit:3, Flag: ---I-rea-l--hop-_y---a-t-m--ed----s-someh--_ot-er---e---_mi-h-_-e_a_bit_--ustrating_t-_-o_th-s-m-nu--ly}------
[+] 503 Byte:74, bit:6, Flag: ---I-rea-l--hop-_y---a-t-m--ed----s-someh--_ot-er---e---_mi-h-_-e_a_bit_--ustrating_t-_-o_th-s-m-nu--ly}------
[+] 504 Byte:74, bit:7, Flag: ---I-rea-l--hop-_y---a-t-m--ed----s-someh--_ot-er---e---_mi-h-_-e_a_bit_--ustrating_t-_-o_th-s-m-nu--ly}------
[+] 505 Byte:1, bit:0, Flag: -~-I-rea-l--hop-_y---a-t-m--ed----s-someh--_ot-er---e---_mi-h-_-e_a_bit_--ustrating_t-_-o_th-s-m-nu--ly}------
[+] 506 Byte:1, bit:7, Flag: -~-I-rea-l--hop-_y---a-t-m--ed----s-someh--_ot-er---e---_mi-h-_-e_a_bit_--ustrating_t-_-o_th-s-m-nu--ly}------
[+] 507 Byte:1, bit:2, Flag: -~-I-rea-l--hop-_y---a-t-m--ed----s-someh--_ot-er---e---_mi-h-_-e_a_bit_--ustrating_t-_-o_th-s-m-nu--ly}------
[+] 508 Byte:1, bit:3, Flag: -v-I-rea-l--hop-_y---a-t-m--ed----s-someh--_ot-er---e---_mi-h-_-e_a_bit_--ustrating_t-_-o_th-s-m-nu--ly}------
[+] 509 Byte:1, bit:4, Flag: -v-I-rea-l--hop-_y---a-t-m--ed----s-someh--_ot-er---e---_mi-h-_-e_a_bit_--ustrating_t-_-o_th-s-m-nu--ly}------
[+] 510 Byte:1, bit:5, Flag: -v-I-rea-l--hop-_y---a-t-m--ed----s-someh--_ot-er---e---_mi-h-_-e_a_bit_--ustrating_t-_-o_th-s-m-nu--ly}------
[+] 511 Byte:1, bit:6, Flag: -6-I-rea-l--hop-_y---a-t-m--ed----s-someh--_ot-er---e---_mi-h-_-e_a_bit_--ustrating_t-_-o_th-s-m-nu--ly}------
[+] 512 Byte:1, bit:1, Flag: -4-I-rea-l--hop-_y---a-t-m--ed----s-someh--_ot-er---e---_mi-h-_-e_a_bit_--ustrating_t-_-o_th-s-m-nu--ly}------
[+] 513 Byte:18, bit:0, Flag: -4-I-rea-l--hop-_y---a-t-m--ed----s-someh--_ot-er---e---_mi-h-_-e_a_bit_--ustrating_t-_-o_th-s-m-nu--ly}------
[+] 514 Byte:18, bit:1, Flag: -4-I-rea-l--hop-_y---a-t-m--ed----s-someh--_ot-er---e---_mi-h-_-e_a_bit_--ustrating_t-_-o_th-s-m-nu--ly}------
[+] 515 Byte:18, bit:7, Flag: -4-I-rea-l--hop-_y\x7f--a-t-m--ed----s-someh--_ot-er---e---_mi-h-_-e_a_bit_--ustrating_t-_-o_th-s-m-nu--ly}------
[+] 516 Byte:18, bit:4, Flag: -4-I-rea-l--hop-_yo--a-t-m--ed----s-someh--_ot-er---e---_mi-h-_-e_a_bit_--ustrating_t-_-o_th-s-m-nu--ly}------
[+] 517 Byte:18, bit:6, Flag: -4-I-rea-l--hop-_yo--a-t-m--ed----s-someh--_ot-er---e---_mi-h-_-e_a_bit_--ustrating_t-_-o_th-s-m-nu--ly}------
[+] 518 Byte:18, bit:2, Flag: -4-I-rea-l--hop-_yo--a-t-m--ed----s-someh--_ot-er---e---_mi-h-_-e_a_bit_--ustrating_t-_-o_th-s-m-nu--ly}------
[+] 519 Byte:18, bit:3, Flag: -4-I-rea-l--hop-_yo--a-t-m--ed----s-someh--_ot-er---e---_mi-h-_-e_a_bit_--ustrating_t-_-o_th-s-m-nu--ly}------
[+] 520 Byte:18, bit:5, Flag: -4-I-rea-l--hop-_yo--a-t-m--ed----s-someh--_ot-er---e---_mi-h-_-e_a_bit_--ustrating_t-_-o_th-s-m-nu--ly}------
[.... TRUNCATED FOR BREVITY .....]
[+] 800 Byte:61, bit:3, Flag: -4{I_really_hope_you-a-toma-ed_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 801 Byte:22, bit:0, Flag: -4{I_really_hope_you-a-toma-ed_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 802 Byte:22, bit:3, Flag: -4{I_really_hope_you-awtoma-ed_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 803 Byte:22, bit:2, Flag: -4{I_really_hope_you-awtoma-ed_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 804 Byte:22, bit:6, Flag: -4{I_really_hope_you-awtoma-ed_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 805 Byte:22, bit:7, Flag: -4{I_really_hope_you-awtoma-ed_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 806 Byte:22, bit:1, Flag: -4{I_really_hope_you-automa-ed_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 807 Byte:22, bit:4, Flag: -4{I_really_hope_you-automa-ed_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 808 Byte:22, bit:5, Flag: -4{I_really_hope_you-automa-ed_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 809 Byte:0, bit:0, Flag: ~4{I_really_hope_you-automa-ed_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 810 Byte:0, bit:7, Flag: ~4{I_really_hope_you-automa-ed_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 811 Byte:0, bit:3, Flag: v4{I_really_hope_you-automa-ed_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 812 Byte:0, bit:5, Flag: v4{I_really_hope_you-automa-ed_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 813 Byte:0, bit:2, Flag: r4{I_really_hope_you-automa-ed_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 814 Byte:0, bit:6, Flag: r4{I_really_hope_you-automa-ed_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 815 Byte:0, bit:4, Flag: r4{I_really_hope_you-automa-ed_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 816 Byte:0, bit:1, Flag: p4{I_really_hope_you-automa-ed_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 817 Byte:27, bit:0, Flag: p4{I_really_hope_you-automa~ed_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 818 Byte:27, bit:1, Flag: p4{I_really_hope_you-automa|ed_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 819 Byte:27, bit:7, Flag: p4{I_really_hope_you-automa|ed_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 820 Byte:27, bit:3, Flag: p4{I_really_hope_you-automated_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 821 Byte:27, bit:2, Flag: p4{I_really_hope_you-automated_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 822 Byte:27, bit:5, Flag: p4{I_really_hope_you-automated_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 823 Byte:27, bit:6, Flag: p4{I_really_hope_you-automated_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 824 Byte:27, bit:4, Flag: p4{I_really_hope_you-automated_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 825 Byte:20, bit:0, Flag: p4{I_really_hope_you-automated_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 826 Byte:20, bit:5, Flag: p4{I_really_hope_you_automated_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 827 Byte:20, bit:3, Flag: p4{I_really_hope_you_automated_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 828 Byte:20, bit:6, Flag: p4{I_really_hope_you_automated_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 829 Byte:20, bit:7, Flag: p4{I_really_hope_you_automated_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 830 Byte:20, bit:1, Flag: p4{I_really_hope_you_automated_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 831 Byte:20, bit:2, Flag: p4{I_really_hope_you_automated_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] 832 Byte:20, bit:4, Flag: p4{I_really_hope_youOautomated_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}------
[+] Program finished successfully. Bye bye :)
 
real    65m35.753s
user    62m52.436s
sys 2m41.664s

ispo@nogirl:~/ctf/ctf-writeups/confidence_ctf_2019/elementary$ ./elementary
Password: p4{I_really_hope_you_automated_this_somehow_otherwise_it_might_be_a_bit_frustrating_to_do_this_manually}
Good job!
'''
# -------------------------------------------------------------------------------------------------
