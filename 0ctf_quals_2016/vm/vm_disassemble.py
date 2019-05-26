#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# 0CTF 2016 - VM (RE 7)
# --------------------------------------------------------------------------------------------------
import struct

raw_insts = []

insn_dispatcher = {
    0x02 : 'mov',
    0x05 : 'add',           # vreg + vreg 
    0x06 : 'add',           # vreg + imm
    0x09 : 'sub',           # vreg - vreg
    0x0b : 'smul',          # signed multiplication. Result in vm+0x200, vm+0x204
    0x0c : 'mul',           # unsigned multiplication. Result in vm+0x200, vm+0x204
    0x0e : 'div',           # division. Modulo in vm+0x200, quotient in vm+0x204
    0x11 : 'ldr',
    0x14 : 'ldrb',
    0x16 : 'str',
    0x18 : 'strb',
    0x1d : 'movt',          # mov on high order word
    0x1e : 'mov_f1',        # mov vreg, vm+0x200
    0x1f : 'mov_f2',        # mov vreg, vm+0x204
    0x21 : 'and',           # vreg & imm
    0x22 : 'or',            # vreg | vreg
    0x23 : 'or',            # vreg | imm
    0x24 : 'xor',
    0x26 : 'nor',
    0x29 : 'tstl',          # dst = 1 if src1 < src2 else 0
    0x2b : 'cmp?',          # come back to that
    0x2c : 'lsl',
    0x2e : 'lsr',
    0x30 : 'asr',           # arithmetic right shift
    0x32 : 'cbz',           # compare and branch
    0x33 : 'cbnz',          # compare and branch
    0x34 : 'be',            # branch if dst is zero
    0x35 : 'bne',           # branch if dst is nonzero
    0x3e : 'b',             # unconditional branch
    0x3f : 'retn',          # r32 = link register
    0x40 : 'libcall',       # call to libc (r26 holds the address)
    0x41 : 'call',          # call imm
    0x4d : 'nop'            # no operation
}


# --------------------------------------------------------------------------------------------------
# diassemble one instruction
#
def disassemble( raw_insn ):
    insn = [struct.unpack("<L", raw_insn[i:i+4])[0] for i in range(0, 0x48, 4)]

    try:    
        mnem = insn_dispatcher[ insn[0] ]
    except KeyError:
        raise Exception("Unknown opcode '0x%x'" % insn[0])

    disas = mnem + ' '*(8-len(mnem))
    n_op  = insn[1] & 0xff

    # -------------------------------------------------------------------------
    # internal function to decode an operand
    # -------------------------------------------------------------------------
    def decode_operand(ty, op1, op2):
        return {
            1 : 'r%d' % op1,                # register
            2 : '#%xh' % op1,               # immediate
            3 : '[r%d, #%xh]' % (op1, op2) # register + immediate
        }[ty]


    if n_op > 0: 
        disas += decode_operand(insn[2], insn[3], insn[4])

    if n_op > 1: 
        disas += ', ' + decode_operand(insn[6], insn[7], insn[8])

    if n_op > 2: 
        disas += ', ' + decode_operand(insn[10], insn[11], insn[12])

    return disas

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    
    try:
        progfd = open('raw_vm_program.dat','rb') 
        
        addr = 0x400830
        while True:
            raw_insn = progfd.read(0x48)

            if len(raw_insn) != 0x48:
                break

            print '0x%06x: ' % addr, disassemble(raw_insn)

            addr += 4

        progfd.close()

    except EOFError:
        pass
    except IOError:
        print 'File not found!'
        exit()

# --------------------------------------------------------------------------------------------------
