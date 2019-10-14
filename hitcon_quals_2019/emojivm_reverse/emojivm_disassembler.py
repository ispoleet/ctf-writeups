#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# HITCON CTF quals 2019 - EmojiVM (RE 300) 
# --------------------------------------------------------------------------------------------------
import sys
import struct
import codecs

emoji_to_opcode = {
    0x1f233: 0x01,
    0x02795: 0x02,
    0x02796: 0x03,
    0x0274c: 0x04,
    0x02753: 0x05,
    0x0274e: 0x06,
    0x1f46b: 0x07,
    0x1f480: 0x08,
    0x1f4af: 0x09,
    0x1f680: 0x0a,
    0x1f236: 0x0b,
    0x1f21a: 0x0c,
    0x023ec: 0x0d,
    0x1f4e4: 0x0f,
    0x1f4e5: 0x10,
    0x1f195: 0x11,
    0x1f4c4: 0x13,
    0x1f4dd: 0x14,
    0x1f6d1: 0x17
}

emoji_to_digit = {
    0x1f600: 0x00,
    0x1f601: 0x01,
    0x1f602: 0x02,
    0x1f604: 0x05,
    0x1f605: 0x06,
    0x1f606: 0x07,
    0x1f609: 0x08,
    0x1f60a: 0x09,
    0x1f60d: 0x0a,
    0x1f61c: 0x04,
    0x1f923: 0x03
}

# To make analysis easier we keep an emulated stack.
# However, stack can be imprecise as we don't emulate the program.
S = []

gptr = {
    0: [], 
    1: [],
    2: [], 
    3: [],
    4: [], 
    5: [],
    6: [], 
    7: [],
    8: [], 
    9: []
}

gptr_next = 0

# --------------------------------------------------------------------------------------------------
def insn_nop(pc):
    return "", "nop", 1

# --------------------------------------------------------------------------------------------------
def insn_add(pc):
    S.append(S.pop() + S.pop())

    return "", "add", 1

# --------------------------------------------------------------------------------------------------
def insn_sub(pc):
    S.append(S.pop() - S.pop())

    return "", "sub", 1

# --------------------------------------------------------------------------------------------------
def insn_mul(pc):
    S.append(S.pop() * S.pop())

    return "", "mul", 1

# --------------------------------------------------------------------------------------------------
def insn_modulo(pc):
    S.append(S.pop() % S.pop())

    return "", "mod", 1

# --------------------------------------------------------------------------------------------------
def insn_xor(pc):
    S.append(S.pop() ^ S.pop())

    return "", "xor", 1

# --------------------------------------------------------------------------------------------------
def insn_and(pc):
    S.append(S.pop() & S.pop())

    return "", "and", 1

# --------------------------------------------------------------------------------------------------
# a = pop, b = pop; if (a >= b) push 0; else push 1; pc += 1
def insn_cmp_lt(pc):
    a, b = S.pop(), S.pop()

    if a >= b: S.append(0);
    else: S.append(1);

    return "", "cmp: %d < %d ?" % (a, b), 1

# --------------------------------------------------------------------------------------------------
# a = pop, b = pop; if (a != b) push 0; else push 1; pc += 1
def insn_cmp_eq(pc):
    a, b = S.pop(), S.pop()

    if a != b: S.append(0);
    else: S.append(1);

    return "", "cmp: %d == %d ?" % (a, b), 1

# --------------------------------------------------------------------------------------------------
def insn_goto(pc):
    a = S.pop()

    return "", "jump %04Xh" % a, 1

# --------------------------------------------------------------------------------------------------
# a = pop, b = pop; if (!b) pc += 1 else pc = a
def insn_jnz(pc):
    a, b = S.pop(), S.pop()

    return "", "jnz (%d) %04Xh" % (b, a), 1

# --------------------------------------------------------------------------------------------------
# a = pop, b = pop; if (b)  pc += 1 else pc = a
def insn_jz(pc):
    a, b = S.pop(), S.pop()

    return "", "jz (%d) %04Xh" % (b, a), 1

# --------------------------------------------------------------------------------------------------
def insn_push_emoji(pc):
    emoji_code = struct.unpack("<L", emojis[pc].encode('utf-32le'))[0]

    S.append(emoji_to_digit[emoji_code])

    return emojis[pc], "push %d" % emoji_to_digit[emoji_code], 2
    
# --------------------------------------------------------------------------------------------------
def insn_gptr_mem_read(pc):
    a, b = S.pop(), S.pop()

    try:
        S.append(gptr[a][b])

        return "", "mem read: %d = *gptr[%d][%d]" % (gptr[a][b], a, b), 1    
    except IndexError:
        S.append(ord('?'))
        return "", "mem read: gptr[%d][%d] (exception)" % (a, b), 1    
    

# --------------------------------------------------------------------------------------------------
def insn_gptr_mem_write(pc):
    a, b, c = S.pop(), S.pop(), S.pop()

    gptr[a][b] = c
    return "", "mem write: *gptr[%d][%d] = %d" % (a, b, c), 1

# --------------------------------------------------------------------------------------------------
def insn_gptr_malloc(pc):
    global gptr_next

    a = S.pop()
    
    gptr[gptr_next] = [0]*a
    gptr_next += 1
    return "", "gptr malloc(%d)" % a, 1

# --------------------------------------------------------------------------------------------------
def insn_gptr_free(pc):
    # unused
    return "", "gptr free", 1

# --------------------------------------------------------------------------------------------------
def insn_gptr_scanf(pc):
    a = S.pop()

    gptr[a] = [ord('~')]*25

    return "", "gptr scanf(%d)" % a, 1

# --------------------------------------------------------------------------------------------------
def insn_gptr_printf(pc):
    a = S.pop()

    return "", "gptr printf(%d)" % a, 1

# --------------------------------------------------------------------------------------------------
def insn_retn(pc):
    return "", "return", 1

# --------------------------------------------------------------------------------------------------
def disassemble(pc):
    emoji_code = struct.unpack("<L", emojis[pc].encode('utf-32le'))[0]

    extra_emoji, mnemonic, size = {
        0x01: insn_nop,
        0x02: insn_add,
        0x03: insn_sub,
        0x04: insn_mul,
        0x05: insn_modulo,
        0x06: insn_xor,
        0x07: insn_and,
        0x08: insn_cmp_lt,
        0x09: insn_cmp_eq,
        0x0a: insn_goto,
        0x0b: insn_jnz,
        0x0c: insn_jz,
        0x0d: insn_push_emoji,
        # no 0x0e
        0x0f: insn_gptr_mem_read,
        0x10: insn_gptr_mem_write,
        0x11: insn_gptr_malloc,
        0x12: insn_gptr_free,
        0x13: insn_gptr_scanf,
        0x14: insn_gptr_printf,
        # no 0x15
        # no 0x16
        0x17: insn_retn
    }[emoji_to_opcode[emoji_code]](pc + 1)

    if extra_emoji == '': extra_emoji = ' '

    # skip nops, to make disassembly more clean
    #if mnemonic == "nop":
    #    return '', pc + size

    mnemonic = emojis[pc] + ' ' + extra_emoji + '\t' + mnemonic

    return mnemonic, pc + size


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":

    with codecs.open('chal.evm', encoding='utf-8') as fp:
        emojis = fp.readline()

    fp_out = codecs.open('emojivm_full.asm', 'w', encoding='utf-8');

    pc = 0
    while True:
        mnemonic, size = disassemble(pc) 
        
        if mnemonic == '': continue

        SS = S
        stack = '[' + ' '.join(('%02x' % s) for s in SS) + ']'

        print u"{0:04X}h: {1}{2}; {3}".format(pc, mnemonic, ' '*(32 - len(mnemonic)), stack)

        # gptr_0 --> buffer to print to stdout
        # gptr_1 --> key
        # gptr_2 --> const
        # gptr_3 --> encrypted key
        # gtpr_4 --> const
        gptr2 = '[' + ' '.join('%02x' % s for s in gptr[2]) + ']'
        gptr3 = '[' + ' '.join('%02x' % s for s in gptr[3]) + ']'
       
        mnemonic_pad = mnemonic + ' '*(32 - len(mnemonic))
        stack_pad = stack + ' '*(26 - len(stack))

        fp_out.write(u"{0:04X}h: {1}{2}; {3} {4}".format(
                     pc, mnemonic_pad, stack_pad, gptr2, gptr3) + '\n')

        pc = size
        if pc >= len(emojis):
            break
        
    fp_out.close()

# --------------------------------------------------------------------------------------------------
