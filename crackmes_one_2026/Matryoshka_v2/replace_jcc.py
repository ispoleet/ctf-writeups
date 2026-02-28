#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Crackmes One CTF 2026 - Matryoshka v2 - (Hard - 912)
#
# This module replaces blocks of opposite conditional jumps with a direct jump.
# For example, this:
#   seg000:000451EA         jge     loc_111766
#   seg000:000451F0         push    rax
#   seg000:000451F1         mov     rax, rdx
#   seg000:000451F4         pop     rax
#   seg000:000451F5         jl      loc_111766
#
# Is replaced with:
#   seg000:000451EA         jmp     loc_111766
#
# We can have more "kinds" of opposite jumps:
#   seg000:00111784         jg      loc_BD223
#   seg000:0011178A         pushfq
#   seg000:0011178B         cmp     rax, 0
#   seg000:0011178F         popfq
#   seg000:00111790         jle     loc_BD223
#
# The pattern is to look for a jcc followed by its opposite jcc.
# ----------------------------------------------------------------------------------------
import struct
from capstone import *
from capstone.x86 import *


JCC_OPPOSITES = {
    'jo': ('jno',), 'jno': ('jo',),
    
    # jb / jc / jnae  <--->  jae / jnb / jnc
    'jb': ('jae', 'jnb', 'jnc'), 'jc': ('jae', 'jnb', 'jnc'), 'jnae': ('jae', 'jnb', 'jnc'),
    'jae': ('jb', 'jc', 'jnae'), 'jnb': ('jb', 'jc', 'jnae'), 'jnc': ('jb', 'jc', 'jnae'),
    
    # je / jz  <--->  jne / jnz
    'jz': ('jne', 'jnz'), 'je': ('jne', 'jnz'),
    'jnz': ('je', 'jz'), 'jne': ('je', 'jz'),
    
    # jbe / jna  <--->  ja / jnbe
    'jbe': ('ja', 'jnbe'), 'jna': ('ja', 'jnbe'),
    'ja': ('jbe', 'jna'), 'jnbe': ('jbe', 'jna'),
    
    # js  <--->  jns
    'js': ('jns',), 'jns': ('js',),
    
    # jp / jpe  <--->  jnp / jpo
    'jp': ('jnp', 'jpo'), 'jpe': ('jnp', 'jpo'),
    'jnp': ('jp', 'jpe'), 'jpo': ('jp', 'jpe'),
    
    # jl / jnge  <--->  jge / jnl
    'jl': ('jge', 'jnl'), 'jnge': ('jge', 'jnl'),
    'jge': ('jl', 'jnge'), 'jnl': ('jl', 'jnge'),
    
    # jle / jng  <--->  jg / jnle
    'jle': ('jg', 'jnle'), 'jng': ('jg', 'jnle'),
    'jg': ('jle', 'jng'), 'jnle': ('jle', 'jng')
}


# ----------------------------------------------------------------------------------------
def _replace_jcc_block(md, sc, off):
    """Replaces a block of opposite jumps with a direct jump and returns next offset."""
    instructions = list(md.disasm(sc[off:off + 64], off))
    if not instructions:
        return off + 1  # Disassembly failed. Move on 1 byte.

    insn1 = instructions[0]
    mnem1 = insn1.mnemonic
    if mnem1 not in JCC_OPPOSITES:
        return off + insn1.size  # Not a conditional jump.

    if len(insn1.operands) == 0 or insn1.operands[0].type != X86_OP_IMM:
        return off + insn1.size  # Jump target must be immediate address
    
    # Search for the opposite jump.
    for i in range(1, len(instructions)):
        insn2 = instructions[i]    
        if (insn2.mnemonic not in JCC_OPPOSITES[mnem1] or
            len(insn2.operands) == 0 or insn2.operands[0].type != X86_OP_IMM):
            continue

        if insn1.operands[0].imm == insn2.operands[0].imm:
            # Found opposite jcc pattern. Extract jump address and patch it with a jmp.
            blk_end = insn2.address + insn2.size
            blk_sz = blk_end - off
            
            # Calculate jmp bytes
            jmp_off = insn1.operands[0].imm - (off + 2)
            if -128 <= jmp_off <= 127:
                jmp_bytes = b"\xEB" + struct.pack('<B', jmp_off & 0xFF)
                jmp_sz    = 2
            else:
                jmp_off   = insn1.operands[0].imm - (off + 5)
                jmp_bytes = b"\xE9" + struct.pack('<L', jmp_off & 0xFFFFFFFF)
                jmp_sz    = 5
        
            sc[off:off + jmp_sz] = jmp_bytes
            nop_sled = blk_sz - jmp_sz
            sc[off + jmp_sz:off + jmp_sz + nop_sled] = b'\x90'*nop_sled

            return blk_end
                    
    return off + insn1.size  # No match found. Move on.


# ----------------------------------------------------------------------------------------
def replace_opposite_jcc(sc):
    """Scans the whole shellcode and replaces opposite jumps with direct jumps."""
    print(f'[+] Replacing opposite jumps ...')

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    off = 0
    while off < len(sc):
        off = _replace_jcc_block(md, sc, off)

    return sc  # Return modified shellcode.

# ----------------------------------------------------------------------------------------
