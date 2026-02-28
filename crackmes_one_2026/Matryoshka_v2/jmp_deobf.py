#!/usr/bin/env python3
#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Crackmes One CTF 2026 - Matryoshka v2 - (Hard - 912)
#
# This module removes the unnecessary jump instructions from the shellcode. Let's see
# how it looks like (after replacing the opposite jumps):
#
#    seg000:00000000         jmp     loc_451EA
#
#    seg000:000451EA loc_451EA:
#    seg000:000451EA         jmp     loc_111766
#
#    [..... MANY MORE JUMPS .....]
#
#    seg000:000689BD loc_689BD:
#    seg000:000689BD         jmp     loc_FBFDF
#
#    seg000:000FBFDF loc_FBFDF:
#    seg000:000FBFDF         mov     [rsp+8], rcx   ; <---- FIRST INSN
#    seg000:000FBFE4         jmp     loc_1434B9
#
#    seg000:001434B9 loc_1434B9:
#    seg000:001434B9         jmp     loc_C9997
#
#    [..... MANY MORE JUMPS .....]
#
#    seg000:0010C327 loc_10C327:
#    seg000:0010C327         jmp     sub_11BDE4
#
#    seg000:0011BDE4         sub     rsp, 68h   ; <---- SECOND INSN
#    seg000:0011BDE8         jmp     loc_12A71A
#
# And so on.
#
# The plan is to ignore all these jumps and build a new, clean shellcode that contains
# only the useful instructions. We have to be careful with the real unconditional jumps.
# Also we have to recompute the relative jump/call offsets.
#
# Furtunately, the exact same obfuscation was used in Where Am I? challenge from 
# 10th Flare On, so we can reuse the code from:
#
# https://github.com/ispoleet/flare-on-challenges/tree/master/flare-on-2023/05_where_am_i
# ----------------------------------------------------------------------------------------
import capstone
import struct

_MAX_FUNC_LEN_ = 0x1400


# ----------------------------------------------------------------------------------------
def _deobf_func(entry, code, md, func_map, func_off):
    """Deobfuscates a shellcode function at address `entry`."""
    global _MAX_FUNC_LEN_

    deobf_shellcode = {}    
    visited = set()  # Visited instructions.
    queue = [entry]

    deobf_shellcode = bytearray()
    off_map = {}
    jmp_fix_tbl = []
    func_calls = []

    while queue:  # Do a BFS to visit all conditional jumps.
        nxt_blk = queue.pop(0)
        chunk_base = nxt_blk

        # Follow the jmp instructions and collect all other instructions through the way.
        more_shellcode = True
        while more_shellcode:
            # Disassemble instructions from `nxt_blk` until you hit a jmp/ret.
            for insn in md.disasm(code[nxt_blk:nxt_blk+32], nxt_blk):

                if insn.address in visited:
                    more_shellcode = False
                    
                    # 5 is the new jmp insn size.
                    diff = (off_map[insn.address] - len(deobf_shellcode) - 5) & 0xFFFFFFFF
                    deobf_shellcode += b'\xe9' + struct.pack('<L', diff)
                    break
                else:
                    visited.add(insn.address)

                off_map[insn.address] = len(deobf_shellcode)

                if insn.mnemonic == 'ret':
                    # We 've reached the end of function/shellcode.
                    deobf_shellcode += insn.bytes
                    more_shellcode = False
                    break
                elif insn.mnemonic == 'jmp':
                    # Move on to the next block
                    nxt_blk = insn.op_find(capstone.CS_OP_IMM, 1).imm
                    break
                elif insn.mnemonic in ['je', 'jne', 'jl', 'jle', 'jg', 'jge', 'jb', 'jbe', 'ja', 'jae']:
                    # For conditional jumps we need to relocate jump target.
                    jmp_trg = insn.op_find(capstone.CS_OP_IMM, 1).imm
                    queue.append(jmp_trg)
                    
                    jmp_fix_tbl.append((jmp_trg, len(deobf_shellcode), insn.size))
                    deobf_shellcode += insn.bytes

                elif insn.mnemonic == 'call':
                    if insn.op_find(capstone.CS_OP_IMM, 1) == None:
                        pass  # We have a call to win32.
                        deobf_shellcode += insn.bytes
                    else:
                        func_entry = insn.op_find(capstone.CS_OP_IMM, 1).imm
                        func_calls.append(func_entry)
                        
                        if func_entry not in func_map:
                            func_off += _MAX_FUNC_LEN_
                            func_map[func_entry] = func_off
                        
                        f = func_map[func_entry]
                        g = func_map[entry]

                        diff = (f - g - len(deobf_shellcode) - 5) & 0xFFFFFFFF
                        deobf_shellcode += b'\xe8' + struct.pack('<L', diff)
                else:
                    # For all other instructions simply append them to the new shellcode.
                    deobf_shellcode += insn.bytes
                
        deobf_shellcode += b'\x90'*4

    for trg, off, sz in jmp_fix_tbl:
        new_off = off_map[trg]
        diff = (new_off - off - sz) & 0xFFFFFFFF
        if sz == 2:
            if diff >= 0x100:
                raise Exception('Jump offset is not enough!', diff)
            else:
                deobf_shellcode[off + 1] = diff & 0xFF
        elif sz == 3:
            deobf_shellcode[off + 1: off + 5] = struct.pack('<H', diff)
        elif sz == 6:
            deobf_shellcode[off + 2: off + 6] = struct.pack('<L', diff)
        else:
            raise Exception(f'Unknown jump instruction size: {sz}')

    return deobf_shellcode, func_calls


# ----------------------------------------------------------------------------------------
def deobf_shellcode(obf_shellcode, base_addr=0):
    """Deobfuscates a whole shellcode `base_addr`."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True


    # We run this code twice.
    #
    # The reason we do that, is because when we encounter a call instruction we do not
    # know the new offset because we do not know the new size of the current function.
    # So we run once to compute all offsets and then we run again to build the new
    # shellcode with the correct offsets.

    func_map = {0:0}  # Initially empty
    func_off = 0
    queue = [base_addr]
    visited = set()
    funcz = {}
    while queue:
        nxt_func = queue.pop(0)
        if nxt_func in visited:
            continue
        visited.add(nxt_func)

        func, nxt_funcs = _deobf_func(nxt_func, obf_shellcode, md, func_map, func_off)
        funcz[nxt_func] = func
        queue += nxt_funcs

    deobf_shellcode = b'\x90'*0x6000  # Max possible func size.
    deobf_shellcode = bytearray(deobf_shellcode)

    func_map_new = {}
    prev = 0
    for addr, code in funcz.items():
        off = func_map[addr] - base_addr
        func_map_new[addr] = base_addr + prev
        prev += len(code) + 16

    # Now rerun the same code, but this time func_map and func_off are set.
    func_map = func_map_new
    func_off = 0
    queue = [base_addr]
    visited = set()
    funcz = {}
    while queue:
        nxt_func = queue.pop(0)
        if nxt_func in visited:
            continue
        visited.add(nxt_func)

        func, nxt_funcs = _deobf_func(nxt_func, obf_shellcode, md, func_map, func_off)
        funcz[nxt_func] = func
        queue += nxt_funcs
    
    deobf_shellcode = b'\x90'*0x6000  # Max possible func size.
    deobf_shellcode = bytearray(deobf_shellcode)
    
    for addr, code in funcz.items():
        off = func_map[addr] - base_addr
        if len(code) > _MAX_FUNC_LEN_:
            raise Exception(f'Function is too big (0x{len(code):X} bytes)')

        deobf_shellcode[off:off + len(code)] = code

    return deobf_shellcode

# ----------------------------------------------------------------------------------------
