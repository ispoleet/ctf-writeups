#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# HXP 2024 - mbins (Reversing 588)
# ----------------------------------------------------------------------------------------
import struct
import re
import subprocess
import time
import lief


rol64 = lambda a, b: ((a << b) | (a >> (64 - b))) & 0xFFFFFFFFFFFFFFFF
ror64 = lambda a, b: ((a >> b) | (a << (64 - b))) & 0xFFFFFFFFFFFFFFFF


# ----------------------------------------------------------------------------------------
def extract_vm_bytecode(chk_bin_path):
    """Extracts the VM bytecode from the .data section of a chk*.bin file."""
    binary = lief.parse(chk_bin_path)
    data_section = binary.get_section('.data')
    return data_section.content.tobytes()[0x10:] # Bytecode is after 16 bytes.


# ----------------------------------------------------------------------------------------
def emulate_vm_bytecode(
    vm, key, endian, max_insn=9999999999, decr_key_ty=False, dbg=False):
    """Emulates a VM bytecode."""
    if dbg: print(f'[+] VM program size: 0x{len(vm):X}')

    sol = [0]*18
    keyhit = [0]*18

    insn_cnt = 0
    pc = 0
    regs = [0]*32

    stack = bytearray(0x2000)
    regs[0]  = 0x1000
    regs[1]  = len(key)
    regs[30] = 0x2000 # sp
    regs[31] = 0      # pc

    # Write the key somewhere in the middle of the stack.
    for i, k in enumerate(key):
        stack[0x1000 + i] = k
    
    # Initialize stack with the final return address.
    stack[regs[30] - 8:regs[30]] = struct.pack('<Q', 0x13371337)
    regs[30] -= 8
    decr_key = 0

    # If VM bytecode is encrypted, use the first 4 bytes as decryption key
    if decr_key_ty:
        decr_key = struct.unpack(f'{endian}L', vm[:4])[0]
        pc = 4

    while pc != 0x13371337:
        if insn_cnt > max_insn:
            return None, [], insn_cnt
        
        if pc + 4 > len(vm):
            break
    
        # Update decryption key.
        A = decr_key ^ ((decr_key << 13) & 0xFFFFFFFF) ^ ((decr_key ^ ((decr_key << 13) & 0xFFFFFFFF)) >> 17)    
        A &= 0xFFFFFFFF
        B = A ^ (32 * A)
        B &= 0xFFFFFFFF
        decr_key = B & 0xFFFFFFFF
        
        insn = struct.unpack(f'{endian}L', vm[pc:pc + 4])[0]  # Endian changes!
        insn = decr_key ^ insn

        curr_pc = pc
        pc += 4
        insn_cnt += 1

        # When VM starts:
        #   R0  = input
        #   R1  = len(input)
        #   R30 = SP
        #   R31 = PC

        # NOTE: Decoder doesn't have to be perfect/optimized.
        type = insn >> 29
        
        # ================================================================
        if type == 0:  # Arithmetic Instructions
            opcode      = (insn >> 25) & 0x1F
            dst_reg     = (insn >> 19) & 0x1F
            dst_reg_asm = f'R{dst_reg}'
            op1         = (insn >> 14) & 0x1F
            op1_asm     = f'R{op1}'

            v1 = regs[op1]    

            # E = 1110b ~> type is 0 AND bit #24 is set
            if insn & 0xE1000000 == 0:
                if opcode == 7 or opcode == 9:
                    raise Exception('Oups!')
                else:
                    op2 = insn & 0x3FFF
                    op2_asm = f'0x{op2:X}'
                    v2 = op2
            else:
                op2 = (insn >> 9) & 0x1F
                op2_asm = f'R{op2}'
                v2 = regs[op2]

            asm = ''
            opcode &= 0xF
            if opcode == 0:
                res = v1 | v2;
                asm += 'OR'
            elif opcode == 1:
                res = v1 ^ v2;
                asm += 'XOR'
            elif opcode == 2:
                res = v1 & v2;
                asm += 'AND'
            elif opcode == 3:
                res = v1 + v2;
                asm += 'ADD'
            elif opcode == 4:
                res = v1 - v2;
                asm += 'SUB'
            elif opcode == 5:
                res = v1 * v2;
                asm += 'MUL'
            elif opcode == 6:
                res = v1 // v2;
                asm += 'DIV'
            elif opcode == 7:
                res = v1 // v2;
                asm += 'IDIV'
            elif opcode == 8:
                res = v1 % v2;
                asm += 'MOD'
            elif opcode == 9:
                res = v1 % v2;
                asm += 'IMOD'
            elif opcode == 10:
                res = v1 << v2;
                asm += 'SHL'
            elif opcode == 11:
                res = v1 >> v2;
                asm += 'ASR'
            elif opcode == 12:
                res = v1 >> v2;
                asm += 'SHR'
            elif opcode == 13:
                res = rol64(v1, v2);
                asm += 'ROL'
            elif opcode == 14:
                res = ror64(v1, v2);
                asm += 'ROR'
            else:
                res = 0
                asm = 'NUL'

            op1_asm = op1_asm.replace('R30', 'SP')
            op1_asm = op1_asm.replace('R31', 'PC')
            op2_asm = op2_asm.replace('R30', 'SP')
            op2_asm = op2_asm.replace('R31', 'PC')
            dst_reg_asm = dst_reg_asm.replace('R30', 'SP')
            dst_reg_asm = dst_reg_asm.replace('R31', 'PC')

            regs[dst_reg] = res & 0xFFFFFFFFFFFFFFFF

            asm = f'{asm:5} {dst_reg_asm}, {op1_asm}, {op2_asm}'
        # ================================================================
        elif type == 1:  # Branch Instructions        
            if insn & 0x10000000 == 0:
                opcode      = (insn >> 25) & 0x1F        
                dst_reg     = (insn >> 19) & 0x1F            
                dst_reg_asm = f'R{dst_reg}'
                op1         = (insn >> 14) & 0x1F
                op1_asm     = f'R{op1}'
                v1 = regs[op1]

                if (insn >> 24) & 1 or (insn & 0xE1000000) == 0:
                    op2 = ((insn << 50) & 0xFFFFFFFFFFFFFFFF) >> 50
                    op2_asm = f'0x{op2:X}'
                    v2 = op2
                else:
                    op2 = (insn >> 9) & 0x1F
                    op2_asm = f'R{op2}'
                    v2 = regs[op2]

                opcode &= 0x7
                asm = ''
                if opcode == 0:
                    res = v1 == v2;
                    asm += 'S.EQ'
                elif opcode == 1:
                    res = v1 != v2;
                    asm += 'S.NE'
                elif opcode == 2:
                    res = v1 <= v2;
                    asm += 'S.LE'
                elif opcode == 3:
                    res = v1 < v2;
                    asm += 'S.LT'
                elif opcode == 4:
                    res2 = v1 <= v2;
                    asm += 'S.BT'
                elif opcode == 5:
                    res = v1 < v2;
                    asm += 'S.BE'
                elif opcode == 6:
                    res = 0
                    asm += 'NUL'

                asm = f'{asm:5} {dst_reg_asm}, {op1_asm}, {op2_asm}'
                regs[dst_reg] = res
            else:                
                type2 = (insn >> 26) & 3
                reg   = (insn >> 20) & 0x1F
                if type2 == 2:
                    addr = regs[reg]
                    asm = f'CALL R{reg}'

                    #if ( addr < ctx->vm_prog_start || addr >= ctx->vm_prog_end )
                    if addr >= len(vm):
                        raise Exception('Out-Of-Bounds VM Call!')
                
                    raise Exception('Cannot handle CALL instructions!')

                elif type2 == 0:
                    asm = 'RET'                
                    pc = struct.unpack('<Q', stack[regs[30]:regs[30] + 8])[0]
                    regs[30] += 8

                else:
                    if insn & 0x2000000 != 0:
                        # unconditional jump
                        shr, shl = 0x25, 0x27

                        if decr_key_ty:
                            # Update decryption key.
                            C = B ^ ((B << 13) & 0xffffffff) ^ ((B ^ ((B << 13) & 0xffffffff)) >> 17) ^ ((32 * (B ^ ((B << 13) & 0xffffffff) ^ ((B ^ ((B << 13) & 0xffffffff)) >> 17))) & 0xffffffff)
                            C &= 0xffffffff
                            decr_key = C

                            next_pc = struct.unpack(f'{endian}L', vm[pc:pc + 4])[0]
                            pc += 4
                            new_key = C ^ next_pc

                        # Compute offset (+do a hack for negative offsets).
                        off = ((insn << shl) & 0xFFFFFFFFFFFFFFFF) >> shr
                        if off > 0xfffff:
                            # is negative
                            off = ((off & 0xfffff) ^ 0xfffff) +1

                        asm = f'JMP   0x{off:X} (R{reg})'
                        pc = pc - off - 4
                        if decr_key_ty:
                            decr_key = new_key
                            pc -= 4
                    else:
                        # conditional jump
                        # if ( !ctx->vm_regs[insn >> 20) & 0x1F] )              
                        shr, shl = 0x2A, 0x2C

                        if decr_key_ty:
                            # Update decryption key.                            
                            C = B ^ ((B << 13) & 0xffffffff) ^ ((B ^ ((B << 13) & 0xffffffff)) >> 17) ^ ((32 * (B ^ ((B << 13) & 0xffffffff) ^ ((B ^ ((B << 13) & 0xffffffff)) >> 17))) & 0xffffffff)
                            C &= 0xffffffff
                            decr_key = C

                            next_pc = struct.unpack(f'{endian}L', vm[pc:pc + 4])[0]
                            pc += 4
                            new_key = C ^ next_pc

                        # Compute offset (+do a hack for negative offsets).
                        off = ((insn << shl) & 0xFFFFFFFFFFFFFFFF) >> shr
                        if off > 0xfffff:
                            # is negative
                            off = ((off & 0xfffff) ^ 0xfffff) +1
                            off = -off

                        asm = f'JCC   0x{off:X} (R{reg})'
                        
                        if regs[reg] != 0:
                            pc = pc + off - 4
                            if decr_key_ty:
                                decr_key = new_key
                                pc -= 4                                                
                        else:
                            pc = pc + 0  # Jump not taken

        # ================================================================
        elif type == 2:  # Memory Access Instructions
            access_type = (insn >> 27) & 3
            
            if access_type != 0:
                reg1     = (insn >> 21) & 0x1F
                reg1_asm = f'R{reg1}'
                reg2     = (insn >> 16) & 0x1F
                reg2_asm = f'R{reg2}'

                base = (insn & 0xffff) - 0x8000
                if insn & 0x8000 == 0:
                    base = insn & 0xffff
    
                if access_type == 1:
                    asm  = f'LDR'
                    addr = regs[reg2] + base
                    regs[reg1] = struct.unpack('<Q', stack[addr:addr + 8])[0]
                else:
                    access_size = (insn >> 26) & 3

                    addr = regs[reg2] + base
                    if access_size == 0:
                        asm = f'STR.B'
                        stack[addr] = regs[reg1] & 0xFF
                    elif access_size == 1:
                        asm = f'STR.W'
                        stack[addr:addr + 2] = struct.pack('<H', regs[reg1] & 0xFFFF)
                    elif access_size == 2:
                        asm = f'STR.D'
                        stack[addr:addr + 4] = struct.pack('<L', regs[reg1] & 0xFFFFFFFF)
                    elif access_size == 3:
                        asm = f'STR'                        
                        stack[addr:addr + 8] = struct.pack('<Q', regs[reg1])
                    
                reg1_asm = reg1_asm.replace('R30', 'SP')
                reg1_asm = reg1_asm.replace('R31', 'PC')
                reg2_asm = reg2_asm.replace('R30', 'SP')
                reg2_asm = reg2_asm.replace('R31', 'PC')

                asm = f'{asm:5} {reg1_asm}, [{reg2_asm} + 0x{base:X}]'
            else:
                reg1 = (insn >> 16) & 0x1F
                reg1_asm = f'R{reg1}'

                const = struct.unpack(f'{endian}Q', vm[pc:pc + 8])[0] # Endian changes!


                A = decr_key ^ ((decr_key << 13) & 0xFFFFFFFF) ^ ((decr_key ^ ((decr_key << 13) & 0xFFFFFFFF)) >> 17) ^ (32 * (decr_key ^ ((decr_key << 13) & 0xFFFFFFFF) ^ ((decr_key ^ ((decr_key << 13) & 0xFFFFFFFF)) >> 17)))
                A &= 0xFFFFFFFF 

                # This equation changes among binaries :(                
                B = A ^ ((decr_key ^ ((decr_key << 13) & 0xFFFFFFFF) ^ ((decr_key ^ ((decr_key << 13) & 0xFFFFFFFF)) >> 17) ^ ((32 * (decr_key ^ ((decr_key << 13) & 0xFFFFFFFF) ^ ((decr_key ^ ((decr_key << 13) & 0xFFFFFFFF)) >> 17))) & 0xffffffff) ) << 13)                
                B &= 0xFFFFFFFF
#                C = B ^ (32 * B)  # For some other VM programs.
                C = B ^ (B >> 17) ^ (32 * (B ^ (B >> 17)))
                C &= 0xFFFFFFFF

                decr_key = C
                if decr_key_ty == 1:
                    const ^= (C | (A << 32))
                elif decr_key_ty == 2:
                    const ^= (A | (C << 32))
 
                pc += 8
                asm = f'MOV   {reg1_asm}, 0x{const:X}' 

                regs[reg1] = const

        # ================================================================
        else:
            raise Exception(f'Invalid instruction type: 0x{type:x}')

        # Print the instruction, the stack and first 6/last 2 VM registers.
        if dbg: 
            a = ', '.join(f'{r:X}' for r in regs[:6])
            b = ', '.join(f'{r:X}' for r in regs[29:])
            R = f'R:[{a}...{b}]'
            S = '' #S = f'S:' + f'{bytes(stack[regs[30]:])}'  # Print stack.
            print(f'[+] 0x{curr_pc:03X}: {asm:30} | {R:50} {S}')

        # VM hook: Check if we executed a XOR instruction.
        # 
        # It is possible to recover the key just from the XOR instruction.
        # The operation is: `buf[key[i] & 0xFF] ^ const == 0`
        # We know `const` as it's the constant in the `XOR`.
        #
        # If we XOR the `const` with the value in the register, we can recover
        # `buf[key[i] & 0xFF]`. Since `buf` is a permutation of all 256 numbers,
        # we can uniquely find its index from the value.
        #
        # At this point we have recovered `key[i] & 0xFF`. But we know that all
        # key values are unique starting from 0xA0 and incrementing by one. Thus,
        # by subtracting 0xA0 from the value we can find the key index.
        #
        # Finally we need to find the correct value for that index. We use the
        # expected value (`x`) and we do another scan in the array to find the
        # correct index that yields `x`.
        if match := re.match(r'XOR   R..?, R(..?), 0x([0-9A-F]+)', asm):
            r = int(match.group(1))
            x = int(match.group(2), 16)
            print(f'[+] Matching XOR: R{r} = 0x{regs[r]:X} ~> 0x{x:X}')

            # Scan buf (located at sp) searching for the inverse value.
            for j in range(256):
                # This is after XOR is executed, so we xor it again to get the
                # original value.
                if stack[regs[30] + j] == regs[r] ^ x:
                    print(f'[+]   Found XOR: buf[0x{j:X}] = 0x{regs[r] ^ x:X}')
                    
                    # We have found the key index. 
                    # Now scan buf again to find the desired value.
                    for k in range(256):
                        if stack[regs[30] + k] == x:
                            print(f'[+]   Found solution: key[{j-0xa0}] = 0x{k:X}')
                            sol[j - 0xa0] = k
                            keyhit[j - 0xa0] = 1
                    break
                
        asm = ''

    print('[+] Shuffled buf:')
    for k in range(0, 16):
        print(f'[+]    {k:02X} ~>', ', '.join(
                f'{stack[regs[30] - 0x100 + j - 8]:02X}' for j in range(16*k, 16*k+16)))

    print(f'[+] Key bytes found: {sum(keyhit)}/18')

    return sol, keyhit, insn_cnt


# ----------------------------------------------------------------------------------------
def find_bytecode_config(vm):
    """Finds the correct config for the VM bytecode by trial and error."""
    key = [0]*18
    try:
        _, _, cnt = emulate_vm_bytecode(vm, key, '>', max_insn=30, dbg=True)  
        return '>', False      
    except Exception as e:
        print('Not big endian with no decryption key:', e)
    
    try:
        _, _, cnt = emulate_vm_bytecode(vm, key, '<', max_insn=30, dbg=True)        
        return '<', False
    except Exception as e:
        print('Not little endian with no decryption key:', e)

    try:
        _, _, cnt = emulate_vm_bytecode(vm, key, '>', max_insn=30, decr_key_ty=1, dbg=True)
        if cnt >= 30:
            return '>', 1      
    except Exception as e:
        print('Not big endian with decryption key #1:', e)
    
    try:
        _, _, cnt = emulate_vm_bytecode(vm, key, '<', max_insn=30, decr_key_ty=1, dbg=True)
        if cnt >= 30:
            return '<', 1
    except Exception as e:
        print('Not little endian with decryption key #1:', e)

    try:
        _, _, cnt = emulate_vm_bytecode(vm, key, '>', max_insn=30, decr_key_ty=2, dbg=True)
        if cnt >= 30:
            return '>', 2      
    except Exception as e:
        print('Not big endian with decryption key #2:', e)
    
    try:
        _, _, cnt = emulate_vm_bytecode(vm, key, '<', max_insn=30, decr_key_ty=2, dbg=True)
        if cnt >= 30:
            return '<', 2
    except Exception as e:
        print('Not little endian with decryption key #2:', e)

    raise Exception('Cannot find config :(')


# ----------------------------------------------------------------------------------------
def crack_vm_bytecode(vm):
    """Cracks a VM bytecode and recovers the key."""
    endian, decr_key_ty = find_bytecode_config(vm)
    key = [0xA0 + i for i in range(18)]
    print(f'[+] Starting with dummy key: {bytes(key).hex()}')

    key, hits, _ = emulate_vm_bytecode(vm, key, endian,
                        max_insn=9999999999, decr_key_ty=decr_key_ty, dbg=False)
       
    print(f'[+] FINAL KEY: {key}')
    print(f'[+] FINAL KEY: {bytes(key).hex()}')

    return bytes(key).hex(), key, hits


# ----------------------------------------------------------------------------------------
def verify_key(chk_bin_path, key):
  """Verifies that a `key` returns a 0 exit code on a chk binary."""
  result = subprocess.run(f'{chk_bin_path} {key}',
                          shell=True, capture_output=True, text=True)
  return result.returncode == 0


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] mbins VM custom emulator crack started.')

    # The failed binaries from `mbins_vm_emulate_crack.py`:
    bin_set = [
        17, 20, 25, 32, 51, 52, 53, 59, 62, 72, 77, 81, 84, 96, 97, 98, 105, 106, 109, 115, 118, 125, 128, 142, 153, 160, 162, 165, 169, 171, 174, 176, 181, 188, 190, 191, 204, 206, 216, 222, 231, 237, 244, 246, 247, 248, 250, 252, 263, 268, 271, 274, 280, 290, 299, 302, 320, 324, 329, 330, 337, 340, 342, 347, 350, 351, 357, 365, 373, 376, 377, 383, 389, 401, 414, 417, 422, 423, 424, 430, 439, 444, 458, 460, 462, 464, 471, 472, 473, 474, 475, 477, 478, 480, 481, 485, 489, 494, 496, 498, 504, 513, 514, 515, 521, 530, 533, 540, 549, 557, 560, 562, 563, 568, 569, 577, 583, 585, 590, 594, 596, 598, 603, 604, 609, 617, 618, 619, 625, 628, 630, 634, 641, 643, 647, 650, 652, 656, 675, 682, 683, 685, 686, 687, 705, 712, 714, 720, 728, 733, 740, 741, 747, 751, 754, 767, 772, 773, 784, 790, 799, 800, 803, 804, 805, 807, 808, 811, 812, 813, 837, 838, 843, 844, 845, 846, 848, 849, 856, 857, 858, 860, 864, 866, 868, 882, 890, 892, 893, 897, 898, 903, 904, 909, 920, 935, 937, 938, 946, 948, 969, 976, 985
    ]
 
    solutions = []
    failed = []

    for i in bin_set:
        print(f'============================== {i} ==============================')
    
        try:
            vmb = extract_vm_bytecode(f'binaries/chk{i}.bin')
            key, key_list, hits = crack_vm_bytecode(vmb)

            if verify_key(f'binaries/chk{i}.bin', key):
                print(f'[+] SOLUTION #{i} VERIFIED! :D')

                solutions.append(key)

                # We need 950 solutions in total to get the flag.
                # We already have 797 from the previous script.
                if 797 + len(solutions) >= 950:
                    print(f'[+] Solutions:', solutions)

            elif sum(hits) == 17:
                # It possible to recover 17/18 key bytes.
                #
                # This is because if the `const` in the XOR instruction is 0
                # (e.g., `XOR R0, R0, 0`) the whole XOR instruction is omitted.
                #
                # Since we are missing only one byte, we can brute force it.
                print('[+] Missing 1 byte. Starting bruteforce...')
                for j in range(18):
                    if hits[j] == 0:
                        print(f'[+] Missing byte at index #{j}')
                        for k in range(256):
                            key_list[j] = k
                            newkey = bytes(key_list).hex()

                            if verify_key(f'binaries/chk{i}.bin', newkey):
                                print(f'[+] SOLUTION #{i} VERIFIED! :D')
                                solutions.append(newkey)
                
                                if 797 + len(solutions) >= 950:
                                    print(f'[+] Solutions:', solutions)
                                break

                        if k == 256:
                            print('[!] Error. Bruteforce failed.')
            else:
                # If we are missing more than one bytes, fuck it.
                # We already have enough solutions.
                print(f'[!] Error. Missing too many bytes: {sum(hits)}/18')
                failed.append(i)

        except Exception as e:
            print(f'[!] Error. VM emulation failed: {e!r}')
            failed.append(i)
            

        print(f'[+] Correct:{len(solutions)}/{len(bin_set)}. Failed:{len(failed)}/{len(bin_set)}')


    print('[+] Emulation completed.')
    print(f'[+] #{len(solutions)} Solutions:', solutions)
    print(f'[+] #{len(failed)} failed binaries:', failed) 
    print('[+] Program finished successfully. Bye bye :)')

# ----------------------------------------------------------------------------------------
r"""
┌─[11:22:07]─[ispo@ispo-glaptop2]─[~/ctf/hxp_2024/mbins/mbins]
└──> time ./mbins_vm_custom_emu_crack.py 
[+] mbins VM custom emulator crack started.
============================== 17 ==============================
[+] VM program size: 0xA8C
[+] 0x000: OR    R16, R7, 0x3708          | R:[1000, 12, 0, 0, 0, 0...0, 1FF8, 0]              
[+] 0x004: OR    R0, R0, 0x240            | R:[1240, 12, 0, 0, 0, 0...0, 1FF8, 0]              
Not big endian with no decryption key: Invalid instruction type: 0x7
[+] VM program size: 0xA8C
[+] 0x000: SUB   SP, SP, 0x100            | R:[1000, 12, 0, 0, 0, 0...0, 1EF8, 0]              
[+] 0x004: MOV   R2, 0xFFFFFFFF           | R:[1000, 12, FFFFFFFF, 0, 0, 0...0, 1EF8, 0]       
[+] 0x010: AND   R1, R1, R2               | R:[1000, 12, FFFFFFFF, 0, 0, 0...0, 1EF8, 0]       
[+] 0x014: S.NE  R1, R1, 0x12             | R:[1000, 0, FFFFFFFF, 0, 0, 0...0, 1EF8, 0]        
[+] 0x018: JCC   0xA60 (R1)               | R:[1000, 0, FFFFFFFF, 0, 0, 0...0, 1EF8, 0]        
[+] 0x01C: MOV   R3, 0x0                  | R:[1000, 0, FFFFFFFF, 0, 0, 0...0, 1EF8, 0]        
[+] 0x028: ADD   R1, SP, 0x0              | R:[1000, 1EF8, FFFFFFFF, 0, 0, 0...0, 1EF8, 0]     
[+] 0x02C: ADD   R4, R3, 0x0              | R:[1000, 1EF8, FFFFFFFF, 0, 0, 0...0, 1EF8, 0]     
[+] 0x030: ADD   R5, R1, R3               | R:[1000, 1EF8, FFFFFFFF, 0, 0, 1EF8...0, 1EF8, 0]  
[+] 0x034: STR.B R4, [R5 + 0x0]           | R:[1000, 1EF8, FFFFFFFF, 0, 0, 1EF8...0, 1EF8, 0]  
[+] 0x038: ADD   R4, R4, 0x1              | R:[1000, 1EF8, FFFFFFFF, 0, 1, 1EF8...0, 1EF8, 0]  
[+] 0x03C: ADD   R3, R3, 0x1              | R:[1000, 1EF8, FFFFFFFF, 1, 1, 1EF8...0, 1EF8, 0]  
[+] 0x040: S.EQ  R5, R3, 0x100            | R:[1000, 1EF8, FFFFFFFF, 1, 1, 0...0, 1EF8, 0]     
[+] 0x044: JCC   0x8 (R5)                 | R:[1000, 1EF8, FFFFFFFF, 1, 1, 0...0, 1EF8, 0]     
[+] 0x048: JMP   0x18 (R31)               | R:[1000, 1EF8, FFFFFFFF, 1, 1, 0...0, 1EF8, 0]     
[+] 0x030: ADD   R5, R1, R3               | R:[1000, 1EF8, FFFFFFFF, 1, 1, 1EF9...0, 1EF8, 0]  
[+] 0x034: STR.B R4, [R5 + 0x0]           | R:[1000, 1EF8, FFFFFFFF, 1, 1, 1EF9...0, 1EF8, 0]  
[+] 0x038: ADD   R4, R4, 0x1              | R:[1000, 1EF8, FFFFFFFF, 1, 2, 1EF9...0, 1EF8, 0]  
[+] 0x03C: ADD   R3, R3, 0x1              | R:[1000, 1EF8, FFFFFFFF, 2, 2, 1EF9...0, 1EF8, 0]  
[+] 0x040: S.EQ  R5, R3, 0x100            | R:[1000, 1EF8, FFFFFFFF, 2, 2, 0...0, 1EF8, 0]     
[+] 0x044: JCC   0x8 (R5)                 | R:[1000, 1EF8, FFFFFFFF, 2, 2, 0...0, 1EF8, 0]     
[+] 0x048: JMP   0x18 (R31)               | R:[1000, 1EF8, FFFFFFFF, 2, 2, 0...0, 1EF8, 0]     
[+] 0x030: ADD   R5, R1, R3               | R:[1000, 1EF8, FFFFFFFF, 2, 2, 1EFA...0, 1EF8, 0]  
[+] 0x034: STR.B R4, [R5 + 0x0]           | R:[1000, 1EF8, FFFFFFFF, 2, 2, 1EFA...0, 1EF8, 0]  
[+] 0x038: ADD   R4, R4, 0x1              | R:[1000, 1EF8, FFFFFFFF, 2, 3, 1EFA...0, 1EF8, 0]  
[+] 0x03C: ADD   R3, R3, 0x1              | R:[1000, 1EF8, FFFFFFFF, 3, 3, 1EFA...0, 1EF8, 0]  
[+] 0x040: S.EQ  R5, R3, 0x100            | R:[1000, 1EF8, FFFFFFFF, 3, 3, 0...0, 1EF8, 0]     
[+] 0x044: JCC   0x8 (R5)                 | R:[1000, 1EF8, FFFFFFFF, 3, 3, 0...0, 1EF8, 0]     
[+] 0x048: JMP   0x18 (R31)               | R:[1000, 1EF8, FFFFFFFF, 3, 3, 0...0, 1EF8, 0]     
[+] 0x030: ADD   R5, R1, R3               | R:[1000, 1EF8, FFFFFFFF, 3, 3, 1EFB...0, 1EF8, 0]  
[+] 0x034: STR.B R4, [R5 + 0x0]           | R:[1000, 1EF8, FFFFFFFF, 3, 3, 1EFB...0, 1EF8, 0]  
[+] Starting with dummy key: a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1
[+] Matching XOR: R2 = 0xBA ~> 0xB8
[+]   Found XOR: buf[0xA3] = 0x2
[+]   Found solution: key[3] = 0xB1
[+] Matching XOR: R3 = 0x22 ~> 0x4C
[+]   Found XOR: buf[0xA7] = 0x6E
[+]   Found solution: key[7] = 0x3E
[+] Matching XOR: R3 = 0xD4 ~> 0xFE
[+]   Found XOR: buf[0xA6] = 0x2A
[+]   Found solution: key[6] = 0x1D
[+] Matching XOR: R3 = 0xE2 ~> 0x56
[+]   Found XOR: buf[0xAD] = 0xB4
[+]   Found solution: key[13] = 0x72
[+] Matching XOR: R0 = 0xE0 ~> 0x94
[+]   Found XOR: buf[0xA5] = 0x74
[+]   Found solution: key[5] = 0xB6
[+] Matching XOR: R1 = 0x39 ~> 0xD3
[+]   Found XOR: buf[0xAB] = 0xEA
[+]   Found solution: key[11] = 0xD9
[+] Matching XOR: R1 = 0xD4 ~> 0xC7
[+]   Found XOR: buf[0xA4] = 0x13
[+]   Found solution: key[4] = 0xCF
[+] Matching XOR: R1 = 0xAA ~> 0x11
[+]   Found XOR: buf[0xA0] = 0xBB
[+]   Found solution: key[0] = 0x1
[+] Matching XOR: R1 = 0x22 ~> 0xE9
[+]   Found XOR: buf[0xAA] = 0xCB
[+]   Found solution: key[10] = 0x63
[+] Matching XOR: R1 = 0xFB ~> 0x87
[+]   Found XOR: buf[0xAC] = 0x7C
[+]   Found solution: key[12] = 0x18
[+] Matching XOR: R1 = 0xA4 ~> 0xD5
[+]   Found XOR: buf[0xA2] = 0x71
[+]   Found solution: key[2] = 0x17
[+] Matching XOR: R1 = 0x91 ~> 0xF
[+]   Found XOR: buf[0xB0] = 0x9E
[+]   Found solution: key[16] = 0x2D
[+] Matching XOR: R1 = 0x79 ~> 0x65
[+]   Found XOR: buf[0xA9] = 0x1C
[+]   Found solution: key[9] = 0xF6
[+] Matching XOR: R1 = 0x9 ~> 0x4D
[+]   Found XOR: buf[0xAF] = 0x44
[+]   Found solution: key[15] = 0xE3
[+] Matching XOR: R1 = 0x50 ~> 0x8
[+]   Found XOR: buf[0xA1] = 0x58
[+]   Found solution: key[1] = 0x90
[+] Matching XOR: R1 = 0x4 ~> 0xBC
[+]   Found XOR: buf[0xB1] = 0xB8
[+]   Found solution: key[17] = 0x34
[+] Matching XOR: R1 = 0x82 ~> 0x79
[+]   Found XOR: buf[0xA8] = 0xFB
[+]   Found solution: key[8] = 0x26
[+] Matching XOR: R1 = 0x5C ~> 0xD7
[+]   Found XOR: buf[0xAE] = 0x8B
[+]   Found solution: key[14] = 0x95
[+] Shuffled buf:
[+]    00 ~> 82, 11, A0, 20, 88, 25, 28, D4, 9C, 95, AC, 36, D1, A1, F0, 98
[+]    01 ~> 14, 62, 2B, 47, AE, 49, 90, D5, 87, E0, 68, 4F, CC, FE, 32, 6A
[+]    02 ~> C6, 30, BA, 6C, DC, 2F, 79, A4, 83, D8, 41, 86, E2, 0F, 7E, 81
[+]    03 ~> 26, 8F, 45, DA, BC, 52, 70, 22, 7A, E4, 27, E8, 05, DB, 4C, D6
[+]    04 ~> 51, 35, AA, C4, 67, D0, 59, 21, C3, 03, 97, 17, F3, 34, 54, 8E
[+]    05 ~> 9B, 6D, 84, 1D, DD, A5, CD, B5, F1, 60, 93, 73, EB, C5, 9F, EC
[+]    06 ~> 89, AB, C1, E9, 5D, 64, 85, B3, 4A, 3B, 38, 42, E3, 6F, 77, 7F
[+]    07 ~> B6, 1A, 56, 61, 2C, C0, A2, 7D, B9, 6B, 06, 55, 00, 8C, E1, 9A
[+]    08 ~> 63, 5C, 5A, E5, 72, 96, C8, C9, BE, 9D, 33, C2, F2, 09, 3C, 4E
[+]    09 ~> 08, 04, 7B, 5B, 50, D7, 8A, 48, 5E, CE, 99, FF, 12, 16, BD, E7
[+]    0A ~> BB, 58, 71, 02, 13, 74, 2A, 6E, FB, 1C, CB, EA, 7C, B4, 8B, 44
[+]    0B ~> 9E, B8, 5F, B0, 76, BF, 94, 8D, 53, A6, 46, 1F, 29, DE, 18, EF
[+]    0C ~> 0D, AF, D2, 1E, 15, B1, A8, EE, 39, 0C, F9, 01, 23, FA, 78, C7
[+]    0D ~> 0E, A7, DF, 80, 69, 24, F8, A3, F7, D3, 40, 19, 91, 07, 10, 43
[+]    0E ~> 75, B2, 2E, 4D, E6, 3D, 2D, 3E, CF, 3A, 0B, FD, 1B, 4B, 92, F5
[+]    0F ~> A9, F6, B7, F4, D9, 0A, 65, 37, AD, ED, 66, FC, 31, 57, CA, 3F
[+] Key bytes found: 18/18
[+] FINAL KEY: [1, 144, 23, 177, 207, 182, 29, 62, 38, 246, 99, 217, 24, 114, 149, 227, 45, 52]
[+] FINAL KEY: 019017b1cfb61d3e26f663d9187295e32d34
[+] SOLUTION #17 VERIFIED! :D
[+] Correct:1/203. Failed:0/203
============================== 20 ==============================
[+] VM program size: 0xA90
Not big endian with no decryption key: Invalid instruction type: 0x3
[+] VM program size: 0xA90
Not little endian with no decryption key: Invalid instruction type: 0x3
[+] VM program size: 0xA90
[+] 0x004: SUB   SP, SP, 0x100            | R:[1000, 12, 0, 0, 0, 0...0, 1EF8, 0]              
[+] 0x008: MOV   R2, 0xFFFFFFFF           | R:[1000, 12, FFFFFFFF, 0, 0, 0...0, 1EF8, 0]       
[+] 0x014: AND   R1, R1, R2               | R:[1000, 12, FFFFFFFF, 0, 0, 0...0, 1EF8, 0]       
[+] 0x018: S.NE  R1, R1, 0x12             | R:[1000, 0, FFFFFFFF, 0, 0, 0...0, 1EF8, 0]        
[+] 0x01C: JCC   0xA60 (R1)               | R:[1000, 0, FFFFFFFF, 0, 0, 0...0, 1EF8, 0]        
[+] 0x024: MOV   R3, 0x0                  | R:[1000, 0, FFFFFFFF, 0, 0, 0...0, 1EF8, 0]        
[+] 0x030: ADD   R1, SP, 0x0              | R:[1000, 1EF8, FFFFFFFF, 0, 0, 0...0, 1EF8, 0]     
[+] 0x034: ADD   R4, R3, 0x0              | R:[1000, 1EF8, FFFFFFFF, 0, 0, 0...0, 1EF8, 0]     
[+] 0x038: ADD   R5, R1, R3               | R:[1000, 1EF8, FFFFFFFF, 0, 0, 1EF8...0, 1EF8, 0]  
[+] 0x03C: STR.B R4, [R5 + 0x0]           | R:[1000, 1EF8, FFFFFFFF, 0, 0, 1EF8...0, 1EF8, 0]  
[+] 0x040: ADD   R4, R4, 0x1              | R:[1000, 1EF8, FFFFFFFF, 0, 1, 1EF8...0, 1EF8, 0]  
[+] 0x044: ADD   R3, R3, 0x1              | R:[1000, 1EF8, FFFFFFFF, 1, 1, 1EF8...0, 1EF8, 0]  
[+] 0x048: S.EQ  R5, R3, 0x100            | R:[1000, 1EF8, FFFFFFFF, 1, 1, 0...0, 1EF8, 0]     
[+] 0x04C: JCC   0x10 (R5)                | R:[1000, 1EF8, FFFFFFFF, 1, 1, 0...0, 1EF8, 0]     
[+] 0x054: JMP   0x1C (R31)               | R:[1000, 1EF8, FFFFFFFF, 1, 1, 0...0, 1EF8, 0]     
[+] 0x038: ADD   R5, R1, R3               | R:[1000, 1EF8, FFFFFFFF, 1, 1, 1EF9...0, 1EF8, 0]  
[+] 0x03C: STR.B R4, [R5 + 0x0]           | R:[1000, 1EF8, FFFFFFFF, 1, 1, 1EF9...0, 1EF8, 0]  
[+] 0x040: ADD   R4, R4, 0x1              | R:[1000, 1EF8, FFFFFFFF, 1, 2, 1EF9...0, 1EF8, 0]  
[+] 0x044: ADD   R3, R3, 0x1              | R:[1000, 1EF8, FFFFFFFF, 2, 2, 1EF9...0, 1EF8, 0]  
[+] 0x048: S.EQ  R5, R3, 0x100            | R:[1000, 1EF8, FFFFFFFF, 2, 2, 0...0, 1EF8, 0]     
[+] 0x04C: JCC   0x10 (R5)                | R:[1000, 1EF8, FFFFFFFF, 2, 2, 0...0, 1EF8, 0]     
[+] 0x054: JMP   0x1C (R31)               | R:[1000, 1EF8, FFFFFFFF, 2, 2, 0...0, 1EF8, 0]     
[+] 0x038: ADD   R5, R1, R3               | R:[1000, 1EF8, FFFFFFFF, 2, 2, 1EFA...0, 1EF8, 0]  
[+] 0x03C: STR.B R4, [R5 + 0x0]           | R:[1000, 1EF8, FFFFFFFF, 2, 2, 1EFA...0, 1EF8, 0]  
[+] 0x040: ADD   R4, R4, 0x1              | R:[1000, 1EF8, FFFFFFFF, 2, 3, 1EFA...0, 1EF8, 0]  
[+] 0x044: ADD   R3, R3, 0x1              | R:[1000, 1EF8, FFFFFFFF, 3, 3, 1EFA...0, 1EF8, 0]  
[+] 0x048: S.EQ  R5, R3, 0x100            | R:[1000, 1EF8, FFFFFFFF, 3, 3, 0...0, 1EF8, 0]     
[+] 0x04C: JCC   0x10 (R5)                | R:[1000, 1EF8, FFFFFFFF, 3, 3, 0...0, 1EF8, 0]     
[+] 0x054: JMP   0x1C (R31)               | R:[1000, 1EF8, FFFFFFFF, 3, 3, 0...0, 1EF8, 0]     
[+] 0x038: ADD   R5, R1, R3               | R:[1000, 1EF8, FFFFFFFF, 3, 3, 1EFB...0, 1EF8, 0]  
[+] 0x03C: STR.B R4, [R5 + 0x0]           | R:[1000, 1EF8, FFFFFFFF, 3, 3, 1EFB...0, 1EF8, 0]  
[+] Starting with dummy key: a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1
[+] Matching XOR: R2 = 0x2B ~> 0x9D
[+]   Found XOR: buf[0xA5] = 0xB6
[+]   Found solution: key[5] = 0xC2
[+] Matching XOR: R3 = 0xE1 ~> 0xF6
[+]   Found XOR: buf[0xA2] = 0x17
[+]   Found solution: key[2] = 0x98
[+] Matching XOR: R3 = 0x92 ~> 0x7B
[+]   Found XOR: buf[0xB0] = 0xE9
[+]   Found solution: key[16] = 0xAA
[+] Matching XOR: R3 = 0x6F ~> 0x7B
[+]   Found XOR: buf[0xAE] = 0x14
[+]   Found solution: key[14] = 0xAA
[+] Matching XOR: R0 = 0xC0 ~> 0x7
[+]   Found XOR: buf[0xA8] = 0xC7
[+]   Found solution: key[8] = 0x3F
[+] Matching XOR: R1 = 0x43 ~> 0xC3
[+]   Found XOR: buf[0xA4] = 0x80
[+]   Found solution: key[4] = 0x8E
[+] Matching XOR: R1 = 0x25 ~> 0xA2
[+]   Found XOR: buf[0xAD] = 0x87
[+]   Found solution: key[13] = 0x5A
[+] Matching XOR: R1 = 0xCB ~> 0x20
[+]   Found XOR: buf[0xA1] = 0xEB
[+]   Found solution: key[1] = 0x65
[+] Matching XOR: R1 = 0x85 ~> 0x5C
[+]   Found XOR: buf[0xAF] = 0xD9
[+]   Found solution: key[15] = 0xB3
[+] Matching XOR: R1 = 0xFF ~> 0x61
[+]   Found XOR: buf[0xA6] = 0x9E
[+]   Found solution: key[6] = 0x42
[+] Matching XOR: R1 = 0x72 ~> 0xFE
[+]   Found XOR: buf[0xA9] = 0x8C
[+]   Found solution: key[9] = 0x3B
[+] Matching XOR: R1 = 0x18 ~> 0x13
[+]   Found XOR: buf[0xB1] = 0xB
[+]   Found solution: key[17] = 0x1C
[+] Matching XOR: R1 = 0xAF ~> 0x94
[+]   Found XOR: buf[0xA0] = 0x3B
[+]   Found solution: key[0] = 0x1
[+] Matching XOR: R1 = 0x59 ~> 0xDF
[+]   Found XOR: buf[0xAC] = 0x86
[+]   Found solution: key[12] = 0x82
[+] Matching XOR: R1 = 0x6E ~> 0x7
[+]   Found XOR: buf[0xA7] = 0x69
[+]   Found solution: key[7] = 0x3F
[+] Matching XOR: R1 = 0xA7 ~> 0xF8
[+]   Found XOR: buf[0xA3] = 0x5F
[+]   Found solution: key[3] = 0x38
[+] Matching XOR: R1 = 0x2A ~> 0x51
[+]   Found XOR: buf[0xAA] = 0x7B
[+]   Found solution: key[10] = 0x48
[+] Matching XOR: R1 = 0x94 ~> 0xDD
[+]   Found XOR: buf[0xAB] = 0x49
[+]   Found solution: key[11] = 0xFB
[+] Shuffled buf:
[+]    00 ~> A0, 94, BC, FF, 6B, B7, B8, 04, 42, DE, 06, 90, C8, 35, 15, 1D
[+]    01 ~> 72, 23, B3, 76, 25, CD, 6A, 1B, 31, B0, 68, 93, 13, 63, 50, 6E
[+]    02 ~> 55, AF, 4D, 96, 7D, E6, 22, FB, 5D, C0, 74, C9, F0, 91, 2F, 0D
[+]    03 ~> F4, D1, F5, 01, 19, 52, C4, D2, F8, BB, B5, FE, C5, 0C, DB, 07
[+]    04 ~> 4C, 75, 61, A3, 00, A6, C6, 5E, 51, 39, 02, D8, 5B, 9B, 6D, 95
[+]    05 ~> 8A, 03, 3F, 59, 98, F3, 2A, 8D, B1, 24, A2, 4A, 6F, AC, 77, 6C
[+]    06 ~> AA, 2D, 7A, A5, 66, 20, 84, D0, FA, 3C, 71, 2C, 48, ED, EE, 37
[+]    07 ~> 32, E3, 38, 8F, 2E, 44, 05, 11, CB, A9, A7, FD, 1F, 12, 83, AB
[+]    08 ~> 67, F9, DF, 41, 1C, 28, 47, 30, CE, E7, 26, 21, 2B, 33, C3, 79
[+]    09 ~> EC, 1E, A1, 36, 1A, 9A, CC, D5, F6, A8, E8, 3A, 29, D4, 16, F1
[+]    0A ~> 3B, EB, 17, 5F, 80, B6, 9E, 69, C7, 8C, 7B, 49, 86, 87, 14, D9
[+]    0B ~> E9, 0B, 81, 5C, 3D, CA, 73, DC, B2, 64, BE, B9, 7E, DA, 0A, 82
[+]    0C ~> D3, 4B, 9D, BF, 58, 53, 78, 43, E0, 34, 08, 45, AE, 40, 65, 9F
[+]    0D ~> 88, 10, D6, 9C, 4F, E5, BD, BA, D7, 62, 27, 60, 46, E4, 85, A4
[+]    0E ~> EF, E1, 99, 89, CF, 7F, E2, 0E, 4E, 8B, 7C, EA, 56, 54, 92, 09
[+]    0F ~> 8E, AD, F2, 97, 0F, C2, 18, 70, 3E, B4, F7, DD, 57, 5A, FC, C1
[+] Key bytes found: 18/18
[+] FINAL KEY: [1, 101, 152, 56, 142, 194, 66, 63, 63, 59, 72, 251, 130, 90, 170, 179, 170, 28]
[+] FINAL KEY: 016598388ec2423f3f3b48fb825aaab3aa1c
[+] SOLUTION #20 VERIFIED! :D
[+] Correct:2/203. Failed:0/203
============================== 25 ==============================

..... TRUNCATED FOR BREVITY .....


[+] Correct:191/203. Failed:11/203
============================== 985 ==============================
[+] VM program size: 0xA8C
[+] 0x000: JMP   0x98234 (R31)            | R:[1000, 12, 0, 0, 0, 0...0, 1FF8, 0]              
Not big endian with no decryption key: unpack requires a buffer of 4 bytes
[+] VM program size: 0xA8C
Not little endian with no decryption key: Invalid instruction type: 0x3
[+] VM program size: 0xA8C
Not big endian with decryption key #1: Invalid instruction type: 0x4
[+] VM program size: 0xA8C
[+] 0x004: SUB   SP, SP, 0x100            | R:[1000, 12, 0, 0, 0, 0...0, 1EF8, 0]              
[+] 0x008: MOV   R2, 0x440A951CBBF56AE3   | R:[1000, 12, 440A951CBBF56AE3, 0, 0, 0...0, 1EF8, 0] 
[+] 0x014: AND   R1, R1, R2               | R:[1000, 2, 440A951CBBF56AE3, 0, 0, 0...0, 1EF8, 0] 
[+] 0x018: S.NE  R1, R1, 0x12             | R:[1000, 1, 440A951CBBF56AE3, 0, 0, 0...0, 1EF8, 0] 
[+] 0x01C: JCC   0xA5C (R1)               | R:[1000, 1, 440A951CBBF56AE3, 0, 0, 0...0, 1EF8, 0] 
[+] 0xA78: MOV   R0, 0xFCD05998FCD05998   | R:[FCD05998FCD05998, 1, 440A951CBBF56AE3, 0, 0, 0...0, 1EF8, 0] 
[+] 0xA84: ADD   SP, SP, 0x100            | R:[FCD05998FCD05998, 1, 440A951CBBF56AE3, 0, 0, 0...0, 1FF8, 0] 
[+] 0xA88: RET                            | R:[FCD05998FCD05998, 1, 440A951CBBF56AE3, 0, 0, 0...0, 2000, 0] 
[+] Shuffled buf:
[+]    00 ~> 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
[+]    01 ~> 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
[+]    02 ~> 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
[+]    03 ~> 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
[+]    04 ~> 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
[+]    05 ~> 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
[+]    06 ~> 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
[+]    07 ~> 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
[+]    08 ~> 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
[+]    09 ~> 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
[+]    0A ~> 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
[+]    0B ~> 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
[+]    0C ~> 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
[+]    0D ~> 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
[+]    0E ~> 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
[+]    0F ~> 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00
[+] Key bytes found: 0/18
[+] VM program size: 0xA8C
Not big endian with decryption key #2: Invalid instruction type: 0x4
[+] VM program size: 0xA8C
[+] 0x004: SUB   SP, SP, 0x100            | R:[1000, 12, 0, 0, 0, 0...0, 1EF8, 0]              
[+] 0x008: MOV   R2, 0xFFFFFFFF           | R:[1000, 12, FFFFFFFF, 0, 0, 0...0, 1EF8, 0]       
[+] 0x014: AND   R1, R1, R2               | R:[1000, 12, FFFFFFFF, 0, 0, 0...0, 1EF8, 0]       
[+] 0x018: S.NE  R1, R1, 0x12             | R:[1000, 0, FFFFFFFF, 0, 0, 0...0, 1EF8, 0]        
[+] 0x01C: JCC   0xA5C (R1)               | R:[1000, 0, FFFFFFFF, 0, 0, 0...0, 1EF8, 0]        
[+] 0x024: MOV   R3, 0x0                  | R:[1000, 0, FFFFFFFF, 0, 0, 0...0, 1EF8, 0]        
[+] 0x030: ADD   R1, SP, 0x0              | R:[1000, 1EF8, FFFFFFFF, 0, 0, 0...0, 1EF8, 0]     
[+] 0x034: ADD   R4, R3, 0x0              | R:[1000, 1EF8, FFFFFFFF, 0, 0, 0...0, 1EF8, 0]     
[+] 0x038: ADD   R5, R1, R3               | R:[1000, 1EF8, FFFFFFFF, 0, 0, 1EF8...0, 1EF8, 0]  
[+] 0x03C: STR.B R4, [R5 + 0x0]           | R:[1000, 1EF8, FFFFFFFF, 0, 0, 1EF8...0, 1EF8, 0]  
[+] 0x040: ADD   R4, R4, 0x1              | R:[1000, 1EF8, FFFFFFFF, 0, 1, 1EF8...0, 1EF8, 0]  
[+] 0x044: ADD   R3, R3, 0x1              | R:[1000, 1EF8, FFFFFFFF, 1, 1, 1EF8...0, 1EF8, 0]  
[+] 0x048: S.EQ  R5, R3, 0x100            | R:[1000, 1EF8, FFFFFFFF, 1, 1, 0...0, 1EF8, 0]     
[+] 0x04C: JCC   0x10 (R5)                | R:[1000, 1EF8, FFFFFFFF, 1, 1, 0...0, 1EF8, 0]     
[+] 0x054: JMP   0x1C (R31)               | R:[1000, 1EF8, FFFFFFFF, 1, 1, 0...0, 1EF8, 0]     
[+] 0x038: ADD   R5, R1, R3               | R:[1000, 1EF8, FFFFFFFF, 1, 1, 1EF9...0, 1EF8, 0]  
[+] 0x03C: STR.B R4, [R5 + 0x0]           | R:[1000, 1EF8, FFFFFFFF, 1, 1, 1EF9...0, 1EF8, 0]  
[+] 0x040: ADD   R4, R4, 0x1              | R:[1000, 1EF8, FFFFFFFF, 1, 2, 1EF9...0, 1EF8, 0]  
[+] 0x044: ADD   R3, R3, 0x1              | R:[1000, 1EF8, FFFFFFFF, 2, 2, 1EF9...0, 1EF8, 0]  
[+] 0x048: S.EQ  R5, R3, 0x100            | R:[1000, 1EF8, FFFFFFFF, 2, 2, 0...0, 1EF8, 0]     
[+] 0x04C: JCC   0x10 (R5)                | R:[1000, 1EF8, FFFFFFFF, 2, 2, 0...0, 1EF8, 0]     
[+] 0x054: JMP   0x1C (R31)               | R:[1000, 1EF8, FFFFFFFF, 2, 2, 0...0, 1EF8, 0]     
[+] 0x038: ADD   R5, R1, R3               | R:[1000, 1EF8, FFFFFFFF, 2, 2, 1EFA...0, 1EF8, 0]  
[+] 0x03C: STR.B R4, [R5 + 0x0]           | R:[1000, 1EF8, FFFFFFFF, 2, 2, 1EFA...0, 1EF8, 0]  
[+] 0x040: ADD   R4, R4, 0x1              | R:[1000, 1EF8, FFFFFFFF, 2, 3, 1EFA...0, 1EF8, 0]  
[+] 0x044: ADD   R3, R3, 0x1              | R:[1000, 1EF8, FFFFFFFF, 3, 3, 1EFA...0, 1EF8, 0]  
[+] 0x048: S.EQ  R5, R3, 0x100            | R:[1000, 1EF8, FFFFFFFF, 3, 3, 0...0, 1EF8, 0]     
[+] 0x04C: JCC   0x10 (R5)                | R:[1000, 1EF8, FFFFFFFF, 3, 3, 0...0, 1EF8, 0]     
[+] 0x054: JMP   0x1C (R31)               | R:[1000, 1EF8, FFFFFFFF, 3, 3, 0...0, 1EF8, 0]     
[+] 0x038: ADD   R5, R1, R3               | R:[1000, 1EF8, FFFFFFFF, 3, 3, 1EFB...0, 1EF8, 0]  
[+] 0x03C: STR.B R4, [R5 + 0x0]           | R:[1000, 1EF8, FFFFFFFF, 3, 3, 1EFB...0, 1EF8, 0]  
[+] Starting with dummy key: a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1
[+] Matching XOR: R2 = 0x5 ~> 0x70
[+]   Found XOR: buf[0xA1] = 0x75
[+]   Found solution: key[1] = 0xCB
[+] Matching XOR: R3 = 0x68 ~> 0x36
[+]   Found XOR: buf[0xAC] = 0x5E
[+]   Found solution: key[12] = 0x16
[+] Matching XOR: R3 = 0xFD ~> 0x66
[+]   Found XOR: buf[0xB1] = 0x9B
[+]   Found solution: key[17] = 0xD9
[+] Matching XOR: R3 = 0x2E ~> 0x38
[+]   Found XOR: buf[0xA4] = 0x16
[+]   Found solution: key[4] = 0xD8
[+] Matching XOR: R0 = 0xC1 ~> 0x99
[+]   Found XOR: buf[0xA9] = 0x58
[+]   Found solution: key[9] = 0x9D
[+] Matching XOR: R1 = 0xF ~> 0x43
[+]   Found XOR: buf[0xA5] = 0x4C
[+]   Found solution: key[5] = 0xA
[+] Matching XOR: R1 = 0x5 ~> 0x2F
[+]   Found XOR: buf[0xA8] = 0x2A
[+]   Found solution: key[8] = 0x84
[+] Matching XOR: R1 = 0x26 ~> 0xA7
[+]   Found XOR: buf[0xB0] = 0x81
[+]   Found solution: key[16] = 0x9
[+] Matching XOR: R1 = 0x57 ~> 0x2D
[+]   Found XOR: buf[0xA2] = 0x7A
[+]   Found solution: key[2] = 0x31
[+] Matching XOR: R1 = 0xCB ~> 0x97
[+]   Found XOR: buf[0xAE] = 0x5C
[+]   Found solution: key[14] = 0x6F
[+] Matching XOR: R1 = 0x50 ~> 0xEC
[+]   Found XOR: buf[0xAA] = 0xBC
[+]   Found solution: key[10] = 0x75
[+] Matching XOR: R1 = 0x32 ~> 0xC
[+]   Found XOR: buf[0xAD] = 0x3E
[+]   Found solution: key[13] = 0x15
[+] Matching XOR: R1 = 0x89 ~> 0x13
[+]   Found XOR: buf[0xAB] = 0x9A
[+]   Found solution: key[11] = 0x58
[+] Matching XOR: R1 = 0xD3 ~> 0xD0
[+]   Found XOR: buf[0xAF] = 0x3
[+]   Found solution: key[15] = 0x3E
[+] Matching XOR: R1 = 0x7D ~> 0x2C
[+]   Found XOR: buf[0xA0] = 0x51
[+]   Found solution: key[0] = 0x1
[+] Matching XOR: R1 = 0x31 ~> 0xF5
[+]   Found XOR: buf[0xA6] = 0xC4
[+]   Found solution: key[6] = 0x8B
[+] Matching XOR: R1 = 0x19 ~> 0x2E
[+]   Found XOR: buf[0xA7] = 0x37
[+]   Found solution: key[7] = 0x9C
[+] Matching XOR: R1 = 0x5F ~> 0xAD
[+]   Found XOR: buf[0xA3] = 0xF2
[+]   Found solution: key[3] = 0xF0
[+] Shuffled buf:
[+]    00 ~> 78, 2C, D5, 62, 44, A1, E5, F3, F0, A7, 43, 7F, 1C, 56, 3B, DA
[+]    01 ~> 20, 7B, 25, 50, E4, 0C, 36, 77, 05, 57, 9E, 32, 08, E6, B0, AA
[+]    02 ~> BD, F4, 54, 94, 6A, 7D, EE, 3C, B9, 52, 67, E3, CD, 39, 06, 9C
[+]    03 ~> EB, 2D, 3F, 1D, 6B, 5F, 64, 48, CE, 60, 1F, AE, 4D, 7E, D0, D1
[+]    04 ~> 3D, 8A, 27, C1, C3, DC, 79, D3, CC, 28, 40, 31, AC, 83, 92, C0
[+]    05 ~> FC, B8, 17, 9F, B2, 30, 59, 55, 13, 98, 6E, 02, 14, A8, 23, 65
[+]    06 ~> 1B, 91, 22, 24, A6, 45, C7, D2, AF, 41, 8B, ED, 8F, 8C, 09, 97
[+]    07 ~> 61, E1, 47, 15, 89, EC, 7C, 88, 19, E9, 4B, C6, 18, 12, B7, EF
[+]    08 ~> 07, A3, F9, 4A, 2F, 87, B3, 95, 4E, D8, 9D, F5, 8D, 53, 90, 42
[+]    09 ~> C5, A5, CB, C9, 5D, DD, FD, 6F, 26, 84, BE, 96, 2E, 99, 46, 0D
[+]    0A ~> 51, 75, 7A, F2, 16, 4C, C4, 37, 2A, 58, BC, 9A, 5E, 3E, 5C, 03
[+]    0B ~> 81, 9B, 5A, 3A, 4F, E0, 10, 1E, FF, D9, BF, CF, 33, DF, 04, 63
[+]    0C ~> FE, 85, 0F, 8E, 1A, 21, CA, EA, 76, A4, F7, 70, BA, 5B, 69, A2
[+]    0D ~> 29, 6D, 35, C8, BB, F1, 72, B4, 38, 66, DE, E7, C2, FB, F8, 0A
[+]    0E ~> 0B, 68, E2, AB, A0, 82, D7, 6C, 11, DB, 93, 0E, 01, 73, B1, 49
[+]    0F ~> AD, D4, FA, 74, A9, D6, 2B, 00, E8, 71, 86, F6, 34, B5, B6, 80
[+] Key bytes found: 18/18
[+] FINAL KEY: [1, 203, 49, 240, 216, 10, 139, 156, 132, 157, 117, 88, 22, 21, 111, 62, 9, 217]
[+] FINAL KEY: 01cb31f0d80a8b9c849d755816156f3e09d9
[+] SOLUTION #985 VERIFIED! :D
[+] Solutions: ['019017b1cfb61d3e26f663d9187295e32d34', '016598388ec2423f3f3b48fb825aaab3aa1c', '038319e19165f3f7e54089b06612c40cff1a', '01e02366c8595f6452bf6b8f2cf2b3e7fa0c', ....
[+] Correct:192/203. Failed:11/203
[+] Emulation completed.
[+] #192 Solutions: ['019017b1cfb61d3e26f663d9187295e32d34', '016598388ec2423f3f3b48fb825aaab3aa1c', '038319e19165f3f7e54089b06612c40cff1a', '01e02366c8595f6452bf6b8f2cf2b3e7fa0c', ...
[+] #11 failed binaries: [250, 324, 424, 549, 618, 687, 712, 813, 860, 909, 948]
[+] Program finished successfully. Bye bye :)

real    97m3.195s
user    96m53.767s
sys 0m9.333s

"""
# ----------------------------------------------------------------------------------------
