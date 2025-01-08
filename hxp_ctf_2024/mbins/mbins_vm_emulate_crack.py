#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# HXP 2024 - mbins (Reversing 588)
# ----------------------------------------------------------------------------------------
import struct
import capstone
import unicorn
import lief
import re
import subprocess
import z3


rol64 = lambda a, b: ((a << b) | (a >> (64 - b))) & 0xFFFFFFFFFFFFFFFF
ror64 = lambda a, b: ((a >> b) | (a << (64 - b))) & 0xFFFFFFFFFFFFFFFF

# ----------------------------------------------------------------------------------------
def disassemble_vm_insn(insn, dbg=False):
    """Disassembles a VM instruction."""
    deferred = None

    # NOTE: Decoder doesn't have to be perfect/optimized.
    type = insn >> 29  # Instruction type
    
    # ================================================================
    if type == 0:  # Arithmetic Instructions
        opcode      = (insn >> 25) & 0x1F
        dst_reg     = (insn >> 19) & 0x1F
        dst_reg_asm = f'R{dst_reg}'
        op1         = (insn >> 14) & 0x1F
        op1_asm     = f'R{op1}'

        # E = 1110b ~> type is 0 AND bit #24 is set
        if insn & 0xE1000000 == 0:
            if opcode == 7 or opcode == 9:
                raise Exception('Oups!')
            else:
                op2 = insn & 0x3FFF
                op2_asm = f'0x{op2:X}'
        else:
            op2 = (insn >> 9) & 0x1F
            op2_asm = f'R{op2}'

        asm = ''
        opcode &= 0xF
        if   opcode == 0:  asm += 'OR'
        elif opcode == 1:  asm += 'XOR'
        elif opcode == 2:  asm += 'AND'
        elif opcode == 3:  asm += 'ADD'
        elif opcode == 4:  asm += 'SUB'
        elif opcode == 5:  asm += 'MUL'
        elif opcode == 6:  asm += 'DIV'
        elif opcode == 7:  asm += 'IDIV'
        elif opcode == 8:  asm += 'MOD'
        elif opcode == 9:  asm += 'IMOD'
        elif opcode == 10: asm += 'SHL'
        elif opcode == 11: asm += 'ASR'
        elif opcode == 12: asm += 'SHR'
        elif opcode == 13: asm += 'ROL'
        elif opcode == 14: asm += 'ROR'
        else:              asm = 'NUL'

        op1_asm = op1_asm.replace('R30', 'SP')
        op1_asm = op1_asm.replace('R31', 'PC')
        op2_asm = op2_asm.replace('R30', 'SP')
        op2_asm = op2_asm.replace('R31', 'PC')
        dst_reg_asm = dst_reg_asm.replace('R30', 'SP')
        dst_reg_asm = dst_reg_asm.replace('R31', 'PC')

        asm = f'{asm:5} {dst_reg_asm}, {op1_asm}, {op2_asm}'
    # ================================================================
    elif type == 1:  # Branch Instructions
        if insn & 0x10000000 == 0:
            opcode      = (insn >> 25) & 0x1F        
            dst_reg     = (insn >> 19) & 0x1F            
            dst_reg_asm = f'R{dst_reg}'
            op1         = (insn >> 14) & 0x1F
            op1_asm     = f'R{op1}'

            if (insn >> 24) & 1 or (insn & 0xE1000000) == 0:
                op2 = ((insn << 50) & 0xFFFFFFFFFFFFFFFF) >> 50
                op2_asm = f'0x{op2:X}'
            else:
                op2 = (insn >> 9) & 0x1F
                op2_asm = f'R{op2}'

            opcode &= 0x7
            asm = ''
            if   opcode == 0: asm += 'S.EQ'
            elif opcode == 1: asm += 'S.NE'
            elif opcode == 2: asm += 'S.LE'
            elif opcode == 3: asm += 'S.LT'
            elif opcode == 4: asm += 'S.BE'
            elif opcode == 5: asm += 'S.BT'
            elif opcode == 6: asm += 'NUL'

            asm = f'{asm:5} {dst_reg_asm}, {op1_asm}, {op2_asm}'
        else:                
            type2 = (insn >> 26) & 3
            reg   = (insn >> 20) & 0x1F
            if type2 == 2:
                asm = f'CALL R{reg}'

            elif type2 == 0:
                asm = 'RET'            
            else:
                if insn & 0x2000000 != 0:
                    # unconditional jump
                    shr, shl = 0x25, 0x27

                    # Compute offset (+do a hack for negative offsets).
                    off = ((insn << shl) & 0xFFFFFFFFFFFFFFFF) >> shr
                    if off > 0xfffff:                        
                        off = ((off & 0xfffff) ^ 0xfffff) +1

                    asm = f'JMP   0x{off:X} (R{reg})'
                else:
                    # conditional jump
                    # if ( !ctx->vm_regs[insn >> 20) & 0x1F] )              
                    shr, shl = 0x2A, 0x2C
                    off = ((insn << shl) & 0xFFFFFFFFFFFFFFFF) >> shr
                    if off > 0xfffff:
                        # is negative
                        off = ((off & 0xfffff) ^ 0xfffff) +1
                        off = -off

                    asm = f'JCC   0x{off:X} (R{reg})'  
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
                asm = f'LDR'
            else:
                access_size = (insn >> 26) & 3

                if   access_size == 0: asm = f'STR.B'
                elif access_size == 1: asm = f'STR.W'
                elif access_size == 2: asm = f'STR.D'
                elif access_size == 3: asm = f'STR'                        
                
            reg1_asm = reg1_asm.replace('R30', 'SP')
            reg1_asm = reg1_asm.replace('R31', 'PC')
            reg2_asm = reg2_asm.replace('R30', 'SP')
            reg2_asm = reg2_asm.replace('R31', 'PC')

            asm = f'{asm:5} {reg1_asm}, [{reg2_asm} + 0x{base:X}]'
        else:
            reg1 = (insn >> 16) & 0x1F
            reg1_asm = f'R{reg1}'

            # The value of 'const' can be encrypted so it is unknown at this point
            # of the emulation.
            # Mark instrution as 'deferred' and record the destination register.
            asm = f'MOV   {reg1_asm}, -' 
            deferred = reg1

    if dbg: print(f'[+] {asm:30}')

    return asm, deferred


# ----------------------------------------------------------------------------------------
def disassemble(code, start_addr):
    """Disassembles an instruction from the `code`."""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for insn in md.disasm(code, start_addr):
        return f'{insn.mnemonic:6s} {insn.op_str}'


# ----------------------------------------------------------------------------------------
def read_regs(uc):
    """Reads register values from unicorn emulator."""
    return {
        'rax': uc.reg_read(unicorn.x86_const.UC_X86_REG_RAX),
        'rcx': uc.reg_read(unicorn.x86_const.UC_X86_REG_RCX),
        'rdx': uc.reg_read(unicorn.x86_const.UC_X86_REG_RDX),
        'rbx': uc.reg_read(unicorn.x86_const.UC_X86_REG_RBX),
        'rsp': uc.reg_read(unicorn.x86_const.UC_X86_REG_RSP),
        'rbp': uc.reg_read(unicorn.x86_const.UC_X86_REG_RBP),
        'rsi': uc.reg_read(unicorn.x86_const.UC_X86_REG_RSI),
        'rdi': uc.reg_read(unicorn.x86_const.UC_X86_REG_RDI),
        'r8' : uc.reg_read(unicorn.x86_const.UC_X86_REG_R8),
        'r9' : uc.reg_read(unicorn.x86_const.UC_X86_REG_R9),
        'r10': uc.reg_read(unicorn.x86_const.UC_X86_REG_R10),
        'r11': uc.reg_read(unicorn.x86_const.UC_X86_REG_R11),
        'r12': uc.reg_read(unicorn.x86_const.UC_X86_REG_R12),
        'r13': uc.reg_read(unicorn.x86_const.UC_X86_REG_R13),
        'r14': uc.reg_read(unicorn.x86_const.UC_X86_REG_R14),
        'r15': uc.reg_read(unicorn.x86_const.UC_X86_REG_R15),
        'rip': uc.reg_read(unicorn.x86_const.UC_X86_REG_RIP),
    }


# ----------------------------------------------------------------------------------------
def read_vm_reg(reg, ctx):
    """Reads the value of a VM register."""
    v = ctx['mu'].mem_read(ctx['vm_regs'] + reg*8, 8)
    return struct.unpack('<Q', v)[0]


# ----------------------------------------------------------------------------------------
def vm_sym_exec(trace, ctx):
    """Performs a minimal **symbolic execution** on the VM.

    Program keeps a copy of the VM registers stored in ctx['regs'].
    Every time a register is loaded with a byte from the key, we assign a symbolic
    variable to the corresponding register in the copy.
    After executing every VM instruction, we update the register copy.

    When we reach the final comparison instruction, we will end up with a symbolic
    expression -with one symbolic variable- in one register and a constant in the
    other register. We use an SMT solver to solve the equation and recover the
    correct value for the key.
    """
    last_insn = trace[-1]

    # Based on the VM instruction, do the following:

    # Read a byte from flag.
    # NOTE: You can actually read >1 bytes.
    # Example: `LDR   R1, [R0 + 0xD]`
    if match := re.match(r'LDR   R(.*), \[R0 \+ 0x(.*)\]', last_insn):
        reg = int(match.group(1))
        idx = int(match.group(2), 16)

        # Create a new SMT solver and a symbolic variable.
        smt = z3.Solver()
        key = z3.BitVec(f'key_{idx}', 64)

        ctx['smt']       = smt
        ctx['idx']       = idx
        ctx['z3-key']    = key        
        ctx['regs'][reg] = key  # Initialize register copy with symbolic variable.

    # Load a register with a memory value.
    elif match := re.match(r'LDR   R(.*), \[SP \+ 0x(.*)\]', last_insn):
        if ctx['idx'] != None:
            reg = int(match.group(1))
            ctx['regs'][reg] = read_vm_reg(reg, ctx)

    # Deferred value from `MOV reg, const`.
    elif match := re.match(r'DEFERRED 0x([0-9A-F]+), R([0-9]+)', last_insn):
        val = int(match.group(1), 16)
        reg = int(match.group(2))
        if ctx['idx'] != None:
            ctx['regs'][reg] = val

    # Arithmetic instruction with register.
    # Example: `ADD   R0, R1, R0`
    elif match := re.match(r'([A-Z]+)\s*R(.*), R(.*), R(.*)', last_insn):
        op   = match.group(1)
        reg1 = int(match.group(2))
        reg2 = int(match.group(3))
        reg3 = int(match.group(4))

        # If any register contains a symbolic expression, the result will also
        # be a symbolic expression.
        if ctx['idx'] != None:
            if   op == 'OR'  : ctx['regs'][reg1] = ctx['regs'][reg2] |  ctx['regs'][reg3]
            elif op == 'XOR' : ctx['regs'][reg1] = ctx['regs'][reg2] ^  ctx['regs'][reg3]
            elif op == 'AND' : ctx['regs'][reg1] = ctx['regs'][reg2] &  ctx['regs'][reg3]
            elif op == 'ADD' : ctx['regs'][reg1] = ctx['regs'][reg2] +  ctx['regs'][reg3]
            elif op == 'SUB' : ctx['regs'][reg1] = ctx['regs'][reg2] -  ctx['regs'][reg3]
            elif op == 'MUL' : ctx['regs'][reg1] = ctx['regs'][reg2] *  ctx['regs'][reg3]
            elif op == 'DIV' : ctx['regs'][reg1] = ctx['regs'][reg2] // ctx['regs'][reg3]
            elif op == 'IDIV': ctx['regs'][reg1] = ctx['regs'][reg2] // ctx['regs'][reg3]
            elif op == 'MOD' : ctx['regs'][reg1] = ctx['regs'][reg2] %  ctx['regs'][reg3]
            elif op == 'IMOD': ctx['regs'][reg1] = ctx['regs'][reg2] %  ctx['regs'][reg3]
            elif op == 'SHL' : ctx['regs'][reg1] = ctx['regs'][reg2] << ctx['regs'][reg3]
            elif op == 'ASR' : ctx['regs'][reg1] = ctx['regs'][reg2] >> ctx['regs'][reg3]
            elif op == 'SHR' : ctx['regs'][reg1] = ctx['regs'][reg2] >> ctx['regs'][reg3]
            elif op == 'ROL' : ctx['regs'][reg1] = rol64(ctx['regs'][reg2], ctx['regs'][reg3])
            elif op == 'ROR' : ctx['regs'][reg1] = ror64(ctx['regs'][reg2], ctx['regs'][reg3])
            else:
                raise Exception('Invalid operation')

    # Arithmetic instruction with constant (same case as above).
    # Example: `AND   R0, R0, 0x1`
    elif match := re.match(r'([A-Z]+)\s*R(.*), R(.*), 0x(.*)', last_insn):
        op   = match.group(1)
        reg1 = int(match.group(2))
        reg2 = int(match.group(3))
        val  = int(match.group(4), 16)
        if ctx['idx'] != None:
            if   op == 'OR'  : ctx['regs'][reg1] = ctx['regs'][reg2] |  val
            elif op == 'XOR' : ctx['regs'][reg1] = ctx['regs'][reg2] ^  val
            elif op == 'AND' : ctx['regs'][reg1] = ctx['regs'][reg2] &  val
            elif op == 'ADD' : ctx['regs'][reg1] = ctx['regs'][reg2] +  val
            elif op == 'SUB' : ctx['regs'][reg1] = ctx['regs'][reg2] -  val
            elif op == 'MUL' : ctx['regs'][reg1] = ctx['regs'][reg2] *  val
            elif op == 'DIV' : ctx['regs'][reg1] = ctx['regs'][reg2] // val
            elif op == 'IDIV': ctx['regs'][reg1] = ctx['regs'][reg2] // val
            elif op == 'MOD' : ctx['regs'][reg1] = ctx['regs'][reg2] %  val
            elif op == 'IMOD': ctx['regs'][reg1] = ctx['regs'][reg2] %  val
            elif op == 'SHL' : ctx['regs'][reg1] = ctx['regs'][reg2] << val
            elif op == 'ASR' : ctx['regs'][reg1] = ctx['regs'][reg2] >> val
            elif op == 'SHR' : ctx['regs'][reg1] = ctx['regs'][reg2] >> val
            elif op == 'ROL' : ctx['regs'][reg1] = rol64(ctx['regs'][reg2], val)
            elif op == 'ROR' : ctx['regs'][reg1] = ror64(ctx['regs'][reg2], val)
            else:
                raise Exception('Invalid operation')

    # Final comparison with register.
    # Example: `S.NE  R4, R5, R4`
    elif match := re.match(r'S.(NE|EQ)  R(.*), R(.*), R(.*)', last_insn):        
        op = match.group(1)
        reg1 = int(match.group(2))
        reg2 = int(match.group(3))
        reg3 = int(match.group(4))

        if ctx['self-mod'] == False and ctx['idx'] != None:
            # Solve the equation and recover the correct key value.
            ctx['smt'].add(ctx['regs'][reg2] == ctx['regs'][reg3])
            if ctx['smt'].check() == z3.sat:
                mdl = ctx['smt'].model()
                val = mdl.evaluate(ctx['z3-key']).as_long()
                if ctx['dbg']: print(f'[+] Key found: 0x{c:X}')

                # Value can be 1, 2 or 4 bytes.
                if val <= 0xFF:
                    ctx['mu'].mem_write(ctx['usr'] + ctx['idx'], struct.pack('B', val))
                elif val <= 0xFFFF:
                    ctx['mu'].mem_write(ctx['usr'] + ctx['idx'], struct.pack('<H', val))
                elif val <= 0xFFFFFFFF:
                    ctx['mu'].mem_write(ctx['usr'] + ctx['idx'], struct.pack('<L', val))
            else:
                raise Exception('Unsat!')
        
            # Patch the comparison result (because we had the wrong key)
            # to allow the emulation to continue.
            if op == 'NE':
                ctx['mu'].mem_write(ctx['vm_regs'] + reg1*8, struct.pack('<Q', 0))
            elif op == 'EQ':
                ctx['mu'].mem_write(ctx['vm_regs'] + reg1*8, struct.pack('<Q', 1))

            # Reset the VM register copy.
            for r in range(32):
                ctx['regs'][r] = read_vm_reg(r, ctx)

            ctx['idx'] = None

    # Final comparison with constant (same case as above).
    # Example: `S.NE  R4, R5, R4`
    elif match := re.match(r'S.(NE|EQ)  R(.*), R(.*), 0x(.*)', last_insn):        
        op = match.group(1)
        reg1 = int(match.group(2))
        reg2 = int(match.group(3))
        val  = int(match.group(4), 16)

        if ctx['self-mod'] == False and ctx['idx'] != None:
            # Solve the equation and recover the correct key value.        
            ctx['smt'].add(ctx['regs'][reg2] == val)

            if ctx['smt'].check() == z3.sat:
                mdl = ctx['smt'].model()
                val = mdl.evaluate(ctx['z3-key']).as_long()
                if ctx['dbg']: print(f'[+] Key found: 0x{c:X}')

                # Value can be 1, 2 or 4 bytes.
                if val <= 0xFF:
                    ctx['mu'].mem_write(ctx['usr'] + ctx['idx'], struct.pack('B', val))
                elif val <= 0xFFFF:
                    ctx['mu'].mem_write(ctx['usr'] + ctx['idx'], struct.pack('<H', val))
                elif val <= 0xFFFFFFFF:
                    ctx['mu'].mem_write(ctx['usr'] + ctx['idx'], struct.pack('<L', val))
            else:
                raise Exception('Unsat!')
        
            # Patch the comparison result (because we had the wrong key)
            # to allow the emulation to continue.
            if op == 'NE':
                ctx['mu'].mem_write(ctx['vm_regs'] + reg1*8, struct.pack('<Q', 0))
            elif op == 'EQ':
                ctx['mu'].mem_write(ctx['vm_regs'] + reg1*8, struct.pack('<Q', 1))

            # Reset the VM register copy.
            for r in range(32):
                ctx['regs'][r] = read_vm_reg(r, ctx)

            ctx['idx'] = None


# ----------------------------------------------------------------------------------------
def hook_code(uc, address, size, user_data):
    """Callback before executing every instruction."""
    ctx = user_data

    # Read instruction bytes from emulated memory and disassemble them.
    insn_bytes = ctx['mu'].mem_read(address, size)
    asm  = disassemble(insn_bytes, address)
    regs = read_regs(uc)
#    print(f'  {address:X}h: {asm} | rax:{regs["rax"]:X} | rdx:{regs["rdx"]:X}')

    # Check if we hit a libc call.
    if address == 0x1030:    # memset()
        pass  # No action. Memory is already NULL.
    elif address == 0x1050:  # __Znam()   
        # Allocate something "big" enough.
        ctx['mu'].reg_write(unicorn.x86_const.UC_X86_REG_RAX, ctx['heap'])
        ctx['heap'] += 0x1000
    elif address == 0x1060:  # __Znwm()
        ctx['mu'].reg_write(unicorn.x86_const.UC_X86_REG_RAX, ctx['heap'])
        ctx['heap'] += 0x1000
    elif address == ctx['malloc']:
        # Allocate something "big" enough in the heap.        
        ctx['mu'].reg_write(unicorn.x86_const.UC_X86_REG_RAX, ctx['heap'])
        ctx['heap'] += 0x1000

    # Check if we hit the entry point of u_emu_insn().
    if address == ctx['emu_insn']:
        # If the last instruction was a `MOV reg, const`, the constant was
        # unknown then, so we can read the VM register `reg` now and get
        # its value.
        if ctx['deferred'] != None:
            ctx['vm_regs'] = regs['rdi']

            const = read_vm_reg(ctx['deferred'], ctx)
            if ctx['dbg']:
                print(f"[+]   Deferred value: 0x{const:X} (R{ctx['deferred']})")

            ctx['trace'].append(f'DEFERRED 0x{const:X}, R{ctx["deferred"]}')
            ctx['deferred'] = None

        # Now the most critical part:
        #
        # Do a symbolic execution of the previous instruction.
        vm_sym_exec(ctx['trace'], ctx)
    
        # Go through all VM symbolic registers that do not have symbolic values
        # and update them.
        for r in range(32):
            if isinstance(ctx['regs'][r], int):
                ctx['regs'][r] = read_vm_reg(r, ctx)

        ctx['insn_cnt'] += 1
        if ctx['insn_cnt'] > 2000:
            # If there's no solution after 2000 VM instructions, halt.
            # The "Shuffling VMs" have too large loops and hence they are
            # too slow to be emulated by this approach.
            print('[!] Error. Exceeded instruction count limit!')
            # set RIP to the special value to halt emulation.
            ctx['mu'].reg_write(unicorn.x86_const.UC_X86_REG_RIP, 0xdeadbeefdeadbeef)

    # For self-modifying VMs: Check if we hit the '==' VM instruction.
    if match := re.match(r'cmp\s+(r.*), (r.*)', asm):
        r1, r2 = match.groups()  # Registers are always r1 = rcx and r2 = rdx

        # The first register contains 0xAA which the dummy key we set.
        # The second register contains the target value.
        if regs[r1] == 0xaa and regs[r2] < 0x100:
            if ctx['dbg']:
                print(f'[+] VM cmp found: {regs[r1]:X} == {regs[r2]:X} ? (idx:{ctx["key"][-1]})')

            # Replace key[idx] with the correct value.
            ctx['mu'].mem_write(ctx['usr'] + ctx["key"][-1],
                                struct.pack('B', regs['rcx']))


    # Some VM programs are encrypted. We let the emulator decrypt the instruction
    # and wee disassemble it right before the first comparison:
    #       .text:0000555555555407        cmp     eax, 20000000h
    if match := re.match(r'cmp\s+e(..), 0x20000000', asm):
        asm, ctx['deferred'] = disassemble_vm_insn(regs['r' + match.group(1)], ctx['dbg'])
        ctx['trace'].append(asm)


# ----------------------------------------------------------------------------------------
def hook_mem_read(uc, access, address, size, value, user_data):
    """Callback before every memory read."""
    ctx = user_data

    # If we read a byte from the key, log it.
    if ctx['usr'] <= address and address <= ctx['usr'] + 0x12:
        idx = address - ctx['usr']
        ctx['key'].append(idx)
        if ctx['dbg']: print(f'[+] Accessing key[{idx}] ...')


# ----------------------------------------------------------------------------------------
def hook_mem_write(uc, access, address, size, value, user_data):
    """Callback before every memory write."""
    ctx = user_data

    # If there is a write in the VM bytecode, then it is self modifying.
    vm_bytecode_start = ctx['vm_bytecode']['addr']
    vm_bytecode_end   = ctx['vm_bytecode']['addr'] + ctx['vm_bytecode']['size']
    if vm_bytecode_start <= address and address <= vm_bytecode_end:
        if ctx['dbg']: print('[+] Self modfying VM payload!')
        ctx['self-mod'] = True


# ----------------------------------------------------------------------------------------
def emulate_chk_bin(chkbin_path, key, start_off=0, dbg=False):
    """Emulates a `chk*.bin` binary, starting from emu_vm()."""
    funcs = locate_funcs(chkbin_path)

    FUNC_ENTRY = funcs['emu_vm']  # 0x1180
    FUNC_RETN  = 0xdeadbeefdeadbeef
    STACK      = 0xBFFE0000
    HEAP       = 0x800000
    USERDATA   = 0x400000

    binary = lief.parse(chkbin_path)

    # Select the basic sections to copy to the emulator.
    _data   = binary.get_section('.data')
    _text   = binary.get_section('.text')
    _rodata = binary.get_section('.rodata')
    _got    = binary.get_section('.got')
  
    # Initialize the emulator.
    mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)

    # Initialize the memory.
    #
    # NOTE: If sections are too small, an exception will be thrown because
    #       we will try to map overlapping regions.
    _4KB = lambda n: n & 0xFFFFFFFFF000   # Align address on 4KB.

    mu.mem_map(_4KB(_data.virtual_address),   _4KB(_data.size)   + 4096)
    mu.mem_map(_4KB(_text.virtual_address),   _4KB(_text.size)   + 4096)
    mu.mem_map(_4KB(_rodata.virtual_address), _4KB(_rodata.size) + 4096)
    mu.mem_map(_4KB(_got.virtual_address),    _4KB(_got.size)    + 4096)

    mu.mem_map(STACK,    1 * 1024*1024)   # 1MB for stack.
    mu.mem_map(HEAP,     1 * 1024*1024)   # 1MB for malloc() allocations.
    mu.mem_map(USERDATA, 0x10000)         # 16KB for user input.
    
    # Additional patches to avoid crashing.
    #
    # In unicorn, `fs` register is initialized to 0 and can't be modified.
    # In emu_vm() we have the following instructions that cause problems
    # because `fs` is 0:
    #   1208h: mov    rax, qword ptr fs:[0]
    #   .....
    #   1218h: cmp    qword ptr fs:[0xfffffffffffffff8], 0
    #
    # To fix that we make sure that addresses 0 and 0xfffffffffffffff8 are RW.
    mu.mem_map(0, 0x1000)
    mu.mem_map(0xfffffffffffff000, 0x1000)
    mu.mem_map(0xffffffffff000, 0x1000)
    # We need to map this for allocated memory:
    #       1351h: mov    qword ptr [rax - 8], 0x13371337 (rax:641C)
    mu.mem_map(0x6000, 0x10000)  

    # Write data to allocated regions.
    mu.mem_write(_data.virtual_address,   _data.content.tobytes())
    mu.mem_write(_text.virtual_address,   _text.content.tobytes())
    mu.mem_write(_rodata.virtual_address, _rodata.content.tobytes())
    mu.mem_write(_got.virtual_address,    _got.content.tobytes())

    # Patch libc functions with a retn (0xC3) so they immediately return.
    # Handle these calls in `hook_code`.
    mu.mem_write(0x1030, b'\xc3')  # __Znam()
    mu.mem_write(0x1050, b'\xc3')  # memset()
    mu.mem_write(0x1060, b'\xc3')  # __Znwm()
    # .got.malloc() is called from iniside the VM, Make sure it returns immediately.
    mu.mem_write(0x3fc8, struct.pack('<Q', USERDATA + 0x500)) # .got.malloc
    mu.mem_write(USERDATA + 0x500, b'\xc3')

    mu.mem_write(USERDATA, key) # Write the key to memory

    # Initialize registers.
    mu.reg_write(unicorn.x86_const.UC_X86_REG_RIP, FUNC_ENTRY)
    mu.reg_write(unicorn.x86_const.UC_X86_REG_RSP, STACK + 0x10000)

    # We start from emu_vm(). The arguments are either:
    #   u_emu_vm(0LL, 2uLL, buf, keylen_ >> 1)
    #   u_emu_vm(180LL, 2uLL, buf, keylen_ >> 1)
    mu.reg_write(unicorn.x86_const.UC_X86_REG_RDI, funcs['vm_entry'])
    mu.reg_write(unicorn.x86_const.UC_X86_REG_RSI, 2)
    mu.reg_write(unicorn.x86_const.UC_X86_REG_RDX, USERDATA)
    mu.reg_write(unicorn.x86_const.UC_X86_REG_RCX, 0x12)

    # Write a dummy return address on stack so we know when to stop
    # emulation.
    # NOTE: emu_vm() is recursive in some VMs, so we cannot stop at
    #       its last `ret` instruction.
    mu.mem_write(STACK + 0x10000, struct.pack('<Q', FUNC_RETN))

    # Context with all data to pass between hooks.
    ctx = {
        'mu'         : mu,
        'usr'        : USERDATA,
        'vm_bytecode': {'addr': _data.virtual_address, 'size':_data.size},
        'self-mod'   : False,
        'dbg'        : dbg,
        'key'        : [],
        'heap'       : HEAP,
        'main'       : funcs['main'],
        'emu_vm'     : funcs['emu_vm'],
        'emu_insn'   : funcs['emu_insn'],
        'malloc'     : USERDATA + 0x500,
        'insn_cnt'   : 0,
        'deferred'   : False,
        'trace'      : [],
        'vm_regs'    : 0,
        'idx'        : None,
        'regs'       : [0]*32,
    }

    # Add hooks.
    mu.hook_add(unicorn.UC_HOOK_CODE,      hook_code,      user_data=ctx)
    mu.hook_add(unicorn.UC_HOOK_MEM_READ,  hook_mem_read,  user_data=ctx)
    mu.hook_add(unicorn.UC_HOOK_MEM_WRITE, hook_mem_write, user_data=ctx)

    # Start emulation.
    mu.emu_start(FUNC_ENTRY, FUNC_RETN)

    # After the emulation, we should have the correct key stored in memory.
    key = mu.mem_read(USERDATA, 18)
    print('[+] Recovered Key:', key.hex())
    return key.hex()


# ----------------------------------------------------------------------------------------
def locate_funcs(chkbin_path):
    """Finds the addresses of main(), emu_vm() and emu_insn() using patterns."""
    binary = lief.parse(chkbin_path)
    _text  = binary.get_section('.text')
    code   = _text.content.tobytes()
    
    # Pattern for main():
    #   .text:0000000000001960 55       push    rbp
    #   .text:0000000000001961 41 57    push    r15
    #   .text:0000000000001963 41 56    push    r14
    p1 = b'\x55\x41\x57\x41\x56'
    main = code.find(p1)
    assert main != -1
    assert code[main + len(p1):].find(p1) == -1  # Ensure there is exactly 1 match.

    # Pattern from emu_vm():
    #   .text:0000000000001180 41 57    push    r15
    #   .text:0000000000001182 41 56    push    r14
    #   .text:0000000000001184 41 54    push    r12
    #   .text:0000000000001186 53       push    rbx
    p2 = b'\x41\x57\x41\x56\x41\x54'
    emu_vm = code.find(p2)
    assert emu_vm != -1
    assert code[emu_vm + len(p2):].find(p2) == -1
    
    # Pattern from emu_insn():
    #
    # Prolog changes, so we need another invariant:
    # We search for the while loop that compares return value with 0x13371337:
    #   .text:0000000000001383 E8 28 00 00 00   call    u_emu_insn
    #   .text:0000000000001388 49 81 BF F8 00   cmp     qword ptr [r15+0F8h], 13371337h
    #   .text:0000000000001388 00 00 00 37 13
    #   .text:0000000000001388 37 13
    #
    # We match the compare instruction. Then, we move 4 bytes up and we get the
    # offset from the call instruction.
    #
    # NOTE: We can also search for the next `ret` instruction as emu_insn()
    #       is right below emu_vm().
    p3 = b'\x49\x81\xBF\xF8\x00\x00\x00\x37\x13\x37\x13'
    emu_insn = code.find(p3)
    assert emu_insn != -1
    assert code[emu_insn + len(p3):].find(p3) == -1
    assert code[emu_insn - 5] == 0xe8  # Must be a `call`.

    off = struct.unpack('<L', code[emu_insn - 4:emu_insn])[0]
    assert off == 0x28
    assert code[emu_insn + len(p3):].find(p3) == -1
    emu_insn += off

    # Pattern to find the VM bytecode entry point:
    #
    # Usually this is 0 so there is a `xor edi, edi` instruction.
    # In self-modyfing VMs it's not 0 and main() has an instruction like this:
    #   .text:0000000000001B55 BF CC 00 00 00    mov     edi, 0CCh
    vm_entry = 0
    for i in range(main, len(code) - 5):
        if (code[i]     == 0xbf and
            code[i + 2] == 0x00 and
            code[i + 3] == 0x00 and
            code[i + 4] == 0x00):

            vm_entry = code[i+1]
            break

    return {
        'main'    : main     + _text.virtual_address,
        'emu_vm'  : emu_vm   + _text.virtual_address,
        'emu_insn': emu_insn + _text.virtual_address,
        'vm_entry': vm_entry
    }


# ----------------------------------------------------------------------------------------
def verify_key(chk_bin_path, key):
  """Verifies that a `key` returns a 0 exit code on a chk binary."""
  result = subprocess.run(f'{chk_bin_path} {key}',
                          shell=True, capture_output=True, text=True)
  return result.returncode == 0


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] mbins VM emulator (unicorn) crack started.')

    # Test: Make sure you can locate correctly all functions from all binaries.
    #for i in range(1000):
    #    locate_funcs(f'binaries/chk{i}.bin')
    #exit()

    # # chk0 ~> 034e442f138a2b33e89d2a6022a93ad95a39
    #key = b'\xaa'*18
    #key = emulate_chk_bin(f'binaries/chk0.bin', key, dbg=True)
    #exit()

    solutions = []
    failed = []
    for i in range(0, 1000):
        print(f'============================== {i} ==============================')
    
        try:
            key = b'\xaa'*18  # Start with a dummy key
            key = emulate_chk_bin(f'binaries/chk{i}.bin', key)

            # Verify that the key is correct.
            if verify_key(f'binaries/chk{i}.bin', key):
                print(f'[+] SOLUTION #{i} VERIFIED! :D')
                solutions.append(key)
            else:
                print(f'[!] Solution #{i} invalid :( ~> {key}')
                failed.append(i)
        except Exception as e:
            print(f'[+] Emulation failed: {e!r}')
            failed.append(i)

        print(f'[+] Correct:{len(solutions)}/{i+1}. Failed:{len(failed)}/{i+1}')

   #     break

    print('[+] Emulation completed.')
    print(f'[+] #{len(solutions)} Solutions:', solutions)
    print(f'[+] #{len(failed)} failed binaries:', failed) 
    print('[+] Program finished successfully. Bye bye :)')

# ----------------------------------------------------------------------------------------
r"""
┌─[:(]─[00:51:01]─[✗:8]─[ispo@ispo-glaptop2]─[~/ctf/hxp_2024/mbins/mbins]
└──> time ./mbins_vm_emulate_crack.py 
[+] mbins VM emulator (unicorn) crack started.
============================== 0 ==============================
[+] Recovered Key: 034e442f138a2b33e89d2a6022a93ad95a39
[+] SOLUTION #0 VERIFIED! :D
[+] Correct:1/1. Failed:0/1
============================== 1 ==============================
[+] Recovered Key: 019749700b31bcb948e14999d5dbca427bab
[+] SOLUTION #1 VERIFIED! :D
[+] Correct:2/2. Failed:0/2
============================== 2 ==============================
[+] Recovered Key: 00182210c2bbb177d3cddcfb4b0ee64fecc1
[+] SOLUTION #2 VERIFIED! :D
[+] Correct:3/3. Failed:0/3
============================== 3 ==============================
[+] Recovered Key: 02e95496f2111121da0641af47b14d790e33
[+] SOLUTION #3 VERIFIED! :D
[+] Correct:4/4. Failed:0/4
============================== 4 ==============================
[+] Recovered Key: 03ba1b8cb86ee41edda24701d029696af1cb
[+] SOLUTION #4 VERIFIED! :D
[+] Correct:5/5. Failed:0/5
============================== 5 ==============================
[+] Recovered Key: 000f66af38c4b59e350009759afeaf48efaf
[+] SOLUTION #5 VERIFIED! :D
[+] Correct:6/6. Failed:0/6
============================== 6 ==============================
[+] Recovered Key: 01a02782de14310a1b8898478c1a11609f03
[+] SOLUTION #6 VERIFIED! :D
[+] Correct:7/7. Failed:0/7

[..... TRUNCATED FOR BREVITY .....]

============================== 984 ==============================
[+] Recovered Key: 005d0be67a84b309fc76c3a4d4004293276f
[+] SOLUTION #984 VERIFIED! :D
[+] Correct:783/985. Failed:202/985
============================== 985 ==============================
[!] Error. Exceeded instruction count limit!
[+] Recovered Key: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[!] Solution #985 invalid :( ~> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
[+] Correct:783/986. Failed:203/986
============================== 986 ==============================
[+] Recovered Key: 02483d68a5667a7cf6b8c2e393500edd2c87
[+] SOLUTION #986 VERIFIED! :D
[+] Correct:784/987. Failed:203/987
============================== 987 ==============================
[+] Recovered Key: 00af0091a94aee70185af013e980a4b53fa2
[+] SOLUTION #987 VERIFIED! :D
[+] Correct:785/988. Failed:203/988
============================== 988 ==============================
[+] Recovered Key: 02df711b2d76307b18245f4d5abbda7eeef2
[+] SOLUTION #988 VERIFIED! :D
[+] Correct:786/989. Failed:203/989
============================== 989 ==============================
[+] Recovered Key: 033f8ef83b752598a89ec72f9a0603736b6d
[+] SOLUTION #989 VERIFIED! :D
[+] Correct:787/990. Failed:203/990
============================== 990 ==============================
[+] Recovered Key: 025b76839fcc65cb265bb75e967006207b3e
[+] SOLUTION #990 VERIFIED! :D
[+] Correct:788/991. Failed:203/991
============================== 991 ==============================
[+] Recovered Key: 0245401c6e53679e643b718b12b3a38f588e
[+] SOLUTION #991 VERIFIED! :D
[+] Correct:789/992. Failed:203/992
============================== 992 ==============================
[+] Recovered Key: 01d3049616813b9bad45d8748f9507523d01
[+] SOLUTION #992 VERIFIED! :D
[+] Correct:790/993. Failed:203/993
============================== 993 ==============================
[+] Recovered Key: 016c0635fab2a857fff2bbd375f35ce57f43
[+] SOLUTION #993 VERIFIED! :D
[+] Correct:791/994. Failed:203/994
============================== 994 ==============================
[+] Recovered Key: 02824161a615e6dcc78ceda028389ca3dacb
[+] SOLUTION #994 VERIFIED! :D
[+] Correct:792/995. Failed:203/995
============================== 995 ==============================
[+] Recovered Key: 024906b26cc7d8d5eb68927943013f31b8db
[+] SOLUTION #995 VERIFIED! :D
[+] Correct:793/996. Failed:203/996
============================== 996 ==============================
[+] Recovered Key: 01870320912a27c6932d6c4ac301faffa084
[+] SOLUTION #996 VERIFIED! :D
[+] Correct:794/997. Failed:203/997
============================== 997 ==============================
[+] Recovered Key: 01a52ee7e87e7610986ce7c1080c225654fb
[+] SOLUTION #997 VERIFIED! :D
[+] Correct:795/998. Failed:203/998
============================== 998 ==============================
[+] Recovered Key: 00d82680b08b28ba75601fae811f2509bee9
[+] SOLUTION #998 VERIFIED! :D
[+] Correct:796/999. Failed:203/999
============================== 999 ==============================
[+] Recovered Key: 00f38173d36cd109880b8fd778b8e3b4f0a0
[+] SOLUTION #999 VERIFIED! :D
[+] Correct:797/1000. Failed:203/1000
[+] Emulation completed.
[+] #797 Solutions: ['034e442f138a2b33e89d2a6022a93ad95a39', '019749700b31bcb948e14999d5dbca427bab', '00182210c2bbb177d3cddcfb4b0ee64fecc1', .....
[+] #203 failed binaries: [17, 20, 25, 32, 51, 52, 53, 59, .....
[+] Program finished successfully. Bye bye :)

real    60m12.260s
user    59m25.718s
sys 1m8.899s
"""
# ----------------------------------------------------------------------------------------
