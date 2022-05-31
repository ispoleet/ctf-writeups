#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# HXP CTF 2021 - revvm (RE - 833pt)
# ----------------------------------------------------------------------------------------
import struct
import re
import os


# ----------------------------------------------------------------------------------------
class DisasmVM(object):
    """Disassembles a VM program."""

    def __init__(self, path):
        """Loads VM program and input into memory."""
        rbin = open(path, 'rb').read()

        inp_len, = struct.unpack("<Q", rbin[0:8])
        self.input = rbin[8:inp_len]
        self.code  = rbin[inp_len+8:]

        print(f'[+] VM Code offset: {inp_len:X}h')
        print(f'[+] VM Input: {repr(self.input)}')
        print(f'[+] VM Code: {len(self.code)} bytes')


    def mk_bitvecs(self):
        """Converts VM code and input into bit vectors."""
        self.bitvec      = ''.join([f'{b:#010b}'[2:] for b in self.code ][::-1])
        self.bitvec_data = ''.join([f'{b:#010b}'[2:] for b in self.input][::-1])

        # Pad with some zeros to catch the last instructions.
        self.bitvec = '0'*64 + self.bitvec


    def _decode_insn(self, bitvec76, start, pos):
        """Decodes (or tries to) an instruction from a 64+12 bit vector."""
        insn_wnd = bitvec76[start:start + 0xC]  # Opcode is 12 bits long.        
        opcode   = int(insn_wnd, 2)        

        # print(f'[+] Instruction Window at {pos:2X}h: {insn_wnd} ~> Opcode: {opcode:03X}h')
        
        # Check if opcode is valid
        if opcode & 0x80 == 0:
            if (opcode & 0x3F) + 0xD != pos:
                raise IndexError("instruction and immediate size mismatch")
            
            if opcode & 0x40 != 0:
                insn_wnd2 = bitvec76[start + 0xC:]
                operand  = int(insn_wnd2, 2)
            else:
                insn_wnd2 = bitvec76[start + 0xC:]
                operand  = int(insn_wnd2[::-1], 2)

            width = (opcode & 0x3F) + 1
        else:
            if opcode & 0xFF00 == 0x400 or opcode & 0xFF00 == 0xF00:
                raise IndexError("inappropriate combination of mnemonic and operand type")
            if pos != 12:
                raise IndexError("inappropriate combination of operand type and immediate data")

            insn_wnd2, operand = None, None
            width = (opcode & 0x3F) + 1
        
        return opcode >> 8, operand, width

        
    def _get_mnemonic(self, opcode):
        """Gets the instruction mnemonic for an opcode."""
        try:
            return {
                # Math Operations: +, -. *. /.
                0x0: ('ADD',     'W'),
                0x1: ('SUB',     'W'),
                0x2: ('MUL',     'W'),
                0x3: ('IDIV',    'W'),
                # Stack operations
                0x4: ('PUSH',    'W'),
                0x5: ('POP',     '-'),
                0x6: ('DUP',     '-'),
                0x7: ('STCK_RD', 'W'),
                0x8: ('STCK_WR', 'W'),
                # Global data (VM program input) operatiaons
                0x9: ('LDR',     'W'),
                0xA: ('STR',     'W'),
                # Jumps and syscalls (SVCs)
                0xB: ('JZ',      'W'),
                0xC: ('JMP',     'W'),
                0xD: ('SVC',     'W'),
                # Miscellaneous
                0xE: ('SPNLCK',  '-'),
                0xF: ('UNKNWN',  '-')
            }[opcode]
        except KeyError:
            raise Exception(f'Illegal instruction with opcode: {opcode:X}h')


    def _disasm_insn(self, opcode, operand, width, inv_pos, pos):
        """Disassembles a VM instruction."""
        mnem, W = self._get_mnemonic(opcode)
        addr = inv_pos + pos
        jmp_trg = ('', -1)

        if opcode == 0xB:  # Special case for JZ where offset is relative. 
            if operand is None:
                operand_str = f'$_top_ + {addr:02X}h'
            else:
                operand += addr
                jmp_trg = ('jz', operand)

        elif opcode == 0xC:  # Special case for JMP.
            if operand is not None:
                jmp_trg = ('jmp', operand)


        # Do the operand operation.
        if operand is None:
            operand_str = '$_top_'  # Top value of the stack.
        elif type(operand) == int:
            operand_str = f'0x{operand:X}'

        return f'.text:{inv_pos:04X}+{pos:02X}={addr:04X}    {mnem:8} {operand_str:16}   ({W}:{width:2d})', jmp_trg


    def disasm_bitvec(self, start=0, limit=999999):
        """Disassembles the bit vector and extracts all VM instructions from all contexts."""        
        print(f'[+] Disassembling bit vector of {len(self.bitvec):X}h bits ...')
        print(f'[+] Starting from position: {start:X}h')

        vm_progs = []
      
        # Sliding window starts from 64+12 bits from the end.
        wnd_idx = len(self.bitvec) - 64 - 12 - start
   
        queue = [{'opcode': '', 'operand': '', 'pos': 0, 'wnd_idx': wnd_idx,
                  'trace': [], 'addrs': [], 'jmp': [], 'jz': []}]

        # All instructions have been parsed. Pop the next from the queue and move on.
        while queue:
            insn = queue.pop(0)

            wnd_idx = insn['wnd_idx'] - insn['pos']  # Move sliding window to the left.

            if wnd_idx < 0:
                print(f'[!] Warning: Sliding window is at offset: {wnd_idx}')
                # We can't proceed (reached the end). Save VM program.
                vm_progs.append({
                    'prog' : insn['trace'],
                    'addrs': insn['addrs'],
                    'jmp'  : insn['jmp'],
                    'jz'   : insn['jz'],
                })
                continue

            bitvec76 = self.bitvec[wnd_idx:wnd_idx + 64 + 12]            
            inv_pos  = len(self.bitvec) - 64 - 12 - wnd_idx

            print(f'[+] Extracting instructions from {bitvec76} at: {inv_pos:X}h')

            is_empty = True
            pos = 12
            for start in range(64, -1, -1):  # Scan bitvec76 with a 12-bit sliding window.
                try:
                    opcode, operand, width = self._decode_insn(bitvec76, start, pos)
                    asm, jmp_trg = self._disasm_insn(opcode, operand, width, inv_pos, pos)

                    # We do have 3 cases: regular insns, jmp, jz (2 targets).
                    next_insn = {  
                            'opcode'  : opcode,
                            'operand' : operand,
                            'pos'     : pos,
                            'wnd_idx' : wnd_idx,
                            'trace'   : insn['trace'] + [asm],
                            # We need these for program verification.
                            'addrs'   : insn['addrs'] + [inv_pos],
                            'jmp'     : insn['jmp']   + ([jmp_trg[1]] if jmp_trg[0] == 'jmp' else []),
                            'jz'      : insn['jz']    + ([jmp_trg[1]] if jmp_trg[0] == 'jz'  else []),
                    }

                    if jmp_trg[0] == '':  # Regular instruction. Follow next instruction.
                        queue.append(next_insn)

                    elif jmp_trg[0] == 'jmp':  # Unconditional jump. Follow the jump target.
                        print(f'[+] Unconditional jump found. Target: {jmp_trg[1]:X}h')

                        # IMPORTANT: To avoid cycles follow forward jumps only.
                        if jmp_trg[1] > 64 and jmp_trg[1] < len(self.bitvec):
                            if jmp_trg[1] not in insn['addrs']:
                                print('[+] Jump target is good.')

                                next_insn['pos']     = 0
                                next_insn['wnd_idx'] = len(self.bitvec) - 64 - 12 - jmp_trg[1]
                                queue.append(next_insn)
                            else:
                                queue.append(next_insn)

                    elif jmp_trg[0] == 'jz':  # Conditional jump. Follow next insn & store target for later processing.
                        if jmp_trg[1] > 64 and jmp_trg[1] < len(self.bitvec):
                            print(f'[+] Adding conditional jump target: {jmp_trg[1]:X}h')
                            queue.append(next_insn)

                    print(f'[+]    {asm}')

                    # We add every instruction we found in bitvec76 to a queue and we
                    # continue scanning from its `pos`. For example:
                    #   0  ~> D, 1C
                    #   D  ~> -
                    #   1C ~> 28, 29, 2D
                    #   28 ~> -
                    #   29 ~> 37, 6E
                    #   2D ~> 3A, 49

                    is_empty = False
                except IndexError as ex:
                    # Can't decode instruction at `pos`. Just move on.
                    pass

                pos += 1

            if is_empty:
                # If current context cannot proceed, save VM program.
                vm_progs.append({
                    'prog' : insn['trace'],
                    'addrs': insn['addrs'],
                    'jmp'  : insn['jmp'],
                    'jz'   : insn['jz'],
                })

            # That's for debugging only.
            limit -= 1
            if limit == 0: break

        # If there are leftovers in the `queue` add them to the `vm_progs`.
        print(f'[+] Leftovers in queue: {len(queue)}')
        vm_progs += [{ 'prog' : insn['trace'],
                       'addrs': insn['addrs'],
                       'jmp'  : insn['jmp'],
                       'jz'   : insn['jz'] } for insn in queue]
        
        print(f'[+] Total parallel VM programs: {len(vm_progs)}')

        return vm_progs

    
    def get_conditional_jump_targets(self, vm_progs):
        """Gets all jump targets from conditional jumps."""
        print('[+] Collecting all conditional jump targets ...')
        jz_all = set()

        for i, prog in enumerate(vm_progs):       
            jz_all.update(set(prog['jz']))

        print(f"[+] Done. {len(jz_all)} new target(s) found:",
               ", ".join('%Xh' % x for x in jz_all))

        return jz_all


    def verify_vm_prog(self, prog):
        """Checks if a VM program is programmatically "correct"."""
        # Check #1: All jump targets should point to the beginning of instructions.
        if not set(prog['jmp']).issubset(set(prog['addrs'])):
            return False

        # Check #2: ?

        return True   


    def verify_vm_progs(self, vm_progs):
        """Verifies if the disassembled program is syntactially correct."""
        try:
            max_prog = max(len(p['prog']) for p in vm_progs)
            print(f'[+] Max program size: {max_prog}')
        except ValueError:
            return []
        
        if not max_prog: return []

        # [prog for prog in vm_progs if self.verify_vm_prog(prog)]
        
        verified_vm_progs = []
        for prog in vm_progs:
            # Random heuristic: Discard programs have < 95% insns of the longest program.
            if self.verify_vm_prog(prog) and len(prog['prog']) / max_prog > .95:
                verified_vm_progs.append(prog)

        return verified_vm_progs
 

# ----------------------------------------------------------------------------------------
def save_prog(vm_prog, name, idx):
    """Saves the program instructions into memory."""
    disasm = ''
    
    for line in vm_prog:
        disasm += f'{line}\n'

    open(f'vm_progs/{name}_{idx}.asm', 'w').write(disasm)

    # The disassembled programs are identical except the last few instructions:
    #
    # ispo@ispo-glaptop:~/ctf/hxp_2021/revvm/vm_progs$ diff main_0.asm main_1.asm
    #   230,231c230,231
    #   < .text:0CB2+10=0CC2    STCK_WR  0x0                (W: 4)
    #   < .text:0CC2+1B=0CDD    SUB      0x5612             (W:15)
    #   ---
    #   > .text:0CB2+2E=0CE0    ADD      0x3006B093         (W:34)
    #   > .text:0CE0+0C=0CEC    SUB      $_top_             (W:57)
    #
    # ispo@ispo-glaptop:~/ctf/hxp_2021/revvm/vm_progs$ diff main_0.asm main_2.asm
    #   231c231,233
    #   < .text:0CC2+1B=0CDD    SUB      0x5612             (W:15)
    #   ---
    #   > .text:0CC2+10=0CD2    MUL      0x5                (W: 4)
    #   > .text:0CD2+11=0CE3    ADD      0x1C               (W: 5)
    #   > .text:0CE3+15=0CF8    ADD      0x1F8              (W: 9)
    #
    # So, instead of having multiple programs, we only keep one,
    # and we just append all diffs from the other programs.
    if idx > 0:
        os.system(f'diff vm_progs/{name}_0.asm vm_progs/{name}_{idx}.asm '
                  f'>> vm_progs/{name}.diff')
        os.system(f'rm vm_progs/{name}_{idx}.asm')


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Revvm disassembler started.')


    # NOTE: For hello.rbin set heuristic precision to 85%
#    vm = DisasmVM('hello.rbin')
    vm = DisasmVM('chall.rbin')
    vm.mk_bitvecs()

    # Disassemble bit vector from the beginning.
    vm_progs = vm.disasm_bitvec()
    vm_progs = vm.verify_vm_progs(vm_progs)


    print('='*512)

    # Add the missing jump targets manually (whatever...)
    missing = [0xf16, 0xf8c, 0xfee, 0x1c2, 0x1674, 0x18cb, 0x18ea, 0x1228, 0x1290, 0x1151]

    # Disassemble bit vector at conditional jump target locations as well.
    jz_vm_progs = {}    
    for jz in list(vm.get_conditional_jump_targets(vm_progs)) + missing:
        print(f"[+] {'='*100}")
        print(f"[+] Disassembling bit vector for jump target: {jz:X}h")
        progs = vm.disasm_bitvec(jz)
        jz_vm_progs[jz] = vm.verify_vm_progs(progs)

    # Save programs into memory.
    if not os.path.exists('vm_progs'):
        os.mkdir('vm_progs')

    print('[+] Dumping all VM programs:')
    final_vm_prog = set()

    for i, prog in enumerate(vm_progs):
        print(f'[+] ==================== VM PROG: #{i} (Size: {len(prog["prog"])}) ====================')
        for line in prog['prog']:
#            print(line)
            if f'{line}' not in final_vm_prog:
                final_vm_prog.add(f'{line}')

#        save_prog(prog['prog'], 'main', i)

#    os.system(f'cat vm_progs/main.diff >> vm_progs/main_0.asm')
#    os.system(f'rm  vm_progs/main.diff')
    
    print('[+] Dumping all JZ VM programs:')  
    for trg, vm_prog in jz_vm_progs.items():
        print(f'[+] ==================== JZ VM PROG TRG: {trg:X}h ====================')

        for j, prog in enumerate(vm_prog):
            print(f'[+]     ==================== VM PROG: #{j} (Size: {len(prog["prog"])}) ====================')
            for line in prog['prog']:
#                print(line)
                if f'{line}' not in final_vm_prog:
                    final_vm_prog.add(f'{line}')

#            save_prog(prog['prog'], f'{trg:04X}', j)

#        os.system(f'cat vm_progs/{trg:04X}.diff >> vm_progs/{trg:04X}_0.asm')
#        os.system(f'rm  vm_progs/{trg:04X}.diff')


    print('[+] Dumping final VM program:')
    for line in sorted(final_vm_prog):
        print(line)

    print('[+] Program finished. Bye bye :)')


# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop:~/ctf/hxp_2021/revvm$ ./revvm_disasm_vm_progs.py 
[+] Revvm disassembler started.
[+] VM Code offset: 4Bh
[+] VM Input: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0y-\x14\xa0\xda\xc1\xa2\x8c\x84\xcb\x9d\x8f\t\xe5\x8c\x93\xb2]bBQ'
[+] VM Code: 805 bytes
[+] Disassembling bit vector of 1928h bits ...
[+] Starting from position: 0h
[+] Extracting instructions from 1101000001010000000100001011010001011101001010100110100111100101110000000100 at: 0h
[+]    .text:0000+0E=000E    STCK_RD  0x0                (W: 2)
[+]    .text:0000+3A=003A    PUSH     0x80E9E5952E8      (W:46)
[+] Extracting instructions from 0110100000000111010000010100000001000010110100010111010010101001101001111001 at: Eh
[+]    .text:000E+24=0032    SVC      0x9E5952           (W:24)
[+] Extracting instructions from 0100000001110000011110100000010000000100000001101000000001110100000101000000 at: 3Ah
[+]    .text:003A+12=004C    SVC      0x0                (W: 6)
[+]    .text:003A+1B=0055    ADD      0x141              (W:15)
[+]    .text:003A+2D=0067    ADD      0x505C02C          (W:33)
[+] Extracting instructions from 0111000001111010000001000000010000000110100000000111010000010100000001000010 at: 32h
[+] Extracting instructions from 1000111001000000010100000001110000011110100000010000000100000001101000000001 at: 4Ch
[+]    .text:004C+0D=0059    SVC      0x1                (W: 1)
[+] Extracting instructions from 0111000001000111001000000010100000001110000011110100000010000000100000001101 at: 55h
[+] Extracting instructions from 0001001000100001110111000001000111001000000010100000001110000011110100000010 at: 67h
[+] Extracting instructions from 0111011100000100011100100000001010000000111000001111010000001000000010000000 at: 59h
[+]    .text:0059+0C=0065    ADD      $_top_             (W: 1)
[+]    .text:0059+0D=0066    ADD      0x0                (W: 1)
[+]    .text:0059+11=006A    PUSH     0x0                (W: 5)
[+] Extracting instructions from 0100100010000111011100000100011100100000001010000000111000001111010000001000 at: 65h
[+]    .text:0065+44=00A9    STCK_WR  0x4720280E0F408    (W:56)
.....
.text:1852+1A=186C    JMP      0x16B4             (W:14)
.text:186C+10=187C    POP      0xA                (-: 4)
.text:187C+0C=1888    STCK_RD  $_top_             (W:29)
.text:1888+0C=1894    STR      $_top_             (W:49)
.text:1894+0C=18A0    STR      $_top_             (W:33)
.text:18A0+0C=18AC    ADD      $_top_             (W:24)
.text:18A0+11=18B1    SUB      0x1D               (W: 5)
.text:18AC+0C=18B8    STCK_WR  $_top_             (W: 3)
.text:18B1+0C=18BD    POP      $_top_             (-: 7)
.text:18B8+14=18CC    DUP      0xD5               (-: 8)
.text:18BD+10=18CD    JZ       0x18D8             (W: 4)
.text:18CB+1F=18EA    PUSH     0x293AF            (W:19)
.text:18CC+3E=190A    ADD      0x293AF4820C0BA    (W:50)
.text:18CD+38=1905    DUP      0x49D7A410605      (-:44)
.text:18EA+10=18FA    SVC      0x0                (W: 4)
.text:18FA+13=190D    PUSH     0x54               (W: 7)
.text:1905+15=191A    PUSH     0x4                (W: 9)
.text:190A+0C=1916    ADD      $_top_             (W: 3)
.text:190A+11=191B    STR      0x8                (W: 5)
.text:190A+1A=1924    STCK_WR  0x1040             (W:14)
.text:190D+0F=191C    SVC      0x0                (W: 3)
.text:1916+10=1926    MUL      0x2                (W: 4)
.text:191C+0D=1929    MUL      0x0                (W: 1)
[+] Program finished. Bye bye :)
'''
# ----------------------------------------------------------------------------------------

