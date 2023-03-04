#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# 0CTF 2019 - J (RE 297)
# ----------------------------------------------------------------------------------------
vm_prog = [
    0x0009, 0x091D, 0x0009, 0x0000, 0x000A, 0x0005, 0x0006, 0x0014, 0x0009, 0x0001,
    0x000A, 0x0001, 0x000B, 0x0008, 0x0009, 0x0001, 0x0006, 0xFFE0, 0x0009, 0x0011,
    0x0002, 0x0009, 0xB248, 0x0003, 0x0009, 0x72A9, 0x0005, 0x0007, 0x0144, 0x0009,
    0x0011, 0x0002, 0x0009, 0xB248, 0x0003, 0x0009, 0x097E, 0x0005, 0x0007, 0x012E,
    0x0009, 0x0011, 0x0002, 0x0009, 0xB248, 0x0003, 0x0009, 0x5560, 0x0005, 0x0007,
    0x0118, 0x0009, 0x0011, 0x0002, 0x0009, 0xB248, 0x0003, 0x0009, 0x4CA1, 0x0005,
    0x0007, 0x0102, 0x0009, 0x0011, 0x0002, 0x0009, 0xB248, 0x0003, 0x0009, 0x0037,
    0x0005, 0x0007, 0x00EC, 0x0009, 0x0011, 0x0002, 0x0009, 0xB248, 0x0003, 0x0009,
    0xAA71, 0x0005, 0x0007, 0x00D6, 0x0009, 0x0011, 0x0002, 0x0009, 0xB248, 0x0003,
    0x0009, 0x122C, 0x0005, 0x0007, 0x00C0, 0x0009, 0x0011, 0x0002, 0x0009, 0xB248,
    0x0003, 0x0009, 0x4536, 0x0005, 0x0007, 0x00AA, 0x0009, 0x0011, 0x0002, 0x0009,
    0xB248, 0x0003, 0x0009, 0x11E8, 0x0005, 0x0007, 0x0094, 0x0009, 0x0011, 0x0002,
    0x0009, 0xB248, 0x0003, 0x0009, 0x1247, 0x0005, 0x0007, 0x007E, 0x0009, 0x0011,
    0x0002, 0x0009, 0xB248, 0x0003, 0x0009, 0x76C7, 0x0005, 0x0007, 0x0068, 0x0009,
    0x0011, 0x0002, 0x0009, 0xB248, 0x0003, 0x0009, 0x096D, 0x0005, 0x0007, 0x0052,
    0x0009, 0x0011, 0x0002, 0x0009, 0xB248, 0x0003, 0x0009, 0x122C, 0x0005, 0x0007,
    0x003C, 0x0009, 0x0011, 0x0002, 0x0009, 0xB248, 0x0003, 0x0009, 0x87CB, 0x0005,
    0x0007, 0x0026, 0x0009, 0x0011, 0x0002, 0x0009, 0xB248, 0x0003, 0x0009, 0x09E4,
    0x0005, 0x0007, 0x0010, 0x0009, 0x091D, 0x0007, 0x0008, 0x0009, 0x0000, 0x000B,
    0x000D, 0x0009, 0x0001, 0x000B, 0x000D, 0xE4DD, 0xAC7C, 0x6C6C, 0xC81B, 0xB4D8,    
]


# ----------------------------------------------------------------------------------------
def disasm_vm_prog():
    """Disassembles the VM program."""
    print('[+] Disassembling the VM program ...')

    start_addr = 0x80003D40
    pc = 0
    
    while True:
        addr = start_addr + pc*2
        opcode = vm_prog[pc]
        pc += 1

        if   opcode == 0: mnem = 'add'
        elif opcode == 1: mnem = 'sub'
        elif opcode == 2: mnem = 'mul'
        elif opcode == 3: mnem = 'mod'
        elif opcode == 4: mnem = 'cmp <'
        elif opcode == 5: mnem = 'cmp =='
        elif opcode == 6:
            off = vm_prog[pc]
            pc += 1  # First increment pc then add jump offset.

            # +2 to eat the operand.
            # +2 to move on the next insn.
            if off & 0x8000 == 0: trg_addr = addr + off + 2 +2
            else:                 trg_addr = addr - (~off + 1) + 2 + 2
            mnem = f'je {off:04X}h (~> {trg_addr:08X})'
        elif opcode == 7:
            off = vm_prog[pc]
            pc += 1
            if off & 0x8000 == 0: trg_addr = addr + off + 2 + 2
            else:                 trg_addr = addr -off  + 2 + 2
            mnem = f'jne {off:04X}h (~> {trg_addr:08X})'
        elif opcode == 8: mnem = 'read_flag_half'
        elif opcode == 9:
            imm = vm_prog[pc]
            pc += 1 
            mnem = f'push 0x{imm:04X}'
        elif opcode == 10: mnem = 'push reg'            
        elif opcode == 11: mnem = 'pop reg'            
        elif opcode == 12: mnem = 'pop'        
        elif opcode == 13: mnem = 'halt'
        else:
            break  # Invalid opcode; We reached the end of the program.

        pad = ' '*(41-len(f'{addr:08X}h: {mnem}')) + ';'
        print(f'{addr:08X}h: {mnem}{pad}')

# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] flash VM Disassembler Started.')
    disasm_vm_prog()
    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop2:~/ctf/0ctf_2020/flash-1$ ./flash_disasm.py 
[+] flash VM Disassembler Started.
[+] Disassembling the VM program ...
80003D40h: push 0x091D                   ;
80003D44h: push 0x0000                   ;
80003D48h: push reg                      ;
80003D4Ah: cmp ==                        ;
80003D4Ch: je 0014h (~> 80003D64)        ;
80003D50h: push 0x0001                   ;
80003D54h: push reg                      ;
80003D56h: sub                           ;
80003D58h: pop reg                       ;
80003D5Ah: read_flag_half                ;
80003D5Ch: push 0x0001                   ;
80003D60h: je FFE0h (~> 80013D44)        ;
80003D64h: push 0x0011                   ;
80003D68h: mul                           ;
80003D6Ah: push 0xB248                   ;
80003D6Eh: mod                           ;
80003D70h: push 0x72A9                   ;
80003D74h: cmp ==                        ;
80003D76h: jne 0144h (~> 80003EBE)       ;
80003D7Ah: push 0x0011                   ;
80003D7Eh: mul                           ;
80003D80h: push 0xB248                   ;
80003D84h: mod                           ;
80003D86h: push 0x097E                   ;
80003D8Ah: cmp ==                        ;
80003D8Ch: jne 012Eh (~> 80003EBE)       ;
80003D90h: push 0x0011                   ;
80003D94h: mul                           ;
80003D96h: push 0xB248                   ;
80003D9Ah: mod                           ;
80003D9Ch: push 0x5560                   ;
80003DA0h: cmp ==                        ;
80003DA2h: jne 0118h (~> 80003EBE)       ;
80003DA6h: push 0x0011                   ;
80003DAAh: mul                           ;
80003DACh: push 0xB248                   ;
80003DB0h: mod                           ;
80003DB2h: push 0x4CA1                   ;
80003DB6h: cmp ==                        ;
80003DB8h: jne 0102h (~> 80003EBE)       ;
80003DBCh: push 0x0011                   ;
80003DC0h: mul                           ;
80003DC2h: push 0xB248                   ;
80003DC6h: mod                           ;
80003DC8h: push 0x0037                   ;
80003DCCh: cmp ==                        ;
80003DCEh: jne 00ECh (~> 80003EBE)       ;
80003DD2h: push 0x0011                   ;
80003DD6h: mul                           ;
80003DD8h: push 0xB248                   ;
80003DDCh: mod                           ;
80003DDEh: push 0xAA71                   ;
80003DE2h: cmp ==                        ;
80003DE4h: jne 00D6h (~> 80003EBE)       ;
80003DE8h: push 0x0011                   ;
80003DECh: mul                           ;
80003DEEh: push 0xB248                   ;
80003DF2h: mod                           ;
80003DF4h: push 0x122C                   ;
80003DF8h: cmp ==                        ;
80003DFAh: jne 00C0h (~> 80003EBE)       ;
80003DFEh: push 0x0011                   ;
80003E02h: mul                           ;
80003E04h: push 0xB248                   ;
80003E08h: mod                           ;
80003E0Ah: push 0x4536                   ;
80003E0Eh: cmp ==                        ;
80003E10h: jne 00AAh (~> 80003EBE)       ;
80003E14h: push 0x0011                   ;
80003E18h: mul                           ;
80003E1Ah: push 0xB248                   ;
80003E1Eh: mod                           ;
80003E20h: push 0x11E8                   ;
80003E24h: cmp ==                        ;
80003E26h: jne 0094h (~> 80003EBE)       ;
80003E2Ah: push 0x0011                   ;
80003E2Eh: mul                           ;
80003E30h: push 0xB248                   ;
80003E34h: mod                           ;
80003E36h: push 0x1247                   ;
80003E3Ah: cmp ==                        ;
80003E3Ch: jne 007Eh (~> 80003EBE)       ;
80003E40h: push 0x0011                   ;
80003E44h: mul                           ;
80003E46h: push 0xB248                   ;
80003E4Ah: mod                           ;
80003E4Ch: push 0x76C7                   ;
80003E50h: cmp ==                        ;
80003E52h: jne 0068h (~> 80003EBE)       ;
80003E56h: push 0x0011                   ;
80003E5Ah: mul                           ;
80003E5Ch: push 0xB248                   ;
80003E60h: mod                           ;
80003E62h: push 0x096D                   ;
80003E66h: cmp ==                        ;
80003E68h: jne 0052h (~> 80003EBE)       ;
80003E6Ch: push 0x0011                   ;
80003E70h: mul                           ;
80003E72h: push 0xB248                   ;
80003E76h: mod                           ;
80003E78h: push 0x122C                   ;
80003E7Ch: cmp ==                        ;
80003E7Eh: jne 003Ch (~> 80003EBE)       ;
80003E82h: push 0x0011                   ;
80003E86h: mul                           ;
80003E88h: push 0xB248                   ;
80003E8Ch: mod                           ;
80003E8Eh: push 0x87CB                   ;
80003E92h: cmp ==                        ;
80003E94h: jne 0026h (~> 80003EBE)       ;
80003E98h: push 0x0011                   ;
80003E9Ch: mul                           ;
80003E9Eh: push 0xB248                   ;
80003EA2h: mod                           ;
80003EA4h: push 0x09E4                   ;
80003EA8h: cmp ==                        ;
80003EAAh: jne 0010h (~> 80003EBE)       ;
80003EAEh: push 0x091D                   ;
80003EB2h: jne 0008h (~> 80003EBE)       ;
80003EB6h: push 0x0000                   ;
80003EBAh: pop reg                       ;
80003EBCh: halt                          ;
80003EBEh: push 0x0001                   ;
80003EC2h: pop reg                       ;
80003EC4h: halt                          ;
[+] Program finished. Bye bye :)
'''
# ----------------------------------------------------------------------------------------
