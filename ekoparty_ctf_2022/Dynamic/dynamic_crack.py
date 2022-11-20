#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# EKOPARTY CTF 2022 - Dynamic (RE 490)
# ----------------------------------------------------------------------------------------
import struct
import re
import capstone
import qiling

I = 0
FLAG = ''

# ----------------------------------------------------------------------------------------
def code_hook(ql: qiling.Qiling, addr: int, size: int,
                 md: capstone.Cs):   
    insn = next(md.disasm(ql.mem.read(addr, size), addr))

    global I, FLAG
    global FLAG

    main_st = 0x403F15 
    main_en = 0x404DED 

    if main_st <= addr and addr <= main_en:
        if insn.mnemonic == 'xor':

            byte = ql.mem.read(0x6C0100 + I, 1)[0]
            #other = ql.mem.read(ql.arch.regs.rbp - 0x54, 1)[0]
            other = ql.mem.read(ql.arch.regs.rbp-0x54+I, 1)[0]#ql.arch.regs.al
            print(f'[+] HIT THE SPOT: {I}, {byte:X} ^ {other:X} = {byte ^ other:c}')

            # ql.mem.write(0x313370080 + I, bytes(byte ^ other))
            ql.arch.regs.al = (byte ^ other)

            FLAG += chr(byte ^ other)
            I += 1


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Dynamic Crack Started.')
    
    ql = qiling.Qiling(['./dynamic'], '.')
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    img_base = int(ql.profile.get('OS64', 'load_address'), 16)
    print('[+] Image Base:', hex(img_base))


    ql.hook_code(code_hook, user_data=md)

    img_base = 0;
    begin = 0x403F5C 
    end   = 0x00404DDB #0x0403FBA

    ql.log.info(f'Starting emulation from: {begin:X} ~> {end:X}')


    ql.arch.regs.edi = 2
    ql.arch.regs.rsi = 0x313370000

    # Set up stack frame
    ql.mem.map(ql.arch.regs.rbp - 0x1000, 0x1000)

    ql.mem.write(ql.arch.regs.rbp - 8, struct.pack("<Q", 0x313370080))

    ql.mem.map(ql.arch.regs.rsi, 0x1000)

    ql.mem.write(ql.arch.regs.rsi, struct.pack("<Q", 0x8000000))
    ql.mem.write(ql.arch.regs.rsi + 8, struct.pack("<Q", 0x313370080))    
    ql.mem.write(0x313370080, b'\x77'*76)
                   
    ql.run(begin=img_base + begin, end=img_base + end)
    
    print(f'[+] FLAG FOUND: {FLAG}')    
    print('[+] Program finished! Bye bye :)')

# ----------------------------------------------------------------------------------------
"""
ispo@ispo-glaptop2:~/ctf/ekoparty_ctf_2022/Dynamic$ ./dynamic_crack.py 
[+] Dynamic Crack Started.
[+] Image Base: 0x555555554000
[=]     Starting emulation from: 403F5C ~> 404DDB
[+] HIT THE SPOT: 0, A4 ^ E1 = E
[+] HIT THE SPOT: 1, 6B ^ 20 = K
[+] HIT THE SPOT: 2, A6 ^ E9 = O
[+] HIT THE SPOT: 3, FF ^ 84 = {
[+] HIT THE SPOT: 4, AD ^ EC = A
[+] HIT THE SPOT: 5, A4 ^ E2 = F
[+] HIT THE SPOT: 6, 1 ^ 4D = L
[+] HIT THE SPOT: 7, 11 ^ 57 = F
[+] HIT THE SPOT: 8, A7 ^ F3 = T
[+] HIT THE SPOT: 9, E4 ^ B3 = W
[+] HIT THE SPOT: 10, 73 ^ 2C = _
[+] HIT THE SPOT: 11, 56 ^ 34 = b
[+] HIT THE SPOT: 12, E4 ^ D6 = 2
[+] HIT THE SPOT: 13, 9F ^ AC = 3
[+] HIT THE SPOT: 14, EB ^ DC = 7
[+] HIT THE SPOT: 15, D2 ^ EB = 9
[+] HIT THE SPOT: 16, 7D ^ 1B = f
[+] HIT THE SPOT: 17, 94 ^ A4 = 0
[+] HIT THE SPOT: 18, E9 ^ D9 = 0
[+] HIT THE SPOT: 19, F9 ^ 98 = a
[+] HIT THE SPOT: 20, D5 ^ B4 = a
[+] HIT THE SPOT: 21, FD ^ C4 = 9
[+] HIT THE SPOT: 22, 9A ^ A8 = 2
[+] HIT THE SPOT: 23, F5 ^ C2 = 7
[+] HIT THE SPOT: 24, 40 ^ 22 = b
[+] HIT THE SPOT: 25, 5C ^ 6D = 1
[+] HIT THE SPOT: 26, 46 ^ 75 = 3
[+] HIT THE SPOT: 27, 11 ^ 26 = 7
[+] HIT THE SPOT: 28, 44 ^ 76 = 2
[+] HIT THE SPOT: 29, 5F ^ 3A = e
[+] HIT THE SPOT: 30, 89 ^ B1 = 8
[+] HIT THE SPOT: 31, 5D ^ 3C = a
[+] HIT THE SPOT: 32, F8 ^ 9E = f
[+] HIT THE SPOT: 33, 57 ^ 60 = 7
[+] HIT THE SPOT: 34, E1 ^ 82 = c
[+] HIT THE SPOT: 35, BD ^ DE = c
[+] HIT THE SPOT: 36, C9 ^ FC = 5
[+] HIT THE SPOT: 37, 5A ^ 39 = c
[+] HIT THE SPOT: 38, 96 ^ AE = 8
[+] HIT THE SPOT: 39, E ^ 37 = 9
[+] HIT THE SPOT: 40, 60 ^ 52 = 2
[+] HIT THE SPOT: 41, CE ^ FE = 0
[+] HIT THE SPOT: 42, C4 ^ F4 = 0
[+] HIT THE SPOT: 43, FA ^ 9E = d
[+] HIT THE SPOT: 44, 24 ^ 1D = 9
[+] HIT THE SPOT: 45, 7 ^ 63 = d
[+] HIT THE SPOT: 46, 38 ^ 59 = a
[+] HIT THE SPOT: 47, 12 ^ 20 = 2
[+] HIT THE SPOT: 48, 4F ^ 7D = 2
[+] HIT THE SPOT: 49, 30 ^ 9 = 9
[+] HIT THE SPOT: 50, 9E ^ F8 = f
[+] HIT THE SPOT: 51, F ^ 6A = e
[+] HIT THE SPOT: 52, 94 ^ A5 = 1
[+] HIT THE SPOT: 53, 80 ^ B8 = 8
[+] HIT THE SPOT: 54, 79 ^ 4A = 3
[+] HIT THE SPOT: 55, 87 ^ E4 = c
[+] HIT THE SPOT: 56, 4F ^ 77 = 8
[+] HIT THE SPOT: 57, B2 ^ D1 = c
[+] HIT THE SPOT: 58, BA ^ DE = d
[+] HIT THE SPOT: 59, 50 ^ 60 = 0
[+] HIT THE SPOT: 60, 8 ^ 39 = 1
[+] HIT THE SPOT: 61, 3B ^ 5F = d
[+] HIT THE SPOT: 62, 75 ^ 16 = c
[+] HIT THE SPOT: 63, 43 ^ 72 = 1
[+] HIT THE SPOT: 64, 5F ^ 66 = 9
[+] HIT THE SPOT: 65, 8A ^ BC = 6
[+] HIT THE SPOT: 66, AA ^ 93 = 9
[+] HIT THE SPOT: 67, 2C ^ 1D = 1
[+] HIT THE SPOT: 68, 10 ^ 26 = 6
[+] HIT THE SPOT: 69, 9B ^ AF = 4
[+] HIT THE SPOT: 70, 3 ^ 67 = d
[+] HIT THE SPOT: 71, 11 ^ 28 = 9
[+] HIT THE SPOT: 72, A5 ^ 9C = 9
[+] HIT THE SPOT: 73, 2E ^ 48 = f
[+] HIT THE SPOT: 74, 3 ^ 3A = 9
[+] HIT THE SPOT: 75, F8 ^ 85 = }
[+] FLAG FOUND: EKO{AFLFTW_b2379f00aa927b1372e8af7cc5c89200d9da229fe183c8cd01dc1969164d99f9}
[+] Program finished! Bye bye :)
"""
# ----------------------------------------------------------------------------------------
