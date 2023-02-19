#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# 0CTF 2019 - Elements (RE 107)
# ----------------------------------------------------------------------------------------
import struct
import unicorn
import keystone
import z3
import math


# ----------------------------------------------------------------------------------------
# NOTE: THIS FUNCTION IS NOT USED TO GET THE FLAG.
def floatify(hexnum):
    """Converts a hex number into a floating point number."""    
    asm_code = b'''
        xor         r14, r14
        
        movq        xmm0, rax
        punpckldq   xmm0, xmmword ptr [rip+0x210]
        subpd       xmm0, xmmword ptr [rip+0x218]
        pshufd      xmm1, xmm0, 4Eh
        addpd       xmm1, xmm0
        movlpd      qword ptr [rsp+r14*8+0x20], xmm1
    '''
    try:
        # Initialize engine in X86-32bit mode
        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        encoding, count = ks.asm(asm_code)
    except keystone.KsError as e:
        raise Exception('Keystone Error', e)

    # Memory address where emulation starts
    ADDRESS = 0x4009B3 - 3
    STACK = 0xbeef0000
    
    try:
        # Initialize emulator
        mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        mu.mem_map(ADDRESS & 0xFFFF0000, 1 * 1024 * 1024)
        mu.mem_map(STACK, 1 * 1024 * 1024)

        # Write globals to memory
        mu.mem_write(ADDRESS, bytes(encoding))
        mu.mem_write(0x400BD0, b'\x00\x00\x30\x43\x00\x00\x30\x45\x00\x00\x00\x00\x00\x00\x00\x00')
        mu.mem_write(0x400BE0, b'\x00\x00\x00\x00\x00\x00\x30\x43\x00\x00\x00\x00\x00\x00\x30\x45')

        # Initialize machine registers
        mu.reg_write(unicorn.x86_const.UC_X86_REG_RAX, hexnum)
        mu.reg_write(unicorn.x86_const.UC_X86_REG_RSP, STACK)

        # Do the actual emulation
        mu.emu_start(ADDRESS, ADDRESS + len(encoding))

        # Print the results
        xmm0 = mu.reg_read(unicorn.x86_const.UC_X86_REG_XMM0)
        xmm1 = mu.reg_read(unicorn.x86_const.UC_X86_REG_XMM1)

        dbl = mu.mem_read(STACK + 0x20, 8)
        dbl = struct.unpack('d', dbl)[0]

        print(f'[+] xmm0: {xmm0:032X}')
        print(f'[+] xmm1: {xmm1:032X}')
        print(f'[+] Double Number: {dbl}')

        return dbl
    except unicorn.UcError as e:
        raise Exception('Emulation error', e)


# ----------------------------------------------------------------------------------------
def unfloatify(fpnum):
    """Inverse of `floatify`. Converts a floating point into hex."""
    # Be very careful with instruction offsets.
    asm_code = b'''
        movq        xmm1, rax
        movlhps     xmm2, xmm1
        por         xmm2, xmm1
        nop 
        addpd       xmm0, xmmword ptr [rip+0x218]
        addpd       xmm2, xmm0
    '''
    try:
        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
        encoding, count = ks.asm(asm_code)
    except keystone.KsError as e:
        raise Exception('Keystone Error', e)

    # Memory address where emulation starts
    ADDRESS = 0x4009B3
    STACK = 0xbeef0000
    
    try:
        pack = struct.pack('d', fpnum)
        pack = struct.unpack('<Q', pack)[0]
        print(f'[+] Packing Number: {pack:X}h')

        # Initialize emulator
        mu = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        mu.mem_map(ADDRESS & 0xFFFF0000, 1 * 1024 * 1024)
        mu.mem_map(STACK, 1 * 1024 * 1024)

        # Write machine code to be emulated to memory
        mu.mem_write(ADDRESS, bytes(encoding))
        mu.mem_write(0x400BD0, b'\x00\x00\x30\x43\x00\x00\x30\x45\x00\x00\x00\x00\x00\x00\x00\x00')
        mu.mem_write(0x400BE0, b'\x00\x00\x00\x00\x00\x00\x30\x43\x00\x00\x00\x00\x00\x00\x30\x45')

        # Initialize machine registers
        mu.reg_write(unicorn.x86_const.UC_X86_REG_RAX, pack)
        mu.reg_write(unicorn.x86_const.UC_X86_REG_RSP, STACK)

        # Do the actual emulation
        mu.emu_start(ADDRESS, ADDRESS + len(encoding))

        # Print the results
        xmm0 = mu.reg_read(unicorn.x86_const.UC_X86_REG_XMM0)
        xmm1 = mu.reg_read(unicorn.x86_const.UC_X86_REG_XMM1)
        xmm2 = mu.reg_read(unicorn.x86_const.UC_X86_REG_XMM2)

        print(f'[+] xmm0: {xmm0:032X}')
        print(f'[+] xmm1: {xmm1:032X}')
        print(f'[+] xmm2: {xmm2:032X}')

        return xmm2 & 0xFFFFFFFFFFFF  # Keep only 12 last digits        
    except unicorn.UcError as e:
        raise Exception('Emulation error', e)


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Elements Crack Started.')

    print('[+] Solving equations ...')
    # Consider a general triangle with sides A, B, C:
    #   inradius      : 2*area / (A + B + C)
    #   circumradius  : A*B*C / 4*area
    #       
    #   semiperimeter : s = (A + B + C) / 2
    #   area          : sqrt( s(s - A)(s - B)(s - C) )
    #   law of sines  : A / sinA = 2*circumradius
    #   law of cosines: A^2 = B^2 + C^2 - 2BCcos(A)
    #   Pythagorean identity: sinA^2 + cosA^2 = 1
    #
    # Triangle area can also be calculated as:
    #   sqrt(4*B^2*C^2 - (B^2 + C^2 - A^2)) / 4
    #
    # See: https://www.cuemath.com/measurement/area-of-triangle-with-3-sides
    #
    # Let's rephrase our problem:
    #   We have a triangle. We known:
    #       * side A has length: 6.2791383142154e13
    #       * inradius is: 1.940035480806554e13
    #       * circumradius is: 4.777053952827391e13
    #
    #   We want to find: sides B and C.
    #
    #   Equations we have:
    #       * A < B
    #       * B < C
    #       * A + B > C  ~> We know A, B, C are the sides of a triangle
    #       * D = A^2 + B^2 - C^2
    #       * E = sqrt(4*A^2*B^2 - D^2) / 4 ~> area of triangle
    #       * Z = 2E / (A + B + C) - C0     ~> inradius: C0
    #       * H = ABC / 4E - C1             ~> circumradius: C1
    #
    # * * * SOLUTION * * *
    #
    # From the law of sines:
    #   A / sinA = 2*circumradius = 2*C1 => sinA = 2*C1 / A     (1)
    #
    # From the law of cosines:
    #   cosA = (B^2 + C^2 - A^2) / 2BC  (2)
    #
    # Substitute (2) in the following equation:
    #   4*C0*C1*cosA/A + 4*C0*C1/A => (2)
    #   4*C0*C1*(B^2 + C^2 - A^2)/2ABC + 4*C0*C1/A => (substitute Z & H)
    #   4*2E/(A + B + C)*ABC/4E*(B^2 + C^2 - A^2)/2ABC + 4*2E/(A + B + C)*ABC/4E/A => (drop E)
    #   2*ABC/(A + B + C)*(B^2 + C^2 - A^2)/2ABC + 2*ABC/(A + B + C)/A =>
    #   (B^2 + C^2 - A^2)/(A + B + C) + 2ABC/(A + B + C)/A => (mul 2nd fraction with 2BC)
    #   (B^2 + C^2 - A^2)/(A + B + C) + 2ABC*2BC/(A + B + C)/A*2BC =>
    #   (B^2 + C^2 - A^2)/(A + B + C) + 2BC/(A + B + C) =>
    #   (B^2 + C^2 - A^2 + 2BC)/(A + B + C) =>
    #   (B^2 + C^2 + 2BC - A^2)/(A + B + C) =>
    #   ((B + C)^2 - A^2)/(A + B + C) =>
    #   (B + C + A)*(B + C - A)/(A + B + C) =>
    #   B + C - A.
    #
    # That is:
    #   4*C0*C1*cosA/A + 4*C0*C1/A + A = Q1 = B + C  (3)
    #
    # Combine (Z) and (H) equations:
    #   (Z): 2E / (A + B + C) = C0 => E = C0 / 2(A + B + C)
    #   (H): ABC / 4E = C1         => E = ABC / 4C1
    #
    #   C0 / 2(A + B + C) = ABC / 4C1 =>
    #   ABC = 2*C0*C1(A + B + C) =>
    #   BC = 2*C0*C1(A + B + C)/A =>
    #   BC = 2*C0*C1(A + Q1)/A = Q2.    (4)
    #
    # We know B + C, so we need to compute C - B:
    #   C - B =>
    #   sqrt((C - B)^2) =>
    #   sqrt(C^2 + B^2 - 2BC + 2BC - 2BC) =>
    #   sqrt((B + C)^2 - 4BC) =>
    #   sqrt(Q1^2 - 4Q2).   (5)
    #
    # That is, we end up with 2 equations with 2 unknowns:
    #   B + C = Q1                  (6)
    #   C - B = sqrt(Q1^2 - 4Q2).   (7)
    #
    # Where:
    #   Q1 = 4*C0*C1*cosA/A + 4*C0*C1/A + A
    #   Q2 = 2*C0*C1*(A + Q1)/A
    C0 = 1.940035480806554e13
    C1 = 4.777053952827391e13
    A = 6.2791383142154e13

    # math.cos(A) doesn't work, we compute it from Pythagorean identiy.
    cosA = math.sqrt(1 - A*A / (4*C1*C1))

    print(f'[+] cos(A): {cosA}')

    Q1 = 4*C0*C1*cosA/A + 4*C0*C1/A + A
    Q2 = 2*C0*C1*(A + Q1)/A
    
    print(f'[+] Computing Q1: {Q1}')
    print(f'[+] Computing Q2: {Q2}')

    # Add (6) and (7): 2C = Q1 + sqrt(Q1^2 - 4Q2)
    C = (Q1 + math.sqrt(Q1*Q1 - 4*Q2)) / 2
    print(f'[+] Found edge C: {C}')

    B = Q1 - C
    print(f'[+] Found edge B: {B}')

    # --------------------------------------------------------------------------
    print('[+] Converting B and C into hex format ...')

    # dbl = floatify(0x391BC2164F0A)
    # dbl = unfloatify(62791383142154.0)
    hexA = 0x391BC2164F0A
    hexB = unfloatify(B)
    hexC = unfloatify(C)
    print(f'[+] Double B is: {hexB:X}')
    print(f'[+] Double C is: {hexC:X}')

    a, b = '{', '}'
    
    print(f'[+] Final flag: flag{a}{hexA:x}-{hexB:x}-{hexC:x}{b}')

    print('[+] Program finished! Bye bye :)')


# ----------------------------------------------------------------------------------------
"""
ispo@ispo-glaptop2:~/ctf/0ctf_2019/elements$ ./elements_crack.py 
[+] Elements Crack Started.
[+] Solving equations ...
[+] cos(A): 0.7536999330403872
[+] Computing Q1: 166325872560350.97
[+] Computing Q2: 6.763283056335451e+27
[+] Found edge C: 95523798483317.97
[+] Found edge B: 70802074077033.0
[+] Converting B and C into hex format ...
[+] Packing Number: 42D019391E61DA40h
[+] xmm0: 45300000000000004330000000000000
[+] xmm1: 000000000000000042D019391E61DA40
[+] xmm2: 453000000000406543304064E4798769
[+] Packing Number: 42D5B83784E05D7Eh
[+] xmm0: 45300000000000004330000000000000
[+] xmm1: 000000000000000042D5B83784E05D7E
[+] xmm2: 45300000000056E1433056E0DE138176
[+] Double B is: 4064E4798769
[+] Double C is: 56E0DE138176
[+] Final flag: flag{391bc2164f0a-4064e4798769-56e0de138176}
[+] Program finished! Bye bye :)
"""
# ----------------------------------------------------------------------------------------

