#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Tokyo Westerns CTF 2019 - EBC (RE 232)
# --------------------------------------------------------------------------------------------------
import struct
import os
import sys
import re
import numpy
import zlib
from z3 import *


# --------------------------------------------------------------------------------------------------
# Code copied from: https://gist.github.com/percontation/11310679
# Data must be in 32 bit chunks, because I'm lazy.
def z3crc32(data, crc = 0):
    crc ^= 0xFFFFFFFF
    #for c in data:
    c = data
    #for block in range(64, -1, -8):
    for block in range(0, 64, 8):
        crc ^= LShR(c, block) & 0xFF
        for i in range(8):
            crc = If(crc & 1 == BitVecVal(1, 64), LShR(crc, 1) ^ 0xedb88320, LShR(crc, 1))
    return crc ^ 0xFFFFFFFF


# --------------------------------------------------------------------------------------------------
def emulate_chunk(code, target_value, crc32=0, all=False, printable=True):
    s = Solver()                                    # our constraint solver

    regs = {
        0: [], 
        1: [BitVec('R1_0', 64)],
        2: [],
        3: [],
        4: [],
        5: [],
        6: [],
        7: []
    }
 
    for line in code:                               # for asm line in the code
        if not line.strip(): continue               # skip empty lines

        print "[+] Parsing line: '%s'" % line.strip()

        # parse line looking for instruction matches
        match_0 = re.search(r'MOVIqq R([0-7]), (0x[0-9a-f]+)', line)
        match_b = re.search(r'MOVIqd R([0-7]), (0x[0-9a-f]+)', line)
        match_1 = re.search(r'MOVIqw R([0-7]), (0x[0-9a-f]+)', line)
        match_2 = re.search(r'MOVqw R([0-7]), R([0-7])',     line)
        match_3 = re.search(r'ADD R([0-7]), R([0-7])',     line)
        match_4 = re.search(r'SUB R([0-7]), R([0-7])',     line)
        match_5 = re.search(r'XOR R([0-7]), R([0-7])',     line)
        match_c = re.search(r'AND R([0-7]), R([0-7])',     line)
        match_6 = re.search(r'OR R([0-7]), R([0-7])',      line)
        match_7 = re.search(r'NOT R([0-7]), R([0-7])',     line)
        match_8 = re.search(r'NEG R([0-7]), R([0-7])',     line)
        match_9 = re.search(r'SHL R([0-7]), R([0-7])',     line)
        match_a = re.search(r'SHR R([0-7]), R([0-7])',     line)
        match_d = re.search(r'MULU R([0-7]), R([0-7])',    line)


        # immediate assignment (64 bits)
        if match_0 is not None:
            reg = int(match_0.group(1))
            val = int(match_0.group(2), 0)

            reg_st = BitVec('R%d_%d' % (reg, len(regs[reg])), 64)
            s.add(reg_st == val)
            regs[reg].append(reg_st)

        # immediate assignment (32 bits)
        elif match_b is not None:
            reg = int(match_b.group(1))
            val = int(match_b.group(2), 0)

            reg_st = BitVec('R%d_%d' % (reg, len(regs[reg])), 64)
            s.add(reg_st == val & 0xffffffff)
            regs[reg].append(reg_st)

        # immediate assignment (16 bits)
        elif match_1 is not None:
            reg = int(match_1.group(1))
            val = int(match_1.group(2), 0)
            
            reg_st = BitVec('R%d_%d' % (reg, len(regs[reg])), 64)
            s.add(reg_st == val & 0xffff)
            regs[reg].append(reg_st)

        # register to register move    
        elif match_2 is not None:
            reg1 = int(match_2.group(1))
            reg2 = int(match_2.group(2))

            reg_st = BitVec('R%d_%d' % (reg1, len(regs[reg1])), 64)
            s.add(reg_st == regs[reg2][-1])
            regs[reg1].append(reg_st)

        # addition
        elif match_3 is not None:
            reg1 = int(match_3.group(1))
            reg2 = int(match_3.group(2))

            reg_st = BitVec('R%d_%d' % (reg1, len(regs[reg1])), 64)
            s.add(reg_st == regs[reg1][-1] + regs[reg2][-1])
            regs[reg1].append(reg_st)

        # subtraction
        elif match_4 is not None:
            reg1 = int(match_4.group(1))
            reg2 = int(match_4.group(2))                      

            reg_st = BitVec('R%d_%d' % (reg1, len(regs[reg1])), 64)
            s.add(reg_st == regs[reg1][-1] - regs[reg2][-1])
            regs[reg1].append(reg_st)

        # logic xor
        elif match_5 is not None:
            reg1 = int(match_5.group(1))
            reg2 = int(match_5.group(2))            

            reg_st = BitVec('R%d_%d' % (reg1, len(regs[reg1])), 64)
            s.add(reg_st == regs[reg1][-1] ^ regs[reg2][-1])
            regs[reg1].append(reg_st)

        # logic and
        elif match_c is not None:
            reg1 = int(match_c.group(1))
            reg2 = int(match_c.group(2))

            reg_st = BitVec('R%d_%d' % (reg1, len(regs[reg1])), 64)
            s.add(reg_st == regs[reg1][-1] & regs[reg2][-1])
            regs[reg1].append(reg_st)

        # logic or
        elif match_6 is not None:
            reg1 = int(match_6.group(1))
            reg2 = int(match_6.group(2))

            reg_st = BitVec('R%d_%d' % (reg1, len(regs[reg1])), 64)
            s.add(reg_st == regs[reg1][-1] | regs[reg2][-1])
            regs[reg1].append(reg_st)

        # logic not
        elif match_7 is not None:
            reg1 = int(match_7.group(1))
            reg2 = int(match_7.group(2))

            reg_st = BitVec('R%d_%d' % (reg1, len(regs[reg1])), 64)
            s.add(reg_st == ~regs[reg2][-1])
            regs[reg1].append(reg_st)

        # 2's complement
        elif match_8 is not None:
            reg1 = int(match_8.group(1))
            reg2 = int(match_8.group(2))                    

            reg_st = BitVec('R%d_%d' % (reg1, len(regs[reg1])), 64)
            s.add(reg_st == -1*regs[reg2][-1])
            regs[reg1].append(reg_st)

        # logic left shift
        elif match_9 is not None:
            reg1 = int(match_9.group(1))
            reg2 = int(match_9.group(2))            

            reg_st = BitVec('R%d_%d' % (reg1, len(regs[reg1])), 64)
            s.add(reg_st == regs[reg1][-1] << regs[reg2][-1])
            regs[reg1].append(reg_st)

        # logic right shift
        elif match_a is not None:
            reg1 = int(match_a.group(1))
            reg2 = int(match_a.group(2))            

            reg_st = BitVec('R%d_%d' % (reg1, len(regs[reg1])), 64)
            # /!\ DON'T USE >>, we don't want the arithmetic one (with sign extension)
            s.add(reg_st == LShR(regs[reg1][-1], regs[reg2][-1]))
            regs[reg1].append(reg_st)
        
        # multiplication
        elif match_d is not None:
            reg1 = int(match_d.group(1))
            reg2 = int(match_d.group(2))            

            reg_st = BitVec('R%d_%d' % (reg1, len(regs[reg1])), 64)
            s.add(reg_st == regs[reg1][-1] * regs[reg2][-1])
            regs[reg1].append(reg_st)
        else:
            print '[+] Error! Cannot parse instruction:', line
            # exit()


    # Add the final constraint
    s.add(regs[1][-1] == target_value)
    
    if printable:
        # We also want characters to be printable
        s.add(And( regs[1][0]        & 0xff > 0x20,  regs[1][0]        & 0xff < 0x7f))
        s.add(And((regs[1][0] >>  8) & 0xff > 0x20, (regs[1][0]  >> 8) & 0xff < 0x7f))
        s.add(And((regs[1][0] >> 16) & 0xff > 0x20, (regs[1][0] >> 16) & 0xff < 0x7f))
        s.add(And((regs[1][0] >> 24) & 0xff > 0x20, (regs[1][0] >> 24) & 0xff < 0x7f))
        s.add(And((regs[1][0] >> 32) & 0xff > 0x20, (regs[1][0] >> 32) & 0xff < 0x7f))
        s.add(And((regs[1][0] >> 40) & 0xff > 0x20, (regs[1][0] >> 40) & 0xff < 0x7f))
        s.add(And((regs[1][0] >> 48) & 0xff > 0x20, (regs[1][0] >> 48) & 0xff < 0x7f))
        s.add(And((regs[1][0] >> 56) & 0xff > 0x20, (regs[1][0] >> 56) & 0xff < 0x7f))


    if crc32:
        # Add the checksum constraint to narrow down the solutions
        s.add(crc32 == z3crc32(regs[1][0]))
    
    print '[+] Constraints:'
    print s


    # check if sat
    if s.check() == unsat:
        print '[!] Error. Unsatisfiable Constraints :('
        exit()

    # Enumerate all solutions
    while s.check() == sat:
        m = s.model()
        
        # for reg, states in regs.items():
        #     print '[+] Solution states for R_%d:' % reg
        #
        #     for reg_st in states:
        #         print '\t%6s = 0x%016x' % (reg_st, m.evaluate(reg_st).as_long())
        
        solution_int = m.evaluate(regs[1][0]).as_long()
        solution     = '%016x' % solution_int

        solution_ascii = [chr(int(solution[i:i+2], 16)) for i in xrange(0, len(solution), 2)]
        solution_ascii.reverse()

        
        print '[+] Solution: R_1[0] = 0x%s' % solution, solution_ascii, ''.join(solution_ascii)

        # add solution to the constraints so it won't show up again
        s.add(regs[1][0] != m.evaluate(regs[1][0]).as_long())

        if not all: break

    return ''.join(solution_ascii), solution_int


# --------------------------------------------------------------------------------------------------
def load_asm(filename):
    payload = []

    with open(filename, 'r') as fp:
        lines = fp.readlines()

        for line in lines:
            if not line or line[0] == ';':
                continue
        
            # if you hit the CMP instruction stop parsing
            if re.search(r'CMPeq', line) is not None:
                break    

            payload.append(line) 

    return payload


# --------------------------------------------------------------------------------------------------
def load_asm_ex(filename):
    payload1 = []
    payload2 = []

    payload = payload1

    with open(filename, 'r') as fp:
        lines = fp.readlines()

        for line in lines:
            if not line or line[0] == ';':
                continue
        
            # if you hit the CMP instruction stop parsing
            if re.search(r'CMPeq', line) is not None:            
                if payload == payload1:
                    payload = payload2 
                    continue
                else:
                    break

            payload.append(line) 

    return payload1, payload2


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    print '[+] EBC crack started.'

    # -------------------------------------------------------------------------
    print '[+] Cracking characters 0-7 from key ...'

    payload_stage_1 = load_asm('payload_stage_1.asm')
    key1, _ = emulate_chunk(payload_stage_1, 0x80a7fc193032faed)


    # -------------------------------------------------------------------------
    print '[+] Cracking characters 8-15 from key ...'

    payload_stage_2 = load_asm('payload_stage_2.asm')
    key2, _ = emulate_chunk(payload_stage_2, 0x0fa64b5e994d9761)


    # -------------------------------------------------------------------------
    print '[+] Cracking characters 16-23 from key ...'

    payload_stage_3a, payload_stage_3b = load_asm_ex('payload_stage_3.asm')

    # This has 2 solutions: "1q_m4d3_" and "1s_m4d3_". The 2nd is the correct
    # one so we don't need to crack payload_stage_3b.
    key3, _ = emulate_chunk(payload_stage_3a, 0x670892bafae5ffa3, all=True)


    # -------------------------------------------------------------------------
    print '[+] Cracking characters 24-31 from key ...'

    payload_stage_4a, payload_stage_4b = load_asm_ex('payload_stage_4.asm')
        
    _, crc32 = emulate_chunk(payload_stage_4b, 0x3b8a0c323fc86d82, printable=False)
    print '[+] Cracking crc32 first: 0x%08x' % crc32
    
    key4, _ = emulate_chunk(payload_stage_4a, 0xc652a134ee9daa02, crc32=crc32)


    print '[+] Final Key: %s%s%s%s' % (key1, key2, key3, key4)


# --------------------------------------------------------------------------------------------------
'''
ispo@leet:~/ctf/tokyowesterns_ctf_2019/EBC$ time ./ebc_crack.py
[+] EBC crack started.
[+] Cracking characters 0-7 from key ...
[+] Parsing line: '0x04006354: 60 81 02 10                     MOVqw R1, @R0 (+2, +0)          ; arg1'
....
[+] Parsing line: '0x040065ec: f7 37 ed fa 32 30 19 fc a7 80   MOVIqq R7, 0x80a7fc193032faed   ;'
[+] Constraints:
[R2_0 == 13501076693576984818,
 R3_0 == 15207011548010871691,
...
 R2_3 == 10165337342589784186,
 R1_86 == R1_85 + R3_4,
 R4_4 == 1887921491485505893,
 R1_87 == R1_86 ^ R3_4,
 R6_15 == 4559460261259898968,
 ...]
[+] Solution: R_1[0] = 0x65376e315f434245 ['E', 'B', 'C', '_', '1', 'n', '7', 'e'] EBC_1n7e
[+] Cracking characters 8-15 from key ...
[+] Parsing line: '0x04006354: 60 81 02 10                     MOVqw R1, @R0 (+2, +0)'
....
[+] Parsing line: '0x04006a6a: 58 21                           SHR R1, R2'
[+] Parsing line: '0x04006a6c: 55 31                           OR R1, R3'
[+] Parsing line: '0x04006a6e: f7 33 36 51 8e 8c ce de 5c e6   MOVIqq R3, 0xe65cdece8c8e5136'
[+] Parsing line: '0x04006a78: f7 32 77 51 2d af 1d ec aa ee   MOVIqq R2, 0xeeaaec1daf2d5177'
[+] Parsing line: '0x04006a82: f7 34 8e 36 b0 c6 1e c6 1d 45   MOVIqq R4, 0x451dc61ec6b0368e'
[+] Parsing line: '0x04006a8c: 4d 71                           SUB R1, R7'
[+] Parsing line: '0x04006a8e: f7 37 61 97 4d 99 5e 4b a6 0f   MOVIqq R7, 0x0fa64b5e994d9761'
[+] Constraints:
[R2_0 == 13501076693576984818,
 R3_0 == 15207011548010871691,
 R4_0 == 2016015100068516181,
 R5_0 == 11717325765229425493,
 R6_0 == 12324678189547737396,
 R7_0 == 7444875943671868221,
 R1_1 == R1_0 - R6_0,
 R1_2 == R1_1 ^ R5_0,
 R7_1 == 15713790020847686318,
 R7_2 == R1_2,
 ....
 R1_39 == 18446744073709551615*R1_38,
 ...]
[+] Solution: R_1[0] = 0x5f72337465727072 ['r', 'p', 'r', 'e', 't', '3', 'r', '_'] rpret3r_
[+] Cracking characters 16-23 from key ...
[+] Parsing line: '0x04006354:  60 81 02 10 MOVqw R1, @R0 (+2, +0)'
....
[+] Parsing line: '0x04006aca:  4d 21   SUB R1, R2'
[+] Parsing line: '0x04006acc:  f7 36 67 dd 4b fd f2 08 83 30   MOVIqq R6, 0x308308f2fd4bdd67'
[+] Parsing line: '0x04006ad6:  f7 37 a3 ff e5 fa ba 92 08 67   MOVIqq R7, 0x670892bafae5ffa3'
[+] Constraints:
[R2_0 == 13501076693576984818,
 ....
 R7_14 == R7_13 << R2_12,
 R2_13 == 6,
 R1_33 == LShR(R1_32, R2_13),
 R1_34 == R1_33 | R7_14,
 R7_15 == 15705948179577831904,
 R2_14 == 8968981868227906830,
 ...]
[+] Solution: R_1[0] = 0x5f3364346d5f7131 ['1', 'q', '_', 'm', '4', 'd', '3', '_'] 1q_m4d3_
[+] Solution: R_1[0] = 0x5f3364346d5f7331 ['1', 's', '_', 'm', '4', 'd', '3', '_'] 1s_m4d3_
[+] Cracking characters 24-31 from key ...
[+] Parsing line: '0x04006a7c:  82 7e   JMP8cc 0x7e'
[+] Error! Cannot parse instruction: 0x04006a7c:    82 7e   JMP8cc 0x7e

[+] Parsing line: '0x04006a7e:  60 81 03 10 MOVqw R1, @R0 (+3, +0)'
[+] Error! Cannot parse instruction: 0x04006a7e:    60 81 03 10 MOVqw R1, @R0 (+3, +0)

[+] Parsing line: '0x04006a82:  f7 32 fa 75 dc d9 d1 08 18 4e   MOVIqq R2, 0x4e1808d1d9dc75fa'
[+] Parsing line: '0x04006a8c:  f7 33 9e 9d 48 fc 94 22 f9 2e   MOVIqq R3, 0x2ef92294fc489d9e'
[+] Parsing line: '0x04006a96:  f7 34 12 f2 b3 24 12 1c 27 fe   MOVIqq R4, 0xfe271c1224b3f212'
[+] Parsing line: '0x04006aa0:  f7 35 e4 99 7e 36 18 b0 c8 4c   MOVIqq R5, 0x4cc8b018367e99e4'
[+] Parsing line: '0x04006aaa:  f7 36 d6 be ec 8a b1 ab ed ef   MOVIqq R6, 0xefedabb18aecbed6'
[+] Parsing line: '0x04006ab4:  f7 37 10 1a 3d 6e d0 3f 97 c4   MOVIqq R7, 0xc4973fd06e3d1a10'
[+] Parsing line: '0x04006abe:  4d 71   SUB R1, R7'
[+] Parsing line: '0x04006ac0:  4d 51   SUB R1, R5'
[+] Parsing line: '0x04006ac2:  f7 33 83 bc 88 c8 97 3d 36 dc   MOVIqq R3, 0xdc363d97c888bc83'
[+] Parsing line: '0x04006acc:  4d 71   SUB R1, R7'
[+] Parsing line: '0x04006ace:  4d 61   SUB R1, R6'
[+] Parsing line: '0x04006ad0:  f7 33 a9 51 83 29 72 dc d3 75   MOVIqq R3, 0x75d3dc72298351a9'
[+] Parsing line: '0x04006ada:  56 21   XOR R1, R2'
[+] Parsing line: '0x04006adc:  20 13   MOVqw R3, R1'
[+] Parsing line: '0x04006ade:  77 34 3f 00 MOVIqw R4, 0x003f'
[+] Parsing line: '0x04006ae2:  58 43   SHR R3, R4'
[+] Parsing line: '0x04006ae4:  77 34 01 00 MOVIqw R4, 0x0001'
[+] Parsing line: '0x04006ae8:  57 41   SHL R1, R4'
[+] Parsing line: '0x04006aea:  55 31   OR R1, R3'
[+] Parsing line: '0x04006aec:  f7 33 77 1f 23 45 12 f2 cc 3c   MOVIqq R3, 0x3cccf21245231f77'
[+] Parsing line: '0x04006af6:  f7 34 2e e3 d4 b9 a8 dc 24 94   MOVIqq R4, 0x9424dca8b9d4e32e'
[+] Parsing line: '0x04006b00:  20 16   MOVqw R6, R1'
[+] Parsing line: '0x04006b02:  77 34 33 00 MOVIqw R4, 0x0033'
[+] Parsing line: '0x04006b06:  57 46   SHL R6, R4'
[+] Parsing line: '0x04006b08:  77 34 0d 00 MOVIqw R4, 0x000d'
[+] Parsing line: '0x04006b0c:  58 41   SHR R1, R4'
[+] Parsing line: '0x04006b0e:  55 61   OR R1, R6'
[+] Parsing line: '0x04006b10:  f7 36 0d 13 65 cb a9 a9 cc 5f   MOVIqq R6, 0x5fcca9a9cb65130d'
[+] Parsing line: '0x04006b1a:  f7 34 69 5c ff ff 20 97 8a 43   MOVIqq R4, 0x438a9720ffff5c69'
[+] Parsing line: '0x04006b24:  56 61   XOR R1, R6'
[+] Parsing line: '0x04006b26:  4d 71   SUB R1, R7'
[+] Parsing line: '0x04006b28:  4c 51   ADD R1, R5'
[+] Parsing line: '0x04006b2a:  f7 32 81 f2 58 e7 4e 16 f0 93   MOVIqq R2, 0x93f0164ee758f281'
[+] Parsing line: '0x04006b34:  4c 41   ADD R1, R4'
[+] Parsing line: '0x04006b36:  f7 35 2e cc 48 c6 67 e8 35 4f   MOVIqq R5, 0x4f35e867c648cc2e'
[+] Parsing line: '0x04006b40:  20 14   MOVqw R4, R1'
[+] Parsing line: '0x04006b42:  77 37 03 00 MOVIqw R7, 0x0003'
[+] Parsing line: '0x04006b46:  58 74   SHR R4, R7'
[+] Parsing line: '0x04006b48:  77 37 3d 00 MOVIqw R7, 0x003d'
[+] Parsing line: '0x04006b4c:  57 71   SHL R1, R7'
[+] Parsing line: '0x04006b4e:  55 41   OR R1, R4'
[+] Parsing line: '0x04006b50:  f7 34 31 72 23 f5 97 27 de 39   MOVIqq R4, 0x39de2797f5237231'
[+] Parsing line: '0x04006b5a:  f7 37 a5 4d 1e 96 2e 98 7d bc   MOVIqq R7, 0xbc7d982e961e4da5'
[+] Parsing line: '0x04006b64:  56 31   XOR R1, R3'
[+] Parsing line: '0x04006b66:  f7 37 82 6d c8 3f 32 0c 8a 3b   MOVIqq R7, 0x3b8a0c323fc86d82'
[+] Constraints:
[R2_0 == 5627257431795725818,
 R3_0 == 3384774618228759966,
 R4_0 == 18313637273976173074,
 R5_0 == 5532865760264624612,
 R6_0 == 17288663323573534422,
 R7_0 == 14165861317352430096,
 R1_1 == R1_0 - R7_0,
 R1_2 == R1_1 - R5_0,
 R3_1 == 15867938059200281731,
 R1_3 == R1_2 - R7_0,
 R1_4 == R1_3 - R6_0,
 R3_2 == 8490372105404371369,
 R1_5 == R1_4 ^ R2_0,
 R3_3 == R1_5,
 R4_1 == 63,
 R3_4 == LShR(R3_3, R4_1),
 R4_2 == 1,
 R1_6 == R1_5 << R4_2,
 R1_7 == R1_6 | R3_4,
 R3_5 == 4381142697807912823,
 R4_3 == 10674899634005271342,
 R6_1 == R1_7,
 R4_4 == 51,
 R6_2 == R6_1 << R4_4,
 R4_5 == 13,
 R1_8 == LShR(R1_7, R4_5),
 R1_9 == R1_8 | R6_2,
 R6_3 == 6903078875579093773,
 R4_6 == 4866868515316915305,
 R1_10 == R1_9 ^ R6_3,
 R1_11 == R1_10 - R7_0,
 R1_12 == R1_11 + R5_0,
 R2_1 == 10660044846130590337,
 R1_13 == R1_12 + R4_6,
 R5_1 == 5707723635167906862,
 R4_7 == R1_13,
 R7_1 == 3,
 R4_8 == LShR(R4_7, R7_1),
 R7_2 == 61,
 R1_14 == R1_13 << R7_2,
 R1_15 == R1_14 | R4_8,
 R4_9 == 4169813838597943857,
 R7_3 == 13582179377073769893,
 R1_16 == R1_15 ^ R3_5,
 R7_4 == 4290255004981816706,
 R1_16 == 4290255004981816706]
[+] Solution: R_1[0] = 0x00000000c13fa3bb ['\xbb', '\xa3', '?', '\xc1', '\x00', '\x00', '\x00', '\x00'] ��?�
[+] Cracking crc32 first: 0xc13fa3bb
[+] Parsing line: '0x04006254:  60 81 02 10 MOVqw R1, @R0 (+2, +0)'
....
[+] Parsing line: '0x04006a58:  57 61   SHL R1, R6'
[+] Parsing line: '0x04006a5a:  55 21   OR R1, R2'
[+] Parsing line: '0x04006a5c:  f7 32 ef c7 8f 57 5d ec ac 8f   MOVIqq R2, 0x8facec5d578fc7ef'
[+] Parsing line: '0x04006a66:  f7 36 c3 7a 55 82 ca b3 01 ed   MOVIqq R6, 0xed01b3ca82557ac3'
[+] Parsing line: '0x04006a70:  f7 37 02 aa 9d ee 34 a1 52 c6   MOVIqq R7, 0xc652a134ee9daa02'
[+] Constraints:
[R2_0 == 13501076693576984818,
 R3_0 == 15207011548010871691,
....
 R5_16 == LShR(R5_15, R4_16),
 R4_17 == 53,
 R1_37 == R1_36 << R4_17,
 R1_38 == R1_37 | R5_16,
 R5_17 == 3389717820076447729,
 R4_18 == 7840921510260739643,
 R5_18 == 7708744519154432345,
 R7_8 == R1_38,
 R5_19 == 28,
 R7_9 == R7_8 << R5_19,
 R5_20 == 36,
 R1_39 == LShR(R1_38, R5_20),
 ...]
[+] Solution: R_1[0] = 0x6c346e303174706f ['o', 'p', 't', '1', '0', 'n', '4', 'l'] opt10n4l
[+] Final Key: EBC_1n7erpret3r_1s_m4d3_opt10n4l

real    0m4.131s
user    0m4.214s
sys 0m0.236s
'''
# --------------------------------------------------------------------------------------------------

