#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# 0CTF 2019 - J (RE 578)
# ----------------------------------------------------------------------------------------
import z3

trg = [
  0x0F, 0xDA, 0x04, 0xD8, 0xD0, 0xAB, 0xF4, 0xE5, 0x3F, 0xBD, 
  0x61, 0x7C, 0x6B, 0x13, 0x7C, 0xC4, 0xF9, 0xA0, 0x54, 0x33, 
  0xA7, 0x60, 0x50, 0xDA, 0x20, 0xE2, 0x7E, 0xE1, 0x13, 0x0B, 
  0xB2, 0x25
]


buf = [
  0x43, 0x54, 0x46, 0x54, 0x51, 0x5F, 0x41, 0x55, 0x53, 0x4C,
  0x32, 0x5F, 0x32, 0x30, 0x5F, 0x30, 0xBE, 0x8C, 0xAA, 0xA2,
  0x98, 0x82, 0xBE, 0xA6, 0x60, 0x64, 0x60, 0x64, 0xA8, 0xBE,
  0xA8, 0x86, 0x05, 0x55, 0x4D, 0x31, 0xC8, 0x7C, 0xC8, 0xC0,
  0x7D, 0xC1, 0x0D, 0x51, 0x19, 0x51, 0x45, 0x7D, 0xF9, 0x9A,
  0x81, 0x91, 0x82, 0x91, 0xA2, 0xFA, 0xA2, 0x1A, 0xFA, 0x32,
  0xAA, 0x8A, 0x62, 0x0A, 0x23, 0x03, 0xF5, 0x05, 0x35, 0x44,
  0x65, 0x44, 0x15, 0xF5, 0x14, 0x54, 0x35, 0xC5, 0x23, 0xF3,
  0x88, 0xEA, 0x88, 0x6A, 0xEA, 0xCB, 0xA8, 0x2A, 0x8A, 0x29,
  0xE6, 0x6B, 0x06, 0x46, 0x0B, 0x46, 0x97, 0x11, 0x55, 0xD4,
  0x53, 0x50, 0xD7, 0x14, 0x8B, 0x48, 0xAB, 0x2B, 0xAD, 0xAF,
  0x2A, 0x28, 0x06, 0x46, 0x0B, 0x46, 0x3B, 0xF7, 0x76, 0xD6,
  0x58, 0xD5, 0x2F, 0xDD, 0x88, 0xEA, 0x88, 0x6A, 0xAC, 0xF7,
  0xCB, 0x3A, 0xEC, 0xAB, 0x4A, 0x2B, 0x35, 0x44, 0x65, 0x44,
  0x61, 0xB9, 0xDD, 0xFC, 0x9E, 0xF5, 0x0F, 0x65, 0xA2, 0x1A,
  0xFA, 0x32, 0x4F, 0xC4, 0x7E, 0x6E, 0x7F, 0x6E, 0x3F, 0x12,
  0x19, 0x51, 0x45, 0x7D, 0x6A, 0x47, 0x83, 0x3E, 0x38, 0x3F,
  0xC5, 0x9A, 0x05, 0x55, 0x4D, 0x31, 0x11, 0x6C, 0x58, 0x41,
  0xA0, 0x9B, 0xBD, 0x8C, 0x98, 0x82, 0xBE, 0xA6, 0xE7, 0x5A,
  0x42, 0x73, 0xA1, 0xCF, 0x95, 0x43, 0x53, 0x4C, 0x32, 0x5F,
  0xD4, 0xBD, 0xBA, 0xAB, 0xAF, 0xA0, 0x21, 0x04, 0xF2, 0x55,
  0xC5, 0x2D, 0x99, 0x2B, 0x00, 0x00, 0x47, 0x8E, 0x41, 0xFE,
  0xFE
]


# Helper functions.
WORD  = lambda b: (b[0] << 8) | (b[1])
WORDB = lambda b: b[0] | (b[1] << 8)  # Big endian
DWORD = lambda b: b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)

# Change endianess (big <-> little) in 32 bits.
_byteswap_ulong = lambda a: (( a        & 0xFF) << 24 |
                             ((a >> 8)  & 0xFF) << 16 |
                             ((a >> 16) & 0xFF) << 8  |
                              (a >> 24))


# ----------------------------------------------------------------------------------------
def hash_flag(flag, off = 0, dbg=True):
    """Generates a hash using 8 `flag` characters starting from `off` offset in target."""
    global trg, buf

    assert len(flag) == 8

    if dbg:
        print(f"[+] Hashing flag part: '{flag}' at offset: {off}")
    flag = [ord(c) for c in flag]

    fl1 = (flag[0] << 8) | flag[1]
    fl2 = (~(flag[2] << 8) & 0xE99E | (flag[2] << 8) & 0x1600) ^ (~flag[3] & 0xE99E | flag[3] & 0x61)
    fl3 = (~(flag[4] << 8) & 0x562A | (flag[4] << 8) & 0xA900) ^ (~flag[5] & 0x562A | flag[5] & 0xD5)
    fl4 = (~(flag[6] << 8) & 0x5089 | (flag[6] << 8) & 0xAF00) ^ (~flag[7] & 0x5089 | flag[7] & 0x76)

    if dbg:
        print(f'[+] Initial: fl1:0x{fl1:04X}, fl2:0x{fl2:04X}, fl3:0x{fl3:04X}, fl4:0x{fl4:04X}')

    trg1 = DWORD(trg[8*off:])
    trg2 = DWORD(trg[8*off + 4:])
    VAL = 0x104D9AF0

    for i in range(9):
        # Part 1.
        buf01 = WORDB(buf[12*i:])
        v1 = buf01 * fl1
        if not v1:
            # This is just fl1 - buf01 - 1!
            r1 = (0x7226 - fl1 - buf01 - 0x7225) & 0xFFFF
        else:
            r1 = (((((v1 | (v1 << 32)) >> 16) - v1) >> 16) + 1) & 0xFFFF
        
        if i == 8: break

        # Part 2.
        buf67 = WORDB(buf[12*i + 6:])
        v2 = buf67 * fl4
        if not v2:
           r2 = (0xF1F - fl4 - buf67 - 0xF1E) & 0xFFFF
        else:
           r2 = (((((~(v2 >> 16) & 0x334DAD1A | (v2 >> 16) & 0x52E5) ^ 
                    (~(v2 << 16) & 0x334DAD1A | (v2 << 16) & 0xCCB20000))
                                - v2) >> 16) + 1) & 0xFFFF
        # Part 3.
        buf23 = WORDB(buf[12*i + 2:])
        buf45 = (fl3 + WORDB(buf[12*i + 4:])) & 0xFFFF
        buf89 = WORDB(buf[12*i + 8:])

        x1 = (~r1 & 0xA212 | r1 & 0x5DED) ^ (~buf45 & 0xA212 | buf45 & 0x5DED)
        v3 = buf89 * x1
        if not v3:
            r3 = (0x493D - x1 - buf89 - 0x493C) & 0xFFFF
        else:
            r3 = (((((v3 | (v3 << 32)) >> 16) - v3) >> 16) + 1) & 0xFFFF

        # Part 4.
        bufAB = WORDB(buf[12*i + 10:])
        x0 = (fl2 + buf23) & 0xFFFF
        x2 = (r3 + ((~r2 & 0xFE0E | r2 & 0x1F1) ^ (~x0 & 0xFE0E | x0 & 0x1F1))) & 0xFFFF
        v4 = bufAB * x2 
        if not v4:
            x3 = (r3 + ((~r2 & 0xFE0E | r2 & 0x1F1) ^ (~buf23 & 0xFE0E | buf23 & 0x1F1)))
            r4 = (0xB81C - x3 - bufAB + 18405) & 0xFFFF
        else:
            r4 = (((((v4 | (v4 << 32)) >> 16) - v4) >> 16) + 1) & 0xFFFF

        H = (r4 + r3) & 0xFFFF
        fl1 = (~r4 & 0x8EC5 | r4 & 0x713A) ^ (~r1 & 0x8EC5 | r1 & 0x713A)
        fl2 = (~r4 & 0xA438 | r4 & 0x5BC7) ^ (~buf45 & 0xA438 | buf45 & 0x5BC7)
        fl3 = ~H & x0 | ~x0 & H
        fl4 = (~H & 0x3E72 | H & 0xC18D) ^ (~r2 & 0x3E72 | r2 & 0xC18D)

        # The rest is independent of the flag value.
        off2 = 4*((VAL >> 11) & (0x1FFFFC ^ (VAL >> 11)))
        t1 = (((~(trg1 >> 5) & 0x568C210F | (trg1 >> 5) & 0x173DEF0) ^ 
               (~(trg1 << 4) & 0x568C210F | (trg1 << 4) & 0xA973DEF0)) + trg1) & 0xFFFFFFFF
        t2 = (VAL + DWORD(buf[off2:])) & 0xFFFFFFFF
        trg2 = (trg2 - (t1 & ~t2 | t2 & ~t1)) & 0xFFFFFFFF

        VAL = (VAL + 0x3DF64CA2) & 0xFFFFFFFF

        off1 = 4 * (VAL & (VAL ^ 0xFFFFFFFC))
        t3 = ((~(DWORD(buf[off1:]) + VAL) & 0x6D1A24E8 | 
                (DWORD(buf[off1:]) + VAL) & 0x92E5DB17) ^ 
              (~(((trg2 >> 5) & ~(trg2 << 4) | (trg2 << 4) & ~(trg2 >> 5)) + trg2) & 0x6D1A24E8 | 
                (((trg2 >> 5) & ~(trg2 << 4) | (trg2 << 4) & ~(trg2 >> 5)) + trg2) & 0x92E5DB17))
        trg1 = (trg1 - t3) & 0xFFFFFFFF

        # buf = buf[12:]
        
        if dbg:
            print(f'[+] Round {i}: fl1:0x{fl1:04X}, fl2:0x{fl2:04X}, fl3:0x{fl3:04X}, fl4:0x{fl4:04X}')

    # Final shuffle.
    buf23 = WORDB(buf[12*i + 2:])
    buf45 = WORDB(buf[12*i + 4:]) 
    buf67 = WORDB(buf[12*i + 6:])
    
    v5 = buf67 * fl4    
    if not v5:
        r5 = (1 - fl4 - buf67) & 0xFFFF
    else:        
        r5 = (((((~(v5 >> 16) & 0x258A1540 | (v5 >> 16) & 0xEABF) ^ 
                 (~(v5 << 16) & 0x258A1540 | (v5 << 16) & 0xDA750000)) - v5) >> 16) + 1) & 0xFFFF

    # Hash computation.
    M = fl3 + buf23
    X = ((~(r1 << 8) & 0x6000 | 0xC0CC0073 | (r1 << 8) & 0x9F00) ^
         (~(r1 >> 8) & 0xC0CC6073 | (r1 >> 8) & 0x8C))
    Y =  ((~((M & (M ^ 0xFFFF0000)) >> 8) & 0xE170 | ((M & (M ^ 0xFFFF0000)) >> 8) & 0x1E8F) ^
          (~((M & (M ^ 0xFFFF0000)) << 8) & 0xE170 | ((M & (M ^ 0xFFFF0000)) << 8) & 0x1E00) | 
         ~(~((M & (M ^ 0xFFFF0000)) << 8)          | ~((M & (M ^ 0xFFFF0000)) >> 8))) << 16
    Z = X & ~(Y & ~trg1 | trg1 & ~Y) | (Y & ~trg1 | trg1 & ~Y) & ~X
    hi_W = (((r5 & (r5 ^ 0xFFFF0000)) << 8) & ((r5 & (r5 ^ 0xFFFF0000)) >> 8) | 
            ((r5 & (r5 ^ 0xFFFF0000)) >> 8) ^ ((r5 & (r5 ^ 0xFFFF0000)) << 8))
    lo_W = _byteswap_ulong((fl2 + buf45) & 0xFFFF)
    W = (hi_W << 32) | lo_W
    Q = (~(W >> 16) & 0x7E3841F4 | (W >> 16) & 0x81C7BE0B) ^ (~trg2 & 0x7E3841F4 | trg2 & 0x81C7BE0B)
    res = (~Z & 0x996215AF | Z & 0x669DEA50) ^ (~Q & 0x996215AF | Q & 0x669DEA50) | ~(~Q | ~Z)

    if dbg:
        print(f'[+] Final Hash: 0x{res:08X}')

    return res


# ----------------------------------------------------------------------------------------
def gen_trg_values(off):
    """Generates `trg` target values from a given `off` (not related to the flag value."""
    global trg, buf

    trg1 = DWORD(trg[8*off:])
    trg2 = DWORD(trg[8*off+4:])
    VAL = 0x104D9AF0

    for i in range(9):
        if i == 8: break

        # This is independent of tha flag. We only need the final values of `trg1` and `trg2`
        off2 = 4*((VAL >> 11) & (0x1FFFFC ^ (VAL >> 11)))
        t1 = (((~(trg1 >> 5) & 0x568C210F | (trg1 >> 5) & 0x173DEF0) ^ 
               (~(trg1 << 4) & 0x568C210F | (trg1 << 4) & 0xA973DEF0)) + trg1) & 0xFFFFFFFF
        t2 = (VAL + DWORD(buf[off2:])) & 0xFFFFFFFF
        trg2 = (trg2 - (t1 & ~t2 | t2 & ~t1)) & 0xFFFFFFFF

        VAL = (VAL + 0x3DF64CA2) & 0xFFFFFFFF
        
        off1 = 4 * (VAL & (VAL ^ 0xFFFFFFFC))
        t3 = ((~(DWORD(buf[off1:]) + VAL) & 0x6D1A24E8 | 
                (DWORD(buf[off1:]) + VAL) & 0x92E5DB17) ^ 
              (~(((trg2 >> 5) & ~(trg2 << 4) | (trg2 << 4) & ~(trg2 >> 5)) + trg2) & 0x6D1A24E8 | 
                (((trg2 >> 5) & ~(trg2 << 4) | (trg2 << 4) & ~(trg2 >> 5)) + trg2) & 0x92E5DB17))
        trg1 = (trg1 - t3) & 0xFFFFFFFF

    return trg1, trg2


# ----------------------------------------------------------------------------------------
def crack_final(off):
    """Cracks the last hash and recovers final values of `fl1` to `fl4`."""
    global trg, buf
    print('[+] Cracking hash to recover final flag values ...')

    for i in range(9):
        if i == 8: break
    buf_o = buf[12*i:]
    
    trg1, trg2 = gen_trg_values(off)

    smt = z3.Solver()
    fl1 = z3.BitVec(f'fl1', 64)
    fl2 = z3.BitVec(f'fl2', 64)
    fl3 = z3.BitVec(f'fl3', 64)
    fl4 = z3.BitVec(f'fl4', 64)

    smt.add(fl1 & 0xFFFFFFFFFFFF0000 == 0)  # All these are 16-bit values.
    smt.add(fl2 & 0xFFFFFFFFFFFF0000 == 0)
    smt.add(fl3 & 0xFFFFFFFFFFFF0000 == 0)
    smt.add(fl4 & 0xFFFFFFFFFFFF0000 == 0)

    buf01 = WORDB(buf_o)
    buf23 = WORDB(buf_o[2:])
    buf45 = WORDB(buf_o[4:]) 
    buf67 = WORDB(buf_o[6:])
    
    # Make if statement symbolic.
    # r1 from 9-th round.
    r1 = z3.BitVec(f'r1', 64)
    smt.add(r1 &  0xFFFFFFFFFFFF0000 == 0)
    v1 = buf01 * fl1
    y1 = (0x7226 - fl1 - buf01 - 0x7225) & 0xFFFF
    y2 = (((((v1 | (v1 << 32)) >> 16) - v1) >> 16) + 1) & 0xFFFF
    smt.add(r1 == z3.If(v1 == 0, y1, y2))

    # r5 after the for loop.
    r5 = z3.BitVec(f'r5', 64)
    smt.add(r5 &  0xFFFFFFFFFFFF0000 == 0)
    v5 = buf67 * fl4    
    y9 = (1 - fl4 - buf67) & 0xFFFF
    y10 = (((((~(v5 >> 16) & 0x258A1540 | (v5 >> 16) & 0xEABF) ^ 
             (~(v5 << 16) & 0x258A1540 | (v5 << 16) & 0xDA750000)) - v5) >> 16) + 1) & 0xFFFF
    smt.add(r5 == z3.If(v5 == 0, y9, y10))

    # Do the computations using symbolic variables.
    M = (fl3 + buf23) & 0xFFFF
    X = ((~(r1 << 8) & 0x6000 | 0xC0CC0073 | (r1 << 8) & 0x9F00) ^
         (~(r1 >> 8) & 0xC0CC6073 | (r1 >> 8) & 0x8C))
    Y =  ((~((M & (M ^ 0xFFFF0000)) >> 8) & 0xE170 | ((M & (M ^ 0xFFFF0000)) >> 8) & 0x1E8F) ^
          (~((M & (M ^ 0xFFFF0000)) << 8) & 0xE170 | ((M & (M ^ 0xFFFF0000)) << 8) & 0x1E00) | 
         ~(~((M & (M ^ 0xFFFF0000)) << 8)          | ~((M & (M ^ 0xFFFF0000)) >> 8))) << 16
    Z = X & ~(Y & ~trg1 | trg1 & ~Y) | (Y & ~trg1 | trg1 & ~Y) & ~X
    hi_W = (((r5 & (r5 ^ 0xFFFF0000)) << 8) & ((r5 & (r5 ^ 0xFFFF0000)) >> 8) | 
            ((r5 & (r5 ^ 0xFFFF0000)) >> 8) ^ ((r5 & (r5 ^ 0xFFFF0000)) << 8))
    lo_W = _byteswap_ulong((fl2 + buf45) & 0xFFFF)
    W = (hi_W << 32) | lo_W
    Q = (~(W >> 16) & 0x7E3841F4 | (W >> 16) & 0x81C7BE0B) ^ (~trg2 & 0x7E3841F4 | trg2 & 0x81C7BE0B)
    res = (~Z & 0x996215AF | Z & 0x669DEA50) ^ (~Q & 0x996215AF | Q & 0x669DEA50) | ~(~Q | ~Z)

    # Final hash must be 0.
    smt.add(res == 0)

    while smt.check() == z3.sat:
        mdl = smt.model()

        f1 = mdl.evaluate(fl1).as_long()
        f2 = mdl.evaluate(fl2).as_long()
        f3 = mdl.evaluate(fl3).as_long()
        f4 = mdl.evaluate(fl4).as_long()

        print(f'[+] FOUND: fl1:0x{f1:04X}, fl2:0x{f2:04X}, fl3:0x{f3:04X}, fl4:0x{f4:04X}')

        # # Ensure current solution doesn't appear again.
        # smt.add(z3.Or([fl1 != f1, fl2 != f2, fl3 != f3, fl4 != f4]))
        
        return f1, f2, f3, f4
    else:
        raise Exception('Cannot find solution :(')


# ----------------------------------------------------------------------------------------
def crack_round(i, fl1_, fl2_, fl3_, fl4_):
    """Cracks the i-th round of the encryption, using the values `fl1`-`fl4` from the
       previous round. 
    """
    global trg, buf

    print(f'[+] Cracking round {i} to move backwards ...')

    smt = z3.Solver()

    # Get buf values for the given round.
    buf_r = buf[12*(i-1):]

    fl1 = z3.BitVec(f'fl1', 64)
    fl2 = z3.BitVec(f'fl2', 64)
    fl3 = z3.BitVec(f'fl3', 64)
    fl4 = z3.BitVec(f'fl4', 64)

    smt.add(fl1 & 0xFFFFFFFFFFFF0000 == 0)  # All these are 16-bit values.
    smt.add(fl2 & 0xFFFFFFFFFFFF0000 == 0)
    smt.add(fl3 & 0xFFFFFFFFFFFF0000 == 0)
    smt.add(fl4 & 0xFFFFFFFFFFFF0000 == 0)

    # Do the round using the symbolic variables
    r1 = z3.BitVec(f'r1_{i}', 64)
    r2 = z3.BitVec(f'r2_{i}', 64)
    r3 = z3.BitVec(f'r3_{i}', 64)
    r4 = z3.BitVec(f'r4_{i}', 64)
    
    smt.add(r1 &  0xFFFFFFFFFFFF0000 == 0)
    smt.add(r2 &  0xFFFFFFFFFFFF0000 == 0)
    smt.add(r3 &  0xFFFFFFFFFFFF0000 == 0)
    smt.add(r4 &  0xFFFFFFFFFFFF0000 == 0)

    buf01 = WORDB(buf_r)
    v1 = buf01 * fl1
    y1 = (0x7226 - fl1 - buf01 - 0x7225) & 0xFFFF
    y2 = (((((v1 | (v1 << 32)) >> 16) - v1) >> 16) + 1) & 0xFFFF
    smt.add(r1 == z3.If(v1 == 0, y1, y2))

    buf67 = WORDB(buf_r[6:])
    v2 = buf67 * fl4
    y3 = (0xF1F - fl4 - buf67 - 0xF1E) & 0xFFFF
    y4 = (((((~(v2 >> 16) & 0x334DAD1A | (v2 >> 16) & 0x52E5) ^ 
             (~(v2 << 16) & 0x334DAD1A | (v2 << 16) & 0xCCB20000))
                         - v2) >> 16) + 1) & 0xFFFF
    smt.add(r2 == z3.If(v2 == 0, y3, y4))

    buf23 = WORDB(buf_r[2:])
    buf45 = (fl3 + WORDB(buf_r[4:])) & 0xFFFF

    x1 = (~r1 & 0xA212 | r1 & 0x5DED) ^ (~buf45 & 0xA212 | buf45 & 0x5DED)
   
    buf89 = WORDB(buf_r[8:])
    v3 = buf89 * x1
    y5 = (0x493D - x1 - buf89 - 0x493C) & 0xFFFF
    y6 = (((((v3 | (v3 << 32)) >> 16) - v3) >> 16) + 1) & 0xFFFF
    smt.add(r3 == z3.If(v3 == 0, y5, y6))

    bufAB = WORDB(buf_r[10:])
    x0 = (fl2 + buf23) & 0xFFFF
    x2 = (r3 + ((~r2 & 0xFE0E | r2 & 0x1F1) ^ (~x0 & 0xFE0E | x0 & 0x1F1))) & 0xFFFF
    v4 = bufAB * x2 
    x3 = (r3 + ((~r2 & 0xFE0E | r2 & 0x1F1) ^ (~buf23 & 0xFE0E | buf23 & 0x1F1)))
    y7 = (0xB81C - x3 - bufAB + 18405) & 0xFFFF
    y8 = (((((v4 | (v4 << 32)) >> 16) - v4) >> 16) + 1) & 0xFFFF

    smt.add(r4 == z3.If(v4 == 0, y7, y8))

    # Round update.
    H = (r4 + r3) & 0xFFFF
    fl1x = (~r4 & 0x8EC5 | r4 & 0x713A) ^ (~r1 & 0x8EC5 | r1 & 0x713A)
    fl2x = (~r4 & 0xA438 | r4 & 0x5BC7) ^ (~buf45 & 0xA438 | buf45 & 0x5BC7)
    fl3x = ~H & x0 | ~x0 & H
    fl4x = (~H & 0x3E72 | H & 0xC18D) ^ (~r2 & 0x3E72 | r2 & 0xC18D)

    # The final values need to be fl1_, fl2_, fl3_, fl4_. Find the initial ones.
    smt.add(fl1x == fl1_)
    smt.add(fl2x == fl2_)
    smt.add(fl3x == fl3_)
    smt.add(fl4x == fl4_)

    while smt.check() == z3.sat:
        mdl = smt.model()

        f1 = mdl.evaluate(fl1).as_long()
        f2 = mdl.evaluate(fl2).as_long()
        f3 = mdl.evaluate(fl3).as_long()
        f4 = mdl.evaluate(fl4).as_long()

        print(f'[+] FOUND: fl1:0x{f1:04X}, fl2:0x{f2:04X}, fl3:0x{f3:04X}, fl4:0x{f4:04X}')

        # # Ensure current solution doesn't appear again.
        # smt.add(z3.Or([fl1 != f1, fl2 != f2, fl3 != f3, fl4 != f4]))
        
        return f1, f2, f3, f4
    else:
        raise Exception('Cannot find solution :(')


# ----------------------------------------------------------------------------------------
def crack_flag(fl1_, fl2_, fl3_, fl4_):
    """Cracks the inital found values and recovers the original flag value."""
    print('[+] Cracking initial round values to get the flag ...')
    
    smt = z3.Solver()

    # Flag is printable ASCII.
    flag = [z3.BitVec(f'f_{i}', 64) for i in range(8)]   
    for f in flag:
        smt.add(z3.And(f >= 0x20, f <= 0x7f))

    fl1 = (flag[0] << 8) | flag[1]
    fl2 = (~(flag[2] << 8) & 0xE99E | (flag[2] << 8) & 0x1600) ^ (~flag[3] & 0xE99E | flag[3] & 0x61)
    fl3 = (~(flag[4] << 8) & 0x562A | (flag[4] << 8) & 0xA900) ^ (~flag[5] & 0x562A | flag[5] & 0xD5)
    fl4 = (~(flag[6] << 8) & 0x5089 | (flag[6] << 8) & 0xAF00) ^ (~flag[7] & 0x5089 | flag[7] & 0x76)

    smt.add(fl1 == fl1_)
    smt.add(fl2 == fl2_)
    smt.add(fl3 == fl3_)
    smt.add(fl4 == fl4_)

    if smt.check() == z3.sat:
        mdl = smt.model()
        fl = ''.join(chr(mdl.evaluate(f).as_long()) for f in flag)
        print(f'[+] Flag part FOUND: {fl}')

        return fl
    else:
        raise Exception('Cannot find solution :(')


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] J crack started.')
   
    '''
    # Flag starts with 'flag{' so we can quickly brute force the remaining 3.
    for i in range(0x21, 0x7e):
        print(f'[+] Brute Forcing 0x{i:02X} ...')
        for j in range(0x21, 0x7e):
            for k in range(0x21, 0x7e):
                if hash_flag('flag{' + chr(i) + chr(j) + chr(k), off=0, dbg=False) == 0:
                    print('FLAG FOUND: flag{' + chr(i) + chr(j) + chr(k))
                    exit()
                    # flag{3nj
    '''
    print('[+] Testing forward algorithm ...')
    flag = 'ISPOLEET'  # flag = 'flag{3nj'

    encr = hash_flag(flag, 0)
    assert encr == 0xbcfd31b7
    # assert encr == 0

    flag = ''
    # Crack flag 1 part at a time (4 in total).
    for i in range(4):
        print(f'[+] * * * * * Recovering flag part #{i} * * * * *')

        # z3 is too slow if we try to find thei original flag form the final hash (0),
        # so we do it backwards, 1 step at a time.
        a, b, c, d = crack_final(i)
        for j in range(8, 0, -1):  # Crack rounds in reverse order.
            a, b, c, d = crack_round(j, a, b, c, d)

        flag += crack_flag(a, b, c, d)


    print(f'[+] Complete flag: {flag}')

    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop2:~/ctf/0ctf_2020/J$ time ./j_crack.py 
[+] J crack started.
[+] Testing forward algorithm ...
[+] Hashing flag part: 'ISPOLEET' at offset: 0
[+] Initial: fl1:0x4953, fl2:0x504F, fl3:0x4C45, fl4:0x4554
[+] Round 0: fl1:0xBAF8, fl2:0x45F9, fl3:0x3F29, fl4:0xFC82
[+] Round 1: fl1:0x1BE2, fl2:0x313B, fl3:0xF181, fl4:0xD63A
[+] Round 2: fl1:0x5294, fl2:0x536F, fl3:0xD61E, fl4:0xC2E7
[+] Round 3: fl1:0xDF5D, fl2:0x43A6, fl3:0x7631, fl4:0xDD01
[+] Round 4: fl1:0xC8C6, fl2:0x634A, fl3:0xCC9E, fl4:0xE5FC
[+] Round 5: fl1:0x916E, fl2:0xFC12, fl3:0xDCF8, fl4:0xB186
[+] Round 6: fl1:0x088B, fl2:0x026B, fl3:0x4D76, fl4:0xD3E9
[+] Round 7: fl1:0xEAAD, fl2:0x9CED, fl3:0x3C06, fl4:0x7C13
[+] Final Hash: 0xBCFD31B7
[+] * * * * * Recovering flag part #0 * * * * *
[+] Cracking hash to recover final flag values ...
[+] FOUND: fl1:0x70C4, fl2:0x0A0E, fl3:0x549A, fl4:0x2A40
[+] Cracking round 8 to move backwards ...
[+] FOUND: fl1:0x4F8E, fl2:0xDEA3, fl3:0x3F1A, fl4:0xB952
[+] Cracking round 7 to move backwards ...
[+] FOUND: fl1:0xCE97, fl2:0x4FD2, fl3:0x797B, fl4:0x17ED
[+] Cracking round 6 to move backwards ...
[+] FOUND: fl1:0x634F, fl2:0xDE0D, fl3:0xD0C6, fl4:0xF050
[+] Cracking round 5 to move backwards ...
[+] FOUND: fl1:0x3ACC, fl2:0x49E7, fl3:0xE815, fl4:0xCD8D
[+] Cracking round 4 to move backwards ...
[+] FOUND: fl1:0xB5CD, fl2:0xDE25, fl3:0xC72A, fl4:0x31B5
[+] Cracking round 3 to move backwards ...
[+] FOUND: fl1:0xB15C, fl2:0xFB64, fl3:0x8876, fl4:0x6F15
[+] Cracking round 2 to move backwards ...
[+] FOUND: fl1:0xD785, fl2:0x118F, fl3:0x0892, fl4:0xAB1A
[+] Cracking round 1 to move backwards ...
[+] FOUND: fl1:0x666C, fl2:0x6167, fl3:0x7B33, fl4:0x6E6A
[+] Cracking initial round values to get the flag ...
[+] Flag part FOUND: flag{3nj
[+] * * * * * Recovering flag part #1 * * * * *
[+] Cracking hash to recover final flag values ...
[+] FOUND: fl1:0x9BDC, fl2:0x04DB, fl3:0x8640, fl4:0x4B1E
[+] Cracking round 8 to move backwards ...
[+] FOUND: fl1:0xB2D9, fl2:0x30FD, fl3:0x3857, fl4:0xE4A4
[+] Cracking round 7 to move backwards ...
[+] FOUND: fl1:0x2B0F, fl2:0x5082, fl3:0x72F2, fl4:0xAFD7
[+] Cracking round 6 to move backwards ...
[+] FOUND: fl1:0x7635, fl2:0x8936, fl3:0xA77E, fl4:0x0EFE
[+] Cracking round 5 to move backwards ...
[+] FOUND: fl1:0x08FE, fl2:0x8EF8, fl3:0xE91C, fl4:0x6C72
[+] Cracking round 4 to move backwards ...
[+] FOUND: fl1:0xD5B6, fl2:0xB73E, fl3:0x6E83, fl4:0xF7D6
[+] Cracking round 3 to move backwards ...
[+] FOUND: fl1:0x2DF6, fl2:0x819E, fl3:0x620B, fl4:0x49B6
[+] Cracking round 2 to move backwards ...
[+] FOUND: fl1:0x95EC, fl2:0x499D, fl3:0x3AF9, fl4:0xCD1F
[+] Cracking round 1 to move backwards ...
[+] FOUND: fl1:0x3079, fl2:0x5F79, fl3:0x3075, fl4:0x325F
[+] Cracking initial round values to get the flag ...
[+] Flag part FOUND: 0y_y0u2_
[+] * * * * * Recovering flag part #2 * * * * *
[+] Cracking hash to recover final flag values ...
[+] FOUND: fl1:0xEBAC, fl2:0x9E7B, fl3:0xBAFE, fl4:0xA786
[+] Cracking round 8 to move backwards ...
[+] FOUND: fl1:0x4129, fl2:0xEE51, fl3:0x81B9, fl4:0x5AEE
[+] Cracking round 7 to move backwards ...
[+] FOUND: fl1:0x05BA, fl2:0xA943, fl3:0x168A, fl4:0xF594
[+] Cracking round 6 to move backwards ...
[+] FOUND: fl1:0x9549, fl2:0xDAB4, fl3:0x8444, fl4:0x8017
[+] Cracking round 5 to move backwards ...
[+] FOUND: fl1:0x2D09, fl2:0xC33A, fl3:0xC201, fl4:0x3354
[+] Cracking round 4 to move backwards ...
[+] FOUND: fl1:0x8700, fl2:0x36F9, fl3:0x1683, fl4:0x13EA
[+] Cracking round 3 to move backwards ...
[+] FOUND: fl1:0xD622, fl2:0x40AD, fl3:0x328A, fl4:0xC1A8
[+] Cracking round 2 to move backwards ...
[+] FOUND: fl1:0x89BE, fl2:0x134E, fl3:0x6EE3, fl4:0x019F
[+] Cracking round 1 to move backwards ...
[+] FOUND: fl1:0x5233, fl2:0x4131, fl3:0x5F6A, fl4:0x6363
[+] Cracking initial round values to get the flag ...
[+] Flag part FOUND: R3A1_jcc
[+] * * * * * Recovering flag part #3 * * * * *
[+] Cracking hash to recover final flag values ...
[+] FOUND: fl1:0x466F, fl2:0x5D4A, fl3:0xA101, fl4:0x03FB
[+] Cracking round 8 to move backwards ...
[+] FOUND: fl1:0xB2EC, fl2:0x5724, fl3:0x1087, fl4:0xF67F
[+] Cracking round 7 to move backwards ...
[+] FOUND: fl1:0xA432, fl2:0xB12F, fl3:0x8BED, fl4:0x168C
[+] Cracking round 6 to move backwards ...
[+] FOUND: fl1:0x4937, fl2:0x433E, fl3:0x06A0, fl4:0x0DE7
[+] Cracking round 5 to move backwards ...
[+] FOUND: fl1:0x426B, fl2:0x3DAE, fl3:0x3454, fl4:0x9799
[+] Cracking round 4 to move backwards ...
[+] FOUND: fl1:0x9B66, fl2:0x9B41, fl3:0x3ABA, fl4:0x1F34
[+] Cracking round 3 to move backwards ...
[+] FOUND: fl1:0x2FCE, fl2:0x22C1, fl3:0x93FD, fl4:0x75C4
[+] Cracking round 2 to move backwards ...
[+] FOUND: fl1:0x8680, fl2:0x9F03, fl3:0x99E3, fl4:0xD80D
[+] Cracking round 1 to move backwards ...
[+] FOUND: fl1:0x5F30, fl2:0x6333, fl3:0x346E, fl4:0x217D
[+] Cracking initial round values to get the flag ...
[+] Flag part FOUND: _0c34n!}
[+] Complete flag: flag{3nj0y_y0u2_R3A1_jcc_0c34n!}
[+] Program finished. Bye bye :)

real	0m38.941s
user	0m38.880s
sys	0m0.058s
'''
# ----------------------------------------------------------------------------------------

