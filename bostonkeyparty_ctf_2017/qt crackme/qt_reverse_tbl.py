#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
from z3 import *
    
E_trg = [ 
    0x146FC26A, 0x10766B04, 0x2AE5CE6C, 0x2DF5FCE4, 0x2434019A, 0x1F67E99D, 0x4048AA7F, 0x4C26C74C,
    0x16B2964E, 0x13905802, 0x33CF9B5F, 0x2CD5980F, 0x1DFCC164, 0x14A99DA3, 0x2C101662, 0x2BA9DEDB 
]

Cp = [ 
    0x1380, 0x25FA, 0x0CAA, 0x00E2, 0x04E4, 0x56DA, 0x1A61, 0x123F,
    0x2709, 0x0103, 0x0E07, 0x00C0, 0x2035, 0x1531, 0x0020, 0x0DC7 
]

E = [0]*16
C = [0]*16

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":

    s = Solver()

    # we have 16 unknown variables
    Cx = [ BitVec('C%d' % i, 32) for i in range(16)]


    # limit each variable to 16 bits
    for c in Cx:
        s.add( And(c >= 0, c <= 0xffff) )

    # add equations as constraints
    for i in range(0,4):
        for j in range(0,16,4):
            s.add( E_trg[i + j] == Cx[i]*Cp[j] + Cx[i+4]*Cp[j+1] +\
                                   Cx[i+12]*Cp[j+3] + Cx[i+8]*Cp[j+2] )

    # for each valid solution
    while s.check() == sat: 
        print '[+] Valid solution found!'

        m = s.model()

        # extract solution
        i = 0
        for c in Cx: 
            C[i] = m.evaluate(c).as_long()
            i = i + 1

        # print it as a C-like array
        print 'uint C[] = {', ','.join([str(c) for c in C]), '};'

        # make sure that current solution won't appear again
        s.add( Or([c != m.evaluate(c).as_long() for c in Cx ]) )

        # verify that given solution can regenerate E_trg
        for i in range(0,4):
            for j in range(0,16,4):
                E[i + j] = C[i]*Cp[j] + C[i+4]*Cp[j+1] + C[i+12]*Cp[j+3] + C[i+8]*Cp[j+2]

        if cmp(E, E_trg) == 0:
            print '[+] Solution has verified!'

# --------------------------------------------------------------------------------------------------
