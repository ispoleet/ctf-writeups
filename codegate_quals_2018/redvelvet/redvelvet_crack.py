#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Codegate CTF 2018 - RedValvet (RE 216)
# --------------------------------------------------------------------------------------------------
from z3 import *
import hashlib


# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":

    X = [BitVec('x%d' % i, 16) for i in range(26) ]


    # Add the contraints for each function. Each of the functions 1-5 check 2 characters,
    # while functions 6-15 check 3. The last character of each function is passed to the
    # next function
    #
    # TODO: Add more.
    constraints = [
        # -------------------------------------------------------------------------
        # int __fastcall func1(char a1, char a2)
        # {
        #   if ( a1 * 2 * (char)(a2 ^ a1) - a2 != 10858 )
        #     exit(1);
        #   if ( a1 <= 85 || a1 > 95 || a2 <= 96 || a2 > 111 )
        #     exit(1);
        #   return puts("HAPPINESS:)");
        # }
        2 * X[0] * (X[0] ^ X[1]) - X[1] == 10858, X[0] > 85, X[0] < 94, X[1] > 96, X[1] < 111,
        

        # -------------------------------------------------------------------------
        # int __fastcall func2(char a1, char a2)
        # {
        #   if ( a1 % a2 != 7 )
        #     exit(1);
        #   if ( a2 <= 90 )
        #     exit(1);
        #   return puts("HAPPINESS:)");
        # }
        X[1] % X[2] == 7, X[2] > 90,


        # -------------------------------------------------------------------------
        # int __fastcall func3(char a1, char a2)
        # {
        #   if ( a1 / a2 + (char)(a2 ^ a1) != 21 || a1 > 99 || a2 > 119 )
        #     exit(1);
        #   return puts("HAPPINESS:)");
        # }
        X[2] / X[3] + X[2] ^ X[3] == 21, X[2] < 100, X[3] < 120,


        # -------------------------------------------------------------------------
        # int __fastcall func4(char a1, char a2)
        # {
        #   signed __int64 v2; // rtt@1
        # 
        #   LODWORD(v2) = (char)(a2 ^ a1 ^ a2);
        #   HIDWORD(v2) = (unsigned __int64)(char)(a2 ^ a1 ^ a2) >> 32;
        #   if ( (unsigned int)(v2 % a2) + a1 != 137 || a1 <= 115 || a2 > 99 || a2 != 95 )
        #     exit(1);
        #   return puts("HAPPINESS:)");
        # }
        X[3] % X[4] + X[3] == 137, X[3] > 115, X[4] == 95,


        # -------------------------------------------------------------------------
        # int __fastcall func5(char a1, char a2)
        # {
        #   if ( ((a2 + a1) ^ (char)(a1 ^ a2 ^ a1)) != 225 || a1 <= 90 || a2 > 89 )
        #     exit(1);
        #   return puts("HAPPINESS:)");
        # }
        (X[4]+ X[5]) ^ X[5] == 225, X[4] > 90, X[5] <= 89,


        # -------------------------------------------------------------------------
        # int __fastcall func6(char a1, char a2, char a3)
        # {
        #   if ( a1 > a2 )
        #     exit(1);
        #   if ( a2 > a3 )
        #     exit(1);
        #   if ( a1 <= 85 || a2 <= 110 || a3 <= 115 || ((a2 + a3) ^ (a1 + a2)) != 44 || 
        #        (a2 + a3) % a1 + a2 != 161 )
        #     exit(1);
        #   return puts("HAPPINESS:)");
        # }
        X[5] <= X[6], X[6] <= X[7], X[5] > 85, X[6] > 110, X[7] > 115,
        ((X[6] + X[7]) ^ (X[5] + X[6])) == 44,
        (X[6] + X[7]) % X[5] + X[6] == 161,


        # -------------------------------------------------------------------------
        # int __fastcall func7(char a1, char a2, char a3)
        # {
        #   if ( a1 < a2 )
        #     exit(1);
        #   if ( a2 < a3 )
        #     exit(1);
        #   if ( a1 > 119 || a2 <= 90 || a3 > 89 || ((a1 + a3) ^ (a2 + a3)) != 122 ||
        #        (a1 + a3) % a2 + a3 != 101 )
        #     exit(1);
        #   return puts("HAPPINESS:)");
        # }
        X[7] >= X[8], X[8] >= X[9], X[7] <= 119, X[8] > 90, X[9] <= 89,
        (X[7] + X[9]) ^ (X[8] + X[9]) == 122,
        (X[7] + X[9]) % X[8] + X[9] == 101,


        # -------------------------------------------------------------------------
        # int __fastcall func8(char a1, char a2, char a3)
        # {
        #   if ( a1 > a2 )
        #     exit(1);
        #   if ( a2 > a3 )
        #     exit(1);
        #   if ( a3 > 114 || (a1 + a2) / a3 * a2 != 97 || (a3 ^ (a1 - a2)) * a2 != -10088 || a3 > 114 )
        #     exit(1);
        #   return puts("HAPPINESS:)");
        # }
        X[9] <= X[10], X[10] <= X[11],
        X[11] <= 114,
        (X[9] + X[10]) / X[11] * X[10] == 97,
        (X[11] ^ (X[9] - X[10])) * X[10] == -10088,


        # -------------------------------------------------------------------------
        # int __fastcall func9(char a1, char a2, char a3)
        # {
        #   if ( a1 != a2 )
        #     exit(1);
        #   if ( a2 < a3 )
        #     exit(1);
        #   if ( a3 > 99 || a3 + a1 * (a3 - a2) - a1 != -1443 )
        #     exit(1);
        #   return puts("HAPPINESS:)");
        # }
        X[11] == X[12], X[12] >= X[13], X[13] <= 99,
        X[13] + X[11]*(X[13] - X[12]) - X[11] == -1443,


        # -------------------------------------------------------------------------
        # int __fastcall func10(char a1, char a2, char a3)
        # {
        #   if ( a1 < a2 )
        #     exit(1);
        #   if ( a2 < a3 )
        #     exit(1);
        #   if ( a2 * (a1 + a3 + 1) - a3 != 15514 || a2 <= 90 || a2 > 99 )
        #     exit(1);
        #   return puts("HAPPINESS:)");
        # }        
        X[13] >= X[14], X[14] >= X[15], X[14] >= 90, X[14] <= 99,
        X[14] * (X[13] + X[15] + 1) - X[15] == 15514,
        

        # -------------------------------------------------------------------------
        # int __fastcall func11(char a1, char a2, char a3)
        # {
        #   if ( a2 < a1 )
        #     exit(1);
        #   if ( a1 < a3 )
        #     exit(1);
        #   if ( a2 <= 100 || a2 > 104 || a1 + (a2 ^ (a2 - a3)) - a3 != 70 || (a2 + a3) / a1 + a1 != 68 )
        #     exit(1);
        #   return puts("HAPPINESS:)");
        # }
        X[16] >= X[15], X[15] >= X[17], X[16] > 100, X[16] <= 104,
        X[15] + (X[16] ^ (X[16] - X[17])) - X[17] == 70,
        (X[16] + X[17]) / X[15] + X[15] == 68,

        # -------------------------------------------------------------------------
        # int __fastcall func12(char a1, char a2, char a3)
        # {
        #   if ( a1 < a2 )
        #     exit(1);
        #   if ( a2 < a3 )
        #     exit(1);
        #   if ( a2 > 59 || a3 > 44 || a1 + (a2 ^ (a3 + a2)) - a3 != 111 || (a2 ^ (a2 - a3)) + a2 != 101 )
        #     exit(1);
        #   return puts("HAPPINESS:)");
        # }
        X[17] >= X[18], X[18] >= X[19], X[18] <= 59, X[19] <= 44,
        X[17] + (X[18] ^ (X[19] + X[18])) - X[19] == 111,
        (X[18] ^ (X[18] - X[19])) + X[18] == 101,


        # -------------------------------------------------------------------------
        # int __fastcall func13(char a1, char a2, char a3)
        # {
        #   if ( a1 > a2 )
        #     exit(1);
        #   if ( a2 > a3 )
        #     exit(1);
        #   if ( a1 <= 40 || a2 <= 90 || a3 > 109 || a3 + (a2 ^ (a3 + a1)) - a1 != 269 ||
        #        (a3 ^ (a2 - a1)) + a2 != 185 )
        #     exit(1);
        #   return puts("HAPPINESS:)");
        # }
        X[19] <= X[20], X[20] <= X[21], X[19] > 40, X[20] > 90,X[21] <= 109,
        X[21] + (X[20] ^ (X[21] + X[19])) - X[19] == 269,
        (X[21] ^ (X[20] - X[19])) + X[20] == 185,


        # -------------------------------------------------------------------------
        # int __fastcall func14(char a1, char a2, char a3)
        # {
        #   if ( a1 < a3 )
        #     exit(1);
        #   if ( a2 < a3 )
        #     exit(1);
        #   if ( a2 > 99 || a3 <= 90 || a1 + (a2 ^ (a2 + a1)) - a3 != 185 )
        #     exit(1);
        #   return puts("HAPPINESS:)");
        # }
        X[21] >= X[23], X[22] >= X[23], X[22] <= 99, X[23] > 90,
        X[21] + (X[22] ^ (X[22] + X[21])) - X[23] == 185,


        # -------------------------------------------------------------------------
        # int __fastcall func15(char a1, char a2, char a3)
        # {
        #   if ( a2 < a3 )
        #     exit(1);
        #   if ( a2 < a1 )
        #     exit(1);
        #   if ( a3 <= 95 || a2 > 109 || ((a2 - a1) * a2 ^ a3) - a1 != 1214 || 
        #        ((a3 - a2) * a3 ^ a1) + a2 != -1034 )
        #     exit(1);
        #   return puts("HAPPINESS:)");
        # }    
        X[24] >= X[25], X[24] >= X[23], X[25] > 95, X[24] <= 109,
        ((X[24] - X[23]) * X[24] ^ X[25]) - X[23] == 1214,
        ((X[25] - X[24])*X[25] ^ X[23]) + X[24] == -1034,
    ]


    s = Solver()
   
    s.add([And(x >= 0x20, x <= 0x7e) for x in X])   # make sure that flag is printable

    for c in constraints:                           # add all the constraints
        s.add( c )


    while s.check() == sat: 

        m = s.model()

        sol  = [m.evaluate(x).as_long() for x in X] # get solution 
        flag = ''.join([chr(x) for x in sol])       # convert it to flag


        print '[+] Solution found:', flag


        sha256 = hashlib.sha256()                           # verify checksum
        sha256.update(flag)
        if sha256.hexdigest() == '0a435f46288bb5a764d13fca6c901d3750cee73fd7689ce79ef6dc0ff8f380e5':
            print '[+] This is the flag!!!'
            exit()


        
        s.add( Or([x != m.evaluate(x).as_long() for x in X]) )

# --------------------------------------------------------------------------------------------------
'''
ispo@nogirl:~/ctf/2018/codegate_ctf$ ./redvelvet_crack.py 
    [+] Solution found: What_You_Wanna_Be?:)_lc_la
    [+] Solution found: What_You_Wanna_Be?:)_l`_la
    [+] Solution found: What_You_Wanna_Be?:)_lb_la
    [+] Solution found: What_You_Wanna_Be?:)_la_la
    [+] This is the flag!!!


ispo@nogirl:~/ctf/2018/codegate_ctf$ ./RedVelvet 
    Your flag : What_You_Wanna_Be?:)_la_la
    HAPPINESS:)
    HAPPINESS:)
    HAPPINESS:)
    HAPPINESS:)
    HAPPINESS:)
    HAPPINESS:)
    HAPPINESS:)
    HAPPINESS:)
    HAPPINESS:)
    HAPPINESS:)
    HAPPINESS:)
    HAPPINESS:)
    HAPPINESS:)
    HAPPINESS:)
    HAPPINESS:)
    flag : {" What_You_Wanna_Be?:)_la_la "}
'''
# --------------------------------------------------------------------------------------------------
