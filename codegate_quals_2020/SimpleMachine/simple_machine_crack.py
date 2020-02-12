#!/usr/bin/env python2
# -------------------------------------------------------------------------------------------------
# Codegate CTF 2020 Preliminary - Simple Machine (RE 333)
#
# NOTE: Perf requires sudo. Run as: `sudo time ./simple_machine_crack.py`
# -------------------------------------------------------------------------------------------------
import struct
import sys
import os
import subprocess
  
# -------------------------------------------------------------------------------------------------
# Count the number of instruction in the binary using a given input.
def count_insn(flag, c1, c2):
    proc = subprocess.Popen('perf stat -e instructions:u ./simple_machine target',
                shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    proc.stdin.write(flag + c1 + c2)

    # Performance report is printed to stderr and it looks like this:
    #
    #   Performance counter stats for './simple_machine target':
    #
    #         2,229,884      instructions:u                                              
    #
    #       5.652137451 seconds time elapsed
    #
    #       0.004624000 seconds user
    #       0.000000000 seconds sys
    #
    # We care about the number of instructions: 2,229,884
    for line in proc.stderr:
        if line.find('instructions:u') > 0:
            num = line.split()[0]
            num = num.replace(',', '')
            return int(num)


# -------------------------------------------------------------------------------------------------
def brute_force_word(flag, key1=None, key2=None):   
    charset = 'abcdefghijklmnopqrstuvwxyz_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

    # If c1 is know don't bruteforce it
    charset_1 = charset if not key1 else key1
    charset_2 = charset if not key2 else key2


    # Knowing the initial number of instructions executed is challenging (bootstrapping program). 
    # A quick trick is to always start with a dummy character ('~') that we know (hope) it's not
    # part of the flag, just to initialize max_ctr first.
    max_ctr = count_insn(flag, '~', '~')

    print '[+] Initial Counter Value: %d' % max_ctr

    i = 0
    for c1, c2 in [(c1, c2) for c1 in charset_1 for c2 in charset_2]:
        insn_ctr = count_insn(flag, c1, c2)
        
        print "[+] %5d Instruction Count: %d. Trying '%c%c' Flag: '%s'" % (i, insn_ctr, c1, c2, flag)

        # We may have noise. If insn_ctr slightly bigger than max_ctr doesn't mean we
        # found the word. We need one more iteration which should be ~1000 instructions.
        if insn_ctr > max_ctr + 100:
            print "[+]\tWord found! (%d > %d): '%c%c'" % (max_ctr, insn_ctr, c1, c2)

            return c1, c2

        i += 1


# -------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    print '[+] Simple machine side channel attack started.'

    # We know how the flag starts.
    flag = 'CODEGATE2020'
    key1, key2 = brute_force_word(flag, key1='{')

    flag += key1 + key2

    print "[+] Flag so far: '%s'" % flag

    # Brute force each word
    while len(flag) < 0x22:
        key1, key2 = brute_force_word(flag)
        flag += key1 + key2

        print "[+] Flag so far: '%s'" % flag

    
    # We know how the flag ends.
    key1, key2 = brute_force_word(flag, key2='}')
    flag += key1 + key2

    print "[+] Final flag: '%s'" % flag
    print '[+] Program finished successfully. Bye bye :)'

# -------------------------------------------------------------------------------------------------
'''
ispo@leet:~/ctf/codegate_2020/SimpleMachine$ sudo time ./simple_machine_crack.py 
[sudo] password for ispo: 
[+] Simple machine side channel attack started.
[+] Initial Counter Value: 2238687
[+]     0 Instruction Count: 2238686. Trying '{a' Flag: 'CODEGATE2020'
[+]     1 Instruction Count: 2238687. Trying '{b' Flag: 'CODEGATE2020'
[+]     2 Instruction Count: 2238686. Trying '{c' Flag: 'CODEGATE2020'
[+]     3 Instruction Count: 2238687. Trying '{d' Flag: 'CODEGATE2020'
[+]     4 Instruction Count: 2241950. Trying '{e' Flag: 'CODEGATE2020'
[+] Word found! (2238687 > 2241950): '{e'
[+] Flag so far: 'CODEGATE2020{e'
[+] Initial Counter Value: 2241949
[+]     0 Instruction Count: 2241949. Trying 'aa' Flag: 'CODEGATE2020{e'
[+]     1 Instruction Count: 2241949. Trying 'ab' Flag: 'CODEGATE2020{e'
....
[+]  1589 Instruction Count: 2241950. Trying 'zo' Flag: 'CODEGATE2020{e'
[+]  1590 Instruction Count: 2245214. Trying 'zp' Flag: 'CODEGATE2020{e'
[+] Word found! (2241949 > 2245214): 'zp'
[+] Flag so far: 'CODEGATE2020{ezp'
[+] Initial Counter Value: 2245213
[+]     0 Instruction Count: 2245213. Trying 'aa' Flag: 'CODEGATE2020{ezp'
[+]     1 Instruction Count: 2245213. Trying 'ab' Flag: 'CODEGATE2020{ezp'
....
[+]  1600 Instruction Count: 2245212. Trying 'zz' Flag: 'CODEGATE2020{ezp'
[+]  1601 Instruction Count: 2248476. Trying 'z_' Flag: 'CODEGATE2020{ezp'
[+] Word found! (2245213 > 2248476): 'z_'
[+] Flag so far: 'CODEGATE2020{ezpz_'
[+] Initial Counter Value: 2248475
[+]     0 Instruction Count: 2248476. Trying 'aa' Flag: 'CODEGATE2020{ezpz_'
[+]     1 Instruction Count: 2248476. Trying 'ab' Flag: 'CODEGATE2020{ezpz_'
....
[+]    82 Instruction Count: 2248475. Trying 'bt' Flag: 'CODEGATE2020{ezpz_'
[+]    83 Instruction Count: 2251739. Trying 'bu' Flag: 'CODEGATE2020{ezpz_'
[+] Word found! (2248475 > 2251739): 'bu'
[+] Flag so far: 'CODEGATE2020{ezpz_bu'
[+] Initial Counter Value: 2251740
[+]     0 Instruction Count: 2251738. Trying 'aa' Flag: 'CODEGATE2020{ezpz_bu'
[+]     1 Instruction Count: 2251739. Trying 'ab' Flag: 'CODEGATE2020{ezpz_bu'
[+]   
....
[+]  1222 Instruction Count: 2251738. Trying 'tz' Flag: 'CODEGATE2020{ezpz_bu'
[+]  1223 Instruction Count: 2255001. Trying 't_' Flag: 'CODEGATE2020{ezpz_bu'
[+] Word found! (2251740 > 2255001): 't_'
[+] Flag so far: 'CODEGATE2020{ezpz_but_'
[+] Initial Counter Value: 2255001
[+]     0 Instruction Count: 2255001. Trying 'aa' Flag: 'CODEGATE2020{ezpz_but_'
[+]     1 Instruction Count: 2255001. Trying 'ab' Flag: 'CODEGATE2020{ezpz_but_'
....
[+]  3420 Instruction Count: 2255001. Trying '1s' Flag: 'CODEGATE2020{ezpz_but_'
[+]  3421 Instruction Count: 2258264. Trying '1t' Flag: 'CODEGATE2020{ezpz_but_'
[+] Word found! (2255001 > 2258264): '1t'
[+] Flag so far: 'CODEGATE2020{ezpz_but_1t'
[+] Initial Counter Value: 2258264
[+]     0 Instruction Count: 2258264. Trying 'aa' Flag: 'CODEGATE2020{ezpz_but_1t'
[+]     1 Instruction Count: 2258264. Trying 'ab' Flag: 'CODEGATE2020{ezpz_but_1t'
....
[+]  1691 Instruction Count: 2258265. Trying '_0' Flag: 'CODEGATE2020{ezpz_but_1t'
[+]  1692 Instruction Count: 2261527. Trying '_1' Flag: 'CODEGATE2020{ezpz_but_1t'
[+] Word found! (2258266 > 2261527): '_1'
[+] Flag so far: 'CODEGATE2020{ezpz_but_1t_1'
[+] Initial Counter Value: 2261528
[+]     0 Instruction Count: 2261529. Trying 'aa' Flag: 'CODEGATE2020{ezpz_but_1t_1'
[+]     1 Instruction Count: 2261530. Trying 'ab' Flag: 'CODEGATE2020{ezpz_but_1t_1'
....
[+]  1159 Instruction Count: 2261527. Trying 'sz' Flag: 'CODEGATE2020{ezpz_but_1t_1'
[+]  1160 Instruction Count: 2264793. Trying 's_' Flag: 'CODEGATE2020{ezpz_but_1t_1'
[+] Word found! (2261528 > 2264793): 's_'
[+] Flag so far: 'CODEGATE2020{ezpz_but_1t_1s_'
[+] Initial Counter Value: 2264794
[+]     0 Instruction Count: 2264793. Trying 'aa' Flag: 'CODEGATE2020{ezpz_but_1t_1s_'
[+]     1 Instruction Count: 2264790. Trying 'ab' Flag: 'CODEGATE2020{ezpz_but_1t_1s_'
....
[+]   961 Instruction Count: 2264794. Trying 'pq' Flag: 'CODEGATE2020{ezpz_but_1t_1s_'
[+]   962 Instruction Count: 2268054. Trying 'pr' Flag: 'CODEGATE2020{ezpz_but_1t_1s_'
[+] Word found! (2264794 > 2268054): 'pr'
[+] Flag so far: 'CODEGATE2020{ezpz_but_1t_1s_pr'
[+] Initial Counter Value: 2268054
[+]     0 Instruction Count: 2268056. Trying 'aa' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr'
[+]     1 Instruction Count: 2268053. Trying 'ab' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr'
....
[+]  3546 Instruction Count: 2268055. Trying '3s' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr'
[+]  3547 Instruction Count: 2271318. Trying '3t' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr'
[+] Word found! (2268054 > 2271318): '3t'
[+] Flag so far: 'CODEGATE2020{ezpz_but_1t_1s_pr3t'
[+] Initial Counter Value: 2271319
[+]     0 Instruction Count: 2271316. Trying 'aa' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t'
[+]     1 Instruction Count: 2271316. Trying 'ab' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t'
....
[+]  3550 Instruction Count: 2271316. Trying '3w' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t'
[+]  3551 Instruction Count: 2274579. Trying '3x' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t'
[+] Word found! (2271319 > 2274579): '3x'
[+] Flag so far: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3x'
[+] Initial Counter Value: 2274579
[+]     0 Instruction Count: 2274579. Trying 'a}' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3x'
[+]     1 Instruction Count: 2274580. Trying 'b}' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3x'
[+]     2 Instruction Count: 2274579. Trying 'c}' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3x'
[+]     3 Instruction Count: 2274580. Trying 'd}' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3x'
[+]     4 Instruction Count: 2274580. Trying 'e}' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3x'
[+]     5 Instruction Count: 2274580. Trying 'f}' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3x'
[+]     6 Instruction Count: 2274579. Trying 'g}' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3x'
[+]     7 Instruction Count: 2274580. Trying 'h}' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3x'
[+]     8 Instruction Count: 2274580. Trying 'i}' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3x'
[+]     9 Instruction Count: 2274579. Trying 'j}' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3x'
[+]    10 Instruction Count: 2274579. Trying 'k}' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3x'
[+]    11 Instruction Count: 2274579. Trying 'l}' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3x'
[+]    12 Instruction Count: 2274579. Trying 'm}' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3x'
[+]    13 Instruction Count: 2274579. Trying 'n}' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3x'
[+]    14 Instruction Count: 2274579. Trying 'o}' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3x'
[+]    15 Instruction Count: 2274581. Trying 'p}' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3x'
[+]    16 Instruction Count: 2274581. Trying 'q}' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3x'
[+]    17 Instruction Count: 2274580. Trying 'r}' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3x'
[+]    18 Instruction Count: 2274580. Trying 's}' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3x'
[+]    19 Instruction Count: 2275943. Trying 't}' Flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3x'
[+] Word found! (2274579 > 2275943): 't}'
[+] Final flag: 'CODEGATE2020{ezpz_but_1t_1s_pr3t3xt}'
[+] Program finished successfully. Bye bye :)
837.19user 1674.93system 43:47.17elapsed 95%CPU (0avgtext+0avgdata 9312maxresident)k
0inputs+0outputs (0major+30424779minor)pagefaults 0swaps

ispo@leet:~/ctf/codegate_2020/SimpleMachine$ ./simple_machine target
    CODEGATE2020{ezpz_but_1t_1s_pr3t3xt}
    GOOD!
'''
# -------------------------------------------------------------------------------------------------
