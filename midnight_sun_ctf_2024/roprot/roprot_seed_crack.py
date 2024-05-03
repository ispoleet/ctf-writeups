#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Midnight Sun CTF 2024 - roprot (RE 200)
# ----------------------------------------------------------------------------------------
import random
import subprocess
import threading
import capstone
from ctypes import CDLL


valid_seeds = []

 
# ----------------------------------------------------------------------------------------
# Forward algorithm
# ----------------------------------------------------------------------------------------
def hash_license_key(lic_key):
    """Computes the 16-bit mini hash from license key."""
    chksum = 0

    for k in lic_key:
        if k >= ord('0') and k <= ord('9'):
            c = k - 0x30
        elif k >= ord('A') and k <= ord('Z'):
            c = k - 0x37
        else:
            continue  # Skip '-'
            
        chksum  = 36*chksum + c  # Base 36
        chksum &= 0xFFFFFFFFFFFFFFFF

    seed = (chksum >> 32) ^ (chksum & 0xFFFFFFFF)
    # If mini hash ss 0x2cc2, then license key is correct.
    return compute_minihash(seed)


def compute_minihash(num):
    """Computes the mini hash of a 32-bit number."""
    chksum = 0xFFFF
    for n in num.to_bytes(4, 'little'):
        chksum ^= n << 8
        chksum &= 0xFFFF

        for j in range(8):  # A Galois Field multiplication.
            if (chksum & 0x8000) == 0:
                chksum *= 2
            else:
                chksum = (2 * chksum) ^ 0x1021

        chksum &= 0xFFFF

    return chksum


# ----------------------------------------------------------------------------------------
# Crack checksum
# ----------------------------------------------------------------------------------------
def run_roprot_tool(seed, gadget, exp_addr):[+] List of valid seeds: 
    """Runs roprot tool to find ROP gadgets in the random blob."""
    # NOTE: This is too slow. We can patch the binary produce to generate only 0x1000
    # random numbers, but it's still too slow.
    proc = subprocess.Popen(['./tool', '-s', f'{seed}', 'find', gadget],
                            stdout=subprocess.PIPE)
    for line in proc.stdout.read().splitlines():
        if exp_addr in line:
            print(f'[+] Gadget {gadget} found at {exp_addr} using seed 0x{seed:08X}')
            return True 

    return False


def generate_rand_blob(seed):
    """Generates a random blob using C's srand() and rand()."""
    blob = []
    '''
    # NOTE: This is **not** thread safe, so we will do a workaround.
    libc = CDLL("libc.so.6")
    libc.srand(seed)

    for i in range(0x570 // 4):
        rand = libc.rand()
        
        blob.append(rand & 0xFF)
        blob.append((rand >> 8)  & 0xFF)
        blob.append((rand >> 16) & 0xFF)
        blob.append((rand >> 24) & 0xFF)
    '''
    # Just run the rand binary and collect the results.
    proc = subprocess.Popen(['./rand', f'{seed}'], stdout=subprocess.PIPE)
    for line in proc.stdout.read().splitlines():
        blob.append(int(line.strip(), 16))

    return blob


def try_disasm(buf):
    """Tries to disassemble a buffer."""    
    asm = ''
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for insn in md.disasm(bytes(buf), 0x0):
        asm += f'{insn.mnemonic}'
        if insn.op_str:
            asm += f' {insn.op_str};'

        if 'ret' == insn.mnemonic:
            break
    return asm


def thread_routine(name, offset):
    """Thread routine that brute forces a given range of seeds."""
    for seed in range(0x10000000*offset, 0x10000000*(offset + 1)):
        if compute_minihash(seed) == 0x2cc2:
            print(f'[+] Valid mini hash found for seed: {seed:08X}')

            # Approach #1 (DOES NOT WORK)
            #
            # Check for the following gadgets at address 0x54b:
            #   * `endbr64` opcode: F3-0F-1E-FA
            #   * `push rbp; mov rsp, rbp` opcodes: 55-48-89-EC
            # if run_roprot_tool(seed, '55-48-89-EC', b'0x0000054b'):
            # #if run_roprot_tool(seed, 'F3-0F-1E-FA', b'0x0000054b'):
            #     print(f'[+] Seed FOUND: {seed:08X}')

            # Approach #2 (CORRECT)
            # Try to disassemble the blob and check if offsets 0x54B and 0x24A
            # contain valid gadgets (end with a ret instruction).
            blob = generate_rand_blob(seed)

            asm1 = try_disasm(blob[0x54B:])
            asm2 = try_disasm(blob[0x24A:])

            if asm1.endswith('ret') and asm2.endswith('ret'):
                print(f'[+] Gadgets FOUND for seed 0x{seed:08X}')
                print(f'[+]   0x54B: {asm1}')
                print(f'[+]   0x24A: {asm2}')
                global valid_seeds
                valid_seeds.append(seed)


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] roprot seed crack started.')

    # Testing area:
    lic_key = b'AAAA-BBBB-CCCC-DDDD'
    print(f'[+] Test: mini hash of {lic_key} ~> 0x{hash_license_key(lic_key):04X}')

    # run_roprot_tool(31337, '11-22-33-44', b'0x0754fa0c')
    # print(generate_rand_blob(31337))

    # Brute force using 16 threads.
    thread_pool = []
    for i in range(16):
        thread_pool.append(
            threading.Thread(target=thread_routine, name=f'tid_{i}', args=(0,), kwargs={'offset':i})
        )

    for thread in thread_pool:
        thread.start()

    for thread in thread_pool:
        thread.join()

    print(f'[+] List of valid seeds: {valid_seeds}')


# ----------------------------------------------------------------------------------------
r"""
┌─[11:49:26]─[ispo@ispo-glaptop2]─[~/ctf/midnight_sun_ctf_2024/roprot]
└──> ./roprot_crack.py 
[+] roprot crack started.
[+] Test: mini hash of b'AAAA-BBBB-CCCC-DDDD' ~> 0xFA44
[+] Valid mini hash found for seed: 100011F7
[+] Valid mini hash found for seed: 000028B1
[+] Valid mini hash found for seed: 20005A3D
[+] Valid mini hash found for seed: D0005EEE
[+] Valid mini hash found for seed: C00067A8
[+] Valid mini hash found for seed: 3000637B
[+] Valid mini hash found for seed: E0001524
[+] Valid mini hash found for seed: 60009F35
[+] Valid mini hash found for seed: 7000A673
[+] Valid mini hash found for seed: 90009BE6
[+] Valid mini hash found for seed: 5000D4FF
[+] Valid mini hash found for seed: F0002C62
[+] Valid mini hash found for seed: 4000EDB9
[+] Valid mini hash found for seed: 100105D4
[+] Valid mini hash found for seed: B000E96A
[+] Valid mini hash found for seed: A000D02C
[+] Valid mini hash found for seed: 8000A2A0
[.....]
[+] Valid mini hash found for seed: 9013A592
[+] Valid mini hash found for seed: E015539A
[+] Valid mini hash found for seed: C018E4B1
[+] Gadgets FOUND for seed 0x201408A0
[+]   0x54B: ret
[+]   0x24A: ret
[+] Valid mini hash found for seed: 40169762
[+] Valid mini hash found for seed: 8016D87B
[+] Valid mini hash found for seed: 10166B2C
[+] Valid mini hash found for seed: 5012FEA8
[.....]
[+] Valid mini hash found for seed: 6B620509
[+] Valid mini hash found for seed: FB7C4D8D
[+] Valid mini hash found for seed: AB606256
[+] Gadgets FOUND for seed 0x7B71023B
[+] Valid mini hash found for seed: DB4E1174
[+]   0x54B: pop rdi;ret
[+]   0x24A: ret
[+] Valid mini hash found for seed: 8B155A02
[+] Valid mini hash found for seed: 9B5207E9
[+] Valid mini hash found for seed: 5B49F78C
[+] Valid mini hash found for seed: 1B4E5E6D
[+] Valid mini hash found for seed: 3B46ADE9
[+] Valid mini hash found for seed: CB5F3E00
[+] Valid mini hash found for seed: 2B6A4109
[.....]
[+] Valid mini hash found for seed: 8FF7E8FF
[+] Valid mini hash found for seed: 8FF8051E
[+] Valid mini hash found for seed: 8FF9113D
[+] Valid mini hash found for seed: 8FFA2D58
[+] Valid mini hash found for seed: 8FFB397B
[+] Valid mini hash found for seed: 8FFC5592
[+] Valid mini hash found for seed: 8FFD41B1
[+] Valid mini hash found for seed: 8FFE7DD4
[+] Valid mini hash found for seed: 8FFF69F7
[+] List of valid seeds: [538183840, 1345518218, 2973588323, 2438371556, 562022454, 2984624310, 1125593590, 1395313444, 3819725501, 2760119933, 1685967536, 1956841705, 2494143538, 899781690, 3877712327, 2008972776, 933641209, 1475285266, 411045332, 4190440759, 445902986, 2326450373, 2071003707, 2333784035, 194363547, 1004420728, 1821095982, 3435999293, 1562580955, 1301982477, 1304361379, 3461275642]
"""
# ----------------------------------------------------------------------------------------

