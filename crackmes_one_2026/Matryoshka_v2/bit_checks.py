#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Crackmes One CTF 2026 - Matryoshka v2 - (Hard - 912)
#
# This module performs a symbolic execution on the (deobfuscated) shellcode to
# extract the encrypted license block from the bit checks.
# ----------------------------------------------------------------------------------------
import angr
import claripy
from angr.sim_type import parse_type

BASE_ADDR    = 0x100000 
ENTRY_POINT  = BASE_ADDR + 0x0    # Entry point (sub_0)
FEISTEL_ADDR = BASE_ADDR + 0x166  # Feistel network (sub_166)
GOODBOY_ADDR = BASE_ADDR + 0x125  # Goodboy address: mov al, 1
BADBOY_ADDR  = BASE_ADDR + 0x130  # Badboy  address: xor al, al


# ----------------------------------------------------------------------------------------
class _FakeFeistel(angr.SimProcedure):
    def run(self, a1, a2, a3, a4):
        """Every time sub_166 is called, return a 64-bit sym var."""
        call_idx = self.state.globals.get('sub166_calls', 0)
        sym_val = claripy.BVS(f'buf_val_{call_idx}', 64)
                
        if 'sym_bufs' not in self.state.globals:
            self.state.globals['sym_bufs'] = []
        
        self.state.globals['sym_bufs'].append(sym_val)
        self.state.globals['sub166_calls'] = call_idx + 1

        return sym_val


# ----------------------------------------------------------------------------------------
def recover_ciphertext_from_bit_checks(SHELLCODE_PATH):
    print('[+] Loading shellcode into angr ...')
    project = angr.Project(
        SHELLCODE_PATH, 
        main_opts={
            'backend'    : 'blob', 
            'arch'       : 'x86_64', 
            'base_addr'  : BASE_ADDR,
            'entry_point': ENTRY_POINT
        },
        auto_load_libs=False)

    project.hook(FEISTEL_ADDR, _FakeFeistel())  # Add hook to bypass Feistel network.

    # Setup the State.
    LICENSE_ADDR = 0x200000   # Where to store dummy license block.
    
    clean_options = {  # zero-fill uninitialized registers.
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
    }

    # Initialize the state with the C prototype for entry point:
    #   bool __fastcall sub_0(__int64 a1, __int64 a2, __int64 a3, _BYTE *a4, int a5, int a6)
    state = project.factory.call_state(
        ENTRY_POINT, 
        0, 0, 0, LICENSE_ADDR, 0, 0, 
        add_options=clean_options,
        prototype=parse_type('int (long long, long long, long long, char*, int, int)')
    )

    # Write a dummy license to pass the `if lic_len != 32` check.
    state.memory.store(LICENSE_ADDR, b'?'*32)
    
    # Create the simulation manager.
    print(f'[+] Exploring for goodboy address: 0x{GOODBOY_ADDR:08X} ...')
    simgr = project.factory.simgr(state)
    simgr.explore(find=GOODBOY_ADDR, avoid=BADBOY_ADDR)

    if simgr.found:        
        found_state = simgr.found[0]
        print('[+] Goodboy FOUND! Extracting target ciphertext:')

        sym_bufs = found_state.globals.get('sym_bufs', [])
        trg_cipher = []        
        for i, sym_var in enumerate(sym_bufs):
            val = found_state.solver.eval(sym_var)
            trg_cipher.append(val)
            print(f'[+]     trg_cipher[{i}] = 0x{val:016X}')
        
        return trg_cipher
    else:
        raise Exception('Cannot reach goodboy :(')

# ----------------------------------------------------------------------------------------
