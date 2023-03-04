#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# 0CTF 2019 - J (RE 297)
# ----------------------------------------------------------------------------------------
import struct

# ----------------------------------------------------------------------------------------
for i in range(257):
  a = ida_bytes.get_dword(0x80010000 + 8*i)       # Address of spinlock
  b = ida_bytes.get_dword(0x80010000 + 8*i + 4)   # Address to continue

  a ^= 0xD3ABC0DE
  b ^= 0xD3ABC0DE

  # Patch address of spinlock with a jmp to b.
  t = ((b - a) & 0xFFFF) // 4 - 1
  print(f'[+] Patching: 0x{a:08X} ~> 0x{b:08X}')

  # If you want to restore everything back to original:
  #   t = 0xFFFF
  #   ida_bytes.patch_dword(a, 0x10000000 | (t & 0x00FFFFFF)
  b //= 4
  # Opcodes: https://opencores.org/projects/plasma/opcodes
  # Replace with J instructions
  ida_bytes.patch_dword(a,  0x08000000 | b & 0xFFFF )

  # Make previous instruction a nop:
  #     mtc0    $zero, Count             # Timer Count
  ida_bytes.patch_dword(a - 4, 0x00000000)
  
# ----------------------------------------------------------------------------------------
'''
[+] Patching: 0x800005A0 ~> 0x80002920
[+] Patching: 0x800005B0 ~> 0x80002934
[+] Patching: 0x800005CC ~> 0x80002948
[+] Patching: 0x800005EC ~> 0x8000295C
....
[+] Patching: 0x800025E0 ~> 0x80003CF8
[+] Patching: 0x80002600 ~> 0x80003D0C
[+] Patching: 0xD3ABC0DE ~> 0xD3ABC0DE
'''
# ----------------------------------------------------------------------------------------