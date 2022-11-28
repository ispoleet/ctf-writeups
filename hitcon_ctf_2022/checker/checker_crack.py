#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# HITCON Quals CTF 2022 - Checker (RE 252)
# ----------------------------------------------------------------------------------------
import capstone


encrypted_flag = [
  0x63, 0x60, 0xA5, 0xB9, 0xFF, 0xFC, 0x30, 0x0A, 0x48, 0xBB, 
  0xFE, 0xFE, 0x32, 0x2C, 0x0A, 0xD6, 0xE6, 0xFE, 0xFE, 0x32, 
  0x2C, 0x0A, 0xD6, 0xBB, 0x4A, 0x4A, 0x32, 0x2C, 0xFC, 0xFF, 
  0x0A, 0xFD, 0xBB, 0xFE, 0x2C, 0xB9, 0x63, 0xD6, 0xB9, 0x62, 
  0xD6, 0x0A, 0x4F, 0x00, 0x00, 0x00, 0x00, 0x00,
]

opcodes_xor_buf = [
  0x19, 0xBC, 0x8F, 0x82, 0xD0, 0x2C, 0x61, 0x34, 0xC0, 0x9F, 
  0xF6, 0x50, 0xD5, 0xFB, 0x0C, 0x6E, 0xD0, 0xEB, 0xE5, 0xE3, 
  0xCE, 0xB5, 0x4C, 0xCA, 0x45, 0xAA, 0x11, 0xB2, 0x3E, 0x62, 
  0x6F, 0x7D, 0xD0, 0xEB, 0xA9, 0xE3, 0xB2, 0x2F, 0x06, 0x47, 
  0x7C, 0x28, 0xC5, 0xDE, 0xDE, 0x1A, 0x4E, 0xD6, 0xD8, 0x2D, 
  0x93, 0x4F, 0x82, 0x65, 0x64, 0xFD, 0x08, 0x62, 0x4B, 0x87, 
  0x7E, 0x52, 0x47, 0x30, 0xB7, 0xBA, 0xD0, 0x39, 0x68, 0x53, 
  0x50, 0xAB, 0x20, 0xD5, 0xCA, 0x84, 0x26, 0x71, 0x6F, 0x91, 
  0x1B, 0x36, 0x46, 0x11, 0xA5, 0xF1, 0x4E, 0x58, 0x6C, 0x74, 
  0xD4, 0x9C, 0x15, 0xE2, 0x28, 0xD5, 0xD9, 0x0F, 0x3D, 0x83, 
  0xF3, 0xFC, 0xD1, 0x13, 0x1A, 0x62, 0x12, 0x40, 0xAA, 0xEA, 
  0xCD, 0xCB, 0xE1, 0xC6, 0x08, 0x81, 0x98, 0xF6, 0x68, 0x88, 
  0xBE, 0x23, 0xB5, 0x9E, 0x55, 0xB9, 0xE2, 0x7D, 0x5A, 0xDA, 
  0x39, 0x07, 0xF0, 0x2E, 0x32, 0x20, 0x59, 0x56, 0x4C, 0xB4, 
  0x8F, 0x3E, 0x07, 0x61, 0xD9, 0x0F, 0x2D, 0x61, 0xF1, 0x91, 
  0x33, 0x14, 0xCB, 0x49, 0x68, 0xFE, 0x1F, 0xD4, 0x8A, 0xFE, 
  0xE1, 0xC6, 0x18, 0x63, 0x9A, 0x9B, 0x8A, 0x8A, 0x7F, 0x08, 
  0xC3, 0xE8, 0xE1, 0xEC, 0x0B, 0x8F, 0x3B, 0x00, 0x94, 0xA5, 
  0x11, 0xE7, 0x47, 0x66, 0xC4, 0x9F, 0x98, 0x18, 0x70, 0xF0, 
  0x30, 0xF6, 0x94, 0x71, 0xB1, 0x95, 0xD1, 0xF0, 0x6F, 0xB7, 
  0xD9, 0x3D, 0x05, 0x9E, 0xC1, 0x53, 0x33, 0x76, 0x9B, 0x4B, 
  0x69, 0xCA, 0xDE, 0xFD, 0x7D, 0x67, 0xB8, 0x29, 0x2B, 0xC7, 
  0xC5, 0x84, 0x2C, 0xD1, 0x87, 0x87, 0xF1, 0x98, 0x97, 0x74, 
  0xAD, 0x4B, 0x32, 0xF0, 0x4A, 0x51, 0x72, 0xEA, 0x09, 0xF7, 
  0x38, 0xFD, 0x27, 0xBD, 0x1C, 0x52, 0x71, 0x43, 0x95, 0x9C, 
  0x1A, 0x86, 0xF2, 0xC0, 0xF9, 0xF8
]

init_xor_buf = [
  0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0x05, 0x3B,
  0x0C, 0x00, 0x00, 0x48, 0x8B, 0xDA, 0x48, 0x8B, 0x4A, 0x10,
  0x48, 0x39, 0x08, 0x75, 0x37, 0x48, 0x8B, 0x4A, 0x08, 0xFF,
  0x15, 0x1D, 0x0C, 0x00, 0x00, 0x48, 0x8D, 0x0D, 0x16, 0x1D,
  0x00, 0x00, 0x80, 0x3C, 0x08, 0x00, 0x74, 0x20, 0x8B, 0x03,
  0x83, 0xF8, 0x01, 0x74, 0x05, 0x83, 0xF8, 0x02, 0x75, 0x14,
  0x48, 0x8B, 0x4B, 0x20, 0x8B, 0x41, 0x04, 0x83, 0xE0, 0x01,
  0x84, 0xC0, 0x74, 0x06, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00,
  0x33, 0xC0, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0xC3
]

decr_opcodes_buf = [
  0x80, 0xE9, 0x22, 0x80, 0xF1, 0xAD, 0x0F, 0xB6, 0xC1, 0x6B,
  0xC8, 0x11, 0xB8, 0x9E, 0x00, 0x00, # 0x00, 0x2A, 0xC1, 0xC3
]


# ----------------------------------------------------------------------------------------
def decr_func_orig(a1):
    """Original decryption routine (decrypts one character).

        .text:0000000140001B30                decr_func proc near
        .text:0000000140001B30 80 E9 22          sub     cl, 22h
        .text:0000000140001B33 80 F1 AD          xor     cl, 0ADh
        .text:0000000140001B36 0F B6 C1          movzx   eax, cl
        .text:0000000140001B39 6B C8 11          imul    ecx, eax, 11h
        .text:0000000140001B3C B8 9E 00 00 00    mov     eax, 9Eh
        .text:0000000140001B41 2A C1             sub     al, cl
        .text:0000000140001B43 C3                retn
        .text:0000000140001B43                decr_func endp
    """
    return (0x9E - 0x11 * ((a1 - 0x22) ^ 0xAD)) & 0xFF


# ----------------------------------------------------------------------------------------
def try_disasm(buf):
    """Tries to disassemble a buffer."""    
    print(f"[+]\tOpcodes: {'-'.join('%02X' % x for x in buf)}")

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for insn in md.disasm(bytes(buf), 0x140001B30):
        print(f'[+]\t.text:{insn.address:X} \t{insn.mnemonic}\t{insn.op_str}')


# ----------------------------------------------------------------------------------------
def find_next_order(candidates, buf):
    """XORs a buffer with all `candidates` offses in `opcodes_xor_buf`.
       Function lets useer decide which guess is the correct one.

       NOTE: We can also try all possible orders recursively, create a tree and see
             which path reaches a depth 8, but this is much simpler :)
    """
    for i, off in enumerate(candidates):
        print(f'[+] Trying candidate #{i} (Offset: 0x{off:X}) ...')

        try_disasm([a ^ b for a, b in zip(buf, opcodes_xor_buf[off:])])

    return int(input('Which one do you want? '), 0)


# ----------------------------------------------------------------------------------------
def recover_decryption_order():
    """Recovers the decryption order (let's user decide)."""
    global decr_opcodes_buf

    candidates = list(range(0, 0x100, 0x20))
    correct_order = []

    while candidates:
        print(f"[+]\tOpcodes: {'-'.join('%02X' % x for x in decr_opcodes_buf)}")
        nxt = find_next_order(candidates, decr_opcodes_buf)

        if nxt < 0 or nxt >= len(candidates):
            raise Exception(f'Invalid choice: {nxt}')

        off = candidates[nxt]

        print(f'[+] Selecting Offset: 0x{off:X}')

        decr_opcodes_buf = [a ^ b for a, b in zip(decr_opcodes_buf, opcodes_xor_buf[off:])]

        correct_order.append((off, decr_opcodes_buf))
        
        decr_opcodes_buf = [a ^ b for a, b in zip(decr_opcodes_buf, opcodes_xor_buf[off+16:])]

        candidates.remove(candidates[nxt])

    
    print('[+] Final Order:')
    for off, opcs in correct_order:
        print(f"[+] Offset: 0x{off:X} ~> {' '.join('%02X' % x for x in opcs)}")

    return correct_order


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Checker Crack Started.')

    for i in range(16):
        decr_opcodes_buf[i] ^= init_xor_buf[i] ^ init_xor_buf[i + 16]

    print('[+] Original Opcodes:', ' '.join('%02X' % x for x in decr_opcodes_buf))


    # Run this to get the decryption order.
    # decr_order = recover_decryption_order()

    '''
    Decryption Order:
       0xE0 ~> 0F B6 D1 8B C2 C0 E2 03 C1 E8 05 0A C2 C3 97 30
       0x40 ~> 80 F1 26 0F B6 C1 C3 EB 74 A1 D5 08 16 72 01 59
       0xC0 ~> 0F B6 D1 8B C2 C0 E2 04 C1 E8 04 0A C2 C3 1A FA
       0x0 ~>  8D 41 37 C3 CC 11 FE 57 B9 5E D9 9D D2 BC 3A 45
       0x20 ~> 8D 41 7B C3 B0 8B B4 DA 80 DC 0D F1 32 C4 1B EE
       0x80 ~> 0F B6 D1 8B C2 C0 E2 07 D1 E8 0A C2 C3 A8 5B BF
       0x60 ~> 0F B6 C1 69 C0 AD 00 00 00 C3 70 7C 76 96 1C 8A
       0xA0 ~> 0F B6 D1 8B C2 C0 E2 02 C1 E8 06 0A C2 C3 F5 78

    Below are the decryption routines for each layer:

        # 0F B6 D1 8B C2 C0 E2 03 C1 E8 05 0A C2 C3 97 30
        unsigned __int8 __fastcall decr_func(unsigned __int8 a1) {
          return (8 * a1) | (a1 >> 5);
        }

        # 80 F1 26 0F B6 C1 C3 EB 74 A1 D5 08 16 72 01 59
        unsigned __int8 __fastcall decr_func(unsigned __int8 a1) {
          return a1 ^ 0x26u;
        }

        # 0F B6 D1 8B C2 C0 E2 04 C1 E8 04 0A C2 C3 1A FA
        unsigned __int8 __fastcall decr_func(unsigned __int8 a1) {
            return (16 * a1) | (a1 >> 4);
        }

        # 8D 41 37 C3 CC 11 FE 57 B9 5E D9 9D D2 BC 3A 45
        unsigned __int8 __fastcall decr_func(unsigned __int8 a1) {
          return a1 + 55;
        }

        # 8D 41 7B C3 B0 8B B4 DA 80 DC 0D F1 32 C4 1B EE
        unsigned __int8 __fastcall decr_func(unsigned __int8 a1) {
            return a1 + 123;
        }
        
        # 0F B6 D1 8B C2 C0 E2 07 D1 E8 0A C2 C3 A8 5B BF
        unsigned __int8 __fastcall decr_func(unsigned __int8 a1) {
            return (a1 << 7) | (a1 >> 1);
        }    

        # 0F B6 C1 69 C0 AD 00 00 00 C3 70 7C 76 96 1C 8A
        unsigned __int8 __fastcall decr_func(unsigned __int8 a1) {
            return 0xAD * a1;
        }    

        # 0F B6 D1 8B C2 C0 E2 02 C1 E8 06 0A C2 C3 F5 78
        unsigned __int8 __fastcall decr_func(unsigned __int8 a1) {
            return (4 * a1) | (a1 >> 6);
        }    
    '''
    decr_order = [0xE0, 0x40, 0xC0, 0x00, 0x20, 0x80, 0x60, 0xA0]

    crypt_tbl = {
        0xE0: lambda a1: ((8 * a1) | (a1 >> 5) ) & 0xFF,
        0x40: lambda a1: (a1 ^ 0x26            ) & 0xFF,
        0xC0: lambda a1: ((16 * a1) | (a1 >> 4)) & 0xFF,
        0x00: lambda a1: (a1 + 55              ) & 0xFF,
        0x20: lambda a1: (a1 + 123             ) & 0xFF,
        0x80: lambda a1: ((a1 << 7) | (a1 >> 1)) & 0xFF,
        0x60: lambda a1: (0xAD * a1            ) & 0xFF,
        0xA0: lambda a1: ((4 * a1) | (a1 >> 6) ) & 0xFF            
    }

    for i in decr_order:
        print(f'[+] Decrypting `decr_func` using buf at offset: 0x{i:X}')
        for j in range(16):
            decr_opcodes_buf[j] ^= opcodes_xor_buf[i + j]

        print('[+]\tOpcodes:', ' '.join('%02X' % x for x in decr_opcodes_buf))
        for j in range(43):
            encrypted_flag[j] = crypt_tbl[i](encrypted_flag[j])

        for j in range(16):
            decr_opcodes_buf[j] ^= opcodes_xor_buf[i + j + 16]

        # break

    print('[+] Decrypted Flag: ', ''.join('%c' % x for x in encrypted_flag))

    print('[+] Program finished! Bye bye :)')


# ----------------------------------------------------------------------------------------
"""
ispo@ispo-glaptop2:~/ctf/hitcon_quals_2022/checker$ ./checker_crack.py 
    [+] Checker Crack Started.
    [+] Original Opcodes: 88 31 20 13 55 B4 4F 48 F3 18 4F 5B B0 29 9E C7
    [+]	Opcodes: 88-31-20-13-55-B4-4F-48-F3-18-4F-5B-B0-29-9E-C7
    [+] Trying candidate #0 (Offset: 0x0) ...
    [+]	Opcodes: 91-8D-AF-91-85-98-2E-7C-33-87-B9-0B-65-D2-92-A9
    [+]	.text:140001B30 	xchg	eax, ecx
    [+]	.text:140001B31 	lea	ebp, [rdi + 0x2e988591]
    [+]	.text:140001B37 	jl	0x140001b6c
    [+]	.text:140001B39 	xchg	dword ptr [rcx - 0x6d2d9af5], edi
    [+] Trying candidate #1 (Offset: 0x20) ...
    [+]	Opcodes: 58-DA-89-F0-E7-9B-49-0F-8F-30-8A-85-6E-33-D0-11
    [+]	.text:140001B30 	pop	rax
    [+]	.text:140001B31 	fimul	dword ptr [rcx + 0x499be7f0]
    [+]	.text:140001B37 	jg	0x1ae85a56d
    [+]	.text:140001B3D 	xor	edx, eax
    [+] Trying candidate #2 (Offset: 0x40) ...
    [+]	Opcodes: 3F-8B-F0-2A-3D-E7-1F-E3-D3-CD-85-DF-96-58-F1-56
    [+] Trying candidate #3 (Offset: 0x60) ...
    [+]	Opcodes: 51-3E-1D-90-A6-48-9E-5B-E9-7A-5D-1B-1A-C3-53-0C
    [+]	.text:140001B30 	push	rcx
    [+]	.text:140001B31 	sbb	eax, 0x9e48a690
    [+]	.text:140001B37 	pop	rbx
    [+]	.text:140001B38 	jmp	0x15a1b78b7
    [+]	.text:140001B3D 	ret	
    [+]	.text:140001B3E 	push	rbx
    [+] Trying candidate #4 (Offset: 0x80) ...
    [+]	Opcodes: D2-EB-19-14-A5-9A-7D-68-AA-4E-03-EF-3F-17-99-A6
    [+]	.text:140001B30 	shr	bl, cl
    [+]	.text:140001B32 	sbb	dword ptr [0xffffffffaa687d9a], edx
    [+]	.text:140001B39 	add	r13, rdi
    [+] Trying candidate #5 (Offset: 0xA0) ...
    [+]	Opcodes: 69-F7-38-70-CF-2F-C5-C2-8C-10-8C-B3-51-C5-95-48
    [+]	.text:140001B30 	imul	esi, edi, 0x2fcf7038
    [+] Trying candidate #6 (Offset: 0xC0) ...
    [+]	Opcodes: 1C-40-91-86-84-44-20-FF-2A-25-4A-C5-71-7A-AD-B1
    [+]	.text:140001B30 	sbb	al, 0x40
    [+]	.text:140001B32 	xchg	eax, ecx
    [+]	.text:140001B33 	xchg	byte ptr [rsp + rax*2 + 0x252aff20], al
    [+] Trying candidate #7 (Offset: 0xE0) ...
    [+]	Opcodes: 0F-B6-D1-8B-C2-C0-E2-03-C1-E8-05-0A-C2-C3-97-30
    [+]	.text:140001B30 	movzx	edx, cl
    [+]	.text:140001B33 	mov	eax, edx
    [+]	.text:140001B35 	shl	dl, 3
    [+]	.text:140001B38 	shr	eax, 5
    [+]	.text:140001B3B 	or	al, dl
    [+]	.text:140001B3D 	ret	
    [+]	.text:140001B3E 	xchg	eax, edi
    Which one do you want? 7
    [+] Selecting Offset: 0xE0
    [+]	Opcodes: 37-4B-F6-36-DE-92-93-40-54-74-1F-8C-30-03-6E-C8
    [+] Trying candidate #0 (Offset: 0x0) ...
    [+]	Opcodes: 2E-F7-79-B4-0E-BE-F2-74-94-EB-E9-DC-E5-F8-62-A6
    [+]	.text:140001B30 	idiv	dword ptr cs:[rcx - 0x4c]
    [+] Trying candidate #1 (Offset: 0x20) ...
    [+]	Opcodes: E7-A0-5F-D5-6C-BD-95-07-28-5C-DA-52-EE-19-20-1E
    [+]	.text:140001B30 	out	0xa0, eax
    [+]	.text:140001B32 	pop	rdi
    [+] Trying candidate #2 (Offset: 0x40) ...
    [+]	Opcodes: 80-F1-26-0F-B6-C1-C3-EB-74-A1-D5-08-16-72-01-59
    [+]	.text:140001B30 	xor	cl, 0x26
    [+]	.text:140001B33 	movzx	eax, cl
    [+]	.text:140001B36 	ret	
    [+]	.text:140001B37 	jmp	0x140001bad
    [+] Trying candidate #3 (Offset: 0x60) ...
    [+]	Opcodes: EE-44-CB-B5-2D-6E-42-53-4E-16-0D-CC-9A-E9-A3-03
    [+]	.text:140001B30 	out	dx, al
    [+]	.text:140001B31 	retf	
    [+]	.text:140001B33 	mov	ch, 0x2d
    [+]	.text:140001B35 	outsb	dx, byte ptr [rsi]
    [+]	.text:140001B36 	push	rbx
    [+] Trying candidate #4 (Offset: 0x80) ...
    [+]	Opcodes: 6D-91-CF-31-2E-BC-A1-60-0D-22-53-38-BF-3D-69-A9
    [+]	.text:140001B30 	insd	dword ptr [rdi], dx
    [+]	.text:140001B31 	xchg	eax, ecx
    [+]	.text:140001B32 	iretd	
    [+]	.text:140001B33 	xor	dword ptr [rsi], ebp
    [+]	.text:140001B35 	mov	esp, 0x220d60a1
    [+]	.text:140001B3A 	push	rbx
    [+] Trying candidate #5 (Offset: 0xA0) ...
    [+]	Opcodes: D6-8D-EE-55-44-09-19-CA-2B-7C-DC-64-D1-EF-65-47
    [+] Trying candidate #6 (Offset: 0xC0) ...
    [+]	Opcodes: A3-3A-47-A3-0F-62-FC-F7-8D-49-1A-12-F1-50-5D-BE
    [+]	.text:140001B30 	movabs	dword ptr [0x8df7fc620fa3473a], eax
    [+]	.text:140001B39 	sbb	dl, byte ptr [r10]
    [+]	.text:140001B3C 	int1	
    [+]	.text:140001B3D 	push	rax
    [+]	.text:140001B3E 	pop	rbp
    Which one do you want? 2
    [+] Selecting Offset: 0x40
    [+]	Opcodes: 9B-C7-60-1E-13-30-8D-B3-18-D5-01-94-03-90-29-8C
    [+] Trying candidate #0 (Offset: 0x0) ...
    [+]	Opcodes: 82-7B-EF-9C-C3-1C-EC-87-D8-4A-F7-C4-D6-6B-25-E2
    [+] Trying candidate #1 (Offset: 0x20) ...
    [+]	Opcodes: 4B-2C-C9-FD-A1-1F-8B-F4-64-FD-C4-4A-DD-8A-67-5A
    [+]	.text:140001B30 	sub	al, 0xc9
    [+]	.text:140001B33 	std	
    [+]	.text:140001B34 	movabs	eax, dword ptr [0xdd4ac4fd64f48b1f]
    [+]	.text:140001B3D 	mov	ah, byte ptr [rdi + 0x5a]
    [+] Trying candidate #2 (Offset: 0x60) ...
    [+]	Opcodes: 42-C8-5D-9D-E0-CC-5C-A0-02-B7-13-D4-A9-7A-E4-47
    [+]	.text:140001B30 	enter	-0x62a3, -0x20
    [+]	.text:140001B35 	int3	
    [+]	.text:140001B36 	pop	rsp
    [+]	.text:140001B37 	movabs	al, byte ptr [0x47e47aa9d413b702]
    [+] Trying candidate #3 (Offset: 0x80) ...
    [+]	Opcodes: C1-1D-59-19-E3-1E-BF-93-41-83-4D-20-8C-AE-2E-ED
    [+]	.text:140001B30 	rcr	dword ptr [rip + 0x1ee31959], 0xbf
    [+]	.text:140001B37 	xchg	eax, ebx
    [+]	.text:140001B38 	or	dword ptr [r13 + 0x20], 0xffffff8c
    [+]	.text:140001B3D 	scasb	al, byte ptr [rdi]
    [+]	.text:140001B3E 	in	eax, dx
    [+] Trying candidate #4 (Offset: 0xA0) ...
    [+]	Opcodes: 7A-01-78-7D-89-AB-07-39-67-DD-C2-7C-E2-7C-22-03
    [+]	.text:140001B30 	jp	0x140001b33
    [+]	.text:140001B32 	js	0x140001bb1
    [+]	.text:140001B34 	mov	dword ptr [rbx - 0x2298c6f9], ebp
    [+]	.text:140001B3A 	ret	0xe27c
    [+]	.text:140001B3D 	jl	0x140001b61
    [+] Trying candidate #5 (Offset: 0xC0) ...
    [+]	Opcodes: 0F-B6-D1-8B-C2-C0-E2-04-C1-E8-04-0A-C2-C3-1A-FA
    [+]	.text:140001B30 	movzx	edx, cl
    [+]	.text:140001B33 	mov	eax, edx
    [+]	.text:140001B35 	shl	dl, 4
    [+]	.text:140001B38 	shr	eax, 4
    [+]	.text:140001B3B 	or	al, dl
    [+]	.text:140001B3D 	ret	
    [+]	.text:140001B3E 	sbb	bh, dl
    Which one do you want? 5
    [+] Selecting Offset: 0xC0
    [+]	Opcodes: 94-FD-B8-41-1C-3D-9F-63-79-C1-2F-CD-07-47-36-2B
    [+] Trying candidate #0 (Offset: 0x0) ...
    [+]	Opcodes: 8D-41-37-C3-CC-11-FE-57-B9-5E-D9-9D-D2-BC-3A-45
    [+]	.text:140001B30 	lea	eax, [rcx + 0x37]
    [+]	.text:140001B33 	ret	
    [+]	.text:140001B34 	int3	
    [+]	.text:140001B35 	adc	esi, edi
    [+]	.text:140001B37 	push	rdi
    [+]	.text:140001B38 	mov	ecx, 0xd29dd95e
    [+] Trying candidate #1 (Offset: 0x20) ...
    [+]	Opcodes: 44-16-11-A2-AE-12-99-24-05-E9-EA-13-D9-5D-78-FD
    [+] Trying candidate #2 (Offset: 0x60) ...
    [+]	Opcodes: 4D-F2-85-C2-EF-C1-4E-70-63-A3-3D-8D-AD-AD-FB-E0
    [+]	.text:140001B30 	test	edx, eax
    [+]	.text:140001B34 	out	dx, eax
    [+]	.text:140001B35 	ror	dword ptr [rsi + 0x70], 0x63
    [+] Trying candidate #3 (Offset: 0x80) ...
    [+]	Opcodes: CE-27-81-46-EC-13-AD-43-20-97-63-79-88-79-31-4A
    [+] Trying candidate #4 (Offset: 0xA0) ...
    [+]	Opcodes: 75-3B-A0-22-86-A6-15-E9-06-C9-EC-25-E6-AB-3D-A4
    [+]	.text:140001B30 	jne	0x140001b6d
    [+]	.text:140001B32 	movabs	al, byte ptr [0xecc906e915a68622]
    [+]	.text:140001B3B 	and	eax, 0xa43dabe6
    Which one do you want? 0
    [+] Selecting Offset: 0x0
    [+]	Opcodes: 5D-AA-D2-20-02-A4-B2-9D-FC-F4-C8-2F-EC-DE-55-38
    [+] Trying candidate #0 (Offset: 0x20) ...
    [+]	Opcodes: 8D-41-7B-C3-B0-8B-B4-DA-80-DC-0D-F1-32-C4-1B-EE
    [+]	.text:140001B30 	lea	eax, [rcx + 0x7b]
    [+]	.text:140001B33 	ret	
    [+]	.text:140001B34 	mov	al, 0x8b
    [+]	.text:140001B36 	mov	ah, 0xda
    [+]	.text:140001B38 	sbb	ah, 0xd
    [+]	.text:140001B3B 	int1	
    [+]	.text:140001B3C 	xor	al, ah
    [+]	.text:140001B3E 	sbb	ebp, esi
    [+] Trying candidate #1 (Offset: 0x60) ...
    [+]	Opcodes: 84-A5-EF-A3-F1-58-63-8E-E6-96-DA-6F-46-34-98-F3
    [+]	.text:140001B30 	test	byte ptr [rbp + 0x58f1a3ef], ah
    [+]	.text:140001B36 	movsxd	rcx, dword ptr [rsi + 0x6fda96e6]
    [+]	.text:140001B3C 	xor	al, 0x98
    [+] Trying candidate #2 (Offset: 0x80) ...
    [+]	Opcodes: 07-70-EB-27-F2-8A-80-BD-A5-A2-84-9B-63-E0-52-59
    [+] Trying candidate #3 (Offset: 0xA0) ...
    [+]	Opcodes: BC-6C-CA-43-98-3F-38-17-83-FC-0B-C7-0D-32-5E-B7
    [+]	.text:140001B30 	mov	esp, 0x9843ca6c
    Which one do you want? 0
    [+] Selecting Offset: 0x20
    [+]	Opcodes: 55-6C-E8-8C-32-EE-D0-27-88-BE-46-76-4C-96-5C-DE
    [+] Trying candidate #0 (Offset: 0x60) ...
    [+]	Opcodes: 8C-63-D5-0F-C1-12-01-34-92-DC-54-36-E6-7C-91-15
    [+]	.text:140001B30 	mov	word ptr [rbx - 0x2b], fs
    [+]	.text:140001B33 	xadd	dword ptr [rdx], edx
    [+]	.text:140001B36 	add	dword ptr [rdx + rdx*4], esi
    [+]	.text:140001B39 	fcom	qword ptr [rsi + rsi - 0x1a]
    [+]	.text:140001B3D 	jl	0x140001ad0
    [+] Trying candidate #1 (Offset: 0x80) ...
    [+]	Opcodes: 0F-B6-D1-8B-C2-C0-E2-07-D1-E8-0A-C2-C3-A8-5B-BF
    [+]	.text:140001B30 	movzx	edx, cl
    [+]	.text:140001B33 	mov	eax, edx
    [+]	.text:140001B35 	shl	dl, 7
    [+]	.text:140001B38 	shr	eax, 1
    [+]	.text:140001B3A 	or	al, dl
    [+]	.text:140001B3C 	ret	
    [+]	.text:140001B3D 	test	al, 0x5b
    [+] Trying candidate #2 (Offset: 0xA0) ...
    [+]	Opcodes: B4-AA-F0-EF-A8-75-5A-AD-F7-B6-85-9E-AD-7A-57-51
    [+]	.text:140001B30 	mov	ah, 0xaa
    Which one do you want? 1
    [+] Selecting Offset: 0x80
    [+]	Opcodes: D6-B9-FC-EA-33-51-D1-13-1A-A1-62-3C-DC-7C-D1-41
    [+] Trying candidate #0 (Offset: 0x60) ...
    [+]	Opcodes: 0F-B6-C1-69-C0-AD-00-00-00-C3-70-7C-76-96-1C-8A
    [+]	.text:140001B30 	movzx	eax, cl
    [+]	.text:140001B33 	imul	eax, eax, 0xad
    [+]	.text:140001B39 	ret	
    [+]	.text:140001B3A 	jo	0x140001bb8
    [+]	.text:140001B3C 	jbe	0x140001ad4
    [+]	.text:140001B3E 	sbb	al, 0x8a
    [+] Trying candidate #1 (Offset: 0xA0) ...
    [+]	Opcodes: 37-7F-E4-89-A9-CA-5B-99-65-A9-A1-D4-3D-90-DA-CE
    Which one do you want? 0
    [+] Selecting Offset: 0x60
    [+]	Opcodes: EE-70-C9-E8-58-5B-68-88-BE-E0-C5-E2-23-2F-FE-F7
    [+] Trying candidate #0 (Offset: 0xA0) ...
    [+]	Opcodes: 0F-B6-D1-8B-C2-C0-E2-02-C1-E8-06-0A-C2-C3-F5-78
    [+]	.text:140001B30 	movzx	edx, cl
    [+]	.text:140001B33 	mov	eax, edx
    [+]	.text:140001B35 	shl	dl, 2
    [+]	.text:140001B38 	shr	eax, 6
    [+]	.text:140001B3B 	or	al, dl
    [+]	.text:140001B3D 	ret	
    [+]	.text:140001B3E 	cmc	
    Which one do you want? 0
    [+] Selecting Offset: 0xA0
    [+] Final Order:
    [+] Offset: 0xE0 ~> 0F B6 D1 8B C2 C0 E2 03 C1 E8 05 0A C2 C3 97 30
    [+] Offset: 0x40 ~> 80 F1 26 0F B6 C1 C3 EB 74 A1 D5 08 16 72 01 59
    [+] Offset: 0xC0 ~> 0F B6 D1 8B C2 C0 E2 04 C1 E8 04 0A C2 C3 1A FA
    [+] Offset: 0x0 ~> 8D 41 37 C3 CC 11 FE 57 B9 5E D9 9D D2 BC 3A 45
    [+] Offset: 0x20 ~> 8D 41 7B C3 B0 8B B4 DA 80 DC 0D F1 32 C4 1B EE
    [+] Offset: 0x80 ~> 0F B6 D1 8B C2 C0 E2 07 D1 E8 0A C2 C3 A8 5B BF
    [+] Offset: 0x60 ~> 0F B6 C1 69 C0 AD 00 00 00 C3 70 7C 76 96 1C 8A
    [+] Offset: 0xA0 ~> 0F B6 D1 8B C2 C0 E2 02 C1 E8 06 0A C2 C3 F5 78


ispo@ispo-glaptop2:~/ctf/hitcon_quals_2022/checker$ ./checker_crack.py 
    [+] Checker Crack Started.
    [+] Original Opcodes: 88 31 20 13 55 B4 4F 48 F3 18 4F 5B B0 29 9E C7
    [+] Decrypting `decr_func` using buf at offset: 0xE0
    [+]	Opcodes: 0F B6 D1 8B C2 C0 E2 03 C1 E8 05 0A C2 C3 97 30
    [+] Decrypting `decr_func` using buf at offset: 0x40
    [+]	Opcodes: 80 F1 26 0F B6 C1 C3 EB 74 A1 D5 08 16 72 01 59
    [+] Decrypting `decr_func` using buf at offset: 0xC0
    [+]	Opcodes: 0F B6 D1 8B C2 C0 E2 04 C1 E8 04 0A C2 C3 1A FA
    [+] Decrypting `decr_func` using buf at offset: 0x0
    [+]	Opcodes: 8D 41 37 C3 CC 11 FE 57 B9 5E D9 9D D2 BC 3A 45
    [+] Decrypting `decr_func` using buf at offset: 0x20
    [+]	Opcodes: 8D 41 7B C3 B0 8B B4 DA 80 DC 0D F1 32 C4 1B EE
    [+] Decrypting `decr_func` using buf at offset: 0x80
    [+]	Opcodes: 0F B6 D1 8B C2 C0 E2 07 D1 E8 0A C2 C3 A8 5B BF
    [+] Decrypting `decr_func` using buf at offset: 0x60
    [+]	Opcodes: 0F B6 C1 69 C0 AD 00 00 00 C3 70 7C 76 96 1C 8A
    [+] Decrypting `decr_func` using buf at offset: 0xA0
    [+]	Opcodes: 0F B6 D1 8B C2 C0 E2 02 C1 E8 06 0A C2 C3 F5 78
    [+] Decrypted Flag:  hitcon{r3ally_re4lly_rea11y_normal_checker}
    [+] Program finished! Bye bye :)
"""
# ----------------------------------------------------------------------------------------

