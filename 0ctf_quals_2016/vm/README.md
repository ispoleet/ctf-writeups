
## 0CTF 2016 - VM (RE 7pt)
##### 12-14/03/2016 (48hr)
___

### Description: 


    You are (not) virtual.

    vm_bfd6ae310ab1c8c58437edb8b7df85cf

    update: here is a new binary comilped in i686 from same source code vm_recompile_00ce14276b4c33048ed3b3d48dbfcde7

___
### Solution

As the name suggests, we're dealing with a vm crackme. I'll provide a brief write up :)


### Virtual Emulator
Instructions are ARM-like. Each instruction is 0x48 bytes long and contains the following fields:
```C
struct instruction = {
    uint32_t opcode;        // +0h
    uint16_t dummy = 4;     // +4h
    uint16_t n_operands;    // +6h

    uint32_t dst_ty;        // +8h
    uint32_t dst_vreg;      // +Ch
    uint32_t dst_imm;       // +10h
    uint32_t pad_1;         // +14h

    uint32_t src1_ty;       // +18h
    uint32_t src1_vreg;     // +1Ch
    uint32_t src1_imm       // +20h
    uint32_t pad_2;         // +24h

    uint32_t src2_ty;       // +28h
    uint32_t src2_vreg;     // +2Ch
    uint32_t src2_imm       // +30h
    uint32_t pad_3;         // +34h

    uint8_t reserved[16];   // pad
}
```

The `src_ty`/`dst_ty` contain the type of the operand: `{ 1: vreg, 2: imm, 3: [vreg + imm] }`.
The *dispatchter table* is shown below:
```
    0x02 : 'mov',
    0x05 : 'add',
    0x06 : 'add',
    0x09 : 'sub',
    0x0b : 'smul',
    0x0c : 'mul',
    0x0e : 'div',
    0x11 : 'ldr',
    0x14 : 'ldrb',
    0x16 : 'str',
    0x18 : 'strb',
    0x1d : 'movt',
    0x1e : 'mov_f1',
    0x1f : 'mov_f2',
    0x21 : 'and',
    0x22 : 'or',
    0x23 : 'or',
    0x24 : 'xor',
    0x26 : 'nor',
    0x29 : 'tstl',
    0x2b : 'cmp?',
    0x2c : 'lsl',
    0x2e : 'lsr',
    0x30 : 'asr',
    0x32 : 'cbz',
    0x33 : 'cbnz',
    0x34 : 'be',
    0x35 : 'bne',
    0x3e : 'b',
    0x3f : 'retn',
    0x40 : 'libcall',
    0x41 : 'call',
    0x4d : 'nop'
```

vm has a special call instruction `libcall` that invokes external libc calls. Each instruction in
the emulated program is 4 bytes long. Upon function return program counter is incremented by 8
so the instruction after return is always dummy as it's executed. Entry point is at `0x400b94`.
The vm state is the following:
```C
vm_state_56966964[145] = {
    r0  - r15: 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    r16 - r25: 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    r26      : 400B94h
    r27 - r31: 0, 0, 0
    r30      : 1234FE94h
    r31      : 0 
    r32      : 0                    ; link register
    ...
    +80h     : 0                    ; link register
    +220h    : 400B94h              ; program counter
}
```

On function return, `r3` holds the return value. `r26` contains the address of the library call.
The first function argument is placed on `r5`, the second on `r6` and so on.
The `.rodata` section of the emulated program is the following:
```
 45 72 72 6F 72 21 00 00  49 6E 70 75 74 20 74 68  Error!..Input th
 65 20 66 6C 61 67 2C 20  70 6C 65 61 73 65 3A 00  e flag, please:.
 CC ED F5 AC 70 A4 68 6C  C3 9C 4B 1B 1F 9F CB F2  ¦f)¼pñhl+£K..ƒ-=
 74 7D 1D 4E DF 6C 30 CB  23 EB 7F 0E 77 98 79 7E  t}.N¯l0-#d..wÿy~
 00 00 00 00 47 6F 6F 64  21 20 53 75 62 6D 69 74  ....Good! Submit
 20 79 6F 75 72 20 66 6C  61 67 21 00 08 0D 40 00   your flag!...@.
 58 0D 40 00 9C 0D 40 00  EC 0D 40 00 30 0E 40 00  X.@.£.@.8.@.0.@.
 74 0E 40 00 B8 0E 40 00  F4 0E 40 00 00 00 00 00  t.@.+.@.(.@.....
```

Finally at `0x411360` there are all the libc symbols (it's like a .got table):
```
zero:00411360         dd offset exit
zero:00411364         dd offset _IO_puts
zero:00411368         dd offset stdin
zero:0041136C         dd offset _IO_printf
zero:00411370         dd offset unk_F7D149B0 ; strlen
zero:00411374         dd 0
zero:00411378         dd 0
zero:0041137C         dd 0
zero:00411380         dd offset fgets
zero:00411384         dd 0
zero:00411388         dd 0
zero:0041138C         dd offset unk_F7DD42B0
```

To access the symbols, code uses 2 instructions: `r29 = [r31, #10h]` and then, `[r29, #ffff803ch]`
(for `printf`). The following line invokes the library call:
```Assembly
.text:56558D4A         call    [esp+7Ch+var_20]
```

Function `dispatcher_56556140` is the instruction dispatcher/decoder. This is simply a huge function
we weird control flow transfers.
The emulated program is pretty large, and it's stored in [raw_vm_program.dat](raw_vm_program.dat)

### Cracking the emulated program

[vm_disassemble.py](vm_disassemble.py), is a disassembler for the emulated program. By using it,
we can get the [emulated program](emulated_program.txt).

The code is already analyzed. Some interesting points:
* flag must be 0x1f (including \n) characters long.
* algorithm uses its own PRNG to encrypt the flag.
* algorithm performs 128 iterations. On each iteration it "randomly" picks two characters and apply
  some (reversable) operations on them.
* at the end, the encrypted flag, is compared against the following string:
  `CC ED F5 AC 70 A4 68 6C C3 9C 4B 1B 1F 9F CB F2 74 7D 1D 4E DF 6C 30 CB 23 EB 7F 0E 77 98 79 7E`


To get the flag we have to execute the algorithm *backwards*. To do so, we first "idle-run" the
algorithm and collect pseudo-random numbers from the generator. Then we start from the last
iteration and we use the PRNG in the "reverse" way. After that, we get the flag:
`0ctf{Mipsel_Virtual_Machine_><}`. [vm_crack.py](vm_crack.py) does this for us.

```
ispo@nogirl:~/ctf/2016/0ctf/vm$ ./vm_recompile_00ce14276b4c33048ed3b3d48dbfcde7 
Input the flag, please:0ctf{Mipsel_Virtual_Machine_><}
Good! Submit your flag!
```

#### Optimization
Instead of reversing the complicated `rand()` (which is about 200 lines of emulated
assembly code), we can simply set the following conditional breakpoint at `dispatcher_56556140`:
```C
SetBptCnd(0x56556167, "Dword(ESI+0x220) == 0x400b44");
```

That is, debugger will stop every time the emulated program reaches instruction `0x400b44` (at
the end of `rand()`). Then we can simply dump the contents of `r3` register (ESI+0x12), which
holds the return value of `rand()`. The use of rand() is independent of the input flag, so we
can write a small IDC script to collect all return values from `rand()` and use them in crack,
instead of reversing this function.
___