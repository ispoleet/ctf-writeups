## HXP CTF 2024 - mbins (Reversing 588)
### 27-29/12/2024 (48hr)
___

## Description

*仮想機械家族に優しくしてください。 Have fun with the virtual machine family.*

*プログラムが入力を受け入れるの倍は終了コードがゼロです。 The exit code will be 0 when the binary accepts the input.*


*Download:*
```
mbins-ff70e6b874978884.tar.xz (884.2 KiB)
```
___

### Solution

For this challenge we are given **1000** different binaries and we are asked to find the their
key in at least **950** of them. Each binary contains a different VM. Let's start from
`chk0.bin`:

```c
__int64 __fastcall main(int argc, char **argv, char **argp) {
  /* ... */
  retv = 1;
  if ( argc == 2 ) {
    key = argv[1];
    keylen = strlen(key);
    keylen_ = keylen;
    if ( (keylen & 1) == 0 ) {
      buf = malloc(keylen >> 1);
      cond = keylen_ != 0;
      if ( !keylen_ )
        return u_emu_vm(0LL, 2uLL, buf, keylen_ >> 1) == 0;
      prev_val = 0;
      // This is like atoi(): Convert argv[1] into hex string
      for ( i = 0LL; i < keylen_; cond = i < keylen_ ) {
        // convert hex string to bytes
      }
      if ( !cond )
        return u_emu_vm(0LL, 2uLL, buf, keylen_ >> 1) == 0;
    }
  }
  return retv;
}
```

The `u_emu_vm()` starts the VM emulation:
```c
__int64 u_emu_vm(__int64 a1_is_0, unsigned __int64 a2_is_2, ...) {
  /* ... */
  va_start(va, a2_is_2);
  vm_ctx = (vm_ctx **)(__readfsqword(0) - 8);
  if ( !__readfsqword(0xFFFFFFF8) ) {
    state = (#8 *)operator new(0x110uLL);
    memset(state, 0, 0x110uLL);
    *((_QWORD *)state + 32) = glo_VM_PROG;
    *((_QWORD *)state + 33) = &glo_dtors_flag;
    *vm_ctx = (vm_ctx *)state;
    // looks like stack (we point to the end of th buffer)
    (*vm_ctx)->sp = operator new[](0x2000uLL) + 0x2000LL;
  }
  var_args = *vm_ctx;
  sp = (*vm_ctx)->sp;
  if ( a2_is_2 ) {
    /* parse VA args in vm_regs. */
    ii = glo_indx_arr;                          // 0, 1, 2, 3, ...
    // parse args (buf/buflen) = (input/input_len)
    for ( i = 0LL; i < a2_is_2; ++i )
    {
      if ( (unsigned __int64)(int)va[0].gp_offset > 0x28 )
      {
        v9 = va_arg(va, _QWORD);
        v8 = &v9;
      }
      else
      {
        v8 = (__int64 *)((char *)va[0].reg_save_area + (int)va[0].gp_offset);
        va[0].gp_offset += 8;
      }
      var_args->vm_regs[*ii] = *v8;             // push arguments on registers
      if ( i > 6 )
        break;
      ++ii;
    }
  }
  if ( a2_is_2 >= 9 ) {                         // this never happens
    /* ... */
  }

  stack = var_args->sp;
  *(_QWORD *)(stack - 8) = 0x13371337LL;        // push 0x13371337
  var_args->sp = stack - 8;
  first_pc = var_args->vm_prog_start + a1_is_0; // first insn is always 0
  var_args->pc = first_pc;
  while ( var_args->pc != 0x13371337 )          // emulate instructions until pc becomes 0x13371337
                                                // (probably we do a `ret`)
    u_emu_insn(var_args);
  var_args->sp = sp;
  return var_args->vm_regs[0];
}
```


This function prepares the VM environment: It initializes the stack and registers as follows:
```
R0  = key
R1  = len(key)
R30 = SP
R31 = PC
```

It also pushes the address **0x13371337** on stack. When the VM executes the last `RET`, the `PC`
takes that value and emulation stops.

The VM bytecode is located at **0x4040**:
```assembly
.data:0000000000004040 glo_VM_PROG     dd 1080F708h, 8801706h, 340h, 0, 76626F3Fh, 625Ch, 340h
.data:0000000000004040                                         ; DATA XREF: u_emu_vm+C0↑o
.data:000000000000405C                 dd 0, 0FFFFFFFFh, 460805h, 12400823h, 0E7001034h, 7006048h
```

The VM context is defined as follows:
```
00000000 vm_ctx          struc ; (sizeof=0x118, copyof_9)
00000000 vm_regs         dq 30 dup(?)
000000F0 sp              dq ?
000000F8 pc              dq ?
00000100 vm_prog_start   dq ?
00000108 vm_prog_end     dq ?
00000110 decr_key        dq ?
00000118 vm_ctx          ends
```

Finally we have the `u_emu_insn()` that emulates a single instruction:
```c
void __fastcall u_emu_insn(vm_ctx *ctx) {
  /* ... */

  pc = (unsigned int *)ctx->pc;
  insn_orig = *pc;                              // next 4 byte instruction
  next_pc = (__int64)(pc + 1);
  ctx->pc = (__int64)(pc + 1);                  // update pc
  insn = _byteswap_ulong(insn_orig);
  // INSTRUCTION LAYOUT:
  //   * First 3 bits are for instruction type:
  //     * 000 ~> Arithmetic
  //     * 001 ~> Branch/Conditional
  //     * 010 ~> Memory access
  type = (unsigned int)insn >> 29;              // get 3 MSBits
  // ARITHMETIC INSTRUCTIONS
  // (or branch instructions with condition; 2 cases are mixed)
  if ( (unsigned int)insn < 0x20000000 || type == 1 && (insn & 0x10000000) == 0 )
  {
    dst_reg = ((unsigned int)insn >> 19) & 0x1F;// 5 bits for destination register
    // type == 1 && opcode LSBit == 1 OR
    // type == 0 && opcode LSBit == 0
    if ( (BYTE3(insn) & 1 & (type == 1)) != 0 || (insn & 0xE1000000) == 0 )
    {
      // opcodes 7 and 9 are for signed division/modulo
      if ( type == 1 || (unsigned int)insn >> 25 == 9 || (unsigned int)insn >> 25 == 7 )
        op2 = insn << 50 >> 50;
      else
        op2 = insn & 0x3FFF;
    }
    else
    {
      op2 = ctx->vm_regs[((unsigned int)insn >> 9) & 0x1F];// 5 bits for source register #2
    }
    op1 = ctx->vm_regs[((unsigned int)insn >> 14) & 0x1F];// 5 bits for source register #1
    opcode = (unsigned int)insn >> 25;          // 4 bits for opcode
    if ( type == 1 )                            // for ___conditional branch instructions
    {
      switch ( opcode & 7 )
      {
        case 0u:
          ctx->vm_regs[dst_reg] = op1 == op2;
          break;
        case 1u:
          ctx->vm_regs[dst_reg] = op1 != op2;
          break;
        case 2u:
          ctx->vm_regs[dst_reg] = op1 <= op2;
          break;
        case 3u:
          ctx->vm_regs[dst_reg] = op1 < op2;
          break;
        case 4u:
          ctx->vm_regs[dst_reg] = op1 <= (unsigned __int64)op2;
          break;
        case 5u:
          ctx->vm_regs[dst_reg] = op1 < (unsigned __int64)op2;
          break;
        default:
SET_REG_TO_ZERO:
          ctx->vm_regs[dst_reg] = 0LL;
          break;
      }
    }
    else                                        // type is 0 ~> Arithmetic insn
    {
      switch ( opcode & 0xF )
      {
        case 0u:
          res = op1 | op2;
          goto SET_REG;
        case 1u:
          res = op1 ^ op2;
          goto SET_REG;
        case 2u:
          res = op1 & op2;
          goto SET_REG;
        case 3u:
          res = op1 + op2;
          goto SET_REG;
        case 4u:
          res2 = op1 - op2;
          goto SET_REG_2;
        case 5u:
          res = op1 * op2;
SET_REG:
          ctx->vm_regs[dst_reg] = res;
          return;
        case 6u:
          ctx->vm_regs[dst_reg] = op1 / (unsigned __int64)op2;
          return;
        case 7u:
          ctx->vm_regs[dst_reg] = op1 / op2;
          return;
        case 8u:
          res2 = op1 % (unsigned __int64)op2;
          goto SET_REG_2;
        case 9u:
          res2 = op1 % op2;
          goto SET_REG_2;
        case 0xAu:
          res2 = op1 << op2;
          goto SET_REG_2;
        case 0xBu:
          res2 = op1 >> op2;
          goto SET_REG_2;
        case 0xCu:
          res2 = (unsigned __int64)op1 >> op2;
          goto SET_REG_2;
        case 0xDu:
          res2 = __ROL8__(op1, op2);
          goto SET_REG_2;
        case 0xEu:
          res2 = __ROR8__(op1, op2);
SET_REG_2:
          ctx->vm_regs[dst_reg] = res2;
          break;
        default:
          goto SET_REG_TO_ZERO;
      }
    }
    return;
  }
  // BRANCH INSTRUCTIONS (pt2)
  if ( type == 1 )
  {
    type = ((unsigned int)insn >> 26) & 3;      // redefine type
    if ( type == 2 )
    {
      reg = ((unsigned int)insn >> 20) & 0x1F;
      addr = (__int64 (__fastcall *)(__int64, __int64, __int64, __int64, __int64, __int64))ctx->vm_regs[reg];
      // check if address is outside of VM program region
      if ( (unsigned __int64)addr < ctx->vm_prog_start || (unsigned __int64)addr >= ctx->vm_prog_end )
      {
        ctx->vm_regs[0] = addr(                 // system call?
                            ctx->vm_regs[0],
                            ctx->vm_regs[1],
                            ctx->vm_regs[2],
                            ctx->vm_regs[3],
                            ctx->vm_regs[4],
                            ctx->vm_regs[5]);
        ctx->pc = next_pc;
      }
      else                                      // call (normal)
      {
        sp = ctx->sp;
        *(_QWORD *)(sp - 8) = next_pc;
        ctx->pc = ctx->vm_regs[reg];
        ctx->sp = sp - 8;
      }
      return;
    }
    if ( !type )                                // return instruction
    {
      sp_ = (__int64 *)ctx->sp;
      ctx->pc = *sp_;
      ctx->sp = (__int64)(sp_ + 1);
      return;
    }
    if ( (insn & 0x2000000) != 0 )              // Unconditional jump
    {
      shr = 0x25;
      shl = 0x27;
    }
    else
    {
      // Conditional jump
      if ( !ctx->vm_regs[((unsigned int)insn >> 20) & 0x1F] )
        goto END;
      shr = 0x2A;
      shl = 0x2C;
    }
    ctx->pc = (__int64)pc + ((__int64)((unsigned __int64)(unsigned int)insn << shl) >> shr);
END:
    if ( (insn & 0x2000000) == 0 )
      return;
  }
  // MEMORY ACCESS
  if ( type == 2 )
  {
    if ( (((unsigned int)insn >> 27) & 3) != 0 )// 27-28 bits for the type
    {
      reg1 = ((unsigned int)insn >> 21) & 0x1F; // 21 to 26
      reg2 = WORD1(insn) & 0x1F;                // 16 to 21
      base = (unsigned __int16)insn - 0x8000LL;
      if ( (insn & 0x8000u) == 0LL )
        base = (unsigned __int16)insn;
      if ( (((unsigned int)insn >> 27) & 3) == 1 )// load
      {
        ctx->vm_regs[reg1] = *(_QWORD *)(ctx->vm_regs[reg2] + base);
      }
      else
      {
        switch ( ((unsigned int)insn >> 26) & 3 )// store
        {
          case 0u:
            *(_BYTE *)(ctx->vm_regs[reg2] + base) = ctx->vm_regs[reg1];// 1 byte
            break;
          case 1u:
            *(_WORD *)(ctx->vm_regs[reg2] + base) = ctx->vm_regs[reg1];
            break;
          case 2u:
            *(_DWORD *)(ctx->vm_regs[reg2] + base) = ctx->vm_regs[reg1];
            break;
          case 3u:
            *(_QWORD *)(ctx->vm_regs[reg2] + base) = ctx->vm_regs[reg1];// 8 bytes
            break;
        }
      }
    }
    else                                        // load immediate
    {
      pc_ = (unsigned __int64 *)ctx->pc;
      imm = _byteswap_uint64(*pc_);             // 64 bits!
      ctx->pc = (__int64)(pc_ + 1);             // pc += 8
      ctx->vm_regs[WORD1(insn) & 0x1F] = imm;
    }
  }
}
```

That's a normal VM, so we can easily reverse it and write an emulator in python. Then we can
see the VM instructions (the full listing is in [vm_chk0.txt](./vm_chk0.txt)):
```
[+] VM program size: 0x3DC
[+] 0x000: SUB   SP, SP, 0x10
[+] 0x004: ADD   R2, SP, 0x8
[+] 0x008: MOV   R3, 0x3F6F6276
[+] 0x014: STR   R3, [R2 + 0x0]   ; R2 = 76 62 6f 3f
[+] 0x018: MOV   R3, 0xFFFFFFFF
[+] 0x024: AND   R1, R1, R3     
[+] 0x028: S.NE  R1, R1, 0x12     ; we need 18 digits
[+] 0x02C: JCC   0x39C (R1)

[+] 0x030: LDR   R3, [R0 + 0x7]   ; R3 = inp[7]
[+] 0x034: MOV   R1, 0xFF000000   
[+] 0x040: LDR   R4, [SP + 0x8]   ; R4 = 0x3F6F6276 
[+] 0x044: AND   R4, R4, R1       ;
[+] 0x048: SHR   R4, R4, 0x18     ; R4 = 0x3F
[+] 0x04C: AND   R3, R3, 0xFF
[+] 0x050: XOR   R3, R3, 0xC       ; 
[+] 0x054: S.NE  R3, R4, R3        ; 0x3F == inp[7] ^ 0xC ?
[+] 0x058: JCC   0x370 (R3)

[+] 0x05C: MOV   R3, 0x59631B35   ; R3 = 0x59631B35
[+] 0x068: LDR   R4, [SP + 0x8]   ; R4 = 0x3F6F6276
[+] 0x06C: MUL   R5, R4, R3       ; R5 = 0x59631B35 * 0x3F6F6276
[+] 0x070: MOV   R4, 0xB4B1A669   ; R4 = 0xB4B1A669
[+] 0x07C: ADD   R5, R5, R4       ; R5 = 0x59631B35 * 0x3F6F6276 + 0xB4B1A669
[+] 0x080: STR   R5, [R2 + 0x0]   ; *v = 0x59631B35 * 0x3F6F6276 + 0xB4B1A669
[+] 0x084: LDR   R5, [R0 + 0x8]   ; R5 = inp[8]
[+] 0x088: LDR   R6, [SP + 0x8]
[+] 0x08C: AND   R6, R6, R1       ; R6 = v & len
[+] 0x090: SHR   R6, R6, 0x18     ;
[+] 0x094: AND   R5, R5, 0xFF     ; MSByte(R6)
[+] 0x098: XOR   R5, R5, 0x47     ; R5 = inp[8] ^ 47
[+] 0x09C: S.NE  R5, R6, R5       ; v[3] == inp[8] ^ 47 ?
[+] 0x0A0: JCC   0x328 (R5)

....

[+] 0x39C: S.NE  R0, R1, R0
[+] 0x3A0: JCC   0x28 (R0)
[+] 0x3A4: LDR   R0, [SP + 0x8]
[+] 0x3A8: MUL   R0, R0, R3
[+] 0x3AC: ADD   R0, R0, R4
[+] 0x3B0: STR   R0, [R2 + 0x0]
[+] 0x3B4: MOV   R0, 0x1
[+] 0x3C0: ADD   SP, SP, 0x10
[+] 0x3C4: RET
[+] 0x3C8: MOV   R0, 0x0
[+] 0x3D4: ADD   SP, SP, 0x10
[+] 0x3D8: RET
```

First we check if the key is **18** bytes long and then we start comparing it byte by byte.
In each iteration we select a random byte from the key, perform some random computations and
we compare it against another random constant. Nothing particularly special here.

___


### Reversing chk1.bin

Now let's move on to the second binary (`chk1.bin`). This time things are more complicated:
```c
void __fastcall u_emu_insn(vm_ctx *ctx) {
  /* ... */
  pc = (int *)ctx->pc;
  insn_orig = *pc;
  next_pc = pc + 1;
  ctx->pc = (__int64)(pc + 1);
  key = ctx->decr_key;
  if ( !key )
  {
    ctx->decr_key = insn_orig;
    return;
  }
  A = key ^ (key << 13) ^ ((key ^ (unsigned int)(key << 13)) >> 17);
  B = A ^ (32 * A);
  ctx->decr_key = B;
  insn = B ^ insn_orig;
  v9 = (unsigned int)insn >> 29;
  if ( (unsigned int)insn < 0x20000000 || v9 == 1 && (insn & 0x10000000) == 0 ) {
      /* ... Same as chk0.bin ... */
  }
  if ( v9 == 1 )
  {
    v9 = ((unsigned int)insn >> 26) & 3;
    if ( v9 == 2 ) {
      /* ... Same as chk0.bin ... */
    }
    if ( !v9 ) {
      v15 = ctx->sp;
      ctx->pc = *(_QWORD *)v15;
      ctx->decr_key = *(_DWORD *)(v15 + 8);
      ctx->sp = v15 + 16;
      return;
    }
    C = B ^ (B << 13) ^ ((B ^ (B << 13)) >> 17) ^ (32 * (B ^ (B << 13) ^ ((B ^ (B << 13)) >> 17)));
    // reset to a new key
    new_key = C ^ *next_pc;
    ctx->decr_key = C;
    if ( (insn & 0x2000000) != 0 )  {
      offset = insn << 39 >> 37;
    }
    else  {
      if ( !ctx->regs[((unsigned int)insn >> 20) & 0x1F] )
      {
        ctx->pc = (__int64)(pc + 2);
        if ( (insn & 0x2000000) == 0 )
          return;
        goto LABEL_54;
      }
      offset = insn << 44 >> 42;
    }
    ctx->pc = (__int64)pc + offset;
    ctx->decr_key = new_key;
    if ( (insn & 0x2000000) == 0 )
      return;
  }
LABEL_54:
  if ( v9 == 2 )
  {
    if ( (((unsigned int)insn >> 27) & 3) != 0 ) {
        /* ... Same as chk0.bin ... */
    }
    else {
      pc_ = (_QWORD *)ctx->pc;
      A_ = ctx->decr_key ^ (ctx->decr_key << 13) ^ ((unsigned int)(ctx->decr_key ^ (ctx->decr_key << 13)) >> 17) ^ (32 * (ctx->decr_key ^ (ctx->decr_key << 13) ^ ((unsigned int)(ctx->decr_key ^ (ctx->decr_key << 13)) >> 17)));
      B_ = A_ ^ ((ctx->decr_key ^ (ctx->decr_key << 13) ^ ((unsigned int)(ctx->decr_key ^ (ctx->decr_key << 13)) >> 17) ^ (32 * (ctx->decr_key ^ (ctx->decr_key << 13) ^ ((unsigned int)(ctx->decr_key ^ (ctx->decr_key << 13)) >> 17)))) << 13) ^ (((unsigned int)A_ ^ ((ctx->decr_key ^ (ctx->decr_key << 13) ^ ((unsigned int)(ctx->decr_key ^ (ctx->decr_key << 13)) >> 17) ^ (32 * (ctx->decr_key ^ (ctx->decr_key << 13) ^ ((unsigned int)(ctx->decr_key ^ (ctx->decr_key << 13)) >> 17)))) << 13)) >> 17);
      C_ = B_ ^ (32 * B_);
      v30 = *pc_ ^ (A_ | ((unsigned __int64)C_ << 32));
      ctx->decr_key = C_;
      ctx->pc = (__int64)(pc_ + 1);
      ctx->regs[WORD1(insn) & 0x1F] = v30;
    }
  }
}
```

The `main()` and `u_emu_vm()` are basically the same. The `u_emu_insn()` is also the same
except that it has an **encrypted VM bytecode**. That is, the first **4** bytes of the VM
bytecode are used as a decryption key to decrypt subsequent instructions. The constants in
`MOV` instructions are also encrypted and special handling is needed for conditional jumps
to not mess up the decryption keys.

Furthermore, the VM bytecode is interpreted in **little endian** compared to the previous one
(recall the `insn = _byteswap_ulong(insn_orig);` instruction).

Emulating this binary is still possible as long as we are keeping track of the decryption keys.
The emulated VM program is the same as ([vm_chk0.txt](./vm_chk0.txt)) except that the constants
and the order that we compare the key bytes are different.
___


### Implementing A Generic VM Emulator

We continue looking at the other binaries and we draw the following conclusions:
 * Some VMs are in little endian
 * Some VMs are in big endian
 * Some VMs contain encrypted bytecode in little endian
 * Some VMs contain encrypted bytecode in big endian
 * There are different decryption algorithms for encrypted bytecode
   (e.g., variables `A`, `B` and `C` do change across binaries.)
 * Some VMs are **self-modifying**; That is, the modify their own VM bytecode.
 * Some checks involve **2** or **4** consecutive bytes from the key.

Since the bytes from the key are compared one by one, it is possible to bruteforce each byte
and count how many VM instructions we are executing. The correct byte will pass the check and
execute more instructions. The only challenge is to find the index of the byte we are testing
each time. This approach works but it takes **~30 seconds**, which is not acceptable given that
we have **1000** binaries. Even worse, some binaries compare **2** or **4** bytes from the key
at ones or they `XOR` the result with the expected byte and do an `OR`, so they perform only one check at the end if the result is **0** or not.

Given that, extending our VM emulator is not very scalable as there are too many different cases.
Instead we follow a different approach: We will use **unicorn** to **emulate the `chk*.bin` 
binaries**. We will let the **unicorn** decrypt the VM instruction (if it is encrypted) and
then we will process it accordingly. 

To deal with these different computation we will implement a minimal **symbolic execution**
on the VM: First we keep **a copy of the VM registers**. Every time a register is loaded with
a byte from the key, **we assign a symbolic variable** to the corresponding register in the
copy. After executing every VM instruction, we update the register copy.

When we reach the **final comparison instruction**, we will end up with **a symbolic expression**
that contains **exactly one symbolic variable** in one register and a constant in the
other register of the compare instruction. Then we use an **SMT solver** to solve the equation
and recover the correct value for the key.

We implement this approach in [mbins_vm_emulate_crack.py](./mbins_vm_emulate_crack.py).

After running the code for **~60 mins** we can recover the correct keys for **797** binaries.
___


### Optimizing the VM Emulator

We have **203** cases that fail. In fact they do not fail: They are just **super slow** as they
execute too many VM instructions. The first failing test is `chk17.bin`.
Let's see the VM instructions (the full listing is in [vm_chk17.txt](./vm_chk17.txt)):
```
[+] 0x000: SUB   SP, SP, 0x100           
[+] 0x004: MOV   R2, 0xFFFFFFFF          
[+] 0x010: AND   R1, R1, R2              
[+] 0x014: S.NE  R1, R1, 0x12            
[+] 0x018: JCC   0xA60 (R1)              

[+] 0x01C: MOV   R3, 0x0                 ; R3 = 0
[+] 0x028: ADD   R1, SP, 0x0             ; R1 = SP = buf
[+] 0x02C: ADD   R4, R3, 0x0             ; R4 = 0

[+] 0x030: ADD   R5, R1, R3              ; R5 = buf + i
[+] 0x034: STR.B R4, [R5 + 0x0]          ; buf[i] = i
[+] 0x038: ADD   R4, R4, 0x1             ; R4++
[+] 0x03C: ADD   R3, R3, 0x1             ; R3++
[+] 0x040: S.EQ  R5, R3, 0x100           ; R3 == 256 ?
[+] 0x044: JCC   0x8 (R5)                ; break
[+] 0x048: JCC   0x7FFFFE8 (R31)         ; loop back

[+] 0x04C: MOV   R3, 0x0                 ; R3 = 0          
[+] 0x058: MOV   R4, 0x33CA              ; R4 = 0x33CA
[+] 0x064: LDR   R5, [R1 + 0x7C]         ; R5 = buf[0x7C]
[+] 0x068: LDR   R6, [R1 + 0xAC]         ; R6 = buf[0xAC]
[+] 0x06C: STR.B R6, [R1 + 0x7C]         ; buf[0x7C] = buf[0xAC]
[+] 0x070: LDR   R6, [R1 + 0xA]          ; R6 = buf[0xA]
[+] 0x074: LDR   R7, [R1 + 0xF5]         ; R7 = buf[0xF5]
[+] 0x078: STR.B R7, [R1 + 0xA]          ; buf[0xA] = buf[0xF5]
[+] 0x07C: STR.B R6, [R1 + 0xAC]         ; buf[0xAC] = buf[0xA]
[+] 0x080: LDR   R6, [R1 + 0xEF]         ;
[+] 0x084: STR.B R6, [R1 + 0xF5]         ; continue shuffling
[+] 0x088: LDR   R6, [R1 + 0xBF]         

..... MUCH MORE SHUFFLING .....

[+] 0x85C: STR.B R6, [R1 + 0x41]         
[+] 0x860: STR.B R5, [R1 + 0x2A]         
[+] 0x864: AND   R5, R3, R2              
[+] 0x868: S.BT  R5, R5, R4              
[+] 0x86C: ADD   R3, R3, 0x1             
[+] 0x870: JCC   0x3FF7F4 (R5)           

[+] 0x874: LDR   R2, [R0 + 0x3]          ; R2 = key[3]
[+] 0x878: AND   R2, R2, 0xFF            ; R2 = key[3] & 0xFF 
[+] 0x87C: ADD   R2, R1, R2              ; R2 = buf[key[3] & 0xFF]
[+] 0x880: LDR   R2, [R2 + 0x0]          
[+] 0x884: AND   R2, R2, 0xFF            ; R2 = buf[key[3] & 0xFF] & 0xFF
[+] 0x888: XOR   R2, R2, 0xB8            ; R2 = buf[key[3] & 0xFF] & 0xFF ^ 0xBB = A

[+] 0x88C: LDR   R3, [R0 + 0x7]          ; R3 = key[7]
[+] 0x890: AND   R3, R3, 0xFF            ; R3 = key[7] & 0xFF
[+] 0x894: ADD   R3, R1, R3              
[+] 0x898: LDR   R3, [R3 + 0x0]
[+] 0x89C: AND   R3, R3, 0xFF            
[+] 0x8A0: XOR   R3, R3, 0x4C            ; R3 = buf[key[7] & 0xFF] & 0xFF ^ 0x4C = B
[+] 0x8A4: OR    R2, R3, R2              ; R3 = A | B

[+] 0x8A8: LDR   R3, [R0 + 0x6]          ;
[+] 0x8AC: AND   R3, R3, 0xFF            
[+] 0x8B0: ADD   R3, R1, R3              
[+] 0x8B4: LDR   R3, [R3 + 0x0]          
[+] 0x8B8: AND   R3, R3, 0xFF            
[+] 0x8BC: XOR   R3, R3, 0xFE            ; R3 = C
[+] 0x8C0: OR    R2, R2, R3              ; R2 = A | B | C

[+] 0x8C4: LDR   R3, [R0 + 0xD]          
[+] 0x8C8: AND   R3, R3, 0xFF            
[+] 0x8CC: ADD   R3, R1, R3              
[+] 0x8D0: LDR   R3, [R3 + 0x0]          
[+] 0x8D4: AND   R3, R3, 0xFF            
[+] 0x8D8: XOR   R3, R3, 0x56            ; R3 = D
[+] 0x8DC: OR    R4, R2, R3              ; R4 = A | B | C | D
[+] 0x8E0: LDR   R2, [R0 + 0x2]          ; R2 = key[2] & 0xff
[+] 0x8E4: AND   R5, R2, 0xFF            
[+] 0x8E8: LDR   R2, [R0 + 0x10]

..... MORE XORs .....

[+] 0xA54: OR    R0, R0, R1              
[+] 0xA58: LDR   R1, [R2 + 0x0]          
[+] 0xA5C: AND   R1, R1, 0xFF            
[+] 0xA60: XOR   R1, R1, 0xD7            
[+] 0xA64: OR    R0, R0, R1              

[+] 0xA68: S.EQ  R0, R0, 0x0             ; must be 0
[+] 0xA6C: AND   R0, R0, 0x1             
[+] 0xA70: ADD   SP, SP, 0x100           
[+] 0xA74: RET                           
```

This VM program starts by initializing an array with values `0, 1, 2, ..., 255`.
Then it enters a huge for loop that shuffles values in the array. This loop runs for **0x33CA** 
iterations, so it takes forever when we run it in unicorn. After the shuffling is complete,
program uses the bytes from the key as **indices** for the array to perform the following
checks: `buf[key[i] & 0xFF] & 0xFF ^ const == 0 ?` The result is stored in a register and it
is `OR`ed with the previous result. At the end we check if the result it **0** or not, so we
have only one check.

Instead of running this in **unicorn** we write our own VM emulator that loads the VM
bytecode and executes it directly. Then we focus on the `XOR` instructions only:
**It is possible to recover the key just from the XOR instructions.** The operation is:
`buf[key[i] & 0xFF] ^ const == 0 ?` We know `const` as it's the constant value in the `XOR`
instruction.

The moment we hook the `XOR` has already been executed. So, if we XOR the `const` with the
value in the register, we can recover `buf[key[i] & 0xFF]`. Since `buf` is a permutation of
all **256** numbers, we can uniquely **find its index from the value**. At this point we have
recovered `key[i] & 0xFF`. But we know that all key values are unique starting from **0xA0**
and incrementing by one. Thus, **by subtracting `0xA0` from the value we can find the key
index**. Finally we need to find the correct value for that index. We use the `const` value
from the `XOR` instruction and we do another scan in `buf` to find the correct index that
yields that value.

The script that implements the above approach is
[mbins_vm_custom_emu_crack.py](./mbins_vm_custom_emu_crack.py).

We run our script and after **~97 mins** we recover **192** more keys, so we have **989/1000**
which are enough to get the flag.

We still have **11** binaries that fail:
```
  250, 324, 424, 549, 618, 687, 712, 813, 860, 909, 948
```

These binaries probably use a different decryption algorithm (`A`, `B` and `C` variables),
but we don't care much.

Nevermind, we add the solutions in the [derive_key.sage](./derive_key.sage) script and we get the correct key:
```
  79d53a506cb3eb175b2c6ed996b3337e
```

Then we use it to decrypt the flag:
```
┌─[19:34:30]─[✗:1]─[ispo@ispo-glaptop2]─[~/ctf/hxp_2024/mbins/mbins]
└──> python3 decrypt_flag.py 79d53a506cb3eb175b2c6ed996b3337e
flag: hxp{ev3ryOne_has_th3ir_hammer_m!ne_i5_a_llvm_b4ck3nd}
```

So the flag is: `hxp{ev3ryOne_has_th3ir_hammer_m!ne_i5_a_llvm_b4ck3nd}`
___
