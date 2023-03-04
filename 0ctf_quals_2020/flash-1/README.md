## 0CTF 2020 - Flash-1 (Reversing 267)
##### 29/06 - 01/07/2020 (48hr)
___


### Description

-

___


### Solution

The first part of this challenge is to properly locate its assembly code. From the *run.sh* file
we can tell that `flash` is a MIPS BIOS file:
```
#! /bin/sh

qemu-system-mips -M mips -bios ./flash -nographic -m 16M -monitor /dev/null 2>/dev/null
```

If we run the program, it repeatedly asks for a flag:
```
Welcome to Flag Machine
Give me flag: 123
Try again!
Welcome to Flag Machine
Give me flag: 456
Try again!
....
```

We load `flash` into IDA and we select the **MIPS Big Endian** or `mipsb` architecture (I actually
tried all possible MIPS architectures and the only one that made sense was `mipsb`). According to
the [PIC32MX Memory Mapping](https://www.johnloomis.org/microchip/pic32/memory/memory.html), the
program should be loaded at address `0xBFC00000` (we always start execution from **ROM**). Program
performs two tasks: It sets up a software interrupt handler for timer events and loads the program
into **RAM**:
```assembly
ROM:BFC00000         .text # ROM
ROM:BFC00000         j       ROM_ENTRY_POINT_BFC01680
ROM:BFC00004         nop
ROM:BFC00008
...
ROM:BFC01680 ROM_ENTRY_POINT_BFC01680:                     # CODE XREF: ROM:BFC00000↑j
ROM:BFC01680         mtc0    $zero, SR                     # Status register
ROM:BFC01684         nop
ROM:BFC01688         mtc0    $zero, WatchLo                # Memory reference trap address low bits
ROM:BFC0168C         nop
ROM:BFC01690         mtc0    $zero, WatchHi                # Memory reference trap address high bits
ROM:BFC01694         nop
ROM:BFC01698         mfc0    $t0, Config                   # Configuration register
ROM:BFC0169C         li      $at, 0xFFFFFFF8
ROM:BFC016A0         and     $t0, $at
ROM:BFC016A4         ori     $t0, 2
ROM:BFC016A8         mtc0    $t0, Config                   # Configuration register
ROM:BFC016AC         lui     $sp, 0x803C
ROM:BFC016B0         li      $t0, timer_handler_BFC01550   # write handler to RAM
ROM:BFC016B8         sw      $t0, 0x80020008               # *0x80020008 = 0xBFC01550
ROM:BFC016C0         jal     load_prog_to_ram_BFC015E4
ROM:BFC016C4         nop
ROM:BFC016C8
ROM:BFC016C8 loc_BFC016C8:                                 # CODE XREF: ROM_ENTRY_POINT_BFC01680:loc_BFC016C8↓j
ROM:BFC016C8         j       loc_BFC016C8
```

Let's start with the function at `BFC015E4h`:
```assembly
ROM:BFC015E4 load_prog_to_ram_BFC015E4:                    # CODE XREF: ROM_ENTRY_POINT_BFC01680+40↓p
ROM:BFC015E4         addiu   $sp, -0x28
ROM:BFC015E8         sw      $ra, 0x20+var_s4($sp)
ROM:BFC015EC         sw      $fp, 0x20+var_s0($sp)
ROM:BFC015F0         move    $fp, $sp                      # prolog
ROM:BFC015F4         lui     $v0, 0xBFC1
ROM:BFC015F8         sw      $v0, 0x20+src_10($fp)         # src = 0xBFC10000
ROM:BFC015FC         lui     $v0, 0x8000
ROM:BFC01600         sw      $v0, 0x20+dst_C($fp)          # dst = 0x80000000
ROM:BFC01604         sw      $zero, 0x20+i_8($fp)
ROM:BFC01608         b       COPY_LOOP_END_BFC0163C
ROM:BFC0160C         nop
ROM:BFC01610
ROM:BFC01610 COPY_LOOP_BFC01610:                           # CODE XREF: load_prog_to_ram_BFC015E4+60↓j
ROM:BFC01610         lw      $v1, 0x20+src_10($fp)
ROM:BFC01614         addiu   $v0, $v1, 4                   # src += 4
ROM:BFC01618         sw      $v0, 0x20+src_10($fp)
ROM:BFC0161C         lw      $v0, 0x20+dst_C($fp)
ROM:BFC01620         addiu   $a0, $v0, 4                   # dst += 4
ROM:BFC01624         sw      $a0, 0x20+dst_C($fp)
ROM:BFC01628         lw      $v1, 0($v1)
ROM:BFC0162C         sw      $v1, 0($v0)                   # *(dst + 4*i) = *(src + 4*i) (word)
ROM:BFC01630         lw      $v0, 0x20+i_8($fp)
ROM:BFC01634         addiu   $v0, 1                        # ++i
ROM:BFC01638         sw      $v0, 0x20+i_8($fp)
ROM:BFC0163C
ROM:BFC0163C COPY_LOOP_END_BFC0163C:                       # CODE XREF: load_prog_to_ram_BFC015E4+24↑j
ROM:BFC0163C         lw      $v0, 0x20+i_8($fp)
ROM:BFC01640         slti    $v0, 0x1000                   # if i < 0x1000 then loop (copy 1 page)
ROM:BFC01644         bnez    $v0, COPY_LOOP_BFC01610
ROM:BFC01648         nop
ROM:BFC0164C         li      $v0, 0x80000500               # call function at adddress 0x80000500
ROM:BFC01654         jalr    $v0                           # that is, whatever is at 0xBFC10500
ROM:BFC01658         nop
ROM:BFC0165C         nop
ROM:BFC01660         move    $sp, $fp                      # epilog
ROM:BFC01664         lw      $ra, 0x20+var_s4($sp)
ROM:BFC01668         lw      $fp, 0x20+var_s0($sp)
ROM:BFC0166C         addiu   $sp, 0x28
ROM:BFC01670         jr      $
```

This function simply copies **4KB** of code from address `0xBFC10000` (**ROM**) into `0x80000000`
which is where **RAM** starts. Then it invokes the function located at `0x80000500`.

Reversing the code directly from 0xBFC10000, is going to be hard as the constant addresses will
be based on RAM's based address`0x80000000`. Therefore, we launch a new IDA instance and we reload
the program at address such that `0xBFC10000` maps to `0x80000000`. That is, we load program
at address `0x7FFF000`.

Let's see the timer handler at `0xBFC01550`, which is more complicated:
```c
void __fastcall timer_handler_BFC01550(registers *a1) {
  /* ... */
  if ( !MEMORY[0x80020000] )
    timer_init_BFC014D0();
  ret_addr = a1->ra_;                           // address of spinlock
  obj = timer_bin_search_BFC00744((struc_1 *)0x80020000, &ret_addr);
  if ( obj )
    a1->ra_ = obj->second;                      // update return address
}

void __cdecl timer_init_BFC014D0() {
  /* ... */
  timer_BFC00578((struc_1 *)0x80020000);
  for ( i = &glo_big_tbl_BFC20000; i->first; ++i )
    timer_add_BFC005E0((struc_1 *)0x80020000, (int)i);
}
```

```assembly
ROM:BFC20000  # pair glo_big_tbl_BFC20000
ROM:BFC20000 glo_big_tbl_BFC20000:pair <0x53ABC57E, 0x53ABE9FE>
ROM:BFC20008         pair <0x53ABC56E, 0x53ABE9EA>
ROM:BFC20010         pair <0x53ABC512, 0x53ABE996>
ROM:BFC20018         pair <0x53ABC532, 0x53ABE982>
ROM:BFC20020         pair <0x53ABC6CE, 0x53ABE9AE>
ROM:BFC20028         pair <0x53ABC6FE, 0x53ABE95A>
ROM:BFC20030         pair <0x53ABC6EE, 0x53ABE946>
ROM:BFC20038         pair <0x53ABC696, 0x53ABE972>
ROM:BFC20040         pair <0x53ABC6BE, 0x53ABE91E>
ROM:BFC20048         pair <0x53ABC6AE, 0x53ABE90A>
ROM:BFC20050         pair <0x53ABC64E, 0x53ABE936>
ROM:BFC20058         pair <0x53ABC662, 0x53ABE922>
....
```

This function takes the value of the `$ra` register and uses it as a key to search in a binary
tree. If the value is found, the contents of `$ra` are being updated. If the data structure is
empty it gets initialized with the values at `0x80020000` (or `0xBFC20000` before the relocation);
the first value of the pair is the key, the second is the returned value. This looks like an
anti-reversing protection as the value of the return address gets tampered when the timer interrupt
handler is called. We will get back to that later on.


### Reversing the RAM Code

Let's not move on the code in **RAM**. First instruction is at `0x80000500`:
```assembly
RAM:80000500  # void __noreturn RAM_ENTRY_POINT_80000500()
RAM:80000500 RAM_ENTRY_POINT_80000500:                # CODE XREF: RAM:7FFF1654↑p
RAM:80000500                                          # DATA XREF: RAM:7FFF164C↑o
RAM:80000500         jal     init_counter_80000564
RAM:80000504         nop
RAM:80000508         li      $t0, 0x10008001          # enable interrupt at level 7
RAM:80000510         mtc0    $t0, SR                  # Status register
RAM:80000514         lui     $sp, 0x804C              # initialize stack (0x804c0000)
RAM:80000518         j       u_print_welcome_80000D34  # function prolog
RAM:8000051C         nop
```

Program initializes a timing counter (see
[coprocessor 0](https://en.wikichip.org/wiki/mips/coprocessor_0)) and invokes `0x80000D34` to
print the welcome message:

```assembly
RAM:80000564 init_counter_80000564:                   # CODE XREF: RAM_ENTRY_POINT_80000500↑p
RAM:80000564                                          # sub_8000264C+1C↓p
RAM:80000564         li      $t0, 0x1000
RAM:80000568         mtc0    $t0, Compare             # Timer Compare
RAM:8000056C         mtc0    $zero, Count             # Timer Count
RAM:80000570         jr      $ra                      # return
RAM:80000574         nop
```

```assembly
RAM:80000D34 u_print_welcome_80000D34:                # CODE XREF: RAM_ENTRY_POINT_80000500+18↑j
RAM:80000D34
RAM:80000D34 var_s0  =  0
RAM:80000D34 var_s4  =  4
RAM:80000D34
RAM:80000D34         addiu   $sp, -0x20
RAM:80000D38         sw      $ra, 0x18+var_s4($sp)
RAM:80000D3C         sw      $fp, 0x18+var_s0($sp)
RAM:80000D40         move    $fp, $sp
RAM:80000D44         lui     $v0, 0x8000              # v0 = 0x80000000
RAM:80000D48         addiu   $a0, $v0, (aWelcomeToFlagM - 0x80000000)  # "Welcome to Flag Machine"
RAM:80000D4C         mtc0    $zero, Count             # Timer Count
RAM:80000D50
RAM:80000D50 SPINLOCK_80000D50:                       # CODE XREF: u_print_welcome_80000D34:SPINLOCK_80000D50↓j
RAM:80000D50         b       SPINLOCK_80000D50
RAM:80000D54         nop
```

After the welcome message is printed, functions enters into a spinlock at `0x80000D50`. This is
weird since the program later on asks for a flag, so there must be something else going on. To find
the answer we check the address at `0x80000180`:
```assembly
RAM:80000080         nop
RAM:80000084         nop
....
RAM:8000017C         nop
RAM:80000180         move    $k1, $sp
RAM:80000184         li      $sp, 0x8043FF6C
RAM:8000018C         sw      $at, arg_0($sp)
RAM:80000190         sw      $v0, arg_4($sp)
RAM:80000194         sw      $v1, arg_8($sp)
RAM:80000198         sw      $a0, arg_C($sp)
RAM:8000019C         sw      $a1, arg_10($sp)
RAM:800001A0         sw      $a2, arg_14($sp)
RAM:800001A4         sw      $a3, arg_18($sp)
RAM:800001A8         sw      $t0, arg_1C($sp)
RAM:800001AC         sw      $t1, arg_20($sp)
RAM:800001B0         sw      $t2, arg_24($sp)
RAM:800001B4         sw      $t3, arg_28($sp)
RAM:800001B8         sw      $t4, arg_2C($sp)
RAM:800001BC         sw      $t5, arg_30($sp)
RAM:800001C0         sw      $t6, arg_34($sp)
RAM:800001C4         sw      $t7, arg_38($sp)ni
RAM:800001C8         sw      $s0, arg_3C($sp)
RAM:800001CC         sw      $s1, arg_40($sp)
RAM:800001D0         sw      $s2, arg_44($sp)
RAM:800001D4         sw      $s3, arg_48($sp)
RAM:800001D8         sw      $s4, arg_4C($sp)
RAM:800001DC         sw      $s5, arg_50($sp)
RAM:800001E0         sw      $s6, arg_54($sp)
RAM:800001E4         sw      $s7, arg_58($sp)
RAM:800001E8         sw      $t8, arg_5C($sp)
RAM:800001EC         sw      $t9, arg_60($sp)
RAM:800001F0         sw      $gp, arg_6C($sp)
RAM:800001F4         sw      $k1, arg_70($sp)
RAM:800001F8         sw      $fp, arg_74($sp)
RAM:800001FC         sw      $ra, arg_78($sp)
RAM:80000200         mfc0    $t0, EPC                 # Exception Program Counter
RAM:80000204         sw      $t0, arg_7C($sp)
RAM:80000208         mfc0    $t0, ErrorEPC            # Error Exception Program Counter
RAM:8000020C         sw      $t0, arg_80($sp)
RAM:80000210         mfc0    $t0, SR                  # Status register
RAM:80000214         sw      $t0, arg_84($sp)
RAM:80000218         addi    $a0, $sp, arg_0
RAM:8000021C         lw      $k0, off_80003D20
RAM:80000224         jalr    $k0
RAM:80000228         nop
RAM:8000022C         nop
RAM:80000230         lw      $t0, arg_7C($sp)
RAM:80000234         mtc0    $t0, EPC                 # Exception Program Counter
RAM:80000238         lw      $t0, arg_80($sp)
RAM:8000023C         mtc0    $t0, ErrorEPC            # Error Exception Program Counter
RAM:80000240         lw      $t0, arg_84($sp)
RAM:80000244         mtc0    $t0, SR                  # Status register
RAM:80000248         lw      $v0, arg_4($sp)
RAM:8000024C         lw      $v1, arg_8($sp)
RAM:80000250         lw      $a0, arg_C($sp)
RAM:80000254         lw      $a1, arg_10($sp)
RAM:80000258         lw      $a2, arg_14($sp)
RAM:8000025C         lw      $a3, arg_18($sp)
RAM:80000260         lw      $t0, arg_1C($sp)
RAM:80000264         lw      $t1, arg_20($sp)
RAM:80000268         lw      $t2, arg_24($sp)
RAM:8000026C         lw      $t3, arg_28($sp)
RAM:80000270         lw      $t4, arg_2C($sp)
RAM:80000274         lw      $t5, arg_30($sp)
RAM:80000278         lw      $t6, arg_34($sp)
RAM:8000027C         lw      $t7, arg_38($sp)
RAM:80000280         lw      $s0, arg_3C($sp)
RAM:80000284         lw      $s1, arg_40($sp)
RAM:80000288         lw      $s2, arg_44($sp)
RAM:8000028C         lw      $s3, arg_48($sp)
RAM:80000290         lw      $s4, arg_4C($sp)
RAM:80000294         lw      $s5, arg_50($sp)
RAM:80000298         lw      $s6, arg_54($sp)
RAM:8000029C         lw      $s7, arg_58($sp)
RAM:800002A0         lw      $t8, arg_5C($sp)
RAM:800002A4         lw      $t9, arg_60($sp)
RAM:800002A8         lw      $gp, arg_6C($sp)
RAM:800002AC         lw      $k1, arg_70($sp)
RAM:800002B0         lw      $fp, arg_74($sp)
RAM:800002B4         lw      $ra, arg_78($sp)
RAM:800002B8         move    $sp, $k1
RAM:800002BC         eret
```

This function performs a **context switch**: It saves all registers to stack, then it calls function
at `off_80003D20` and then restores the context:
```assembly
RAM:80003D20 off_80003D20:.word u_xor_ra_80002610     # DATA XREF: u_exception_handler_80000080+19C↑r
```

Function `u_xor_ra_80002610` simply XORs `$ra` with the const `0xD3ABC0DE`:
```assembly
RAM:80002610         addiu   $sp, -0x18
RAM:80002614         sw      $ra, 0x10+var_s4($sp)
RAM:80002618         sw      $fp, 0x10+var_s0($sp)
RAM:8000261C         move    $fp, $sp
RAM:80002620         sw      $a0, 0x10+arg_0($fp)
RAM:80002624         lw      $v0, 0x10+arg_0($fp)
RAM:80002628         lw      $v1, 0x7C($v0)
RAM:8000262C         li      $v0, 0xD3ABC0DE
RAM:80002634         xor     $v1, $v0
RAM:80002638         lw      $v0, 0x10+arg_0($fp)
RAM:8000263C         sw      $v1, 0x7C($v0)
RAM:80002640         lw      $a0, 0x10+arg_0($fp)     # a1
RAM:80002644         jal     sub_80000524
RAM:80002648         nop
```

Then it invokes `sub_80000524` that makes a system call:
```
RAM:80000524         mfc0    $t0, SR                  # Status register
RAM:80000528         addiu   $sp, -8
RAM:8000052C         sw      $t0, 4+var_4($sp)
RAM:80000530         sw      $ra, 4+var_s0($sp)
RAM:80000534         li      $t0, 0x400004
RAM:8000053C         mtc0    $t0, SR                  # Status register
RAM:80000540         syscall
RAM:80000544         nop
RAM:80000548         lw      $t0, 4+var_4($sp)
RAM:8000054C         lw      $ra, 4+var_s0($sp)
RAM:80000550         mfc0    $t0, SR                  # Status register
RAM:80000554         addiu   $sp, 8
RAM:80000558         jr      $ra
RAM:8000055C         nop
```

This system call invokes the timer handler from **ROM** (`timer_handler_BFC01550`).

The address `0x80000180` is not random; If we look at
[here](http://contents2.kocw.or.kr/KOCW/document/2013/soongsil/kimbyounggi1031/19.pdf) (slide **14**),
we will that upon an interrupt, the MIPS processor executes the code located at address `0x80000180`.

Now everything becomes clear: Program initializes a counter and then executes some code until it
hits the spinlock, where it waits until the time interrupt is triggered. Then, it invokes the
interrupt handler at `0x80000180`, where it XORs the return address at `$ra` register with
`0xD3ABC0DE`. Then, it makes a syscall to `timer_handler_BFC01550` where it uses the XORed value of
`$ra` as a key to search into a tree that contains the values from `glo_big_tbl_BFC20000` (which is
essentially a *hashmap*) to find the corresponding value. If that value is found, then program
assigns it to the `$ra` and resumes execution. However, the new value is also XORed with `0xD3ABC0DE`,
so it needs to be XORed again before execution returns. This is where syscall at `0x8000264C` is
called to get the final `$ra` value:
```assembly
RAM:8000264C         lw      $v0, 0x18($fp)
RAM:80002650         lw      $v1, 0x7C($v0)
RAM:80002654         li      $v0, 0xD3ABC0DE
RAM:8000265C         xor     $v1, $v0
RAM:80002660         lw      $v0, 0x18($fp)
RAM:80002664         sw      $v1, 0x7C($v0)
RAM:80002668         jal     init_counter_80000564
RAM:8000266C         nop
RAM:80002670         nop
RAM:80002674         move    $sp, $fp
RAM:80002678         lw      $ra, arg_14($sp)
RAM:8000267C         lw      $fp, e($sp)
RAM:80002680         addiu   $sp, 0x18
RAM:80002684         jr      $ra
RAM:80002688         nop
```


### Bypassing the Anti-Reversing Protection

This protection makes debugging really annoying so we have to get rid of it. If we XOR all entries
from the `glo_big_tbl_BFC20000` we can get the next address from every spinlock:
```
  0x800005A0 ~> 0x80002920
  0x800005B0 ~> 0x80002934
  0x800005CC ~> 0x80002948
  0x800005EC ~> 0x8000295C
  0x80000610 ~> 0x80002970
  0x80000620 ~> 0x80002984
  0x80000630 ~> 0x80002998
  0x80000648 ~> 0x800029AC
  ...
  0x80000D50 ~> 0x80002E34
  0x80000D64 ~> 0x80002E48
````

We can see for example that when execution gets stuck in at `0x80000D50` (inside 
`u_print_welcome_80000D34`), then execution resumes at `0x80002E34`. We write a quick IDAPython
script (see [patch_timing_anti_re.py](./patch_timing_anti_re.py) for more details) to replace
all spinlocks with jumps to the appropriate locations:
```python
for i in range(257):
  a = ida_bytes.get_dword(0x80010000 + 8*i)       # Address of spinlock
  b = ida_bytes.get_dword(0x80010000 + 8*i + 4)   # Address to continue

  a ^= 0xD3ABC0DE
  b ^= 0xD3ABC0DE
  b //= 4
  # Replace with a J instruction
  ida_bytes.patch_dword(a,  0x08000000 | b & 0xFFFF )

  # Make previous instruction a nop:
  #     mtc0    $zero, Count             # Timer Count
  ida_bytes.patch_dword(a - 4, 0x00000000)
```

After that, we "apply the changes to the input file" and we have a new, patched binary (call it
`flash_fixed`). We also run it to make sure that it works as expected. At this point we can load
the patch program into [pwndbg](https://github.com/pwndbg/pwndbg) and debug it!


### Setting Up PwnDbg

Properly setting up PwnDbg was also a small challenge. First we add the `-s` (shortcut for 
`-gdb tcp::1234`) and `-S` flags to qemu to prepare it for debugging:
```
qemu-system-mips -D /tmp/qemu-debug-log 
                 -s -S
                 -M mips
                 -bios ./flash_fixed
                 -nographic 
                 -m 16M 
                 monitor /dev/null 2>/dev/null
 ```

The we set up pwndbg:
```
pwndbg> file flash_fixed

"/home/ispo/ctf/0ctf_2020/flash-1/flash_fixed": not in executable format: file format not recognized
pwndbg> set endian big

The target is set to big endian.
pwndbg> set architecture mips:isa32

The target architecture is set to "mips:isa32".
pwndbg> target remote 192.168.3.144:1234

Remote connection closed
pwndbg> target remote 192.168.3.144:1234

Remote debugging using 192.168.3.144:1234
warning: No executable has been specified and target does not support
determining executable automatically.  Try using the "file" command.
0xbfc00000 in ?? ()
```

### Reversing the Challenge Code

We load the `flash_fixed` into pwndbg and we continue execution from `u_print_welcome_80000D34`.
After our fixes, we can see that function at `0x80000D34` is actually much bigger:
```assembly
pwndbg> pdisass 100

 ► 0x80000d34    addiu  $sp, $sp, -0x20
   0x80000d38    sw     $ra, 0x1c($sp)
   0x80000d3c    sw     $fp, 0x18($sp)
   0x80000d40    move   $fp, $sp
   0x80000d44    lui    $v0, 0x8000
   0x80000d48    addiu  $a0, $v0, 0x26c8        ; "Welcome to Flag Machine"
   0x80000d4c    nop    
   0x80000d50    j      0x80002e34              ; print message (character by character)
 
   0x80000d54    nop    
   0x80000d58    lui    $v0, 0x8000
   0x80000d5c    addiu  $a0, $v0, 0x26e0        ; "Give me flag: "
   0x80000d60    nop    
   0x80000d64    j      0x80002e48              ; print another message
 
   0x80000d68    nop    
   0x80000d6c    addiu  $a0, $zero, 0x800
   0x80000d70    nop    
   0x80000d74    j      0x80002e5c                    <0x80002e5c>
 
   0x80000d78    nop    
   0x80000d7c    sw     $v0, 0x10($fp)
   0x80000d80    addiu  $a1, $zero, 0x800
   0x80000d84    lw     $a0, 0x10($fp)
   0x80000d88    nop    
   0x80000d8c    j      0x80002e70              ; read from stdin
 
   0x80000d90    nop    
   0x80000d94    sw     $v0, 0x14($fp)
   0x80000d98    lw     $v0, 0x14($fp)
   0x80000d9c    addiu  $v0, $v0, -1
   0x80000da0    sw     $v0, 0x14($fp)
   0x80000da4    addiu  $a2, $zero, 5
   0x80000da8    lui    $v0, 0x8000
   0x80000dac    addiu  $a1, $v0, 0x26f0        ; "flag{"
   0x80000db0    lw     $a0, 0x10($fp)
   0x80000db4    nop    
   0x80000db8    j      0x80002e84              ; compare flag startswith "flag{"; v0 has cmp result
 
   0x80000dbc    nop    
   0x80000dc0    nop    
   0x80000dc4    j      0x80002e98              ; if 0 move on; else jump to try again
 
   0x80000dc8    nop    
   0x80000dcc    lw     $v0, 0x14($fp)
   0x80000dd0    addiu  $v0, $v0, -1
   0x80000dd4    lw     $v1, 0x10($fp)
   0x80000dd8    addu   $v0, $v1, $v0
   0x80000ddc    lb     $v1, ($v0)
   0x80000de0    addiu  $v0, $zero, 0x7d        ; '}'
   0x80000de4    nop    
   0x80000de8    j      0x80002eac              ; strchr(flag, '}')

   0x80000dec    nop    
   0x80000df0    lw     $v0, 0x14($fp)          ; v0 index of '}'
   0x80000df4    addiu  $v0, $v0, -6            ; v0 inside flag length ("flag{ISPOLEET}")
   0x80000df8    sw     $v0, 0x14($fp)
   0x80000dfc    lw     $v0, 0x10($fp)
   0x80000e00    addiu  $v0, $v0, 5             ; v0 ~> & ISPOLEET (skip "flag{" part)
   0x80000e04    lw     $v1, 0x14($fp)
   0x80000e08    move   $a2, $v1                ; arg3: inside flag length len("ISPOLEET")
   0x80000e0c    move   $a1, $v0                ; arg2: ISPOLEET}\n"
   0x80000e10    lw     $a0, 0x10($fp)          ; arg1: "flag{ISPOLEET}\n"
   0x80000e14    nop    
   0x80000e18    j      0x80002ec0              ; strncpy(flag, &flag[5], inside_flag_len)
 
   0x80000e1c    nop    
   0x80000e20    lw     $v0, 0x14($fp)
   0x80000e24    lw     $v1, 0x10($fp)
   0x80000e28    addu   $v0, $v1, $v0
   0x80000e2c    sb     $zero, ($v0)            ; flag[inside_flag_len] = 0
   0x80000e30    lw     $v0, 0x14($fp)
   0x80000e34    addiu  $v0, $v0, 1             ; v0 = inside_flag_len + 1
   0x80000e38    srl    $v1, $v0, 0x1f
   0x80000e3c    addu   $v0, $v1, $v0
   0x80000e40    sra    $v0, $v0, 1             ; v0 = (inside_flag_len + 1) // 2
   0x80000e44    move   $a1, $v0                ; arg2: (inside_flag_len + 1) >> 1
   0x80000e48    lw     $a0, 0x10($fp)          ; arg1: inside_flag
   0x80000e4c    nop    
   0x80000e50    j      0x80002ed4              ; do some initializations? idk..
 
   0x80000e54    nop                            ; v0: &foo, v1: &glo_const_tbl
   0x80000e58    nop    
   0x80000e5c    j      0x80002ee8              ; check flag and return 0 or 1
 
   0x80000e60    nop    
   0x80000e64    lui    $v0, 0x8000
   0x80000e68    lh     $v0, 0x3d24($v0)
   0x80000e6c    nop    
   0x80000e70    j      0x80002efc              ; if equal go to try again
 
   0x80000e74    nop    
   0x80000e78    lui    $v0, 0x8000
   0x80000e7c    addiu  $a0, $v0, 0x26f8        ; "Correct!"
   0x80000e80    nop    
   0x80000e84    j      0x80002f10                    <0x80002f10>
 
   0x80000e88    nop    
   0x80000e8c    nop    
   0x80000e90    j      0x80002f24                    <0x80002f24>
 
   0x80000e94    nop    
   0x80000e98    nop    
   0x80000e9c    nop    
   0x80000ea0    j      0x80002f38                    <0x80002f38>
 
   0x80000ea4    nop    
   0x80000ea8    nop    
   0x80000eac    lui    $v0, 0x8000
   0x80000eb0    addiu  $a0, $v0, 0x2704        ; "Try again!"
   0x80000eb4    nop    
   0x80000eb8    j      0x80002f4c                    <0x80002f4c>
 
   0x80000ebc    nop    
   0x80000ec0    nop    
   0x80000ec4    move   $sp, $fp
   0x80000ec8    lw     $ra, 0x1c($sp)
   0x80000ecc    lw     $fp, 0x18($sp)
   0x80000ed0    addiu  $sp, $sp, 0x20
   0x80000ed4    nop    
   0x80000ed8    j      0x80002f60                    <0x80002f60>
 
   0x80000edc    nop    
```

We do not really have to analyze all these functions. We can understand what they are doing just
by observing their input/outputs. The flag is checked at function `0x80002ee8`, which ends up
calling `0x8000081c`:
```assembly
0x80000e5c    j      0x80002ee8                    <0x80002ee8>
↓
0x80002ee8    jal    0x8000081c
↓
0x8000081c    addiu  $sp, $sp, -0x48
```

Let's look at how the flag is being verified:
```assembly
0x8000081c    addiu  $sp, $sp, -0x48            ; function prolog
0x80000820    sw     $ra, 0x44($sp)             ;
0x80000824    sw     $fp, 0x40($sp)             ;
0x80000828    move   $fp, $sp                   ;
0x8000082c    sw     $zero, 0x10($fp)           ;
0x80000830    nop                               ;
0x80000834    j      0x80002ab0                 ;
0x80000838    nop                               ;

0x8000083c VM_LOOP:                             ;
0x8000083c    lui    $v0, 0x8000                ;
0x80000840    addiu  $v0, $v0, 0x3d24           ; v0 = 0x80003d24 = &glo_vm_ctx
0x80000844    lw     $v0, 8($v0)                ; v0 = *(0x80003d24 + 8) = glo_vm_pc
0x80000848    lhu    $v0, ($v0)                 ; v0 = glo_vm_pc = &vm_prog[pc] (read VM insn opcode)
0x8000084c    sh     $v0, 0x14($fp)             ; var_14 = VM insn opcode
0x80000850    lui    $v0, 0x8000                ; 
0x80000854    addiu  $v0, $v0, 0x3d24           ;
0x80000858    lw     $v0, 8($v0)                ; v0 = *(0x80003d24 + 8) = glo_vm_pc
0x8000085c    addiu  $v1, $v0, 2                ; v1 = glo_vm_pc + 2 = &vm_prog[pc + 2]
0x80000860    lui    $v0, 0x8000                ; 
0x80000864    addiu  $v0, $v0, 0x3d24           ;
0x80000868    sw     $v1, 8($v0)                ; glo_vm_pc += 2 (advance to VM insn operands)
0x8000086c    lhu    $v0, 0x14($fp)             ; v0 = VM insn opcode
0x80000870    sltiu  $v1, $v0, 0xe              ; v1 = v0 < 0xe ? 1 : 0
0x80000874    nop                               ;
0x80000878    j      0x80002ac4                 ; bound check; we have 14 VM instructions
0x8000087c    nop                               ;
0x80000880    sll    $v1, $v0, 2                ; v1 = VM insn opcode * 4 (find table entry)
0x80000884    lui    $v0, 0x8000                ;
0x80000888    addiu  $v0, $v0, 0x2690           ; v0 = 0x80002690 = VM instruction table
0x8000088c    addu   $v0, $v1, $v0              ;
0x80000890    lw     $v0, ($v0)                 ; v0 = vm_insn[vm_opcode]
0x80000894    nop                               ;
0x80000898    j      0x80002ad8                 ; execute VM instruction and loop back to VM_LOOP
  ↓
0x80002ad8    jr     $v0                        ; call VM instruction
  ↓
0x80000a1c    nop                               ;
0x80000a20    j      0x80002c54                 ; ...
```

Here we have a mini VM :$. VM context is located at `0x80003d24`. VM PC is initialized to
`0x80003D40`, where it is the emulated program:
```
  0x0009, 0x091D, 0x0009, 0x0000, 0x000A, 0x0005, 0x0006, 0x0014, 0x0009, 0x0001,
  ...
```

Program is parsed into **half-words**. First program reads the opcode and uses it to dispatch it to
the appropriate VM instruction. VM instruction table is located at `0x80002690` and contains **14**
VM instructions:
```assembly
RAM:80002690 glo_VM_INSN_TBL_80002690:                # DATA XREF: RAM:80000884↑o
RAM:80002690         .word loc_800008A0         ; VM INSN #0 : add
RAM:80002694         .word loc_800008EC         ; VM INSN #1 : sub
RAM:80002698         .word loc_80000938         ; VM INSN #2 : mul
RAM:8000269C         .word loc_80000980         ; VM INSN #3 : modulo
RAM:800026A0         .word loc_800009CC         ; VM INSN #4 : cmp <
RAM:800026A4         .word loc_80000A1C         ; VM INSN #5 : cmp ==
RAM:800026A8         .word loc_80000A70         ; VM INSN #6 : je
RAM:800026AC         .word loc_80000AFC         ; VM INSN #7 : jne
RAM:800026B0         .word loc_80000B88         ; VM INSN #8 : read from input table
RAM:800026B4         .word loc_80000BD0         ; VM INSN #9 : push imm
RAM:800026B8         .word loc_80000C20         ; VM INSN #10: push reg
RAM:800026BC         .word loc_80000C48         ; VM INSN #11: pop reg
RAM:800026C0         .word loc_80000C6C         ; VM INSN #12: pop
RAM:800026C4         .word loc_80000C84         ; VM INSN #13: halt
```

Let's look at them one by one:
```assembly
; ------------------------------ VM INSTRUCTION #0 ------------------------------
;
; Add the first 2 arguments to the stack (result truncated in .half) and put the
; result back to the stack.
;
0x800008a0    nop                               ;
0x800008a4    j      0x80002aec                 ; stack pop
0x800008a8    nop                               ;
0x800008ac    sh     $v0, 0x3a($fp)             ; var_3a = stack top
0x800008b0    nop                               ;
0x800008b4    j      0x80002b00                 ; stack pop
0x800008b8    nop                               ;
0x800008bc    sh     $v0, 0x3c($fp)             ; var_3c = stack top 2
0x800008c0    lhu    $v1, 0x3a($fp)             ;
0x800008c4    lhu    $v0, 0x3c($fp)             ;
0x800008c8    addu   $v0, $v1, $v0              ; v0 = top + top2
0x800008cc    andi   $v0, $v0, 0xffff           ; truncate result to .half
0x800008d0    move   $a0, $v0                   ;
0x800008d4    nop                               ;
0x800008d8    j      0x80002b14                 ; stack push
0x800008dc    nop                               ;
0x800008e0    nop                               ;
0x800008e4    j      0x80002b28                 ; loop back to VM loop
0x800008e8    nop                               ;

; ------------------------------ VM INSTRUCTION #1 ------------------------------
;
; Subtract the top from the second argument on stack and store the result back
; to the stack.
;
0x800008ec    nop                               ;
0x800008f0    j      0x80002b3c                 ;
  ↓
0x80002b3c    jal    0x80000710                 ; stack pop

0x800008f8    sh     $v0, 0x36($fp)             ; var_36 = stack top
0x800008fc    nop                               ;
0x80000900    j      0x80002b50                 ;
  ↓
0x80002b50    jal    0x80000710                 ; stack pop

0x80000908    sh     $v0, 0x38($fp)             ; var_38 = stack pop 2
0x8000090c    lhu    $v1, 0x36($fp)             ; v1 = top1
0x80000910    lhu    $v0, 0x38($fp)             ; v0 = top2
0x80000914    subu   $v0, $v1, $v0              ; v0 = top1 - top2
0x80000918    andi   $v0, $v0, 0xffff           ; truncate result to 16 bits
0x8000091c    move   $a0, $v0                   ; a0 result
0x80000920    nop                               ;
0x80000924    j      0x80002b64                 ;
  ↓
0x80002b64    jal    0x80000794                 ; stack push

0x8000092c    nop                               ;
0x80000930    j      0x80002b78                 ;
  ↓
0x80002b78    b      0x80000c9c                 ; loop back to VM loop

; ------------------------------ VM INSTRUCTION #2 ------------------------------
;
; Pop the top 2 values from the stack & multiply them. Result goes back to accumulator
;
0x80000938    nop                               ;
0x8000093c    j      0x80002b8c                 ; stack pop
0x80000940    nop                               ;
0x80000944    sh     $v0, 0x32($fp)             ; var_34 = stack top
0x80000948    nop    
0x8000094c    j      0x80002ba0                 ; stack pop
0x80000950    nop                               ;
0x80000954    sh     $v0, 0x34($fp)             ; var_34 = stack top 2
0x80000958    lhu    $v1, 0x32($fp)             ;
0x8000095c    lhu    $v0, 0x34($fp)             ;
0x80000960    mul    $v0, $v1, $v0              ; v0 = top1 * top2 (.word)
0x80000964    move   $v1, $v0                   ;
0x80000968    lui    $v0, 0x8000                ;
0x8000096c    addiu  $v0, $v0, 0x3d24           ;
0x80000970    sw     $v1, 4($v0)                ; vm_ctx->acc = top1 * top2
0x80000974    nop                               ;
0x80000978    j      0x80002bb4                 ; loop back to VM loop
0x8000097c    nop                               ;

; ------------------------------ VM INSTRUCTION #3 ------------------------------
;
; Pop the top 1 value from the stack & divide it by the accumulator. Store modulo
; back to the stack.
;
0x80000980    nop                               ;
0x80000984    j      0x80002bc8                 ; stack pop
0x80000988    nop                               ;
0x8000098c    sh     $v0, 0x30($fp)             ; var_30 = stack top
0x80000990    lui    $v0, 0x8000                ;
0x80000994    addiu  $v0, $v0, 0x3d24           ;
0x80000998    lw     $v1, 4($v0)                ; v1 = accumulator 
0x8000099c    lhu    $v0, 0x30($fp)             ; var_30 = top
0x800009a0    teq    $v0, $zero, 7              ; catch division by 0
0x800009a4    divu   $zero, $v1, $v0            ; lo = accumator / top; hi = accumator % top
0x800009a8    mfhi   $v0                        ; v0 = accumator % top
0x800009ac    andi   $v0, $v0, 0xffff           ; trim result to 16-bits
0x800009b0    move   $a0, $v0                   ;
0x800009b4    nop                               ;
0x800009b8    j      0x80002bdc                 ; stack push
0x800009bc    nop                               ;
0x800009c0    nop                               ;
0x800009c4    j      0x80002bf0                 ; loop back to VM loop
0x800009c8    nop                               ;

; ------------------------------ VM INSTRUCTION #4 ------------------------------
;
; Compare 2 top arguments from stack. If top1 < top2 store 1 back to stack.
; Otherwise store 0 back to stack.
;
0x800009cc    nop                               ;
0x800009d0    j      0x80002c04                 ; stack pop
0x800009d4    nop                               ;
0x800009d8    sh     $v0, 0x2c($fp)             ; var_2c = stack top
0x800009dc    nop                               ;
0x800009e0    j      0x80002c18                 ; stack pop
0x800009e4    nop                               ;
0x800009e8    sh     $v0, 0x2e($fp)             ; var_2e = stack top 2
0x800009ec    lhu    $v1, 0x2c($fp)             ;
0x800009f0    lhu    $v0, 0x2e($fp)             ;
0x800009f4    sltu   $v0, $v1, $v0              ; v0 = top1 < top2 ?
0x800009f8    andi   $v0, $v0, 0xff             ;
0x800009fc    andi   $v0, $v0, 0xffff           ;
0x80000a00    move   $a0, $v0                   ;
0x80000a04    nop                               ;
0x80000a08    j      0x80002c2c                 ; stack push
0x80000a0c    nop                               ;
0x80000a10    nop                               ;
0x80000a14    j      0x80002c40                 ; jump back to VM loop
0x80000a18    nop                               ;

; ------------------------------ VM INSTRUCTION #5 ------------------------------
;
; Compare equal. Take 2 arguments of the stack and push back 1 if they are equal.
; Otherwise push 0.
; 
0x80000a1c    nop                               ;
0x80000a20    j      0x80002c54                 ;
  ↓
0x80002c54    jal    0x80000710                 ; stack pop

  
0x80000a28    sh     $v0, 0x28($fp)             ;
0x80000a2c    nop                               ;
0x80000a30    j      0x80002c68                 ;
  ↓
0x80002c68    jal    0x80000710                 ; stack pop

0x80000a38    sh     $v0, 0x2a($fp)             ; var_2a = v0
0x80000a3c    lhu    $v1, 0x28($fp)             ; v1 = var_28
0x80000a40    lhu    $v0, 0x2a($fp)             ; v0 = var_2a
0x80000a44    xor    $v0, $v1, $v0              ; v0 = v1 ^ v0
0x80000a48    sltiu  $v0, $v0, 1                ; v0 = v0 < 1 ? 1 : 0
0x80000a4c    andi   $v0, $v0, 0xff             ;
0x80000a50    andi   $v0, $v0, 0xffff           ;
0x80000a54    move   $a0, $v0                   ; a0 = (v0 == v1) ?
0x80000a58    nop    
0x80000a5c    j      0x80002c7c                 ;
  ↓
0x80002c7c    jal    0x80000794                 ; push back to stack

0x80000a64    nop    
0x80000a68    j      0x80002c90                 ;
  ↓
0x80002c90    b      0x80000c9c                 ; loop back to VM loop

; ------------------------------ VM INSTRUCTION #6 ------------------------------
;
; pop from stack + jump taken if top of stack is 0.
;
0x80000a70    lui    $v0, 0x8000                ;
0x80000a74    addiu  $v0, $v0, 0x3d24           ; v0 = 0x80003d24 = vm_ctx
0x80000a78    lw     $v0, 8($v0)                ; v0 = vm_pc
0x80000a7c    lh     $v0, ($v0)                 ;
0x80000a80    sw     $v0, 0x20($fp)             ; var_20 = vm_prog[pc] (.half)
0x80000a84    lui    $v0, 0x8000                ;
0x80000a88    addiu  $v0, $v0, 0x3d24           ;
0x80000a8c    lw     $v0, 8($v0)                ; v0 = vm_pc
0x80000a90    addiu  $v1, $v0, 2                ; v1 = vm_pc + 2
0x80000a94    lui    $v0, 0x8000                ;
0x80000a98    addiu  $v0, $v0, 0x3d24           ;
0x80000a9c    sw     $v1, 8($v0)                ; vm_pc += 2
0x80000aa0    nop                               ;
0x80000aa4    j      0x80002ca4                 ;
 ↓
0x80002ca4    jal    0x80000710                 ; stack pop

0x80000aa8    nop                               ;
0x80000aac    sw     $v0, 0x24($fp)             ; var_24 = stack top
0x80000ab0    lw     $v0, 0x24($fp)             ;
0x80000ab4    nop                               ;
0x80000ab8    j      0x80002cb8                 ;
  ↓
0x80002cb8    beqz   $v0, 0x80000c9c            ;
  ↓
0x80000c9c    lw     $v0, 0x10($fp)             ;
0x80000ca0    nop                               ;
0x80000ca4    j      0x80002df8                 ;
  ↓
0x80002df8    beqz   $v0, 0x8000083c            ; go back to VM loop

0x80000abc    nop                               ;
0x80000ac0    lui    $v0, 0x8000                ;
0x80000ac4    addiu  $v0, $v0, 0x3d24           ; v0 = vm_ctx
0x80000ac8    lw     $v1, 8($v0)                ; v1 = vm_pc
0x80000acc    lw     $v0, 0x20($fp)             ; v0 = var_20 = imm from pc
0x80000ad0    srl    $a0, $v0, 0x1f             ; a0 = MSBit of v0
0x80000ad4    addu   $v0, $a0, $v0              ; v0 (2's complement)
0x80000ad8    sra    $v0, $v0, 1                ;
0x80000adc    sll    $v0, $v0, 1                ;
0x80000ae0    addu   $v1, $v1, $v0              ; v1 = vm_pc + off
0x80000ae4    lui    $v0, 0x8000                ;
0x80000ae8    addiu  $v0, $v0, 0x3d24           ;
0x80000aec    sw     $v1, 8($v0)                ; vm_pc += off
0x80000af0    nop                               ;
0x80000af4    j      0x80002ccc                 ;
  ↓
0x80002ccc    b      0x80000c9c                 ; loop back to VM loop

; ------------------------------ VM INSTRUCTION #7 ------------------------------
;
; pop from stack + jump taken if top of stack is not 0.
;
0x80000afc    lui    $v0, 0x8000                ;
0x80000b00    addiu  $v0, $v0, 0x3d24           ;
0x80000b04    lw     $v0, 8($v0)                ; v0 = &vm_ctx->pc
0x80000b08    lh     $v0, ($v0)                 ; v0 = &vm_prog[vm_pc]
0x80000b0c    sw     $v0, 0x18($fp)             ; var_18 = vm_prog[vm_pc] (.half)
0x80000b10    lui    $v0, 0x8000                ;
0x80000b14    addiu  $v0, $v0, 0x3d24           ;
0x80000b18    lw     $v0, 8($v0)                ;
0x80000b1c    addiu  $v1, $v0, 2                ; vm_pc += 2
0x80000b20    lui    $v0, 0x8000                ;
0x80000b24    addiu  $v0, $v0, 0x3d24           ;
0x80000b28    sw     $v1, 8($v0)                ;
0x80000b2c    nop                               ;
0x80000b30    j      0x80002ce0                 ;
  ↓
0x80002ce0    jal    0x80000710                 ; stack pop

0x80000b38    sw     $v0, 0x1c($fp)             ; var_1c = stack top
0x80000b3c    lw     $v0, 0x1c($fp)             ;
0x80000b40    nop                               ;
0x80000b44    j      0x80002cf4                 ;
  ↓
0x80002cf4    bnez   $v0, 0x80000c9c            ; if not 0 loop back to VM loop
  ↓
0x80002cfc    b      0x80000b48                 ; not zero, move on
  ↓
0x80000b48    nop                               ;
0x80000b4c    lui    $v0, 0x8000                ;
0x80000b50    addiu  $v0, $v0, 0x3d24           ;
0x80000b54    lw     $v1, 8($v0)                ; v1 = vm_pc
0x80000b58    lw     $v0, 0x18($fp)             ; v0 = var_18 = vm_prog[vm_pc]
0x80000b5c    srl    $a0, $v0, 0x1f             ;
0x80000b60    addu   $v0, $a0, $v0              ;
0x80000b64    sra    $v0, $v0, 1                ;
0x80000b68    sll    $v0, $v0, 1                ;
0x80000b6c    addu   $v1, $v1, $v0              ; v1 = vm_pc + vm_prog[vm_pc]
0x80000b70    lui    $v0, 0x8000                ;
0x80000b74    addiu  $v0, $v0, 0x3d24           ;
0x80000b78    sw     $v1, 8($v0)                ; vm_pc = v1
0x80000b7c    nop                               ;
0x80000b80    j      0x80002d08                 ;
  ↓
0x80002d08    b      0x80000c9c                 ; go back to VM loop

; ------------------------------ VM INSTRUCTION #8 ------------------------------
;
; Read a .half from input tape (this is where flag is stored)
;
;
0x80000b88    lui    $v0, 0x8000                ;
0x80000b8c    addiu  $v0, $v0, 0x3d24           ; v0 = vm_ctx
0x80000b90    lw     $v0, 0x18($v0)             ; v0 = &vm_inp
0x80000b94    lhu    $v0, ($v0)                 ; v0 = vm_inp[:2] (read 2 bytes from flag)
0x80000b98    move   $a0, $v0                   ; a0 = flag[:2]
0x80000b9c    nop                               ;
0x80000ba0    j      0x80002d1c                 ;
  ↓
0x80002d1c    jal    0x80000794                 ; stack push

0x80000ba4    nop                               ;
0x80000ba8    lui    $v0, 0x8000                ;
0x80000bac    addiu  $v0, $v0, 0x3d24           ; v0 = vm_ctx
0x80000bb0    lw     $v0, 0x18($v0)             ; vm = &vm_inp
0x80000bb4    addiu  $v1, $v0, 2                ; vm_inp += 2 (move pointer to the next .half)
0x80000bb8    lui    $v0, 0x8000                ;
0x80000bbc    addiu  $v0, $v0, 0x3d24           ;
0x80000bc0    sw     $v1, 0x18($v0)             ; store
0x80000bc4    nop                               ;
0x80000bc8    j      0x80002d30                 ;
  ↓
0x80002d58    b      0x80000c9c                 ; loop back to VM loop

; ------------------------------ VM INSTRUCTION #9 ------------------------------
;
; push imm (.half) to stack
; 
0x80000bd0    lui    $v0, 0x8000                ;
0x80000bd4    addiu  $v0, $v0, 0x3d24           ; v0 = vm_ctx
0x80000bd8    lw     $v0, 8($v0)                ; v0 = vm_pc
0x80000bdc    lhu    $v0, ($v0)                 ; v0 = vm_prog[pc] (.half) (read imm)
0x80000be0    sh     $v0, 0x16($fp)             ; var_16 = vm_prog[pc]
0x80000be4    lui    $v0, 0x8000                ;
0x80000be8    addiu  $v0, $v0, 0x3d24           ;
0x80000bec    lw     $v0, 8($v0)                ;
0x80000bf0    addiu  $v1, $v0, 2                ;
0x80000bf4    lui    $v0, 0x8000                ;
0x80000bf8    addiu  $v0, $v0, 0x3d24           ; 
0x80000bfc    sw     $v1, 8($v0)                ; vm_pc += 2
0x80000c00    lhu    $v0, 0x16($fp)             ;
0x80000c04    move   $a0, $v0                   ; a0 = imm
0x80000c08    nop                               ;
0x80000c0c    j      0x80002d44                 ;
  ↓
0x80002d44    jal    0x80000794                 ; stack push

0x80000c14    nop                               ;
0x80000c18    j      0x80002d58                 ;
  ↓
0x80002d58    b      0x80000c9c                 ; loop back to VM loop

; ------------------------------ VM INSTRUCTION #10 ------------------------------
; push vm reg to stack (originally, reg == len(flag) // 2 (.half))
;
0x80000c20    lui    $v0, 0x8000                ;
0x80000c24    lh     $v0, 0x3d24($v0)           ; v0 = vm_ctx->reg
0x80000c28    andi   $v0, $v0, 0xffff           ;
0x80000c2c    move   $a0, $v0                   ; a0 = vm_reg
0x80000c30    nop                               ;
0x80000c34    j      0x80002d6c                 ;
  ↓
0x80002d6c    jal    0x80000794                 ; stack push

0x80000c38    nop                               ;
0x80000c3c    nop                               ;
0x80000c40    j      0x80002d80                 ;
  ↓
0x80002d80    b      0x80000c9c                 ; loop back to VM loop

; ------------------------------ VM INSTRUCTION #11 ------------------------------
;
; pop from stack into VM reg (initialized to flag(len))
;
0x80000c48    nop                               ;
0x80000c4c    j      0x80002d94                 ;
  ↓
0x80002d94    jal    0x80000710                 ; stack pop

0x80000c54    seh    $v1, $v0                   ;
0x80000c58    lui    $v0, 0x8000                ;
0x80000c5c    sh     $v1, 0x3d24($v0)           ; store to vm_ctx->reg
0x80000c60    nop                               ;
0x80000c64    j      0x80002da8                 ;
  ↓
0x80002da8    b      0x80000c9c                 ; loop back to VM loop

; ------------------------------ VM INSTRUCTION #12 ------------------------------
;
; pop
;
0x80000c6c    nop                               ;
0x80000c70    j      0x80002dbc                 ;
  ↓
0x80002dbc    jal    0x80000710                 ; stack pop

0x80000c74    nop                               ;
0x80000c78    nop                               ;
0x80000c7c    j      0x80002dd0                 ;
  ↓
0x80002dd0    b      0x80000c9c                 ; loop back to VM loop

0x80000c80    nop                               ;

; ------------------------------ VM INSTRUCTION #13 ------------------------------
;
; exit VM (return back)
;
0x80000c84    addiu  $v0, $zero, 1              ; v0 = 1
0x80000c88    sw     $v0, 0x10($fp)             ; var_10 = 1
0x80000c8c    nop                               ;
0x80000c90    j      0x80002de4                 ; nop jump?
  ↓
0x80002de4    b      0x80000c9c                 ; 

0x80000c9c    lw     $v0, 0x10($fp)             ; v0 = var_10 = 1
0x80000ca0    nop                               ;
0x80000ca4    j      0x80002df8                 ;
  ↓   
0x80002df8    beqz   $v0, 0x8000083c            ; if not 0, go back to VM loop
  ↓
0x80002e00    b      0x80000ca8                 ;
  ↓
0x80000ca8    nop                               ;
0x80000cac    nop                               ;
0x80000cb0    nop                               ;
0x80000cb4    move   $sp, $fp                   ;
0x80000cb8    lw     $ra, 0x44($sp)             ;
0x80000cbc    lw     $fp, 0x40($sp)             ;
0x80000cc0    addiu  $sp, $sp, 0x48             ;
0x80000cc4    nop                               ;
0x80000cc8    j      0x80002e0c                 ;
  ↓
0x80002e0c    jr     $ra                        ; Return back to 0x80000e60
```

This is stack-based VM machine. Instructions are fairly simple, so we can easily write a
disassembler for it. For more details, please refer to the
[flash_vm_dsiasm.py](./flash_vm_dsiasm.py) script.


### Reversing the VM Program

Using the script we can get the disassembly of the VM program:
```assembly
80003D40h: push 0x091D                   ; S = [0x091D]

80003D44h: push 0x0000                   ; S = [0, 0x091D]
80003D48h: push reg                      ; S = [reg, 0, 0x091D]; reg initialized to len(flag)//2
80003D4Ah: cmp ==                        ; S = [reg == 0 ?, 0x091D]
80003D4Ch: je 0014h (~> 80003D64)        ; pop skip read loop
80003D50h: push 0x0001                   ; S = [1, 0x091D]
80003D54h: push reg                      ; S = [reg, 0x091D]
80003D56h: sub                           ; S = [reg - 1, 0x091D]
80003D58h: pop reg                       ; reg -= 1
80003D5Ah: read_flag_half                ; S = [flag[0:2], 0x091D]
80003D5Ch: push 0x0001                   ; 1
80003D60h: je FFE0h (~> 80013D44)        ; loop back

; At this point: S = [flag[x:x+2], ..., flag[2:4], flag[0:2]]
80003D64h: push 0x0011                   ; S = [0x11, flag[x:x+2], ...,]
80003D68h: mul                           ; S = [...,], acc = 0x11 * flag[x:x+2]
80003D6Ah: push 0xB248                   ; S = [0xB248, ..., flag[x-2:x]]
80003D6Eh: mod                           ; S = [(0x11 * flag[x:x+2]) % 0xB248, ...,]
80003D70h: push 0x72A9                   ; S = [0x72A9, (0x11 * flag[x:x+2]) % 0xB248, ...,]
80003D74h: cmp ==                        ; (0x11 * flag[x:x+2]) % 0xB248 == 0x72A9 ?
80003D76h: jne 0144h (~> 80003EBE)       ; if not go to badboy
80003D7Ah: push 0x0011                   ; S = [0x11, flag[x-2:x], ...]
80003D7Eh: mul                           ;
80003D80h: push 0xB248                   ; same thing repeats but with different constants to check
80003D84h: mod                           ;
80003D86h: push 0x097E                   ;
80003D8Ah: cmp ==                        ;
80003D8Ch: jne 012Eh (~> 80003EBE)       ;
80003D90h: push 0x0011                   ;
80003D94h: mul                           ;
80003D96h: push 0xB248                   ;
80003D9Ah: mod                           ;
80003D9Ch: push 0x5560                   ;
80003DA0h: cmp ==                        ;
80003DA2h: jne 0118h (~> 80003EBE)       ;
80003DA6h: push 0x0011                   ;
80003DAAh: mul                           ;
80003DACh: push 0xB248                   ;
80003DB0h: mod                           ;
80003DB2h: push 0x4CA1                   ;
80003DB6h: cmp ==                        ;
80003DB8h: jne 0102h (~> 80003EBE)       ;
80003DBCh: push 0x0011                   ;
80003DC0h: mul                           ;
80003DC2h: push 0xB248                   ;
80003DC6h: mod                           ;
80003DC8h: push 0x0037                   ;
80003DCCh: cmp ==                        ;
80003DCEh: jne 00ECh (~> 80003EBE)       ;
80003DD2h: push 0x0011                   ;
80003DD6h: mul                           ;
80003DD8h: push 0xB248                   ;
80003DDCh: mod                           ;
80003DDEh: push 0xAA71                   ;
80003DE2h: cmp ==                        ;
80003DE4h: jne 00D6h (~> 80003EBE)       ;
80003DE8h: push 0x0011                   ;
80003DECh: mul                           ;
80003DEEh: push 0xB248                   ;
80003DF2h: mod                           ;
80003DF4h: push 0x122C                   ;
80003DF8h: cmp ==                        ;
80003DFAh: jne 00C0h (~> 80003EBE)       ;
80003DFEh: push 0x0011                   ;
80003E02h: mul                           ;
80003E04h: push 0xB248                   ;
80003E08h: mod                           ;
80003E0Ah: push 0x4536                   ;
80003E0Eh: cmp ==                        ;
80003E10h: jne 00AAh (~> 80003EBE)       ;
80003E14h: push 0x0011                   ;
80003E18h: mul                           ;
80003E1Ah: push 0xB248                   ;
80003E1Eh: mod                           ;
80003E20h: push 0x11E8                   ;
80003E24h: cmp ==                        ;
80003E26h: jne 0094h (~> 80003EBE)       ;
80003E2Ah: push 0x0011                   ;
80003E2Eh: mul                           ;
80003E30h: push 0xB248                   ;
80003E34h: mod                           ;
80003E36h: push 0x1247                   ;
80003E3Ah: cmp ==                        ;
80003E3Ch: jne 007Eh (~> 80003EBE)       ;
80003E40h: push 0x0011                   ;
80003E44h: mul                           ;
80003E46h: push 0xB248                   ;
80003E4Ah: mod                           ;
80003E4Ch: push 0x76C7                   ;
80003E50h: cmp ==                        ;
80003E52h: jne 0068h (~> 80003EBE)       ;
80003E56h: push 0x0011                   ;
80003E5Ah: mul                           ;
80003E5Ch: push 0xB248                   ;
80003E60h: mod                           ;
80003E62h: push 0x096D                   ;
80003E66h: cmp ==                        ;
80003E68h: jne 0052h (~> 80003EBE)       ;
80003E6Ch: push 0x0011                   ;
80003E70h: mul                           ;
80003E72h: push 0xB248                   ;
80003E76h: mod                           ;
80003E78h: push 0x122C                   ;
80003E7Ch: cmp ==                        ;
80003E7Eh: jne 003Ch (~> 80003EBE)       ;
80003E82h: push 0x0011                   ;
80003E86h: mul                           ;
80003E88h: push 0xB248                   ;
80003E8Ch: mod                           ;
80003E8Eh: push 0x87CB                   ;
80003E92h: cmp ==                        ;
80003E94h: jne 0026h (~> 80003EBE)       ;
80003E98h: push 0x0011                   ;
80003E9Ch: mul                           ;
80003E9Eh: push 0xB248                   ;
80003EA2h: mod                           ;
80003EA4h: push 0x09E4                   ;
80003EA8h: cmp ==                        ;
80003EAAh: jne 0010h (~> 80003EBE)       ;
80003EAEh: push 0x091D                   ;
80003EB2h: jne 0008h (~> 80003EBE)       ;
80003EB6h: push 0x0000                   ; goodboy; return 0
80003EBAh: pop reg                       ;
80003EBCh: halt                          ;
80003EBEh: push 0x0001                   ; badboy; return 1
80003EC2h: pop reg                       ;
80003EC4h: halt                          ;
```

It is very easy to understand what this program does. First it pushes flag on the stack (**2**
characters at a time). Then it starts from the end of the flag and does the following check:
```
  if (0x11 * flag[x:x+2]) % 0xB248 == 0x72A9) then move one
  otherwise goto badboy
```

If the check is passed it moves on with the previous **2** characters from the flag and checks them
against another constant, and so on, until all characters are checked.


### Cracking the Code

Getting the flag is actually quite simple. First we find the multiplicative inverse of **17**
modulo **0xB248**, which is **0x4969**. Then:
```
    17*flagN == 0x72A9          mod 0xB248 =>
       flagN == 0x72A9 * 17^-1  mod 0xB248 =>
       flagN == 0x72A9 * 0x4969 mod 0xB248 =>

       flagN = 0x6521 = '!e'
```

That is, to get flag we multiply the constant **0x72A9** with **0x4969** modulo **0xB248**. The
result is the last **2** characters from the flag. We repeat the same for other constants:
```
    0x72A9, 0x097E, 0x5560, 0x4CA1,
    0x0037, 0xAA71, 0x122C, 0x4536,
    0x11E8, 0x1247, 0x76C7, 0x096D,
    0x122C, 0x87CB, 0x09E4
```

And we get the flag.

So, the flag is: `flag{it's_time_to_pwn_this_machine!}`

For more details, please take a look at the [flash_crack.py](./flash_crack.py) file.
___
