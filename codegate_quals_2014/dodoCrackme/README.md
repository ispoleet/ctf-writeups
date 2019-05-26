## Codegate CTF Preliminary 2014 - dodo Crackme (RE 200pt)
##### 22/02 - 23/02/2014 (30hr)
___

### Description: 
    My eyes almost poped out!

    Download


### Solution

This is a super simple challenge (it didn't worth its points at all). Here's the complete
solution in GDB:

```
Reading symbols from crackme_d079a0af0b01789c01d5755c885da4f6...(no debugging symbols found)...done.
(gdb) display/i $pc
(gdb) run
Starting program: /home/ispo/ctf/2014/codegate/dodoCrackme/crackme_d079a0af0b01789c01d5755c885da4f6 
root@localhost's password: ^C
Program received signal SIGINT, Interrupt.
0x00000000004065c2 in ?? ()
1: x/i $pc
=> 0x4065c2:    lea    -0x8(%rbp),%rbp
(gdb) disas 0x04065ab, 0x04065C6
Dump of assembler code from 0x4065ab to 0x4065c6:
   0x00000000004065ab:  lea    0x8(%rbp),%ebp
   0x00000000004065ae:  mov    $0x0,%eax
   0x00000000004065b3:  mov    $0x0,%edi
   0x00000000004065b8:  mov    %rbp,%rsi
   0x00000000004065bb:  mov    $0x1,%edx
   0x00000000004065c0:  syscall 
=> 0x00000000004065c2:  lea    -0x8(%rbp),%rbp
End of assembler dump.
(gdb) b *0x00000000004065c0
Breakpoint 1 at 0x4065c0
(gdb) r
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/ispo/ctf/2014/codegate/dodoCrackme/crackme_d079a0af0b01789c01d5755c885da4f6 
root@localhost's password: 
Breakpoint 1, 0x00000000004065c0 in ?? ()
1: x/i $pc
=> 0x4065c0:    syscall 
(gdb) i r
rax            0x0      0
rbx            0x0      0
rcx            0x400617 4195863
rdx            0x1      1
rsi            0x7ffff7ff6b38   140737354099512
rdi            0x0      0
rbp            0x7ffff7ff6b38   0x7ffff7ff6b38
rsp            0x7fffffffdbd0   0x7fffffffdbd0
r8             0xffffffffffffffff       -1
r9             0x0      0
r10            0x22     34
r11            0x206    518
r12            0x0      0
r13            0x0      0
r14            0x0      0
r15            0x0      0
rip            0x4065c0 0x4065c0
eflags         0x202    [ IF ]
cs             0x33     51
ss             0x2b     43
ds             0x0      0
es             0x0      0
fs             0x0      0
gs             0x0      0
(gdb) x/160cw $rsi
0x7ffff7ff6b38: 0 '\000'        0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6b48: 0 '\000'        0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6b58: 72 'H'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6b68: 52 '4'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6b78: 80 'P'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6b88: 80 'P'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6b98: 89 'Y'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6ba8: 95 '_'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6bb8: 67 'C'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6bc8: 48 '0'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6bd8: 68 'D'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6be8: 69 'E'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6bf8: 71 'G'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6c08: 97 'a'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6c18: 84 'T'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6c28: 69 'E'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6c38: 95 '_'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6c48: 50 '2'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6c58: 48 '0'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6c68: 49 '1'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6c78: 52 '4'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6c88: 95 '_'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6c98: 67 'C'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6ca8: 85 'U'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6cb8: 95 '_'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6cc8: 49 '1'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6cd8: 78 'N'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6ce8: 95 '_'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6cf8: 75 'K'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6d08: 48 '0'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6d18: 82 'R'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6d28: 69 'E'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6d38: 52 '4'  0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6d48: 0 '\000'        0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6d58: 0 '\000'        0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6d68: 0 '\000'        0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6d78: 0 '\000'        0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6d88: 0 '\000'        0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6d98: 0 '\000'        0 '\000'        0 '\000'        0 '\000'
0x7ffff7ff6da8: 0 '\000'        0 '\000'        0 '\000'        0 '\000'
(gdb) q
```

All we have to do, is to set a breakpoint at `0x4065c0`, at the `syscall` which reads 1 byte 
from input. If we dump the contents of the input buffer, we'll see that the flag is right after
it: `H4PPY_C0DEGaTE_2014_CU_1N_K0RE4`
___
