## Codegate CTF 2020 Preliminary - Simple Machine (RE 333)
##### 08-09/02/2020 (24hr)
___

### Description: 

Classic Check Flag Challenge Machine

Download:
```
http://ctf.codegate.org/099ef54feeff0c4e7c2e4c7dfd7deb6e/116ea16dbeabe08d1fe8891a27d0f16b
```
___

### Solution

We have to deal with a VM crackme. Before we reverse let's play a little bit with it:
```
ispo@leet:~/ctf/codegate_2020/SimpleMachine$ ./simple_machine target
aaaaaaaaaaaaaaaaaaaaa
ispo@leet:~/ctf/codegate_2020/SimpleMachine$ ./simple_machine target
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ispo@leet:~/ctf/codegate_2020/SimpleMachine$ aaaaa
aaaaa: command not found
ispo@leet:~/ctf/codegate_2020/SimpleMachine$ ./simple_machine target
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa       
ispo@leet:~/ctf/codegate_2020/SimpleMachine$ ./simple_machine target
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ispo@leet:~/ctf/codegate_2020/SimpleMachine$ a
a: command not found
````

For the above we can infer that flag is **36** characters long (if we give more input
to the program, it discards it). When program starts, it loads the VM program
(passed in `argv[1]`) and then the emulation starts.

The interesting part is that program checks **two characters** from the input each time. This is
easy to infer if we just look at how input is being processed (each time the next pair of two 
characters is set to `ax` register and then is being processed). So we just set breakpoint here:
```assembly
.text:00005555555557A0 scanf_5555555557A0 proc near            ; CODE XREF: sub_5555555557C0+28p
.text:00005555555557A0     sub     rsp, 8
.text:00005555555557A4     movzx   esi, si
.text:00005555555557A7     add     rsi, [rdi]                  ; buf
.text:00005555555557AA     movzx   edx, dx                     ; nbytes
.text:00005555555557AD     xor     edi, edi                    ; fd
.text:00005555555557AF     call    _read                       ; read(buf, 0x24, stdin)
.text:00005555555557B4     add     rsp, 8
.text:00005555555557B8     retn
.text:00005555555557B8 scanf_5555555557A0 endp
```

And then we keep track of the input. The interesting part is `read_word_555555555510` which 
loads a word into `ax`:
```assembly
.text:0000555555555510 read_word_555555555510 proc near        ; CODE XREF: sub_555555555560+EFp
.text:0000555555555510                                         ; sub_555555555560+107p ...
.text:0000555555555510     sub     rsp, 8
.text:0000555555555514     mov     r8, [rdi]
.text:0000555555555517     mov     rdx, [rdi+8]
.text:000055555555551B     movzx   ecx, si
.text:000055555555551E     movzx   esi, si
.text:0000555555555521     add     rsi, 1
.text:0000555555555525     sub     rdx, r8
.text:0000555555555528     cmp     rsi, rdx
.text:000055555555552B     jnb     short OVERFLOW_55555555554B
.text:000055555555552D     movzx   eax, byte ptr [r8+rsi]      ; eax = offset
.text:0000555555555532     shl     eax, 8
.text:0000555555555535     cmp     rcx, rdx
.text:0000555555555538     mov     edi, eax
.text:000055555555553A     jnb     short OVERFLOW_2_555555555548
.text:000055555555553C     movzx   eax, byte ptr [r8+rcx]
.text:0000555555555541     add     rsp, 8
.text:0000555555555545     or      eax, edi
.text:0000555555555547     retn
.text:0000555555555548 ; ---------------------------------------------------------------------------
.text:0000555555555548
.text:0000555555555548 OVERFLOW_2_555555555548:                ; CODE XREF: read_word_555555555510+2Aj
.text:0000555555555548     mov     rsi, rcx
.text:000055555555554B
.text:000055555555554B OVERFLOW_55555555554B:                  ; CODE XREF: read_word_555555555510+1Bj
.text:000055555555554B     lea     rdi, aVector_m_range        ; "vector::_M_range_check: __n (which is %"...
.text:0000555555555552     xor     eax, eax
.text:0000555555555554     call    __ZSt24__throw_out_of_range_fmtPKcz ; std::__throw_out_of_range_fmt(char const*,...)
.text:0000555555555559     nop
.text:000055555555555A     nop     word ptr [rax+rax+00h]
.text:000055555555555A read_word_555555555510 endp ; sp-analysis failed
```

Given that, we can try a classic side channel attack and brute force every pair of the flag.
Since we know how the flag starts, we check first whether our attack works:
```
ispo@leet:~/ctf/codegate_2020/SimpleMachine$ sudo perf stat -e instructions:u ./simple_machine target
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

 Performance counter stats for './simple_machine target':

         2,229,881      instructions:u                                              

       8.361797412 seconds time elapsed

       0.000000000 seconds user
       0.002095000 seconds sys


ispo@leet:~/ctf/codegate_2020/SimpleMachine$ sudo perf stat -e instructions:u ./simple_machine target
COaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa    

 Performance counter stats for './simple_machine target':

         2,230,526      instructions:u                                              

      11.218020873 seconds time elapsed

       0.002096000 seconds user
       0.000000000 seconds sys


ispo@leet:~/ctf/codegate_2020/SimpleMachine$ sudo perf stat -e instructions:u ./simple_machine target
CODEGATEaaaaaaaaaaaaaaaaaaaaaaaaaaaa

 Performance counter stats for './simple_machine target':

         2,232,463      instructions:u                                              

       0.986917055 seconds time elapsed

       0.001839000 seconds user
       0.000000000 seconds sys


```

Cool. We see a significant increase in the number of instructions when the next pair 
is correct. Given that, we can perform a side channel attack and guess the flag: 
`CODEGATE2020{ezpz_but_1t_1s_pr3t3xt}`. Note that our attack takes about 20 minutes.

For more details, please take a look at the [crack file](./simple_machine_crack.py).

```
ispo@leet:~/ctf/codegate_2020/SimpleMachine$ ./simple_machine target
CODEGATE2020{ezpz_but_1t_1s_pr3t3xt}
GOOD!
```
___

