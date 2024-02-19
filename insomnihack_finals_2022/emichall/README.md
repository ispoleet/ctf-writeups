## Insomni'Hack CTF Finals 2022 - emichall (RE)
##### 25/03/2022 (10hr)
___

For this challenge we have to answer `7` questions (`Q0` to `Q6`) related to floating point
peculiarities.

### Q0

For the first question, program displays `Q0:` string and then reads a `float`. Then it does some
checks and either moves on to the next question (`MOVE_ON_Q1`) or jumps to `FUNC_RET` and exits:
```assembly
.text:0000555555555181         call    _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc_isra_0 ; std::operator<<<std::char_traits<char>>(std::ostream &,char const*) [clone]
.text:0000555555555186         lea     rsi, [rbp+var_90]
.text:000055555555518D         lea     rdi, _ZSt3cin@GLIBCXX_3_4
.text:0000555555555194         call    __ZNSi10_M_extractIfEERSiRT_   ; std::istream::_M_extract<float>(float &)
.text:0000555555555199         movss   xmm0, [rbp+var_90]
.text:00005555555551A1         movss   xmm1, cs:glo_const_1024
.text:00005555555551A9         comiss  xmm1, xmm0
.text:00005555555551AC         jbe     short RETURN_1                 ; must be <1024
.text:00005555555551AE         movaps  xmm1, xmm0
.text:00005555555551B1         xorps   xmm1, cs:glo_const_minus_zero  ; flip sign (XOR with 80000000h)
.text:00005555555551B8         mov     edx, 0
.text:00005555555551BD         ucomiss xmm0, xmm1                     ; x VS -x ?
.text:00005555555551C0         setnp   al                             ; result not "unordered" (i.e., NaN)
.text:00005555555551C3         cmovnz  eax, edx                       ; eax = 0 iff x is *not* 0
.text:00005555555551C6         comiss  xmm0, cs:glo_const_minus_2048
.text:00005555555551CD         setnbe  dl                             ; (=seta) number < -2048 ?
.text:00005555555551D0         test    al, dl                         ; al must be 1 (=> x should be 0)
.text:00005555555551D0                                                ; dl must be 1 (=> x > -2048)
.text:00005555555551D2         jz      short RETURN_1
.text:00005555555551D4         movd    eax, xmm1
.text:00005555555551D8         movd    ecx, xmm0
.text:00005555555551DC         cmp     eax, ecx                       ; -0 == x
.text:00005555555551DE         jnz     short MOVE_ON_Q1               ; Q0: -0
```

The first check is that the input (let `x`) must be less than `1024`. Then it XORs `x` with `-0.0`
(which is represented as `80000000h`) to flip the sign bit and checks whether the parity flag is
**not** set, i.e., the result is **not** *"unordered"* (i.e., invalid). According to the
[COMISS](https://c9x.me/x86/html/file_module_x86_id_44.html) instruction reference, parity flag is
set only when the result is "unordered" (e.g., a `NaN` is involved):
```c
Result = OrderedCompare(Source1[0..31], Source2[0..31]);
switch(Result) {
	case ResultUnordered:
		ZF = 1;
		PF = 1;
		CF = 1;
		break;
	case ResultGreaterThan:
		ZF = 0;
		PF = 0;
		CF = 0;
		break;
	case ResultLessThan:
		ZF = 0;
		PF = 0;
		CF = 1;
		break;
	case ResultEqual:
		ZF = 1;
		PF = 0;
		CF = 0;
		break;
}
OF = 0;
AF = 0;
SF = 0;
```

If this result is valid, it moves on and checks if `x` is above `-2048`. The next check
(`test al, dl`) is tricky: To avoid returning, both `al` and `dl` should be `1`. To make `al = 1`,
the conditional mov `cmovnz  eax, edx` should not occur, which means that `ucomiss xmm0, xmm1`
should set `ZF` which in turn means that `x == -x` which is only possible when `x` is `0`.
The final check is `cmp eax, ecx`, which treats floating point numbers as bits.
In this check `x` and `-x` should be different.

Considering all these, the only valid answer for `Q0` is `0`
(or `-0`; which is different in floating point representation).

### Q1

The next question is simpler:
```assembly
.text:00005555555551FD MOVE_ON_Q1:                                    ; CODE XREF: sub_55555555516B+73↑j
.text:00005555555551FD         lea     rsi, aQ1                       ; "Q1: "
.text:0000555555555204         lea     rdi, _ZSt4cout@GLIBCXX_3_4
.text:000055555555520B         call    _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc_isra_0 ; std::operator<<<std::char_traits<char>>(std::ostream &,char const*) [clone]
.text:0000555555555210         lea     rsi, [rbp+var_8C]
.text:0000555555555217         lea     rdi, asc_55555555600E          ; "%f"
.text:000055555555521E         xor     eax, eax
.text:0000555555555220         call    ___isoc99_scanf
.text:0000555555555225         movss   xmm0, [rbp+var_8C]
.text:000055555555522D         movd    eax, xmm0
.text:0000555555555231         test    eax, eax
.text:0000555555555233         jns     short RETURN_1                 ; must be <0 (sign bit must be set)
.text:0000555555555235         ucomiss xmm0, xmm0
.text:0000555555555238         jnp     short RETURN_1                 ; result must be UNORDERED ~> -Q1:  -NaN
.text:0000555555555238                                                ; https://www.felixcloutier.com/x86/ucomiss
```

Here we read a floating point number (using `scanf` this time; this is important), we compare it with 
itself and then we check the parity flag. Recall from
[UCOMISS](https://c9x.me/x86/html/file_module_x86_id_317.html) instruction reference, that the `PF`
is set if the result is unordered, so here, our input should be a `NaN`. However, since the input
should also be negative, our answer should be `-NaN`.

### Q2

In `Q2` we measure the current timestamp, then we enter a loop starting from the input `x` up to
`10.000.000` and then we measure time again:
```assembly
.text:000055555555523A         lea     rsi, aQ2                       ; "Q2: "
.text:0000555555555241         lea     rdi, _ZSt4cout@GLIBCXX_3_4
.text:0000555555555248         call    _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc_isra_0 ; std::operator<<<std::char_traits<char>>(std::ostream &,char const*) [clone]
.text:000055555555524D         lea     rsi, [rbp+var_88]
.text:0000555555555254         lea     rdi, asc_55555555600E          ; "%f"
.text:000055555555525B         xor     eax, eax
.text:000055555555525D         call    ___isoc99_scanf                ; Q2
.text:0000555555555262         movss   xmm0, [rbp+var_88]
.text:000055555555526A         mov     [rbp+const_10m], 10000000
.text:0000555555555271         movss   dword ptr [rbp+var_A8], xmm0
.text:0000555555555279         call    __ZNSt6chrono3_V212system_clock3nowEv ; std::chrono::_V2::system_clock::now(void)
.text:000055555555527E         mov     r12, rax
.text:0000555555555281         mov     eax, [rbp+const_10m]
.text:0000555555555284         call    __ZNSt6chrono3_V212system_clock3nowEv ; std::chrono::_V2::system_clock::now(void)
.text:0000555555555289         sub     rax, r12
.text:000055555555528C         mov     rbx, rax
.text:000055555555528F         call    __ZNSt6chrono3_V212system_clock3nowEv ; std::chrono::_V2::system_clock::now(void)
.text:0000555555555294         mov     edx, [rbp+const_10m]
.text:0000555555555297         movss   xmm1, cs:glo_const_1
.text:000055555555529F         mov     r12, rax
.text:00005555555552A2         movss   xmm0, dword ptr [rbp+var_A8]
.text:00005555555552AA         xor     eax, eax
.text:00005555555552AC         jmp     short loc_5555555552B9         ; start from q2_inp and loop up to 10.000.000
.text:00005555555552AE ; ---------------------------------------------------------------------------
.text:00005555555552AE
.text:00005555555552AE SPIN_LOOP:                                     ; CODE XREF: sub_55555555516B+150↓j
.text:00005555555552AE         addss   xmm0, xmm1                     ; q2_inp ++
.text:00005555555552B2         add     eax, 1
.text:00005555555552B5         subss   xmm0, xmm1                     ; q2_inp --
.text:00005555555552B9
.text:00005555555552B9 loc_5555555552B9:                              ; CODE XREF: sub_55555555516B+141↑j
.text:00005555555552B9         cmp     edx, eax                       ; start from q2_inp and loop up to 10.000.000
.text:00005555555552BB         jnz     short SPIN_LOOP                ; q2_inp ++
.text:00005555555552BD         movss   dword ptr [rbp+var_A8], xmm0
.text:00005555555552C5         imul    rbx, 0Ah
.text:00005555555552C9         call    __ZNSt6chrono3_V212system_clock3nowEv ; check clock again
.text:00005555555552CE         movss   xmm0, dword ptr [rbp+var_A8]
.text:00005555555552D6         movss   xmm1, cs:glo_const_1
.text:00005555555552DE         sub     rax, r12                       ; check time passed
.text:00005555555552E1         addss   xmm0, xmm1
.text:00005555555552E5         movss   [rbp+var_74], xmm0
.text:00005555555552EA         cmp     rax, rbx                       ; check how much time elapsed
.text:00005555555552ED         jle     RETURN_1
```

Obviously there are too many valuid values here, so let's use `9`.

### Q3

`Q3` is also easy:
```assembly
.text:00005555555552F3         lea     rsi, aQ3                       ; "Q3: "
.text:00005555555552FA         lea     rdi, _ZSt4cout@GLIBCXX_3_4
.text:0000555555555301         mov     ebx, [rbp+var_88]
.text:0000555555555307         call    _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc_isra_0 ; std::operator<<<std::char_traits<char>>(std::ostream &,char const*) [clone]
.text:000055555555530C         xor     eax, eax
.text:000055555555530E         lea     rsi, [rbp+var_84]
.text:0000555555555315         lea     rdi, asc_55555555600E          ; "%f"
.text:000055555555531C         call    ___isoc99_scanf
.text:0000555555555321         movss   xmm2, [rbp+var_84]
.text:0000555555555329         movss   xmm1, cs:glo_const_1
.text:0000555555555331         addss   xmm1, xmm2                     ; q3_inp ++
.text:0000555555555335         ucomiss xmm2, xmm1                     ; x + 1 == x ?
.text:0000555555555338         jp      RETURN_1                       ; PF = 0 & ZF = 1 (can't be nan)
.text:000055555555533E         jnz     RETURN_1                       ; Q3: 1e20
.text:0000555555555344         movaps  xmm0, xmm2
.text:0000555555555347         addss   xmm0, xmm2
.text:000055555555534B         ucomiss xmm2, xmm0                     ; x + x != x
.text:000055555555534E         jp      short MOVE_ON_Q4               ; Q3: 1e20
.text:0000555555555350         comiss  xmm2, xmm0
.text:0000555555555353         jz      RETURN_1
```

We just need to enter a number such that `x` and `x + 1` are equal. At first it looks odd, but it
is simple if you consider how floating point numbers are represented. If we enter a very large
number (with a large exponent) and then we add a very small number to it, FPU will do some casting
so both numbers have the same exponent. However, due to precision loss the small number will become
`0` when it takes the exponent of the big number. Any very large number we enter here is a valid
answer. For our case, we enter `1e20` (which is true that `1e20 + 1 = 1e20`).

### Q4

This question is more tricky. All we have to do, is to make `check4` return `1`:
```assembly
.text:0000555555555359 MOVE_ON_Q4:                                    ; CODE XREF: sub_55555555516B+1E3↑j
.text:0000555555555359         lea     rsi, aQ4                       ; "Q4: "
.text:0000555555555360         lea     rdi, _ZSt4cout@GLIBCXX_3_4
.text:0000555555555367         movss   dword ptr [rbp+var_A8], xmm2
.text:000055555555536F         call    _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc_isra_0 ; std::operator<<<std::char_traits<char>>(std::ostream &,char const*) [clone]
.text:0000555555555374         lea     rsi, [rbp+var_80]
.text:0000555555555378         lea     rdi, _ZSt3cin@GLIBCXX_3_4
.text:000055555555537F         call    __ZNSi10_M_extractIjEERSiRT_   ; std::istream::_M_extract<uint>(uint &)
.text:0000555555555384         mov     r12d, [rbp+var_80]
.text:0000555555555388         movd    xmm0, r12d                     ; float
.text:000055555555538D         mov     [rbp+var_7C], r12d
.text:0000555555555391         call    _ZL6check4f                    ; check4(float)
.text:0000555555555396         test    al, al                         ; must return 1
.text:0000555555555398         jz      RETURN_1
```

However, `check` seems to always return `0`:
```assembly
.text:0000555555555710 _ZL6check4f proc near                          ; CODE XREF: sub_55555555516B+226↑p
.text:0000555555555710
.text:0000555555555710 var_1C  = dword ptr -1Ch
.text:0000555555555710 var_C   = dword ptr -0Ch
.text:0000555555555710
.text:0000555555555710 ; __unwind {
.text:0000555555555710         sub     rsp, 28h
.text:0000555555555714         lea     rdi, fpe                       ; env
.text:000055555555571B         movss   [rsp+28h+var_1C], xmm0
.text:0000555555555721         call    __setjmp
.text:0000555555555726         test    eax, eax
.text:0000555555555728         jnz     short loc_55555555573E         ; xmm0 = 0
.text:000055555555572A         movss   xmm0, [rsp+28h+var_1C]
.text:0000555555555730         addss   xmm0, cs:glo_const_1           ; x + 1 (should throw an FPE if NaNS)
.text:0000555555555738         movss   [rsp+28h+var_C], xmm0
.text:000055555555573E
.text:000055555555573E loc_55555555573E:                              ; CODE XREF: check4(float)+18↑j
.text:000055555555573E         pxor    xmm0, xmm0                     ; xmm0 = 0
.text:0000555555555742         ucomiss xmm0, cs:fp                    ; fp becomes 1.0 after exception
.text:0000555555555749         mov     edx, 1
.text:000055555555574E         setp    al
.text:0000555555555751         cmovnz  eax, edx
.text:0000555555555754         add     rsp, 28h
.text:0000555555555758         retn
.text:0000555555555758 ; } // starts at 555555555710
.text:0000555555555758 _ZL6check4f endp
```

However, the `__setjmp` gives us a clue that an exception handler is present. If we take a look
at the other function we can see that `_GLOBAL__sub_I_fp` defines an floating point exception
handler:
```assembly
.text:00005555555555D0 _GLOBAL__sub_I_fp proc near                    ; CODE XREF: __libc_csu_init+41↓p
.text:00005555555555D0                                                ; DATA XREF: .init_array:__frame_dummy_init_array_entry↓o
.text:00005555555555D0 ; __unwind {
.text:00005555555555D0         sub     rsp, 8
.text:00005555555555D4         lea     rdi, _ZStL8__ioinit            ; this
.text:00005555555555DB         call    __ZNSt8ios_base4InitC1Ev       ; std::ios_base::Init::Init(void)
.text:00005555555555E0         mov     rdi, cs:lpfunc                 ; lpfunc
.text:00005555555555E7         lea     rsi, _ZStL8__ioinit            ; obj
.text:00005555555555EE         lea     rdx, __dso_handle              ; lpdso_handle
.text:00005555555555F5         call    ___cxa_atexit
.text:00005555555555FA         mov     edi, 1                         ; excepts
.text:00005555555555FF         call    _feenableexcept
.text:0000555555555604         lea     rsi, _ZN4Init10fpehandlerEi    ; handler
.text:000055555555560B         mov     edi, 8                         ; sig
.text:0000555555555610         add     rsp, 8
.text:0000555555555614         jmp     _signal
.text:0000555555555614 ; } // starts at 5555555555D0
.text:0000555555555614 _GLOBAL__sub_I_fp endp
```

The excpetion handler is `Init::fpehandler(int)` and simply sets `fp` to `1`:
```c
void __noreturn Init::fpehandler()
{
  feclearexcept(1);
  *(float *)&fp = *(float *)&fp + 1.0;
  longjmp(fpe, 1);
}
```

After setting `fp = 1`, the comparison `ucomiss xmm0, cs:fp` will not set `ZF` and therefore
`cmovnz eax, edx` will take place, so `eax` will become `1`.
So all we have to do is to input a **signaling NaN** as input
(please refer [here](https://www.doc.ic.ac.uk/~eedwards/compsys/float/nan.html) for more details)
```
A signalling NaN (NANS) is represented by any bit pattern
between 7F800001 and 7FBFFFFF or between FF800001 and FFBFFFFF
```

We pick the first one (`7F800001h`) so the answer here is `2139095041`.

### Q5

This question operates on `FPU` instead of `XMM` registers:
```assembly
.text:000055555555539E         lea     rsi, aQ5                       ; "Q5: "
.text:00005555555553A5         lea     rdi, _ZSt4cout@GLIBCXX_3_4
.text:00005555555553AC         call    _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc_isra_0 ; std::operator<<<std::char_traits<char>>(std::ostream &,char const*) [clone]
.text:00005555555553B1         lea     rsi, [rbp+var_60]
.text:00005555555553B5         lea     rdi, aLf                       ; "%Lf"
.text:00005555555553BC         xor     eax, eax
.text:00005555555553BE         call    ___isoc99_scanf                ; input a double (%Lf)
.text:00005555555553C3         fld     [rbp+var_60]
.text:00005555555553C6         fld     st                             ; x on FPU stack
.text:00005555555553C8         fld     st                             ; x on FPU stack
.text:00005555555553CA         fsqrt                                  ; sqrt(x)
.text:00005555555553CC         fldpi                                  ; pi on stack
.text:00005555555553CE         fcompp                                 ; sqrt(x) == pi ?
.text:00005555555553D0         fnstsw  ax                             ; status flags on ax
.text:00005555555553D2         mov     word ptr [rbp+var_50], ax
.text:00005555555553D6         fstp    st
.text:00005555555553D8         test    byte ptr [rbp+var_50+1], 40h   ; check ZF
.text:00005555555553DC         jz      RETURN_1
```

We have to enter a double whose square root is [pi](https://en.wikipedia.org/wiki/Pi).
pi in double precision is `3.1415926535897932385`, so our input is `9.8696044010893586190`.

### Q6

For the final question we have to give **2** numbers (let `x` and `y`) as input:
```assembly
.text:00005555555553E2         fld     [rbp+var_60]
.text:00005555555553E5         lea     rsi, aQ6                       ; "Q6: "
.text:00005555555553EC         lea     rdi, _ZSt4cout@GLIBCXX_3_4
.text:00005555555553F3         fstp    [rbp+var_C0]
.text:00005555555553F9         call    _ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc_isra_0 ; std::operator<<<std::char_traits<char>>(std::ostream &,char const*) [clone]
.text:00005555555553FE         lea     rsi, [rbp+var_70]
.text:0000555555555402         lea     rdi, _ZSt3cin@GLIBCXX_3_4
.text:0000555555555409         call    __ZNSi10_M_extractIfEERSiRT_   ; std::istream::_M_extract<float>(float &)
.text:000055555555540E         lea     rsi, [rbp+var_6C]
.text:0000555555555412         mov     rdi, rax
.text:0000555555555415         call    __ZNSi10_M_extractIfEERSiRT_   ; std::istream::_M_extract<float>(float &)
.text:000055555555541A         movss   xmm0, [rbp+var_70]             ; xmm0 = x
.text:000055555555541F         movss   xmm3, [rbp+var_6C]             ; xmm3 = y
.text:0000555555555424         mulss   xmm3, xmm3                     ; xmm3 = y * y
.text:0000555555555428         movaps  xmm1, xmm0
.text:000055555555542B         movaps  xmm4, xmm0
.text:000055555555542E         mulss   xmm1, xmm0                     ; xmm1 = x * x
.text:0000555555555432         addss   xmm4, xmm0                     ; xmm4 = x + y
.text:0000555555555436         addss   xmm1, xmm3                     ; xmm1 = x * x + y * y
.text:000055555555543A         ucomiss xmm4, xmm1                     ; x * x + y * y == x + y ?
.text:000055555555543D         jp      RETURN_1                       ; should not be NaN
.text:0000555555555443         comiss  xmm4, xmm1
.text:0000555555555446         jnz     RETURN_1                       ; should not be zero
.text:000055555555544C         mov     eax, [rbp+var_90]              ; PRINT FLAG
```

The two numbers must satisfy the equation `x*x + x*x == x + y`, which means they should be
points on a circle. There are **4** solutions:
* `x = 0`, `y = 0`
* `x = 0`, `y = 1`
* `x = 1`, `y = 0`
* `x = 1`, `y = 1`

However, we want `comiss  xmm4, xmm1` to not set `ZF`, so among these **4** solutions, only the
last one (`x = 1`, `y = 1`) is valid.

### Final Answer

After we answer successfully all the question, program generates the flag for us
(we do not care how). Since there can be more than one valid answers to a question,
the program makes sure that it prints only a valid one:
```
ispo@leet:~/ctf/insomnihack_2022/emichall$ ./emichall-6aa0aacc5498ac7c7c449b88d1c4c4ddb86f38dcffd22b0b9dc830a770db22fd 
Q0: -0.0
Q1: -NaN
Q2: 9
Q3: 1e20
Q4: 2139095041
Q5: 9.8696044010893586190
Q6: 1 1

+-~-~~-~-+
|80000000|
|ffc00000|
|00000000|
|00000001|
|7f800001|
|411de9e6|
|3f800000|
+-~-~~-~-+
```

So the final flag should be: `INS{|80000000|ffc00000|00000000|00000001|7f800001|411de9e6|3f800000|}`.

However this flag did not get accepted. The problem was in `Q4`, as it reflects any value to the
output flag:
```
ispo@leet:~/ctf/insomnihack_2022/emichall$ ./emichall-6aa0aacc5498ac7c7c449b88d1c4c4ddb86f38dcffd22b0b9dc830a770db22fd 
Q0: -0.0
Q1: -NaN 
Q2: 9
Q3: 1e20
Q4: 2139095042
Q5: 9.8696044010893586190
Q6: 1 1

+-~-~~-~-+
|80000000|
|ffc00000|
|00000000|
|00000001|
|7f800002|
|411de9e6|
|3f800000|
+-~-~~-~-+
```

Since we have many possible flags, the idea is to simply check the **4** corner cases for
singaling NaNs:
* `7F800001h`, or `2139095041`
* `7FBFFFFFh`, or `2143289343`
* `FF800001h`, or `-8388607`
* `FFBFFFFFh`, or `-4194305`

Among these solutions, only the third one (smallest number) gives us a valid flag:
```
ispo@leet:~/ctf/insomnihack_2022/emichall$ ./emichall-6aa0aacc5498ac7c7c449b88d1c4c4ddb86f38dcffd22b0b9dc830a770db22fd 
Q0: -0.0
Q1: -NaN
Q2: 9
Q3: 1e20
Q4: -8388607
Q5: 9.8696044010893586190
Q6: 1 1

+-~-~~-~-+
|80000000|
|ffc00000|
|00000000|
|00000001|
|ff800001|
|411de9e6|
|3f800000|
+-~-~~-~-+
```

So the final flag is: `INS{|80000000|ffc00000|00000000|00000001|ff800001|411de9e6|3f800000|}`.
___
