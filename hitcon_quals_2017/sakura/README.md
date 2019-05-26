## HITCON CTF 2017 - Sakura (RE 300pt)
##### 04/11 - 06/11/2017 (48hr)
___

### Description: 
    She accompanies me every night.

``` 
sakura-fdb3c896d8a3029f40a38150b2e30a79

```

### Solution
 
Binary takes as input a 20x20 matrix A, and generates another 20x20 matrix B. The flag is the
SHA-256 sum of B. If we set A = all 1's then B is the following:
```
00000000000000000000
00000011000011000011
01101111110011101111
01111100110110111100
00110110000111011100
00011011000111101111
00001101100001110111
01100111110001111011
01111110110111101110
00011000000110000110
00000000000000000000
00001101100011101100
00111111110011111111
01110110110110011011
01101101100110001100
00111011100011000110
00110110110001100011
01101101110110110011
01111111100111111110
00110110000001101110
```

which means that approximately half of the numbers in B are not set (initialized to 0).

The verification takes place at `verify_555555554850()` which is a huge function, that consists
of multiple repetitions of the same code snippet. There's a special variable called `is_correct_1E49`
which is initialized to 1 and returned from the function. If anything goes wrong, `is_correct_1E49`
becomes 0 and execution continues normally. The goal is keep `is_correct_1E49 == 1`.

Below is one of code snippets that is repeated in the function:
```assembly
.text:000055555555686A     mov     [rbp+A_1E48], 0
.text:0000555555556874     mov     [rbp+B_1E44], 0
.text:000055555555687E     lea     rax, [rbp+var_DD0]          ; IDX_2 family
.text:0000555555556885     mov     [rbp+var_1738], rax         ; v1738 = "random" value
.text:000055555555688C     mov     rax, [rbp+var_1738]
.text:0000555555556893     mov     rdi, rax
.text:0000555555556896     call    ident_5555555650F4
.text:000055555555689B     mov     [rbp+lower_1BE8], rax       ; lower bound = "random" value
.text:00005555555568A2     mov     rax, [rbp+var_1738]
.text:00005555555568A9     mov     rdi, rax
.text:00005555555568AC     call    plus_0x10_55555556510E      ; we're in the 2-rep family
.text:00005555555568B1     mov     [rbp+upper_1730], rax       ; upper bound = "random" value + 0x10
.text:00005555555568B8
.text:00005555555568B8 LOOP_5555555568B8:                      ; CODE XREF: verify_555555554850+2190j
.text:00005555555568B8     mov     rax, [rbp+lower_1BE8]
.text:00005555555568BF     cmp     rax, [rbp+upper_1730]       ; repeat 2 times
.text:00005555555568C6     jz      END_OF_LOOP_5555555569E5
.text:00005555555568CC     mov     rax, [rbp+lower_1BE8]
.text:00005555555568D3     mov     rax, [rax]                  ; rax = IDX_2.next()= {y, x}
.text:00005555555568D6     mov     [rbp+var_DD8], rax
.text:00005555555568DD     mov     esi, dword ptr [rbp+var_DD8] ; esi = y
.text:00005555555568E3     mov     ecx, dword ptr [rbp+var_DD8+4] ; ecx = x
.text:00005555555568E9     mov     eax, dword ptr [rbp+var_DD8] ; eax = y
.text:00005555555568EF     movsxd  rdx, eax
.text:00005555555568F2     mov     rax, rdx                    ; rdx = rax = y
.text:00005555555568F5     shl     rax, 2                      ; rax = y * 4
.text:00005555555568F9     add     rax, rdx                    ; rax = y*4 + y = y*5
.text:00005555555568FC     shl     rax, 2                      ; rax = y*5*4 = y*20
.text:0000555555556900     mov     rdx, rax                    ; rdx = y*20 (select row from input)
.text:0000555555556903     mov     rax, [rbp+input_ref_1E58]
.text:000055555555690A     add     rdx, rax                    ; rdx = input[y] -> select y-th row
.text:000055555555690D     mov     eax, dword ptr [rbp+var_DD8+4] ; eax = x
.text:0000555555556913     cdqe
.text:0000555555556915     movzx   eax, byte ptr [rdx+rax]     ; eax = input[y][x]
.text:0000555555556919     mov     edi, eax
.text:000055555555691B     movsxd  rcx, ecx                    ; rcx = x
.text:000055555555691E     movsxd  rdx, esi                    ; rdx = y
.text:0000555555556921     mov     rax, rdx
.text:0000555555556924     shl     rax, 2
.text:0000555555556928     add     rax, rdx
.text:000055555555692B     shl     rax, 2                      ; rax = y*20
.text:000055555555692F     lea     rdx, [rax+rcx]              ; rdx = y*20 + x
.text:0000555555556933     lea     rax, matrix_555555766040
.text:000055555555693A     add     rax, rdx
.text:000055555555693D     mov     [rax], dil                  ; matrix[y][x] = input[y][x]
.text:0000555555556940     mov     eax, dword ptr [rbp+var_DD8]
.text:0000555555556946     movsxd  rdx, eax
.text:0000555555556949     mov     rax, rdx
.text:000055555555694C     shl     rax, 2
.text:0000555555556950     add     rax, rdx
.text:0000555555556953     shl     rax, 2
.text:0000555555556957     mov     rdx, rax
.text:000055555555695A     mov     rax, [rbp+input_ref_1E58]
.text:0000555555556961     add     rdx, rax
.text:0000555555556964     mov     eax, dword ptr [rbp+var_DD8+4]
.text:000055555555696A     cdqe
.text:000055555555696C     movzx   eax, byte ptr [rdx+rax]     ; eax = input[y][x]
.text:0000555555556970     movsx   eax, al
.text:0000555555556973     sub     eax, 30h                    ; ASCII -> digit
.text:0000555555556976     mov     [rbp+inpyx_1E40], eax
.text:000055555555697C     cmp     [rbp+inpyx_1E40], 0
.text:0000555555556983     jle     short WRONG_55555555698E    ; AVOID THIS!
.text:0000555555556985     cmp     [rbp+inpyx_1E40], 9
.text:000055555555698C     jle     short OK_555555556995       ; input[y][x] should be a digit
.text:000055555555698E
.text:000055555555698E WRONG_55555555698E:                     ; CODE XREF: verify_555555554850+2133j
.text:000055555555698E     mov     [rbp+is_correct_1E49], 0    ; AVOID THIS!
.text:0000555555556995
.text:0000555555556995 OK_555555556995:                        ; CODE XREF: verify_555555554850+213Cj
.text:0000555555556995     mov     eax, [rbp+inpyx_1E40]       ; input[y][x] should be a digit
.text:000055555555699B     mov     edx, [rbp+B_1E44]
.text:00005555555569A1     mov     ecx, eax                    ; ecx = input[y][x] - '0' = inp[y][x]
.text:00005555555569A3     sar     edx, cl                     ; B = sar(B, inp[y][x])
.text:00005555555569A5     mov     eax, edx
.text:00005555555569A7     and     eax, 1                      ; eax = sar(B, inp[y][x]) & 1
.text:00005555555569AA     test    eax, eax
.text:00005555555569AC     jz      short OK_5555555569B5
.text:00005555555569AE     mov     [rbp+is_correct_1E49], 0    ; eax should not be already set!
.text:00005555555569B5
.text:00005555555569B5 OK_5555555569B5:                        ; CODE XREF: verify_555555554850+215Cj
.text:00005555555569B5     mov     eax, [rbp+inpyx_1E40]
.text:00005555555569BB     mov     edx, 1
.text:00005555555569C0     mov     ecx, eax
.text:00005555555569C2     shl     edx, cl                     ; edx = 1 << inp[y][x]
.text:00005555555569C4     mov     eax, edx
.text:00005555555569C6     or      [rbp+B_1E44], eax           ; B |= 1 << inp[y][x]
.text:00005555555569CC     mov     eax, [rbp+inpyx_1E40]       ; B == map that stores all previous numbers
.text:00005555555569D2     add     [rbp+A_1E48], eax           ; A += inpyx
.text:00005555555569D8     add     [rbp+lower_1BE8], 8
.text:00005555555569E0     jmp     LOOP_5555555568B8
.text:00005555555569E5 ; ---------------------------------------------------------------------------
.text:00005555555569E5
.text:00005555555569E5 END_OF_LOOP_5555555569E5:               ; CODE XREF: verify_555555554850+2076j
.text:00005555555569E5     cmp     [rbp+A_1E48], 11h           ; summation compared against this constant
.text:00005555555569EC     jz      short loc_5555555569F5
.text:00005555555569EE     mov     [rbp+is_correct_1E49], 0
.text:00005555555569F5 ----------------------------------------------------------------
```

Here we actually read some numbers from the array, which must be between 1 and 9 and different
from all the previous numbers (otherwise `is_correct_1E49` will become zero). The numbers are
added together and their summation is compared against a constant. The indices that show the 
coordinates (y,x), are read from a special array in the stack, that we call "family". This array 
is constant and it's initialized during the function prolog. 

There are some small differences across the different code snippets in the function, such as the 
number of iterations in the loop, the family that indices are being read from and the
compared value at the end. We have 6 "families", that contain the coordinates). Based on the 
number of iterations, a different family is used. In the above example, function 
`plus_0x10_55555556510E()` is used to determine the number of iterations (2 iterations) and
the family as well. There are 6 functions:
```
plus_0x10_55555556510E  --> 2 iterations, Family 1
plus_0x18_555555565146  --> 3 iterations, Family 2
plus_0x20_5555555651EE  --> 4 iterations, Family 3
plus_0x28_5555555651B6  --> 5 iterations, Family 4
plus_0x30_55555556517E  --> 6 iterations, Family 5
plus_0x40_555555565226  --> 8 iterations, Family 6
```

### Cracking

Essentially, code reads some "random" numbers in the range [1,9] that are all different, from 
the array, it adds them together and checks whether the summation is equal with a given constant.
This is actually a linear equation that we have to solve in order to find the original array A.

So, first we dump all families (the arrays with the coordinates) and all r-values from the code. 
Then we reconstruct the (linear) equations and we feed them on z3. We use an IDC script for 
this job (dump_equations.idc). 

After a few seconds we get the correct input:
```
00000000000000000000
00000092000041000091
01703781920063804683
02961800810710983700
00890920000936091500
00081012000821602843
00003101200004980931
03700293410003792062
01928370120712801720
00019000000920000910
00000000000000000000
00001406500027104900
00418357920089641275
01250130730910053037
07607208600860002600
00948051200053000360
00570180860005200051
04804905380850690085
01786329400736152840
00310740000003501230
```

which we feed into the binary and we get the flag:
`hitcon{6c0d62189adfd27a12289890d5b89c0dc8098bc976ecc3f6d61ec0429cccae61}`


For more details please refer to the crack file.
___

