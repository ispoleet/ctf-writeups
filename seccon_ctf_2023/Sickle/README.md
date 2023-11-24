## SEECON quals 2023 - Sickle (RE 106)
#### 16/09 - 17/09/2023 (24 hrs)

### Description

*Pickle infected with COVID-19*

```
Sickle.tar.gz 2ca5177b8ced35c355100c626f6273339780f58c
```
___

### Solution

For this challenge, we are give the following Python code:
```python
import pickle, io


payload = b'\x8c\x08builtins\x8c\x07getattr\x93\x942\x8c\x08builtins\x8c\x05input\x93\x8c\x06FLAG> \x85R\x8c\x06encode\x86R)R\x940g0\n\x8c\x08builtins\x8c\x04dict\x93\x8c\x03get\x86R\x8c\x08builtins\x8c\x07globals\x93)R\x8c\x01f\x86R\x8c\x04seek\x86R\x94g0\n\x8c\x08builtins\x8c\x03int\x93\x8c\x07__add__\x86R\x940g0\n\x8c\x08builtins\x8c\x03int\x93\x8c\x07__mul__\x86R\x940g0\n\x8c\x08builtins\x8c\x03int\x93\x8c\x06__eq__\x86R\x940g3\ng5\n\x8c\x08builtins\x8c\x03len\x93g1\n\x85RM@\x00\x86RM\x05\x01\x86R\x85R.0g0\ng1\n\x8c\x0b__getitem__\x86R\x940M\x00\x00\x940g2\ng3\ng0\ng6\ng7\n\x85R\x8c\x06__le__\x86RM\x7f\x00\x85RMJ\x01\x86R\x85R.0g2\ng3\ng4\ng5\ng3\ng7\nM\x01\x00\x86Rp7\nM@\x00\x86RMU\x00\x86RM"\x01\x86R\x85R0g0\ng0\n]\x94\x8c\x06append\x86R\x940g8\n\x8c\x0b__getitem__\x86R\x940g0\n\x8c\x08builtins\x8c\x03int\x93\x8c\nfrom_bytes\x86R\x940M\x00\x00p7\n0g9\ng11\ng6\n\x8c\x08builtins\x8c\x05slice\x93g4\ng7\nM\x08\x00\x86Rg4\ng3\ng7\nM\x01\x00\x86RM\x08\x00\x86R\x86R\x85R\x8c\x06little\x86R\x85R0g2\ng3\ng4\ng5\ng3\ng7\nM\x01\x00\x86Rp7\nM\x08\x00\x86RMw\x00\x86RM\xc9\x01\x86R\x85R0g0\n]\x94\x8c\x06append\x86R\x940g0\ng12\n\x8c\x0b__getitem__\x86R\x940g0\n\x8c\x08builtins\x8c\x03int\x93\x8c\x07__xor__\x86R\x940I1244422970072434993\n\x940M\x00\x00p7\n0g13\n\x8c\x08builtins\x8c\x03pow\x93g15\ng10\ng7\n\x85Rg16\n\x86RI65537\nI18446744073709551557\n\x87R\x85R0g14\ng7\n\x85Rp16\n0g2\ng3\ng4\ng5\ng3\ng7\nM\x01\x00\x86Rp7\nM\x08\x00\x86RM\x83\x00\x86RM\xa7\x02\x86R\x85R0g0\ng12\n\x8c\x06__eq__\x86R(I8215359690687096682\nI1862662588367509514\nI8350772864914849965\nI11616510986494699232\nI3711648467207374797\nI9722127090168848805\nI16780197523811627561\nI18138828537077112905\nl\x85R.'
f = io.BytesIO(payload)
res = pickle.load(f)

if isinstance(res, bool) and res:
    print("Congratulations!!")
else:
    print("Nope")
```

We use [pickletools](https://docs.python.org/3/library/pickletools.html) to disassemble the payload:
```python
import pickletools

pickled_bomb = pickletools.optimize(payload)
pickletools.dis(pickled_bomb)
```

This gives us the pickle bytecode, however it seems to be incomplete:
```
  ...
  266: R    REDUCE
  267: .    STOP
highest protocol among opcodes = 4
```

The problem is that disassembly stops once it encounters the `STOP` instruction. To fix that,
we replace all `STOP` instructions with anohter one that doesn't break the code:
```python
import pickletools

payload = payload.replace(b'.', b'I9999\n') + b'.'

pickled_bomb = pickletools.optimize(payload)
pickletools.dis(pickled_bomb)
```

Then we can get the full disassembly listing and we reverse it using the
[Opcode Reference](https://docs.juliahub.com/Pickle/LAUNc/0.1.0/opcode):
```assembly
    0: \x8c SHORT_BINUNICODE 'builtins'         ;
   10: \x8c SHORT_BINUNICODE 'getattr'          ;
   19: \x93 STACK_GLOBAL                        ; S = [getattr]
   20: p    PUT        0                        ; M = [getattr]
   23: 2    DUP                                 ;
   24: \x8c SHORT_BINUNICODE 'builtins'         ;
   34: \x8c SHORT_BINUNICODE 'input'            ;
   41: \x93 STACK_GLOBAL                        ;
   42: \x8c SHORT_BINUNICODE 'FLAG> '           ; S = ['FLAG >', input, getattr]
   50: \x85 TUPLE1                              ; S = [('FLAG >'), input, getattr]
   51: R    REDUCE                              ; S = [input('FLAG >'), getattr]
   52: \x8c SHORT_BINUNICODE 'encode'           ; S = [encode, input('FLAG >'), getattr]    ~>   stack[-2:] = [tuple(stack[-2:])]
   60: \x86 TUPLE2                              ; S = [(input('FLAG >'), encode), getattr]
   61: R    REDUCE                              ; S = [getattr(input('FLAG >'), encode)] = [input['FLAG >').encode]
   62: )    EMPTY_TUPLE                         ; S = [(), input('FLAG >').encode]
   63: R    REDUCE                              ; S = [input('FLAG >').encode()]
   64: p    PUT        1                        ; M = [getattr, input('FLAG >').encode()]
   67: 0    POP                                 ; S = [getattr]]
   68: g    GET        0                        ;
   71: \x8c SHORT_BINUNICODE 'builtins'         ;
   81: \x8c SHORT_BINUNICODE 'dict'             ; S = [dict, getattr]
   87: \x93 STACK_GLOBAL                        ;
   88: \x8c SHORT_BINUNICODE 'get'              ; S = [get, dict, getattr]
   93: \x86 TUPLE2                              ; S = [(dict, get), getattr]
   94: R    REDUCE                              ; S = [getattr(dict, get)] = [dict.get]
   95: \x8c SHORT_BINUNICODE 'builtins'         ;
  105: \x8c SHORT_BINUNICODE 'globals'          ; S = [globals, dict.get]
  114: \x93 STACK_GLOBAL                        ; S = [globals, dict.get, getattr]
  115: )    EMPTY_TUPLE                         ; S = [(), globals, dict.get, getattr]
  116: R    REDUCE                              ; S = [globals(), dict.get, getattr]
  117: \x8c SHORT_BINUNICODE 'f'                ; S = [f, globals(), dict.get], getattr
  120: \x86 TUPLE2                              ; S = [(globals(), f), dict.get], getattr
  121: R    REDUCE                              ; S = [dict.get(globals(), f)], getattr
  122: \x8c SHORT_BINUNICODE 'seek'             ; S = [seek, dict.get(globals(), f)], getattr
  128: \x86 TUPLE2                              ; S = [(dict.get(globals(), f), seek), getattr] = [(globals()['f'], seek), getattr]
  129: R    REDUCE                              ; S = [getattr(globals()['f'], seek)] = [globals()['f'].seek]
  130: p    PUT        2                        ; M = [getattr, input('FLAG >').encode(), globals()['f'].seek]
  133: g    GET        0                        ; S = [getattr, globals()['f'].seek]
  136: \x8c SHORT_BINUNICODE 'builtins'         ;
  146: \x8c SHORT_BINUNICODE 'int'              ;
  151: \x93 STACK_GLOBAL                        ;
  152: \x8c SHORT_BINUNICODE '__add__'          ; S = [__add__, int, getattr, ...]
  161: \x86 TUPLE2                              ; S = [(int, __add__), getattr, ...]
  162: R    REDUCE                              ; S = [getattr(int, __add__)] = [int.__add__]
  163: p    PUT        3                        ; M += int.__add__
  166: 0    POP                                 ;
  167: g    GET        0                        ; S = [getattr]
  170: \x8c SHORT_BINUNICODE 'builtins'         ;
  180: \x8c SHORT_BINUNICODE 'int'              ;
  185: \x93 STACK_GLOBAL                        ;
  186: \x8c SHORT_BINUNICODE '__mul__'          ;
  195: \x86 TUPLE2                              ;
  196: R    REDUCE                              ; M += int.__mul__
  197: p    PUT        4                        ;
  200: 0    POP                                 ;
  201: g    GET        0                        ;
  204: \x8c SHORT_BINUNICODE 'builtins'         ;
  214: \x8c SHORT_BINUNICODE 'int'              ;
  219: \x93 STACK_GLOBAL                        ;
  220: \x8c SHORT_BINUNICODE '__eq__'           ;
  228: \x86 TUPLE2                              ;
  229: R    REDUCE                              ; M += int.__eq__
  230: p    PUT        5                        ;
  233: 0    POP                                 ;
                                                ; MEMO SO FAR:
                                                ;   0: getattr
                                                ;   1: input('FLAG >').encode()
                                                ;   2: globals()['f'].seek
                                                ;   3: int.__add__
                                                ;   4: int.__mul__
                                                ;   5: int.__eq__
  234: g    GET        3                        ;
  237: g    GET        5                        ; S = [__eq__, __add__]
  240: \x8c SHORT_BINUNICODE 'builtins'         ;
  250: \x8c SHORT_BINUNICODE 'len'              ;
  255: \x93 STACK_GLOBAL                        ;
  256: g    GET        1                        ; S = [input('FLAG >').encode(), len, __eq__, __add__, globals()['f'].seek]
  259: \x85 TUPLE1                              ; 
  260: R    REDUCE                              ; S = [len(input('FLAG >').encode()), __eq__, __add__]
  261: M    BININT2    64                       ; 
  264: \x86 TUPLE2                              ; S = [(len(input('FLAG >').encode()), 64) __eq__, __add__]
  265: R    REDUCE                              ; S = [int.__eq__(len(input('FLAG >').encode()), 64), __add__]
  266: M    BININT2    261                      ;
  269: \x86 TUPLE2                              ;
  270: R    REDUCE                              ; S = [__add__(int.__eq__(len(input('FLAG >').encode()), 64), 261)]
  271: \x85 TUPLE1                              ;
  272: R    REDUCE                              ; S = [globals()['f'].seek((len(input('FLAG >').encode()) == 64) + 261)]
  273: I    INT        9999                     ; I added this instruction to replace STOP
; ------------------------------------------------------------------------------
  279: 0    POP                                 ;
  280: g    GET        0                        ;
  283: g    GET        1                        ;
  286: \x8c SHORT_BINUNICODE '__getitem__'      ;
  299: \x86 TUPLE2                              ; S = [(input('FLAG >').encode(), __getitem__), getattr]
  300: R    REDUCE                              ; S = [input('FLAG >').encode().__getitem__]
  301: p    PUT        6                        ; M += input('FLAG >').encode().__getitem__
  304: 0    POP                                 ;
  305: M    BININT2    0                        ;
  308: p    PUT        7                        ; M += 0 (or i, this should be a variable initialied to 0)
  311: 0    POP                                 ;
  312: g    GET        2                        ;
  315: g    GET        3                        ;
  318: g    GET        0                        ;
  321: g    GET        6                        ;
  324: g    GET        7                        ; S = [i, input('FLAG >').encode().__getitem__, getattr, __add__, globals()['f'].seek]
  327: \x85 TUPLE1                              ;
  328: R    REDUCE                              ; S = [input('FLAG >').encode()[i], ...]
  329: \x8c SHORT_BINUNICODE '__le__'           ;
  337: \x86 TUPLE2                              ;
  338: R    REDUCE                              ;
  339: M    BININT2    127                      ;
  342: \x85 TUPLE1                              ;
  343: R    REDUCE                              ;
  344: M    BININT2    330                      ;
  347: \x86 TUPLE2                              ;
  348: R    REDUCE                              ; S = [__add__(input('FLAG >').encode()[i] <= 127, 330), ...]
  349: \x85 TUPLE1                              ;
  350: R    REDUCE                              ; S = [globals()['f'].seek(input('FLAG >').encode()[i] <= 127 +  330), ...]
  351: I    INT        9999                     ; I added this instruction to replace STOP
; ------------------------------------------------------------------------------
  357: 0    POP                                 ;
  358: g    GET        2                        ;
  361: g    GET        3                        ;
  364: g    GET        4                        ;
  367: g    GET        5                        ;
  370: g    GET        3                        ;
  373: g    GET        7                        ;
  376: M    BININT2    1                        ; S = [1, i, __add__, __eq__, __mul__, __add__, globals()['f'].seek]
  379: \x86 TUPLE2                              ;
  380: R    REDUCE                              ;
  381: p    PUT        8                        ; M += __add__(i, 1)
  384: M    BININT2    64                       ;
  387: \x86 TUPLE2                              ;
  388: R    REDUCE                              ; S = [i + 1 == 64, ...] 
  389: M    BININT2    85                       ;
  392: \x86 TUPLE2                              ; S = [(i + 1 == 64) * 85, ...]
  393: R    REDUCE                              ;
  394: M    BININT2    290                      ;
  397: \x86 TUPLE2                              ;
  398: R    REDUCE                              ; S = [(i + 1 == 64)*85 + 290, ...]
  399: \x85 TUPLE1                              ;
  400: R    REDUCE                              ; S = [globals()['f'].seek((i + 1 == 64)*85 + 290)
  401: 0    POP                                 ;
  402: g    GET        0                        ;
  405: g    GET        0                        ; S = [getattr, getattr]
  408: ]    EMPTY_LIST                          ; S = [[], getattr, getattr]
  409: p    PUT        9                        ; M += [] = `inp` initialized to empty list
  412: \x8c SHORT_BINUNICODE 'append'           ;
  420: \x86 TUPLE2                              ;
  421: R    REDUCE                              ;
  422: p    PUT        10                       ; M += inp.append
  426: 0    POP                                 ;
  427: g    GET        9                        ;
  430: \x8c SHORT_BINUNICODE '__getitem__'      ;
  443: \x86 TUPLE2                              ; S = [getattr([], __getitem__), ...]
  444: R    REDUCE                              ;
  445: p    PUT        11                       ; M += inp.__getitem__
  449: 0    POP                                 ;
  450: g    GET        0                        ;
  453: \x8c SHORT_BINUNICODE 'builtins'         ;
  463: \x8c SHORT_BINUNICODE 'int'              ; 
  468: \x93 STACK_GLOBAL                        ;
  469: \x8c SHORT_BINUNICODE 'from_bytes'       ; S = [from_bytes, int]
  481: \x86 TUPLE2                              ;
  482: R    REDUCE                              ;
  483: p    PUT        12                       ; M += int.from_bytes
                                                ; MEMO SO FAR:
                                                ;   0: getattr
                                                ;   1: input('FLAG >').encode()
                                                ;   2: globals()['f'].seek
                                                ;   3: int.__add__
                                                ;   4: int.__mul__
                                                ;   5: int.__eq__
                                                ;   6: input('FLAG >').encode().__getitem__
                                                ;   7: i (=0)
                                                ;   8: __add__(i, 1)
                                                ;   9: inp
                                                ;  10: inp.append
                                                ;  11: inp.__getitem__
                                                ;  12: int.from_bytes
  487: 0    POP                                 ;
  488: M    BININT2    0                        ;
  491: p    PUT        13                       ; M += j (=0)
  495: 0    POP                                 ;
  496: g    GET        10                       ;
  500: g    GET        12                       ;
  504: g    GET        6                        ;
  507: \x8c SHORT_BINUNICODE 'builtins'         ;
  517: \x8c SHORT_BINUNICODE 'slice'            ; S = [slice, input('FLAG >').encode().__getitem__, int.from_bytes, [].append]
  524: \x93 STACK_GLOBAL                        ;
  525: g    GET        4                        ;
  528: g    GET        13                       ;
  532: M    BININT2    8                        ; S = [8, j, __mul__, slice, ...] 
  535: \x86 TUPLE2                              ;
  536: R    REDUCE                              ; S = [__mul__(8, j), slice, ...]
  537: g    GET        4                        ;
  540: g    GET        3                        ;
  543: g    GET        13                       ;
  547: M    BININT2    1                        ; S = [1, j, __add__, __mul__, __mul__(8, j), slice, ...]
  550: \x86 TUPLE2                              ; 
  551: R    REDUCE                              ;
  552: M    BININT2    8                        ; S = [8, __add__(1, j), __mul__, __mul__(8, j), slice, ...] 
  555: \x86 TUPLE2                              ;
  556: R    REDUCE                              ; S = __mul__(8, __add__(1, j)), __mul__(8, j), slice, ...]
  557: \x86 TUPLE2                              ;
  558: R    REDUCE                              ; S = [slice(8*j, 8*(j+1)), ...]
  559: \x85 TUPLE1                              ;
  560: R    REDUCE                              ; S = [input('FLAG >').encode()[slice(8*j, 8*(j+1))], ...]
  561: \x8c SHORT_BINUNICODE 'little'           ; S = ['little', ...]
  569: \x86 TUPLE2                              ;
  570: R    REDUCE                              ; S = [int.from_bytes(input('FLAG >').encode()[slice(8*j, 8*(j+1))], 'little')]
  571: \x85 TUPLE1                              ;
  572: R    REDUCE                              ; S = [inp.append(int.from_bytes(input('FLAG >').encode()[slice(8*j, 8*(j+1))], 'little'))]
                                                ; 
                                                ; Split flag in groups of 8 bytes and convert them to 64-bit ints:
  572: R    REDUCE                              ;   ~~~> inp.append(int.from_bytes(input('FLAG >').encode()[slice(8*j, 8*(j+1))], 'little'))
  573: 0    POP                                 ;
  574: g    GET        2                        ;
  577: g    GET        3                        ;
  580: g    GET        4                        ;
  583: g    GET        5                        ;
  586: g    GET        3                        ;
  589: g    GET        13                       ;
  593: M    BININT2    1                        ; S = [1, j, __add__, __eq__,  __mul__, __add__, globals()['f'].seek, ...]
  596: \x86 TUPLE2                              ;
  597: R    REDUCE                              ; (ops for .seek() argument ~> ignore them) 
  598: p    PUT        14                       ;
  602: M    BININT2    8                        ;
  605: \x86 TUPLE2                              ;
  606: R    REDUCE                              ;
  607: M    BININT2    119                      ;
  610: \x86 TUPLE2                              ;
  611: R    REDUCE                              ;
  612: M    BININT2    457                      ;
  615: \x86 TUPLE2                              ;
  616: R    REDUCE                              ;
  617: \x85 TUPLE1                              ;
  618: R    REDUCE                              ;
  619: 0    POP                                 ;
  620: g    GET        0                        ; S = [getattr]
  623: ]    EMPTY_LIST                          ;
  624: p    PUT        15                       ; M += [] = out = an empty list named `out`
  628: \x8c SHORT_BINUNICODE 'append'           ;
  636: \x86 TUPLE2                              ;
  637: R    REDUCE                              ; S = [out.append, ...]
  638: p    PUT        16                       ; M += out.append
  642: 0    POP                                 ;
  643: g    GET        0                        ;
  646: g    GET        15                       ; S = [out, getattr]
  650: \x8c SHORT_BINUNICODE '__getitem__'      ;
  663: \x86 TUPLE2                              ;
  664: R    REDUCE                              ;
  665: p    PUT        17                       ; M += out.__getitem__
  669: 0    POP                                 ;
  670: g    GET        0                        ; S = [getattr]
  673: \x8c SHORT_BINUNICODE 'builtins'         ;
  683: \x8c SHORT_BINUNICODE 'int'              ;
  688: \x93 STACK_GLOBAL                        ;
  689: \x8c SHORT_BINUNICODE '__xor__'          ; S = [int.__xor__, getattr]
  698: \x86 TUPLE2                              ;
  699: R    REDUCE                              ;
  700: p    PUT        18                       ; M += __xor__
  704: 0    POP                                 ;
  705: I    INT        1244422970072434993      ;
  726: p    PUT        19                       ; M += 1244422970072434993 = c
  730: 0    POP                                 ;
  731: M    BININT2    0                        ;
  734: p    PUT        20                       ; M += k (=0)
  738: 0    POP                                 ;
  739: g    GET        16                       ; S = [out.append]
  743: \x8c SHORT_BINUNICODE 'builtins'         ;
  753: \x8c SHORT_BINUNICODE 'pow'              ;
  758: \x93 STACK_GLOBAL                        ;
  759: g    GET        18                       ;
  763: g    GET        11                       ;
  767: g    GET        20                       ; S = [k, inp.__getitem__, __xor__, __pow__]
  771: \x85 TUPLE1                              ;
  772: R    REDUCE                              ;
  773: g    GET        19                       ; S = [1244422970072434993, inp[k], __xor__, __pow__]
  777: \x86 TUPLE2                              ;
  778: R    REDUCE                              ; S = [__xor__(inp[k], 1244422970072434993), __pow__]
  779: I    INT        65537                    ;
  786: I    INT        18446744073709551557     ;
  808: \x87 TUPLE3                              ;
  809: R    REDUCE                              ; S = [__pow__(__xor__(inp[k], 1244422970072434993), 65537, 18446744073709551557)]
  810: \x85 TUPLE1                              ;   = [(inp[k] ^ c) ** 65537 % 18446744073709551557]

  811: R    REDUCE                              ;
  812: 0    POP                                 ;
  813: g    GET        17                       ;
  817: g    GET        20                       ; S = [k, out.__getitem__]
  821: \x85 TUPLE1                              ;
  822: R    REDUCE                              ;
  823: p    PUT        21                       ; M += out[k]
  827: 0    POP                                 ;
  828: g    GET        2                        ;
  831: g    GET        3                        ;
  834: g    GET        4                        ;
  837: g    GET        5                        ;
  840: g    GET        3                        ;
  843: g    GET        20                       ;
  847: M    BININT2    1                        ; S = [1, out.__getitem__, __add__, __eq__, __mul__, __add__, globals()['f'].seek]
  850: \x86 TUPLE2                              ;  
  851: R    REDUCE                              ; (ops for .seek() argument ~> ignore them)
  852: p    PUT        22                       ;
  856: M    BININT2    8                        ;
  859: \x86 TUPLE2                              ;
  860: R    REDUCE                              ;
  861: M    BININT2    131                      ;
  864: \x86 TUPLE2                              ;
  865: R    REDUCE                              ;
  866: M    BININT2    679                      ;
  869: \x86 TUPLE2                              ;
  870: R    REDUCE                              ;
  871: \x85 TUPLE1                              ;
  872: R    REDUCE                              ;
  873: 0    POP                                 ;
  874: g    GET        0                        ;
  877: g    GET        15                       ;
  881: \x8c SHORT_BINUNICODE '__eq__'           ;
  889: \x86 TUPLE2                              ;
  890: R    REDUCE                              ;
  891: (    MARK                                ; S = [8215359690687096682, ...]
  892: I        INT        8215359690687096682  ;
  913: I        INT        1862662588367509514  ;
  934: I        INT        8350772864914849965  ;
  955: I        INT        11616510986494699232 ;
  977: I        INT        3711648467207374797  ;
  998: I        INT        9722127090168848805  ;
 1019: I        INT        16780197523811627561 ;
 1041: I        INT        18138828537077112905 ;
 1063: l        LIST       (MARK at 891)        ; S = [[8215359690687096682, ..., 18138828537077112905]]
 1064: \x85 TUPLE1                              ;
 1065: R    REDUCE                              ;
 1066: I    INT        9999                     ;
 1072: .    STOP                                ;
```

This is what the above code does: First, it splits flag into groups of **64** bits:
```python
    inp.append(int.from_bytes(input('FLAG >').encode()[slice(8*j, 8*(j+1))], 'little'))
```

Then, for each flag part it does the following computation:
```python
    [(inp[k] ^ 1244422970072434993) ** 65537 % 18446744073709551557]
```

Finally, it checks if the result matches with the expected output:
```python
expected = [
    8215359690687096682, 1862662588367509514, 8350772864914849965,  11616510986494699232,
    3711648467207374797, 9722127090168848805, 16780197523811627561, 18138828537077112905
]
```

### Cracking the Flag

To get the flag we first need to solve the equation:
```
    (f ^ 1244422970072434993) ** 65537 == 8215359690687096682 mod 18446744073709551557
```

We use [Sage Math](https://sagecell.sagemath.org/):
```python
n = GF(18446744073709551557)
f = int(n(8215359690687096682).nth_root(65537)) ^^ 1244422970072434993
print(int(f).to_bytes(8, 'little'))
```

This gives us: `SECCON{C`. However, the next part (for **186266258836750951**) does not give
a valid flag. This is because the XOR key changes on every iteration (something which is not
obvious by looking at the code). Once we fix this, we recover all flag parts:
```python
expected = [
    8215359690687096682, 1862662588367509514, 8350772864914849965,  11616510986494699232,
    3711648467207374797, 9722127090168848805, 16780197523811627561, 18138828537077112905
]

n = GF(18446744073709551557)
c = 1244422970072434993
for e in expected:
  f = int(n(e).nth_root(65537)) ^^ c
  c = e
  print(int(f).to_bytes(int(8), 'little'))
```

Which gives us:
```
b'SECCON{C'
b'an_someo'
b'ne_pleas'
b'e_make_a'
b'_debugge'
b'r_for_Pi'
b'ckle_byt'
b'ecode??}'
```

So, the flag is: `SECCON{Can_someone_please_make_a_debugger_for_Pickle_bytecode??}`
___

