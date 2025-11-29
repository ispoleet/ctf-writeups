## Lake CTF 2025 - drum machine (RE 100)
##### 28/11 - 29/11/2025 (24hr)

___

### Description

*Can you recreate our beat?*

___

### Solution

This challenge was similar to Flare-On's
[ntfsm](https://github.com/ispoleet/flare-on-challenges/tree/master/flare-on-2025/05_ntfsm)
challenge (both challenges build a FSM/Graph and we need to find the longest path).

Binary is not stripped, so we start from `main`:
```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp) {
  /* ... */
  DrumMachine::DrumMachine(v10, argv);
  std::vector<Step>::vector(cp_vec);
  std::string::basic_string(inp_seq);
  v3 = std::operator<<<std::char_traits<char>>(&std::cout, "Welcome to the polygl0ts Drum Machine!");
  std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
  v4 = std::operator<<<std::char_traits<char>>(
         &std::cout,
         "During this machine's conception, we managed to create what we believe is the most magical beat invented");
  std::ostream::operator<<(v4, &std::endl<char,std::char_traits<char>>);
  v5 = std::operator<<<std::char_traits<char>>(&std::cout, "If you are able to recreate it, we will give you the flag!");
  std::ostream::operator<<(v5, &std::endl<char,std::char_traits<char>>);
  std::operator<<<std::char_traits<char>>(&std::cout, "Please input your beat sequence: ");
  std::operator>><char>(&std::cin, inp_seq);
  decomposeInput(out_vec, inp_seq);
  std::vector<Step>::operator=(cp_vec, out_vec);
  std::vector<Step>::~vector(out_vec);
  DrumMachine::setSteps(v10, cp_vec);           // assignment
  DrumMachine::playBeat(v10);
  if ( DrumMachine::getState(v10) == 181 )
    v6 = std::operator<<<std::char_traits<char>>(
           &std::cout,
           "Congratulations! You were able to recreate our magical beat. Isn't it great?");
  else
    v6 = std::operator<<<std::char_traits<char>>(&std::cout, "This beat is not really magical...");
  std::ostream::operator<<(v6, &std::endl<char,std::char_traits<char>>);
  exit(0);
}
```

Function `decomposeInput()` takes our input (flag) and builds a vector:
```c
void __fastcall decomposeInput(__int64 a1_out, __int64 a2_in) {
  /* ... */
  std::vector<Step>::vector(a1_out);
  for ( i = 0; ; ++i )
  {
    v5 = 42;
    inp_len = std::string::length(a2_in);
    v2 = std::min<int>(&inp_len, &v5);
    if ( i >= *v2 )
      break;
    nxt_chr = *std::string::operator[](a2_in, i);
    for ( j = 0; j <= 7; ++j )
    {
      if ( (nxt_chr >> j) & 1 )                 // for each bit set
      {
        Step::setHit(&v5, j);                   // assignment of the set bits
        std::vector<Step>::push_back(a1_out, &v5);
      }
    }
  }
}
```

For each character of the input, we add to the vector the position of the bits that are set.
For example if the character is `A` (**0x61**, or `0110 0001`), we add to the vector: `0, 5, 6`.

Then we go to the `playBeat()` where it verifies our vector:
```c
void __fastcall DrumMachine::playBeat(DrumMachine *this) {
  /* ... */
  v5[1] = this;
  vec_iter = std::vector<Step>::begin(this);
  v5[0] = std::vector<Step>::end(this);
  while ( __gnu_cxx::operator!=<Step *,std::vector<Step>>(&vec_iter, v5) )
  {
    v6 = __gnu_cxx::__normal_iterator<Step *,std::vector<Step>>::operator*(&vec_iter);
    Hit = Step::getHit(v6);                     // get next bit set from intput
    new_state = *(this + 8 * *(this + 1478) + Hit + 6);// v3 = this[8*state + bit_set + 6]
    ++*(this + Hit + 1487);                     // counter
    *(this + 1478) = new_state;
    __gnu_cxx::__normal_iterator<Step *,std::vector<Step>>::operator++(&vec_iter);
  }
  for ( i = 0; i <= 7; ++i )
  {
    if ( *(this + i + 1479) != *(this + i + 1487) )
      *(this + 1478) = 0;                       // reset state (we don't want this)
  }
}
```

Two things are happening here: First, we use the next number from the vector (bit position which
is **1**) to find the next state (we have **8** options). Initially `state` is **0**. Then we access `this[8*state + bit_set + 6]` to get the next state based on the next bit of the flag 
which is set. Second, we increment total number of bits which are set at this byte position:
`++*(this + Hit + 1487)`.

At the end, the total number of bits in each byte position needs to match the numbers at
`*(this + i + 1479)`. Also (looking back at `main()` the final state needs to be **181**).


These constants are initialized in `DrumMachine()` ctor:
```c
void __fastcall DrumMachine::DrumMachine(DrumMachine *this, __int64 a2) {
  _DWORD *v2; // rdi

  std::vector<Step>::vector(this, a2);
  v2 = (this + 24);
  memset(v2, 0, 0x1700uLL);
  *v2 = 1;
  *(this + 15) = 1;
  *(this + 16) = 2;
  *(this + 25) = 2;
  *(this + 26) = 4;
  *(this + 27) = 5;

  /**
   *  ....
   */
  
  *(this + 1434) = 179;
  *(this + 1443) = 180;
  *(this + 1452) = 181;
  *(this + 1461) = 184;
  *(this + 1478) = 0;                           // state
  *(this + 1479) = 23;                          // total number of bits
  *(this + 1480) = 21;
  *(this + 1481) = 32;
  *(this + 1482) = 19;
  *(this + 1483) = 17;
  *(this + 1484) = 31;
  *(this + 1485) = 38;
  *(this + 1486) = 0;
  *(this + 5948) = 0LL;
  *(this + 5956) = 0LL;
  *(this + 5964) = 0LL;
  *(this + 5972) = 0LL;
}
```
___


### Finding the Longest Path

The problem is clear now: We need to find which bits from the input to set, so the final state
is **181**. Furthermore, **-because we have many solutions-** the total number of bits which are 
**1** at position **0** must be **23**, the total number of bits which are **1** at position **1**
must be **21** and so on.


We start by reading the state using IDAPython. First set a breakpoint at:
```assembly
.text:000055555555584D        mov     ecx, [rbp+var_30]
.text:0000555555555850        movsxd  rcx, ecx
.text:0000555555555853        movsxd  rdx, edx
.text:0000555555555856        shl     rdx, 3
.text:000055555555585A        add     rdx, rcx
.text:000055555555585D        add     rdx, 4
.text:0000555555555861        mov     eax, [rax+rdx*4+8]        ; state array starts at: rax+8
.text:0000555555555865        mov     [rbp+new_state], eax
```

The read the `DWORDs` from address `[rax + 8]` (we don't know how many they are; 
just read **1000**):
```python
arr = [ida_bytes.get_dword(0x7FFFFFFFC308 + 4*i) for i in range(1500)]
for i in range(0, len(arr), 8):
    print(', '.join(f'0x{x:X}' for x in arr[i:i + 8]) + ',')
```

This is how it looks like:
```python
    0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,     # Bit transitions for state #0
    0x0, 0x1, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0,     # Bit transitions for state #1
    0x0, 0x0, 0x0, 0x2, 0x4, 0x5, 0x3, 0x0,     # Bit transitions for state #2
    0x6, 0x3, 0x3, 0x0, 0x4, 0x0, 0x0, 0x6,     # ...
    0x0, 0x0, 0x0, 0x0, 0x0, 0x4, 0x5, 0x0,
    0x5, 0x6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5,
```

The first row says that if the next bit from`input[0]` is **1** then we go to **state #1** (we
always start from **state #0**). If any other bit from `input[0]` is set we remain at **state #0**.
If we are in **state #1** and the next bit which is set is in position **0** we go back to
**state #0**. If the next bit which is set is at position **1**, we remain at **state #1**, if the
next bit set is at position **2** we move on to **state #2**, and so on.

Now we build the state graph and we look for a path from **state #0** to **state #181**.
Unfortunately, there are many solutions to it. To check if a solution is correct we count the
total number of bits set in each position and we check if it is `[23, 21, 32, 19, 17, 31, 38, 0]`.
I noticed that in any solution I was finding, the total number of bits was much smaller than the
target array, so I searched for the longest path.

The is a problem however: **The graph has cycles, so we cannot compute a longest path**. But 
we can easily solve this problem by removing the backward edges from the graph. We know that
a valid solution will always move forward.

For more details, please refer to the [drum_machine_crack.py](./drum_machine_crack.py) script.

So the flag is: `EPFL{dance_along_to_the_b34t_of_the_fl4g!}`

___