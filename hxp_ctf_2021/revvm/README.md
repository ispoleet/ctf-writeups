## HXP CTF 2021 - revvm (RE 833)
##### 17-19/12/2021 (48hr)
___

### Description
 
**Difficulty estimate:** hard - hard

**Points:** round(1000 · min(1, 10 / (9 + [3 solves]))) = 833 points

*If there was a talk about this VM it would start like this: I have no idea about computers, I don’t even own one.*
*All I use is my Mac. But I see it as my advantage. *
*While all these CS experts dismissed the idea as impractical and stupid, I sat down and got to work.*
*I contrived the VM design they couldn’t for they were blinded by their knowledge.*

Download:
```
revvm-0153f37f9eb4f3b5.tar.xz (16.9 KiB)
```
___

### Solution

This was a VM reversing challenge. There are a few interesting things about this VM:

* VM works with bit vectors (bit streams) instead of bytes
* VM is stack based, but it supports random access/write to stack
* VM executes instructions in parallel using separate contexts of stack and PC
* VM is written in C++ using STL vectors, lists and hash maps, which makes reversing very hard.

### Parallel Architecture

After a lot of effort on reconstructing the structs and the class objects, I managed to get a
reasonable version of the code.

Everything starts from main:
```c
__int64 __fastcall main(int argc, char **argv, char **argp) {
  /* var decls */ 
  rval = 0;
  if ( argc != 2 ) return rval;
  std::ifstream::basic_ifstream(ifstrm, argv[1], 6LL);
  rval = v24 & 5;
  if ( (v24 & 5) != 0 ) {
    std::operator<<<std::char_traits<char>>();
    std::operator<<<std::char_traits<char>>();
    std::operator<<<std::char_traits<char>>();
    std::endl<char,std::char_traits<char>>();
PROGRAM_END:
    std::ifstream::~ifstream(ifstrm);
    return 1;
  }
  vm_size = std::istream::tellg(ifstrm);
  vm_size_ = vm_size;
  if ( vm_size <= 8 ) {                          // VM must be at least 8 bytes
    std::operator<<<std::char_traits<char>>();
    std::endl<char,std::char_traits<char>>();
    goto PROGRAM_END;
  }
  std::istream::seekg();
  vm_prog = operator new[](vm_size_);
  std::istream::read(ifstrm, vm_prog, vm_size_);
  u_initialize_vm_struct(
    &VM,
    vm_prog + 8,
    *vm_prog,                                   // 0xC4
    &vm_prog[*vm_prog + 8],                     // &vm_prog + 0xC4 + 8
    vm_size_ - 8 - *vm_prog);                   // vm_size - 8 - 0xC4
  operator delete[](vm_prog);                   // we don't need this guy anymore
  a2_head._M_node._M_prev = &a2_head;           // single list with 1 element only
  a2_head._M_node._M_next = &a2_head;
  a2_head._M_node._M_size = 0LL;
  a2_head.wnd_idx_ref = &a2_head.wnd_idx;
  a2_head.field_28 = 0LL;
  a2_head.wnd_idx = 0;
  p_obj = &a2_head.obj;
  for ( i = 16LL; i; --i )                      // => field_40 = 4*16 = 64 bytes
    *p_obj++ = 0;
  u_bzero_struc_2(&a2_head.obj);                // => field_40 = 0x30 bytes => WRONG!
  u_list_insert(&a2_head, &a2_head, &a2_head.obj);// => field_40 = 0x40 bytes
  u_list_clear(&a2_head.obj.next);
  u_some_cond_delete(&a2_head.obj);
  for ( curr = a2_head._M_node._M_next; a2_head._M_node._M_next != &a2_head; curr = a2_head._M_node._M_next )// iterate over the list
  {
    // list = pop_front() ?
    a2_head.obj._M_next = curr->st_next;
    a2_head.obj._M_prev = curr->st_finish;
    a2_head.obj.insn_len = curr->st_size;
    curr->st_size = 0LL;
    curr->st_finish = 0LL;
    curr->st_next = 0LL;
    a2_head.obj.next = curr->next;
    curr->next = 0LL;
    a2_head.obj.bitvec_end = curr->len_in_bits;
    a2_head.obj.bit_in_byte = curr->bit_start;
    a2_head.obj.wnd_idx = curr->wnd_idx;
    a2_head.obj.spinlock_count = curr->spinlock_count;
    --a2_head._M_node._M_size;                  // _M_dec_size(a1, 1LL)
    // void _List_node_base::_M_unhook() _GLIBCXX_USE_NOEXCEPT {
    //   _List_node_base* const __next_node = this->_M_next;
    //   _List_node_base* const __prev_node = this->_M_prev;
    //   __prev_node->_M_next = __next_node;
    //   __next_node->_M_prev = __prev_node;
    // }
    std::__detail::_List_node_base::_M_unhook(curr);// remove node
    A = curr->next;                             // this is always 0 (from above)
    if ( A ) {
      /* more deletes on ->next. */
    }
    st_next = curr->st_next;
    if ( st_next )
      operator delete(st_next, curr->st_size - st_next);
    operator delete(curr, 0x50uLL);             // curr is 0x50 bytes
    if ( a2_head.obj.spinlock_count ) {
      --a2_head.obj.spinlock_count;
      u_list_insert(&a2_head, &a2_head, &a2_head.obj);// insert 0x50
      u_list_clear(&a2_head.obj.next);
      u_some_cond_delete(&a2_head.obj);
    } else {
      u_emulate_instruction(&a1_next, &a2_head.obj, &VM);
      // splice() ? (merge 2 lists)
      if ( a1_next._M_next != &a1_next ) {        // !__x.empty()
        // IMPORTANT: SET head._M_next to NEXT
        std::__detail::_List_node_base::_M_transfer(&a2_head, a1_next._M_next, &a1_next);
        a2_head._M_node._M_size += a1_next._M_size;
        a1_next._M_size = 0LL;
      }
      u_delete_all(&a1_next);                   // dispose next (not needed anymore)
      u_list_clear(&a2_head.obj.next);
      u_some_cond_delete(&a2_head.obj);
    }
  }
  std::string::_M_dispose(&a2_head.wnd_idx_ref);
  u_delete_all(&a2_head);
  u_clear_memory(&VM);
  std::ifstream::~ifstream(ifstrm);
  return rval;
}
```

After the program is loaded into memory, there's a big `for` loop that emulates program
instructions. The interesting part is that **from a given instruction, there can be more than one
possible instructions that can be decoded and executed next**. Program uses a **sliding window**
of **76** bits and tries to decode all instructions inside that window. For instance:
```
[+] Extracting instructions from 1101000001010000000100001011010001011101001010100110100111100101110000000100 at: 0h
[+]    .text:0000+0E=000E    STCK_RD  0x0                (W: 2)
[+]    .text:0000+3A=003A    PUSH     0x80E9E5952E8      (W:46)
[+] Extracting instructions from 0110100000000111010000010100000001000010110100010111010010101001101001111001 at: Eh
[+]    .text:000E+24=0032    SVC      0x9E5952           (W:24)
[+] Extracting instructions from 0100000001110000011110100000010000000100000001101000000001110100000101000000 at: 3Ah
[+]    .text:003A+12=004C    SVC      0x0                (W: 6)
[+]    .text:003A+1B=0055    ADD      0x141              (W:15)
[+]    .text:003A+2D=0067    ADD      0x505C02C          (W:33)
```

Here, starting from the beginning (`PC = 0`), there are **2** possible instructions: `STCK_RD  0x0`
at offset `0Eh` and `PUSH 0x80E9E5952E8` at offset `3Ah`. If we choose to follow first instruction,
then, the next instruction (starting from `PC = 0Eh`) is `SVC 0x9E5952` (which is invalid). But
if we choose to follow the second instruction ,we can continue from `3Ah` so we have **3** new
instructions to follow. That is, **there are multiple ways to decode the VM program, however not all
of them are correct**.

Since the program does not know which decoding is the correct one, it executes all of them
**in parallel** maintains an `STL::list` of all contexts. When the emulation of instruction raises
an exception, the context is discared. If an instruction has multiple next instructions, emulator
forks the context (stack & program counter), executes all instructions in different contexts and
merges all contexts to the list (using the `splice` function).

Function `u_emulate_instruction` tries to emulate all instructions in the sliding window:
```c
void __fastcall u_emulate_instruction(_List_node_header *a1_next, struc_2 *a2_curr, vm_struct *VM) {
  /* decls */
  u_decode_next_instruction(&node, VM, a2_curr->wnd_idx);// arg3: where window starts in bitvec
  a1_next->_M_prev = a1_next;
  a1_next->_M_next = a1_next;
  a1_next->_M_size = 0LL;
  if ( a2_curr->spinlock_count ){
    // ANTI-RE MAYBE?
    // we can't bypass the sleep count (it has to become 0 before we can move on)
    exception = __cxa_allocate_exception(0x10uLL);
    std::runtime_error::runtime_error(exception, "sleepwalking is not allowed");
    __cxa_throw(exception, &typeinfo forstd::runtime_error, &std::runtime_error::~runtime_error);
  }

  M_next = node._M_next;
  if ( node._M_next != &node ){
    while ( 1 ) {
      u_prepare_insn(&insn, &M_next->insn_len);
      u_bitvec_ctor(&stack, a2_curr);
      wnd_idx = a2_curr->wnd_idx;
      spinlock_count = a2_curr->spinlock_count;
      u_VM_LOOP(important, &insn, wnd_idx, &VM->vm_input, &stack);
      if ( important[2] <= 1 )
        goto ADD_INSN_TO_QUEUE;                 // skip code below
      // only important[0] = nxt_wnd is used
      cur_Val = (*u_map_insert_maybe(&VM->important_2, important) + 1);
      if ( important[2] < cur_Val )             // important[2] < map[nxt_wnd] + 1 ?
        break;                                  // goto HERE & add insn
      *u_map_insert_maybe(&VM->important_2, important) = cur_Val;// map[nxt_wnd] += 1
      A = stack.next;
      if ( stack.next ) {
         /* ... just deletes ...*/          
      }
      if ( stack._M_impl._M_start )
        operator delete(stack._M_impl._M_start, stack._M_impl._M_end_of_storage - stack._M_impl._M_start);
      if ( insn.hook_fptr )
        operator delete(insn.hook_fptr, 0x10uLL);
      stack_ptr = insn.stack_ptr;
      if ( !insn.stack_ptr )
        goto LABEL_77;
LABEL_76:
      operator delete(stack_ptr, 0x10uLL);
LABEL_77:
      M_next = M_next->_M_next;
      if ( M_next == &node )
        goto LABEL_79;
    }
    // this is HERE
    *u_map_insert_maybe(&VM->important_2, important) = 0LL;// map[nxt_wnd] = 0
ADD_INSN_TO_QUEUE:
    a2_curr->spinlock_count = important[1];
    wnd_idx = important[0];
    NEXT = operator new(0x50uLL);
    NEXT->st_next = stack._M_impl._M_start;
    NEXT->st_finish = stack._M_impl._M_finish;
    NEXT->st_size = stack._M_impl._M_end_of_storage;
    memset(&stack, 0, 0x18);
    NEXT->next = stack.next;
    stack.next = 0LL;
    NEXT->len_in_bits = stack.len_in_bits;
    NEXT->bit_start = stack.bit_start;
    NEXT->wnd_idx = wnd_idx;                    // THIS IS NEXT !!!!
    NEXT->spinlock_count = spinlock_count;
    std::__detail::_List_node_base::_M_hook(NEXT, a1_next);
    ++a1_next->_M_size;
    G = stack.next;
    if ( stack.next ) {
        /* ... just deletes ...*/          
    }
    if ( stack._M_impl._M_start )
      operator delete(stack._M_impl._M_start, stack._M_impl._M_end_of_storage - stack._M_impl._M_start);
    if ( insn.hook_fptr )
      operator delete(insn.hook_fptr, 0x10uLL);
    stack_ptr = insn.stack_ptr;
    if ( !insn.stack_ptr )
      goto LABEL_77;
    goto LABEL_76;
  }
LABEL_79:
  u_recursive_delete(&node);
}
```

### Instruction Decoding

Decoding takes place in `u_decode_next_instruction`, which creates a list of all possible decoded
instructions for the current sliding window (starting from offset `12` up to `12 + 64`):
```c
void __fastcall u_decode_next_instruction(struc_2 *a1, vm_struct *VM, size_t a3_wnd_idx) {
  /* decls */
  start_bitvec = a3_wnd_idx;
  v3 = sub_55555555D68E(&VM->field_30, a3_wnd_idx % VM->field_38, &start_bitvec);
  if ( v3 && (v4 = *v3) != 0 ) {
    a1->_M_prev = a1;
    a1->_M_next = a1;
    a1->insn_len = 0LL;
    v5 = (v4 + 16);
    v6 = *(v4 + 16);
    if ( (v4 + 16) != v6 ) {
      do {
        v8 = operator new(0x30uLL);
        v7 = v8;
        obj._M_next = a1;
        obj._M_prev = v8;
        u_prepare_insn((v8 + 16), (v6 + 2));
        std::__detail::_List_node_base::_M_hook(v7, a1);
        ++a1->insn_len;
        v6 = *v6;
      } while ( v5 != v6 );
    }
  } else{
    v46._M_prev = &v46;
    v46._M_next = &v46;
    v46.st_next = 0LL;
    u_init_bitvec_recursive(&obj, VM, a3_wnd_idx);// move vm code around?
    u_list_search_till_len(&obj.wnd_idx, &obj, 0x4CuLL);// MAX INSN SIZE: 0x4C
                                                // MIN INSN SIZE: 0x0C
    next = obj.next;
    if ( obj.next ) {
      /* ... just deletes ...*/
    }
    if ( obj._M_next )
      operator delete(obj._M_next, obj.insn_len - obj._M_next);
    bitvec_end_ptr_recursive = u_get_bitvec_end_ptr_recursive(&obj.wnd_idx);// 0x4C unless we're at the end?
    if ( bitvec_end_ptr_recursive > 0xB )
    {
      for ( i = 12LL; i <= bitvec_end_ptr_recursive; ++i )// 12 is min insn size in bits
      {
        u_bitvec_repeated_get_recursive(&obj, &obj.wnd_idx, i);
        v16 = operator new(0x30uLL);
        p_M_prev = &v46;
        v42 = v16;
        u_parse_insn_to_struct((v16 + 16), &obj);
        std::__detail::_List_node_base::_M_hook(v16, &v46);
        ++v46.st_next;
        v17 = obj.next;
        if ( obj.next ) {
            /* ... just deletes ...*/          
        }
        if ( obj._M_next )
          operator delete(obj._M_next, obj.insn_len - obj._M_next);
      }
    }
    obj._M_next = a3_wnd_idx;
    obj.insn_len = &obj._M_prev;
    obj._M_prev = &obj._M_prev;
    obj.next = 0LL;
    for ( j = v46._M_next; j != &v46; j = j->_M_next )// add each successfully parsed insn to stl::list
    {
      v26 = operator new(0x30uLL);
      v25 = v26;
      p_M_prev = &obj._M_prev;
      v42 = v26;
      u_prepare_insn((v26 + 16), &j->st_next);
      std::__detail::_List_node_base::_M_hook(v25, &obj._M_prev);
      ++obj.next;
    }

    /* ... */
}
```

The interesting functions here are the `u_bitvec_multiget_recursive`, that returns a continuous
stream of bits for a list of bit vector chunks:
```c
// Let's say you want to get 10 bits:
// 
// If bitvec has 20 bits => get the first 10.
// If bitvec has 7  bits => get all 7 and then recurse with size 10-7=3 to get the 3 again
void __fastcall u_bitvec_multiget_recursive(_Vector_impl_data *a1_bitvec, _Vector_impl_data *a2, size_t a3_idx) {
  /* ... */
}
```

Finally, the `u_parse_insn_to_struct` decodes a bit vector into an instruction:
```c
// Parse a bitstream instruction into a vm_insn struct obj
void __fastcall u_parse_insn_to_struct(vm_insn *a1, struc_2 *a2) {
  /* decls */
  a1->stack_ptr = 0LL;
  a1->hook_fptr = 0LL;
  a1->bitvec_end = u_get_bitvec_end_ptr_recursive(a2);
  bitvec_end_ptr = u_get_bitvec_end_ptr_recursive(a2);
  insn_sz = a1->bitvec_end - 0xC;
  if ( insn_sz > 0x40 ) {                       // instructions must be < 64 + 12 = 76 bits long
    exception = __cxa_allocate_exception(0x10uLL);
    std::runtime_error::runtime_error(exception, "unable to reconstruct instruction from bitvector: invalid size");
    __cxa_throw(exception, &typeinfo forstd::runtime_error, &std::runtime_error::~runtime_error);
  }

  u_init_bitvec_recursive(&a1a.wnd_idx, a2, insn_sz);
  // Treat vm program as a bitstream in reverse order :)
  _opcode_ = u_get_opcode_from_bitvec(&a1a.wnd_idx);// gets the next K bits from the VM program bitstream
  v7 = v52;
  if ( v52 ) {
    /* ... delete ->next ... */
  }
  if ( a1a.wnd_idx )
    operator delete(a1a.wnd_idx, v51 - a1a.wnd_idx);
  a1->op_hi = HIBYTE(_opcode_);
  op_lo = _opcode_ & 0x3F;                      // reserve 6 LSBits for instruction size
  op_lo_p1 = op_lo + 1;
  if ( (_opcode_ & 0x80u) == 0 )
  {
    if ( op_lo + 0xD != bitvec_end_ptr ) {
      v17 = __cxa_allocate_exception(0x10uLL);
      std::runtime_error::runtime_error(v17, "instruction and immediate size mismatch");
      __cxa_throw(v17, &typeinfo forstd::runtime_error, &std::runtime_error::~runtime_error);
    }
    if ( (_opcode_ & 0x40) != 0 ) {
      u_bitvec_repeated_get_recursive(&a1a.wnd_idx, a2, bitvec_end_ptr - 12);
      _operand_ = u_get_opcode_from_bitvec(&a1a.wnd_idx);// single operand ISA?
      v29 = v52;
      if ( v52 )
      {
            /* ... delete ->next ... */
      }
      if ( a1a.wnd_idx )
        operator delete(a1a.wnd_idx, v51 - a1a.wnd_idx);
    } else {
      u_bitvec_repeated_get_recursive(&a1a.wnd_idx, a2, bitvec_end_ptr - 12);
      u_invert_bitvec_maybe(&a1a, &a1a.wnd_idx);
      _operand_ = u_get_opcode_from_bitvec(&a1a);
      next = a1a.next;
      if ( a1a.next ) {
           /* ... delete ->next ... */
      }
      if ( a1a._M_next )
        operator delete(a1a._M_next, a1a.insn_len - a1a._M_next);
      v24 = v52;
      if ( v52 ) {
           /* ... delete ->next ... */
      }
      if ( a1a.wnd_idx )
        operator delete(a1a.wnd_idx, v51 - a1a.wnd_idx);
    }
    v34 = operator new(0x18uLL);
    u_arg_imm_ctor(v34, _operand_, op_lo_p1);
    stack_ptr = a1->stack_ptr;
    a1->stack_ptr = v34;
    if ( stack_ptr )
      operator delete(stack_ptr, 0x10uLL);
  } else {
    if ( HIBYTE(_opcode_) == 4 || HIBYTE(_opcode_) == 15 ) {
      v15 = __cxa_allocate_exception(0x10uLL);
      std::runtime_error::runtime_error(v15, "inappropriate combination of mnemonic and operand type");
      __cxa_throw(v15, &typeinfo forstd::runtime_error, &std::runtime_error::~runtime_error);
    }
    if ( bitvec_end_ptr != 12 ) {
      v16 = __cxa_allocate_exception(0x10uLL);
      std::runtime_error::runtime_error(v16, "inappropriate combination of operand type and immediate data");
      __cxa_throw(v16, &typeinfo forstd::runtime_error, &std::runtime_error::~runtime_error);
    }
    v36 = operator new(0x10uLL);
    u_ArgStk_ctor(v36, op_lo_p1);
    v37 = a1->stack_ptr;
    a1->stack_ptr = v36;
    if ( v37 )
      operator delete(v37, 0x10uLL);
  }
  // check how many arguments are required for the instruction (1 or 2)
  if ( glo_arg_cnt[a1->op_hi] == 2 ) {
    v38 = operator new(0x10uLL);
    u_ArgStk_ctor(v38, op_lo_p1);
    hook_fptr = a1->hook_fptr;
    a1->hook_fptr = v38;
    if ( hook_fptr )
      operator delete(hook_fptr, 0x10uLL);
  }
}
```

```c
__int64 __fastcall u_get_opcode_from_bitvec(_Vector_impl_data *a1) {

  u_get_vm_code_substream(a1);
  len = a1->len_in_bits;
  if ( len > 0x40 ) {
    exception = __cxa_allocate_exception(0x10uLL);
    std::runtime_error::runtime_error(exception, "not convertable with 64 bits");
    __cxa_throw(exception, &typeinfo forstd::runtime_error, &std::runtime_error::~runtime_error);
  }
  a1_ = a1->_M_impl._M_start;
  M_finish = a1->_M_impl._M_finish;
  if ( a1->_M_impl._M_start == M_finish ) {
    retv = 0LL;
  }
  else                                          // convert bytes to word/dword (little endian)
  {
    v5 = M_finish - a1_;
    i = 0LL;
    retv = 0LL;
    do {
      retv |= a1_[i] << (8 * i);
      ++i;
    } while ( i != v5 );
  }
  if ( len <= 0x3F )
    return ~(-1LL << len) & retv;
  return retv;
}
```

```c
void __fastcall u_get_vm_code_substream(_Vector_impl_data *vm_code) {
  /* decls */
  while ( 1 ) {
    len = vm_code_->len_in_bits;
    if ( len ) {
      if ( len > 8 ) {                          // do we have more than 8 bits?
        bit_st = vm_code_->bit_start;
        vm_start = vm_code_->_M_impl._M_start + (bit_st >> 3);
        vm_end = vm_code_->_M_impl._M_start + ((len + bit_st + 7) >> 3);
        A = VAL | (*vm_start >> (bit_st & 7) << idx);// modulo 8 (get start bit)
        val = A;
        v13 = idx - (vm_code_->bit_start & 7);  // modulo 8 again
        v13_ = v13;
        SHF = v13 + 8;                          // how many bits to get from the 1st byte
        if ( SHF > 7u ) {
          A_ = A;
          u_vector_emplace(&start, &A_);
          LOWORD(A) = BYTE1(A);
          val = A;
          SHF = v13_;
        }
        for ( vm_p = (vm_start + 1); vm_end - 1 != vm_p; ++vm_p ) {
          val |= *vm_p << SHF;                  // read next byte
          val_ = val;
          LOWORD(val) = BYTE1(val);
          v28[0] = val_;
          u_vector_emplace(&start, v28);
        }
        VAL = (*(vm_end - 1) << SHF) | val;
        idx = SHF + ((LOBYTE(vm_code_->bit_start) + vm_code_->len_in_bits - 1) & 7) + 1;
      } else {
        v7 = vm_code_->_M_impl._M_start + (vm_code_->bit_start >> 3);
        v8 = *v7 >> (vm_code_->bit_start & 7);
        if ( len > (8 - (vm_code_->bit_start & 7)) )
          v8 |= v7[1] << (8 - (vm_code_->bit_start & 7));
        VAL |= v8 << idx;
        idx += len;
      }
    }
    if ( idx > 7u ) {
      x = VAL;
      u_vector_emplace(&start, &x);
      LOWORD(VAL) = BYTE1(VAL);
      idx -= 8;
    }
    VAL = (glo_bit_masks[idx] & VAL);
    v3 += vm_code_->len_in_bits;
    next = vm_code_->next;
    if ( vm_code_ == vm_code ){
      vm_code_->next = 0LL;
    } else {
      if ( vm_code_->_M_impl._M_start )
        operator delete(vm_code_->_M_impl._M_start, vm_code_->_M_impl._M_end_of_storage - vm_code_->_M_impl._M_start);
      operator delete(vm_code_, 0x30uLL);
    }
    if ( !next )
      break;
    vm_code_ = next;
  }
  if ( idx ) {
    v27 = VAL;
    u_vector_emplace(&start, &v27);
  }
  M_start = vm_code->_M_impl._M_start;
  M_end_of_storage = vm_code->_M_impl._M_end_of_storage;
  vm_code->_M_impl._M_start = start;
  vm_code->_M_impl._M_finish = end;
  vm_code->_M_impl._M_end_of_storage = v24;
  vm_code->bit_start = 0LL;
  vm_code->len_in_bits = v3;
  if ( M_start )
    operator delete(M_start, M_end_of_storage - M_start);
}
```

The IDA Python script below is used to extract the bit vector with the VM program:
```python
# Treat vm program as a bitstream in reverse order :)

from ida_bytes import *
off = 0x7FFFFFFFD800

vm = ''.join([f'{get_byte(i):#010b}'[2:] for i in range(get_qword(off), get_qword(off + 8))][::-1])
size  = get_qword(off + 0x20)
start = get_qword(off + 0x28)

opcode = vm[len(vm)-start-size:len(vm)-start]
opcode = ('%X' % int(opcode, 2))

print(f'size={size}, start=0x{start:x}, vm={vm}, opcode={opcode}')
```

Finally, we can rewrite all of the above into Python:
```python
def _decode_insn(self, bitvec76, start, pos):
    """Decodes (or tries to) an instruction from a 64+12 bit vector."""
    insn_wnd = bitvec76[start:start + 0xC]  # Opcode is 12 bits long.        
    opcode   = int(insn_wnd, 2)        

    # print(f'[+] Instruction Window at {pos:2X}h: {insn_wnd} ~> Opcode: {opcode:03X}h')
    
    # Check if opcode is valid
    if opcode & 0x80 == 0:
        if (opcode & 0x3F) + 0xD != pos:
            raise IndexError("instruction and immediate size mismatch")
        
        if opcode & 0x40 != 0:
            insn_wnd2 = bitvec76[start + 0xC:]
            operand  = int(insn_wnd2, 2)
        else:
            insn_wnd2 = bitvec76[start + 0xC:]
            operand  = int(insn_wnd2[::-1], 2)

        width = (opcode & 0x3F) + 1
    else:
        if opcode & 0xFF00 == 0x400 or opcode & 0xFF00 == 0xF00:
            raise IndexError("inappropriate combination of mnemonic and operand type")
        if pos != 12:
            raise IndexError("inappropriate combination of operand type and immediate data")

        insn_wnd2, operand = None, None
        width = (opcode & 0x3F) + 1
    
    return opcode >> 8, operand, width
```

### Emulation

Going back to `u_emulate_instruction`, after `u_decode_next_instruction`, there is `u_VM_LOOP` that
emulates the instruction using a huge switch dispatcher.

Depending whether the emulation is successful or not it update it adds the updated context
(stack & PC) to the main list:
```c
void __fastcall u_VM_LOOP(
        unsigned __int64 *important,
        vm_insn *a2_insn,
        __int64 a3,
        const char *vm_inp,
        _Vector_impl_data *glo_stack) {
  /* decls */
  u_bitvec_ctor(&v194, glo_stack);
  operand = (*a2_insn->stack_ptr->ptr)(a2_insn->stack_ptr, glo_stack);
  top_val_of_stack = 0LL;
  important[1] = 0LL;
  important[2] = 0LL;
  next_wnd_idx = a2_insn->bitvec_end + a3;
  *important = next_wnd_idx;
  u_bzero_struc_2(&ctx);
  v189 = &v191;
  v190 = 0LL;
  LOBYTE(v191) = 0;
  hook_fptr = a2_insn->hook_fptr;
  if ( hook_fptr )
    top_val_of_stack = (**hook_fptr)(hook_fptr, glo_stack);// glo_stack_pop ?
  switch ( a2_insn->op_hi ) {
    case 0:
      // ----------------------------------------------------------------------------------------------------
      // ADD
      u_vector_push_back_num_as_bytes(&stack, top_val_of_stack + operand, a2_insn->stack_ptr->len);
      u_list_add_inverse(glo_stack, &stack);
      /* .... */
      goto FREE_N_RETURN;
    case 1:
      // ----------------------------------------------------------------------------------------------------
      // SUB
      u_vector_push_back_num_as_bytes(&stack, top_val_of_stack - operand, a2_insn->stack_ptr->len);
      u_list_add_inverse(glo_stack, &stack);
      /* .... */            
      goto FREE_N_RETURN;
    case 2:
      // ----------------------------------------------------------------------------------------------------
      // MUL
      st_width = a2_insn->stack_ptr->len;
      if ( st_width > 0x20 )
      {
        // 2 step multiplication (64 bits each time)
        mul = top_val_of_stack * operand;
        u_vector_push_back_num_as_bytes(&tmp_stack, mul, 0x40uLL);
        u_vector_push_back_num_as_bytes(&stack, *(&mul + 1), 2 * a2_insn->stack_ptr->len - 0x40);
        u_append_to_list(&tmp_stack, &stack);
        u_list_add_inverse(glo_stack, v24);
        v25 = stack.next;
        /* .... */            
        goto FREE_N_RETURN;
      }
      // ELSE CASE: width less < 32 bits => Regular mul
      u_vector_push_back_num_as_bytes(&stack, top_val_of_stack * operand, 2 * st_width);
      u_list_add_inverse(glo_stack, &stack);
      /* .... */            
      goto FREE_N_RETURN2;
    case 3:
      // ----------------------------------------------------------------------------------------------------
      // IDIV (integer division)
      // push divisor and modulo in stack
      if ( !operand )
      {
        exception = __cxa_allocate_exception(0x10uLL);
        std::runtime_error::runtime_error(exception, "division by zero");
        __cxa_throw(exception, &typeinfo for std::runtime_error, &std::runtime_error::~runtime_error);
      }
      u_vector_push_back_num_as_bytes(&tmp_stack, top_val_of_stack / operand, a2_insn->stack_ptr->len);
      u_vector_push_back_num_as_bytes(&stack, top_val_of_stack % operand, a2_insn->stack_ptr->len);
      u_append_to_list(&tmp_stack, &stack);
      u_list_add_inverse(glo_stack, v31);      
      /* .... */            
      goto FREE_N_RETURN;
    case 4:
      // ----------------------------------------------------------------------------------------------------
      // MOV IMM ? ~> PUSH
      u_vector_push_back_num_as_bytes(&stack, operand, a2_insn->stack_ptr->len);
      u_list_add_inverse(glo_stack, &stack);
      /* .... */
      goto FREE_N_RETURN;
    case 5:
      // ----------------------------------------------------------------------------------------------------
      // POP
      u_get_bitvec_n_swap(&stack, glo_stack, operand);// operand == len
      bitvec_end_ptr_recursive = u_get_bitvec_end_ptr_recursive(&stack);
      /* .... */
      if ( operand != bitvec_end_ptr_recursive )
      {
        v57 = __cxa_allocate_exception(0x10uLL);
        std::runtime_error::runtime_error(v57, "not enough space on the stack to pop");
        __cxa_throw(v57, &typeinfo for std::runtime_error, &std::runtime_error::~runtime_error);
      }
      goto FREE_N_RETURN;
    case 6:
      // ----------------------------------------------------------------------------------------------------
      // DUP
      u_bitvec_repeated_get_recursive(&a1_bitvec, glo_stack, operand);// operand == how many times to duplicate
      v58 = ctx._M_impl._M_start;
      M_end_of_storage = ctx._M_impl._M_end_of_storage;
      ctx._M_impl._M_start = a1_bitvec._M_impl._M_start;
      ctx._M_impl._M_finish = a1_bitvec._M_impl._M_finish;
      ctx._M_impl._M_end_of_storage = a1_bitvec._M_impl._M_end_of_storage;
      memset(&a1_bitvec, 0, 24);
      /* .... */
      if ( operand != u_get_bitvec_end_ptr_recursive(&ctx) )
      {
        v67 = __cxa_allocate_exception(0x10uLL);
        std::runtime_error::runtime_error(v67, "out of bounds: duplicating past end of stack");
        __cxa_throw(v67, &typeinfo for std::runtime_error, &std::runtime_error::~runtime_error);
      }
      u_list_add_inverse(glo_stack, &ctx);
      goto FREE_N_RETURN;
    case 7:
      // ----------------------------------------------------------------------------------------------------
      // STACK READ
      // (read len bits from operand offset and put them on top of stack)
      u_init_bitvec_recursive(&stack, glo_stack, operand);
      u_list_search_till_len(&var, &stack, a2_insn->stack_ptr->len);
      /* .... */
      if ( a2_insn->stack_ptr->len != u_get_bitvec_end_ptr_recursive(&ctx) )
      {
        v79 = __cxa_allocate_exception(0x10uLL);
        std::runtime_error::runtime_error(v79, "out of bounds: reading past end of stack");
        __cxa_throw(v79, &typeinfo for std::runtime_error, &std::runtime_error::~runtime_error);
      }
      u_list_add_inverse(glo_stack, &ctx);
      goto FREE_N_RETURN;
    case 8:
      // ----------------------------------------------------------------------------------------------------
      // STACK WRITE
      // Write the top of the stack (len bits) at operand offset
      u_get_bitvec_n_swap(&local_stack, glo_stack, a2_insn->stack_ptr->len + operand);
      /* .... */
      if ( a2_insn->stack_ptr->len + operand != u_get_bitvec_end_ptr_recursive(&ctx) )
      {
        v89 = __cxa_allocate_exception(0x10uLL);
        std::runtime_error::runtime_error(v89, "out of bounds: writing past end of stack");
        __cxa_throw(v89, &typeinfo for std::runtime_error, &std::runtime_error::~runtime_error);
      }
      u_bitvec_repeated_get_recursive(&tmp_stack, &ctx, operand);
      // WRITE TOP OF STACK!
      u_vector_push_back_num_as_bytes(&stack, top_val_of_stack, a2_insn->stack_ptr->len);
      u_append_to_list(&tmp_stack, &stack);
      u_list_add_inverse(glo_stack, v90);
      /* .... */
      goto FREE_N_RETURN;
    case 9:
      // ----------------------------------------------------------------------------------------------------
      // READ GLO DATA
      // Read len bits from VM input at offset `operand` and put them in top of the stack
      u_init_bitvec_recursive(&stack, vm_inp, operand);
      u_list_search_till_len(&tmp, &stack, a2_insn->stack_ptr->len);
      /* .... */
      if ( a2_insn->stack_ptr->len != u_get_bitvec_end_ptr_recursive(&ctx) )
      {
        v104 = __cxa_allocate_exception(0x10uLL);
        std::runtime_error::runtime_error(v104, "out of bounds: reading past end of global data");
        __cxa_throw(v104, &typeinfo for std::runtime_error, &std::runtime_error::~runtime_error);
      }
      // PUSH IN TOP OF STACK
      u_list_add_inverse(glo_stack, &ctx);
      goto FREE_N_RETURN;
    case 0xA:
      // ----------------------------------------------------------------------------------------------------
      // WRITE GLO DATA
      // Write len bits from top of the stack to VM Input at offset `operand`
      u_bitvec_repeated_get_recursive(&vm_stack, vm_inp, a2_insn->stack_ptr->len + operand);
      /* .... */
      if ( a2_insn->stack_ptr->len + operand != u_get_bitvec_end_ptr_recursive(&ctx) )
      {
        v114 = __cxa_allocate_exception(0x10uLL);
        std::runtime_error::runtime_error(v114, "out of bounds: writing past end of global data");
        __cxa_throw(v114, &typeinfo for std::runtime_error, &std::runtime_error::~runtime_error);
      }
      u_bitvec_repeated_get_recursive(&prnt_stk, &ctx, operand);
      // top of the stack as bitvec
      u_vector_push_back_num_as_bytes(&tmp_stack, top_val_of_stack, a2_insn->stack_ptr->len);
      u_append_to_list(&prnt_stk, &tmp_stack);
      v116 = v115;
      u_init_bitvec_recursive(&stack, vm_inp, a2_insn->stack_ptr->len + operand);
      u_append_to_list(v116, &stack);
      /* .... */
      goto FREE_N_RETURN;
    case 0xB:
      // ----------------------------------------------------------------------------------------------------
      // JZ (OR BEQ)
      if ( !top_val_of_stack )
        *important = next_wnd_idx + operand;
      goto FREE_N_RETURN;
    case 0xC:
      // ----------------------------------------------------------------------------------------------------
      // JMP IMM
      *important = operand;
      goto FREE_N_RETURN;
    case 0xD:
      // ----------------------------------------------------------------------------------------------------
      // SYSCALL
      // We have 4 syscall numbers (0, 1, 2, 3)
      //   0 ~> print 1 letter
      //   1 ~> read byte
      //   2 ~> print long
      //   3 ~> read long
      if ( operand == 2 )
      {
        // SVC == 2
        // Pop len bits from stack and print them as long int
        u_get_bitvec_n_swap(&stack, glo_stack, a2_insn->stack_ptr->len);
        /* .... */
        if ( a2_insn->stack_ptr->len > u_get_bitvec_end_ptr_recursive(&ctx) )
        {
          v168 = __cxa_allocate_exception(0x10uLL);
          std::runtime_error::runtime_error(v168, "out of bounds: reading past end of stack");
          __cxa_throw(v168, &typeinfo for std::runtime_error, &std::runtime_error::~runtime_error);
        }
        opcode_from_bitvec = u_get_opcode_from_bitvec(&ctx);
        std::ostream::_M_insert<unsigned long>(&std::cout, opcode_from_bitvec);
      }
      else if ( operand > 2 )
      {
        if ( operand != 3 )
        {
          v171 = __cxa_allocate_exception(0x10uLL);
          std::runtime_error::runtime_error(v171, "undefined SVC number");
          __cxa_throw(v171, &typeinfo for std::runtime_error, &std::runtime_error::~runtime_error);
        }
        // SVC == 3
        // Read a long int from cin and push it in the stack (use len bits)
        std::istream::_M_extract<unsigned long>(std::cin, &top_val_of_stack);
        u_vector_push_back_num_as_bytes(&stack, top_val_of_stack, a2_insn->stack_ptr->len);
        u_list_add_inverse(glo_stack, &stack);
        /* .... */
      }
      else if ( operand )
      {
        // SVC == 1
        // Read a line (using getline) (up to 0x2A characters) from cin and push it to the stack
        v132 = *(std::cin[0] - 0x18);
        v133 = *(&std::cin[30] + v132);
        if ( !v133 )
          std::__throw_bad_cast();
        if ( v133[56] )
        {
          v134 = v133[67];
        }
        else
        {
          std::ctype<char>::_M_widen_init(*(&std::cin[30] + v132));
          v134 = (*(*v133 + 0x30LL))(v133, 10LL);
        }
        std::getline<char,std::char_traits<char>,std::allocator<char>>(std::cin, &v189, v134);
        if ( v190 > 0x2A )
          std::string::resize();
        u_vector_create(&stack, v189, v190);
        u_list_add_inverse(glo_stack, &stack);
        /* .... */
      }
      else
      {
        // SVC == 0
        // Read (and pop) len bits from stack and print them to cout
        u_get_bitvec_n_swap(&prnt_stk, glo_stack, a2_insn->stack_ptr->len);
        /* .... */
        if ( a2_insn->stack_ptr->len > u_get_bitvec_end_ptr_recursive(&ctx) )
        {
          v143 = __cxa_allocate_exception(0x10uLL);
          std::runtime_error::runtime_error(v143, "out of bounds: reading past end of stack");
          __cxa_throw(v143, &typeinfo for std::runtime_error, &std::runtime_error::~runtime_error);
        }
        top_val_of_stack = u_get_opcode_from_bitvec(&ctx);
        u_get_bitvec_n_swap(&tmp_stack, glo_stack, top_val_of_stack);
        /* .... */
        if ( top_val_of_stack > v152 )
        {
          v154 = __cxa_allocate_exception(0x10uLL);
          std::runtime_error::runtime_error(v154, "out of bounds: reading past end of stack");
          __cxa_throw(v154, &typeinfo for std::runtime_error, &std::runtime_error::~runtime_error);
        }
        str_to_print = u_PRINT_ONE_LETTER(&ctx);
        str_to_print_ = str_to_print;
        if ( str_to_print )
        {
          len = strlen(str_to_print);
          std::__ostream_insert<char,std::char_traits<char>>(&std::cout, str_to_print_, len);
        }
        else
        {
          std::ios::clear(&std::cout + *(std::cout - 3), *(&std::cout + *(std::cout - 3) + 32) | 1u);
        }
        std::ostream::flush(&std::cout);
        if ( str_to_print_ )
          operator delete[](str_to_print_);
      }
FREE_N_RETURN:
      /* .... */
      return;
    case 0xE:
      // ----------------------------------------------------------------------------------------------------
      // SPINLOCK COUNT
      important[1] = operand;
      goto FREE_N_RETURN;
    case 0xF:
      // ----------------------------------------------------------------------------------------------------
      // ?
      important[2] = operand;
      goto FREE_N_RETURN;
    default:
      // ----------------------------------------------------------------------------------------------------
      // ILLEGAL INSN
      v172 = __cxa_allocate_exception(0x10uLL);
      std::runtime_error::runtime_error(v172, "instruction not part of ISA");
      __cxa_throw(v172, &typeinfo for std::runtime_error, &std::runtime_error::~runtime_error);
  }
}
```

The ISA consists of **16** instructions:
```python
def _get_mnemonic(self, opcode):
    """Gets the instruction mnemonic for an opcode."""
    try:
        return {
            # Math Operations: +, -. *. /.
            0x0: ('ADD',     'W'),
            0x1: ('SUB',     'W'),
            0x2: ('MUL',     'W'),
            0x3: ('IDIV',    'W'),
            # Stack operations
            0x4: ('PUSH',    'W'),
            0x5: ('POP',     '-'),
            0x6: ('DUP',     '-'),
            0x7: ('STCK_RD', 'W'),
            0x8: ('STCK_WR', 'W'),
            # Global data (VM program input) operatiaons
            0x9: ('LDR',     'W'),
            0xA: ('STR',     'W'),
            # Jumps and syscalls (SVCs)
            0xB: ('JZ',      'W'),
            0xC: ('JMP',     'W'),
            0xD: ('SVC',     'W'),
            # Miscellaneous
            0xE: ('SPNLCK',  '-'),
            0xF: ('UNKNWN',  '-')
        }[opcode]
    except KeyError:
        raise Exception(f'Illegal instruction with opcode: {opcode:X}h')
```

### Disassembling VM Program

At this point we know everything to recover the emulated program.
The biggest challenge here is that instructions get executed in parallel, so it is hard to know
exactly which program branch is the correct one. To deal with this problem, we use some heuristics
to quickly discard the incorrect programs:

* All jump targets must point to the beginning of other instructions
* The size of a VM program must be at least **85%** (or higher) 
of the largest program (in terms of instructions). 
The rationale behind this is that an invalid instruction has a "short life" as there are not many
instructions that can follow the invalid one.

By doing this, we can quickly eliminate most of the programs and end with only a few (about **10**)
of them. The interesting part is that all these programs are very similar except their last
instructions for instance:
```
ispo@ispo-glaptop:~/ctf/hxp_2021/revvm$ cat vm_progs/main.diff 
230,231c230,231
< .text:0CB2+10=0CC2    STCK_WR  0x0                (W: 4)
< .text:0CC2+1B=0CDD    SUB      0x5612             (W:15)
---
> .text:0CB2+2E=0CE0    ADD      0x3006B093         (W:34)
> .text:0CE0+0C=0CEC    SUB      $_top_             (W:57)
231c231,233
< .text:0CC2+1B=0CDD    SUB      0x5612             (W:15)
---
> .text:0CC2+10=0CD2    MUL      0x5                (W: 4)
> .text:0CD2+11=0CE3    ADD      0x1C               (W: 5)
> .text:0CE3+15=0CF8    ADD      0x1F8              (W: 9)
231c231,234
< .text:0CC2+1B=0CDD    SUB      0x5612             (W:15)
---
> .text:0CC2+10=0CD2    MUL      0x5                (W: 4)
> .text:0CD2+0C=0CDE    ADD      $_top_             (W: 8)
> .text:0CDE+0C=0CEA    STCK_RD  $_top_             (W:33)
> .text:0CEA+1B=0D05    ADD      0x200              (W:15)
231c231,236
< .text:0CC2+1B=0CDD    SUB      0x5612             (W:15)
---
> .text:0CC2+10=0CD2    MUL      0x5                (W: 4)
> .text:0CD2+0C=0CDE    ADD      $_top_             (W: 8)
> .text:0CDE+14=0CF2    MUL      0x7                (W: 8)
> .text:0CF2+14=0D06    STCK_WR  0x0                (W: 8)
> .text:0D06+10=0D16    DUP      0x8                (-: 4)
> .text:0D16+21=0D37    MUL      0x1C33D0           (W:21)
```

Given that we can combine all these programs (after removing the invalid ones) and sort them.
The result is super close to the original program, but it still contains some invalid instructions.
However, it is very easy to remove them manually by looking at the offsets. For example:
```
.text:187C+14=1890    JZ       0x18CB             (W: 8)        ; if top == 0 goto badboy   
# .text:1888+0C=1894    STR      $_top_             (W:49)
.text:1890+1F=18AF    PUSH     0x283AF            (W:19)        ; top = '(:\x0f' = :)
# .text:1894+0C=18A0    STR      $_top_             (W:33)
# .text:18A0+0C=18AC    ADD      $_top_             (W:24)
# .text:18A0+11=18B1    SUB      0x1D               (W: 5)
# .text:18AC+0C=18B8    STCK_WR  $_top_             (W: 3)
.text:18AF+1C=18CB    JMP      0x18EA             (W:16)        ; print goodboy message
```
Instructions that start with `#` are invalid. The first instruction at `187Ch` is valid. However,
the second one is invalid, as it should start from address `187C+14 = 1890`, but it starts from
`1888h`, so we can remove it along with all instructions that start from `1888 + 0C = 1894h` and so
on.

The full disassembly listing for the VM program is in [vm_prog.asm](./vm_prog.asm).

The [revvm_disasm_vm_progs.py](./revvm_disasm_vm_progs.py) script disassembles the VM program.

### Cracking the VM Program

The emulated program at [vm_prog.asm](./vm_prog.asm) works as follows:

* Reads a **25** character flag
* Converts the flag into a `5x5` matrix
* It multiplies the flag matrix with a constant matrix (let's say `A`)
* It computes the determinant of the flag matrix (let's say `det`)
* It multiplies it with the identity matrix `I`.
* It checks if the results match: `A * flag = det*I`
* It prints the appropriate goodboy `:)` or badboy `:(` message
* All operations are modulo **127**.

To recover the flag all we have to do is to compute the inverse matrix of `A` and mutliply it (from
the left) with `I` * `det`.

We can recover `A` from the global data of `chall.rbin`:
```
  64,  84,  18,  4,   91
  115, 118, 92,  101, 75
  53,  96,  92,  25,  24
  33,  34,  115, 78,  33
  1,   25,  99,  20,  81
```

The inverse matrix of `A` is:
```
  85, 59,  72,  70, 65
  85, 106, 2,   52, 106
  52, 28,  48,  61, 71
  52, 80,  60,  83, 95
  39, 107, 121, 95, 35
```

The only issue is that we do not know the determinant of the flag, however we can brute force it
as it will be in the range `(0, 126)`. After the brute force we find that the correct determinant
is **58**.

We run the [revvm_crack.py](./revvm_crack.py) script and we get the flag.

The flag is: `hxp{Wh4t_4_dum6_D3s1gn!1}`
___
