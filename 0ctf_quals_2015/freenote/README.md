## 0CTF 2015 - Freenote (Pwn 300pt)
##### 28-30/03/2015 (48hr)
___

### Description: 
Freenote, note free.

libc.so.6

202.112.26.108:10001

202.112.28.117:10001

Notice: Ubuntu 14.04.2 LTS
___
### Solution

This was another heap overflow challenge. main() starts at 0x401087 and iterates over a simple
loop. In each iterator user is asked for an option:

```
	== 0ops Free Note ==
	1. List Note
	2. New Note
	3. Edit Note
	4. Delete Note
	5. Exit
	====================
	Your choice: 
```

A simple switch statement process user's choice. Before that loop there's a function which
initializes note table:
```assembly
	.text:000000000040109E                 call    init_note_tbl_400A49
```

Note table contains 256 enties and has the following layout:
```
	0                               32                               64
	+--------------------------------+--------------------------------+
	|       max notes (0x100)        |          note counter          |
	+--------------------------------+--------------------------------+
	|        note[0].is_used         |          note[0].size          |
	+--------------------------------+--------------------------------+
	|        note[0].pointer         |        note[1].is_used         |
	+--------------------------------+--------------------------------+
	|          note[1].size          |        note[1].pointer         |
	+--------------------------------+--------------------------------+
	....
```

When we list the notes, list_note_400B14() is called:
```assembly
.....
.text:0000000000400B1C     mov     rax, cs:note_tbl_6020A8
.text:0000000000400B23     mov     rax, [rax+8]                ; check number of notes
.text:0000000000400B27     test    rax, rax
.text:0000000000400B2A     jle     NO_NOTES_400BB6
.....
.text:0000000000400B39 NEXT_SLOT_400B39:                       ; CODE XREF: list_note_400B14+9Ej
.text:0000000000400B39     mov     rcx, cs:note_tbl_6020A8
.text:0000000000400B40     mov     eax, [rbp+iterator_4]
.text:0000000000400B43     movsxd  rdx, eax
.text:0000000000400B46     mov     rax, rdx
.text:0000000000400B49     add     rax, rax
.text:0000000000400B4C     add     rax, rdx
.text:0000000000400B4F     shl     rax, 3
.text:0000000000400B53     add     rax, rcx
.text:0000000000400B56     add     rax, 10h
.text:0000000000400B5A     mov     rax, [rax]
.text:0000000000400B5D     cmp     rax, 1
.text:0000000000400B61     jnz     short NOTE_UNUSED_400B9B
.text:0000000000400B63     mov     rcx, cs:note_tbl_6020A8     ; if note is used, print it
.text:0000000000400B6A     mov     eax, [rbp+iterator_4]
.text:0000000000400B6D     movsxd  rdx, eax
.text:0000000000400B70     mov     rax, rdx
.text:0000000000400B73     add     rax, rax
.text:0000000000400B76     add     rax, rdx
.text:0000000000400B79     shl     rax, 3
.text:0000000000400B7D     add     rax, rcx
.text:0000000000400B80     add     rax, 20h
.text:0000000000400B84     mov     rdx, [rax]
.text:0000000000400B87     mov     eax, [rbp+iterator_4]
.text:0000000000400B8A     mov     esi, eax
.text:0000000000400B8C     mov     edi, offset aD_S            ; "%d. %s\n"
.text:0000000000400B91     mov     eax, 0
.text:0000000000400B96     call    _printf                     ; print note and its index
.text:0000000000400B9B
.text:0000000000400B9B NOTE_UNUSED_400B9B:                     ; CODE XREF: list_note_400B14+4Dj
.text:0000000000400B9B     add     [rbp+iterator_4], 1
.text:0000000000400B9F
.text:0000000000400B9F loc_400B9F:                             ; CODE XREF: list_note_400B14+23j
.text:0000000000400B9F     mov     eax, [rbp+iterator_4]
.text:0000000000400BA2     movsxd  rdx, eax
.text:0000000000400BA5     mov     rax, cs:note_tbl_6020A8
.text:0000000000400BAC     mov     rax, [rax]
.text:0000000000400BAF     cmp     rdx, rax                    ; i < max nodes ?
.text:0000000000400BB2     jl      short NEXT_SLOT_400B39
```

This function simply iterates over note table and prints all notes which have is_used field set.
new_note_400BC2() creates a new note:
```assembly
.....
.text:0000000000400BFF NEXT_SLOT_400BFF:                       ; CODE XREF: new_note_400BC2+1BDj
.text:0000000000400BFF     mov     rcx, cs:note_tbl_6020A8
.text:0000000000400C06     mov     eax, [rbp+iterator_14]
.text:0000000000400C09     movsxd  rdx, eax
.text:0000000000400C0C     mov     rax, rdx
.text:0000000000400C0F     add     rax, rax
.text:0000000000400C12     add     rax, rdx                    ; rax = i*3
.text:0000000000400C15     shl     rax, 3                      ; rax = i*24
.text:0000000000400C19     add     rax, rcx
.text:0000000000400C1C     add     rax, 10h                    ; note[i]
.text:0000000000400C20     mov     rax, [rax]
.text:0000000000400C23     test    rax, rax                    ; check note[i].used
.text:0000000000400C26     jnz     SLOT_USED_400D68
.text:0000000000400C2C     mov     edi, offset aLengthOfNewNot ; "Length of new note: "
.text:0000000000400C31     mov     eax, 0
.text:0000000000400C36     call    _printf
.....
	[check length. If length > 4096, then truncate to 4096]
.....
.text:0000000000400C6D     mov     eax, [rbp+note_len_10]
.....
.text:0000000000400C98     add     eax, edx                    ; round up to multiple of 128
.text:0000000000400C9A     mov     [rbp+new_len_C], eax
.text:0000000000400C9D     mov     eax, [rbp+new_len_C]
.text:0000000000400CA0     cdqe
.text:0000000000400CA2     mov     rdi, rax                    ; size
.text:0000000000400CA5     call    _malloc                     ; allocate new note
.text:0000000000400CAA     mov     [rbp+note_ptr_8], rax
.text:0000000000400CAE     mov     edi, offset aEnterYourNote  ; "Enter your note: "
.text:0000000000400CB3     mov     eax, 0
.text:0000000000400CB8     call    _printf
.text:0000000000400CBD     mov     edx, [rbp+note_len_10]
.text:0000000000400CC0     mov     rax, [rbp+note_ptr_8]
.text:0000000000400CC4     mov     esi, edx                    ; arg2: buflen
.text:0000000000400CC6     mov     rdi, rax                    ; arg1: buf
.text:0000000000400CC9     call    read_exact_input_40085D     ; read exactly buflen bytes from stdin
.text:0000000000400CCE     mov     rcx, cs:note_tbl_6020A8
.text:0000000000400CD5     mov     eax, [rbp+iterator_14]
.....
.text:0000000000400CEF     mov     qword ptr [rax], 1          ; note[i].used = 1
.....
.text:0000000000400D1D     mov     [rax+8], rcx                ; set note[i].len
.....
.text:0000000000400D46     mov     [rdx], rax                  ; set note[i].ptr
.text:0000000000400D49     mov     rax, cs:note_tbl_6020A8
.text:0000000000400D50     mov     rdx, [rax+8]
.text:0000000000400D54     add     rdx, 1
.text:0000000000400D58     mov     [rax+8], rdx                ; note_counter++
.text:0000000000400D5C     mov     edi, offset aDone_          ; "Done."
.text:0000000000400D61     call    _puts
.text:0000000000400D66     jmp     short locret_400D85
.text:0000000000400D68 ; ---------------------------------------------------------------------------
.text:0000000000400D68
.text:0000000000400D68 SLOT_USED_400D68:                       ; CODE XREF: new_note_400BC2+64j
.text:0000000000400D68     add     [rbp+iterator_14], 1
.text:0000000000400D6C
.text:0000000000400D6C loc_400D6C:                             ; CODE XREF: new_note_400BC2+38j
.text:0000000000400D6C     mov     eax, [rbp+iterator_14]
.text:0000000000400D6F     movsxd  rdx, eax
.text:0000000000400D72     mov     rax, cs:note_tbl_6020A8
.text:0000000000400D79     mov     rax, [rax]
.text:0000000000400D7C     cmp     rdx, rax                    ; i < 0x100 ?
.text:0000000000400D7F     jl      NEXT_SLOT_400BFF
```

What this function does is to find the first empty slot in note table and then to allocate the
appropriate space for that note in the heap. The interesting thing here is that note's size
is rounded up to be a multiple of 128. Also, if a note is K bytes long, we must initialize all
of the K bytes.

Editing a note is also simple:
```assembly
.....
.text:0000000000400D90     mov     edi, offset aNoteNumber     ; "Note number: "
.text:0000000000400D95     mov     eax, 0
.text:0000000000400D9A     call    _printf
.text:0000000000400D9F     mov     eax, 0
.text:0000000000400DA4     call    read_int_40094E
.text:0000000000400DA9     mov     [rbp+note_idx_18], eax
.....
	[check if index is valid]
.....
.text:0000000000400DC7     mov     rcx, cs:note_tbl_6020A8
.text:0000000000400DCE     mov     eax, [rbp+note_idx_18]
.text:0000000000400DD1     movsxd  rdx, eax
.text:0000000000400DD4     mov     rax, rdx
.text:0000000000400DD7     add     rax, rax
.text:0000000000400DDA     add     rax, rdx
.text:0000000000400DDD     shl     rax, 3
.text:0000000000400DE1     add     rax, rcx
.text:0000000000400DE4     add     rax, 10h
.text:0000000000400DE8     mov     rax, [rax]
.text:0000000000400DEB     cmp     rax, 1                      ; if note[idx].used == 0 then abort
.text:0000000000400DEF     jz      short NOTE_USED_400E00
.....
.text:0000000000400E00 NOTE_USED_400E00:                       ; CODE XREF: edit_note_400D87+68j
.text:0000000000400E00     mov     edi, offset aLengthOfNote   ; "Length of note: "
.text:0000000000400E05     mov     eax, 0
.text:0000000000400E0A     call    _printf
.text:0000000000400E0F     mov     eax, 0
.text:0000000000400E14     call    read_int_40094E
.text:0000000000400E19     mov     [rbp+new_len_1C], eax
.....
	[check length]
.....
.text:0000000000400E41     mov     eax, [rbp+new_len_1C]
.text:0000000000400E44     movsxd  rcx, eax
.text:0000000000400E47     mov     rsi, cs:note_tbl_6020A8
.text:0000000000400E4E     mov     eax, [rbp+note_idx_18]
.text:0000000000400E51     movsxd  rdx, eax
.text:0000000000400E54     mov     rax, rdx
.text:0000000000400E57     add     rax, rax
.text:0000000000400E5A     add     rax, rdx
.text:0000000000400E5D     shl     rax, 3
.text:0000000000400E61     add     rax, rsi
.text:0000000000400E64     add     rax, 10h                    ; rax = note[idx]
.text:0000000000400E68     mov     rax, [rax+8]
.text:0000000000400E6C     cmp     rcx, rax
.text:0000000000400E6F     jz      NEW_LEN_DIFFERS_400F2C
.text:0000000000400E75     mov     eax, [rbp+new_len_1C]       ; if new length is different, call realloc
.....
.text:0000000000400ED6     mov     rsi, rcx                    ; size
.text:0000000000400ED9     mov     rdi, rax                    ; ptr
.text:0000000000400EDC     call    _realloc
.....
.text:0000000000400F28     mov     [rax+8], rcx                ; update ptr
.text:0000000000400F2C
.text:0000000000400F2C NEW_LEN_DIFFERS_400F2C:                 ; CODE XREF: edit_note_400D87+E8j
.text:0000000000400F2C     mov     edi, offset aEnterYourNote  ; "Enter your note: "
.text:0000000000400F31     mov     eax, 0
.text:0000000000400F36     call    _printf
.text:0000000000400F3B     mov     rcx, cs:note_tbl_6020A8
.text:0000000000400F42     mov     eax, [rbp+note_idx_18]
.text:0000000000400F45     movsxd  rdx, eax
.text:0000000000400F48     mov     rax, rdx
.text:0000000000400F4B     add     rax, rax
.text:0000000000400F4E     add     rax, rdx
.text:0000000000400F51     shl     rax, 3
.text:0000000000400F55     add     rax, rcx
.text:0000000000400F58     add     rax, 20h
.text:0000000000400F5C     mov     rax, [rax]
.text:0000000000400F5F     mov     edx, [rbp+new_len_1C]
.text:0000000000400F62     mov     esi, edx
.text:0000000000400F64     mov     rdi, rax
.text:0000000000400F67     call    read_exact_input_40085D
.text:0000000000400F6C     mov     edi, offset aDone_          ; "Done."
.text:0000000000400F71     call    _puts
```

If the new note's size differs from the previous, then realloc() is called. In our exploitation
process, realloc() can cause problems, so must keep the same size when editing notes.

Finally delete_note_400F7D deletes an existing note. Its code is very similar with the previous
functions:
```assembly
.....
.text:0000000000400F99     mov     edi, offset aNoteNumber     ; "Note number: "
.text:0000000000400F9E     mov     eax, 0
.text:0000000000400FA3     call    _printf
.text:0000000000400FA8     mov     eax, 0
.text:0000000000400FAD     call    read_int_40094E
.text:0000000000400FB2     mov     [rbp+idx_4], eax
.text:0000000000400FB5     cmp     [rbp+idx_4], 0
.text:0000000000400FB9     js      short INVALID_INDEX_400FD0
.text:0000000000400FBB     mov     eax, [rbp+idx_4]
.....
	[check if index is valid]
.....
.text:0000000000400FDF
.text:0000000000400FDF INDEX_OK_400FDF:                        ; CODE XREF: delete_note_400F7D+51j
.text:0000000000400FDF     mov     rax, cs:note_tbl_6020A8
.text:0000000000400FE6     mov     rdx, [rax+8]
.text:0000000000400FEA     sub     rdx, 1
.text:0000000000400FEE     mov     [rax+8], rdx                ; note_counter--
.text:0000000000400FF2 ----------------------------------------------------------------
.text:0000000000400FF2 The problem here is that delete_note does not check whether a note is used or not
.text:0000000000400FF2 during free. Also, after free() pointer does not set to NULL, so we can have a UAF
.text:0000000000400FF2 ----------------------------------------------------------------
.text:0000000000400FF2     mov     rcx, cs:note_tbl_6020A8
.text:0000000000400FF9     mov     eax, [rbp+idx_4]
.text:0000000000400FFC     movsxd  rdx, eax
.text:0000000000400FFF     mov     rax, rdx
.text:0000000000401002     add     rax, rax
.text:0000000000401005     add     rax, rdx
.text:0000000000401008     shl     rax, 3
.text:000000000040100C     add     rax, rcx
.text:000000000040100F     add     rax, 10h
.text:0000000000401013     mov     qword ptr [rax], 0          ; note[idx].used = 0
.text:000000000040101A     mov     rcx, cs:note_tbl_6020A8
.text:0000000000401021     mov     eax, [rbp+idx_4]
.text:0000000000401024     movsxd  rdx, eax
.text:0000000000401027     mov     rax, rdx
.text:000000000040102A     add     rax, rax
.text:000000000040102D     add     rax, rdx
.text:0000000000401030     shl     rax, 3
.text:0000000000401034     add     rax, rcx
.text:0000000000401037     add     rax, 10h
.text:000000000040103B     mov     qword ptr [rax+8], 0        ; note[idx].len = 0
.text:0000000000401043     mov     rcx, cs:note_tbl_6020A8
.text:000000000040104A     mov     eax, [rbp+idx_4]
.text:000000000040104D     movsxd  rdx, eax
.text:0000000000401050     mov     rax, rdx
.text:0000000000401053     add     rax, rax
.text:0000000000401056     add     rax, rdx
.text:0000000000401059     shl     rax, 3
.text:000000000040105D     add     rax, rcx
.text:0000000000401060     add     rax, 20h
.text:0000000000401064     mov     rax, [rax]
.text:0000000000401067     mov     rdi, rax                    ; ptr
.text:000000000040106A     call    _free
.text:000000000040106F     mov     edi, offset aDone_          ; "Done."
.text:0000000000401074     call    _puts
.text:0000000000401079     jmp     short locret_401085         ; note[id].ptr does not set to NULL -> UAF
.....
```

There are 2 problems in this function:
	1. Function does not check if a note exist before it deletes it
	2. When a note is deleted the pointer does not set to NULL, so we can have UAF.

These 2 bugs are enough for a successfull exploitation.	

### Leaking a heap address

By using the UAF we can leak an address from the heap. First we create 4 notes and we delete the
1st and the 3rd. Then freelist will contain chunks 1 and 3 and these chunks will contain fd and bk
pointers. bk pointer of 1st note will contain the address of the 3rd note's chunk header and 
fd pointer of 3rd note will contain the address of the 1st note's chunk header. 

```   
/---->	+--------------------------------+--------------------------------+
|   	|        prev_size (0x00)        |          size (0x91)           |
|  x----|------------   fd               |               bk   ------------|----------\
|   	| AAAAAAAAAAAAAAA....                                             |          |
|  /--> +--------------------------------+--------------------------------+          |
|  |	|        prev_size (0x90)        |          size (0x90)           |          |
|  |	| BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB |          | 
|  |	|                              .....                              |          |
|  |	| BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB |     x    |
|  |	+--------------------------------+--------------------------------+     |    |
|  |	|        prev_size (0x00)        |          size (0x91)           |     |    |
\-------|------------   fd               |               bk   ------------|-----/    |
   |	| CCCCCCCCCCCCCCC....                                             |          |
   |	+--------------------------------+--------------------------------+          |
   |	|        prev_size (0x90)        |          size (0x90)           |          |
   |	| DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD |          |
   |	|                              .....                              |          |
   |	| DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD |          |
   |	+--------------------------------+--------------------------------+          |
   |	|                        wildernesss chunk                        |          |
   |	+--------------------------------+--------------------------------+          |
   |                                                                                 |
   \---------------------------------------------------------------------------------/
```

However we cannot print these notes because they appear as free in note table. So, we allocate
a new note, which is stored at index 0 in note table. It's size is only 8 bytes just to 
ovewrite fd pointer of first note (we don't set smaller size as fd may contain NULL bytes).

Then if we print the notes, the first note will have is_used bit set in note table, so we can
get the address of the 3rd note in the heap. From there we can easily find the base of the 
heap. At the base of the heap relies the note table which we need its address for our attack.

### Arbitrary write primitive

So far we know where the .heap starts. What we need also is an arbitrary write primitive. To
do that we create a fake chunk and we free it, in order to make unlink() write an abritrary
pointer in the note table.

Before we do anything, we clear any notes left from the leaking step. First we create 4  
notes of 128 bytes each (call them A, B, C and D). Then, we delete notes B and C and we
create a new note E of size 256. Due to the first fit algorithm, note E will be stored
where notes B and C were.

If we free note C again (its pointer is still in note table), then free() will process a
chunk's header which is within E and it's under our control. The heap layout before
final free() will be:

```
note_tbl:	01154010  00 01 00 00 00 00 00 00  03 00 00 00 00 00 00 00
			01154020  01 00 00 00 00 00 00 00  80 00 00 00 00 00 00 00
			01154030  30 58 15 01 00 00 00 00  01 00 00 00 00 00 00 00
			01154040  00 01 00 00 00 00 00 00  C0 58 15 01 00 00 00 00
			01154050  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
			01154060  50 59 15 01 00 00 00 00  01 00 00 00 00 00 00 00
			01154070  80 00 00 00 00 00 00 00  E0 59 15 01 00 00 00 00
			01154080  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
			01154090  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
			........
			01155820  00 00 00 00 00 00 00 00  91 00 00 00 00 00 00 00
note A:		01155830  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41
			........  [More A's]
			011558A0  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 0A
			011558B0  90 00 00 00 00 00 00 00  21 01 00 00 00 00 00 00
note E:		011558C0  45 45 45 45 45 45 45 45  45 45 45 45 45 45 45 45
(old B)		........  [More E's]
			01155930  45 45 45 45 45 45 45 45  45 45 45 45 45 45 45 45
			01155940  60 FF FF FF FF FF FF FF  90 00 00 00 00 00 00 00
note C:		01155950  45 45 45 45 45 45 45 45  45 45 45 45 45 45 45 45
			........  [More E's]
			011559B0  45 45 45 45 45 45 45 45  45 45 45 45 45 45 45 0A
			011559C0  43 43 43 43 43 43 43 43  43 43 43 43 43 43 43 0A
			011559D0  20 01 00 00 00 00 00 00  91 00 00 00 00 00 00 00
note D:		011559E0  44 44 44 44 44 44 44 44  44 44 44 44 44 44 44 44
			011559F0  60 40 15 01 00 00 00 00  68 40 15 01 00 00 00 00
			01155A00  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
			01155A10  44 44 44 44 44 44 44 44  44 44 44 44 44 44 44 44
			01155A20  44 44 44 44 44 44 44 44  44 44 44 44 44 44 44 44
			01155A30  44 44 44 44 44 44 44 44  44 44 44 44 44 44 44 44
			01155A40  44 44 44 44 44 44 44 44  44 44 44 44 44 44 44 44
			01155A50  44 44 44 44 44 44 44 44  44 44 44 44 44 44 44 0A
			01155A60  00 00 00 00 00 00 00 00  A1 05 02 00 00 00 00 00
			........  [Wilderness chunk]
```

Note table has the following entries:
```
	+-----------+-------+---------+-------+-----------+
	| base_addr | index | is_used | size  |  pointer  |
	+-----------+-------+---------+-------+-----------+
	| 0x1154020 |   0   |    1    | 0x80  | 0x1155830 |		(note A)
	+-----------+-------+---------+-------+-----------+
	| 0x1154038 |   1   |    1    | 0x100 | 0x11558c0 |		(note E)
	+-----------+-------+---------+-------+-----------+
	| 0x1154050 |   2   |    0    | 0x00  | 0x1155950 |		(note C) -> UAF
	+-----------+-------+---------+-------+-----------+
	| 0x1154068 |   3   |    1    | 0x80  | 0x11559E0 |		(note D)
	+-----------+-------+---------+-------+-----------+
```

Let's what happens when we free chunk C (at 0x01155950) for 2nd time. free() check if previous 
chunk is used. Because size = 0x90 (LSBit is clear) this means that the previous chunk is free.
Thus it has to be coalesced with the current chunk. To find where the previous chunk begins, we
substract prev_size from current size. However prev_size has a negative value; So when free()
tries to find the previous chunk, it will calculate: 
```
	prev_chunk = 0x01155950 - 0xffffffffffffff60 = 0x01155950 - (-0xa0) = 0x01155950 + 0xa0 = 0x011559F0
```

This address is within note D which we control. Current chunk's size is updated to include prev_size
and previous_chunk gets unlinked from freelist. In previous chunk (0x11559F0) we have set 
fd = 0x01154060 and bk = 0x01154068.  Unlink will check first if fd->bk = P and bk->fd = P. 
In our example we have:
```
	fd->bk = *(0x01154060 + 0x18) = *0x01154078 = 0x011559E0 == 0x11559E0  (ok)
	bk->fd = *(0x01154068 + 0x10) = *0x01154078 = 0x011559E0 == 0x11559E0  (ok)
```

After we pass this check, unlink() removes previous chunk from freelist:
```
	fd->bk = bk 	-> *0x01154078 = 0x01154068
	bk->fd = fd 	-> *0x01154078 = 0x01154060
```

Note that in order to do that, previous chunk cannot be on top of the free list. After unlink,
the 4th note in note table will be:
```
	+-----------+-------+---------+-------+-----------+
	| 0x1154068 |   3   |    1    | 0x80  | 0x1154060 |		(note D)
	+-----------+-------+---------+-------+-----------+
```

This is a very intersting result, because if we set note D again, we can overwrite entiers in 
note table. So we set note D (index 3) and we add 2 entries: One that points to .got.free()
and one that points to "/bin/sh". The new size of the note when editing must be the same to
avoid calling realloc(). After that the note table will contain 2 new entries:
```
	+-----------+-------+---------+-------+-----------+
	| 0x1154050 |   2   |    0    | 0x00  |    PAD    |
	+-----------+-------+---------+-------+-----------+
	| 0x1154068 |   3   |    1    | 0x08  | 0x601820  |
	+-----------+-------+---------+-------+-----------+
	| 0x1154080 |   4   |    1    | 0x08  | 0x1154098 |
	+-----------+-------+---------+-------+-----------+
	| 0x1154098 | "/bin/sh"                           |
	+-----------+-------+---------+-------+-----------+
```

Because we know the base of the heap we can easily calculate all these addresses as their offsets
do not change by ASLR. This way we can have arbitrary reads and writes. All we need to do is to
add entries in note table that point to the address that we want to read/write and either list
note or edit note (when editing new size must be the same).

### Final Steps

First we need to leak address of free(). This is as easy as printing all notes. Note 3 will
contain the address of free(). From there, we can easily calculate the address of system() as
libc is provided.

Once we do that, we edit note 3, to overwrite .got.free() with &system(). At this point, when
we call free(), system() will be called instead. The last step is to trigger free() with 
/bin/sh as an argument. This is very easy because note #4 already points to string /bin/sh.

When we delete note 4, we get a shell and a wonderful flag: `0ctf{freenote_use_free_to_get_flag}`

___