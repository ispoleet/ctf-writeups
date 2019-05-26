## 9447 Security Society CTF - Search Engine (Pwn 230)
##### 27-29/11/2015 (48hr)
___

### Description: 
Ever wanted to search through real life? Well this won't help, but it will let you search strings.
 
Find it at search-engine-qgidg858.9447.plumbing port 9447.

search bf61fbb8fa7212c814b2607a81a84adf
___
### Solution

Reversing the binary was a little bit challenging. The binary implements a simple word search
algorithm. User can add sentences or search for words. When we add a sentence function 
index_sentence_400C00 is called:

```assembly
.text:0000000000400C00 index_sentence_400C00 proc near         ; CODE XREF: main2_400D60+2Ap
.text:0000000000400C00     push    r13
.text:0000000000400C02     mov     edi, offset aEnterTheSenten ; "Enter the sentence size:"
.text:0000000000400C07     push    r12
.text:0000000000400C09     push    rbp
.text:0000000000400C0A     push    rbx
.text:0000000000400C0B     sub     rsp, 8
.text:0000000000400C0F     call    _puts
.text:0000000000400C14     xor     eax, eax
.text:0000000000400C16     call    read_int_400A40
.text:0000000000400C1B     lea     ebp, [rax-1]
.text:0000000000400C1E     mov     r13d, eax
.text:0000000000400C21     cmp     ebp, 0FFFDh
.text:0000000000400C27     ja      TOO_BIG_400D1A
.text:0000000000400C2D     mov     edi, offset aEnterTheSent_0 ; "Enter the sentence:"
.text:0000000000400C32     call    _puts
.text:0000000000400C37     movsxd  rdi, r13d                   ; size
.text:0000000000400C3A     call    _malloc                     ; malloc size is controlled
.text:0000000000400C3F     xor     edx, edx
.text:0000000000400C41     mov     rdi, rax
.text:0000000000400C44     mov     esi, r13d
.text:0000000000400C47     mov     r12, rax
.text:0000000000400C4A     call    read_raw_4009B0
.text:0000000000400C4F     mov     edi, 28h                    ; size
.text:0000000000400C54     lea     rbx, [r12+1]
.text:0000000000400C59     lea     rbp, [r12+rbp+2]
.text:0000000000400C5E     call    _malloc
.text:0000000000400C63     xor     edx, edx
.text:0000000000400C65     mov     [rax], r12                  ; meta.sentence = &sentence
.text:0000000000400C68     mov     dword ptr [rax+8], 0
.text:0000000000400C6F     mov     [rax+10h], r12
.text:0000000000400C73     mov     [rax+18h], r13d
.text:0000000000400C77     jmp     short loc_400C8F
.text:0000000000400C77 ; ---------------------------------------------------------------------------
.text:0000000000400C79     align 20h
.text:0000000000400C80
.text:0000000000400C80 loc_400C80:                             ; CODE XREF: index_sentence_400C00+93j
.text:0000000000400C80     add     edx, 1
.text:0000000000400C83     mov     [rax+8], edx
.text:0000000000400C86
.text:0000000000400C86 loc_400C86:                             ; CODE XREF: index_sentence_400C00+108j
.text:0000000000400C86     add     rbx, 1
.text:0000000000400C8A     cmp     rbx, rbp
.text:0000000000400C8D     jz      short loc_400CA8
.text:0000000000400C8F
.text:0000000000400C8F loc_400C8F:                             ; CODE XREF: index_sentence_400C00+77j
.text:0000000000400C8F                                         ; index_sentence_400C00+A3j
.text:0000000000400C8F     cmp     byte ptr [rbx-1], 20h
.text:0000000000400C93     jnz     short loc_400C80
.text:0000000000400C95     test    edx, edx
.text:0000000000400C97     jnz     short ADD_WORD_400CD8
.text:0000000000400C99     mov     [rax], rbx
.text:0000000000400C9C     add     rbx, 1
.text:0000000000400CA0     cmp     rbx, rbp
.text:0000000000400CA3     jnz     short loc_400C8F
.text:0000000000400CA5     nop     dword ptr [rax]
.text:0000000000400CA8
.text:0000000000400CA8 loc_400CA8:                             ; CODE XREF: index_sentence_400C00+8Dj
.text:0000000000400CA8     test    edx, edx
.text:0000000000400CAA     jz      short loc_400D10
.text:0000000000400CAC     mov     rdx, cs:last_ptr_6020B8
.text:0000000000400CB3     mov     cs:last_ptr_6020B8, rax
.text:0000000000400CBA     mov     [rax+20h], rdx
.text:0000000000400CBE
.text:0000000000400CBE loc_400CBE:                             ; CODE XREF: index_sentence_400C00+118j
.text:0000000000400CBE     add     rsp, 8
.text:0000000000400CC2     mov     edi, offset aAddedSentence  ; "Added sentence"
.text:0000000000400CC7     pop     rbx
.text:0000000000400CC8     pop     rbp
.text:0000000000400CC9     pop     r12
.text:0000000000400CCB     pop     r13
.text:0000000000400CCD     jmp     _puts
.text:0000000000400CCD ; ---------------------------------------------------------------------------
.text:0000000000400CD2     align 8
.text:0000000000400CD8
.text:0000000000400CD8 ADD_WORD_400CD8:                        ; CODE XREF: index_sentence_400C00+97j
.text:0000000000400CD8     mov     rdx, cs:last_ptr_6020B8
.text:0000000000400CDF     mov     edi, 28h                    ; size
.text:0000000000400CE4     mov     cs:last_ptr_6020B8, rax
.text:0000000000400CEB     mov     [rax+20h], rdx
.text:0000000000400CEF     call    _malloc
.text:0000000000400CF4     xor     edx, edx
.text:0000000000400CF6     mov     [rax], rbx
.text:0000000000400CF9     mov     dword ptr [rax+8], 0
.text:0000000000400D00     mov     [rax+10h], r12
.text:0000000000400D04     mov     [rax+18h], r13d
.text:0000000000400D08     jmp     loc_400C86
.text:0000000000400D08 ; ---------------------------------------------------------------------------
.text:0000000000400D0D     align 10h
.text:0000000000400D10
.text:0000000000400D10 loc_400D10:                             ; CODE XREF: index_sentence_400C00+AAj
.text:0000000000400D10     mov     rdi, rax                    ; ptr
.text:0000000000400D13     call    _free
.text:0000000000400D18     jmp     short loc_400CBE
.text:0000000000400D1A ; ---------------------------------------------------------------------------
.text:0000000000400D1A
.text:0000000000400D1A TOO_BIG_400D1A:                         ; CODE XREF: index_sentence_400C00+27j
.text:0000000000400D1A     mov     edi, offset aInvalidSize    ; "Invalid size"
.text:0000000000400D1F     call    fatal_400990
.text:0000000000400D1F index_sentence_400C00 endp
```

What this code does is first to store the sentence in the heap (no overflows here). Then it 
searches for all words in the sentence and for each word adds an element in a word list.
Each element in the word list has the following format:
```c
struct word {
	char *offset;			// pointer to the word within the sentence
	int  len;				// length of the word

	char *sentence;			// pointer to the beginning of the sentence
	int  sent_len;			// length of the sentence

	word* prev;				// previous element in the list
};
```

The tail of the list is stored in .bss: last_ptr_6020B8.

When we search for word, function search_word_400AD0 is invoked:
```assembly
.text:0000000000400AD0 search_word_400AD0 proc near            ; CODE XREF: main2_400D60+3Ap
.text:0000000000400AD0
.text:0000000000400AD0 var_38= byte ptr -38h
.text:0000000000400AD0
.text:0000000000400AD0     push    r13
.text:0000000000400AD2     mov     edi, offset s               ; "Enter the word size:"
.text:0000000000400AD7     push    r12
.text:0000000000400AD9     push    rbp
.text:0000000000400ADA     push    rbx
.text:0000000000400ADB     sub     rsp, 18h
.text:0000000000400ADF     call    _puts
.text:0000000000400AE4     xor     eax, eax
.text:0000000000400AE6     call    read_int_400A40
.text:0000000000400AEB     mov     ebp, eax
.text:0000000000400AED     lea     eax, [rax-1]
.text:0000000000400AF0     cmp     eax, 0FFFDh
.text:0000000000400AF5     ja      INVALID_SIZE_400BF2
.text:0000000000400AFB     mov     edi, offset aEnterTheWord   ; "Enter the word:"
.text:0000000000400B00     movsxd  r13, ebp
.text:0000000000400B03     call    _puts
.text:0000000000400B08     mov     rdi, r13                    ; size
.text:0000000000400B0B     call    _malloc
.text:0000000000400B10     xor     edx, edx
.text:0000000000400B12     mov     esi, ebp
.text:0000000000400B14     mov     rdi, rax
.text:0000000000400B17     mov     r12, rax
.text:0000000000400B1A     call    read_raw_4009B0
.text:0000000000400B1F     mov     rbx, cs:last_ptr_6020B8
.text:0000000000400B26     test    rbx, rbx
.text:0000000000400B29     jnz     short loc_400B3D
.text:0000000000400B2B     jmp     loc_400BE0
.text:0000000000400B30 ; ---------------------------------------------------------------------------
.text:0000000000400B30
.text:0000000000400B30 GET_NEXT_ELT_400B30:                    ; CODE XREF: search_word_400AD0+74j
.text:0000000000400B30                                         ; search_word_400AD0+79j ...
.text:0000000000400B30     mov     rbx, [rbx+20h]
.text:0000000000400B34     test    rbx, rbx
.text:0000000000400B37     jz      loc_400BE0
.text:0000000000400B3D
.text:0000000000400B3D loc_400B3D:                             ; CODE XREF: search_word_400AD0+59j
.text:0000000000400B3D     mov     rcx, [rbx+10h]
.text:0000000000400B41     cmp     byte ptr [rcx], 0           ; this check is bad :(
.text:0000000000400B44     jz      short GET_NEXT_ELT_400B30
.text:0000000000400B46     cmp     [rbx+8], ebp                ; check if len is equal first
.text:0000000000400B49     jnz     short GET_NEXT_ELT_400B30
.text:0000000000400B4B     mov     rdi, [rbx]                  ; s1
.text:0000000000400B4E     mov     rdx, r13                    ; n
.text:0000000000400B51     mov     rsi, r12                    ; s2
.text:0000000000400B54     call    _memcmp
.text:0000000000400B59     test    eax, eax
.text:0000000000400B5B     jnz     short GET_NEXT_ELT_400B30
.text:0000000000400B5D     mov     edx, [rbx+18h]
.text:0000000000400B60     mov     esi, offset aFoundD         ; "Found %d: "
.text:0000000000400B65     mov     edi, 1
.text:0000000000400B6A     call    ___printf_chk
.text:0000000000400B6F     movsxd  rdx, dword ptr [rbx+18h]    ; n
.text:0000000000400B73     mov     rcx, cs:stdout              ; s
.text:0000000000400B7A     mov     esi, 1                      ; size
.text:0000000000400B7F     mov     rdi, [rbx+10h]              ; ptr
.text:0000000000400B83     call    _fwrite
.text:0000000000400B88     mov     edi, 0Ah                    ; c
.text:0000000000400B8D     call    _putchar
.text:0000000000400B92     mov     edi, offset aDeleteThisSent ; "Delete this sentence (y/n)?"
.text:0000000000400B97     call    _puts
.text:0000000000400B9C     mov     edx, 1
.text:0000000000400BA1     mov     esi, 2
.text:0000000000400BA6     mov     rdi, rsp
.text:0000000000400BA9     call    read_raw_4009B0
.text:0000000000400BAE     cmp     [rsp+38h+var_38], 79h
.text:0000000000400BB2     jnz     GET_NEXT_ELT_400B30
.text:0000000000400BB8     movsxd  rdx, dword ptr [rbx+18h]    ; n
.text:0000000000400BBC     mov     rdi, [rbx+10h]              ; s
.text:0000000000400BC0     xor     esi, esi                    ; c
.text:0000000000400BC2     call    _memset
.text:0000000000400BC7     mov     rdi, [rbx+10h]              ; ptr
.text:0000000000400BCB     call    _free
.text:0000000000400BD0     mov     edi, offset aDeleted        ; "Deleted!"
.text:0000000000400BD5     call    _puts
.text:0000000000400BDA     jmp     GET_NEXT_ELT_400B30
.text:0000000000400BDA ; ---------------------------------------------------------------------------
.text:0000000000400BDF     align 20h
.text:0000000000400BE0
.text:0000000000400BE0 loc_400BE0:                             ; CODE XREF: search_word_400AD0+5Bj
.text:0000000000400BE0                                         ; search_word_400AD0+67j
.text:0000000000400BE0     add     rsp, 18h
.text:0000000000400BE4     mov     rdi, r12                    ; ptr
.text:0000000000400BE7     pop     rbx
.text:0000000000400BE8     pop     rbp
.text:0000000000400BE9     pop     r12
.text:0000000000400BEB     pop     r13
.text:0000000000400BED     jmp     _free
.text:0000000000400BF2 ; ---------------------------------------------------------------------------
.text:0000000000400BF2
.text:0000000000400BF2 INVALID_SIZE_400BF2:                    ; CODE XREF: search_word_400AD0+25j
.text:0000000000400BF2     mov     edi, offset aInvalidSize    ; "Invalid size"
.text:0000000000400BF7     call    fatal_400990
.text:0000000000400BF7 search_word_400AD0 endp
```

This function simply iterates over the list, looking for a specific word. First it checks whether
the "len" in each element is equal with the length of the word, if so it does a memcmp(). If the
words match, it prints the whole sentence and ask for deletion. Upon deletion, the sentence is
zeroed out, and it's freed.

The first problem here is that the words in the list that point to the sentence do not removed
from word list so we have Use After Free (UAF) situations.

The second bug is on read_int_400A40:
```assembly
.text:0000000000400A40 read_int_400A40 proc near               ; CODE XREF: read_int_400A40+76p
.text:0000000000400A40                                         ; search_word_400AD0+16p ...
.text:0000000000400A40
.text:0000000000400A40 endptr= qword ptr -50h
.text:0000000000400A40 nptr= byte ptr -48h
.text:0000000000400A40 var_10= qword ptr -10h
.text:0000000000400A40
.text:0000000000400A40     push    rbx
.text:0000000000400A41     mov     edx, 1
.text:0000000000400A46     mov     esi, 30h
.text:0000000000400A4B     sub     rsp, 50h
.text:0000000000400A4F     lea     rbx, [rsp+58h+nptr]
.text:0000000000400A54     mov     rax, fs:28h
.text:0000000000400A5D     mov     [rsp+58h+var_10], rax
.text:0000000000400A62     xor     eax, eax
.text:0000000000400A64     mov     rdi, rbx
.text:0000000000400A67     call    read_raw_4009B0
.text:0000000000400A6C     lea     rsi, [rsp+58h+endptr]       ; endptr
.text:0000000000400A71     xor     edx, edx                    ; base
.text:0000000000400A73     mov     rdi, rbx                    ; nptr
.text:0000000000400A76     call    _strtol
.text:0000000000400A7B     cmp     [rsp+58h+endptr], rbx
.text:0000000000400A80     jz      short loc_400AA0
.text:0000000000400A82
.text:0000000000400A82 loc_400A82:                             ; CODE XREF: read_int_400A40+7Bj
.text:0000000000400A82     mov     rcx, [rsp+58h+var_10]
.text:0000000000400A87     xor     rcx, fs:28h
.text:0000000000400A90     jnz     short loc_400ABD
.text:0000000000400A92     add     rsp, 50h
.text:0000000000400A96     pop     rbx
.text:0000000000400A97     retn
.text:0000000000400A97 ; ---------------------------------------------------------------------------
.text:0000000000400A98     align 20h
.text:0000000000400AA0
.text:0000000000400AA0 loc_400AA0:                             ; CODE XREF: read_int_400A40+40j
.text:0000000000400AA0     mov     rdx, rbx
.text:0000000000400AA3     mov     esi, offset aSIsNotAValidNu ; "%s is not a valid number\n"
.text:0000000000400AA8     mov     edi, 1
.text:0000000000400AAD     xor     eax, eax
.text:0000000000400AAF     call    ___printf_chk
.text:0000000000400AB4     xor     eax, eax
.text:0000000000400AB6     call    read_int_400A40
.text:0000000000400ABB     jmp     short loc_400A82
.text:0000000000400ABD ; ---------------------------------------------------------------------------
.text:0000000000400ABD
.text:0000000000400ABD loc_400ABD:                             ; CODE XREF: read_int_400A40+50j
.text:0000000000400ABD     nop     dword ptr [rax]
.text:0000000000400AC0     call    ___stack_chk_fail
.text:0000000000400AC0 read_int_400A40 endp
```

When we enter a non-number which is exactly 0x30 bytes, the returned string from read_raw_4009B0 is 
not null terminated and is printed to the user (%s is not a valid number\n). The first time that 
read_int is called, there's nothing useful after the 0x30 bytes of our input However this 
function is called recursively when an invalid number is given. The 2nd time there's a stack address
 right after the non null termintating input, so we can leak a stack address. 

The next step in our exploitation process is to leak a heap address. We can do this as follows:
First we allocate a big enough sentence (in a smallbin). Then we delete it and we allocate
a smaller one, which is stored at the same address with the previous. Then we use a stale
pointer in the word list to print the sentence. This stale element in the list will point
to a word in the new sentence but its size will be equal with the old sentence. Thus we 
will print the sentence according with an element in the word list. From there we can
leak a heap address.

The next step is to abuse the fastbins in order to force malloc to return an almost 
arbitrary pointer. The first step is to do a double free(). This is not very easy due to
the following instruction:
```assembly
	.text:0000000000400B41     cmp     byte ptr [rcx], 0           ; this check is bad :(
```

This instruction checks if a sentence is empty before the comparison. Thus if we delete
a sentence, it will be zeroed out before free, so the next time we won't be able to free
it again.

However if we free a 2nd sentence which has the same size with the first one (both belong 
to the same fastbin), the first 8 bytes of the sentence will have a pointer to the previous
element in the freelist, which means that we can bypass that check.

The plan here is to allocate 3 sentences of equal size: A, B and C with that order. Then we
free B and C. C will have a pointer to B's chunk header. Then we free A. We can't free C
instead of A because C is already on the top of the freelist. After A we free C again without
any problems.

Now, when we call malloc() it will return the chunks from the freelist. The 1st malloc() will
return C, the 2nd will return A and the 3rd C again. Before malloc() returns C for 2nd time,
it will treat it as free, so it can mis-interpret the first 8 bytes as a pointer to the next
free chunk. Thus the 1st time that malloc returns C we create a fake pointer. This pointer
must point a fake chunk with a valid size (equal with current fastbin size). This way, the
next call to malloc, will return the fake pointer + 0x10.

We know the base of the heap (we leaked it before), so we force malloc to return a pointer
to an element in the word list. From there we can manipulate that element and make the 
"sentence" field point to GOT. If we search for a word that only this element matches, we
can leak an address from GOT and thus we can find the libc base.

From there the obvious plan is to repeat this attack and force malloc to return a pointer
in GOT to get an arbitrary write. However this is not possible because the returned address
by malloc should contain a valid chunk size 8 bytes before that address. This is not the 
case in GOT so we need another avenue.

The next possible attack is a ROP/return to libc. This sounds great because we already 
leaked a stack address and in the stack frame of main() we can find a valid chunk size 
(0x40). However we have to break the aligment in order to find 7 null bytes + 0x40. 

So we repeat the previous attack and we force malloc() to return a pointer in the stack.
From there we can return to system(). But before that, rdi must contain the address of 
/bin/sh, so we need a pop rdi; ret gadget (there is one at 0x00400E23).

Once we do this, we can get a shell. For more details please have a look at the exploit file.
___