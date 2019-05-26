## DEFCAMP CTF 2013 - (RE 500)

##### 15-16/11/2013 (24hr)

___
### Solution

For this crackme I will use IDA and VB Decompiler Lite. There's also a useful 
paper on VB reversing (Andrea Geddon, VISUAL BASIC REVERSED - A decompiling 
approach), and the following links:

	http://msdn.microsoft.com/en-us/library/7f5ztkz3%28v=vs.90%29.aspx
	http://www.csidata.com/custserv/onlinehelp/vbsdocs../vbs218.htm

___

We start by loading program in VB Decompiler. We can extract some interesting 
information from there:
```
1. Begin Timer Timer1			; Declare a timer with name Timer1
		Interval = 3000			; trigger every 3 secs (3000 = 0xBB8)
		Left = 2760			
		Top = 720
	End
2. Private Sub Timer1_Timer() '40AB60		; timer handler
3. Private Sub Command1_Click() '402F90		; button click handler
4. Private Sub Form_Load() '408100      	; handler for OnLoad event
5. 'VA: 4021A0
	Private Declare Sub IsDebuggerPresent Lib "kernel32"()
```

Now, open IDA (or Olly, we won't use any special feature of IDA) and try to remove 
debugging protection. Inside Form_Load() we have:
```assembly
.text:00408B6F push    ecx                             ; arg4: v_4dc
.text:00408B70 lea     ecx, [ebp-1Ch]
.text:00408B73 push    edx                             ; arg3: "Ollydbg"
.text:00408B74 push    ecx                             ; arg2: v_1c
.text:00408B75 push    ebx                             ; arg1: 0040E3E8
.text:00408B76 call    dword ptr [eax+704h]            ; Proc_0_5_405BA0
.text:00408B7C cmp     word ptr [ebp-4DCh], 0FFFFh
.text:00408B84 jnz     short loc_408BB1                ; if v_4dc != -1 skip bad code
```

Function Proc_0_5_405BA0 is called with argument "Ollydbg". If returns -1, then program
terminates. Proc_0_5_405BA0 is called many times with the following arguments:
	1.Ollydbg
	2.PEiD
	3.Windows
	4.IDA
	5.Hex
	6.CPU	
	
Proc_0_5_405BA0 may looks for window names and return -1 when detects a window with 
such a name. I am using IDA and function returns -1 when IDA argument is called. A 
fast analysis of this function shown that is searching all windows for window_text 
that contains the specified string. All we have to do is to set a breakpoint at:
```assembly
.text:00408B84 jnz     short loc_408BB1          	; if you use Olly
.text:0040977A jz      loc_4090F6					; if you use IDA
```

and toggle ZF flag to cancel branch.

Then, form appears to screen, but it closes again. We can blame timer handler for 
this. When Proc_0_6_405D60 is called, then form closes:
```assembly
.text:0040B092 call    dword ptr [ecx+708h]            ; Proc_0_6_405D60
```

Inside Proc_0_6_405D60, we have the same protection as in Form_Load(). We can bypass
it as before, but after 3 seconds, we have to bypass it again, and again... This is 
very annoying. However, there are (at least) 2 solutions for this:
	1. Patch jz command with jnz command. (easy)
	2. Tamper timer's interval. 		  (difficult)

The first solution is quite simple, so I'll show the second. Let's get into Visual 
Basic Internals. Set a breakpoint at EntryPoint:
```assembly
.text:004014C4 public start
.text:004014C4 start:
.text:004014C4 push    offset dword_401880		; RT_MainStruct
.text:004014C9 call    ThunRTMain
```

This is the main struct of the program, and contains lots of information about program:
```assembly
	00401880:	56 42 35 21 --> VB5! ; signature
	00401884:	F0 1F 2A 00 --> dd 0x002a1ff0
	........
	004018cc:	30 18 40 00 --> offset 0x00401830 -> DialogsStruct
	........
```

Follow DialogsStruct:
```assembly
	00401830:	50 00 00 00 --> sizeof struct
	00401834:	7C 6C A5 22 --> 
	........
	00401878: 	14 15 40 00 --> offset 0x00401514 -> MainDialog
	........
```

Follow MainDialog. This struct contains all information about form and objects of 
the program. It's easy to determine the declaration of Timer object, because we 
know it's name (Timer1):
```assembly
	00401714  FF 01 1F 00 00 00 01 06  00 54 69 6D 65 72 31 00   ........Timer1.
	00401724  0B 03 B8 0B 00 00 07 C8  0A 00 00 08 D0 02 00 00  .._....L...._...
```

The 2 bytes at 00401726 (0B B0) is the time interval (0x0BB0 = 3000). One solution
is to set the interval to very big value (0x7BB8 = 31 sec). But the problem is not 
solved. You can also find where the Enabled property is located and set it to false.
But we'll implement something different: We'll set the interval at an illegal value
(0x0000). Thus timer handler will fail, and will never execute.

Now, we can set a BP at Command1_Click button handler, and enter the password. We have 
the same protection as before, in the following lines of the code:
```assembly
.text:0040321A call    dword ptr [ecx+708h]            ; CHECK!
.text:00403301 call    dword ptr [eax+708h]            ; CHECK!
.text:0040330A call    dword ptr [ecx+708h]            ; CHECK!
.text:00403313 call    dword ptr [edx+708h]            ; CHECK!
.text:0040331C call    dword ptr [eax+708h]            ; CHECK!
.text:004033BD call    dword ptr [edx+708h]            ; CHECK!
.text:00403528 call    dword ptr [ecx+708h]            ; CHECK!
.text:00403531 call    dword ptr [edx+708h]            ; CHECK!
.text:0040459E call    dword ptr [eax+708h]            ; CHECK!
```


After bypassing all protections, we can go to the main encryption algorithm:
```assembly
.text:00403933 mov     edx, [ebp-0D0h]
.text:00403939 mov     eax, [ebp-88h]
.text:0040393F push    edx                             ; user password
.text:00403940 push    eax                             ; ThisIsOneOfTheEasiestInTheWorld
.text:00403941 call    ds:__vbaStrCmp                  ; Don't get tricked!
```

If password is "ThisIsOneOfTheEasiestInTheWorld" then a MessageBox is shown with
the text "You really think so? :P". This of course is not the real password
(it's too easy for level 5). Serial Phishing don't work :(. Let's go on.

```assembly			
.text:00403E20 loc_403E20:                             ; CODE XREF: .text:00403E06
.text:00403E20 mov     edx, [ebp-0D0h]                 ; user password
.text:00403E26 push    edx
.text:00403E27 call    ds:__vbaLenBstr                 ; strlen( password )
.text:00403E2D mov     ecx, eax
.text:00403E2F call    ds:__vbaI2I4                    ; int16 to int32
.text:00403E35 lea     ecx, [ebp-0D0h]
.text:00403E3B mov     [ebp-0A8h], eax                 ; v_a8 = int32( strlen(password) )
.text:00403E41 call    ds:__vbaFreeStr
.text:00403E47 lea     ecx, [ebp-0D4h]
.text:00403E4D call    ds:__vbaFreeObj
.text:00403E53 cmp     word ptr [ebp-0A8h], 0Ch        ; strlen(password) == 12 ?
.text:00403E5B jz      short loc_403EA0                ; if yes skip bad code
			
So, password must be 12 characters long.

Code from .text:004045A4 to .text:0040552A is the actual encryption algorithm. We'll not
make a very thorough analysis of the assembly code because assembly code is quite big:

```assembly					
.text:004045A4 mov     edx, offset H                   ; "MANAAAFAAFAAFAweFAFFFFQGINKOQareIIIIIII"...
.text:004045A9 lea     ecx, [ebp-2Ch]			       ; set TYPE to Empty
.text:004045AC mov     dword ptr [ebp-30h], 1		   
.text:004045B3 mov     dword ptr [ebp-70h], 0
.text:004045BA call    ds:__vbaStrCopy                 ; strcpy(v_2c, H)
.text:004045C0
.text:004045C0 loc_4045C0:                             ; CODE XREF: .text:0040506D
.text:004045C0 mov     ecx, [ebp-2Ch]
.text:004045C3 push    ecx
.text:004045C4 call    ds:__vbaLenBstr
.text:004045CA mov     ecx, [ebp-30h]                  ; i = v_30
.text:004045CD cmp     ecx, eax                        ; i > strlen(H) ?
.text:004045CF jg      loc_405072                      ; if yes break from loop		
.............				
.text:0040505E loc_40505E:                             ; CODE XREF: .text:004046A5
.text:0040505E                                         ; .text:004046F7 ...
.text:0040505E mov     eax, [ebp-30h]
.text:00405061 add     eax, 1
.text:00405064 jo      loc_405B95                      ; overflow?
.text:0040506A mov     [ebp-30h], eax                  ; v_30++
.text:0040506D jmp     loc_4045C0
```
	
The decompiled code (in C - I hate VB :P) is:

```c
char H[] = {
    "MANAAAFAAFAAFAweFAFFFFQGINKOQareIIIIIIITOKGNUQGNQKJsorryJJTKVWGI"
    "INRTQtoGGQJJJJIIIIIIIinterruptIITOKENHNQKAAAAyourAAAAAAAAAAAAAAA"
    "workAAAAAAAAAAbutAAAAAAweIIIIIwouldTUGGNOQVlikeWGNIMEEtoEEEEEEEE"
    "EtellEEEEEEEyouEEQGNFFFFthatFFFFFFFFFFtheFOFFFFFFFFinputFFFFFyou"
    "FFKKKKKareKKKKKKKQSORTsearchingINTUGNFFFFforFEEEEEEEEEEEconsists"
    "EEEEEEEEEEEEofEEEEEEEEEEonlyEEEEEElowercaseEQIIIIIhexIIIIITOAAch"
    "aractersAAAAfromAAAKGJaJIIItoIIJNOfKTFFandFFFFFFnumbersFFFFF0FFF"
    "FtoFFFFF9QNQW"
};

for( int i=0; i<strlen(H); i++ )
{
	// some code
}
```

Be careful when reversing VB apps. Variables are usually VBVARIANT type. This means
that their type can change during execution. For example instruction
	.text:00404BFE mov     dword ptr [ebp-554h], 3
converts variable v_554 to Long Integer. v_554 = 3 is wrong! The internal structure 
of VBVARIANT is something like the following:
```
	Bytes 0-2: Variable Type
	Bytes 2-8: Reserved 
	Bytes 8-+: Actual Data0
```

Inside loop, there's a big switch statement. Operations are depended on H[i].If H[i] 
is a lowercase letter, is ignored:
```c
	switch( H[i] )
    {
        case 'A': v_50 += v_554;    break;
        case 'B':                   break;
        case 'C':                   break;
        case 'D':                   break;
        case 'E': v_80 += v_554;    break;
        case 'F': v_80 -= v_554;    break;
        case 'G': v_c4 += v_554;    break;
        case 'H': v_c4 -= v_554;    break;
        case 'I': v_40 += v_554;    break;
        case 'J': v_40 -= v_554;    break;
        case 'K': v_50 += v_80;     break;
        case 'L':                   break;
        case 'M': v_50 = L[v_40-1]; break;
        case 'N': v_80 = password[v_c4-1];      break;
        case 'O': v_80 = (0xffffffffffffffff ^ v_80) &
                          0xffffffffffffffff;   break;
        case 'P':                   break;
        case 'Q': v_50 *= v_80;     break;
        case 'R': v_50  = v_80;     break;
        case 'S': v_80  = v_50;     break;
        case 'T': v_80  = L[v_40-1];break;
        case 'U': v_50 ^= v_80;     break;
        case 'V': if( v_50 < 0 ) v_50 = -v_50;  break;
        case 'W': // convert 8 MSBytes of v_50 to string
					while( v_50 > 0xffffffff ) v_50 >>= 4;
					// store v_50 as string
					
					v_50 = 0;
					break;
	}
```


A hidden message is revealed if we extract the lowercase letters from H:
"we are sorry to interrupt your work but we would like to tell you that the input you 
are searching for consists of only lowercase hex characters from a to f and numbers 
0 to 9".

Letters B,C,D,L and P are not contained in H, so we don't need to analyse their 
operations. Also:
	
N   letters: read a character from password string
G/H letters: increase/decrease character pointer of password
W   letters: create an 8 byte hash and store it as a string and clear v_50

There are 3 W's in H, so 3 hashes will be generate.
___

Code from .text:00405072 to .text:004053ED creates the 3 original hashes in order to 
compare with hashes generated by user's password. Hashes are generated at run time by 
concatenated one character with the previous string, one at a time. Thus, String 
references can't help us.
```assembly
	.text:00405072 loc_405072:                   	; CODE XREF: .text:004045CF
	.text:00405072 lea     ecx, [ebp-0E4h]
	.text:00405078 push    41h ; 'A'
	.text:0040507A push    ecx
	.text:0040507B call    esi ; rtcVarBstrFromAnsi
	..............
	.text:004053E8 mov     edx, eax
	.text:004053EA lea     ecx, [ebp-6Ch]
	.text:004053ED call    ds:__vbaStrMove
```

The 3 original hashes are:
```c
	v_24 = "A70086D2" (VBVARIANT)
	v_60 = "14F1163F" (VBVARIANT)
	v_6c = "4108761A" (VBVARIANT)	
```

Finally, code from .text:00405464 to .text:0040552A, compares these hashes:
```assembly
.text:00405464 mov     eax, [ebp-94h]
.text:0040546A mov     ecx, 8008h
.text:0040546F add     esp, 40h
.text:00405472 mov     edx, [eax]                      ; edx = 1st hash
.text:00405474 mov     [ebp-554h], ecx
.text:0040547A mov     [ebp-54Ch], edx                 ; v_54c = password
.text:00405480 mov     edx, [eax+4]                    ; edx = 2nd hash
.text:00405483 mov     [ebp-55Ch], edx
.text:00405489 mov     [ebp-564h], ecx                 
.text:0040548F mov     eax, [eax+8]                    ; eax = 3rd hash
.text:00405492 mov     ecx, [ebp-6Ch]                  ; v_6c = 4108761A
.text:00405495 push    eax                             ; user 3rd hash
.text:00405496 push    ecx                             ; 4108761A (const)
.text:00405497 call    ds:__vbaStrCmp                  ; strcmp(v_6c, v_94[0])
..............
.text:004054BD mov     dword ptr [ebp-574h], 0Bh       ; v_574 = VB BOOL
.text:004054C7 call    ds:__vbaVarCmpEq                ; v_e4 = (v_24 == v_554)
.text:004054CD push    eax                             ; arg3: v_e4
..............
.text:004054E0 call    ds:__vbaVarCmpEq                ; v_f4 = (v_60 == v_564)
..............
.text:004054EE call    ds:__vbaVarAnd                  ; v_104 = v_f4 & v_e4
.text:004054F4 push    eax                             ; arg3: v_104
.text:004054F5 lea     eax, [ebp-574h]
.text:004054FB lea     ecx, [ebp-114h]
.text:00405501 push    eax                             ; arg2: v_574
.text:00405502 push    ecx                             ; arg1: v_114
.text:00405503 call    ds:__vbaVarAnd                  ; v_114 = v_574 & v_104
.text:00405509 push    eax
.text:0040550A call    ds:__vbaBoolVarNull             ; isNULL?
.text:00405510 lea     ecx, [ebp-574h]
.text:00405516 mov     [ebp-598h], eax                 ; v_598 = (v_114 == false)
.text:0040551C call    ds:__vbaFreeVar
.text:00405522 cmp     word ptr [ebp-598h], 0          ; v_598 == 0 ?
.text:0040552A jz      loc_405867                      ; set ZF to 0
```

The 1st hash compared with "A70086D2", the 2nd with "14F1163F" and the 3rd with "4108761A".
___
Now we know everything about encryption algorithm. But, how can we crack it? If we 
believe the author that password consists only of lowercase hex numbers, then trying 
all possible passwords (16^12 = 2^48) requires some weeks of runtime...

Fortunately things are not so bad, due to "vulnerable" construction of table H. If we 
watch carefully H, we'll see the following:
```
N...G...N...G...N...G...N...W			=> hash1: p[0], p[1], p[2] and p[3]
G...N...G...G...NHN...GGN...W			=> hash2: p[4], p[6], p[5] and p[7]
G...N...G...N...N...GN...G...N...N...W" => hash3: p[8], p[9], p[9], p[10], p[11] and p[11]
```

Can you see the independence? We can brute-force the first 4 digits of password to match
with the first hash, then the next 4 digits, and so on... Brute-forcing all possible 
passwords with hex digits, gives:
```
	first 4 digits: 9a5e
	next  4 digits: f4xa, where x is any hex digit
	last  4 digits: 3cab
```

Thus there are 16 valid passwords: `9a5ef40a3cab`, `9a5ef41a3cab`, ..., `9a5ef4fa3cab`.

___