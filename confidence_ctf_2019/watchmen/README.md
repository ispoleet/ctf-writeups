
## Teaser CONFidence CTF 2019 - watchmen (Reversing 264)
##### 16/03 - 17/03/2019 (24hr)
___
### Description: 

Who watches the watchmen?

```
watchmen.tar.gz 44.4 KB
```

The flag format is: `p4{letters_digits_and_special_characters}`.
If you have any questions, you can find our team-members at the IRC channel #p4team @ freenode.

___
### Solution

### Part 1: Breaking the anti-reversing protection


Binary uses a cool anti-reversing protection: First, it clones itself, and then it 
starts debugging the child process. To do that, it sets the Trap Flag (TF), so it single-steps 
the execution on the clone. Because the clone is already being debugged, we cannot attach a 
debugger to it. Let's start with the actual entry point: 

```assembly
.text:0040154B A1 04 C4 43+    mov     eax, ds:CreateMutexA_43C404
.text:00401550 C7 44 24 08+    mov     [esp+34h+var_2C], offset aDynamic_exec ; "DYNAMIC_EXEC"
.text:00401558 C7 44 24 04+    mov     [esp+34h+var_30], 1
.text:00401560 C7 04 24 00+    mov     [esp+34h+var_34], 0
.text:00401567 FF D0           call    eax ; CreateMutexA_43C404
.text:00401569 83 EC 0C        sub     esp, 0Ch
.text:0040156C 89 45 F0        mov     [ebp+var_10], eax
.text:0040156F A1 08 C4 43+    mov     eax, ds:GetLastError_43C408
.text:00401574 FF D0           call    eax ; GetLastError_43C408
.text:00401576 89 45 EC        mov     [ebp+var_14], eax
.text:00401579 C7 45 F4 00+    mov     [ebp+var_C], 0
.text:00401580 83 7D F0 00     cmp     [ebp+var_10], 0
.text:00401584 75 07           jnz     short loc_40158D
.text:00401586 C7 45 F4 01+    mov     [ebp+var_C], 1
.text:0040158D
.text:0040158D             loc_40158D:                                       ; CODE XREF: real_main_401530+54j
.text:0040158D 81 7D EC B7+    cmp     [ebp+var_14], 0B7h
.text:00401594 75 07           jnz     short FIRST_CLONE_40159D
.text:00401596 E8 CE 08 00+    call    SECRET_CODE_401E69                    ; second clone
.text:00401596 00          ; ---------------------------------------------------------------------------
.text:0040159B EB              db 0EBh ; Έ
.text:0040159C 3C              db  3Ch ; <
.text:0040159D             ; ---------------------------------------------------------------------------
.text:0040159D
.text:0040159D             FIRST_CLONE_40159D:                               ; CODE XREF: real_main_401530+64j
.text:0040159D 83 7D EC 00     cmp     [ebp+var_14], 0
.text:004015A1 75 2F           jnz     short loc_4015D2
.text:004015A3 8D 45 DC        lea     eax, [ebp+var_24]
.text:004015A6 89 04 24        mov     [esp+38h+Code], eax
.text:004015A9 E8 4A 00 00+    call    clone_4015F8
.text:004015AE 8B 55 E0        mov     edx, [ebp+var_20]
.text:004015B1 8B 45 DC        mov     eax, [ebp+var_24]
.text:004015B4 89 54 24 04     mov     [esp+38h+var_34], edx
.text:004015B8 89 04 24        mov     [esp+38h+Code], eax
.text:004015BB E8 40 01 00+    call    launch_decryptor_401700
.text:004015C0 A1 0C C4 43+    mov     eax, ds:ReleaseMutex_43C40C
.text:004015C5 8B 55 F0        mov     edx, [ebp+var_10]
.text:004015C8 89 14 24        mov     [esp+38h+Code], edx
.text:004015CB FF D0           call    eax ; ReleaseMutex_43C40C
.text:004015CD 83 EC 04        sub     esp, 4
.text:004015D0 EB 07           jmp     short loc_4015D9
```

First program tries to crate mutex `DYNAMIC_EXEC`. If creation fails, it means that
it's already created, so current process is the clone, so it jumps to `SECRET_CODE_401E69`
which is encrypted:

```assembly
.text:00401E69             SECRET_CODE_401E69 proc near                      ; CODE XREF: real_main_401530+66p
.text:00401E69                                                               ; DATA XREF: .protect:004400F0o
.text:00401E69 0F 0B           ud2
.text:00401E69             SECRET_CODE_401E69 endp
.text:00401E69
.text:00401E69             ; ---------------------------------------------------------------------------
.text:00401E6B 31              db  31h ; 1
.text:00401E6C 9B              db  9Bh ; δ
.text:00401E6D 2A              db  2Ah ; *
....
```

Otherwise, it invokes `clone_4015F8` that clones current process with `DEBUG_ONLY_THIS_PROCES` flag
being set. Then the main loop starts, where the original process listens for 
`EXCEPTION_DEBUG_EVENT` debug events form the clone:

```assembly
.text:00401720             decryptor_401720 proc near                        ; CODE XREF: launch_decryptor_401700+18p
.text:00401720
....
.text:0040174F             LOOP_40174F:                                      ; CODE XREF: decryptor_401720+9Aj
.text:0040174F A1 EC C3 43+    mov     eax, ds:WaitForDebugEvent_43C3EC
.text:00401754 C7 44 24 04+    mov     [esp+88h+var_84], 0FFFFFFFFh
.text:0040175C 8D 55 94        lea     edx, [ebp+dbg_event_6C]
.text:0040175F 89 14 24        mov     [esp+88h+var_88], edx
.text:00401762 FF D0           call    eax ; WaitForDebugEvent_43C3EC
.text:00401764 83 EC 08        sub     esp, 8
.text:00401767 8B 45 94        mov     eax, [ebp+dbg_event_6C]
.text:0040176A 83 F8 01        cmp     eax, 1
.text:0040176D 74 0E           jz      short EXCEPTION_DEBUG_EVENT_40177D
.text:0040176F 83 F8 05        cmp     eax, 5
.text:00401772 75 23           jnz     short OTHER_EVENTS_401797
.text:00401774 C7 45 F4 01+    mov     [ebp+var_C], 1                        ; EXIT_PROCESS_DEBUG_EVENT
.text:0040177B EB 1A           jmp     short OTHER_EVENTS_401797
.text:0040177D             ; ---------------------------------------------------------------------------
.text:0040177D
.text:0040177D             EXCEPTION_DEBUG_EVENT_40177D:                     ; CODE XREF: decryptor_401720+4Dj
.text:0040177D 8D 45 94        lea     eax, [ebp+dbg_event_6C]
.text:00401780 89 44 24 08     mov     [esp+88h+var_80], eax                 ; arg3: DEBUG_EVENT
.text:00401784 8B 45 0C        mov     eax, [ebp+arg_4]
.text:00401787 89 44 24 04     mov     [esp+88h+var_84], eax                 ; arg2: thread handle
.text:0040178B 8B 45 08        mov     eax, [ebp+arg_0]
.text:0040178E 89 04 24        mov     [esp+88h+var_88], eax                 ; arg1: process handle
.text:00401791 E8 29 00 00+    call    handle_exception_4017BF
.text:00401796 90              nop
.text:00401797
.text:00401797             OTHER_EVENTS_401797:                              ; CODE XREF: decryptor_401720+52j
.text:00401797                                                               ; decryptor_401720+5Bj
.text:00401797 A1 F0 C3 43+    mov     eax, ds:ContinueDebugEvent_43C3F0
.text:0040179C 8B 4D 9C        mov     ecx, [ebp+var_64]
.text:0040179F 8B 55 98        mov     edx, [ebp+var_68]
.text:004017A2 C7 44 24 08+    mov     [esp+88h+var_80], 10002h
.text:004017AA 89 4C 24 04     mov     [esp+88h+var_84], ecx
.text:004017AE 89 14 24        mov     [esp+88h+var_88], edx
.text:004017B1 FF D0           call    eax ; ContinueDebugEvent_43C3F0
.text:004017B3 83 EC 0C        sub     esp, 0Ch
.text:004017B6
.text:004017B6             END_4017B6:                                       ; CODE XREF: decryptor_
```

We have 2 types of exceptions here: **Illegal instruction** and **single step**:
```assembly
.text:004017BF             handle_exception_4017BF proc near                 ; CODE XREF: decryptor_401720+71p
....
.text:004017DE 89 45 F4        mov     [ebp+var_C], eax
.text:004017E1 8B 45 A0        mov     eax, [ebp+var_60]                     ; eax = ExceptionCode
.text:004017E4 3D 04 00 00+    cmp     eax, 80000004h                        ; (= EXCEPTION_SINGLE_STEP)
.text:004017E9 74 0E           jz      short EXCEPTION_SINGLE_STEP_4017F9
.text:004017EB 3D 1D 00 00+    cmp     eax, 0C000001Dh                       ; (= EXCEPTION_ILLEGAL_INSTRUCTION)
.text:004017F0 74 22           jz      short EXCEPTION_ILLEGAL_INSTRUCTION_401814
.text:004017F2 3D 03 00 00+    cmp     eax, 80000003h                        ; (= EXCEPTION_BREAKPOINT)
.text:004017F7 EB 35           jmp     short END_40182E
.text:004017F9             ; ---------------------------------------------------------------------------
.text:004017F9
.text:004017F9             EXCEPTION_SINGLE_STEP_4017F9:                     ; CODE XREF: handle_exception_4017BF+2Aj
.text:004017F9 8B 45 F4        mov     eax, [ebp+var_C]
.text:004017FC 89 44 24 08     mov     [esp+78h+var_70], eax                 ; ExceptionAddress
.text:00401800 8B 45 0C        mov     eax, [ebp+arg_4]
.text:00401803 89 44 24 04     mov     [esp+78h+var_74], eax                 ; arg2: thread handle
.text:00401807 8B 45 08        mov     eax, [ebp+8]
.text:0040180A 89 04 24        mov     [esp+78h+var_78], eax                 ; arg1: process handle
.text:0040180D E8 24 00 00+    call    single_step_ex_401836
.text:00401812 EB 1A           jmp     short END_40182E
.text:00401814             ; ---------------------------------------------------------------------------
.text:00401814
.text:00401814             EXCEPTION_ILLEGAL_INSTRUCTION_401814:             ; CODE XREF: handle_exception_4017BF+31j
.text:00401814 8B 45 F4        mov     eax, [ebp+var_C]
.text:00401817 89 44 24 08     mov     [esp+78h+var_70], eax                 ; arg3: ExceptionAddress
.text:0040181B 8B 45 0C        mov     eax, [ebp+arg_4]
.text:0040181E 89 44 24 04     mov     [esp+78h+var_74], eax                 ; arg2: thread handle
.text:00401822 8B 45 08        mov     eax, [ebp+arg_0]
.text:00401825 89 04 24        mov     [esp+78h+var_78], eax                 ; arg1: process handle
.text:00401828 E8 5F 01 00+    call    illegal_instr_ex_40198C
.text:0040182D 90              nop
.text:0040182E
.text:0040182E             END_40182E:                                       ; CODE XREF: handle_exception_4017BF+38j
....
```

Here are also some important structs that we are gonna need:
```C
typedef struct _DEBUG_EVENT {
  DWORD dwDebugEventCode;
  DWORD dwProcessId;
  DWORD dwThreadId;
  union {
    EXCEPTION_DEBUG_INFO      Exception;
    CREATE_THREAD_DEBUG_INFO  CreateThread;
    CREATE_PROCESS_DEBUG_INFO CreateProcessInfo;
    EXIT_THREAD_DEBUG_INFO    ExitThread;
    EXIT_PROCESS_DEBUG_INFO   ExitProcess;
    LOAD_DLL_DEBUG_INFO       LoadDll;
    UNLOAD_DLL_DEBUG_INFO     UnloadDll;
    OUTPUT_DEBUG_STRING_INFO  DebugString;
    RIP_INFO                  RipInfo;
  } u;
} DEBUG_EVENT, *LPDEBUG_EVENT;


typedef struct _EXCEPTION_DEBUG_INFO {
  EXCEPTION_RECORD ExceptionRecord;
  DWORD            dwFirstChance;
} EXCEPTION_DEBUG_INFO, *LPEXCEPTION_DEBUG_INFO;


typedef struct _EXCEPTION_RECORD {
  DWORD                    ExceptionCode;
  DWORD                    ExceptionFlags;
  struct _EXCEPTION_RECORD *ExceptionRecord;
  PVOID                    ExceptionAddress;
  DWORD                    NumberParameters;
  ULONG_PTR                ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD;


#define EXCEPTION_ACCESS_VIOLATION          ((DWORD)0xC0000005L)
#define EXCEPTION_DATATYPE_MISALIGNMENT     ((DWORD)0x80000002L)
#define EXCEPTION_BREAKPOINT                ((DWORD)0x80000003L)
#define EXCEPTION_SINGLE_STEP               ((DWORD)0x80000004L)
#define EXCEPTION_ARRAY_BOUNDS_EXCEEDED     ((DWORD)0xC000008CL)
#define EXCEPTION_FLT_DENORMAL_OPERAND      ((DWORD)0xC000008DL)
#define EXCEPTION_FLT_DIVIDE_BY_ZERO        ((DWORD)0xC000008EL)
#define EXCEPTION_FLT_INEXACT_RESULT        ((DWORD)0xC000008FL)
#define EXCEPTION_FLT_INVALID_OPERATION     ((DWORD)0xC0000090L)
#define EXCEPTION_FLT_OVERFLOW              ((DWORD)0xC0000091L)
#define EXCEPTION_FLT_STACK_CHECK           ((DWORD)0xC0000092L)
#define EXCEPTION_FLT_UNDERFLOW             ((DWORD)0xC0000093L)
#define EXCEPTION_INT_DIVIDE_BY_ZERO        ((DWORD)0xC0000094L)
#define EXCEPTION_INT_OVERFLOW              ((DWORD)0xC0000095L)
#define EXCEPTION_PRIV_INSTRUCTION          ((DWORD)0xC0000096L)
#define EXCEPTION_IN_PAGE_ERROR             ((DWORD)0xC0000006L)
#define EXCEPTION_STACK_OVERFLOW            ((DWORD)0xC00000FDL)
#define EXCEPTION_ILLEGAL_INSTRUCTION       ((DWORD)0xC000001DL)
#define EXCEPTION_NONCONTINUABLE_EXCEPTION  ((DWORD)0xC0000025L)
#define EXCEPTION_INVALID_DISPOSITION       ((DWORD)0xC0000026L)
#define EXCEPTION_GUARD_PAGE                ((DWORD)0x80000001L)
#define EXCEPTION_INVALID_HANDLE            ((DWORD)0xC0000008L)
#define EXCEPTION_POSSIBLE_DEADLOCK         ((DWORD)0xC0000194L)
#define CONTROL_C_EXIT                      ((DWORD)0xC000013AL)
```


When clone starts, it hits an illegal instruction violation at `SECRET_CODE_401E69`, so the
parent program executes `illegal_instr_ex_40198C`:
```assembly
.text:0040198C             illegal_instr_ex_40198C proc near                 ; CODE XREF: handle_exception_4017BF+69p
....
.text:00401992 C7 44 24 04+    mov     [esp+58h+sloc_54], offset LAST_STATE_43C43C ; arg2: state1
.text:0040199A 8B 45 08        mov     eax, [ebp+arg_0]
.text:0040199D 89 04 24        mov     [esp+58h+sloc_58], eax                ; arg1: process handle
.text:004019A0 E8 BA 06 00+    call    write_to_clone_40205F
.text:004019A5 C7 44 24 04+    mov     [esp+58h+sloc_54], offset KEY_STATE_43C420 ; arg2: &state
.text:004019AD 8B 45 08        mov     eax, [ebp+arg_0]
.text:004019B0 89 04 24        mov     [esp+58h+sloc_58], eax                ; arg1: process handle
.text:004019B3 E8 A7 06 00+    call    write_to_clone_40205F
.text:004019B8 C7 05 8C C6+    mov     ds:GLO_B_43C68C, 1
.text:004019C2 8B 45 10        mov     eax, [ebp+addr_loc_8]
.text:004019C5 89 04 24        mov     [esp+58h+sloc_58], eax                ; arg1: exception address
.text:004019C8 E8 24 07 00+    call    table_search_4020F1                   ; find key
.text:004019CD 89 45 F4        mov     [ebp+var_C], eax
.text:004019D0 8B 45 F4        mov     eax, [ebp+var_C]
.text:004019D3 8B 50 04        mov     edx, [eax+4]                          ; edx = table key
.text:004019D6 8B 00           mov     eax, [eax]                            ; eax = crash location
.text:004019D8 89 45 EC        mov     [ebp+addr_14], eax
.text:004019DB 89 55 F0        mov     [ebp+key_10], edx
.text:004019DE C7 44 24 04+    mov     [esp+58h+sloc_54], 2                  ; arg2: key size (always 2)
.text:004019E6 8D 45 EC        lea     eax, [ebp+addr_14]
.text:004019E9 83 C0 04        add     eax, 4
.text:004019EC 89 04 24        mov     [esp+58h+sloc_58], eax                ; arg1: &key
.text:004019EF E8 A9 05 00+    call    decrypt_wrapper_401F9D
.text:004019F4 8D 45 C8        lea     eax, [ebp+out_38]
.text:004019F7 C7 44 24 10+    mov     [esp+58h+var_48], 2                   ; arg5: key size (always 2)
.text:004019FF 8D 55 EC        lea     edx, [ebp+addr_14]
.text:00401A02 83 C2 04        add     edx, 4
.text:00401A05 89 54 24 0C     mov     [esp+58h+var_4C], edx                 ; arg4: &key
.text:00401A09 8B 55 10        mov     edx, [ebp+addr_loc_8]
.text:00401A0C 89 54 24 08     mov     [esp+58h+var_50], edx                 ; arg3: address to decrypt
.text:00401A10 8B 55 08        mov     edx, [ebp+arg_0]
.text:00401A13 89 54 24 04     mov     [esp+58h+sloc_54], edx                ; arg2: process handle
.text:00401A17 89 04 24        mov     [esp+58h+sloc_58], eax                ; arg1: output
.text:00401A1A E8 99 05 00+    call    write_to_clone_ret_prev_401FB8
.text:00401A1F 8B 45 C8        mov     eax, [ebp+out_38]
.text:00401A22 A3 20 C4 43+    mov     ds:KEY_STATE_43C420, eax              ; update state
.text:00401A27 8B 45 CC        mov     eax, [ebp+var_34]
.text:00401A2A A3 24 C4 43+    mov     ds:KEY_SZ_43C424, eax
.text:00401A2F 8B 45 D0        mov     eax, [ebp+var_30]
.text:00401A32 A3 28 C4 43+    mov     ds:dword_43C428, eax
.text:00401A37 8B 45 D4        mov     eax, [ebp+var_2C]
.text:00401A3A A3 2C C4 43+    mov     ds:dword_43C42C, eax
.text:00401A3F 8B 45 D8        mov     eax, [ebp+var_28]
.text:00401A42 A3 30 C4 43+    mov     ds:dword_43C430, eax
.text:00401A47 8B 45 DC        mov     eax, [ebp+var_24]
.text:00401A4A A3 34 C4 43+    mov     ds:dword_43C434, eax
.text:00401A4F 8B 45 E0        mov     eax, [ebp+var_20]
.text:00401A52 A3 38 C4 43+    mov     ds:LAST_WRT_SIZE_43C438, eax
.text:00401A57 8B 45 10        mov     eax, [ebp+addr_loc_8]
.text:00401A5A 89 44 24 08     mov     [esp+58h+var_50], eax                 ; arg3: address to decrypt
.text:00401A5E 8B 45 0C        mov     eax, [ebp+arg_4]
.text:00401A61 89 44 24 04     mov     [esp+58h+sloc_54], eax                ; arg2: thread handle
.text:00401A65 8B 45 08        mov     eax, [ebp+arg_0]
.text:00401A68 89 04 24        mov     [esp+58h+sloc_58], eax                ; arg1: process handle
.text:00401A6B E8 BB 00 00+    call    decrypt_stage_2_401B2B
.text:00401A70 C7 44 24 04+    mov     [esp+58h+sloc_54], 1                  ; arg2: 1 (== clone continues in single step)
.text:00401A78 8B 45 0C        mov     eax, [ebp+arg_4]
.text:00401A7B 89 04 24        mov     [esp+58h+sloc_58], eax                ; arg1: thread handle
.text:00401A7E E8 03 00 00+    call    continue_clone_execution_401A86
.text:00401A83 90              nop
.text:00401A84 C9              leave
.text:00401A85 C3              retn
.text:00401A85             illegal_instr_ex_40198C endp
```

I have renamed the functions to give them meaningful names, to make it simpler.
**We're gonna omit all details and focus on the major parts of the algorithm.**
Here's the decompliled version:
```python
def illegal_instr(address):
    global key_state, last_state, glo_a, glo_b

    write_mem(*last_state)
    write_mem(*key_state)

    glo_b = 1

    key = key_lookup(address)
    key_list = [key & 0xff, (key & 0xff00) >> 8]
    key_state = (address, 2, key_list)

    decr_code = decrypt(key_list, 2)
    data = read_mem(address, 2)    

    # replace the first two bytes
    write_mem(address, 2, decr_code)
    key_state = (address, 2, data)

    sz, opcode = decrypt_stage_2(address)

    return sz, opcode
```


The first important function is `table_search_4020F1` that takes the crash location and looks up
in a table to extract a key. This table contains all possible locations that the clone can crash
along with a 2-byte decryption key:
```python
key_table = [
    (0x401C20, 0x8955), (0x401C37, 0x558B), (0x401C5F, 0x7D83), (0x401C65, 0x8390),
    (0x401C6C, 0x8955), (0x401C84, 0x558B), (0x401CBA, 0x7D83), (0x401CC0, 0x458B),
    (0x401CE2, 0x8955), (0x401CFB, 0x458B), (0x401D24, 0x7D83), (0x401D2A, 0x45C7),
    (0x401D33, 0x458B), (0x401D9E, 0x558B), (0x401DAD, 0x45C7), (0x401DB6, 0x458B),
    (0x401DD6, 0x7D83), (0x401DDC, 0xC990), (0x401DDF, 0x8955), (0x401DF0, 0x458B),
    (0x401DFB, 0x458B), (0x401E06, 0xC990), (0x401E09, 0x8955), (0x401E18, 0x458B),
    (0x401E23, 0x4583), (0x401E27, 0x7D83), (0x401E2D, 0xC990), (0x401E30, 0x8955),
    (0x401E48, 0x44C7), (0x401E62, 0xC085), (0x401E69, 0x8955), (0x401E7B, 0x458D),
    (0x401E8E, 0xA8A1), (0x401E9B, 0x458D), (0x401EA6, 0x4588), (0x401EAF, 0x04C7),
    (0x401EBB, 0x0CEB), (0x401EBD, 0x04C7), (0x401EC9, 0x00B8), 
    (0x436E3C, 0x25FF), 
    (0x436E44, 0x25FF),
    (0x436E5C, 0x25FF), 
    (0x436E84, 0x25FF)
]
```


Once we get the key, we decrypt it using a very simple decryption algorithm:

```assembly
.text:00401ED0             decrypt_401ED0 proc near                          ; CODE XREF: decrypt_stage_2_401B2B+42p
.text:00401ED0 55              push    ebp
.text:00401ED1 89 E5           mov     ebp, esp
.text:00401ED3 53              push    ebx
.text:00401ED4 83 EC 50        sub     esp, 50h
.text:00401ED7 C7 45 B4 0F+    mov     [ebp+tab_B_4C], 0Fh                   ; local table B
.text:00401EDE C7 45 B8 0B+    mov     [ebp+var_48], 0Bh
.text:00401EE5 C7 45 BC 4F+    mov     [ebp+var_44], 4Fh
.text:00401EEC C7 45 C0 3E+    mov     [ebp+var_40], 3Eh
.text:00401EF3 C7 45 C4 89+    mov     [ebp+var_3C], 89h
.text:00401EFA C7 45 C8 AC+    mov     [ebp+var_38], 0ACh
.text:00401F01 C7 45 CC FF+    mov     [ebp+var_34], 0FFh
.text:00401F08 C7 45 D0 81+    mov     [ebp+var_30], 81h
.text:00401F0F C7 45 D4 BA+    mov     [ebp+var_2C], 0BAh
.text:00401F16 C7 45 D8 7E+    mov     [ebp+var_28], 7Eh
.text:00401F1D C7 45 DC EC+    mov     [ebp+var_24], 0ECh
.text:00401F24 C7 45 E0 CC+    mov     [ebp+var_20], 0CCh
.text:00401F2B C7 45 E4 66+    mov     [ebp+var_1C], 66h
.text:00401F32 C7 45 E8 29+    mov     [ebp+var_18], 29h
.text:00401F39 C7 45 EC EE+    mov     [ebp+var_14], 0EEh
.text:00401F40 C7 45 F0 10+    mov     [ebp+var_10], 10h
.text:00401F47 C7 45 F8 00+    mov     [ebp+iter_8], 0
.text:00401F4E EB 3E           jmp     short loc_401F8E
.text:00401F50             ; ---------------------------------------------------------------------------
.text:00401F50
.text:00401F50             LOOP_401F50:                                      ; CODE XREF: decrypt_401ED0+C4j
.text:00401F50 8B 55 F8        mov     edx, [ebp+iter_8]
.text:00401F53 8B 45 08        mov     eax, [ebp+arg_0]
.text:00401F56 01 D0           add     eax, edx
.text:00401F58 0F B6 00        movzx   eax, byte ptr [eax]                   ; get the next byte of the key
.text:00401F5B 0F B6 D0        movzx   edx, al
.text:00401F5E 8B 45 F8        mov     eax, [ebp+iter_8]
.text:00401F61 8B 44 85 B4     mov     eax, [ebp+eax*4+tab_B_4C]             ; eax = loc_table_B[i]
.text:00401F65 29 C2           sub     edx, eax                              ; edx = key[i] - B[i]
.text:00401F67 89 D0           mov     eax, edx
.text:00401F69 89 45 F4        mov     [ebp+var_C], eax
.text:00401F6C F7 5D F4        neg     [ebp+var_C]                           ; var_C = ~(key[i] - B[i]) + 1 (2's complement)
.text:00401F6F 8B 45 F8        mov     eax, [ebp+iter_8]
.text:00401F72 8B 44 85 B4     mov     eax, [ebp+eax*4+tab_B_4C]
.text:00401F76 89 C3           mov     ebx, eax
.text:00401F78 8B 45 F4        mov     eax, [ebp+var_C]
.text:00401F7B 89 C1           mov     ecx, eax
.text:00401F7D 8B 55 F8        mov     edx, [ebp+iter_8]
.text:00401F80 8B 45 08        mov     eax, [ebp+arg_0]
.text:00401F83 01 D0           add     eax, edx
.text:00401F85 8D 14 0B        lea     edx, [ebx+ecx]
.text:00401F88 88 10           mov     [eax], dl                             ; key[i] = ~(key[i] - B[i]) + 1 + B[i]
.text:00401F8A 83 45 F8 01     add     [ebp+iter_8], 1
.text:00401F8E
.text:00401F8E             loc_401F8E:                                       ; CODE XREF: decrypt_401ED0+7Ej
.text:00401F8E 8B 45 F8        mov     eax, [ebp+iter_8]
.text:00401F91 3B 45 0C        cmp     eax, [ebp+n_4]
.text:00401F94 7C BA           jl      short LOOP_401F50
....
```

Here's the decompiled version:
```python
def decrypt(code, size):
    key = [0x0F, 0x0B, 0x4F, 0x3E, 0x89, 0xAC, 0xFF, 0x81,
           0xBA, 0x7E, 0xEC, 0xCC, 0x66, 0x29, 0xEE, 0x10]

    out = [0]*size

    for i in range(size):
        out[i] = (~(code[i] - key[i]) + 1 + key[i]) & 0xff

    return out
```

After key decryption, we move on `decrypt_stage_2_401B2B` which is the second part
of the decryption. Let's skip this for now and move on single step exception handler:
```assembly
.text:00401836             single_step_ex_401836 proc near                   ; CODE XREF: handle_exception_4017BF+4Ep
....
.text:0040183C C7 44 24 04+    mov     [esp+58h+var_54], offset LAST_STATE_43C43C ; arg2: state2 struct
.text:00401844 8B 45 08        mov     eax, [ebp+arg_0]
.text:00401847 89 04 24        mov     [esp+58h+var_58], eax                 ; arg1: process handle
.text:0040184A E8 10 08 00+    call    write_to_clone_40205F
.text:0040184F A1 20 C4 43+    mov     eax, ds:KEY_STATE_43C420              ; eax = current PC
.text:00401854 39 45 10        cmp     [ebp+arg_8], eax                      ; instruction already decrypted?
.text:00401857 0F 82 E4 00+    jb      DONT_DECRYPT_401941                   ; if so, skip decryption
.text:0040185D 8B 15 20 C4+    mov     edx, ds:KEY_STATE_43C420
.text:00401863 A1 24 C4 43+    mov     eax, ds:KEY_SZ_43C424
.text:00401868 01 D0           add     eax, edx
.text:0040186A 39 45 10        cmp     [ebp+arg_8], eax
.text:0040186D 0F 83 CE 00+    jnb     DONT_DECRYPT_401941
.text:00401873 8B 45 10        mov     eax, [ebp+arg_8]
.text:00401876 8B 15 20 C4+    mov     edx, ds:KEY_STATE_43C420
.text:0040187C 29 D0           sub     eax, edx                              ; eax = offset from prev state
.text:0040187E 89 45 F4        mov     [ebp+var_C], eax
.text:00401881 C7 44 24 04+    mov     [esp+58h+var_54], offset KEY_STATE_43C420
.text:00401889 8B 45 08        mov     eax, [ebp+arg_0]
.text:0040188C 89 04 24        mov     [esp+58h+var_58], eax
.text:0040188F E8 CB 07 00+    call    write_to_clone_40205F
.text:00401894 A1 20 C4 43+    mov     eax, ds:KEY_STATE_43C420
.text:00401899 89 04 24        mov     [esp+58h+var_58], eax
.text:0040189C E8 50 08 00+    call    table_search_4020F1
.text:004018A1 89 45 F0        mov     [ebp+var_10], eax
.text:004018A4 8B 45 F0        mov     eax, [ebp+var_10]
.text:004018A7 8B 50 04        mov     edx, [eax+4]                          ; edx = key
.text:004018AA 8B 00           mov     eax, [eax]                            ; eax = address location
.text:004018AC 89 45 E8        mov     [ebp+addr_18], eax
.text:004018AF 89 55 EC        mov     [ebp+key_14], edx
.text:004018B2 B8 02 00 00+    mov     eax, 2
.text:004018B7 2B 45 F4        sub     eax, [ebp+var_C]
.text:004018BA 8B 55 F4        mov     edx, [ebp+var_C]
.text:004018BD 8D 4D E8        lea     ecx, [ebp+addr_18]
.text:004018C0 83 C1 04        add     ecx, 4
.text:004018C3 01 CA           add     edx, ecx
.text:004018C5 89 44 24 04     mov     [esp+58h+var_54], eax
.text:004018C9 89 14 24        mov     [esp+58h+var_58], edx
.text:004018CC E8 CC 06 00+    call    decrypt_wrapper_401F9D                ; decrypt key
.text:004018D1 B8 02 00 00+    mov     eax, 2
.text:004018D6 2B 45 F4        sub     eax, [ebp+var_C]
.text:004018D9 89 C1           mov     ecx, eax
.text:004018DB 8B 45 F4        mov     eax, [ebp+var_C]
.text:004018DE 8D 55 E8        lea     edx, [ebp+addr_18]
.text:004018E1 83 C2 04        add     edx, 4
.text:004018E4 01 C2           add     edx, eax
.text:004018E6 8D 45 C8        lea     eax, [ebp+var_38]
.text:004018E9 89 4C 24 10     mov     [esp+58h+var_48], ecx
.text:004018ED 89 54 24 0C     mov     [esp+58h+var_4C], edx
.text:004018F1 8B 55 10        mov     edx, [ebp+arg_8]
.text:004018F4 89 54 24 08     mov     [esp+58h+var_50], edx
.text:004018F8 8B 55 08        mov     edx, [ebp+arg_0]
.text:004018FB 89 54 24 04     mov     [esp+58h+var_54], edx
.text:004018FF 89 04 24        mov     [esp+58h+var_58], eax                 ; output
.text:00401902 E8 B1 06 00+    call    write_to_clone_ret_prev_401FB8
.text:00401907 8B 45 C8        mov     eax, [ebp+var_38]
.text:0040190A A3 20 C4 43+    mov     ds:KEY_STATE_43C420, eax
.text:0040190F 8B 45 CC        mov     eax, [ebp+var_34]
.text:00401912 A3 24 C4 43+    mov     ds:KEY_SZ_43C424, eax                 ; # bytes written
.text:00401917 8B 45 D0        mov     eax, [ebp+var_30]
.text:0040191A A3 28 C4 43+    mov     ds:dword_43C428, eax
.text:0040191F 8B 45 D4        mov     eax, [ebp+var_2C]
.text:00401922 A3 2C C4 43+    mov     ds:dword_43C42C, eax
.text:00401927 8B 45 D8        mov     eax, [ebp+var_28]
.text:0040192A A3 30 C4 43+    mov     ds:dword_43C430, eax
.text:0040192F 8B 45 DC        mov     eax, [ebp+var_24]
.text:00401932 A3 34 C4 43+    mov     ds:dword_43C434, eax
.text:00401937 8B 45 E0        mov     eax, [ebp+var_20]
.text:0040193A A3 38 C4 43+    mov     ds:LAST_WRT_SIZE_43C438, eax
.text:0040193F EB 13           jmp     short ELSE_401954
.text:00401941             ; ---------------------------------------------------------------------------
.text:00401941
.text:00401941             DONT_DECRYPT_401941:                              ; CODE XREF: single_step_ex_401836+21j
.text:00401941                                                               ; single_step_ex_401836+37j
.text:00401941 C7 44 24 04+    mov     [esp+58h+var_54], offset KEY_STATE_43C420
.text:00401949 8B 45 08        mov     eax, [ebp+arg_0]
.text:0040194C 89 04 24        mov     [esp+58h+var_58], eax
.text:0040194F E8 0B 07 00+    call    write_to_clone_40205F
.text:00401954
.text:00401954             ELSE_401954:                                      ; CODE XREF: single_step_ex_401836+109j
.text:00401954 A1 8C C6 43+    mov     eax, ds:GLO_B_43C68C
.text:00401959 85 C0           test    eax, eax
.text:0040195B 74 2C           jz      short SKIP_401989
.text:0040195D 8B 45 10        mov     eax, [ebp+arg_8]
.text:00401960 89 44 24 08     mov     [esp+58h+var_50], eax
.text:00401964 8B 45 0C        mov     eax, [ebp+arg_4]
.text:00401967 89 44 24 04     mov     [esp+58h+var_54], eax
.text:0040196B 8B 45 08        mov     eax, [ebp+arg_0]
.text:0040196E 89 04 24        mov     [esp+58h+var_58], eax
.text:00401971 E8 B5 01 00+    call    decrypt_stage_2_401B2B
.text:00401976 C7 44 24 04+    mov     [esp+58h+var_54], 1
.text:0040197E 8B 45 0C        mov     eax, [ebp+arg_4]
.text:00401981 89 04 24        mov     [esp+58h+var_58], eax
.text:00401984 E8 FD 00 00+    call    continue_clone_execution_401A86
.text:00401989
.text:00401989             SKIP_401989:                                      ; CODE XREF: single_step_ex_
```

Here we follow a similar process with illegal instruction handler. Here's the decompiled version:
```python
def single_step(address):
    global key_state, last_state, glo_a, glo_b

    write_mem(*last_state)
    

    if address < key_state[0] or address >= key_state[0] + key_state[1]:
        write_mem(*key_state)

    else:
        write_mem(*key_state)

        key = key_lookup(key_state[0])
        key_list = [key & 0xff, (key & 0xff00) >> 8]
        key_state = (key_state[0]+1, 1, key_list[1:])

        decr_code = decrypt(key_list[1:], 1)
        data = read_mem(address, 1)

        write_mem(address, 1, decr_code)
        key_state = (address, 1, data)


    if glo_b != 0:
        sz, opcode = decrypt_stage_2(address)
        return sz, opcode

    else:
        return 0, ''
```



The last part is the second stage of the decryption which is common for both illegal instruction
and single step exception handlers:
```assembly
.text:00401B2B             decrypt_stage_2_401B2B proc near                  ; CODE XREF: single_step_ex_401836+13Bp
....
.text:00401B31 A1 FC C3 43+    mov     eax, ds:ReadProcessMemory_43C3FC
.text:00401B36 C7 44 24 10+    mov     [esp+68h+var_58], 0
.text:00401B3E C7 44 24 0C+    mov     [esp+68h+var_5C], 10h                 ; read 16 bytes from crash location
.text:00401B46 8D 55 E4        lea     edx, [ebp+enc_code_1C]
.text:00401B49 89 54 24 08     mov     [esp+68h+var_60], edx
.text:00401B4D 8B 55 10        mov     edx, [ebp+arg_8]
.text:00401B50 89 54 24 04     mov     [esp+68h+var_64], edx
.text:00401B54 8B 55 08        mov     edx, [ebp+arg_0]
.text:00401B57 89 14 24        mov     [esp+68h+var_68], edx
.text:00401B5A FF D0           call    eax ; ReadProcessMemory_43C3FC
.text:00401B5C 83 EC 14        sub     esp, 14h
.text:00401B5F C7 44 24 04+    mov     [esp+68h+var_64], 10h                 ; arg2: 16
.text:00401B67 8D 45 E4        lea     eax, [ebp+enc_code_1C]
.text:00401B6A 89 04 24        mov     [esp+68h+var_68], eax                 ; arg1: encrypted code from clone
.text:00401B6D E8 5E 03 00+    call    decrypt_401ED0                        ; decrypt 16 bytes from clone
.text:00401B72 8D 45 E4        lea     eax, [ebp+enc_code_1C]
.text:00401B75 A3 60 C4 43+    mov     ds:remote_code_43C460, eax
.text:00401B7A C7 04 24 60+    mov     [esp+68h+var_68], offset remote_code_43C460 ; arg1: decrypted code
.text:00401B81 E8 72 18 03+    call    get_decoded_instruction_size_4333F8
.text:00401B86 83 EC 04        sub     esp, 4
.text:00401B89 89 45 F4        mov     [ebp+ins_sz_C], eax
.text:00401B8C A1 D4 C4 43+    mov     eax, ds:GLO_A_43C4D4
.text:00401B91 85 C0           test    eax, eax
.text:00401B93 74 0A           jz      short IS_ZERO_401B9F
.text:00401B95 C7 05 8C C6+    mov     ds:GLO_B_43C68C, 0
.text:00401B9F
.text:00401B9F             IS_ZERO_401B9F:                                   ; CODE XREF: decrypt_stage_2_401B2B+68j
.text:00401B9F B8 10 00 00+    mov     eax, 10h
.text:00401BA4 2B 45 F4        sub     eax, [ebp+ins_sz_C]                   ; decrypt the remaining 16-ins_sz bytes
.text:00401BA7 8B 55 F4        mov     edx, [ebp+ins_sz_C]
.text:00401BAA 8D 4D E4        lea     ecx, [ebp+enc_code_1C]
.text:00401BAD 01 CA           add     edx, ecx
.text:00401BAF 89 44 24 04     mov     [esp+68h+var_64], eax
.text:00401BB3 89 14 24        mov     [esp+68h+var_68], edx
.text:00401BB6 E8 15 03 00+    call    decrypt_401ED0                        ; decrypt the remaining 16-ins_sz bytes
.text:00401BBB 8D 45 B8        lea     eax, [ebp+var_48]
.text:00401BBE C7 44 24 10+    mov     [esp+68h+var_58], 10h
.text:00401BC6 8D 55 E4        lea     edx, [ebp+enc_code_1C]
.text:00401BC9 89 54 24 0C     mov     [esp+68h+var_5C], edx
.text:00401BCD 8B 55 10        mov     edx, [ebp+arg_8]
.text:00401BD0 89 54 24 08     mov     [esp+68h+var_60], edx
.text:00401BD4 8B 55 08        mov     edx, [ebp+arg_0]
.text:00401BD7 89 54 24 04     mov     [esp+68h+var_64], edx
.text:00401BDB 89 04 24        mov     [esp+68h+var_68], eax
.text:00401BDE E8 D5 03 00+    call    write_to_clone_ret_prev_401FB8
.text:00401BE3 8B 45 B8        mov     eax, [ebp+var_48]
.text:00401BE6 A3 3C C4 43+    mov     ds:LAST_STATE_43C43C, eax
.text:00401BEB 8B 45 BC        mov     eax, [ebp+var_44]
.text:00401BEE A3 40 C4 43+    mov     ds:dword_43C440, eax
.text:00401BF3 8B 45 C0        mov     eax, [ebp+var_40]
.text:00401BF6 A3 44 C4 43+    mov     ds:dword_43C444, eax
.text:00401BFB 8B 45 C4        mov     eax, [ebp+var_3C]
.text:00401BFE A3 48 C4 43+    mov     ds:dword_43C448, eax
.text:00401C03 8B 45 C8        mov     eax, [ebp+var_38]
.text:00401C06 A3 4C C4 43+    mov     ds:dword_43C44C, eax
.text:00401C0B 8B 45 CC        mov     eax, [ebp+var_34]
.text:00401C0E A3 50 C4 43+    mov     ds:dword_43C450, eax
.text:00401C13 8B 45 D0        mov     eax, [ebp+var_30]
.text:00401C16 A3 54 C4 43+    mov     ds:dword_43C454, eax
....
```

Function `get_decoded_instruction_size_4333F8` expands to a huge set of functions that are used to disassemble an x86 instruction. We don't care how it works. All we need to know is that it returns 
the current instruction size. Here's the decompiled version of the 2nd stage of the decryption:
```python
def decrypt_stage_2(address):
    global key_state, last_state, glo_a, glo_b    

    # read 16 bytes and decrypt them
    code = read_mem(address, 16)
    decr_code = decrypt(code, 16)


    code = decr_code
    code_str = ''.join(['%c' % c for c in code])

    # -------------------------------------------------------------------------
    # disassemble the instruction
    # -------------------------------------------------------------------------
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    sz = -1

    for i in md.disasm(code_str, address):
        print "0x%x:     %s\t%s" % (i.address, i.mnemonic, i.op_str)
        sz, opcode =  i.size, i.mnemonic
        break

    # this insturction disassembled incorrectly by capstone. Fix it       
    if code_str[:5] == '\xa1\xa8\xd1\x43\x00':
        size, opcode = 5, "mov     eax, ds:_iob"
        print "Correction:", opcode


    if sz == -1:
        raise Exception('Disassembly at 0x%x failed' % address)


    # update last state
    if glo_a != 0: glo_b = 0

    decr_code2 = decrypt(decr_code[sz:16], 16-sz)
    data = read_mem(address, 16)

    write_mem(address, 16-sz, decr_code2)

    last_state = (address, 16, data)

    return sz, opcode
```

[watchmen_decrypt.py](watchmen_decrypt.py), decrypts the code from clone and dumps it
to stdout.


### Part 2: Reversing the actual code

Below is the actual assembly code that is being executed in the clone:
```assembly
; ---------------------------------------------------------------------------------------
0x401c20:     push      rbp                                 ; xor_flag(flag)
0x401c21:     mov       ebp, esp                            ;
0x401c23:     push      rbx                                 ;
0x401c24:     sub       esp, 0x10                           ;
0x401c27:     mov       dword ptr [rbp - 0xc], 0x43a010     ; C_STR1 = October 12th, 1985...
0x401c2e:     mov       dword ptr [rbp - 8], 0              ; iterator = 0
0x401c35:     jmp       0x401c5f                            ;
0x401c37:     ud2                                           ;
0x401c37:     mov       edx, dword ptr [rbp - 8]            ; edx = iterator
0x401c3a:     mov       eax, dword ptr [rbp + 8]            ;
0x401c3d:     add       eax, edx                            ; 
0x401c3f:     movzx     ebx, byte ptr [rax]                 ; ebx = flag[i]
0x401c42:     mov       edx, dword ptr [rbp - 8]            ; edx = iterator
0x401c45:     mov       eax, dword ptr [rbp - 0xc]          ;
0x401c48:     add       eax, edx                            ; 
0x401c4a:     movzx     ecx, byte ptr [rax]                 ; ecx = C_STR1[i]
0x401c4d:     mov       edx, dword ptr [rbp - 8]            ; 
0x401c50:     mov       eax, dword ptr [rbp + 8]            ;
0x401c53:     add       eax, edx                            ;
0x401c55:     xor       ebx, ecx                            ; ebx = flag[i] ^ C_STR1[i]
0x401c57:     mov       edx, ebx                            ;
0x401c59:     mov       byte ptr [rax], dl                  ; flag[i] ^= C_STR[i]
0x401c5b:     add       dword ptr [rbp - 8], 1              ; ++iterator
0x401c5f:     ud2                                           ;
0x401c5f:     cmp       dword ptr [rbp - 8], 0x1f           ; if iterator <= 31 continue
0x401c63:     jle       0x401c37                            ; loop
0x401c65:     ud2                                           ;
0x401c65:     nop                                           ; epilog
0x401c66:     add       esp, 0x10                           ;
0x401c69:     pop       rbx                                 ;
0x401c6a:     pop       rbp                                 ;
0x401c6b:     ret


; ---------------------------------------------------------------------------------------
0x401c6c:     ud2                                           ; shuffle_nibbles(flag)
0x401c6c:     push      rbp                                 ;
0x401c6d:     mov       ebp, esp                            ;
0x401c6f:     sub       esp, 0x10                           ;
0x401c72:     mov       eax, dword ptr [rbp + 8]            ;
0x401c75:     movzx     eax, byte ptr [rax]                 ;
0x401c78:     mov       byte ptr [rbp - 5], al              ; v5 = flag[0]
0x401c7b:     mov       dword ptr [rbp - 4], 0              ; iterator = 0
0x401c82:     jmp       0x401cba                            ;
0x401c84:     ud2                                           ;
0x401c84:     mov       edx, dword ptr [rbp - 4]            ;
0x401c87:     mov       eax, dword ptr [rbp + 8]            ;
0x401c8a:     add       eax, edx                            ;
0x401c8c:     movzx     eax, byte ptr [rax]                 ; eax = flag[i]
0x401c8f:     shr       al, 4                               ;
0x401c92:     mov       ecx, eax                            ; ecx = flag[i] >> 4
0x401c94:     mov       eax, dword ptr [rbp - 4]            ;
0x401c97:     lea       edx, [rax + 1]                      ;
0x401c9a:     mov       eax, dword ptr [rbp + 8]            ;
0x401c9d:     add       eax, edx                            ;
0x401c9f:     movzx     eax, byte ptr [rax]                 ; eax = flag[i + 1]
0x401ca2:     movzx     eax, al                             ;
0x401ca5:     shl       eax, 4                              ; eax = flag[i + 1] << 4
0x401ca8:     or        ecx, eax                            ; ecx = (flag[i] >> 4) | (flag[i+1] << 4)
0x401caa:     mov       edx, dword ptr [rbp - 4]            ;
0x401cad:     mov       eax, dword ptr [rbp + 8]            ;
0x401cb0:     add       eax, edx                            ; eax = flag[i]
0x401cb2:     mov       edx, ecx                            ;
0x401cb4:     mov       byte ptr [rax], dl                  ; flag[i] = (flag[i] >> 4) | (flag[i+1] << 4)
0x401cb6:     add       dword ptr [rbp - 4], 1              ; ++iterator
0x401cba:     ud2                                           ;
0x401cba:     cmp       dword ptr [rbp - 4], 0x1e           ; if iterator <= 31 continue
0x401cbe:     jle       0x401c84                            ; loop
0x401cc0:     ud2                                           ;
0x401cc0:     mov       eax, dword ptr [rbp + 8]            ;
0x401cc3:     add       eax, 0x1f                           ;
0x401cc6:     movzx     eax, byte ptr [rax]                 ; eax = flag[31]
0x401cc9:     shr       al, 4                               ; eax = flag[31] >> 4
0x401ccc:     mov       edx, eax                            ;
0x401cce:     movzx     eax, byte ptr [rbp - 5]             ;
0x401cd2:     shl       eax, 4                              ; eax = flag[0] << 4
0x401cd5:     or        edx, eax                            ;
0x401cd7:     mov       eax, dword ptr [rbp + 8]            ;
0x401cda:     add       eax, 0x1f                           ;
0x401cdd:     mov       byte ptr [rax], dl                  ; flag[31] = (flag[31] >> 4) | (flag[0] << 4)
0x401cdf:     nop                                           ; epilog
0x401ce0:     leave                                         ;
0x401ce1:     ret                                           ;


; ---------------------------------------------------------------------------------------
0x401ce2:     ud2                                           ; swap_flag(flag)
0x401ce2:     push      rbp                                 ;
0x401ce3:     mov       ebp, esp                            ;
0x401ce5:     sub       esp, 0xc0                           ;
0x401ceb:     mov       dword ptr [rbp - 0x10], 0x43a04c    ; C_STR2 = I am tired of Earth, these ...
0x401cf2:     mov       dword ptr [rbp - 4], 0              ; iterator = 0
0x401cf9:     jmp       0x401d24                            ;
0x401cfb:     ud2                                           ;
0x401cfb:     mov       eax, dword ptr [rbp - 4]            ; (initialization loop)
0x401cfe:     mov       edx, dword ptr [rbp - 4]            ;
0x401d01:     mov       dword ptr [rbp + rax*4 - 0x94], edx ; v94[i] = i (int)
0x401d08:     mov       edx, dword ptr [rbp - 4]            ;
0x401d0b:     mov       eax, dword ptr [rbp + 8]            ;
0x401d0e:     add       eax, edx                            ;
0x401d10:     movzx     eax, byte ptr [rax]                 ; eax = flag[i]
0x401d13:     lea       ecx, [rbp - 0xb4]                   ; 
0x401d19:     mov       edx, dword ptr [rbp - 4]            ;
0x401d1c:     add       edx, ecx                            ;
0x401d1e:     mov       byte ptr [rdx], al                  ; vb4[i] = flag[i]
0x401d20:     add       dword ptr [rbp - 4], 1              ; ++iterator
0x401d24:     ud2                                           ;
0x401d24:     cmp       dword ptr [rbp - 4], 0x1f           ; if iterator <= 31 continue
0x401d28:     jle       0x401cfb                            ; loop
0x401d2a:     ud2                                           ;

0x401d2a:     mov       dword ptr [rbp - 8], 0              ; j = 0
0x401d31:     jmp       0x401d9e                            ;
0x401d33:     ud2                                           ;
0x401d33:     mov       eax, dword ptr [rbp - 8]            ; eax = j
0x401d36:     cdq                                           ;
0x401d37:     shr       edx, 0x1b                           ; edx = 0
0x401d3a:     add       eax, edx                            ;
0x401d3c:     and       eax, 0x1f                           ; eax = j & 0x1f
0x401d3f:     sub       eax, edx                            ;
0x401d41:     mov       eax, dword ptr [rbp + rax*4 - 0x94] ;
0x401d48:     mov       byte ptr [rbp - 0x11], al           ; v11 = v94[j & 0x1f]

0x401d4b:     mov       edx, dword ptr [rbp - 8]            ; edx = j
0x401d4e:     mov       eax, dword ptr [rbp - 0x10]         ; eax = C_STR2
0x401d51:     add       eax, edx                            ;
0x401d53:     movzx     eax, byte ptr [rax]                 ;
0x401d56:     movzx     eax, al                             ;  
0x401d59:     and       eax, 0x1f                           ;
0x401d5c:     mov       ecx, eax                            ; ecx = C_STR2[j] & 0x1f
0x401d5e:     mov       eax, dword ptr [rbp - 8]            ; eax = j
0x401d61:     cdq                                           ; edx = 0
0x401d62:     shr       edx, 0x1b                           ; edx = 0
0x401d65:     add       eax, edx                            ;
0x401d67:     and       eax, 0x1f                           ; eax = j & 0x1f
0x401d6a:     sub       eax, edx                            ; edx = j
0x401d6c:     mov       edx, eax                            ;
0x401d6e:     mov       eax, dword ptr [rbp + rcx*4 - 0x94] ; eax = v94[i]
0x401d75:     mov       dword ptr [rbp + rdx*4 - 0x94], eax ; v94[j & 0x1f] = v94[C_STR2[j] & 0x1f]
0x401d7c:     mov       edx, dword ptr [rbp - 8]            ;
0x401d7f:     mov       eax, dword ptr [rbp - 0x10]         ;
0x401d82:     add       eax, edx                            ;
0x401d84:     movzx     eax, byte ptr [rax]                 ; 
0x401d87:     movzx     eax, al                             ;
0x401d8a:     and       eax, 0x1f                           ; eax = C_STR2[j] & 0x1f
0x401d8d:     mov       edx, eax                            ;
0x401d8f:     movzx     eax, byte ptr [rbp - 0x11]          ;
0x401d93:     mov       dword ptr [rbp + rdx*4 - 0x94], eax ; v94[C_STR2[j] & 0x1f] = v11

0x401d9a:     add       dword ptr [rbp - 8], 1              ; ++j
0x401d9e:     ud2                                           ;
0x401d9e:     mov       edx, dword ptr [rbp - 8]            ;
0x401da1:     mov       eax, dword ptr [rbp - 0x10]         ;
0x401da4:     add       eax, edx                            ;
0x401da6:     movzx     eax, byte ptr [rax]                 ; eax = C_STR2[j]
0x401da9:     test      al, al                              ; if C_STR2[j] != 0 continue
0x401dab:     jne       0x401d33                            ; loop

0x401dad:     ud2                                           ;
0x401dad:     mov       dword ptr [rbp - 0xc], 0            ; k = 0
0x401db4:     jmp       0x401dd6                            ; 
0x401db6:     ud2                                           ;
0x401db6:     mov       eax, dword ptr [rbp - 0xc]          ;
0x401db9:     mov       eax, dword ptr [rbp + rax*4 - 0x94] ; eax = v94[k]
0x401dc0:     mov       ecx, dword ptr [rbp - 0xc]          ;
0x401dc3:     mov       edx, dword ptr [rbp + 8]            ;
0x401dc6:     add       edx, ecx                            ; edx = flag[k]
0x401dc8:     movzx     eax, byte ptr [rbp + rax - 0xb4]    ; eax = vb4[v94[k]]
0x401dd0:     mov       byte ptr [rdx], al                  ; flag[k] = vb4[v94[k]]
0x401dd2:     add       dword ptr [rbp - 0xc], 1            ; ++k
0x401dd6:     ud2                                           ;
0x401dd6:     cmp       dword ptr [rbp - 0xc], 0x1f         ; if k <= 31 continue
0x401dda:     jle       0x401db6                            ; loop
0x401ddc:     ud2                                           ;
0x401ddc:     nop                                           ;
0x401ddd:     leave                                         ;
0x401dde:     ret                                           ;


; ---------------------------------------------------------------------------------------
0x401ddf:     ud2                                           ; encrypt_round()
0x401ddf:     push      rbp                                 ;
0x401de0:     mov       ebp, esp                            ;
0x401de2:     sub       esp, 4                              ;

0x401de5:     mov       eax, dword ptr [rbp + 8]            ;                                 ;
0x401de8:     mov       dword ptr [rsp], eax                ; arg1: flag
0x401deb:     call      0x401c20                            ; xor_flag()
0x401df0:     ud2                                           ;
0x401df0:     mov       eax, dword ptr [rbp + 8]            ;
0x401df3:     mov       dword ptr [rsp], eax                ; arg1: flag
0x401df6:     call      0x401c6c                            ; shuffle_nibbles()
0x401dfb:     ud2                                           ;
0x401dfb:     mov       eax, dword ptr [rbp + 8]            ;
0x401dfe:     mov       dword ptr [rsp], eax                ; arg1: flag
0x401e01:     call      0x401ce2                            ; swap_flag()
0x401e06:     ud2                                           ;
0x401e06:     nop                                           ;
0x401e07:     leave                                         ;
0x401e08:     ret                                           ;


; ---------------------------------------------------------------------------------------
0x401e09:     ud2                                           ; encrypt()
0x401e09:     push      rbp                                 ;
0x401e0a:     mov       ebp, esp                            ;
0x401e0c:     sub       esp, 0x14                           ;
0x401e0f:     mov       dword ptr [rbp - 4], 0              ; iterator
0x401e16:     jmp       0x401e27                            ;

0x401e18:     ud2                                           ;
0x401e18:     mov       eax, dword ptr [rbp + 8]            ;
0x401e1b:     mov       dword ptr [rsp], eax                ; arg1: flag
0x401e1e:     call      0x401ddf                            ; ecnrypt_round(flag)
0x401e23:     ud2                                           ;
0x401e23:     add       dword ptr [rbp - 4], 1              ; ++iterator
0x401e27:     ud2                                           ;
0x401e27:     cmp       dword ptr [rbp - 4], 0xf            ; if iterator <= 15 continue
0x401e2b:     jle       0x401e18                            ; loop
                                                            ;
0x401e2d:     ud2                                           ; epilog
0x401e2d:     nop                                           ;
0x401e2e:     leave                                         ;
0x401e2f:     ret                                           ;


; ---------------------------------------------------------------------------------------
0x401e30:     ud2                                           ; check_flag
0x401e30:     push      rbp                                 ;
0x401e31:     mov       ebp, esp                            ;
0x401e33:     sub       esp, 0x28                           ;
0x401e36:     mov       dword ptr [rbp - 0xc], 0x43a0a8     ; buf_A
0x401e3d:     mov       eax, dword ptr [rbp + 8]            ;
0x401e40:     mov       dword ptr [rsp], eax                ; arg1: flag
0x401e43:     call      0x401e09                            ; encrypt(flag)
0x401e48:     ud2                                           ;
0x401e48:     mov       dword ptr [rsp + 8], 0x20           ;
0x401e50:     mov       eax, dword ptr [rbp + 8]            ; arg3: 0x20
0x401e53:     mov       dword ptr [rsp + 4], eax            ; arg2: encrypt(flag)
0x401e57:     mov       eax, dword ptr [rbp - 0xc]          ;
0x401e5a:     mov       dword ptr [rsp], eax                ; arg1: buf_A
0x401e5d:     call      0x436e5c                            ; memcmp()
0x401e62:     ud2                                           ;
0x401e62:     test      eax, eax                            ;
0x401e64:     sete      al                                  ; if equal return 1
0x401e67:     leave                                         ;
0x401e68:     ret                                           ;


; ---------------------------------------------------------------------------------------
0x401e69:     ud2                                           ;
0x401e69:     push      rbp                                 ; prolog
0x401e6a:     mov       ebp, esp                            ;
0x401e6c:     sub       esp, 0x48                           ;
0x401e6f:     mov       dword ptr [rsp], 0x43a0cc           ; Once you realize what a joke ...
0x401e76:     call      0x436e44                            ; puts()    
0x401e7b:     ud2                                           ;
0x401e7b:     lea       eax, [rbp - 0x2a]                   ; store flag at rbp-0x2a
0x401e7e:     mov       dword ptr [rsp + 4], eax            ;
0x401e82:     mov       dword ptr [rsp], 0x43a12f           ; "%32s"
0x401e89:     call      0x436e3c                            ; scanf()
0x401e8e:     ud2                                           ;

0x401e8e:     movabs    eax, dword ptr [0x3e88ecc30043d1a8] ; capstone fault
Correction:   mov     eax, ds:_iob                          ; I/O buffer

0x401e93:     mov       dword ptr [rsp], eax                ;
0x401e96:     call      0x436e84                            ; flush(stdout)
0x401e9b:     ud2                                           ;
0x401e9b:     lea       eax, [rbp - 0x2a]                   ;
0x401e9e:     mov       dword ptr [rsp], eax                ; arg1: flag
0x401ea1:     call      0x401e30                            ; check_flag()
0x401ea6:     ud2                                           ;
0x401ea6:     mov       byte ptr [rbp - 9], al              ;
0x401ea9:     cmp       byte ptr [rbp - 9], 0               ;
0x401ead:     je        0x401ebd                            ; if it's 1 go to the goodboy message
0x401eaf:     ud2                                           ;
0x401eaf:     mov       dword ptr [rsp], 0x43a134           ; What happened to the American ...
0x401eb6:     call      0x436e44                            ; puts()
0x401ebb:     ud2                                           ;
0x401ebb:     jmp       0x401ec9                            ;
0x401ebd:     ud2                                           ;
0x401ebd:     mov       dword ptr [rsp], 0x43a180           ; No. Not even in the face of ...
0x401ec4:     call      0x436e44                            ; puts()
0x401ec9:     ud2                                           ;
0x401ec9:     mov       eax, 0                              ; epilog
0x401ece:     leave                                         ;
0x401ecf:     ret                                           ;

; ---------------------------------------------------------------------------------------
0x436e3c:     jmp       qword ptr [rip + 0x43d1e4]          ; scanf
0x436e44:     jmp       qword ptr [rip + 0x43d1e0]          ; puts
0x436e5c:     jmp       qword ptr [rip + 0x43d1d4]          ; memcmp
0x436e84:     jmp       qword ptr [rip + 0x43d1c0]          ; fflush
```


The way it works is very simple: First we give a 32 byte input, then we encrypt it, and finally
we compare it against the following string:
```
0xE8, 0xF4, 0xDA, 0xF1, 0x15, 0xC6, 0xB8, 0xBD, 0x77, 0x8C, 0xC1, 0xF9, 0x74, 0x46, 0x78, 0xBA,
0xD1, 0x4E, 0xBC, 0x3A, 0xF3, 0x6D, 0xA9, 0x61, 0x44, 0x61, 0x65, 0x13, 0x6D, 0x3D, 0xCE, 0x7B
```

Encryption consists of **16** rounds. In each round we perform **3** operations: `xor_flag`, 
`rotate_nibbles` and `shuffle_flag`:

```python
def xor_flag(flag):
    C_STR1 = "October 12th, 1985. Tonight, a comedian died in New York"

    for i in range(32): flag[i] ^= ord(C_STR1[i])

    return flag
```

```python
def rotate_nibbles(flag):
    v5 = flag[0]

    for i in range(31):
        flag[i] = ((flag[i] >> 4) | (flag[i+1] << 4)) & 0xff

    flag[31] = ((flag[31] >> 4) | (v5 << 4) & 0xff) & 0xff

    return flag
```

```python
def shuffle_flag(flag):
    C_STR2 = "I am tired of Earth, these people. I'm tired of being caught in the tangle of their lives."

    v94, vb4 = [0]*len(C_STR2), [0]*len(C_STR2)

    for i in range(32):
        v94[i] = i
        vb4[i] = flag[i]

    for j in range(len(C_STR2)):
        # swap element at offset j % 32 with element at offset C_STR2[j] % 32
        v11 = v94[j % 32]
        v94[j % 32] = v94[ord(C_STR2[j]) % 32]
        v94[ord(C_STR2[j]) % 32] = v11

    for k in range(32):
        flag[k] = vb4[v94[k]] & 0xff

    return flag
```


### Part 3: Cracking the algorithm

Cracking the algorithm is also straightforward as all steps can be inverted. 
[watchmen_crack.py](watchmen_crack.py), applies the reverse algorithm to recover the
flag: `p4{~JusticeIsComingToAllOfUs...}`

Finally we test the flag to make sure that it's valid:
```
C:\Users\ispo\watchmen>watchmen.exe
Once you realize what a joke everything is, being the Comedian is the only thing that makes sense.
p4{~JusticeIsComingToAllOfUs...}
What happened to the American Dream? It came true! You're lookin' at it.

C:\Users\ispo\watchmen>watchmen.exe
Once you realize what a joke everything is, being the Comedian is the only thing that makes sense.
foo
No. Not even in the face of Armageddon. Never compromise
```


### Bonus: Dumping the intermediate state of encryption

To simplify the debugging, I wrote the following function that reads arbitrary data from the
clone:
```python
def debug_remote_read(pid, address, size):
    PROCESS_ALL_ACCESS = 0x1F0FFF
    
    buff   = c_char_p(" "*size)
    buflen = len(buff.value)
    nread  = c_ulong(0)

    # open process
    proc_hdl = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)

    if  windll.kernel32.ReadProcessMemory(proc_hdl, address, buff, buflen, byref(nread)):
        size, data = nread.value, buff.value

    else:
        print 'ReadProcessMemory failed'
        size, data = 0, ""


    windll.kernel32.CloseHandle(proc_hdl)

    return size, data
```

That way, we can check the intermediate state of the flag, while we're debugging it from 
the parent:
```python
# Use process explorer to find process ID
pid = 10100

# at any point of clone's execution you can read the (intermediate) flag
# (set a breakpoint at GetThreadContext to read ebp)
ebp     = 0x28FE68
address = ebp - 0x2a
sz, buf = debug_remote_read(pid, address, 128)

print "Flag:", ['%02x' % ord(b) for b in buf]
```

___