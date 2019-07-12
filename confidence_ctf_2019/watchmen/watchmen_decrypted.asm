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
