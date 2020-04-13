; ---------------- Node 31 at 0x555555559ADC. Next: 3A ----------------
    mov     [rbp+iter_14], 0
    cmp     [rbp+iter_14], 0Fh
    jg      short END_XOR_555555559B66
    mov     eax, [rbp+iter_14]
    movsxd  rdx, eax
    lea     rax, pwd_1_5555557671A0
    movzx   ecx, byte ptr [rdx+rax]     ; ecx = pwd[0]
    mov     eax, [rbp+iter_14]
    movsxd  rdx, eax
    lea     rax, enc_blk_1_5555557671B0
    movzx   eax, byte ptr [rdx+rax]
    xor     ecx, eax                    ; pwd[0:16] ^= enc_blk_1/2[0:16]
    mov     eax, [rbp+iter_14]
    movsxd  rdx, eax
    lea     rax, pwd_1_5555557671A0
    mov     [rdx+rax], cl
    add     [rbp+iter_14], 1
    jmp     short XOR_LOOP_555555559B26
; ---------------- Node 3A at 0x55555555AE98. Next: 3B ----------------
    movzx   eax, byte ptr cs:pwd_1_5555557671A0
    movzx   eax, al
    movzx   edx, byte ptr cs:pwd_1_5555557671A0+1
    movzx   edx, dl
    shl     edx, 8
    or      edx, eax
    movzx   eax, byte ptr cs:pwd_1_5555557671A0+2
    movzx   eax, al
    shl     eax, 10h
    or      edx, eax
    movzx   eax, byte ptr cs:pwd_1_5555557671A0+3
    movzx   eax, al
    shl     eax, 18h
    or      edx, eax                    ; edx = atoi(pwd_1[0:4])
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax]
    xor     eax, edx
    mov     cs:tmp_A_5555557671C0, eax  ; tmp_A = atoi(pwd_1[0:4]) ^ tbl_A[0]
; ---------------- Node 3B at 0x55555555A026. Next: 3 ----------------
    movzx   eax, byte ptr cs:pwd_1_5555557671A0+4
    movzx   eax, al
    movzx   edx, byte ptr cs:pwd_1_5555557671A0+5
    movzx   edx, dl
    shl     edx, 8
    or      edx, eax
    movzx   eax, byte ptr cs:pwd_1_5555557671A0+6
    movzx   eax, al
    shl     eax, 10h
    or      edx, eax
    movzx   eax, byte ptr cs:pwd_1_5555557671A0+7
    movzx   eax, al
    shl     eax, 18h
    or      edx, eax                    ; edx = atoi(pwd[4:8])
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+4]
    xor     eax, edx
    mov     cs:tmp_B_5555557671C4, eax  ; tmp_B = edx = atoi(pwd[4:8]) ^ tbl_A[1]
; ---------------- Node 3 at 0x55555555AFE2. Next: 13 ----------------
    movzx   eax, byte ptr cs:pwd_2_5555557671A8
    movzx   eax, al
    movzx   edx, byte ptr cs:pwd_2_5555557671A8+1
    movzx   edx, dl
    shl     edx, 8
    or      edx, eax
    movzx   eax, byte ptr cs:pwd_2_5555557671A8+2
    movzx   eax, al
    shl     eax, 10h
    or      edx, eax
    movzx   eax, byte ptr cs:pwd_2_5555557671A8+3
    movzx   eax, al
    shl     eax, 18h
    or      edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+8]
    xor     eax, edx
    mov     cs:tmp_C_5555557671C8, eax  ; tmp_C = atoi(pwd_2[0:4]) ^ tbl_A[2]
; ---------------- Node 13 at 0x55555555BC30. Next: 0 ----------------
    movzx   eax, byte ptr cs:pwd_2_5555557671A8+4
    movzx   eax, al
    movzx   edx, byte ptr cs:pwd_2_5555557671A8+5
    movzx   edx, dl
    shl     edx, 8
    or      edx, eax
    movzx   eax, byte ptr cs:pwd_2_5555557671A8+6
    movzx   eax, al
    shl     eax, 10h
    or      edx, eax
    movzx   eax, byte ptr cs:pwd_2_5555557671A8+7
    movzx   eax, al
    shl     eax, 18h
    or      edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+0Ch]
    xor     eax, edx
    mov     cs:tmp_D_5555557671CC, eax  ; tmp_D = atoi(pwd_2[4:8]) ^ tbl_A[3]
; ---------------- Node 0 at 0x55555555A1E6. Next: C ----------------
; ---------------- Node C at 0x55555555BB34. Next: 49 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 40h                    ; sub_A = tbl_A + 0x40
    mov     edx, [rax+rdx*4]            ; edx = sub_A[tmp_A & 0xFF] = sub_A[BYTE_1(tmp_A)]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_A_5555557671C0
    shr     ecx, 8
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h                   ; sub_B = tbl_A + 0x140
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax                    ; ecx = sub_A[tmp_A & 0xFF] ^ sub_B[(tmp_A >> 8) & 0xFF])
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h                   ; sub_C = tbl_A + 0x240
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 340h                   ; sub_D = tbl_A + 0x340
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_E_5555557671D0, eax  ; tmp_E = sub_A[B1(tmp_A)] ^ sub_B[B2(tmp_A)] ^ sub_C[B3(tmp_A)] ^ sub_D[B4(tmp_A)]
; ---------------- Node 49 at 0x55555555D282. Next: 21 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]            ; a = sub_A[B4(tmp_B)]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_B_5555557671C4
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]            ; b = sub_B[B1(tmp_B)]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]            ; c = sub_C[B2(tmp_B)]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]            ; d = sub_D[B3(tmp_B)]
    xor     eax, ecx
    mov     cs:tmp_F_5555557671D4, eax  ; tmp_F = a ^ b ^ c ^ d
; ---------------- Node 21 at 0x55555555A7D2. Next: 19 ----------------
    mov     edx, cs:tmp_E_5555557671D0
    mov     eax, cs:tmp_F_5555557671D4
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+20h]
    add     edx, eax                    ; edx = tmp_E + tmp_F + tbl_A[8]
    mov     eax, cs:tmp_C_5555557671C8
    xor     eax, edx
    mov     cs:tmp_C_5555557671C8, eax  ; tmp_C ^= tmp_E + tmp_F + tbl_A[8]
; ---------------- Node 19 at 0x55555555DD88. Next: 1F ----------------
    mov     eax, cs:tmp_C_5555557671C8
    ror     eax, 1                      ; tmp_C = ror(tmp_C, 1)
    mov     cs:tmp_C_5555557671C8, eax
; ---------------- Node 1F at 0x55555555E1EA. Next: 39 ----------------
    mov     eax, cs:tmp_D_5555557671CC
    rol     eax, 1                      ; tmp_D = rol(tmp_D, 1)
    mov     cs:tmp_D_5555557671CC, eax
; ---------------- Node 39 at 0x55555555C51E. Next: 47 ----------------
    mov     eax, cs:tmp_F_5555557671D4
    lea     edx, [rax+rax]              ; edx = tmp_F * 2 (32 bit)
    mov     eax, cs:tmp_E_5555557671D0
    add     edx, eax                    ; edx = 2*tmp_F + tmp_E (32 bit)
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+24h]
    add     edx, eax
    mov     eax, cs:tmp_D_5555557671CC
    xor     eax, edx
    mov     cs:tmp_D_5555557671CC, eax  ; tmp_D ^= 2*tmp_F + tmp_E + tbl_A[9]
; ---------------- Node 47 at 0x55555555A0EA. Next: 3D ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_C_5555557671C8
    shr     ecx, 8
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_E_5555557671D0, eax
; ---------------- Node 3D at 0x55555555CCC8. Next: A ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_D_5555557671CC
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_F_5555557671D4, eax
; ---------------- Node A at 0x55555555DE9A. Next: 71 ----------------
    mov     edx, cs:tmp_E_5555557671D0
    mov     eax, cs:tmp_F_5555557671D4
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+28h]
    add     edx, eax
    mov     eax, cs:tmp_A_5555557671C0
    xor     eax, edx                    ; tmp_A ^= tmp_E + tmp_F + tbl_A[9]
    mov     cs:tmp_A_5555557671C0, eax
; ---------------- Node 71 at 0x55555555DF3C. Next: 69 ----------------
    mov     eax, cs:tmp_A_5555557671C0
    ror     eax, 1                      ; ror(tmp_A, 1)
    mov     cs:tmp_A_5555557671C0, eax
; ---------------- Node 69 at 0x555555559F14. Next: 63 ----------------
    mov     eax, cs:tmp_B_5555557671C4
    rol     eax, 1                      ; rol(tmp_B, 1)
    mov     cs:tmp_B_5555557671C4, eax
; ---------------- Node 63 at 0x55555555BD7C. Next: 76 ----------------
    mov     eax, cs:tmp_F_5555557671D4
    lea     edx, [rax+rax]
    mov     eax, cs:tmp_E_5555557671D0
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+2Ch]
    add     edx, eax
    mov     eax, cs:tmp_B_5555557671C4
    xor     eax, edx
    mov     cs:tmp_B_5555557671C4, eax
; ---------------- Node 76 at 0x55555555D186. Next: 56 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_A_5555557671C0
    shr     ecx, 8
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_E_5555557671D0, eax
; ---------------- Node 56 at 0x55555555B1F2. Next: 53 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_B_5555557671C4
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_F_5555557671D4, eax
; ---------------- Node 53 at 0x55555555E0C0. Next: 5B ----------------
    mov     edx, cs:tmp_E_5555557671D0
    mov     eax, cs:tmp_F_5555557671D4
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+30h]
    add     edx, eax
    mov     eax, cs:tmp_C_5555557671C8
    xor     eax, edx
    mov     cs:tmp_C_5555557671C8, eax
; ---------------- Node 5B at 0x55555555D056. Next: 1E ----------------
    mov     eax, cs:tmp_C_5555557671C8
    ror     eax, 1
    mov     cs:tmp_C_5555557671C8, eax
; ---------------- Node 1E at 0x55555555E162. Next: 20 ----------------
    mov     eax, cs:tmp_D_5555557671CC
    rol     eax, 1
    mov     cs:tmp_D_5555557671CC, eax
; ---------------- Node 20 at 0x55555555D6FE. Next: 14 ----------------
    mov     eax, cs:tmp_F_5555557671D4
    lea     edx, [rax+rax]
    mov     eax, cs:tmp_E_5555557671D0
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+34h]
    add     edx, eax
    mov     eax, cs:tmp_D_5555557671CC
    xor     eax, edx
    mov     cs:tmp_D_5555557671CC, eax
; ---------------- Node 14 at 0x55555555E38C. Next: 2F ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_C_5555557671C8
    shr     ecx, 8
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_E_5555557671D0, eax
; ---------------- Node 2F at 0x55555555DC8C. Next: 42 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_D_5555557671CC
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_F_5555557671D4, eax
; ---------------- Node 42 at 0x55555555ABB0. Next: 11 ----------------
    mov     edx, cs:tmp_E_5555557671D0
    mov     eax, cs:tmp_F_5555557671D4
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+38h]
    add     edx, eax
    mov     eax, cs:tmp_A_5555557671C0
    xor     eax, edx
    mov     cs:tmp_A_5555557671C0, eax
; ---------------- Node 11 at 0x55555555CB44. Next: 5C ----------------
    mov     eax, cs:tmp_A_5555557671C0
    ror     eax, 1
    mov     cs:tmp_A_5555557671C0, eax
; ---------------- Node 5C at 0x55555555EA52. Next: 37 ----------------
    mov     eax, cs:tmp_B_5555557671C4
    rol     eax, 1
    mov     cs:tmp_B_5555557671C4, eax
; ---------------- Node 37 at 0x55555555A8FC. Next: 1A ----------------
    mov     eax, cs:tmp_F_5555557671D4
    lea     edx, [rax+rax]
    mov     eax, cs:tmp_E_5555557671D0
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+3Ch]
    add     edx, eax
    mov     eax, cs:tmp_B_5555557671C4
    xor     eax, edx
    mov     cs:tmp_B_5555557671C4, eax
; ---------------- Node 1A at 0x555555559B9E. Next: 4C ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_A_5555557671C0
    shr     ecx, 8
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_E_5555557671D0, eax
; ---------------- Node 4C at 0x55555555A9A2. Next: 40 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_B_5555557671C4
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_F_5555557671D4, eax
; ---------------- Node 40 at 0x55555555C75E. Next: 41 ----------------
    mov     edx, cs:tmp_E_5555557671D0
    mov     eax, cs:tmp_F_5555557671D4
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+40h]
    add     edx, eax
    mov     eax, cs:tmp_C_5555557671C8
    xor     eax, edx
    mov     cs:tmp_C_5555557671C8, eax
; ---------------- Node 41 at 0x55555555E488. Next: 58 ----------------
    mov     eax, cs:tmp_C_5555557671C8
    ror     eax, 1
    mov     cs:tmp_C_5555557671C8, eax
; ---------------- Node 58 at 0x55555555BF1E. Next: 15 ----------------
    mov     eax, cs:tmp_D_5555557671CC
    rol     eax, 1
    mov     cs:tmp_D_5555557671CC, eax
; ---------------- Node 15 at 0x55555555A72C. Next: 7B ----------------
    mov     eax, cs:tmp_F_5555557671D4
    lea     edx, [rax+rax]
    mov     eax, cs:tmp_E_5555557671D0
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+44h]
    add     edx, eax
    mov     eax, cs:tmp_D_5555557671CC
    xor     eax, edx
    mov     cs:tmp_D_5555557671CC, eax
; ---------------- Node 7B at 0x55555555DB16. Next: 2A ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_C_5555557671C8
    shr     ecx, 8
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_E_5555557671D0, eax
; ---------------- Node 2A at 0x55555555A5A6. Next: 4 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_D_5555557671CC
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_F_5555557671D4, eax
; ---------------- Node 4 at 0x555555559C9A. Next: 78 ----------------
    mov     edx, cs:tmp_E_5555557671D0
    mov     eax, cs:tmp_F_5555557671D4
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+48h]
    add     edx, eax
    mov     eax, cs:tmp_A_5555557671C0
    xor     eax, edx
    mov     cs:tmp_A_5555557671C0, eax
; ---------------- Node 78 at 0x55555555E598. Next: 7A ----------------
    mov     eax, cs:tmp_A_5555557671C0
    ror     eax, 1
    mov     cs:tmp_A_5555557671C0, eax
; ---------------- Node 7A at 0x55555555B4E6. Next: 50 ----------------
    mov     eax, cs:tmp_B_5555557671C4
    rol     eax, 1
    mov     cs:tmp_B_5555557671C4, eax
; ---------------- Node 50 at 0x55555555D974. Next: 26 ----------------
    mov     eax, cs:tmp_F_5555557671D4
    lea     edx, [rax+rax]
    mov     eax, cs:tmp_E_5555557671D0
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+4Ch]
    add     edx, eax
    mov     eax, cs:tmp_B_5555557671C4
    xor     eax, edx
    mov     cs:tmp_B_5555557671C4, eax
; ---------------- Node 26 at 0x55555555CBCC. Next: 8 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_A_5555557671C0
    shr     ecx, 8
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_E_5555557671D0, eax
; ---------------- Node 8 at 0x55555555B69E. Next: 17 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_B_5555557671C4
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_F_5555557671D4, eax
; ---------------- Node 17 at 0x55555555ADF6. Next: 61 ----------------
    mov     edx, cs:tmp_E_5555557671D0
    mov     eax, cs:tmp_F_5555557671D4
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+50h]
    add     edx, eax
    mov     eax, cs:tmp_C_5555557671C8
    xor     eax, edx
    mov     cs:tmp_C_5555557671C8, eax
; ---------------- Node 61 at 0x55555555C1C8. Next: D ----------------
    mov     eax, cs:tmp_C_5555557671C8
    ror     eax, 1
    mov     cs:tmp_C_5555557671C8, eax
; ---------------- Node D at 0x55555555BAAC. Next: 48 ----------------
    mov     eax, cs:tmp_D_5555557671CC
    rol     eax, 1
    mov     cs:tmp_D_5555557671CC, eax
; ---------------- Node 48 at 0x55555555B14C. Next: 2D ----------------
    mov     eax, cs:tmp_F_5555557671D4
    lea     edx, [rax+rax]
    mov     eax, cs:tmp_E_5555557671D0
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+54h]
    add     edx, eax
    mov     eax, cs:tmp_D_5555557671CC
    xor     eax, edx
    mov     cs:tmp_D_5555557671CC, eax
; ---------------- Node 2D at 0x55555555B2EE. Next: F ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_C_5555557671C8
    shr     ecx, 8
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_E_5555557671D0, eax
; ---------------- Node F at 0x55555555C398. Next: 6E ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_D_5555557671CC
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_F_5555557671D4, eax
; ---------------- Node 6E at 0x55555555C2F6. Next: 54 ----------------
    mov     edx, cs:tmp_E_5555557671D0
    mov     eax, cs:tmp_F_5555557671D4
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+58h]
    add     edx, eax
    mov     eax, cs:tmp_A_5555557671C0
    xor     eax, edx
    mov     cs:tmp_A_5555557671C0, eax
; ---------------- Node 54 at 0x55555555AB28. Next: 24 ----------------
    mov     eax, cs:tmp_A_5555557671C0
    ror     eax, 1
    mov     cs:tmp_A_5555557671C0, eax
; ---------------- Node 24 at 0x55555555D846. Next: 1B ----------------
    mov     eax, cs:tmp_B_5555557671C4
    rol     eax, 1
    mov     cs:tmp_B_5555557671C4, eax
; ---------------- Node 1B at 0x55555555A260. Next: 4E ----------------
    mov     eax, cs:tmp_F_5555557671D4
    lea     edx, [rax+rax]
    mov     eax, cs:tmp_E_5555557671D0
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+5Ch]
    add     edx, eax
    mov     eax, cs:tmp_B_5555557671C4
    xor     eax, edx
    mov     cs:tmp_B_5555557671C4, eax
; ---------------- Node 4E at 0x55555555B79A. Next: 1 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_A_5555557671C0
    shr     ecx, 8
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_E_5555557671D0, eax
; ---------------- Node 1 at 0x55555555DFC4. Next: 23 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_B_5555557671C4
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_F_5555557671D4, eax
; ---------------- Node 23 at 0x55555555D7A4. Next: 3F ----------------
    mov     edx, cs:tmp_E_5555557671D0
    mov     eax, cs:tmp_F_5555557671D4
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+60h]
    add     edx, eax
    mov     eax, cs:tmp_C_5555557671C8
    xor     eax, edx
    mov     cs:tmp_C_5555557671C8, eax
; ---------------- Node 3F at 0x55555555C02E. Next: 66 ----------------
    mov     eax, cs:tmp_C_5555557671C8
    ror     eax, 1
    mov     cs:tmp_C_5555557671C8, eax
; ---------------- Node 66 at 0x55555555E510. Next: 7 ----------------
    mov     eax, cs:tmp_D_5555557671CC
    rol     eax, 1
    mov     cs:tmp_D_5555557671CC, eax
; ---------------- Node 7 at 0x55555555C800. Next: 16 ----------------
    mov     eax, cs:tmp_F_5555557671D4
    lea     edx, [rax+rax]
    mov     eax, cs:tmp_E_5555557671D0
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+64h]
    add     edx, eax
    mov     eax, cs:tmp_D_5555557671CC
    xor     eax, edx
    mov     cs:tmp_D_5555557671CC, eax
; ---------------- Node 16 at 0x55555555DA1A. Next: 3C ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_C_5555557671C8
    shr     ecx, 8
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_E_5555557671D0, eax
; ---------------- Node 3C at 0x55555555ACFA. Next: E ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_D_5555557671CC
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_F_5555557671D4, eax
; ---------------- Node E at 0x55555555E818. Next: 6C ----------------
    mov     edx, cs:tmp_E_5555557671D0
    mov     eax, cs:tmp_F_5555557671D4
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+68h]
    add     edx, eax
    mov     eax, cs:tmp_A_5555557671C0
    xor     eax, edx
    mov     cs:tmp_A_5555557671C0, eax
; ---------------- Node 6C at 0x55555555E304. Next: 38 ----------------
    mov     eax, cs:tmp_A_5555557671C0
    ror     eax, 1
    mov     cs:tmp_A_5555557671C0, eax
; ---------------- Node 38 at 0x55555555E942. Next: 64 ----------------
    mov     eax, cs:tmp_B_5555557671C4
    rol     eax, 1
    mov     cs:tmp_B_5555557671C4, eax
; ---------------- Node 64 at 0x55555555D8CE. Next: 35 ----------------
    mov     eax, cs:tmp_F_5555557671D4
    lea     edx, [rax+rax]
    mov     eax, cs:tmp_E_5555557671D0
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+6Ch]
    add     edx, eax
    mov     eax, cs:tmp_B_5555557671C4
    xor     eax, edx
    mov     cs:tmp_B_5555557671C4, eax
; ---------------- Node 35 at 0x55555555CDC4. Next: 32 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_A_5555557671C0
    shr     ecx, 8
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_E_5555557671D0, eax
; ---------------- Node 32 at 0x55555555E71C. Next: 10 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_B_5555557671C4
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_F_5555557671D4, eax
; ---------------- Node 10 at 0x55555555D550. Next: 5E ----------------
    mov     edx, cs:tmp_E_5555557671D0
    mov     eax, cs:tmp_F_5555557671D4
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+70h]
    add     edx, eax
    mov     eax, cs:tmp_C_5555557671C8
    xor     eax, edx
    mov     cs:tmp_C_5555557671C8, eax
; ---------------- Node 5E at 0x55555555BFA6. Next: 74 ----------------
    mov     eax, cs:tmp_C_5555557671C8
    ror     eax, 1
    mov     cs:tmp_C_5555557671C8, eax
; ---------------- Node 74 at 0x55555555C6D6. Next: 5D ----------------
    mov     eax, cs:tmp_D_5555557671CC
    rol     eax, 1
    mov     cs:tmp_D_5555557671CC, eax
; ---------------- Node 5D at 0x55555555D4AA. Next: 45 ----------------
    mov     eax, cs:tmp_F_5555557671D4
    lea     edx, [rax+rax]
    mov     eax, cs:tmp_E_5555557671D0
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+74h]
    add     edx, eax
    mov     eax, cs:tmp_D_5555557671CC
    xor     eax, edx
    mov     cs:tmp_D_5555557671CC, eax
; ---------------- Node 45 at 0x55555555EBD6. Next: 25 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_C_5555557671C8
    shr     ecx, 8
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_E_5555557671D0, eax
; ---------------- Node 25 at 0x55555555B3EA. Next: 44 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_D_5555557671CC
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_F_5555557671D4, eax
; ---------------- Node 44 at 0x55555555D408. Next: 43 ----------------
    mov     edx, cs:tmp_E_5555557671D0
    mov     eax, cs:tmp_F_5555557671D4
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+78h]
    add     edx, eax
    mov     eax, cs:tmp_A_5555557671C0
    xor     eax, edx
    mov     cs:tmp_A_5555557671C0, eax
; ---------------- Node 43 at 0x55555555BA24. Next: 34 ----------------
    mov     eax, cs:tmp_A_5555557671C0
    ror     eax, 1
    mov     cs:tmp_A_5555557671C0, eax
; ---------------- Node 34 at 0x55555555C0B6. Next: 4A ----------------
    mov     eax, cs:tmp_B_5555557671C4
    rol     eax, 1
    mov     cs:tmp_B_5555557671C4, eax
; ---------------- Node 4A at 0x55555555C9A2. Next: 6F ----------------
    mov     eax, cs:tmp_F_5555557671D4
    lea     edx, [rax+rax]
    mov     eax, cs:tmp_E_5555557671D0
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+7Ch]
    add     edx, eax
    mov     eax, cs:tmp_B_5555557671C4
    xor     eax, edx
    mov     cs:tmp_B_5555557671C4, eax
; ---------------- Node 6F at 0x55555555EADA. Next: 4D ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_A_5555557671C0
    shr     ecx, 8
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_E_5555557671D0, eax
; ---------------- Node 4D at 0x55555555CA48. Next: 28 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_B_5555557671C4
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_F_5555557671D4, eax
; ---------------- Node 28 at 0x55555555C250. Next: 12 ----------------
    mov     edx, cs:tmp_E_5555557671D0
    mov     eax, cs:tmp_F_5555557671D4
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+80h]
    add     edx, eax
    mov     eax, cs:tmp_C_5555557671C8
    xor     eax, edx
    mov     cs:tmp_C_5555557671C8, eax
; ---------------- Node 12 at 0x55555555A422. Next: 4B ----------------
    mov     eax, cs:tmp_C_5555557671C8
    ror     eax, 1
    mov     cs:tmp_C_5555557671C8, eax
; ---------------- Node 4B at 0x55555555C64E. Next: 65 ----------------
    mov     eax, cs:tmp_D_5555557671CC
    rol     eax, 1
    mov     cs:tmp_D_5555557671CC, eax
; ---------------- Node 65 at 0x55555555D0DE. Next: 6B ----------------
    mov     eax, cs:tmp_F_5555557671D4
    lea     edx, [rax+rax]
    mov     eax, cs:tmp_E_5555557671D0
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+84h]
    add     edx, eax
    mov     eax, cs:tmp_D_5555557671CC
    xor     eax, edx
    mov     cs:tmp_D_5555557671CC, eax
; ---------------- Node 6B at 0x55555555981E. Next: 2E ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_C_5555557671C8
    shr     ecx, 8
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_E_5555557671D0, eax
; ---------------- Node 2E at 0x55555555BE22. Next: 30 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_D_5555557671CC
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_F_5555557671D4, eax
; ---------------- Node 30 at 0x555555559A36. Next: 77 ----------------
    mov     edx, cs:tmp_E_5555557671D0
    mov     eax, cs:tmp_F_5555557671D4
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+88h]
    add     edx, eax
    mov     eax, cs:tmp_A_5555557671C0
    xor     eax, edx
    mov     cs:tmp_A_5555557671C0, eax
; ---------------- Node 77 at 0x55555555B56E. Next: 62 ----------------
    mov     eax, cs:tmp_A_5555557671C0
    ror     eax, 1
    mov     cs:tmp_A_5555557671C0, eax
; ---------------- Node 62 at 0x55555555E9CA. Next: 59 ----------------
    mov     eax, cs:tmp_B_5555557671C4
    rol     eax, 1
    mov     cs:tmp_B_5555557671C4, eax
; ---------------- Node 59 at 0x55555555B5F6. Next: 2 ----------------
    mov     eax, cs:tmp_F_5555557671D4
    lea     edx, [rax+rax]
    mov     eax, cs:tmp_E_5555557671D0
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+8Ch]
    add     edx, eax
    mov     eax, cs:tmp_B_5555557671C4
    xor     eax, edx
    mov     cs:tmp_B_5555557671C4, eax
; ---------------- Node 2 at 0x55555555E620. Next: 6D ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_A_5555557671C0
    shr     ecx, 8
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_A_5555557671C0
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_E_5555557671D0, eax
; ---------------- Node 6D at 0x55555555B928. Next: 73 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_B_5555557671C4
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_B_5555557671C4
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_F_5555557671D4, eax
; ---------------- Node 73 at 0x555555559DE4. Next: 60 ----------------
    mov     edx, cs:tmp_E_5555557671D0
    mov     eax, cs:tmp_F_5555557671D4
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+90h]
    add     edx, eax
    mov     eax, cs:tmp_C_5555557671C8
    xor     eax, edx
    mov     cs:tmp_C_5555557671C8, eax
; ---------------- Node 60 at 0x55555555A874. Next: 3E ----------------
    mov     eax, cs:tmp_C_5555557671C8
    ror     eax, 1
    mov     cs:tmp_C_5555557671C8, eax
; ---------------- Node 3E at 0x55555555AF5A. Next: 9 ----------------
    mov     eax, cs:tmp_D_5555557671CC
    rol     eax, 1
    mov     cs:tmp_D_5555557671CC, eax
; ---------------- Node 9 at 0x55555555AC52. Next: 70 ----------------
    mov     eax, cs:tmp_F_5555557671D4
    lea     edx, [rax+rax]
    mov     eax, cs:tmp_E_5555557671D0
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+94h]
    add     edx, eax
    mov     eax, cs:tmp_D_5555557671CC
    xor     eax, edx
    mov     cs:tmp_D_5555557671CC, eax
; ---------------- Node 70 at 0x55555555A4AA. Next: 6A ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_C_5555557671C8
    shr     ecx, 8
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_C_5555557671C8
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_E_5555557671D0, eax
; ---------------- Node 6A at 0x55555555C8A6. Next: 75 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 18h
    mov     edx, edx
    add     rdx, 40h
    mov     edx, [rax+rdx*4]
    mov     rax, cs:tbl_A_555555767150
    mov     ecx, cs:tmp_D_5555557671CC
    movzx   ecx, cl
    mov     ecx, ecx
    add     rcx, 140h
    mov     eax, [rax+rcx*4]
    mov     ecx, edx
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 8
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 240h
    mov     eax, [rax+rdx*4]
    xor     ecx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     edx, cs:tmp_D_5555557671CC
    shr     edx, 10h
    movzx   edx, dl
    mov     edx, edx
    add     rdx, 340h
    mov     eax, [rax+rdx*4]
    xor     eax, ecx
    mov     cs:tmp_F_5555557671D4, eax
; ---------------- Node 75 at 0x55555555B0A6. Next: 27 ----------------
    mov     edx, cs:tmp_E_5555557671D0
    mov     eax, cs:tmp_F_5555557671D4
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+98h]
    add     edx, eax
    mov     eax, cs:tmp_A_5555557671C0
    xor     eax, edx
    mov     cs:tmp_A_5555557671C0, eax
; ---------------- Node 27 at 0x55555555BCF4. Next: 72 ----------------
    mov     eax, cs:tmp_A_5555557671C0
    ror     eax, 1
    mov     cs:tmp_A_5555557671C0, eax
; ---------------- Node 72 at 0x55555555E8BA. Next: 55 ----------------
    mov     eax, cs:tmp_B_5555557671C4
    rol     eax, 1
    mov     cs:tmp_B_5555557671C4, eax
; ---------------- Node 55 at 0x555555559D3C. Next: 67 ----------------
    mov     eax, cs:tmp_F_5555557671D4
    lea     edx, [rax+rax]
    mov     eax, cs:tmp_E_5555557671D0
    add     edx, eax
    mov     rax, cs:tbl_A_555555767150
    mov     eax, [rax+9Ch]
    add     edx, eax
    mov     eax, cs:tmp_B_5555557671C4
    xor     eax, edx
    mov     cs:tmp_B_5555557671C4, eax
; ---------------- Node 67 at 0x55555555DC12. Next: 36 ----------------
; ---------------- Node 36 at 0x55555555A306. Next: 2C ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, [rax+10h]
    mov     eax, cs:tmp_C_5555557671C8
    xor     eax, edx
    mov     cs:tmp_C_5555557671C8, eax  ; tmp_C ^= tbl_A[4]
; ---------------- Node 2C at 0x55555555991A. Next: 68 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, [rax+14h]
    mov     eax, cs:tmp_D_5555557671CC
    xor     eax, edx
    mov     cs:tmp_D_5555557671CC, eax  ; tmp_D ^= tbl_A[5]
; ---------------- Node 68 at 0x55555555E272. Next: 4F ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, [rax+18h]
    mov     eax, cs:tmp_A_5555557671C0
    xor     eax, edx
    mov     cs:tmp_A_5555557671C0, eax  ; tmp_A ^= tbl_A[6]
; ---------------- Node 4F at 0x55555555B896. Next: 57 ----------------
    mov     rax, cs:tbl_A_555555767150
    mov     edx, [rax+1Ch]
    mov     eax, cs:tmp_B_5555557671C4
    xor     eax, edx
    mov     cs:tmp_B_5555557671C4, eax  ; tmp_B ^= tbl_A[7]
; ---------------- Node 57 at 0x55555555D5F2. Next: 22 ----------------
    mov     eax, cs:tmp_C_5555557671C8
    mov     byte ptr cs:enc_blk_1_5555557671B0, al
; ---------------- Node 22 at 0x555555559F9C. Next: 52 ----------------
    mov     eax, cs:tmp_C_5555557671C8
    shr     eax, 8
    mov     byte ptr cs:enc_blk_1_5555557671B0+1, al
; ---------------- Node 52 at 0x55555555DE10. Next: 51 ----------------
    mov     eax, cs:tmp_C_5555557671C8
    shr     eax, 10h
    mov     byte ptr cs:enc_blk_1_5555557671B0+2, al
; ---------------- Node 51 at 0x55555555AA9E. Next: 2B ----------------
    mov     eax, cs:tmp_C_5555557671C8
    shr     eax, 18h
    mov     byte ptr cs:enc_blk_1_5555557671B0+3, al
; ---------------- Node 2B at 0x55555555CFD0. Next: 5A ----------------
    mov     eax, cs:tmp_D_5555557671CC
    mov     byte ptr cs:enc_blk_1_5555557671B0+4, al
; ---------------- Node 5A at 0x555555559E8A. Next: 79 ----------------
    mov     eax, cs:tmp_D_5555557671CC
    shr     eax, 8
    mov     byte ptr cs:enc_blk_1_5555557671B0+5, al
; ---------------- Node 79 at 0x55555555D37E. Next: 29 ----------------
    mov     eax, cs:tmp_D_5555557671CC
    shr     eax, 10h
    mov     byte ptr cs:enc_blk_1_5555557671B0+6, al
; ---------------- Node 29 at 0x55555555A6A2. Next: 5 ----------------
    mov     eax, cs:tmp_D_5555557671CC
    shr     eax, 18h
    mov     byte ptr cs:enc_blk_1_5555557671B0+7, al
; ---------------- Node 5 at 0x55555555D678. Next: 33 ----------------
    mov     eax, cs:tmp_A_5555557671C0
    mov     byte ptr cs:enc_blk_2_5555557671B8, al
; ---------------- Node 33 at 0x55555555C13E. Next: 6 ----------------
    mov     eax, cs:tmp_A_5555557671C0
    shr     eax, 8
    mov     byte ptr cs:enc_blk_2_5555557671B8+1, al
; ---------------- Node 6 at 0x55555555C494. Next: 5F ----------------
    mov     eax, cs:tmp_A_5555557671C0
    shr     eax, 10h
    mov     byte ptr cs:enc_blk_2_5555557671B8+2, al
; ---------------- Node 5F at 0x5555555599AC. Next: 46 ----------------
    mov     eax, cs:tmp_A_5555557671C0
    shr     eax, 18h
    mov     byte ptr cs:enc_blk_2_5555557671B8+3, al
; ---------------- Node 46 at 0x55555555CF4A. Next: 18 ----------------
    mov     eax, cs:tmp_B_5555557671C4
    mov     byte ptr cs:enc_blk_2_5555557671B8+4, al
; ---------------- Node 18 at 0x55555555C5C4. Next: B ----------------
    mov     eax, cs:tmp_B_5555557671C4
    shr     eax, 8
    mov     byte ptr cs:enc_blk_2_5555557671B8+5, al
; ---------------- Node B at 0x55555555A398. Next: 1C ----------------
    mov     eax, cs:tmp_B_5555557671C4
    shr     eax, 10h
    mov     byte ptr cs:enc_blk_2_5555557671B8+6, al
; ---------------- Node 1C at 0x55555555CEC0. Next: 1D ----------------
    mov     eax, cs:tmp_B_5555557671C4
    shr     eax, 18h
    mov     byte ptr cs:enc_blk_2_5555557671B8+7, al
