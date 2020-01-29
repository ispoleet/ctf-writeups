
; --------------------------------------------------------------------------------------------------
; Function A: Print a string
; --------------------------------------------------------------------------------------------------
0x04006000: 79 01 fc 0f         MOVREL R1, 0x0ffc       ; R1 = 0x04006000+4 + 0xffc = 0x4007000
0x04006004: 20 91               MOVqw R1, @R1           ; R1 = *0x4007000 (8 bytes) = SystemTable
0x04006006: 72 91 85 21         MOVnw R1, @R1 (+5, +24) ; R1 = *(R1 +5*8 +24) = SystemTable.ConOut
0x0400600a: b5 08 10 00         PUSHn @R0 (+0, +16)     ; R0 + 16 (=arg0) on stack
0x0400600e: 35 01               PUSHn R1                ; 
0x04006010: 83 29 01 00 00 10   CALLEXa @R1 (+1, +0)    ; SystemTable.ConOut->OutputString(arg0)
0x04006016: 60 00 02 10         MOVqw R0, R0 (+2, +0)   ; R0 = R0 + 2*8 --> (pop arg from stack)
0x0400601a: 04 00               RET                     ; return value on R7

; --------------------------------------------------------------------------------------------------
; Function B: Decoy. We don't know and we don't care what it does
; --------------------------------------------------------------------------------------------------
0x0400601c: 56 66               XOR R6, R6              ;
0x0400601e: 20 63               MOVqw R3, R6			;
0x04006020: 4a 64               NOT R4, R6				;
0x04006022: 79 07 2a 10         MOVREL R7, 0x102a		;
0x04006026: 6b 07               PUSH R7					;
0x04006028: 60 81 18 00         MOVqw R1, @R0 (+0, +24)	;
0x0400602c: 02 0a               JMP8 0x0a				;
0x0400602e: 56 66               XOR R6, R6				;
0x04006030: 77 33 08 00         MOVIqw R3, 0x0008		;
0x04006034: 0a 64               NOT R4, R6				;
0x04006036: 79 07 fc 0f         MOVREL R7, 0x0ffc		;
0x0400603a: 6b 07               PUSH R7					;
0x0400603c: 60 81 18 00         MOVqw R1, @R0 (+0, +24)	;
0x04006040: 54 41               AND R1, R4				;
0x04006042: 6b 01               PUSH R1					;
0x04006044: cc 67 04 00         ADD R7, R6 (0x0004)		;
0x04006048: 79 05 ca 0f         MOVREL R5, 0x0fca		;
0x0400604c: 20 81               MOVqw R1, @R0			;
0x0400604e: 77 32 04 00         MOVIqw R2, 0x0004		;
0x04006052: ce 32 f1 ff         MUL R2, R3 (0xfff1)		;
0x04006056: 4b 22               NEG R2, R2				;
0x04006058: 58 21               SHR R1, R2				;
0x0400605a: 4c 11               ADD R1, R1				;
0x0400605c: 6b 05               PUSH R5					;
0x0400605e: 4c 15               ADD R5, R1				;
0x04006060: 1e df               MOVww @R7, @R5			;
0x04006062: cc 67 02 00         ADD R7, R6 (0x0002)		;
0x04006066: 6c 05               POP R5					;
0x04006068: d8 64 04 00         SHR R4, R6 (0x0004)		;
0x0400606c: 54 48               AND @R0, R4				; 
0x0400606e: cc 63 01 00         ADD R3, R6 (0x0001)		;
0x04006072: 6f 03 10 00         CMPIgte R3, (0x0010)	;
0x04006076: 82 ea               JMP8cc 0xea				;
0x04006078: 6c 01               POP R1					;
0x0400607a: 83 10 80 ff ff ff   CALL R0 (0xffffff80)	;
0x04006080: 6c 01               POP R1					;
0x04006082: 04 00               RET						;

; --------------------------------------------------------------------------------------------------
; Function C: Read a single key stroke from console input and store it at 0x04007010
; --------------------------------------------------------------------------------------------------
0x04006084: 79 01 78 0f         MOVREL R1, 0x0f78       ; R1 = 0x04006088 + 0x0f78 = 0x04007000
0x04006088: 20 91               MOVqw R1, @R1           ; R1 = *0x04007000 = SystemTable
0x0400608a: 72 91 63 10         MOVnw R1, @R1 (+3, +24) ; R1 = SystemTable.ConIn
0x0400608e: 77 32 00 00         MOVIqw R2, 0x0000       ; R2 = 0
0x04006092: 35 02               PUSHn R2                ; arg2: no diagnostics
0x04006094: 35 01               PUSHn R1                ; arg1: SystemTable.ConIn
0x04006096: 03 29               CALLEXa @R1             ; SystemTable.Reset(SystemTable.ConIn, 0)
0x04006098: 36 01               POPn R1                 ; (Reset the input device)
0x0400609a: 36 02               POPn R2                 ; (R1-R3 are preserved)

0x0400609c: 79 03 60 0f M       MOVREL R3, 0x0f60       ; R3 = 0x4007000
0x040060a0: 20 b3               MOVqw R3, @R3           ; R3 = *0x4007000 = SystemTable
0x040060a2: 72 b3 89 21         MOVnw R3, @R3 (+9, +24) ; R3 = SystemTable.BootServices
0x040060a6: 79 02 5e 0f         MOVREL R2, 0x0f5e       ; R2 = 0x040060aa + 0x0f5e = 0x04007008
0x040060aa: 35 02               PUSHn R2                ; arg3: 0x04007008 (Index)
0x040060ac: 60 11 02 10         MOVqw R1, R1 (+2, +0)   ; R1 = R1 +2*8 = SystemTable.ConOut (?)
0x040060b0: 35 01               PUSHn R1                ; arg2: SystemTable.ConOut (Event)
0x040060b2: 77 31 01 00         MOVIqw R1, 0x0001       ;
0x040060b6: 35 01               PUSHn R1                ; arg1: 1 (NumberOfEvents)
0x040060b8: 83 2b 89 01 00 10   CALLEXa @R3 (+9, +24)   ; SystemTable.BootServices->WaitForEvent()
0x040060be: 60 00 03 10         MOVqw R0, R0 (+3, +0)   ; pop 3 args from stack

; wait till a keystroke is pressed

0x040060c2: 79 01 3a 0f         MOVREL R1, 0x0f3a       ; R1 = 0x040060c6 + 0x0f3a = 0x04007000
0x040060c6: 20 91               MOVqw R1, @R1           ; R1 = *0x04007000 = SystemTable
0x040060c8: 72 91 63 10         MOVnw R1, @R1 (+3, +24) ; R1 = SystemTable.ConIn
0x040060cc: 79 02 40 0f         MOVREL R2, 0x0f40       ; R2 = 0x040060d0 + 0x0f40 = 0x04007010
0x040060d0: 35 02               PUSHn R2                ; 
0x040060d2: 35 01               PUSHn R1                ;
0x040060d4: 83 29 01 00 00 10   CALLEXa @R1 (+1, +0)    ; SystemTable.ConIn->ReadKeyStroke(SystemTable.ConIn, 0x04007010)
0x040060da: 36 01               POPn R1                 ; pop args
0x040060dc: 36 02               POPn R2                 ;
0x040060de: 04 00               RET                     ;

; --------------------------------------------------------------------------------------------------
; Function D: Read keystokes in a loop (with echo)
; --------------------------------------------------------------------------------------------------
0x040060e0: 77 33 00 00         MOVIqw R3, 0x0000       ; R3 = 0 = i
0x040060e4: 77 34 20 00         MOVIqw R4, 0x0020       ; R4 = 32

0x040060e8: 6b 03               PUSH R3                 ;
0x040060ea: 6b 04               PUSH R4                 ; (these are not args; just preserve regs)
0x040060ec: 83 10 92 ff ff ff   CALL R0 (0xffffff92)    ; func_C()
0x040060f2: 6c 04               POP R4                  ;
0x040060f4: 6c 03               POP R3                  ; 
0x040060f6: 79 01 18 0f         MOVREL R1, 0x0f18       ; R1 = 0x040060fa + 0x0f18 = 0x04007012 (?)
0x040060fa: 6b 01               PUSH R1                 ;
0x040060fc: 83 10 fe fe ff ff   CALL R0 (0xfffffefe)    ; func_A(0x04007012) (echo key back)
0x04006102: 6c 01               POP R1                  ;
0x04006104: 79 01 0a 0f         MOVREL R1, 0x0f0a       ; R1 = 0x04006108 + 0x0f0a = 0x04007012
0x04006108: 79 02 76 0f         MOVREL R2, 0x0f76       ; R2 = 0x0400610c + 0x0f76 = 0x04007082
0x0400610c: 4c 32               ADD R2, R3              ; R2 += i
0x0400610e: 1d 9a               MOVbw @R2, @R1          ; *(0x04007082 + i) = *0x04007012 (move char)
0x04006110: 77 31 01 00         MOVIqw R1, 0x0001       ; R1 = 1
0x04006114: 4c 13               ADD R3, R1              ; ++R3
0x04006116: 45 43               CMPeq R3, R4            ; R3 == R4 (32) ?
0x04006118: 82 e7               JMP8cc 0xe7             ; jump to 0x040060e8 if CMP was false (cc)
0x0400611a: 04 00               RET                     ;

; --------------------------------------------------------------------------------------------------
; efi_main():
;
; (R0 points to the top of the stack (SP))
; 	IN EFI_HANDLE ImageHandle,
; 	IN EFI_SYSTEM_TABLE * SystemTable
; --------------------------------------------------------------------------------------------------
0x0400611c: 79 01 e0 0e         MOVREL R1, 0x0ee0       ; R1 = 0x0400611c+4 + 0x0ee0 = 0x04007000
0x04006120: 72 89 41 10         MOVnw @R1, @R0 (+1, +16); *0x04007000 = *(SP +1*8 +16) = EFI_SYSTEM_TABLE
0x04006124: 79 01 d8 0f         MOVREL R1, 0x0fd8       ; R1 = 0x04006128 + 0x0fd8 = 0x04007100
0x04006128: 6b 01               PUSH R1                 ; arg1: 0x04007100 = & "Key:"
0x0400612a: 83 10 d0 fe ff ff   CALL R0 (0xfffffed0)    ; func_A("Key: ") (cdelc)
														; (register operand in call always ignored)
0x04006130: 6c 01               POP R1                  ; -
0x04006132: 83 10 a8 ff ff ff   CALL R0 (0xffffffa8)    ; func_D() read with echo
0x04006138: 79 01 be 0f         MOVREL R1, 0x0fbe       ; R1 = 0x0400613c + 0x0fbe = 0x04070fc
0x0400613c: 6b 01               PUSH R1                 ; arg1: 0x04070fc = "\r\n"
0x0400613e: 83 10 bc fe ff ff   CALL R0 (0xfffffebc)    ; func_A("\r\n")
0x04006144: 6c 01               POP R1                  ;

; -----------------------------------------------------------------------------
; Decrypt payload stage 1
;
; XOR-decode of payload at 0x04007114. Size is 0x2c0.
; Write results to 0x04006354 an call it
; -----------------------------------------------------------------------------
0x04006146: 79 02 ca 0f         MOVREL R2, 0x0fca       ; R2 = 0x0400614a + 0x0fca = 0x04007114 = A
0x0400614a: 79 03 06 02         MOVREL R3, 0x0206       ; R3 = 0x0400614e + 0x0206 = 0x04006354 = CODE
0x0400614e: 79 04 ba 0f         MOVREL R4, 0x0fba       ; R4 = 0x04006152 + 0x0fba = 0x0400710c
0x04006152: 20 c4               MOVqw R4, @R4           ; R4 = *0x0400710c = 0x2c0 = len(A)
0x04006154: 77 35 00 00         MOVIqw R5, 0x0000       ; R5 = 0
0x04006158: 79 06 1e 0f         MOVREL R6, 0x0f1e       ; R6 = 0x0400615c + 0x0f1e = 0x0400707A = xor-key
0x0400615c: 1f e6               MOVdw R6, @R6           ; R6 = *0x0400707A = 0x06D35BCD

0x0400615e: 1f a1               MOVdw R1, @R2           ; R1 = *(0x04007114 + i) = c
0x04006160: 16 61               XOR R1, R6              ; R1 = 0x16D1DAAD ^ 0x06D35BCD = 0x10028160
0x04006162: 1f 1b               MOVdw @R3, R1           ; CODE[i] = c ^ key
0x04006164: 77 31 04 00         MOVIqw R1, 0x0004       ; R1 = 4 (next DWORD)
0x04006168: 4c 12               ADD R2, R1              ; R2 += 4
0x0400616a: 4c 13               ADD R3, R1              ; R3 += 4
0x0400616c: 4c 15               ADD R5, R1              ; R5 += 4
0x0400616e: 45 54               CMPeq R4, R5            ; 
0x04006170: 82 f6               JMP8cc 0xf6             ; jump to 0x04006172 - ~(0xf6+1)*2 = 0x0400615e

0x04006172: 79 01 0c 0f         MOVREL R1, 0x0f0c       ; R1 = 0x04006176 + 0x0f0c = 0x04007082
0x04006176: 20 91               MOVqw R1, @R1           ; R1 = *0x04007082 
0x04006178: 6b 01               PUSH R1                 ; arg1: first part of the key
0x0400617a: 83 10 d4 01 00 00   CALL R0 (0x000001d4)    ; call payload (0x04006354)
0x04006180: 6c 01               POP R1                  ;
0x04006182: 77 31 01 00         MOVIqw R1, 0x0001       ; R1 = 1
0x04006186: 45 71               CMPeq R1, R7            ; 1 == return value ?
0x04006188: 81 90 c4 01 00 00   JMPcc R0 (0x000001c4)   ; if not goto to (0x0400618e +0x01c4 =RET)

; -----------------------------------------------------------------------------
; Now, update XOR key
;
; xor-key = CRC32(first 8 characters from the key)
; -----------------------------------------------------------------------------
0x0400618e: 79 03 6e 0e         MOVREL R3, 0x0e6e       ; R3 = 0x04006192 + 0x0e6e = 0x04007000
0x04006192: 20 b3               MOVqw R3, @R3           ; R3 = *0x4007000 = SystemTable
0x04006194: 72 b3 89 21         MOVnw R3, @R3 (+9, +24) ; R3 = SystemTable.BootServices
0x04006198: 79 01 de 0e         MOVREL R1, 0x0ede       ; R1 = 0x0400619c + 0x0ede = 0x0400707a
0x0400619c: 35 01               PUSHn R1                ; arg3: 0x0400707a (Crc32 OUT)
0x0400619e: 77 31 08 00         MOVIqw R1, 0x0008       ; 
0x040061a2: 35 01               PUSHn R1                ; arg2: 8 (data size)
0x040061a4: 79 01 da 0e         MOVREL R1, 0x0eda       ; R1 = 0x040061a8 + 0x0eda = 0x04007082
0x040061a8: 35 01               PUSHn R1                ; arg1: 0x04007082 = first characters from key
0x040061aa: 83 2b 28 18 00 20   CALLEXa @R3 (+40, +24)  ; SystemTable.BootServices->CalculateCrc32()
0x040061b0: 60 00 03 10         MOVqw R0, R0 (+3, +0)   ;

; -----------------------------------------------------------------------------
; Decrypt payload stage 2
;
; The exact same process with stage 1. But:
; Encoded payload at: 0x040073dc with size 0x760
; -----------------------------------------------------------------------------
0x040061b4: 79 02 24 12         MOVREL R2, 0x1224       ; R2 = 0x040061b8 + 0x1224 = 0x040073dc = B
0x040061b8: 79 03 98 01         MOVREL R3, 0x0198       ; R3 = 0x040061bc + 0x0198 = 0x04006354
0x040061bc: 79 04 14 12         MOVREL R4, 0x1214       ; R4 = 0x040061c0 + 0x1214 = 0x040073d4
0x040061c0: 20 c4               MOVqw R4, @R4           ; R4 = *0x040073d4 = 0x760 = len(B)
0x040061c2: 77 35 00 00         MOVIqw R5, 0x0000       ; 
0x040061c6: 79 06 b0 0e         MOVREL R6, 0x0eb0       ;
0x040061ca: 1f e6               MOVdw R6, @R6           ;

0x040061cc: 1f a1               MOVdw R1, @R2           ;
0x040061ce: 16 61               XOR R1, R6              ;
0x040061d0: 1f 1b               MOVdw @R3, R1           ;
0x040061d2: 77 31 04 00         MOVIqw R1, 0x0004       ;
0x040061d6: 4c 12               ADD R2, R1              ; 
0x040061d8: 4c 13               ADD R3, R1              ;
0x040061da: 4c 15               ADD R5, R1              ;
0x040061dc: 45 54               CMPeq R4, R5            ;
0x040061de: 82 f6               JMP8cc 0xf6             ;

0x040061e0: 79 01 a6 0e         MOVREL R1, 0x0ea6       ; R1 = 0x040061e4 + 0x0ea6 = 0x0400708a
0x040061e4: 20 91               MOVqw R1, @R1           ; R1 = *(0x04007082 + 8) = key[8:]
0x040061e6: 6b 01               PUSH R1                 ;
0x040061e8: 83 10 66 01 00 00   CALL R0 (0x00000166)    ; call payload (0x04006354)
0x040061ee: 6c 01               POP R1                  ;

0x040061f0: 77 31 01 00         MOVIqw R1, 0x0001       ; update xor-key
0x040061f4: 45 71               CMPeq R1, R7            ;
0x040061f6: 81 90 56 01 00 00   JMPcc R0 (0x00000156)   ;
0x040061fc: 79 03 00 0e         MOVREL R3, 0x0e00       ;
0x04006200: 20 b3               MOVqw R3, @R3           ;
0x04006202: 72 b3 89 21         MOVnw R3, @R3 (+9, +24) ;
0x04006206: 79 01 70 0e         MOVREL R1, 0x0e70       ;
0x0400620a: 35 01               PUSHn R1                ; 
0x0400620c: 77 31 08 00         MOVIqw R1, 0x0008       ;
0x04006210: 35 01               PUSHn R1                ;
0x04006212: 79 01 74 0e         MOVREL R1, 0x0e74       ;
0x04006216: 35 01               PUSHn R1                ;
0x04006218: 83 2b 28 18 00 20   CALLEXa @R3 (+40, +24)  ;
0x0400621e: 60 00 03 10         MOVqw R0, R0 (+3, +0)   ;

; -----------------------------------------------------------------------------
; Decrypt payload stage 3
;
; The exact same process with stages 1 and 2. But:
; Encoded payload at: 0x04007b44 with size 0x830
; -----------------------------------------------------------------------------
0x04006222: 79 02 1e 19         MOVREL R2, 0x191e       ; R2 = 0x04006226 + 0x191e = 0x04007b44 = C
0x04006226: 79 03 2a 01         MOVREL R3, 0x012a       ; R3 = 0x0400622a + 0x012a = 0x04006354
0x0400622a: 79 04 0e 19         MOVREL R4, 0x190e       ; R4 = 0x0400622e + 0x190e = 0x04007b3c
0x0400622e: 20 c4               MOVqw R4, @R4           ; R4 = *0x04007b3c = 0x830 = len(C)
0x04006230: 77 35 00 00         MOVIqw R5, 0x0000       ; R5 = 0
0x04006234: 79 06 42 0e         MOVREL R6, 0x0e42       ; R6 = 0x04006238 + 0x0e42 = 0x0400707a
0x04006238: 1f e6               MOVdw R6, @R6           ; R6 = *0x0400707a = 0x6D35BCD

0x0400623a: 1f a1               MOVdw R1, @R2           ;
0x0400623c: 16 61               XOR R1, R6              ;
0x0400623e: 1f 1b               MOVdw @R3, R1           ;
0x04006240: 77 31 04 00         MOVIqw R1, 0x0004       ;
0x04006244: 4c 12               ADD R2, R1              ;
0x04006246: 4c 13               ADD R3, R1              ;
0x04006248: 4c 15               ADD R5, R1              ;
0x0400624a: 45 54               CMPeq R4, R5            ;
0x0400624c: 82 f6               JMP8cc 0xf6             ;

0x0400624e: 79 01 40 0e         MOVREL R1, 0x0e40       ;
0x04006252: 20 91               MOVqw R1, @R1           ;
0x04006254: 6b 01               PUSH R1                 ;
0x04006256: 83 10 f8 00 00 00   CALL R0 (0x000000f8)    ;
0x0400625c: 6c 01               POP R1                  ;
0x0400625e: 77 31 01 00         MOVIqw R1, 0x0001       ;
0x04006262: 45 71               CMPeq R1, R7            ;
0x04006264: 82 76               JMP8cc 0x76             ;

0x04006266: 79 03 96 0d         MOVREL R3, 0x0d96       ;
0x0400626a: 20 b3               MOVqw R3, @R3           ;
0x0400626c: 72 b3 89 21         MOVnw R3, @R3 (+9, +24) ;
0x04006270: 79 01 06 0e         MOVREL R1, 0x0e06       ;
0x04006274: 35 01               PUSHn R1                ;
0x04006276: 77 31 08 00         MOVIqw R1, 0x0008       ;
0x0400627a: 35 01               PUSHn R1                ;
0x0400627c: 79 01 12 0e         MOVREL R1, 0x0e12       ;
0x04006280: 35 01               PUSHn R1                ;
0x04006282: 83 2b 28 18 00 20   CALLEXa @R3 (+40, +24)  ;
0x04006288: 60 00 03 10         MOVqw R0, R0 (+3, +0)   ;

; -----------------------------------------------------------------------------
; Decrypt payload stage 4
;
; The exact same process with stages 1, 2 and 3. But:
; Encoded payload at: 0x0400837c with size 0x930
;
; Also decoded payload takes 2 arguments:
;	1) the last 8 characters from key
;	2) the CRC32 of the last 8 characters of the key
; -----------------------------------------------------------------------------
0x0400628c: 79 02 ec 20         MOVREL R2, 0x20ec       ; R2 = 0x04006290 + 0x20ec = 0x0400837c = D
0x04006290: 79 03 c0 00         MOVREL R3, 0x00c0       ; R3 = 0x04006294 + 0x00c0 = 0x04006354
0x04006294: 79 04 dc 20         MOVREL R4, 0x20dc       ; R4 = 0x04006298 + 0x20dc = 0x04008374
0x04006298: 20 c4               MOVqw R4, @R4           ; R4 = *0x04008374 = 0x930 = len(D)
0x0400629a: 77 35 00 00         MOVIqw R5, 0x0000       ;
0x0400629e: 79 06 d8 0d         MOVREL R6, 0x0dd8       ;
0x040062a2: 1f e6               MOVdw R6, @R6           ;
0x040062a4: 1f a1               MOVdw R1, @R2           ;

0x040062a6: 16 61               XOR R1, R6              ;
0x040062a8: 1f 1b               MOVdw @R3, R1           ;
0x040062aa: 77 31 04 00         MOVIqw R1, 0x0004       ;
0x040062ae: 4c 12               ADD R2, R1              ;
0x040062b0: 4c 13               ADD R3, R1              ;
0x040062b2: 4c 15               ADD R5, R1              ;
0x040062b4: 45 54               CMPeq R4, R5            ;
0x040062b6: 82 f6               JMP8cc 0xf6             ;

0x040062b8: 79 03 44 0d         MOVREL R3, 0x0d44       ; update CRC32 using the last 8 characters
0x040062bc: 20 b3               MOVqw R3, @R3           ; from the key
0x040062be: 72 b3 89 21         MOVnw R3, @R3 (+9, +24) ;
0x040062c2: 79 01 b4 0d         MOVREL R1, 0x0db4       ;
0x040062c6: 35 01               PUSHn R1                ;
0x040062c8: 77 31 08 00         MOVIqw R1, 0x0008       ;
0x040062cc: 35 01               PUSHn R1                ;
0x040062ce: 79 01 c8 0d         MOVREL R1, 0x0dc8       ;
0x040062d2: 35 01               PUSHn R1                ;
0x040062d4: 83 2b 28 18 00 20   CALLEXa @R3 (+40, +24)  ;
0x040062da: 60 00 03 10         MOVqw R0, R0 (+3, +0)   ;

0x040062de: 79 01 98 0d         MOVREL R1, 0x0d98       ; R1 = 0x040062e2 + 0x0d98 = 0x0400707a = key
0x040062e2: 77 32 00 00         MOVIqw R2, 0x0000       ; R2 = 0
0x040062e6: 1f 92               MOVdw R2, @R1           ; R2 = *0x0400707a = 0x6D35BCD
0x040062e8: 35 02               PUSHn R2                ; arg2: latest key's CRC32
0x040062ea: 79 01 ac 0d         MOVREL R1, 0x0dac       ; R1 = 0x040062ee + 0x0dac = 0x0400709a
0x040062ee: 20 91               MOVqw R1, @R1           ; R1 = *0x0400709a
0x040062f0: 6b 01               PUSH R1                 ;
0x040062f2: 83 10 5c 00 00 00   CALL R0 (0x0000005c)    ; 0x040062f8 + 0x5c = 0x04006354
0x040062f8: 60 00 02 10         MOVqw R0, R0 (+2, +0)   ; 

0x040062fc: 77 31 01 00         MOVIqw R1, 0x0001       ; R1 = 1
0x04006300: 45 71               CMPeq R1, R7            ; rval == 1 ?
0x04006302: 82 27               JMP8cc 0x27             ; 0x04006304 + 0x27*2 = 0x04006352 (exit)

; -----------------------------------------------------------------------------
; If you reach this point key is correct
; -----------------------------------------------------------------------------
0x04006304: 79 02 7a 0d         MOVREL R2, 0x0d7a       ; R2 = 0x04006308 + 0x0d7a = 0x04007082
0x04006308: 79 03 96 0d         MOVREL R3, 0x0d96       ; R3 = 0x0400630c + 0x0d96 = 0x040070a2
0x0400630c: 77 34 00 00         MOVIqw R4, 0x0000       ; R4 = 0
0x04006310: 77 35 20 00         MOVIqw R5, 0x0020       ; R5 = 32

0x04006314: 1d ab               MOVbw @R3, @R2          ; *(0x040070a2 + j) = *(0x04007082 + i)
0x04006316: 77 31 01 00         MOVIqw R1, 0x0001       ; R1 = 1
0x0400631a: 4c 12               ADD R2, R1              ; ++R2
0x0400631c: 4c 14               ADD R4, R1              ; ++R4
0x0400631e: 77 31 02 00         MOVIqw R1, 0x0002       ;
0x04006322: 4c 13               ADD R3, R1              ; R3 += 2
0x04006324: 45 54               CMPeq R4, R5            ; i += 1, j += 2
0x04006326: 82 f6               JMP8cc 0xf6             ; cast key to unicode ?

0x04006328: 79 01 be 0d         MOVREL R1, 0x0dbe       ; R1 = 0x0400632c + 0x0dbe = 0x40070EA
0x0400632c: 6b 01               PUSH R1                 ; arg1: "TWCTF{"
0x0400632e: 83 10 cc fc ff ff   CALL R0 (0xfffffccc)    ; func_A("TWCTF{")
0x04006334: 6c 01               POP R1                  ;
0x04006336: 79 01 68 0d         MOVREL R1, 0x0d68       ; R1 = 0x0400633a + 0x0d68 = 0x040070a2
0x0400633a: 6b 01               PUSH R1                 ;
0x0400633c: 83 10 be fc ff ff   CALL R0 (0xfffffcbe)    ; func_A(key) (unicode)
0x04006342: 6c 01               POP R1                  ;
0x04006344: 79 01 b0 0d         MOVREL R1, 0x0db0       ; R1 = 0x04006348 + 0x0db0 = 0x40070f8
0x04006348: 6b 01               PUSH R1                 ;
0x0400634a: 83 10 b0 fc ff ff   CALL R0 (0xfffffcb0)    ; func_A("}")
0x04006350: 6c 01               POP R1                  ;
0x04006352: 04 00               RET                     ;
0x04006354: 00 00               BREAK 0                 ;
0x04006356: 00 00               BREAK 0                 ;
; --------------------------------------------------------------------------------------------------
; End
; --------------------------------------------------------------------------------------------------
