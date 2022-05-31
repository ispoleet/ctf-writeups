# ------------------------------------------------------------------------------
# Read Key from cin
# ------------------------------------------------------------------------------
.text:0000+3A=003A    PUSH     0x80E9E5952E8      (W:46)        ;
.text:003A+12=004C    SVC      0x0                (W: 6)        ; print(0x80E9E5952E8 >> 6) = 0x203a79654b = ' :yeK' = 'Key: '
.text:004C+0D=0059    SVC      0x1                (W: 1)        ; push getline() (up to 0x2a chars)
.text:0059+11=006A    PUSH     0x0                (W: 5)        ; Stack = [i=0:5, key] (i is 5 bits)

# ------------------------------------------------------------------------------
# Store flag into global data at offset 0
# ------------------------------------------------------------------------------
.text:006A+14=007E    STCK_RD  0x5                (W: 8)        ; Load key[i] in top of stack (read 8 bits from offset 5 => key[0] and put them in top of stack)
.text:007E+12=0090    PUSH     0x0                (W: 6)        ; 6 more bits in stack
.text:0090+11=00A1    STCK_RD  0xE                (W: 5)        ; Load 5 bits from offset 14 = 6 + 8 => i on top of stack
.text:00A1+11=00B2    MUL      0x7                (W: 5)        ; i *= 7 (MSBit is always 0; it's ASCII) (result is 10 bits)
.text:00B2+14=00C6    STCK_WR  0x0                (W: 8)        ; ?
.text:00C6+0C=00D2    STR      $_top_             (W: 8)        ; Write key[0] (2nd top of stack) at offset $_top_ = i*7 in global data
.text:00D2+11=00E3    STCK_WR  0x3                (W: 5)        ; 
.text:00E3+0E=00F1    POP      0x3                (-: 2)        ;
.text:00F1+11=0102    ADD      0x1                (W: 5)        ; ++i
.text:0102+0F=0111    DUP      0x5                (-: 3)        ; copy i = i'
.text:0111+11=0122    SUB      0x19               (W: 5)        ; i' - 25
.text:0122+11=0133    JZ       0x146              (W: 5)        ; if len == 0x19 = 25 break ~> Flag is 25 chars
.text:0133+13=0146    JMP      0x6A               (W: 7)        ; loop back

# ------------------------------------------------------------------------------
# Not sure what's going on here
# ------------------------------------------------------------------------------
.text:0146+20=0166    PUSH     0xA07F5            (W:20)        ; ?
.text:0166+11=0177    POP      0x19               (-: 5)        ; pop 0xA07F5 (19 bits) + i (5 bits) from stack
.text:0177+13=018A    PUSH     0x7F               (W: 7)        ; 127 on stack?
.text:018A+1C=01A6    PUSH     0x1C2              (W:16)        ; return value in stack
.text:01A6+1C=01C2    JMP      0x1166             (W:16)        ; call MAIN_CALC_FUNC
.text:01C2+13=01D5    SVC      0x2                (W: 7)        ; 
.text:01D5+0D=01E2    MUL      0x0                (W: 1)        ; 

# ------------------------------------------------------------------------------
# Find the inverse number modulo 127 using extended euclidean algorithm
# ------------------------------------------------------------------------------
FIND_INVERSE_FUNC:
.text:01E1+13=01F4    STCK_RD  0x10               (W: 7)        ; a = $ARG on top of stack (first 16 bits are for return address)
# .text:01E2+0C=01EE    SUB      $_top_             (W: 3)
# .text:01EE+1D=020B    PUSH     0x7016             (W:17)
# .text:01EE+4B=0239    PUSH     0x1263CB066820D01C   (W:63)
.text:01F4+13=0207    SUB      0x1                (W: 7)        ; a = $ARG - 1 
.text:0207+13=021A    JZ       0x230              (W: 7)        ; if a == 1 then return $ARG (=1)
# .text:020B+3D=0248    ADD      0x19834F1923F13    (W:49)
.text:021A+16=0230    JMP      0x23C              (W:10)        ; else no return
.text:0230+0C=023C    JMP      $_top_             (W:16)        ; return (jump where return address is)
# .text:0239+0C=0245    SUB      $_top_             (W: 7)

.text:023C+10=024C    PUSH     0x0                (W: 4)        ; i = 0
# .text:0245+19=025E    SPNLCK   0x8A               (-:13)
# .text:0248+28=0270    ADD      0x228C1DF          (W:28)
.text:024C+13=025F    STCK_RD  0x14               (W: 7)        ; top = $ARG
# .text:025E+0C=026A    DUP      $_top_             (-:63)
.text:025F+13=0272    PUSH     0x7F               (W: 7)        ; b = 127 ~> S = [b=0x7F, a=$ARG, i=0]
# .text:026A+1B=0285    SPNLCK   0x107              (-:15)
# .text:0270+0C=027C    SVC      $_top_             (W: 2)

; a = arg; b = 0x7F;
; for (i=0; ;) {
;   if (i % 2 == 0) {
;     stack.push(a / b); a = a % b;
;   } else {
;     stack.push(b / a); b = b % b;
;   }
;   if (b == 1 || a == 1) break;
LOOP_1:
.text:0272+14=0286    STCK_RD  0xE                (W: 8)        ; S = [i=0, 0x7F, $ARG, i=0]
# .text:027C+0C=0288    SUB      $_top_             (W: 2)
# .text:0285+0D=0292    IDIV     0x0                (W: 1)

; IF CONDITION
.text:0286+13=0299    PUSH     0x0                (W: 7)        ; Add 7 bits and then check 8 (7 0's and LSBit of i)
# .text:0288+0C=0294    ADD      $_top_             (W: 1)
.text:0299+14=02AD    JZ       0x344              (W: 8)        ; if LSBit(i) == 0 goto ELSE

; IF CASE
.text:02AD+11=02BE    DUP      0x19               (-: 5)        ; adjust stack
.text:02BE+0F=02CD    POP      0x7                (-: 3)        ; adjust stack
.text:02CD+1E=02EB    STCK_WR  0x0                (W:18)        ; adjust stack
.text:02EB+10=02FB    DUP      0xE                (-: 4)        ; 
.text:02FB+0C=0307    IDIV     $_top_             (W: 7)        ; S = $ARG=a / 0x7F=b; $ARG=a % 0x7F=b
.text:0307+13=031A    STCK_WR  0x19               (W: 7)        ; assign a = a % b
.text:031A+13=032D    STCK_WR  0x7                (W: 7)        ;
.text:032D+17=0344    JMP      0x3D6              (W:11)        ; skip else case
; ELSE CASE
.text:0344+11=0355    DUP      0x19               (-: 5)        ;
.text:0355+0F=0364    POP      0x7                (-: 3)        ;
.text:0364+1E=0382    STCK_WR  0x0                (W:18)        ; adjust stack
.text:0382+0F=0391    DUP      0x7                (-: 3)        ; 
.text:0391+13=03A4    STCK_RD  0xE                (W: 7)        ;
.text:03A4+0C=03B0    IDIV     $_top_             (W: 7)        ; S = 0x7F / $ARG; 0x7F % $ARG
.text:03B0+13=03C3    STCK_WR  0x19               (W: 7)        ; assign b = b % a    => EUCLEDIAN ALGO? YES!
.text:03C3+13=03D6    STCK_WR  0x0                (W: 7)        ;

; top of stack has $ARG % 0x7F or 0x7F % $ARG based on LSBit of i
.text:03D6+1E=03F4    ADD      0x4000             (W:18)        ; 
.text:03F4+0F=0403    DUP      0x7                (-: 3)        ; b on top of stack
.text:0403+13=0416    SUB      0x1                (W: 7)        ; b - 1
.text:0416+13=0429    JZ       0x478              (W: 7)        ; if b == 1 break

.text:0429+13=043C    STCK_RD  0x7                (W: 7)        ;
.text:043C+13=044F    SUB      0x1                (W: 7)        ; a - 1
.text:044F+13=0462    JZ       0x478              (W: 7)        ; if a == 1 break too
.text:0462+16=0478    JMP      0x272              (W:10)        ; else goto LOOP_1

.text:0478+13=048B    STCK_RD  0x12               (W: 7)        ; top = a 
.text:048B+13=049E    STCK_WR  0x7                (W: 7)        ; 
.text:049E+11=04AF    DUP      0x12               (-: 5)        ;
.text:04AF+1E=04CD    STCK_WR  0x7                (W:18)        ;
.text:04CD+10=04DD    POP      0xE                (-: 4)        ;
.text:04DD+13=04F0    PUSH     0x1                (W: 7)        ; c = 1
.text:04F0+13=0503    STCK_RD  0xB                (W: 7)        ;
.text:0503+0F=0512    MUL      0x0                (W: 3)        ; ?

LOOP_2
.text:0512+16=0528    SUB      0x40               (W:10)        ;
.text:0528+10=0538    DUP      0xA                (-: 4)        ; if i == 0 then break
.text:0538+16=054E    JZ       0x643              (W:10)        ;

.text:054E+13=0561    STCK_RD  0x1C               (W: 7)        ; 
.text:0561+13=0574    STCK_RD  0x18               (W: 7)        ;
.text:0574+0C=0580    MUL      $_top_             (W: 7)        ;
.text:0580+13=0593    STCK_RD  0x18               (W: 7)        ;
.text:0593+0C=059F    ADD      $_top_             (W: 7)        ;
.text:059F+13=05B2    STCK_RD  0x1F               (W: 7)        ;
.text:05B2+1A=05CC    STCK_WR  0x11               (W:14)        ;
.text:05CC+28=05F4    STCK_RD  0x7                (W:28)        ;
.text:05F4+28=061C    STCK_WR  0xE                (W:28)        ;
.text:061C+10=062C    POP      0xE                (-: 4)        ;
.text:062C+17=0643    JMP      0x512              (W:11)        ; goto LOOP_2

.text:0643+11=0654    POP      0x11               (-: 5)        ; adjust stack
.text:0654+10=0664    STCK_RD  0x7                (W: 4)        ;
.text:0664+14=0678    PUSH     0x0                (W: 8)        ;
.text:0678+15=068D    JZ       0x6D6              (W: 9)        ;

.text:068D+13=06A0    PUSH     0x7F               (W: 7)        ; 0x7F on top
.text:06A0+13=06B3    STCK_RD  0xA                (W: 7)        ;
.text:06B3+0C=06BF    SUB      $_top_             (W: 7)        ; top = 0x7F - a
.text:06BF+17=06D6    JMP      0x6E9              (W:11)        ;

.text:06D6+13=06E9    STCK_RD  0x3                (W: 7)        ; top = a

; if (i % 2 == 0) return a;
; else            return 0x7F - a;
.text:06E9+13=06FC    STCK_WR  0x1E               (W: 7)        ;
.text:06FC+11=070D    POP      0xE                (-: 5)        ;
.text:070D+0C=0719    JMP      $_top_             (W:16)        ; return top


# ------------------------------------------------------------------------------
# Matrix determinant? Yes!
# ------------------------------------------------------------------------------
CALC_DET_FUNC:
.text:0719+14=072D    PUSH     0x0                (W: 8)        ;
.text:072D+0F=073C    DUP      0x4                (-: 3)        ;
.text:073C+10=074C    ADD      0x1                (W: 4)        ;
.text:074C+15=0761    PUSH     0x0                (W: 9)        ;
.text:0761+10=0771    STCK_RD  0xD                (W: 4)        ;
.text:0771+14=0785    MUL      0x2A               (W: 8)        ;
.text:0785+0C=0791    LDR      $_top_             (W: 8)        ;
.text:0791+13=07A4    STCK_WR  0x7                (W: 7)        ;
.text:07A4+0F=07B3    POP      0x7                (-: 3)        ;
.text:07B3+0F=07C2    DUP      0x7                (-: 3)        ;
.text:07C2+10=07D2    PUSH     0x0                (W: 4)        ;
.text:07D2+17=07E9    JZ       0xD70              (W:11)        ;
.text:07E9+1C=0805    PUSH     0x821              (W:16)        ; return address on stack
.text:0805+1C=0821    JMP      0x1E1              (W:16)        ; call FIND_INVERSE_FUNC
.text:0821+16=0837    PUSH     0x0                (W:10)        ;
.text:0837+14=084B    STCK_RD  0x11               (W: 8)        ;
.text:084B+10=085B    MUL      0x5                (W: 4)        ;
.text:085B+0C=0867    ADD      $_top_             (W: 8)        ;
.text:0867+14=087B    MUL      0x7                (W: 8)        ;
.text:087B+14=088F    STCK_WR  0x0                (W: 8)        ;
.text:088F+0C=089B    LDR      $_top_             (W: 8)        ;
.text:089B+13=08AE    STCK_WR  0x0                (W: 7)        ;
.text:08AE+0C=08BA    MUL      $_top_             (W: 7)        ;
.text:08BA+1A=08D4    IDIV     0x7F               (W:14)        ;
.text:08D4+10=08E4    POP      0xE                (-: 4)        ;
.text:08E4+13=08F7    STCK_WR  0x0                (W: 7)        ;
.text:08F7+10=0907    STCK_RD  0xB                (W: 4)        ;
.text:0907+10=0917    PUSH     0x0                (W: 4)        ;
.text:0917+10=0927    STCK_RD  0x4                (W: 4)        ;
.text:0927+14=093B    SUB      0x5                (W: 8)        ;
.text:093B+14=094F    JZ       0x9AD              (W: 8)        ;
.text:094F+34=0983    PUSH     0xC0BE090038       (W:40)        ;
.text:0983+12=0995    POP      0x28               (-: 6)        ;
.text:0995+18=09AD    JMP      0xA41              (W:12)        ;
.text:09AD+12=09BF    SPNLCK   0x36               (-: 6)        ;
.text:09BF+10=09CF    POP      0xB                (-: 4)        ;
.text:09CF+10=09DF    ADD      0x1                (W: 4)        ;
.text:09DF+13=09F2    PUSH     0x0                (W: 7)        ;
.text:09F2+10=0A02    STCK_RD  0x7                (W: 4)        ;
.text:0A02+10=0A12    SUB      0x5                (W: 4)        ;
.text:0A12+17=0A29    JZ       0xF16              (W:11)        ;
.text:0A29+18=0A41    JMP      0x74C              (W:12)        ;
.text:0A41+12=0A53    PUSH     0x0                (W: 6)        ;
.text:0A53+10=0A63    STCK_RD  0x6                (W: 4)        ;
.text:0A63+14=0A77    STCK_RD  0x15               (W: 8)        ;
.text:0A77+10=0A87    STCK_WR  0x0                (W: 4)        ;
.text:0A87+10=0A97    MUL      0x5                (W: 4)        ;
.text:0A97+0C=0AA3    ADD      $_top_             (W: 8)        ;
.text:0AA3+13=0AB6    MUL      0x7                (W: 7)        ;
.text:0AB6+0C=0AC2    LDR      $_top_             (W: 8)        ;
.text:0AC2+13=0AD5    STCK_WR  0x0                (W: 7)        ;
.text:0AD5+0F=0AE4    DUP      0x7                (-: 3)        ;
.text:0AE4+13=0AF7    STCK_WR  0x1                (W: 7)        ;
.text:0AF7+0D=0B04    POP      0x1                (-: 1)        ;
.text:0B04+15=0B19    ADD      0x7F               (W: 9)        ;

.text:0B19+12=0B2B    PUSH     0x0                (W: 6)        ;
.text:0B2B+10=0B3B    STCK_RD  0xF                (W: 4)        ;
.text:0B3B+14=0B4F    STCK_RD  0x22               (W: 8)        ;
#       .text:0B3B+1B=0B56    DUP      0x1170             (-:15)
.text:0B4F+10=0B5F    STCK_WR  0x0                (W: 4)        ;
.text:0B5F+10=0B6F    MUL      0x5                (W: 4)        ;
#.text:0B5F+30=0B8F    LDR      0x5C04E30E0        (W:36)
.text:0B6F+0C=0B7B    ADD      $_top_             (W: 8)        ;
#.text:0B6F+29=0B98    STCK_RD  0x1C61C189         (W:29)
.text:0B7B+13=0B8E    MUL      0x7                (W: 7)        ;
.text:0B8E+0C=0B9A    LDR      $_top_             (W: 8)        ;
#.text:0B8F+3D=0BCC    MUL      0x18E40300F4068    (W:49)
.text:0B9A+13=0BAD    STCK_WR  0x0                (W: 7)        ;
.text:0BAD+0F=0BBC    DUP      0x7                (-: 3)        ;
#   .text:0BAD+18=0BC5    STCK_WR  0xE80              (W:12)
.text:0BBC+13=0BCF    STCK_WR  0x1                (W: 7)        ;
.text:0BCF+0D=0BDC    POP      0x1                (-: 1)        ;
.text:0BDC+0E=0BEA    PUSH     0x0                (W: 2)        ;
.text:0BEA+13=0BFD    STCK_RD  0x18               (W: 7)        ;
.text:0BFD+0C=0C09    MUL      $_top_             (W: 9)        ;
.text:0C09+1E=0C27    IDIV     0x7F               (W:18)        ;
#.text:0C27+0C=0C33    ADD      $_top_             (W:10)
.text:0C27+11=0C38    POP      0x12               (-: 5)        ;
#.text:0C38+0D=0C45    STCK_WR  0x0                (W: 1)
.text:0C38+15=0C4D    STCK_WR  0x0                (W: 9)        ;
#.text:0C38+25=0C5D    UNKNWN   0x1211             (-:25)
# .text:0C45+0C=0C51    STCK_WR  $_top_             (W: 5)
.text:0C4D+0C=0C59    SUB      $_top_             (W: 9)        ;
#   .text:0C4D+3D=0C8A    ADD      0x231FC12C9C0A     (W:49)
.text:0C59+15=0C6E    IDIV     0x7F               (W: 9)        ;
#.text:0C5D+0E=0C6B    STR      0x3                (W: 2)
#.text:0C6B+0C=0C77    SUB      $_top_             (W:10)
.text:0C6E+10=0C7E    POP      0x9                (-: 4)        ;
#.text:0C6E+17=0C85    DUP      0x4E0              (-:11)
#.text:0C6E+40=0CAE    ADD      0x8703B40305039    (W:52)
.text:0C7E+10=0C8E    PUSH     0x0                (W: 4)        ;
#.text:0C85+0C=0C91    DUP      $_top_             (-: 1)
#.text:0C85+0D=0C92    JZ       0xC92              (W: 1)
#.text:0C8A+0C=0C96    IDIV     $_top_             (W:53)
#.text:0C8A+1B=0CA5    STCK_RD  0x16E0             (W:15)
.text:0C8E+10=0C9E    STCK_RD  0xD                (W: 4)        ;
#.text:0C96+1B=0CB1    SPNLCK   0x70E              (-:15)
.text:0C9E+14=0CB2    STCK_RD  0x1C               (W: 8)        ;
#.text:0C9E+1B=0CB9    DUP      0xE70              (-:15)
#.text:0CA5+25=0CCA    IDIV     0x60E0E            (W:25)
#.text:0CA5+2E=0CD3    LDR      0x1C1C18035        (W:34)
#.text:0CA5+31=0CD6    STCK_RD  0xE0E0C01AC        (W:37)
#.text:0CAE+13=0CC1    ADD      0x70               (W: 7)
.text:0CB2+10=0CC2    STCK_WR  0x0                (W: 4)        ;
#.text:0CB2+2E=0CE0    ADD      0x3006B093         (W:34)

.text:0CC2+10=0CD2    MUL      0x5                (W: 4)        ;
#.text:0CC2+1B=0CDD    SUB      0x5612             (W:15)
.text:0CD2+0C=0CDE    ADD      $_top_             (W: 8)        ;
#.text:0CD2+11=0CE3    ADD      0x1C               (W: 5)
#.text:0CDE+0C=0CEA    STCK_RD  $_top_             (W:33)
.text:0CDE+14=0CF2    MUL      0x7                (W: 8)        ;
#.text:0CE0+0C=0CEC    SUB      $_top_             (W:57)
#.text:0CE3+10=0CF3    SUB      0xF                (W: 4)
#.text:0CE3+15=0CF8    ADD      0x1F8              (W: 9)
#.text:0CEA+1B=0D05    ADD      0x200              (W:15)
.text:0CF2+14=0D06    STCK_WR  0x0                (W: 8)        ;
#.text:0CF3+0C=0CFF    IDIV     $_top_             (W: 1)
#.text:0CFF+0C=0D0B    STCK_WR  $_top_             (W: 1)
.text:0D06+10=0D16    DUP      0x8                (-: 4)        ;
#.text:0D06+1B=0D21    IDIV     0x4603             (W:15)
#.text:0D0B+3D=0D48    ADD      0xD2140BCC3B01     (W:49)
.text:0D16+0C=0D22    LDR      $_top_             (W: 8)        ;
#.text:0D16+21=0D37    MUL      0x1C33D0           (W:21)
#.text:0D16+3E=0D54    ADD      0x1C1A42817987     (W:50)
#.text:0D21+17=0D38    LDR      0x7A0              (W:11)
#.text:0D21+29=0D4A    PUSH     0x1E814258         (W:29)
.text:0D22+0F=0D31    POP      0x7                (-: 3)        ;
.text:0D31+13=0D44    STCK_RD  0x9                (W: 7)        ;
#.text:0D38+14=0D4C    SUB      0x60               (W: 8)
.text:0D44+14=0D58    STCK_RD  0x8                (W: 8)        ;

.text:0D58+0C=0D64    STR      $_top_             (W: 8)        ;
#.text:0D58+24=0D7C    STR      0xE3501F           (W:24)
.text:0D64+1D=0D81    SUB      0x17F80            (W:17)        ;
.text:0D70+0F=0D7F    POP      0x7                (-: 3)        ;
.text:0D7F+1A=0D99    PUSH     0x0                (W:14)        ;
#.text:0D81+0D=0D8E    STCK_WR  0x0                (W: 1)
.text:0D99+10=0DA9    STCK_RD  0xE                (W: 4)        ;
.text:0DA9+1D=0DC6    MUL      0x23               (W:17)        ;
.text:0DC6+1A=0DE0    PUSH     0x0                (W:14)        ;
.text:0DE0+14=0DF4    STCK_RD  0x35               (W: 8)        ;
.text:0DF4+10=0E04    STCK_WR  0x0                (W: 4)        ;
.text:0E04+1D=0E21    MUL      0x23               (W:17)        ;
.text:0E21+12=0E33    DUP      0x23               (-: 6)        ;
.text:0E33+0C=0E3F    LDR      $_top_             (W:35)        ;
.text:0E3F+2F=0E6E    STCK_RD  0x46               (W:35)        ;
.text:0E6E+12=0E80    DUP      0x23               (-: 6)        ;
.text:0E80+0C=0E8C    LDR      $_top_             (W:35)        ;
.text:0E8C+2F=0EBB    STCK_RD  0x69               (W:35)        ;
.text:0EBB+0C=0EC7    STR      $_top_             (W:35)        ;
.text:0EC7+0C=0ED3    STR      $_top_             (W:35)        ;
.text:0ED3+13=0EE6    POP      0x46               (-: 7)        ;
.text:0EE6+18=0EFE    ADD      0x100              (W:12)        ;
.text:0EFE+18=0F16    JMP      0x9CF              (W:12)        ;

.text:0F16+0F=0F25    POP      0x4                (-: 3)        ;
.text:0F25+10=0F35    ADD      0x1                (W: 4)        ;
.text:0F35+0D=0F42    PUSH     0x0                (W: 1)        ;
.text:0F42+10=0F52    STCK_RD  0x1                (W: 4)        ;
.text:0F52+11=0F63    SUB      0x4                (W: 5)        ;
.text:0F63+11=0F74    JZ       0xF8C              (W: 5)        ;
.text:0F74+18=0F8C    JMP      0x72D              (W:12)        ;
.text:0F8C+0F=0F9B    POP      0x4                (-: 3)        ;
.text:0F9B+11=0FAC    PUSH     0x0                (W: 5)        ;
.text:0FAC+12=0FBE    JZ       0xFEE              (W: 6)        ;
.text:0FBE+17=0FD5    PUSH     0x7E               (W:11)        ;
.text:0FD5+19=0FEE    JMP      0x1005             (W:13)        ;

.text:0FEE+17=1005    PUSH     0x1                (W:11)        ;
.text:1005+13=1018    STCK_WR  0x0                (W: 7)        ;
.text:1018+13=102B    PUSH     0x0                (W: 7)        ;

.text:102B+10=103B    DUP      0x7                (-: 4)        ;
.text:103B+13=104E    MUL      0x2A               (W: 7)        ;
.text:104E+0C=105A    LDR      $_top_             (W: 8)        ;
.text:105A+13=106D    STCK_WR  0x0                (W: 7)        ;
.text:106D+13=1080    STCK_RD  0xE                (W: 7)        ;
.text:1080+0C=108C    MUL      $_top_             (W: 7)        ;
.text:108C+1A=10A6    IDIV     0x7F               (W:14)        ;
.text:10A6+10=10B6    POP      0xE                (-: 4)        ;
.text:10B6+13=10C9    STCK_WR  0xE                (W: 7)        ;
.text:10C9+0F=10D8    POP      0x7                (-: 3)        ;
.text:10D8+0F=10E7    ADD      0x1                (W: 3)        ;
.text:10E7+10=10F7    DUP      0x7                (-: 4)        ;
.text:10F7+13=110A    SUB      0x5                (W: 7)        ;
.text:110A+13=111D    JZ       0x1136             (W: 7)        ;
.text:111D+19=1136    JMP      0x102B             (W:13)        ;
.text:1136+11=1147    POP      0x7                (-: 5)        ;
.text:1147+13=115A    STCK_WR  0x10               (W: 7)        ;
.text:115A+0C=1166    JMP      $_top_             (W:16)        ; return

# ------------------------------------------------------------------------------
# Matrix multiplication!
# ------------------------------------------------------------------------------
MAIN_CALC_FUNC:
.text:1166+11=1177    PUSH     0x0                (W: 5)        ; i = 0

LOOP_I
.text:1177+11=1188    PUSH     0x7                (W: 5)        ; j = 7

LOOP_J
.text:1188+0F=1197    ADD      0x1                (W: 3)        ; j += 1 => j = 0 (in 3 bits)
.text:1197+0F=11A6    DUP      0x5                (-: 3)        ; 
.text:11A6+0F=11B5    MUL      0x1                (W: 3)        ;
.text:11B5+0F=11C4    SUB      0x4                (W: 3)        ; j*1 - 4 

# The `PUSH 0x1818231B070A` seems wrong. If we look at the logs for address 0x11C4
# we can see the correct sequence.
# 
# [+] Extracting instructions from 1010100000101101011010001101100110000001100000100011000110110000011100001010 at: 11C4h
# [+] Adding conditional jump target: 1228h
# [+]    .text:11C4+14=11D8    JZ       0x1228             (W: 8)
# [+]    .text:11C4+39=11FD    PUSH     0x1818231B070A     (W:45)
# [+] Extracting instructions from 0000110000111001010010101000001011010110100011011001100000011000001000110001 at: 11D8h
# [+] Unconditional jump found. Target: 1188h
# [+]    .text:11D8+19=11F1    JMP      0x1188             (W:13)
#
# .text:11C4+39=11FD    PUSH     0x1818231B070A     (W:45)
.text:11C4+14=11D8    JZ       0x1228             (W: 8)        ; if j == 4 break
.text:11D8+19=11F1    JMP      0x1188             (W:13)        ; else goto LOOP_J

.text:11FD+12=120F    POP      0x35               (-: 6)        ; parallel?
.text:120F+19=1228    JMP      0x129C             (W:13)        ; goto DO_COMP

.text:1228+0F=1237    POP      0x5                (-: 3)        ;
.text:1237+0F=1246    ADD      0x1                (W: 3)        ; i + 1
.text:1246+0F=1255    DUP      0x5                (-: 3)        ;
.text:1255+11=1266    SUB      0x5                (W: 5)        ; i - 5
.text:1266+11=1277    JZ       0x1290             (W: 5)        ; if i == 5 break
.text:1277+19=1290    JMP      0x1177             (W:13)        ; else goto LOOP_I

.text:1290+0D=129D    MUL      0x0                (W: 1)        ; after loop

DO_COMP:
.text:129C+10=12AC    PUSH     0x0                (W: 4)        ; k = 0
.text:12AC+11=12BD    STCK_RD  0x4                (W: 5)        ; j on top of stack
.text:12BD+15=12D2    MUL      0x5                (W: 9)        ; j*5
.text:12D2+1D=12EF    MUL      0x7                (W:17)        ; j*35
.text:12EF+0C=12FB    LDR      $_top_             (W:35)        ; read 35 bits from global_data[j*35]
.text:12FB+10=130B    PUSH     0x0                (W: 4)        ; 0
.text:130B+16=1321    STCK_RD  0x2C               (W:10)        ; read 10 bits from stack[44] to top = x 
.text:1321+11=1332    STCK_WR  0x0                (W: 5)        ; 
.text:1332+15=1347    MUL      0x5                (W: 9)        ; 
.text:1347+1D=1364    MUL      0x7                (W:17)        ; x * 35
.text:1364+17=137B    ADD      0x168              (W:11)        ; x * 35 + 360
.text:137B+0C=1387    LDR      $_top_             (W:35)        ; load 35 bits from global[360 + x*35]
.text:1387+14=139B    PUSH     0x0                (W: 8)        ; 0
.text:139B+10=13AB    PUSH     0x0                (W: 4)        ; 0

LOOP_X
.text:13AB+0D=13B8    PUSH     0x0                (W: 1)        ; 0  
.text:13B8+13=13CB    STCK_RD  0xD                (W: 7)        ;
.text:13CB+13=13DE    STCK_RD  0x37               (W: 7)        ; 
.text:13DE+0C=13EA    MUL      $_top_             (W: 7)        ;
.text:13EA+1A=1404    IDIV     0x7F               (W:14)        ; 
.text:1404+10=1414    POP      0xE                (-: 4)        ; drop / from stack (keep modulo only)
.text:1414+13=1427    STCK_WR  0x0                (W: 7)        ; 
.text:1427+14=143B    STCK_RD  0xC                (W: 8)        ;
.text:143B+0C=1447    ADD      $_top_             (W: 8)        ;
.text:1447+14=145B    IDIV     0x7F               (W: 8)        ;
.text:145B+10=146B    POP      0x8                (-: 4)        ; drop / from stack (keep modulo only)
.text:146B+10=147B    STCK_RD  0x8                (W: 4)        ;
.text:147B+18=1493    STCK_WR  0x7                (W:12)        ;
.text:1493+0F=14A2    POP      0x7                (-: 3)        ;
.text:14A2+11=14B3    ADD      0x1                (W: 5)        ;
.text:14B3+0E=14C1    DUP      0x3                (-: 2)        ;
.text:14C1+0E=14CF    MUL      0x1                (W: 2)        ;

.text:14CF+11=14E0    SUB      0x11               (W: 5)        ;
.text:14E0+11=14F1    JZ       0x150A             (W: 5)        ; if 
.text:14F1+19=150A    JMP      0x13AB             (W:13)        ; goto LOOP_X

.text:150A+0F=1519    POP      0x4                (-: 3)        ;
.text:1519+13=152C    STCK_WR  0x1D               (W: 7)        ;
.text:152C+11=153D    POP      0x1D               (-: 5)        ;
.text:153D+10=154D    PUSH     0x0                (W: 4)        ;
.text:154D+15=1562    STCK_RD  0xB                (W: 9)        ;
.text:1562+0F=1571    MUL      0x5                (W: 3)        ;
.text:1571+0C=157D    ADD      $_top_             (W: 8)        ;
.text:157D+11=158E    MUL      0x7                (W: 5)        ;
.text:158E+16=15A4    ADD      0xB8               (W:10)        ;
.text:15A4+10=15B4    DUP      0xA                (-: 4)        ;
.text:15B4+0C=15C0    LDR      $_top_             (W:10)        ;
.text:15C0+0F=15CF    POP      0x7                (-: 3)        ;
.text:15CF+13=15E2    STCK_RD  0x10               (W: 7)        ;
.text:15E2+16=15F8    STCK_RD  0xA                (W:10)        ;
.text:15F8+0C=1604    STR      $_top_             (W:10)        ;
.text:1604+11=1615    UNKNWN   0x18               (-: 5)        ;
.text:1615+11=1626    POP      0x1E               (-: 5)        ;
.text:1626+16=163C    PUSH     0x2A               (W:10)        ;
.text:163C+1C=1658    PUSH     0x1674             (W:16)        ; return address
.text:1658+1C=1674    JMP      0x719              (W:16)        ; call CALC_DET_FUNC
.text:1674+16=168A    STR      0x234              (W:10)        ;
.text:168A+14=169E    LDR      0xAF               (W: 8)        ;
.text:169E+16=16B4    PUSH     0x80               (W:10)        ;

LOOP_K:
.text:16B4+25=16D9    PUSH     0x0                (W:25)        ; Compute: I * det
.text:16D9+16=16EF    STCK_RD  0x19               (W:10)        ;
.text:16EF+0C=16FB    SUB      $_top_             (W: 5)        ;
.text:16FB+11=170C    MUL      0x7                (W: 5)        ;
.text:170C+16=1722    ADD      0x218              (W:10)        ;
.text:1722+0C=172E    LDR      $_top_             (W:35)        ;
.text:172E+1A=1748    PUSH     0x0                (W:14)        ;
.text:1748+16=175E    PUSH     0x0                (W:10)        ;
.text:175E+16=1774    STCK_RD  0x3B               (W:10)        ;
.text:1774+11=1785    STCK_WR  0x0                (W: 5)        ;
.text:1785+12=1797    MUL      0x23               (W: 6)        ;
.text:1797+16=17AD    ADD      0xB8               (W:10)        ;
.text:17AD+0C=17B9    LDR      $_top_             (W:35)        ;
.text:17B9+0C=17C5    SUB      $_top_             (W:35)        ;
.text:17C5+2F=17F4    JZ       0x1814             (W:35)        ;
.text:17F4+10=1804    PUSH     0xC                (W: 4)        ;
.text:1804+10=1814    STCK_WR  0xA                (W: 4)        ;

.text:1814+0F=1823    ADD      0x1                (W: 3)        ; k += 1
.text:1823+0F=1832    DUP      0x5                (-: 3)        ; make copy
.text:1832+0F=1841    SUB      0x5                (W: 3)        ; k - 5
.text:1841+11=1852    JZ       0x186C             (W: 5)        ; if k == 5 break
.text:1852+1A=186C    JMP      0x16B4             (W:14)        ; else goto LOOP_K
.text:186C+10=187C    POP      0xA                (-: 4)        ;
.text:187C+0C=1888    STCK_RD  $_top_             (W:29)        ;
.text:187C+14=1890    JZ       0x18CB             (W: 8)        ; if top == 0 goto badboy
                                                                ; else goto goodboy
# ------------------------------------------------------------------------------
#  Print goodboy/badboy messages
# ------------------------------------------------------------------------------
# .text:1888+0C=1894    STR      $_top_             (W:49)
.text:1890+1F=18AF    PUSH     0x283AF            (W:19)        ; top = '(:\x0f' = :)
# .text:1894+0C=18A0    STR      $_top_             (W:33)
# .text:18A0+0C=18AC    ADD      $_top_             (W:24)
# .text:18A0+11=18B1    SUB      0x1D               (W: 5)
# .text:18AC+0C=18B8    STCK_WR  $_top_             (W: 3)
.text:18AF+1C=18CB    JMP      0x18EA             (W:16)        ; print goodboy message
# .text:18B1+0C=18BD    POP      $_top_             (-: 7)
# .text:18B1+23=18D4    MUL      0x3D5C6            (W:23)
.text:18B8+0C=18C4    STCK_RD  $_top_             (W:44)        ;
# .text:18B8+14=18CC    DUP      0xD5               (-: 8)
# .text:18BD+10=18CD    JZ       0x18D8             (W: 4)

.text:18CB+1F=18EA    PUSH     0x293AF            (W:19)        ; top = '):\x0f' = :(
# .text:18CC+3E=190A    ADD      0x293AF4820C0BA    (W:50)
# .text:18CD+0C=18D9    JZ       $_top_             (W:19)
# .text:18CD+38=1905    DUP      0x49D7A410605      (-:44)
# .text:18D4+0C=18E0    JZ       $_top_             (W:24)
# .text:18E0+0E=18EE    ADD      0x0                (W: 2)

.text:18EA+10=18FA    SVC      0x0                (W: 4)        ; print goodboy/badboy message
.text:18FA+13=190D    PUSH     0x54               (W: 7)        ; top = 0x54
# .text:1905+15=191A    PUSH     0x4                (W: 9)
# .text:190A+0C=1916    ADD      $_top_             (W: 3)
# .text:190A+11=191B    STR      0x8                (W: 5)
# .text:190A+1A=1924    STCK_WR  0x1040             (W:14)
.text:190D+0F=191C    SVC      0x0                (W: 3)        ; print 0x54 & 7 = 4 ?
# .text:1916+10=1926    MUL      0x2                (W: 4)
.text:191C+0D=1929    MUL      0x0                (W: 1)        ; ?
