// ------------------------------------------------------------------------------------------------
#include <idc.idc>


// ------------------------------------------------------------------------------------------------
static get_func_name(addr) {
         if (addr == 0x401027) return "nop";
    else if (addr == 0x4010F6) return "change_pace";
    else if (addr == 0x4010FE) return "jz";
    else if (addr == 0x401111) return "jz page";
    else if (addr == 0x401124) return "arithmetic";
    else if (addr == 0x401153) return "not";
    else if (addr == 0x40115F) return "dup";
    else if (addr == 0x401167) return "swap";
    else if (addr == 0x401170) return "pop";
    else if (addr == 0x401176) return "pace rand 1";
    else if (addr == 0x4011A4) return "getch";
    else if (addr == 0x40119D) return "exit";
    else if (addr == 0x4011CD) return "print_int";
    else if (addr == 0x401218) return "print";
    else if (addr == 0x40123C) return "self_modify";
    else if (addr == 0x4013A6) return "secret_push";
    else if (addr == 0x4013B0) return "secret_loop";

    return "__UNKNOWN__";
}   

// ------------------------------------------------------------------------------------------------
static main()
{
    auto addr, trg_func, op1, op2, name, mnem;
    auto idx, page, pace, target;
    
    Message("[+] Stuck in the past straight disassembler started.\n");

    idx  = 0;
    page = 0;

    for (addr=0x004013DE; addr<0x00404AC8; addr=addr+0x0B)
    {
        if (idx % 0x47 == 0) {
            page = idx / 0x47;
            Message("--------------------------- Page: %2d ---------------------------\n", page);        
        }

        op1 = 0x8000;
        op2 = 0x8000;

        // Parse instruction to extract arguments:
        //      .text:00403680 90                     nop
        //      .text:00403681 90                     nop
        //      .text:00403682 6A 04                  push    4
        //      .text:00403684 B8 24 11 40 00         mov     eax, offset MATH_OP_401124
        //      .text:00403689 FF E0                  jmp     eax
        if (Byte(addr) == 0x6A) { // push byte
            op2 = Byte(addr + 1);
        }

        if (Byte(addr + 2) == 0x6A) { // xchg ax, ax
            op1 = Byte(addr + 3);
        }

        trg_func = Dword(addr + 5);
        
        // if last instructions are not mov eax, $INSN; jump eax, then something is wrong
        if (Byte(addr + 4) != 0xB8 || Word(addr + 9) != 0xE0FF) {
            Message("Error!\n");
            break;
        }

        /* make name instruction adjustments */
        name = get_func_name(trg_func);

        if (name == "nop" && op1 != 0x8000) {
            name = "push";
        }

        else if (name == "arithmetic") {
            // check operand to determine the actual arithmetic operation.
                 if (op1 == 0x00) name = "add";
            else if (op1 == 0x04) name = "sub";
            else if (op1 == 0x08) name = "mul";
            else if (op1 == 0x0C) name = "div";
            else if (op1 == 0x15) name = "mod";

            op1 = 0x8000;
        }

        else if (name == "change_pace") {
            target = 0;

                 if (op1 == 0x00) { pace = ">"; target = idx + 1; }
            else if (op1 == 0x21) { pace = "<"; target = idx - 1; }
            else if (op1 == 0x42) { pace = "v"; target = idx + 0x47; }
            else if (op1 == 0x63) { pace = "^"; target = idx - 0x47; }

            name = sprintf("pace %s %d   (target: %x)", pace, op2, target);

            op1 = 0x8000;
            op2 = 0x8000;
        }

        else if (name == "__UNKNOWN__") {
            name = Name(trg_func);
        }

        if (op1 != 0x8000) {           
            if (op1 >= 0x20 && op1 <= 0x7e) {
                mnem = sprintf("%s 0x%02x '%c'", name, op1, op1);
            } else {
                mnem = sprintf("%s %d", name, op1);
            }

            Message("%3x 0x%x: %-33s;\n", idx, addr, mnem);

        } else {
            Message("%3x 0x%x: %-33s;\n", idx, addr, name);
        }
        
        idx = idx + 1;
    }
}
// ------------------------------------------------------------------------------------------------
