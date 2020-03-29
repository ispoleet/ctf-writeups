// ------------------------------------------------------------------------------------------------
// CONFidence CTF 2020 - Locked PE
//
// Run this script once you hit the first BITOR command and after running
// hook_autoit_funcs.idc first.
// ------------------------------------------------------------------------------------------------
#include <idc.idc>


// ------------------------------------------------------------------------------------------------
static proc_param(param_addr) 
{
    auto idx, str, val, ptr;
    auto base, base2, base3, base4, base5, size, bytes, j;
    

    // Message("Processing param at: 0x%0x\n", param_addr);

    /* Type: Int32 */ 
    if (Dword(param_addr + 0x04) == 0xBAADF00D &&
        Qword(param_addr + 0x08) == 0x00 &&
        Dword(param_addr + 0x10) == 0x01)
    {
        // Value is at offset 0
        val = Dword(param_addr);
        str = sprintf("0x%x", val);

        if (val >= 0x20 && val <= 0x7e) {
            str = str + sprintf(" /* %c */", val);
        }            
    }

    /* Type: String */ 
    else if (Dword(param_addr + 0x00) == 0 &&
             Dword(param_addr + 0x04) == 0xBAADF00D &&
             Dword(param_addr + 0x10) == 0x04 &&
             Dword(param_addr + 0x14) == 0xBAADF00D)
    {
        // String pointer is at offset 8 and and from there the actual string is at offset 0
        base  = Qword(param_addr + 0x08);
        base2 = Qword(base);

        str = "\"" + GetString(base2, -1, ASCSTR_UNICODE) + "\"";
    }

    /* Type: Binary */ 
    else if (Qword(param_addr + 0x08) == 0 &&
             Dword(param_addr + 0x10) == 0x0B &&
             Dword(param_addr + 0x14) == 0xBAADF00D)
    {
        // Binary index is at offset 0
        base = Qword(param_addr);
        size  = Dword(base);
        bytes = Qword(base + 0x8);

        str = "{";
        // Format: size (4B) | BAADF00D | actual bytes
        for (j=0; j<size; j++) {
            str = str + sprintf("0x%x", Byte(bytes + j));

            if (j != size -1) {
                str = str + ", ";
            }
        }

        str = str + "}";
    }

    /* Type: Array */ 
    else if (Qword(param_addr + 0x08) == 0 &&
             Dword(param_addr + 0x10) == 0x6 &&
             Dword(param_addr + 0x14) == 0xBAADF00D)
    {
        // Array index is at offset 0        
        base = Qword(param_addr);
        // Message("Base: 0x%x\n", base);

        if (Qword(base + 0x08) == 0 &&
            Dword(base + 0x10) == 0x05 &&
            Dword(base + 0x14) == 0xBAADF00D) 
        {    
            base2 = Qword(base);
            // Message("Base2: 0x%x\n", base2);

            str = "{";

            // 0x100 is arbitrary
            for (ptr=0; ptr<0x100; ptr=ptr + 8) {
                base3 = Qword(base2 + ptr);
                // Message("Base3: 0x%x\n", base3);

                if (base3 == 0xABABABABABABABAB) {
                    break;                    
                }
            
                if (Dword(base3 + 0x04) == 0xBAADF00D &&
                    Dword(base3 + 0x10) == 0x08 &&                
                    Dword(base3 + 0x18) == 0xBAADF00D) 
                {
                    base4 = Qword(base3 + 0x08);
                    size  = Dword(base3 + 0x10); // maybe +14 is size?
                    // Message("Base4: 0x%x (size: %d)\n", base4, size);

                    for (j=0; j<size; j=j + 1) {
                        // or, until you hit 0xABABABABABABABAB
                        base5 = Qword(base4 + j * 8);
                        // Message("Base5: 0x%x\n", base5);

                        str = str + proc_param(base5);

                        if (j != size - 1) {
                            str = str + ", ";
                        }
                    }
                }
            }

            str = str + "}";   
        }
    }

    else {
        return sprintf("U_%x", param_addr);
    }


    return str;
}

// ------------------------------------------------------------------------------------------------
static main() 
{
    auto func, nargs, size, argv, param, i, j, output, dummy_bp, sim_runs;
        
    Message("[+] Trace AutoIt Function simulation started.\n");
    
    // Set a dummy breakpoint (it changes on every run; PIE) and number of simulations
    dummy_bp = 0;//0x13F80ABAF;
    sim_runs = 1;//100;
       
    for (i=0; i<sim_runs; i=i+1)
    {
        // Get function name (from comment created by hook_autoit_funcs.idc) 
        // and access function parameters
        func  = Comment(GetRegValue("rip"));
        nargs = Dword(GetRegValue("rdx") + 0x10);
        size  = 8;

        output = func + "(";

        // You can also stop once you hit 0xBAADFOOD
        for (j=0; j<nargs; j=j+1) {
            argv = Qword(GetRegValue("rdx") + 0x08);

            param = Dword(argv + j*size);
            
            output = output + proc_param(param);

            if (j != nargs - 1) {
                output = output + ", ";
            }
        }
        
        output = output + ")";

        Message("%3d: %s\n", i, output);

        // Run until you hit the next breakpoint (move on the next instruction)
        if (dummy_bp) {
            RunTo(dummy_bp);
            GetDebuggerEvent(WFNE_SUSP, -1);
        }
    }
}
// ------------------------------------------------------------------------------------------------
/*
[+] Trace AutoIt Function simulation started.
  0: OPT("WinTitleMatchMode", 0x2)
  1: CLIPPUT("")
  2: STRINGTOASCIIARRAY("oOoOooOO")
....
 48: STRINGTOASCIIARRAY("oOoOooOO")
 49: BINARYLEN({0x23, 0x20, 0xc, 0x24, 0xa, 0xb, 0x6f, 0x1f, 0x2a})
 50: STRINGTOASCIIARRAY("oOoOooOO")
 51: BINARYLEN({0x26, 0x21, 0xc, 0x20, 0x1d, 0x1d, 0x2a, 0x2c, 0x1b, 0x6e})
 52: MSGBOX(0x0, "Locked PE", "Incorrect!")
*/
// ------------------------------------------------------------------------------------------------
