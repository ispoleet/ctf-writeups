// ------------------------------------------------------------------------------------------------
/*
** Small script to set break points and comments to every instructions in the matrix
** (debugging only).
*/
// ------------------------------------------------------------------------------------------------
#include <idc.idc>


// ------------------------------------------------------------------------------------------------
static main()
{
    auto addr, idx;

    Message("[+] Stuck in the past add bp started.\n");

    for (addr=0x004013DE, idx=0; addr<0x00404AC8; addr=addr+0x0B, idx=idx + 1)
    {
        // Delete any previous break points (if any)
        DelBpt(addr);

        MakeCode(addr);
        MakeCode(addr+2);

        // Skip nops
        if (Dword(addr) == 0x90909090 && Dword(addr + 5) == 0x401027) {
            continue;
        }

        // Skip change pace instructions
        else if (Dword(addr + 5) == 0x4010F6) {
            continue;
        }

        AddBpt(addr);
        MakeComm(addr + 2, sprintf("pc: 0x%x (line: %d, page: %d)", idx, idx % 0x47, idx / 0x47));
        DelBpt(addr);

    }
}
// ------------------------------------------------------------------------------------------------
