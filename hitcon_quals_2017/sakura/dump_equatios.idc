// ------------------------------------------------------------------------------------------------
// HITCON CTF 2017 - Sakura (RE 300)
// ------------------------------------------------------------------------------------------------
#include <idc.idc>


// ------------------------------------------------------------------------------------------------
// Dump an index family.
//
static dump_family(fam, st, end)
{
    auto rbp = GetRegValue("rbp");            // Assume that program runs in verify()
    auto i, j, k = 1;


    Message("IDX_%d = [\n    ", fam);

    // coordinates are read in "order"
    for (i=rbp-st; i<rbp-end+1; i=i+(((fam<<3) + 0xf) & 0xf0)) {
        for (j=0; j<(fam<<3); j=j+4) {
            Message("0x%02x, ", Dword(i + j));

            if (k % 16 == 0) Message("\n    ");
            k = k + 1;
        }
    }

    Message("\n]\n\n");
}

// ------------------------------------------------------------------------------------------------
static main()
{

    Message( "Script started...\n" );

    auto n, next, addr, func, rvalue, family;

    auto i, j = 1;

    /*
     * Make sure that at the time that you run this script, rip is inside verify_555555554850()
     * and is after the initialization.
     */

    dump_family(2, 0xdd0, 0x770);                   // dump index-2 family
    dump_family(3, 0x770, 0x510);                   // dump index-3 family
    dump_family(4, 0x4f0, 0x390);                   // and so on...
    dump_family(5, 0x370, 0x220);
    dump_family(6, 0x1f0, 0x1c0);
    dump_family(8, 0x190, 0x50);


    Message("\n\equations = [\n    ");

    for ( addr=0x0000555555554850; addr!=BADADDR; ) {
        /* for each loop, you need to know the family and the r-value of the equation */

        // Do a simple pattern matching and loop for comparison of rbp-0x1e48:
        //
        // .text:00005555555569E5 83 BD B8 E1 FF FF 11    cmp     [rbp+A_1E48], 11h
        // .text:00005555555569EC 74 07                   jz      short loc_5555555569F5
        // .text:00005555555569EE C6 85 B7 E1 FF FF 00    mov     [rbp+is_correct_1E49], 0
        next   = FindBinary(addr, SEARCH_DOWN | SEARCH_NEXT, "83 BD B8 E1 FF FF");
        rvalue = Byte(next + 6);


        // Family is before rvalue. Check which of these 6 functions is invoked.
        for (i=addr; i<next; i=FindCode(i, SEARCH_DOWN | SEARCH_NEXT)) {
            func = GetFunctionName(Rnext(i, Rfirst(i)));

            if (func == "plus_0x10_55555556510E" ||
                func == "plus_0x18_555555565146" ||
                func == "plus_0x20_5555555651EE" ||
                func == "plus_0x28_5555555651B6" ||
                func == "plus_0x30_55555556517E" ||
                func == "plus_0x40_555555565226") {
                    break;
            }
        }

        // cast function to family
             if (func == "plus_0x10_55555556510E") { family = "IDX_2"; n = 2; }
        else if (func == "plus_0x18_555555565146") { family = "IDX_3"; n = 3; }
        else if (func == "plus_0x20_5555555651EE") { family = "IDX_4"; n = 4; }
        else if (func == "plus_0x28_5555555651B6") { family = "IDX_5"; n = 5; }
        else if (func == "plus_0x30_55555556517E") { family = "IDX_6"; n = 6; }
        else if (func == "plus_0x40_555555565226") { family = "IDX_8"; n = 8; }

        // print tuple
        if (next != BADADDR) {
            Message("(%s, 0x%02x, %d), ", family, rvalue, n);
        }


        if (j % 5 == 0) Message("\n    ");
        j = j + 1;


        addr = next;
        func = "";
    }

    Message("\n]\n");
}
// ------------------------------------------------------------------------------------------------
