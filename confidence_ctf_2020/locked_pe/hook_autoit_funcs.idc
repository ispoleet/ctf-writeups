// ------------------------------------------------------------------------------------------------
#include <idc.idc>


// ------------------------------------------------------------------------------------------------
static read_string(addr) 
{
    auto idx, str;

    str = "";
    for (idx=addr; Byte(idx)!=0; idx=idx+2)
    {
        str = sprintf("%s%c", str, Byte(idx));
    }

    return str;
}

// ------------------------------------------------------------------------------------------------
static main() 
{
    auto tbl_start, index, addr, func, str;
    
    Message("[+] Hook AutoIt Functions started.\n");

    /* rename functions from the table */
    tbl_start = 0x1400BDA30;

    for (index=tbl_start; index<tbl_start+0x3F58; index=index + 0x28)
    {
        Message("Index: 0x%x:\n", index);

        // Name the location
        addr = Qword(index);
        Message("\tLocation Name '%s' at 0x%x\n", read_string(addr), addr);

        str = sprintf("%s_%x", read_string(addr), addr);
        MakeNameEx(index, str, SN_NOCHECK);               
        
        // Rename function
        func = Qword(index + 8);
        Message("\tFunction Name '%s' at 0x%x\n", Name(func), func);

        str = sprintf("%s_%x", read_string(addr), func);
        MakeNameEx(func, str, SN_NOCHECK);

        // Set a break point and add a comment with function name
        AddBpt(func);
        MakeComm(func, read_string(addr));
    }
}
// ------------------------------------------------------------------------------------------------
/*
[+] Hook AutoIt Functions started.
Index: 0x13fe1da30:
    Location Name 'ABS' at 0x13fe0c268
    Function Name 'ABS_13fd48620' at 0x13fd48620
Index: 0x13fe1da58:
    Location Name 'ACOS' at 0x13fdee130
    Function Name 'ACOS_13fdc5c70' at 0x13fdc5c70
Index: 0x13fe1da80:
    Location Name 'ADLIBREGISTER' at 0x13fdecbd0
    Function Name 'ADLIBREGISTER_13fd48664' at 0x13fd48664
...
Index: 0x13fe21950:
    Location Name 'WINWAITCLOSE' at 0x13fded010
    Function Name 'WINWAITCLOSE_13fdddefc' at 0x13fdddefc
Index: 0x13fe21978:
    Location Name 'WINWAITNOTACTIVE' at 0x13fdec298
    Function Name 'WINWAITNOTACTIVE_13fdddf6c' at 0x13fdddf6c
*/
// ------------------------------------------------------------------------------------------------
