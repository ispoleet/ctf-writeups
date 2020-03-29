// ------------------------------------------------------------------------------------------------
#include <idc.idc>


// ------------------------------------------------------------------------------------------------
static decode_secret_single(addr) {
    auto insn_addr;
    auto secret_val;

    insn_addr = Dword(addr + 5);

    if (insn_addr == 0x401027) {
        if (Byte(addr + 2) == 0x90) secret_val = ' ';
        else {
            if (Byte(addr) == 0x66) secret_val = Byte(addr + 3) + 0x30;
            else secret_val = Byte(addr + 3);
        }
    }

    else if (insn_addr == 0x4010F6) {
             if (Byte(addr + 3) == 0x00) secret_val = '>';
        else if (Byte(addr + 3) == 0x21) secret_val = '<';
        else if (Byte(addr + 3) == 0x42) secret_val = 'v';
        else if (Byte(addr + 3) == 0x63) secret_val = '^';
        else                             secret_val = '#';
    }

    else if (insn_addr == 0x401124) {
             if (Byte(addr + 3) == 0x00) secret_val = '+';
        else if (Byte(addr + 3) == 0x04) secret_val = '-';
        else if (Byte(addr + 3) == 0x08) secret_val = '*';
        else if (Byte(addr + 3) == 0x0C) secret_val = '/';
        else                             secret_val = '%';
    }

    else {
        insn_addr = insn_addr + 0x5100;

             if (insn_addr == 0x4061FE) secret_val = '_';
        else if (insn_addr == 0x406211) secret_val = '|';
        else if (insn_addr == 0x406253) secret_val = '!';
        else if (insn_addr == 0x40625F) secret_val = ':';
        else if (insn_addr == 0x406267) secret_val = '\\';
        else if (insn_addr == 0x406270) secret_val = '$';
        else if (insn_addr == 0x406276) secret_val = '?';
        else if (insn_addr == 0x40629D) secret_val = '@';
        else if (insn_addr == 0x4062A4) secret_val = '~';
        else if (insn_addr == 0x4062CD) secret_val = '.';
        else if (insn_addr == 0x406318) secret_val = ',';
        else if (insn_addr == 0x40633C) secret_val = 'p';
        else if (insn_addr == 0x4064A6) secret_val = 'g';
        else if (insn_addr == 0x4064B0) secret_val = '"';
        else {
            secret_val = -1;
        }
    }

    if (secret_val >= 0x20 && secret_val <= 0x7e) {
        Message("\tSecret Value: 0x%02x or '%c'\n", secret_val, secret_val);    
    } else {
        Message("\tSecret Value: 0x%02x\n", secret_val);    
    }
       
    return secret_val;
}

// ------------------------------------------------------------------------------------------------
static decode_secret(start_addr, step) {
    auto addr = start_addr;
    auto insn_addr;
    auto secret_val;


    Message("Decoding secret values for address 0x%x with step 0x%x:\n", start_addr, step);

    for (;;) {
        secret_val = decode_secret_single(addr);        

        if (secret_val == '"') {
            break;
        }

        addr = addr + step*0xB;
    }
}   

// ------------------------------------------------------------------------------------------------
static main()
{
    auto idx;

    Message("[+] Stuck in the past decoder started.\n");

    // Decode welcome message
    decode_secret(0x401533, -1);

    // Decode badboy message
    decode_secret(0x404020, -1);

    // Decode goodboy message
    decode_secret(0x40458a, -1);

    Message("Decoding secret values for single instructions:\n");

    decode_secret_single(0x4013DE + (2 + 5*0x47)*0xB);
    decode_secret_single(0x4013DE + (0 + 2*0x47)*0xB);
    decode_secret_single(0x4013DE + (0 + 4*0x47)*0xB);
    decode_secret_single(0x4013DE + (1 + 4*0x47)*0xB);
    decode_secret_single(0x4013DE + (0 + 2*0x47)*0xB);
    decode_secret_single(0x4013DE + (2 + 0*0x47)*0xB);

    decode_secret_single(0x4013DE + (18 + 11*0x47)*0xB);

    Message("Decoding encoded flag:\n");
    
    for (idx=0; idx<0x1c+1; idx=idx+1) {
        decode_secret_single(0x4013DE + (2+idx + 5*0x47)*0xB);
    }
}
// ------------------------------------------------------------------------------------------------
/*
[+] Stuck in the past decoder started.
Decoding secret values for address 0x401533 with step 0xffffffff:
    Secret Value: 0x3a or ':'
    Secret Value: 0x64 or 'd'
    Secret Value: 0x72 or 'r'
    Secret Value: 0x6f or 'o'
    Secret Value: 0x77 or 'w'
    Secret Value: 0x73 or 's'
    Secret Value: 0x73 or 's'
    Secret Value: 0x61 or 'a'
    Secret Value: 0x70 or 'p'
    Secret Value: 0x20 or ' '
    Secret Value: 0x65 or 'e'
    Secret Value: 0x70 or 'p'
    Secret Value: 0x79 or 'y'
    Secret Value: 0x54 or 'T'
    Secret Value: 0x22 or '"'
Decoding secret values for address 0x404020 with step 0xffffffff:
    Secret Value: 0x21 or '!'
    Secret Value: 0x67 or 'g'
    Secret Value: 0x6e or 'n'
    Secret Value: 0x6f or 'o'
    Secret Value: 0x72 or 'r'
    Secret Value: 0x57 or 'W'
    Secret Value: 0x22 or '"'
Decoding secret values for address 0x40458a with step 0xffffffff:
    Secret Value: 0x21 or '!'
    Secret Value: 0x21 or '!'
    Secret Value: 0x21 or '!'
    Secret Value: 0x7a or 'z'
    Secret Value: 0x74 or 't'
    Secret Value: 0x61 or 'a'
    Secret Value: 0x72 or 'r'
    Secret Value: 0x47 or 'G'
    Secret Value: 0x22 or '"'
Decoding secret values for single instructions:
    Secret Value: 0x3c or '<'
    Secret Value: 0x20 or ' '
    Secret Value: 0x5f or '_'
    Secret Value: 0x61 or 'a'
    Secret Value: 0x20 or ' '
    Secret Value: 0x2c or ','
    Secret Value: 0x32 or '2'
Decoding encoded flag:
    Secret Value: 0x3c or '<'
    Secret Value: 0x25 or '%'
    Secret Value: 0x2d or '-'
    Secret Value: 0x33 or '3'
    Secret Value: 0x71 or 'q'
    Secret Value: 0x36 or '6'
    Secret Value: 0x5f or '_'
    Secret Value: 0x2e or '.'
    Secret Value: 0x2d or '-'
    Secret Value: 0x2d or '-'
    Secret Value: 0x72 or 'r'
    Secret Value: 0x29 or ')'
    Secret Value: 0x5f or '_'
    Secret Value: 0x74 or 't'
    Secret Value: 0x38 or '8'
    Secret Value: 0x61 or 'a'
    Secret Value: 0x32 or '2'
    Secret Value: 0x5f or '_'
    Secret Value: 0x73 or 's'
    Secret Value: 0x22 or '"'
    Secret Value: 0x27 or '''
    Secret Value: 0x24 or '$'
    Secret Value: 0x23 or '#'
    Secret Value: 0x32 or '2'
    Secret Value: 0x31 or '1'
    Secret Value: 0x3a or ':'
    Secret Value: 0x75 or 'u'
    Secret Value: 0x31 or '1'
    Secret Value: 0x20 or ' '
*/
// ------------------------------------------------------------------------------------------------
