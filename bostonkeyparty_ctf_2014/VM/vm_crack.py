#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Boston Key Party CTF 2014 - VM (RE 300)
# --------------------------------------------------------------------------------------------------
from Crypto.Cipher import AES


# --------------------------------------------------------------------------------------------------
# VM opcodes
#
vm_code = [ ord(x) for x in '503D6F05513761035B3C66154423705A0F6D3A40197E10414F03433732353D59'
    'B58058D641BC740A4C12B05C14DF6EA41C8C3AE4E6FA1D804DFD882446A263D8E8F85AB148C68B87A91B7423'
    'F92F0B65521B73BC7B2F93D9FAEAD7846C353DEABA9D57CF6BCE4128EE865314DCB4EC82B4EA249B4C0FEDD2'
    '94036503393F47232BD7A4442306800F5FFDEF845FDE1CCCAF40246E7325C0C63274C0933D2244F6732497D9'
    '53E693C089B924AB60F5C37B4F155B20158F1C3739FE131C47D8F44C3E44048C13935CADC8EAD0ED9FB3DAD3'
    '6374C30304D86A4000F6490EEDB1F8689B841B9C33F2E880DFEBBEDB98604021412C13E5C50C253405C23654'
    '1744F87492303CBC49BC4EFE8372514D358DDFA6F1A783D2E31B0456118497DD2FA58FC9E9361CE11E751A29'
    '363F65D990B37E5ED26FA55C16A4C2B5BE7CBD6A06A5F2894E7D095C11B63E70BE9C8269A2A03088E93DF025'
    '6C9518F3FFA30D2288FCF2480FFE44D29B08113059B02829B2E3C4C14F1E21EB150F17ACAE70E4856BD8840E'
    '204CF4871A0FD7F6A2D8B53102AF83D3666E1486C8097D5109881C21E89013995668E2EC29E6EF89D14252F4'
    'A6DB6220330D6242EBEC4FEADF21ADFE9F9152EE8ED09A2BFECD9A5AC538B221DBC9F507F6AF1E55DD040BB6'
    'FFFB8E396DF6BF8AAE7F90243B0EB8025E202C95E183D65F349747B105EB93B98468E24C569B96E88EDF7D87'
    'C83E79244EAB56946813468DE70C7078E1DA23169F1E4045B41DB2DA6BECF84166B59D712CB4543071032299'
    'ED1902B965F49023CAEA0FF8E723E51ADC77477D17AEF8A040430F06A70F2165A8EF4702413FB3F703EE3A3B'
    '0B9F643DEDD1F1B8AAFDB5CBB259F9DF4E93B6FDBE0468A08126F7D34521F70A03085BDFD49D65998A4CAE61'
    '2C22E426640B0517A3EA71B228E9E6B5836B7962F264B9A4C50EC87EA4A6A8435A08D1E805F8FC60F4028AF4'
    '09D8A1E18AF4B32CEE8DA24A5B9992DD8102CC1936BCBEB4FFB219636FFFFC7AB9F5BAA5D2987F66FA0FBBE9'
    '9B544B2383F0EE2FFB6669D924939CE485D880872DBE13DAEC1498C865074D6D035180DEA23122E0E87EC2C2'
    '2A5993494B43BC23CDEC036DC0E88224E257EF9B5E2F8C167957D45A72D7F48440ABB33BBF3D68B5D446BD9E'
    '46EB80C3498856E34596BF8A5296651B0911D395DD831657840EFFA2590BF2F043A58899476652E3DFC67AD4'
    '6DBF78DC8B31A0E41491827EC1D09994632FB15413CC72A1292CF7655C2AAC85253D155F5FB96D5E498C6100'
    .decode('hex')
]

# --------------------------------------------------------------------------------------------------
# Execution Context
#
class context( object ):
    pc     = 0                                      # program counter
    reg    = -1                                     # our single register
    efl    = 0                                      # EFLAGS (well, only ZF is implemented)
    mem    = [0]*0x200                              # program's memory
    keyidx = 0                                      # AES key and key index
    key    = [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf]
    rval   = 0                                      # return value upon exit
    exit   = False                                  # if it's True, stop execution
    stream = None                                   # stream for files
    trace  = []                                     # traced instructions


# --------------------------------------------------------------------------------------------------
def log(inst, ctx):                                 # log any instruction that you execute
    ctx.trace.append('.text:%04x    %s' % (ctx.pc, inst))


# --------------------------------------------------------------------------------------------------
def next_opcode( offset ):                          # calculate the next opcode
    previous = vm_code[offset - 1] if offset > 0 else 0

    return vm_code[offset] ^ previous ^ (offset % 0x0b)


# --------------------------------------------------------------------------------------------------
def mem_write( ctx ):                               # write a constant value to memory
    ctx.reg += 1
    ctx.pc  += 1
    ctx.mem[ctx.reg] = next_opcode(ctx.pc)

    log(("mem[%2d] = 0x%02x %s" % (ctx.reg, ctx.mem[ctx.reg], repr(chr(ctx.mem[ctx.reg])))), ctx)


# --------------------------------------------------------------------------------------------------
def dec( ctx ):                                     # decrement register
    ctx.reg -= 1

    log('--reg', ctx)


# --------------------------------------------------------------------------------------------------
def set_reg( ctx ):                                 # initialize register
    ctx.reg = -1

    log('reg = -1', ctx)


# --------------------------------------------------------------------------------------------------
def mem_zero( ctx ):                                # set memory
    ctx.reg += 1
    ctx.mem[ctx.reg] = 0

    log('mem[%2d] = 0' % ctx.reg, ctx)
 

# --------------------------------------------------------------------------------------------------
def mem_cmp( ctx ):                                 # compare memory with a constant
    ctx.pc += 1

    if ctx.mem[ctx.reg] == next_opcode(ctx.pc):
        ctx.efl |= 1
    else:
        ctx.efl &= 0xFFFFFFFE


    log('if (mem[%2d] = 0x%02x) == 0x%02x:' % (ctx.reg, ctx.mem[ctx.reg], next_opcode(ctx.pc)), ctx)

    ctx.reg -= 1


# --------------------------------------------------------------------------------------------------
def mem_add( ctx ):                                 # add a constant to the memory
    ctx.pc += 1
    ctx.mem[ctx.reg] = (ctx.mem[ctx.reg] + next_opcode(ctx.pc)) & 0xFF

    log('mem[%2d] += 0x%02x (mod 256)' % (ctx.reg, next_opcode(ctx.pc)), ctx)


# --------------------------------------------------------------------------------------------------
def mem_sub( ctx ):                                 # subtract a constant from the memory
    ctx.pc += 1
    ctx.mem[ctx.reg] = (ctx.mem[ctx.reg] - next_opcode(ctx.pc)) & 0xFF


    log('mem[%2d] -= 0x%02x (mod 256)' % (ctx.reg, next_opcode(ctx.pc)), ctx)


# --------------------------------------------------------------------------------------------------
def fread( ctx ):                                   # read a byte from file
    aux = ctx.stream.read(1)

    if len(aux) == 0:
        ctx.retn = 1
        ctx.exit = True

    ctx.reg += 1
    ctx.mem[ctx.reg] = ord(aux)

    log('mem[%2d] = fread() = %s (0x%x)' % (ctx.reg, repr(aux), ord(aux)), ctx)

    ctx.key[ctx.keyidx] = ord(aux)
    ctx.keyidx += 1


# --------------------------------------------------------------------------------------------------
def printf( ctx ):                                  # print to stdout
    if ctx.mem[ ctx.reg ] == 0:
        print
    else:
        print '%c' % chr(ctx.mem[ctx.reg]),         # don't print newline

    log('print %s    (reg = %d)' % (repr(chr(ctx.mem[ctx.reg])), ctx.reg), ctx)

    ctx.reg -= 1


# --------------------------------------------------------------------------------------------------
def fopen( ctx ):                                   # open a file
    try:
        st   = ctx.reg - ctx.mem[ctx.reg]           # fopen(mem[reg - mem[reg]], "r")
        name = ''

        while True:                                 # cast memory to string
            if ctx.mem[st] == 0:
                break

            name += chr(ctx.mem[st])
            st   += 1


        print "[+] Opening '%s' ..." % name

        ctx.stream = open(name, 'r')
        ctx.reg   -= ctx.mem[ctx.reg] + 1

    except IOError:
        ctx.retn = 1
        ctx.exit = True

    log('fopen("%s", "r") (reg = %d)' % (name, ctx.reg), ctx)


# --------------------------------------------------------------------------------------------------
def jmp( ctx ):                                     # goto
    ctx.pc += 1

    log('goto .text:%04x' % ctx.pc + next_opcode(ctx.pc), ctx)

    ctx.pc += next_opcode(ctx.pc)


# --------------------------------------------------------------------------------------------------
def jz( ctx ):                                      # conditional jump
    ctx.pc += 1

    log('jz .text:%04x    (EFLAGS: %x)' % (ctx.pc + next_opcode(ctx.pc), ctx.efl), ctx)

    if ctx.efl & 1 == 1:
        ctx.pc += next_opcode(ctx.pc)


# --------------------------------------------------------------------------------------------------
def jnz( ctx ):                                      # conditional jump
    ctx.pc += 1

    log('jnz .text:%04x    (EFLAGS: %x)' % (ctx.pc + next_opcode(ctx.pc), ctx.efl), ctx)

    if ctx.efl & 1 == 0:
        ctx.pc += next_opcode(ctx.pc)


# --------------------------------------------------------------------------------------------------
def retn( ctx ):                                    # return
    ctx.retn = 0
    ctx.exit = True

    log('return 0', ctx)


# --------------------------------------------------------------------------------------------------
def mem_swap( ctx ):                                # swap two memory cells
    ctx.pc  += 1

    tmp = ctx.mem[ctx.reg - next_opcode(ctx.pc)]
    ctx.mem[ctx.reg - next_opcode(ctx.pc)] = ctx.mem[ctx.reg]
    ctx.mem[ctx.reg] = tmp

    log('mem[%2d] <-> mem[%2d]' % (ctx.reg, ctx.reg - next_opcode(ctx.pc)), ctx)


# --------------------------------------------------------------------------------------------------
def mem_xor( ctx ):                                 # xor memory with a constant
    ctx.pc += 1
    ctx.mem[ctx.reg] ^= next_opcode(ctx.pc)

    log('mem[%2d] ^= 0x%02x' % (ctx.reg, next_opcode(ctx.pc)), ctx)


# --------------------------------------------------------------------------------------------------
def mem_reverse( ctx ):                             # reverse the bits of a memory cell
    aux = 0

    aux |= (ctx.mem[ ctx.reg ] & 0x01) << 7
    aux |= (ctx.mem[ ctx.reg ] & 0x02) << 5
    aux |= (ctx.mem[ ctx.reg ] & 0x04) << 3
    aux |= (ctx.mem[ ctx.reg ] & 0x08) << 1
    aux |= (ctx.mem[ ctx.reg ] & 0x10) >> 1
    aux |= (ctx.mem[ ctx.reg ] & 0x20) >> 3
    aux |= (ctx.mem[ ctx.reg ] & 0x40) >> 5
    aux |= (ctx.mem[ ctx.reg ] & 0x80) >> 7


    log('REVERSE(mem[%2d]): 0x%02x --> 0x%02x' % (ctx.reg, ctx.mem[ ctx.reg ], aux), ctx)

    ctx.mem[ ctx.reg ] = aux


# --------------------------------------------------------------------------------------------------
def mem_bitflip( ctx ):                             # flip a bit from a memory cell
    ctx.pc  += 1
    ctx.mem[ctx.reg] ^= 1 << next_opcode(ctx.pc)

    log('mem[%2d] flip %d-th bit' % (ctx.reg, next_opcode(ctx.pc)), ctx)


# --------------------------------------------------------------------------------------------------
def mem_nibble_swap( ctx ):                         # swap nibbles of a memory cell
    ctx.mem[ctx.reg] = ((ctx.mem[ctx.reg] & 0x0F) << 4) | ((ctx.mem[ctx.reg] & 0xF0) >> 4)

    log('SWAP_NIBBLE(mem[%2d]): 0x%02x' % (ctx.reg, ctx.mem[ctx.reg]), ctx)


# --------------------------------------------------------------------------------------------------
def mem_nibble_xchg( ctx ):                         # swap nibbles for 2 memory cells
    ctx.pc += 1
    aux = ctx.mem[ctx.reg]

    ctx.mem[ctx.reg] = (ctx.mem[ctx.reg] & 0xF0) | \
                        (ctx.mem[ctx.reg - next_opcode(ctx.pc)] & 0x0F)

    ctx.mem[ctx.reg - next_opcode(ctx.pc)] = (ctx.mem[ctx.reg - next_opcode(ctx.pc)] & 0xF0) | \
                                             (aux & 0x0F)

    log('XCHG_NIBBLE(mem[%2d] <--> mem[%2d])' % (ctx.reg,  ctx.reg - next_opcode(ctx.pc)), ctx)


# --------------------------------------------------------------------------------------------------
def decrypt_code( ctx ):                            # decrypt VM code
    size = 0

    ctx.pc += 1; size |= next_opcode(ctx.pc)
    ctx.pc += 1; size |= next_opcode(ctx.pc) << 8
    ctx.pc += 1; size |= next_opcode(ctx.pc) << 16
    ctx.pc += 1; size |= next_opcode(ctx.pc) << 27


    IV = '000102030405060708090a0b0c0d0e0f'.decode('hex')

    print '[+] Decrypting VM code...'
    print '[+] Key is', ctx.key


    aes = AES.new(key=''.join([chr(x) for x in ctx.key]), IV=IV, mode=AES.MODE_OFB)


    enc = [chr(x) for x in vm_code[ctx.pc+1:ctx.pc+size]]
    dec = aes.decrypt(''.join(enc))

    for i in range(len(dec)):                       # "self-modify" VM code
        vm_code[ctx.pc+1 + i] = ord(dec[i])

    log('* decrypting VM code *', ctx)


# --------------------------------------------------------------------------------------------------
def mem_not( ctx ):                                 # flip all bits of a memory cell
    ctx.mem[ ctx.reg ] = ctx.mem[ ctx.reg ] ^ 0xFF

    log('~ mem[%2d]: 0x%x' % (ctx.reg, ctx.mem[ctx.reg]), ctx)


# --------------------------------------------------------------------------------------------------
def halt( ctx ):                                    # exit()
    ctx.retn = -1
    ctx.exit = True


# --------------------------------------------------------------------------------------------------
dispatcher = {                                      # instruction dispatcher
    0x50 : mem_write,
    0x6e : mem_zero,
    0x4f : fopen,
    0x44 : decrypt_code,
    0x67 : fread,
    0x78 : mem_xor,
    0x73 : mem_swap,
    0x3d : mem_cmp,
    0x6c : jnz,
    0x13 : halt,
    0x6b : jz,
    0x70 : printf,
    0x69 : mem_not,
    0x72 : mem_reverse,
    0x74 : mem_bitflip,
    0x71 : mem_nibble_swap,
    0x61 : mem_nibble_xchg,
    0x5f : retn,
}

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    ctx = context()


    while True:
        try:
            dispatcher[ next_opcode(ctx.pc) ](ctx)  # dispatch next opcode

        except KeyError, e:
            print '[ERROR] Unknown Opcode', hex( int(str(e)) )
            break

        ctx.pc += 1

        if ctx.exit:
            break


    print "[+] Dumping trace to 'trace.txt' ..."
    file = open('trace.txt', 'w')                   # write trace to file

    for inst in ctx.trace:
        file.write(inst + '\n')

    file.close()


# --------------------------------------------------------------------------------------------------
'''
ispo@nogirl:~/ctf/boston_key_party$ ./vm_crack.py 
[+] Opening 'license.drm' ...
[+] Decrypting VM code...
[+] Key is [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
S t a g e   1   c o m p l e t e !   T h a t   w a s   e a s y ,   w a s n ' t   i t ? 
[+] Decrypting VM code...
[+] Key is [95, 39, 139, 220, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
S t a g e   2   c o m p l e t e !   K e e p   m o v i n g ! 
[+] Decrypting VM code...
[+] Key is [95, 39, 139, 220, 231, 238, 102, 82, 8, 9, 10, 11, 12, 13, 14, 15]
S t a g e   3   c o m p l e t e !   Y o u   a r e   n e a r l y   t h e r e ! 
[+] Decrypting VM code...
[+] Key is [95, 39, 139, 220, 231, 238, 102, 82, 58, 134, 191, 219, 12, 13, 14, 15]
S t a g e   4   c o m p l e t e !   H o p e   y o u   l i k e d   i t . 

[+] Decrypting VM code...
[+] Key is [95, 39, 139, 220, 231, 238, 102, 82, 58, 134, 191, 219, 48, 57, 0, 235]
N o w   y o u   c a n   h a z   k e y :   ' V m _ R e V e R s I n G _ I s _ F u N ' 
[+] Dumping trace to 'trace.txt' ...
ispo@nogirl:~/ctf/boston_key_party$ 
'''
# --------------------------------------------------------------------------------------------------
