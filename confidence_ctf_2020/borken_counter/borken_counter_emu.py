#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Teaser CONFidence CTF 2020 - Borken Counter (Reversing 207)
# --------------------------------------------------------------------------------------------------
import struct
import sys


vm_prog = [
    ["9", "5", "5", "+", "*", "1", "-", "v", ")", " "],
    ["v", "_", "#", " ", " ", " ", "#", "<", "v", " "],
    ["1", " ", "v", "<", "v", "<", "v", "<", "#", " "],
    ["+", "!", ":", "g", "/", "9", "1", "2", "D", " "],
    ["0", "`", "0", "0", "\\",":", "+", "g", "#", " "],
    ["0", "*", "8", "0", "9", "g", "+", "%", "U", " "],
    ["p", "5", "g", "p", "%", "0", "0", "9", "#", " "],
    [" ", "^", "<", "^", "<", "^", "<", "\\","C", " "],
    [">", "0", "0", "g", ":", "9", "/", "^", " ", " "],
    ["v", "$", "U", "#", "D", "#", "K", "#", "<", " "],
    ["s", " ", " ", "s", "/", "7", "Y", "\\","s", " "],
    [" ", " ", " ", '"', " ", " ", " ", "7", " ", " "],
    [" ", " ", " ", " ", " ", " ", " ", "*", " ", " "],
    ["s", "!", " ", " ", " ", "!", "!", ".", "9", " "],
    [" ", "s", ".", "\\","s", " ", " ", "[", " ", " "],
    [" ", "6", " ", " ", "s", " ", ";", "[", " ", " "],
    [" ", "d", " ", " ", " ", " ", "Y", "[", " ", " "],
    [" ", ".", " ", " ", " ", " ", ",", " ", " ", " "],
    [" ", "(", " ", " ", ";", "/", "[", " ", " ", " "],
    [" ", ";", ".", "6", "m", "/", "[", "5", " ", " "],
    [";", "{", "7", "2", "2", "(", "*", "y", " ", " "],
    ["s", "5", "d", "6", ".", "!", "!", "9", " ", " "],
    [";", "1", "'", "*", "+", "=", " ", " ", " ", " "]
]

# --------------------------------------------------------------------------------------------------



if __name__ == "__main__":
    qword = lambda value: struct.pack("<Q", value)

    print '[+] Borken Counter Emulator started ...'

    stack = []
    x, y = 0, 0
    x_dir, y_dir = 1, 0
    prev_x, prev_y = 0, 0
    halt = False

    stdin_stream = "ISPO" + "\n"
    stdout_stream = ''

    i = 0
    while halt == False:
        mnem = ''

        opcode = vm_prog[y][x]

        # ---------------------------------------------------------------------
        # Stack
        # ---------------------------------------------------------------------
        if opcode in '0123456789':
            stack.append(ord(opcode) - 48)
            mnem = 'push %c' % opcode
        
        elif opcode == '$':
            stack.pop()
            mnem = 'pop'

        # ---------------------------------------------------------------------
        # Arithmetic
        # ---------------------------------------------------------------------
        elif opcode == '+':
            stack.append(stack.pop() + stack.pop())
            mnem = 'add'

        elif opcode == '-':
            a, b = stack.pop(), stack.pop()
            stack.append(b - a)
            mnem = 'sub'

        elif opcode == '*':
            stack.append(stack.pop() * stack.pop())
            mnem = 'mul'

        elif opcode == '/':
            a, b = stack.pop(), stack.pop()
            stack.append(b / a)
            mnem = 'div'

        elif opcode == '%':
            a, b = stack.pop(), stack.pop()
            stack.append(b % a)
            mnem = 'mod'            

        # ---------------------------------------------------------------------
        # Direction
        # ---------------------------------------------------------------------
        elif opcode == '>':
            mnem = 'dir right'
            x_dir, y_dir = 1, 0

        elif opcode == '<':
            mnem = 'dir left'
            x_dir, y_dir = -1, 0

        elif opcode == 'v':
            mnem = 'dir down'
            x_dir, y_dir = 0, 1

        elif opcode == '^':
            mnem = 'dir up'
            x_dir, y_dir = 0, -1

        # ---------------------------------------------------------------------
        # Memory Access
        # ---------------------------------------------------------------------
        elif opcode == 'p':
            a, b = stack.pop(), stack.pop()
            v    = stack.pop()

            vm_prog[b][a] = chr(v)

            mnem = '*(%d, %d) = %x' % (b, a, v)
            
        elif opcode == 'g':
            a, b = stack.pop(), stack.pop()
            stack.append(ord(vm_prog[b][a]))

            mnem = 'push *(%d, %d)' % (b, a)

        # ---------------------------------------------------------------------
        # Comparison
        # ---------------------------------------------------------------------
        elif opcode == '`':
            a, b = stack.pop(), stack.pop()
            stack.append(1 if a < b else 0)

            mnem = 'cmp below (%x < %x)?' % (a, b)

        elif opcode == '!':
            a = stack.pop()
            stack.append(1 if a == 0 else 0)

            mnem = 'not'

        # ---------------------------------------------------------------------
        # Control Flow
        # ---------------------------------------------------------------------
        elif opcode == '_':
            a = stack.pop()
            x_dir = 1 if a == 0 else -1
            y_dir = 0

            mnem = 'jz right (dir: %c)' % ('>' if a == 0 else '<')

        elif opcode == '|':
            a = stack.pop()
            x_dir = 0
            y_dir = 1 if a == 0 else -1

            mnem = 'jz down (dir: %c)' % ('v' if a == 0 else '^')

        # ---------------------------------------------------------------------
        # I/O
        # ---------------------------------------------------------------------
        elif opcode == '~':
            stack.append(ord(stdin_stream[0]))
            mnem = 'read char (%c)' % stdin_stream[0]

            stdin_stream = stdin_stream[1:]

        elif opcode == '.':
            a = stack.pop()
            mnem = 'print %ld (0x%x)' % (a, a)

            stdout_stream += '%ld ' % a

        # ---------------------------------------------------------------------
        # Miscellaneous
        # ---------------------------------------------------------------------
        elif opcode == ':':
            a = stack.pop()
            stack.append(a)
            stack.append(a)

            mnem = 'dup'

        elif opcode == '\\':
            a, b = stack.pop(), stack.pop()
            stack.append(a)
            stack.append(b)

            mnem = 'swap'

        elif opcode == '#':            
            x += x_dir
            y += y_dir
            mnem = 'skip (%d, %d)' % (y, x)

        elif opcode == ' ':
            pass
            mnem = 'nop'

        elif opcode == '@':
            halt = True
            mnem = 'return'


        else:
            mnem = "unkn0wn: '%c'" % opcode
            halt = True

        x += x_dir
        y += y_dir
        i += 1

        print "%5d: (%d,%2d) %-20s S:[%s]" % (
                i, prev_y, prev_x, mnem, ','.join('%02x' % x for x in stack))

        prev_x, prev_y = x, y

    print '[+] Final VM Output:'
    print "================================================================"
    print stdout_stream
    print "================================================================"


# --------------------------------------------------------------------------------------------------
'''
[+] Borken Counter Emulator started ...
    1: (0, 0) push 9               S:[09]
    2: (0, 1) push 5               S:[09,05]
    3: (0, 2) push 5               S:[09,05,05]
    4: (0, 3) add                  S:[09,0a]
    5: (0, 4) mul                  S:[5a]
    6: (0, 5) push 1               S:[5a,01]
    7: (0, 6) sub                  S:[59]
....
 7656: (20, 5) add                  S:[00,00,00,00,0a,0a,0a]
 7657: (20, 6) sub                  S:[00,00,00,00,0a,00]
 7658: (20, 7) jz down (dir: v)     S:[00,00,00,00,0a]
 7659: (21, 7) dir left             S:[00,00,00,00,0a]
 7660: (21, 6) pop                  S:[00,00,00,00]
 7661: (21, 5) pop                  S:[00,00,00]
 7662: (21, 4) push 1               S:[00,00,00,01]
 7663: (21, 3) push 9               S:[00,00,00,01,09]
 7664: (21, 2) push *(1, 9)         S:[00,00,00,2e]
 7665: (21, 1) push 8               S:[00,00,00,2e,08]
 7666: (21, 0) dir down             S:[00,00,00,2e,08]
 7667: (22, 0) dir right            S:[00,00,00,2e,08]
 7668: (22, 1) push 4               S:[00,00,00,2e,08,04]
 7669: (22, 2) mul                  S:[00,00,00,2e,20]
 7670: (22, 3) sub                  S:[00,00,00,0e]
 7671: (22, 4) print 14 (0xe)       S:[00,00,00]
 7672: (22, 5) return               S:[00,00,00]
[+] Final VM Output:
================================================================
14 
================================================================
'''
# --------------------------------------------------------------------------------------------------
