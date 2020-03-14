#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# Teaser CONFidence CTF 2019 - oldschool (RE 128)
# --------------------------------------------------------------------------------------------------
import string


# --------------------------------------------------------------------------------------------------
# create a drawing from a flag.
#
def draw_flag(flag):
    buf = [0]*256

    si = 0x50                                   # 'P'

    for i in xrange(0, len(flag), 2):
        val = int(flag[i:i+2], 16)

        for j in xrange(4):
            # Shift column (0 <- Move left, 1 <- Move right)
            if val & 1 == 0:
                if si % 0x12: si -= 1
            else:
                if si % 0x12 != 0x10: si += 1

            # Shift row (0 <- Move p, 1 <- Move down)
            if val & 2 == 0:
                if si >= 0x12: si -= 0x12
            else:
                if si <= 0x90: si += 0x12

            buf[si] += 1                        # increment count
            val >>= 2                           # move on the next pair

        print 'Final si: 0x%02x (%d, %d)' % (si, si / 0x12, si % 0x12)

    for i in xrange(8):        
        print '%2d ' % i, buf[i*18:(i+1)*18]

    # Replace counts with flag lettters
    for i in xrange(0xa1):
        if buf[i] <= 0x0d:  
            buf[i] = ord(' p4{krule_ctf}'[buf[i]])
        else:
            buf[i] = 0x5E                       # '^'

    buf[si]   = 0x45                            # 'E' (end)
    buf[0x50] = 0x53                            # 'S' (start)

    print '=================================================='
    for i in xrange(9):
        line = buf[i*18:(i+1)*18]
        print ''.join(chr(x) for x in line)
    print '=================================================='


# --------------------------------------------------------------------------------------------------
# convert a route sequence to a string.
#
def route_to_str(sequence):
    # if we don't have complete bytes, abort
    if len(sequence) % 8:
        return None

    route = []
    for i in xrange(0, len(sequence), 8):
        byte_str = ''
        # for each pair in the byte
        for j in xrange(0, 8, 2):
            # prepend sequence to the byte string
            byte_str = sequence[i+j:i+j+2] + byte_str

        route.append(int(byte_str, 2))

    return ''.join(chr(r) for r in route)


# --------------------------------------------------------------------------------------------------
# crack a drawing and recover the flag.
#
def crack_draw(draw_map, y, x, end_y, end_x, sequence='', depth=0):
    global ctr                                   # make counter static

    # optimization: if you have part of the solution check if the first characters of
    # the flag match.
    route = route_to_str(sequence)
    if route:
        if (len(route) == 1 and route[0] != 'p' or
            len(route) == 2 and route[1] != '4' or
            len(route) == 3 and route[2] != '{' or
            len(route) == 9 and route[8] != '}'):
                return

    # print 'Depth: %2d, Location: (%d,%2d). Value: %d. Dir: %s' % (depth, y, x, map_[y][x], dir_)

    # -------------------------------------------------------------------------
    # check if we are at the end location and depth is 36 (we have 18 digits)
    # -------------------------------------------------------------------------
    if depth == 36 and y == end_y and x == end_x:
        # store the old value of the end location
        bkp, draw_map[y][x] = draw_map[y][x], 0

        # check if table is full of zeros.
        if sum(sum(m) for m in draw_map) == 0:
            # Yes, we have a solution.
            route = route_to_str(sequence)

            # Hint: "The flag in Oldschool challenge should match p4{[0-9a-z]+}."
            if all(ch in string.ascii_lowercase + string.digits + '{}' for ch in route):
                print "[+] %2d. Flag found! %s --> %s" % (
                        ctr, route, ''.join('%02x' % ord(ch) for ch in route))

                ctr += 1

        draw_map[y][x] = bkp

        return

    # -------------------------------------------------------------------------
    # the 4 possible directions to move
    # -------------------------------------------------------------------------
    dirs = [
        (x - 1 if x > 0  else 0,  y - 1 if y > 0 else 0, '00'),
        (x - 1 if x > 0  else 0,  y + 1 if y < 8 else 8, '10'),
        (x + 1 if x < 16 else 16, y - 1 if y > 0 else 0, '01'),
        (x + 1 if x < 16 else 16, y + 1 if y < 8 else 8, '11')
    ]

    for nxt_x, nxt_y, seq in dirs:
        # if there count to move on do it
        if draw_map[nxt_y][nxt_x] > 0:
            draw_map[nxt_y][nxt_x] -= 1

            crack_draw(draw_map, nxt_y, nxt_x, end_y, end_x, sequence + seq, depth + 1)
            
            draw_map[nxt_y][nxt_x] += 1

    # print 'Return from: %d' % depth


# --------------------------------------------------------------------------------------------------
# main()
#
if __name__ == "__main__":
    print '[+] Oldschool crack started.'

    # -------------------------------------------------------------------------
    # draw a test flag
    # -------------------------------------------------------------------------
    flag = '1234567890abcdef12'
    print '[+] Drawing a test flag:', flag
  
    draw_flag(flag)

    print
    print

    # -------------------------------------------------------------------------
    # crack the target drawing
    # -------------------------------------------------------------------------
    drawing_1 = [
        '        4 {4pp   ',
        '       p {k4{ E  ',
        '      p 44p{ p   ',
        '       4 p       ',
        '        S        ',
        '                 ',
        '                 ',
        '                 ',
        '                 '
       ]
 
    # NOTE: this drawing doesn't have a p4{...} solution so crack_draw() won't find it unless
    # you remove the ascii checks (Solution: 0000ffffffffffffff).
    drawing_2 = [
            'ppppp            ',
            ' p   p           ',
            '  p   p          ',
            '   p   p         ',
            '    p   S        ',
            '     p           ',
            '      p          ',
            '       p         ',
            '        ppppppppE']

    print '[+] Breaking drawing:'

    drawing  = drawing_1
    draw_map = []

    print '='*50
    for row in drawing:
        print row
        # anything more than '}' is '^'
        draw_map.append([' p4{krule_ctf}^'.find(ch) for ch in row])
    print '='*50

    # set start location 'S' (always 0x50)
    draw_map[4][8] = 0

    # look for end ('E') location
    for i in xrange(len(drawing)):
        if drawing[i].find('E') != -1:
            end_x = drawing[i].find('E')
            end_y = i
            break

    # The max possible count is 36
    draw_map[end_y][end_x] = 36
    ctr = 0

    print '[+] End location (%d, %d)' % (end_y, end_x)
    print '[+] Starting recursion ....'
    
    crack_draw(draw_map, 4, 8, end_y, end_x)

    print '[+] Program finished!'
    print '[+] Bye bye :)'

# --------------------------------------------------------------------------------------------------
'''
ispo@nogirl:~/ctf/ctf-writeups/confidence_ctf_2019/oldschool$ time ./oldschool_crack.py
[+] Oldschool crack started.
[+] Drawing a test flag: 1234567890abcdef12
Final si: 0x2a (2, 6)
Final si: 0x06 (0, 6)
Final si: 0x08 (0, 8)
Final si: 0x1a (1, 8)
Final si: 0x18 (1, 6)
Final si: 0x5e (5, 4)
Final si: 0x60 (5, 6)
Final si: 0x98 (8, 8)
Final si: 0x60 (5, 6)
 0  [0, 0, 0, 0, 0, 0, 4, 4, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
 1  [0, 0, 0, 0, 0, 2, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
 2  [0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
 3  [0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
 4  [0, 0, 0, 0, 0, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
 5  [0, 0, 0, 0, 1, 0, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
 6  [0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
 7  [0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
==================================================
      kkp         
     44pp         
      p4          
      pp          
     {p S         
    p Ep          
       4          
      p p         
       4p        
==================================================


[+] Breaking drawing:
==================================================
        4 {4pp   
       p {k4{ E  
      p 44p{ p   
       4 p       
        S        
                 
                 
                 
                 
==================================================
[+] End location (1, 14)
[+] Starting recursion ....
[+]  0. Flag found! p4{4qib6} --> 70347b34716962367d
[+]  1. Flag found! p4{4qibc} --> 70347b34716962637d
[+]  2. Flag found! p4{4qi2f} --> 70347b34716932667d
[+]  3. Flag found! p4{tib61} --> 70347b74696236317d
[+]  4. Flag found! p4{tibc1} --> 70347b74696263317d
[+]  5. Flag found! p4{ti2f1} --> 70347b74693266317d
[+]  6. Flag found! p4{aqib6} --> 70347b61716962367d
[+]  7. Flag found! p4{aqibc} --> 70347b61716962637d
[+]  8. Flag found! p4{aqi2f} --> 70347b61716932667d
[+]  9. Flag found! p4{qib6a} --> 70347b71696236617d
[+] 10. Flag found! p4{qibca} --> 70347b71696263617d
[+] 11. Flag found! p4{qi2fa} --> 70347b71693266617d
[+] Program finished!
[+] Bye bye :)

real    0m2.420s
user    0m2.412s
sys 0m0.008s
'''
# --------------------------------------------------------------------------------------------------
