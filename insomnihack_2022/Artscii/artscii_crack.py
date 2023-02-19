#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Insomni'Hack Teaser CTF 2022 - Artscii (Misc 200)
# ----------------------------------------------------------------------------------------
import re
import art
import textwrap


# ----------------------------------------------------------------------------------------
# Original code
# ----------------------------------------------------------------------------------------
def mergeLines(line1,line2):
    line = list(map(lambda xy: " " if xy[0] == xy[1] else "#", zip(line1, line2)))
    # line = list(map(lambda xy: " " if xy[0] == xy[1] else "D", zip(line1, line2)))
    #print(f"MERGING:{line1}|{line2}~>{''.join(line)}")
    return ''.join(line)


def mergeText(text1, text2):
    a = text1.split("\n")
    b = text2.split("\n")
    c = []
    for j in range(8):
        c.append(mergeLines(a[j],b[j]))
    return '\n'.join(c) 

'''
with open("flag.txt") as f:
    flag = f.readline()
    assert(flag[0:4]=="INS{" and flag[-1]=="}")
    content = flag[4:-1]
    assert(re.search(r'^[A-Z1-9_]*$', content))
    assert(content.count("_") == 2)
    content = content.replace("_","\n")

i = 0
while i<3:
    text = art.text2art(content, font="rnd-medium", chr_ignore=False)
    if re.search(r'^[ #\n]*$', text) and text.count('\n') == 24:
        print(text)
        if i == 0:
            res = text
        else:
            res = mergeText(res,text)
        i = i+1

open('output.txt', 'w').write(res)
'''


# ----------------------------------------------------------------------------------------
# Ispo code
# ----------------------------------------------------------------------------------------
def get_matched_columns(word1, word2, depth=1):
    """Returns the number of columns that are equal in `word1` and `word2`."""
    lines1 = word1.splitlines()
    lines2 = word2.splitlines()

    assert(len(lines1) == len(lines2))
    
    # We assume no out-of-bounds execption is raised here.
    for col in range(min(len(lines1[0]), len(lines2[0]))):
        if all(lines1[i][col] == lines2[i][col] for i in range(len(lines1))):
            # Columns are equal. Move on.
            pass
        else:
            return col  # Columns are not equal. 

    # All columns are equal.
    return col + 1
    

# ----------------------------------------------------------------------------------------
def find_font_combo(known_word, nlines=1):
    """Brute force all-3 combinations to find which one produces the `known_word`."""
    print('[+] Searching for font combination ...')

    first_line = textwrap.dedent('''
        ##   ##  #     ####  #    #  ##  
        ### ###  # #  # ## ####  ##### ##
        #######  ##    ## ##    ###     #
        #### ##  ##     ## #    ##   #   
        #    ##  ##       ##    ##   #  #
        #    ##  # #  # # ##### #### ####
        ##  ###  #      ## ###   ##  #   
        ##   ##  ##     ####      # ##   ''')[1:]  # Drop 1st newline.    

    first_line_cols = len(first_line.split('\n')[0])
    font_list = art.FONT_NAMES 
    cnt = 0

    for font1 in font_list: 
        text1 = art.text2art(known_word, font=font1, chr_ignore=False)
        if not (re.search(r'^[ #\n]*$', text1) and text1.count('\n') == 8*nlines):
            continue

        for font2 in font_list:
            if font1 == font2:
                continue  # Fonts must be different.

            text2 = art.text2art(known_word, font=font2, chr_ignore=False)
            if not (re.search(r'^[ #\n]*$', text2) and text2.count('\n') == 8*nlines):
                continue
                        
            for font3 in font_list:
                if font3 == font1 or font3 == font2:
                    continue

                text3 = art.text2art(known_word, font=font3, chr_ignore=False)
                if not (re.search(r'^[ #\n]*$', text3) and text3.count('\n') == 8*nlines):
                    continue
                
                # Generate the mixed text.
                mixed_text = mergeText(mergeText(text1, text2), text3)
               
                # Check how many columns are matching.
                matched = get_matched_columns(first_line, mixed_text)
                if matched == first_line_cols:
                    print(f'[+] Font combination FOUND after {cnt} iterations: '
                          f'{font1}, {font2}, {font3}')

                    return font1, font2, font3

                if (cnt := cnt + 1) % 10000 == 0:
                    print(f'[+] {cnt} combinations tried, but no solution yet ...')

    raise Exception('Cannot find a valid font combination :\\')


# ----------------------------------------------------------------------------------------
def encode_word(word, font1, font2, font3):
    """Encode a word into ASCII art using a specific font combo."""
    # Font order doesn't matter.
    text1 = art.text2art(word, font=font1, chr_ignore=False)
    text2 = art.text2art(word, font=font2, chr_ignore=False)
    text3 = art.text2art(word, font=font3, chr_ignore=False)

    return mergeText(mergeText(text1, text2), text3)


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Artscii crack started.')

    # Let's look at the word in the first line:
    #
    #   ##   ##  #     ####  #    #  ##
    #   ### ###  # #  # ## ####  ##### ##
    #   #######  ##    ## ##    ###     #
    #   #### ##  ##     ## #    ##   #
    #   #    ##  ##       ##    ##   #  #
    #   #    ##  # #  # # ##### #### ####
    #   ##  ###  #      ## ###   ##  #
    #   ##   ##  ##     ####      # ##
    # 
    #
    # It's not very scrambbled, so it should be "MISC" (or M1SC or MI5C or M15C).
    #
    # Font combo should be: future_2, green_be & z-pilot.
    flag1 = 'MISC'
    print(f'[+] Flag part #1: {flag1}')
    
    font1, font2, font3 = find_font_combo('MISC')
#    font1, font2, font3 = 'future_2', 'green_be', 'z-pilot'


    print('[+] Cracking 2nd line ...')
    line2 = textwrap.dedent('''
        ##   ##     #      #   ##  #### ##   #  ##   ##   ##
        ### ###        #  ##    #   ##  ##   #   #   ### ###
        #######        #    #####  ###  ##   #       #######
        #### ##   # ##     ## #     #   ##   #  ###  #### ##
        #    ##   #  ##      ##     ######   #####   #    ##
        #    ##  ### ##      ##     ##  ##   # ##    #    ##
        ##  ###  #### ##    ####   #### ##  ### ##   ##  ###
        ##   ##  ##   ##     ##    ##   ##  ## ###   ##   ##''')[1:]  # Drop 1st newline.

    # Brute force line character by character.
    # The character that matches the most columns with `line2` is the correct one.
    charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789'
    
    flag2 = ''
    for i in range(6):
        longest_match = (0, '')
        for ch in charset:       
            enc = encode_word(flag2 + ch, font1, font2, font3)
            col = get_matched_columns(enc, line2)
        
            if longest_match[0] < col:
                longest_match = (col, ch)

            print(f'[+]     Trying character: {ch}. Matched {col} columns.')

        flag2 += longest_match[1]
        print(f'[+] Correct character: {longest_match[1]}. Flag so far: {flag2}')
    

    print('[+] Cracking 3rd line ...')
    line3 = textwrap.dedent('''
           #     #        ##  #     # # #   ###   # #    ##    ## #   #  # #    #       ## ####
              #  #  ####   #   ##  #  ###   # ##  # ##   #     ####   #  #      #  #### #  # ##
              #      # #  # #  ##  # #  #   #   # #  #   # #   # # #  #             # # ## # ##
         # ##       #      #  ###   # # #   ###   #  # ####     ## #  #  # # #     #    #  #  #
         #  ##    ### # #  ###  #   # # #   # #   #    ##      ########   ##    #   # # #   ###
        ### ##    ### # #  ##      ##  ##     ### #    ##          ## #   ##    #   # # #  # ##
        #### ##    #      #### ##  ## #      ##         # #  ####### ###   #      #     ## ####
        ##   ##           ##   ##           # # #      ##    ######## ## ###            ##   ##''')[1:]  # Drop 1st newline.

    flag3 = ''
    for i in range(10):
        longest_match = (0, '')
        for ch in charset:       
            enc = encode_word(flag3 + ch, font1, font2, font3)
            col = get_matched_columns(enc, line3)
        
            if longest_match[0] < col:
                longest_match = (col, ch)

            print(f'[+]     Trying character: {ch}. Matched {col} columns.')

        flag3 += longest_match[1]
        print(f'[+] Correct character: {longest_match[1]}. Flag so far: {flag3}')


    # INS{MISC_MAYHEM_A7R93Y4E7H}
    print('[+] FINAL FLAG: INS{%s_%s_%s}' % (flag1, flag2, flag3))

    print('[+] Program finished. Bye bye :)')


# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop2:~/ctf/insomnihack_2022/Artscii$ ./artscii_crack.py 
[+] Artscii crack started.
[+] Flag part #1: MISC
[+] Searching for font combination ...
[+] 10000 combinations tried, but no solution yet ...
[+] 20000 combinations tried, but no solution yet ...
[+] 30000 combinations tried, but no solution yet ...
[+] 40000 combinations tried, but no solution yet ...
[+] 50000 combinations tried, but no solution yet ...
[+] 60000 combinations tried, but no solution yet ...
[+] 70000 combinations tried, but no solution yet ...
[+] 80000 combinations tried, but no solution yet ...
[+] 90000 combinations tried, but no solution yet ...
[+] 100000 combinations tried, but no solution yet ...
[+] 110000 combinations tried, but no solution yet ...
[+] 120000 combinations tried, but no solution yet ...
[+] 130000 combinations tried, but no solution yet ...
[+] 140000 combinations tried, but no solution yet ...
[+] 150000 combinations tried, but no solution yet ...
[+] 160000 combinations tried, but no solution yet ...
[+] 170000 combinations tried, but no solution yet ...
[+] 180000 combinations tried, but no solution yet ...
[+] 190000 combinations tried, but no solution yet ...
[+] 200000 combinations tried, but no solution yet ...
[+] 210000 combinations tried, but no solution yet ...
[+] 220000 combinations tried, but no solution yet ...
[+] 230000 combinations tried, but no solution yet ...
[+] 240000 combinations tried, but no solution yet ...
[+] 250000 combinations tried, but no solution yet ...
[+] 260000 combinations tried, but no solution yet ...
[+] 270000 combinations tried, but no solution yet ...
[+] 280000 combinations tried, but no solution yet ...
[+] 290000 combinations tried, but no solution yet ...
[+] 300000 combinations tried, but no solution yet ...
[+] 310000 combinations tried, but no solution yet ...
[+] 320000 combinations tried, but no solution yet ...
[+] 330000 combinations tried, but no solution yet ...
[+] 340000 combinations tried, but no solution yet ...
[+] 350000 combinations tried, but no solution yet ...
[+] 360000 combinations tried, but no solution yet ...
[+] 370000 combinations tried, but no solution yet ...
[+] 380000 combinations tried, but no solution yet ...
[+] 390000 combinations tried, but no solution yet ...
[+] 400000 combinations tried, but no solution yet ...
[+] 410000 combinations tried, but no solution yet ...
[+] 420000 combinations tried, but no solution yet ...
[+] 430000 combinations tried, but no solution yet ...
[+] 440000 combinations tried, but no solution yet ...
[+] 450000 combinations tried, but no solution yet ...
[+] 460000 combinations tried, but no solution yet ...
[+] 470000 combinations tried, but no solution yet ...
[+] 480000 combinations tried, but no solution yet ...
[+] 490000 combinations tried, but no solution yet ...
[+] 500000 combinations tried, but no solution yet ...
[+] 510000 combinations tried, but no solution yet ...
[+] 520000 combinations tried, but no solution yet ...
[+] 530000 combinations tried, but no solution yet ...
[+] 540000 combinations tried, but no solution yet ...
[+] 550000 combinations tried, but no solution yet ...
[+] 560000 combinations tried, but no solution yet ...
[+] 570000 combinations tried, but no solution yet ...
[+] 580000 combinations tried, but no solution yet ...
[+] 590000 combinations tried, but no solution yet ...
[+] 600000 combinations tried, but no solution yet ...
[+] 610000 combinations tried, but no solution yet ...
[+] 620000 combinations tried, but no solution yet ...
[+] 630000 combinations tried, but no solution yet ...
[+] Font combination FOUND after 635590 iterations: future_2, green_be, z-pilot
[+] Cracking 2nd line ...
[+] Correct character: M. Flag so far: M
[+] Correct character: A. Flag so far: MA
[+] Correct character: Y. Flag so far: MAY
[+] Correct character: H. Flag so far: MAYH
[+] Correct character: E. Flag so far: MAYHE
[+] Correct character: M. Flag so far: MAYHEM
[+] Cracking 3rd line ...
[+] Correct character: A. Flag so far: A
[+] Correct character: 7. Flag so far: A7
[+] Correct character: R. Flag so far: A7R
[+] Correct character: 9. Flag so far: A7R9
[+] Correct character: 3. Flag so far: A7R93
[+] Correct character: Y. Flag so far: A7R93Y
[+] Correct character: 4. Flag so far: A7R93Y4
[+] Correct character: E. Flag so far: A7R93Y4E
[+] Correct character: 7. Flag so far: A7R93Y4E7
[+] Correct character: H. Flag so far: A7R93Y4E7H
[+] FINAL FLAG: INS{MISC_MAYHEM_A7R93Y4E7H}
[+] Program finished. Bye bye :)

real	1m10.128s
user	1m10.107s
sys	0m0.016s
'''
# ----------------------------------------------------------------------------------------

