#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Lake CTF 2025 - Wordler (Misc 100)
# ----------------------------------------------------------------------------------------
import re
import socket
from collections import defaultdict


WORDS = defaultdict(list)


# ----------------------------------------------------------------------------------------
def recv_until(string1, string2):
    """Keep receiving data from `sock`, until you encounter a given `string`."""
    recv = b''
    while string1 not in recv and string2 not in recv:
        recv += sock.recv(2048)
    return recv


# ----------------------------------------------------------------------------------------
def make_new_guess(guess, colors, prev):
    """Given a current guess and its colors, make a new, better guess."""
    if colors == 'G'*len(colors):
        return guess

    # Iterate over all words of the same size.
    for cand in WORDS[len(colors)]:
        if cand in prev: continue

        # First, check the green constraints
        match = True

        for j, c in enumerate(colors):
            if c == 'G':
                # Candidate word needs to have the same character at the same position.
                if guess[j] != cand[j]:
                    match = False
                    break  # Try another word.

            # Yellow characters are not working. Just ignore them.
            '''
            elif c == 'Y':
                if guess[j] not in cand:
                    # Yellow character not in candidate. Reject
                
            elif c == '-':
                if guess[j] not in cand:
                    # Grey character is incandidate. Reject                        
            '''

        if match:
            # We have a candidate. Return it.
            prev.add(cand)
            return cand

    raise Exception(f'Cannot find a new guess for {guess!r} :(')


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Worlder crack started.')

    # Read all words and organize them by their size.
    words_raw = open('word_list.txt', 'r').read().splitlines()
    for w in words_raw:
        WORDS[len(w)].append(w.upper())

    # Try many times until you succeed.
    for i in range(500):
        print(f'[+] ==================== Try #{i} ====================')
        sock = socket.create_connection(('chall.polygl0ts.ch', 6052))

        # Parse structure (2nd line)
        r = sock.recv(1024).decode('utf8').splitlines()
        structure = r[1][len('Structure: '):]
        word_lens = [len(w) for w in structure.split('_')]
        #
        print(f'[+] Structure: {structure}. Word lengths: {word_lens}')
       
        # Start with a random guess.
        guess = [WORDS[l][0] for l in word_lens]
        guess_str = '_'.join(guess)
        print(f'[+] Initial guess: {guess_str}')
        
        # We can make up to 1+5 guesses.
        prev = set(guess)
        for j in range(5):
            sock.send(guess_str.encode('utf8') + b'\n')
            r = recv_until(b'Your guess:', b'EPFL{').decode('utf8')

            if 'EPFL{' in r:
                print(f'[+] Flag FOUND: {r}')
                exit()

            r = r.splitlines()[0]
            print(f'[+] Result: {r}')
            
            # Process the colors:
            #   \x1b[93mA\x1b[0m  --> yellow
            #   \x1b[90mV\x1b[0m  --> normal
            #   \x1b[92mI\x1b[0m  --> green
            colors = []
            c = ''
            j = 0
            for m in re.finditer(r'\x1b\[9([023])m([A-Z])\x1b\[0m', r):
                c += {
                    '0': '-', #'grey',
                    '2': 'G', #'green',
                    '3': 'Y', #'yellow'
                } [m.group(1)]

                if len(c) >= word_lens[j]:
                    colors.append(c)
                    c = ''
                    j += 1

            #print(f'[+] Colors: {colors}')

            if not colors:
                print(f'[!] Error. No response from server')
                break

            # Make a new guess, using the current result.
            new_guess = []
            for g, c in zip(guess, colors):
                ng = make_new_guess(g, c, prev)
                new_guess.append(ng)

            guess = new_guess
            guess_str = '_'.join(new_guess)
            #print(f'[+] New guess: {guess_str}')

        sock.close()

    print('[+] Program finished! Bye bye :)')

# ----------------------------------------------------------------------------------------
r'''
┌─[:(]─[21:41:42]─[✗:1]─[ispo@ispo-glaptop2]─[~/ctf/lake_ctf_2025/Wordler]
└──> time ./wordler_crack.py 
[+] Worlder crack started.
[+] ==================== Try #0 ====================
[+] Structure: ■■■■■■■_■■■■■■■■_■■■■■■■_■■■■■■■■. Word lengths: [7, 8, 7, 8]
[+] Initial guess: CONTACT_BUSINESS_CONTACT_BUSINESS
[+] Result: CONTACT_BUSINESS_CONTACT_BUSINESS
[+] Result: SERVICE_TRAINING_MESSAGE_SERVICES
[+] Result: DETAILS_ILLINOIS_TEENAGE_INTERNET
[+] Result: SPECIAL_ENGINEER_WEBPAGE_RESERVED
[+] Result: WEBSITE_REMINDER_WEBPAGE_ADVANCED
[+] ==================== Try #1 ====================
[+] Structure: ■■■■_■■■■■■■_■■■_■■■_■■■■■■■■■■■. Word lengths: [4, 7, 3, 3, 11]
[+] Initial guess: THAT_CONTACT_THE_THE_INFORMATION
[+] Result: THAT_CONTACT_THE_THE_INFORMATION
[+] Result: WHAT_MESSAGE_AND_FOR_DEVELOPMENT
[+] Result: LIST_PRIVACY_YOU_NOT_ENVIRONMENT
[+] Result: GIFT_COMPANY_ARE_BUT_ENGINEERING
[+] Result: DIET_JANUARY_ALL_OUT_EXHIBITIONS
[+] ==================== Try #2 ====================
[+] Structure: ■■■■■_■■■■■■■■■■■_■■■_■■■■■■. Word lengths: [5, 11, 3, 6]
[+] Initial guess: ABOUT_INFORMATION_THE_SEARCH
[+] Result: ABOUT_INFORMATION_THE_SEARCH
[+] Result: OTHER_DEVELOPMENT_AND_ONLINE
[+] Result: WHICH_DESCRIPTION_FOR_PEOPLE
[+] Result: THEIR_RESPONSIBLE_YOU_HEALTH
[+] Result: THERE_RESPONSIBLE_NOT_SHOULD
[+] ==================== Try #3 ====================
[+] Structure: ■■■■_■■■■■■■_■■■■■■■_■■■■■■■■■. Word lengths: [4, 7, 7, 9]
[+] Initial guess: THAT_CONTACT_CONTACT_AVAILABLE
[+] Result: Your guess: 
[!] Error. No response from server


[..... TRUNCATED FOR BREVITY .....]


[+] ==================== Try #45 ====================
[+] Structure: ■■■■■■■■_■■■■■■■■■_■■■■■_■■■■■■■. Word lengths: [8, 9, 5, 7]
[+] Initial guess: BUSINESS_AVAILABLE_ABOUT_CONTACT
[+] Result: BUSINESS_AVAILABLE_ABOUT_CONTACT
[+] Result: SERVICES_COPYRIGHT_FIRST_SERVICE
[+] Result: PRODUCTS_EDUCATION_LEAST_PRODUCT
[+] Result: SOFTWARE_COMMUNITY_COAST_WINDOWS
[+] Result: RESEARCH_AUTHORITY_COAST_OUTDOOR
[+] ==================== Try #46 ====================
[+] Structure: ■■■■■■■■_■■■_■■■■_■■■■_■■■■■. Word lengths: [8, 3, 4, 4, 5]
[+] Initial guess: BUSINESS_THE_THAT_THAT_ABOUT
[+] Result: BUSINESS_THE_THAT_THAT_ABOUT
[+] Result: SERVICES_AND_THIS_WITH_BOOKS
[+] Result: SOFTWARE_FOR_TIME_SITE_GROUP
[+] Result: SOFTBALL_YOU_THEY_DATE_STORE
[+] Result: SOFTBALL_NOT_THAN_RATE_STOCK
[+] ==================== Try #47 ====================
[+] Structure: ■■■■■_■■■■■■■■■■_■■■■■■■■■■■■■. Word lengths: [5, 10, 13]
[+] Initial guess: ABOUT_UNIVERSITY_INTERNATIONAL
[+] Result: ABOUT_UNIVERSITY_INTERNATIONAL
[+] Result: OTHER_TECHNOLOGY_INVESTIGATION
[+] Result: WHICH_TECHNOLOGY_INVESTIGATORS
[+] Result: WATCH_TECHNOLOGY_INVESTIGATORS
[+] Flag FOUND: WITCHTECHNOLOGYINVESTIGATORS
You win! Heres the flag: EPFL{5CR1P71NG_15_CH34T1NG}


real    0m7.932s
user    0m0.120s
sys 0m0.050s
'''
# ----------------------------------------------------------------------------------------
