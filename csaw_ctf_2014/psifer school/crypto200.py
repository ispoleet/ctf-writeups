# --------------------------------------------------------------------------------------------------
import socket
import sys

# --------------------------------------------------------------------------------------------------
# simple ROT-n decryption
def rotn(s, off):
    chars = "abcdefghijklmnopqrstuvwxyz"
    trans = chars[off:]+chars[:off]
    rot_char = lambda c: trans[chars.find(c)] if chars.find(c)>-1 else c
    return '' . join( rot_char(c) for c in s ) 

# --------------------------------------------------------------------------------------------------
def transposition(message, key):
     # Each string in ciphertext represents a column in the grid.
     ciphertext = [''] * key

     # Loop through each column in ciphertext.
     for col in range(key):
         pointer = col

         # Keep looping until pointer goes past the length of the message.
         while pointer < len(message):
             # Place the character at pointer in message at the end of the
             # current column in the ciphertext list.
             ciphertext[col] += message[pointer]

             # move pointer over
             pointer += key
     # Convert the ciphertext list into a single string value and return it.
     return ''.join(ciphertext)

# --------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('54.209.5.48', 12345))

    print s.recv(1024)
    cipher1 = s.recv(1024)
    print cipher1
    print '-------------------------------------'
    print 'extract cipher:', cipher1[102:]

    for n in range(0,25):               # for each possible n
         p1 = rotn(cipher1[102:], n)
         if p1[0:3] == 'the': 
            print 'plaintext 1:', p1[28:]
            break

    s.send(p1[28:] ) 
    print s.recv(1024)
    cipher2 = s.recv(1024)
    print cipher2
    
    for i in range(1,30):
        p2 = transposition(cipher2[120:], i)
        if p2[0:10] == 'I hope you':
            print 'i:', i, ' --- ', p2
            break

    if i == 100:
        print 'plaintext 2 not found'
        exit

    flag = "";
    start = 0;
    for i in range(0, len(p2)):
        if p2[i] == '"':
            start = start + 1;

        if start == 1 and p2[i]!='"':
            flag = flag + p2[i];

    flag = flag + '\n';     
    print 'plaintext 2: ', flag

    s.send( stdin.readline() )
    #s.send(flag)
    cipher3 = s.recv(1024)
    print cipher3

    cipher3 = cipher3[91:]
    print cipher3

    plain3 = 'THIST IMEWE WILLG IVEYO UMORE PLAIN TEXTT OWORK WITHY OUWIL LPROB ABLYF INDTH ATHAV INGEX TRACO NTENT THATI SASCI IMAKE STHIS ONEMO RESOL VABLE ITWOU LDBES OLVAB LEWIT HOUTT HATBU TWEWI LLMAK ESURE TOGIV ELOTS OFTEX TJUST TOMAK ESURE THATW ECANH ANDLE ITIWO NDERH OWMUC HWILL BEREQ UIRED LETSP UTTHE MAGIC PHRAS EFORT HENEX TLEVE LINTH EMIDD LERIG HTHER EBLAH LAHOK NOWMO RETEX TTOMA KESUR ETHAT ITISS OLVAB LEISH OULDP ROBAB LYJUS TPUTI NSOME NURSE RYRHY MEORS OMETH INGMA RYHAD ALITT LELAM BLITT LELAM BLITT LELAM BMARY HADAL ITTLE LAMBW HOSEF LEEZE WASWH ITEAS SNOWI DONTW ANTTO MAKET HISHA RDERT HANIT NEEDS TOBEI FYOUV ESOLV EDALO TOFSI MPLEC RYPTO CHALL ENGES YOUPR OBABL YALRE ADYHA VETHE CODEA NDWIL LBREE ZERIG HTTHR OUGHI TIFIT HELPS MOSTO FTHEP LAINT EXTIS STATI CATEA CHOFT HELEV ELSIM NOTAM ASOCH ISTTH EFUNN YTHIN GISTH ATDEP ENDIN GONWH ICHRA NDOMK EYYOU GETTH ATPOE MMIGH TBEEX ACTLY THERI GHTOF FSETT OSUCC ESSFU LLY'

    k = ''
    for i in range(0, 32):
        if cipher3[i] != ' ':
            c = abs(ord(cipher3[i])-ord('A'))   
            p = abs(ord(plain3[i])-ord('A'))    
                
            k = k + chr(ord('A') + (26 + c - p) % 26);
    #       print cipher3[i],plain3[i], k
        
    print k

    for l in range(3,16): # for all possible key lengths
        for i in range(0,16-l):
            if k[i] != k[i+l]: # wrong length
                break;
        if i >= 4:
            print 'length found. Key:', k[:l]
            break;


    k = k[:l]

    #decrypt c
    p3 = ''
    z = 0
    print 'l:', l
    for i in range(0, len(cipher3)):
        if cipher3[i] != ' ':
    
            c = abs(ord(cipher3[i])-ord('A'))   
            k3 = abs(ord(k[z])-ord('A'))    
                
            p3 = p3 + chr(ord('A') + ((26 + c - k3) % 26));

            z = (z + 1) % l 
    print p3


    plaintext3 =  p3[p3.find('RIGHTHERE')+9: p3.find('OKNOWMORE')]


    print 'plaintext 3: ', plaintext3
    #s.send(plaintext3)
    s.send( stdin.readline() )
    #s.send(flag)
    cipher4 = s.recv(1024)
    print cipher4
    cipher4 = s.recv(1024)
    print cipher4

    s.close()

# --------------------------------------------------------------------------------------------------
