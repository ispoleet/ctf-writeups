#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Hack.Lu CTF 2022 - Linear Starter (Crypto 106)
# ----------------------------------------------------------------------------------------
from Crypto.Util import number


enc = '3640950455282009581 7952466687307948613019816166 17369565224650736430247096541676484812 22953297873638676928488877237515460574 6789459926483754181974800398181847163 23594281354816491687755064935408616946 13599340837403359325873502361810561387 19178280056739850729152448630210469819 5750796724027627985530525957541452882 14899068761052933017575994683202266588 10708609495728939112384997162322651454 24036844658571121697112504137859157324 4617242990748723227674354943304196855 18811895213158432255382911352169730477 19090734008257354768773800356872218807 23781925047665012503501515791546681866 10347259278484713777649406007853539203 17605109204335680853875403098187626639 2130232046631013730828606948294216620 21291605309616464106136625871603541842 15150606512141085908894479535177870451 11797765787966339319703253967573233539 21189076856862287513809886389691260518 754142039204794340361135836514419126 25917710985296323339724454121714117793 10430306687752180036011806859685360248 14155049792151888529548729619035632390 3277912910544070993632544165961133119 24555483850532783362892269386463254744 21851924633623557709496370345447966529 20098849054794528850763913092125585593 22444745345373743765910753631345826657 13200733808198037288814066436970430062 8007919644650239284152245973135853460 4145783825333884041238186581324648059 7949271522783831154823529866563688327 11327815550981551182285405195735287983 15415826677561422516689603695286902950 7368495634839729216447092354421249405 6733239509344973870819169201534188100 5354313196103706975439863056670652201 13376036093138718246443710729245754760 24103815160796670645668570336373371264 4485216241708087407287873644366957244 22487240697267630545487633525954111207 26218250795526710975934739561708728080 404698605898060412543133749966927487 16026843388557166845903618557603773540 4499819451326175246598693217734651275 27802345808115574172733141693429441358'.split(' ')


# ----------------------------------------------------------------------------------------
def test():
    """Generate some test ciphertext with known `a` and `b`."""
    flag = r'flag{fake_flag}'
    m = 28739970040981503709567288369596407869
    a = 0xdeadbeef % m
    b = 0x13371337 % m

    otp = []
    otp.append(int(time.time()) % m)

    for _ in range(50):
        next = (a * otp[-1] + b) % m
        otp.append(next)

    enc = ""
    for i in range(len(flag)):
        enc += str(ord(flag[i]) ^ otp[i+1]) + " "

    print("enc ", enc)


# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Leaky Starter Crack Started.')

    # test()
    # exit()

    # Take values from out.txt
    m = 28739970040981503709567288369596407869

    e0 = 3640950455282009581
    e1 = 7952466687307948613019816166
    e2 = 17369565224650736430247096541676484812
    e3 = 22953297873638676928488877237515460574
    # Test values for a = 0xdeadbeef and b = 0x13371337:
    #  e0 = 6227907302307853181
    #  e1 = 23267016753496554943078273792
    #  e2 = 704002249174731591256877726967462965

    print('[+] Solving the first 2 equations ...')
    # Solve the equations. We know that:
    #
    #   e1 ^ flag[1] = otp[2] = a * otp[1] + b mod m
    #   e2 ^ flag[2] = otp[3] = a * otp[2] + b mod m
    #
    # So:
    #
    #   e2 ^ flag[2] - e1 ^ flag[1] = a * otp[2] + b - a * otp[1] - b mod m
    #   e2 ^ flag[2] - e1 ^ flag[1] = a * (otp[2] - otp[1]) mod m
    #
    # Solve by `a` and `b`:
    #
    #   a = (e2 ^ flag[2] - e1 ^ flag[1]) * modular_inverse(otp[2] - otp[1]) mod m
    #   b =  e1 ^ flag[1] - a * otp[1] mod m
    c0 = e0 ^ ord('f')
    c1 = e1 ^ ord('l')
    c2 = e2 ^ ord('a')
    c3 = e3 ^ ord('g')

    # find inverse of b modulo a
    inverse = number.inverse(c1 - c0, m)      
    print(f'[+] Inverse (modulo m) of subtraction: {inverse}')
    
    a = ((c2 - c1) * inverse) % m
    print(f'[+] Recovering a: {a} ({a:X}h)')

    b = (c1 - a*c0) % m
    print(f'[+] Recovering b: {b} ({b:X}h)')

    print('[+] Reconstructing otp from a and b ...')
    otp = [c0]
    for i in range(0, 50):
        print(f'[+] otp[{i:2d}] = {otp[i]}')
        otp.append((a * otp[i] + b) % m)


    print('[+] Recovering flag ...')

    flag = ''
    for i, e in enumerate(enc):
        flag += chr(int(e) ^ otp[i])

    print(f'[+] Flag found: {flag}')

    print('[+] Program finished! Bye bye :)')


# ----------------------------------------------------------------------------------------
"""
ispo@ispo-glaptop2:~/ctf/hack.lu_ctf_2022/LinearStarter$ ./linearstarter_crack.py 
[+] Leaky Starter Crack Started.
[+] Solving the first 2 equations ...
[+] Inverse (modulo m) of subtraction: 28392556798737183699367898166903768810
[+] Recovering a: 2184173277 (822FD6DDh)
[+] Recovering b: 1390630283 (52E3558Bh)
[+] Reconstructing otp from a and b ...
[+] otp[ 0] = 3640950455282009483
[+] otp[ 1] = 7952466687307948613019816074
[+] otp[ 2] = 17369565224650736430247096541676484781
[+] otp[ 3] = 22953297873638676928488877237515460537
[+] otp[ 4] = 6789459926483754181974800398181847040
[+] otp[ 5] = 23594281354816491687755064935408616862
[+] otp[ 6] = 13599340837403359325873502361810561282
[+] otp[ 7] = 19178280056739850729152448630210469845
[+] otp[ 8] = 5750796724027627985530525957541452897
[+] otp[ 9] = 14899068761052933017575994683202266557
[+] otp[10] = 10708609495728939112384997162322651468
[+] otp[11] = 24036844658571121697112504137859157267
[+] otp[12] = 4617242990748723227674354943304196756
[+] otp[13] = 18811895213158432255382911352169730498
[+] otp[14] = 19090734008257354768773800356872218841
[+] otp[15] = 23781925047665012503501515791546681965
[+] otp[16] = 10347259278484713777649406007853539313
[+] otp[17] = 17605109204335680853875403098187626746
[+] otp[18] = 2130232046631013730828606948294216607
[+] otp[19] = 21291605309616464106136625871603541820
[+] otp[20] = 15150606512141085908894479535177870352
[+] otp[21] = 11797765787966339319703253967573233638
[+] otp[22] = 21189076856862287513809886389691260473
[+] otp[23] = 754142039204794340361135836514419141
[+] otp[24] = 25917710985296323339724454121714117833
[+] otp[25] = 10430306687752180036011806859685360151
[+] otp[26] = 14155049792151888529548729619035632499
[+] otp[27] = 3277912910544070993632544165961133139
[+] otp[28] = 24555483850532783362892269386463254716
[+] otp[29] = 21851924633623557709496370345447966494
[+] otp[30] = 20098849054794528850763913092125585622
[+] otp[31] = 22444745345373743765910753631345826575
[+] otp[32] = 13200733808198037288814066436970429954
[+] otp[33] = 8007919644650239284152245973135853549
[+] otp[34] = 4145783825333884041238186581324647972
[+] otp[35] = 7949271522783831154823529866563688421
[+] otp[36] = 11327815550981551182285405195735288010
[+] otp[37] = 15415826677561422516689603695286903033
[+] otp[38] = 7368495634839729216447092354421249353
[+] otp[39] = 6733239509344973870819169201534188059
[+] otp[40] = 5354313196103706975439863056670652250
[+] otp[41] = 13376036093138718246443710729245754809
[+] otp[42] = 24103815160796670645668570336373371364
[+] otp[43] = 4485216241708087407287873644366957273
[+] otp[44] = 22487240697267630545487633525954111160
[+] otp[45] = 26218250795526710975934739561708728180
[+] otp[46] = 404698605898060412543133749966927382
[+] otp[47] = 16026843388557166845903618557603773463
[+] otp[48] = 4499819451326175246598693217734651363
[+] otp[49] = 27802345808115574172733141693429441331
[+] Recovering flag ...
[+] Flag found: flag{lin3ar_congru3nce_should_only_be_4_s1de_dish}
[+] Program finished! Bye bye :)
"""
# ----------------------------------------------------------------------------------------