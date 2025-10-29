#!/usr/bin/env python3

# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: challenge.obf2.py
# Bytecode version: 3.12.0rc2 (3531)
# Source timestamp: 2025-08-23 11:07:46 UTC (1755947266)

# https://www.tlsbollei.com/blog/hitconctf-writeups

from fractions import Fraction as F

ARRAY = [
    4144803293417776131310451317495228706499130241044716671850484110288180082374299088166459295448719,
    (-2072401646708888065655225658747614353249565120522358335925242055144090041187149544083229647724360),
    1402769202505631727601810730581776197716350949074282314174097681867464170562021714349605843278665,
    (-266910464101355921528772386602523543917783644737516474351090027562514187410064675818699897958587),
    (-313229353281522365344068664569836505240104176843824464617477560855244400498647725320806722489359),
    557751498740761784158621178035559059268846555052211907264408739687389120087425335352771649978396,
    (-148220410045571281675213691246814858326140849250454299621527572224931143542450173517412542679173),
    564587776942621790900159644909288844361323691524579619089869964015177357514421646000222366841011,
    16419311167856483659743166580345122059429852687371972090030542491766200835221304811819328984127643,
    (-129495574458812869075479900411721351204283016397163153311462604211940551198569895507569182199080813),
    47898868564720804115714682250274391102579185635034480293836524415742949562361820585750668129254529,
    (-218390354027018310133763040209628187632374060689193498603396047814125983080443006327100714094044413),
    59103242197276592018409321873953124131699316618422104513410197920897935735761382943069825870316159,
    (-27263762963672679216265023144097755508375724831456195913391130341016602743379285802111387508470863),
    1160187342824936887648971210216937643772466507360201042905423657153536580858662152125535660765491989,
    (-444320422098364618829295716221878629448833826150298094515910374813093990742157048727647821855149363),
    3391657179499987245173012089157446876066874678381207432018307585249041358997171094264590277038007977,
    (-24577331115755648042095942172693201165277671886951704215934044389070300940570840382524224198279961),
    1269071325010846032881520707673575200237482393580774435940684724230748033745143799781707960856809939,
    (-7726874421105907152194917563460067676020997409790741668467611810647472035036892326157134516638801157),
    52668298578428194831854365844392870064649623064538094318250290519368281728564224127244694555479507759,
    (-14912585782593436965791721815706880430658073768879853640660934490173887905327298345044778117728763977),
    20665009833075583446533567863500153284398139825571833690969943149563885799810347822665143905426735039,
    (-4881669849418826679690882149267389579292004979139066657955496750719085286782861933735958022689574551),
    19727966805580144784665343549651570513281612075070319397079427974816184475541029955406232208165236847,
    (-412912430703112866772671727077127791058157331577997254034268890188791073228873359777862031674718585977),
    133658941250435616035761147529730684421152093449583968335054480106579383066071224012305258698560296819,
    (-458807313057700431931426630680383859744706640412367673276163407570064822322611955042530141076353045301)
]


# Get these values from `return` variable from chal.pyc directly:
return_ = (
    1, 1, 2, 2, 12, 15, 10, 240, 40320, 362880, 403200, 7983360, 11975040, 37065600,
    12454041600, 43589145600, 3487131648000, 302455296000, 213412456857600,
    20274183401472000, 2432902008176640000, 12772735542927360000, 281000181944401920000,
    738629049682427904000, 26976017466662584320000, 5170403347776995328000000,
    16803810880275234816000000, 640521732377550127104000000
)


# This is fixed
def func_1(arg):
    if arg in (17, 18):
        return 18 - arg
    
    sz = len(ARRAY)
    s = F(0, 1)
    b = F(1, 1)
    for i in range(sz):
        s += F(ARRAY[i], return_[i]) * b
        b *= F(arg - i, 1)  # Factorial until arg == i then b always 0
    return int(s)


DSA_p = func_1(0)
DSA_q = func_1(1)
DSA_g = func_1(2)
DSA_y = func_1(3)
DSA_M = [func_1(4), func_1(5), func_1(6)]

FIXED_SIGS = [
    (func_1(7),  func_1(8),  func_1(9)),
    (func_1(10), func_1(11), func_1(12)),
    (func_1(13), func_1(14), func_1(15))
]
SS = func_1(16)


def f_add(arg1, arg2):
    """This is an adder."""
    while arg2:
        carry = arg1 & arg2
        arg1  = arg1 ^ arg2
        arg2  = carry << 1  # func_1(17) is 1

    return arg1


def f_mul(arg1, arg2):
    """This is integer multiplication."""
    # func_1(17) is 1 and func_1(18) is 0. Replace accordingly.
    if arg2 < 0:
        # If negative, multiply as positive and add minus at front.
        return -f_mul(arg1, -arg2)

    prod = 0
    while arg2:
        prod += arg1 if arg2 & 1 else 0
        arg1 <<= 1
        arg2 >>= 1

    return prod


def f_pow(arg1, arg2, arg3):
    """This is fast exponentiation: arg1^^arg2 % arg3"""
    # func_1(17) is 1. Replace accordingly.
    e = arg1
    p = 1

    while arg2:
        if arg2 & 1:  # If LSBit is set, multiply product with e.
            p = f_mul(p, e)

        p %= arg3
        e = f_mul(e, e)  # e^^X 
        e %= arg3
        arg2 >>= 1  # Move on to the next bit

    return p


def f_dsa(h, u1, u2):
    """This is DSA (Digital Signature Verification)."""
    # https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
    # u = g^u1 * y^u2 mod p
    u = f_mul(f_pow(DSA_g, u1, DSA_p), f_pow(DSA_y, u2, DSA_p)) % DSA_p
    r = 1  # func_1(17) is 1
    c = 1  # func_1(17) is 1

    # g^u1 * y^u2 == m1 * m2^h * m3^h^2 mod p
    # We want to find u1. But we can (discrete logarithm)
    #
    for m in DSA_M:  # Verify each (fixed) message.
        r = f_mul(r, f_pow(m, c, DSA_p)) % DSA_p  # r = m^h, m^h^2, m^h^3 mod p, ...
        c = f_mul(c, h) % DSA_q                   # c = h, h^2, h^3, ...

    return u == r 


def f_ext_gcd(arg1, arg2):
    """This is extended GCD (non-recursive version)."""
    a, b = (1, 0)  # (func_1(17), func_1(18))
    r, prev_r = (arg1 % arg2, arg2)  # That looks like GCD!

    while r > 1:  # func_1(17) is 1
        quotient = prev_r // r
        x = b - f_mul(a, quotient)
        y = prev_r - f_mul(r, quotient)
        a, r, b, prev_r = (x, y, a, r)

    return a % arg2  # g


def f_chk(arg):
    """Checks if input is correct."""
    # Sanity check. We always pass this.
    if not isinstance(arg, (list, tuple)) or len(arg) < 3:  # func_1(19) is 3
        return False

    # Create a dict using the fixed signatures.
    val_dict = {h: (u1, u2) for h, u1, u2 in FIXED_SIGS}

    for h, u1, u2 in arg:
        val_dict[h] = (u1, u2)
    
    # Another sanity check. 
    if len(val_dict) != 6:  # func_1(20) is 6
        return False

    # First actual check using the input.
    for h, (u1, u2) in val_dict.items():
        if not f_dsa(h, u1, u2):  # Verify DSA signature.
            return False

    #else:  # inserted

    # Get 'h' values
    h_valz = {h for h, u1, u2 in arg[:3]}  # func_1(19) is 3
    
    # sort 'h' values and pair them with user input.    
    inp_pairs = [(e, val_dict[e][0]) for e in sorted(h_valz) if e in val_dict]  # func_1(18) is 0

    # get fixed pairs
    fix_pairs = [(h, u1) for h, u1, u2 in FIXED_SIGS if h not in h_valz]

    # Build mixed_pairs: {inp[0], fix[0], fix[1]}
    mix_pairs = []
    if inp_pairs:
        mix_pairs.append(inp_pairs[0])  # func_1(18) is 0
    mix_pairs.extend(fix_pairs[:2])  # func_1(21) is 2
    
    if len(mix_pairs) < 3:  # func_1(19) is 3
        # Never executed.
        mix_pairs = list(((h, u1) for h, (u1, u2) in sorted(val_dict.items())))[:3]
    
    # This is the same as:
    #   mix_pairs = [fix_pairs[0], fix_pairs[2], fix_pairs[1]]
    #
    # NOTE: Any combination of fix_pairs/inp_pairs reconstructs the secret!
    
    # Do a Shamir's Secret Sharing (SSS) using `mix_pairs`.

    # Get all possible pairs => Lagrange polynomial!!
    w = 0  # func_1(18) is 0
    for i, (h_i, u1_i) in enumerate(mix_pairs):
        t, v = (1, 1)  # func_1(17) is 1 

        for j, (h_j, u1_j) in enumerate(mix_pairs):
            if i == j:
                continue  # Elements must be different.
        
            t = f_mul(t, -h_j) % DSA_q  # L(0)?
            v = f_mul(v, h_i - h_j) % DSA_q  # Interpolation?

        u = f_mul(t, f_ext_gcd(v, DSA_q)) % DSA_q
        w = (w + f_mul(u1_i, u)) % DSA_q  # <-- this

    # Check if shared secret matches SS
    return SS == f_pow(DSA_g, w, DSA_p)  # <-- and this


if __name__ == '__main__':
    inp1 = int.from_bytes(input('1:').strip().encode())
    inp2 = int.from_bytes(input('2:').strip().encode())
    inp3 = int.from_bytes(input('3:').strip().encode())

    #inp1 = int.from_bytes('ispoleet'.strip().encode())
    #inp2 = int.from_bytes('13371337'.strip().encode())
    #inp3 = int.from_bytes('foobarfoo'.strip().encode())

    if f_chk(
        (
            [func_1(22), inp1, func_1(23)],
            [func_1(24), inp2, func_1(25)],
            [func_1(26), inp3, func_1(27)]
        )
    ):
        print('Success!')
    else:  # inserted
        print('Fail')

