#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Hack.Lu CTF 2022 - Cocktail Bar (RE 257)
# ----------------------------------------------------------------------------------------
EVALUATE_ME = '''
LimeSlice(
    LimeSlice(
        Stirr(Mix(1024, AddVodka(2,10))),
        Stirr(Mix(3072, Shake(22)))),
    Stirr(Mix(666, AddVodka(Shake(3), 13))),
    LimeSlice(
        Stirr(Mix(999, Shake(Mix(1024, FlirtWithCustomer(16, 0))))),
        AddSyrup(2,5),
        Stirr(Mix(420, AddVodka(Mix(1337, AddVodka(Shake(0), 529)),7))),
        LimeSlice(
            Stirr(Mix(2048, Shake(Shake(118)))),
            Stirr(Mix(666, FlirtWithCustomer(17, 0)))),
        Stirr(Mix(9999, LimeSlice(3, 3))),
        Stirr(Mix(1337, FlirtWithCustomer(12, 0))), 
        LimeSlice(
            LimeSlice(
                Stirr(Mix(4096, Shake(Shake(Shake(AddVodka(1, 7))))))
            ),
            AddSyrup(1, 
                LimeSlice(
                    Mix(5000, Shake(Shake(18))))
                )
        )
    )
)'''


# ----------------------------------------------------------------------------------------
def Mix(x, y):
    return y % 0x17

def Shake(x):
    return x + 24

def FlirtWithCustomer(x, y, z=None):
    return x + 25

def AddSyrup(x, y):
    return ''.join(Stirr(Mix(1000, AddVodka(y, (187 + i*0x1c)))) for i in range(x))

def Stirr(x):
    return chr(65 + x)

def AddVodka(x, y):
    return x + y + 46

def LimeSlice(*x):      
    if isinstance(x[0], int):
        return int(''.join('%d' % a for a in x))
    else:
        return ''.join(q for q in x)

# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] Cocktail Bar Crack Started.')

    print(f'[+] Evaluated Flag: flag{{{eval(EVALUATE_ME)}}}')

    print('[+] Program finished! Bye bye :)')

# ----------------------------------------------------------------------------------------
'''
ispo@ispo-glaptop2:~/ctf/hack.lu_ctf_2022/CocktailBar$ ./cocktail_bar_crack.py
[+] Cocktail Bar Crack Started.
[+] Evaluated Flag: flag{MARTINIFTKOLA}
[+] Program finished! Bye bye :)
'''
# ----------------------------------------------------------------------------------------
