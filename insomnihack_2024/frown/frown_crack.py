#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Insomni'Hack 2024 - frown (RE 57)
#
# To make this attack work run the service using local port forwarding:
#   `ssh -L 27042:127.0.0.1:27042 frown.insomnihack.ch -p24 -l user`
# 
# Once you see the message `[Frida INFO] Listening on 127.0.0.1 TCP port 27042`, hit `p`
# and then you can run the script.
# ----------------------------------------------------------------------------------------
import frida
import sys
import urllib.parse


# ----------------------------------------------------------------------------------------
def get_frida_device():
    """Gets the Frida device (there are 3 ways to do it)."""
    # 1st way:
    devices = frida.get_device_manager().enumerate_devices()
    for device in devices:
        print(f'[+] Enumerating device: {device.id}')

    # 2nd way:
    device = frida.get_remote_device()
    print(f'[+] Remote device: {device}')

    # 3rd way:
    process = frida.get_device_manager()
    device = process.add_remote_device("0.0.0.0:27042")
    print(f'[+] Added remoted device: {device}')

    return device


# ----------------------------------------------------------------------------------------
def exec_shell_cmd(cmd):
    """Executes a shell command through Frida's API."""
    # First resolve the address of libc.system() and then invoke it.
    script = session.create_script(f"""
        var sysPtr = Module.findExportByName('libc.so.6', 'system');
        //console.log('[+] libc.system() at:' + sysPtr);

        var system = new NativeFunction(sysPtr, 'int', ['pointer']);
        var retv = system(Memory.allocUtf8String('{cmd}'));
        //console.log('[+] libc.system() return value:' + retv);

        send('Script finished successfully.');
    """)

    def on_message(message, data):
        if message['type'] == 'send':
            #print(f"[*] Output: {message['payload']}")
            pass

    script.on('message', on_message)
    script.load()


# ----------------------------------------------------------------------------------------
flag_key = ''

def send_flag_key(key):
    """Sends a flag key to http://frown-service. If it is correct it will print the flag."""
    script = session.create_script(f"""
        // We resolve the same functions every time, but we don't care :P
        var dlopenPtr = Module.findExportByName("libc.so.6", "dlopen");
        const dlopen = new NativeFunction(dlopenPtr, 'pointer', ['pointer', 'int']);

        var dlsymPtr = Module.findExportByName("libc.so.6", "dlsym");
        const dlsym = new NativeFunction(dlsymPtr, 'pointer', ['pointer', 'pointer']);

        var hdl = dlopen(Memory.allocUtf8String("libttyris.so"), 2);
        var flag_key = dlsym(hdl, Memory.allocUtf8String("flag_key"));

        var flag_keyPtr = Module.findExportByName("libttyris.so", "flag_key");
        var flag_key = new NativeFunction(flag_keyPtr, 'void', ['int', 'pointer', 'uint64']);

        var buf = Memory.alloc(100);
        flag_key({key}, ptr(buf), 100);

        var res = Memory.readByteArray(ptr(buf), 32);

        var flag = String.fromCharCode.apply(null, new Uint8Array(res))
        send(flag);
    """)
    
    def on_message(message, data):
        global flag_key
        if message['type'] == 'send':
            #print(f"[*] Output: {repr(message['payload'])}")
            flag_key = message['payload']

    script.on('message', on_message)
    script.load()
    return flag_key



# ----------------------------------------------------------------------------------------
if __name__ == "__main__":
    print('[+] frown crack started.')

    device = get_frida_device()

    # Enumerate processes in the remote device (process should be "Gadget").
    # 
    # ┌─[22:57:54]─[✗:1]─[ispo@ispo-glaptop2]─[~/ctf/insomnihack_2024/frown]
    # └──> frida-ps -R
    #   PID  Name
    #   --  ------
    #   18  Gadget
    for process in device.enumerate_processes():
        print(f'[+] Enumerating process: {process}')
        session = device.attach(process.name)
        break

    # Or:
    # session = device.attach("Gadget")

    '''
    # Run some shell commands.
    exec_shell_cmd('clear')
    exec_shell_cmd('id')
    exec_shell_cmd('ls -la')

    # Fetch the challenge binaries:
    exec_shell_cmd('echo "---------- TETRIS ----------"')
    exec_shell_cmd('cat /usr/local/bin/tetris | base64')

    # libttyris.so: /usr/lib/libttyris.so
    #exec_shell_cmd('whereis libttyris.so')

    exec_shell_cmd('echo "---------- LIBTTYRIS ----------"')
    exec_shell_cmd('cat /usr/lib/libttyris.so | base64')

    #exec_shell_cmd('cat /usr/sbin/tetris.sh')
    '''

    # Brute force key (it's 1 byte long).
    exec_shell_cmd('clear')

    for i in range(256):
        flag_key = send_flag_key(i)
        if all(a >= '!' and a <= '~' for a in flag_key):
            # Flag key is ASCII printable. Send it to the frown server.
            print(f'[+] Key: {i:X}h produces flag key: {flag_key!r} (see other window for flag)')

            flag_key = urllib.parse.quote(flag_key)
            
            # Send flag key to server and check the response in the tetris window.
            exec_shell_cmd(f'echo ""')  # Just add a newline.           
            exec_shell_cmd(f'curl -X POST http://frown-service/ -d "{flag_key}"')

    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
r"""
┌─[21:29:11]─[✗:3]─[ispo@ispo-glaptop2]─[~/ctf/insomnihack_2024/frown]
└──> ./frown_crack.py 
[+] frown crack started.
[+] Enumerating device: local
[+] Enumerating device: socket
[+] Enumerating device: barebone
[+] Remote device: Device(id="socket", name="Local Socket", type='remote')
[+] Added remoted device: Device(id="socket@0.0.0.0:27042", name="0.0.0.0:27042", type='remote')
[+] Enumerating process: Process(pid=18, name="Gadget", parameters={})
[+] Key: 21h produces flag key: '~}y|{.yp|})-,x..~xy|~*+|,-q.+q-x' (see other window for flag)
[+] Key: 24h produces flag key: '{x|y~+|uyx,()}++{}|y{/.y)(t+.t(}' (see other window for flag)
[+] Key: 29h produces flag key: 'vuqts&qxtu!%$p&&vpqtv"#t$%y&#y%p' (see other window for flag)
[+] Key: 30h produces flag key: 'olhmj?haml8<=i??oihmo;:m=<`?:`<i' (see other window for flag)
[+] Key: 31h produces flag key: 'nmilk>i`lm9=<h>>nhiln:;l<=a>;a=h' (see other window for flag)
[+] Key: 32h produces flag key: 'mnjoh=jcon:>?k==mkjom98o?>b=8b>k' (see other window for flag)
[+] Key: 33h produces flag key: 'lokni<kbno;?>j<<ljknl89n>?c<9c?j' (see other window for flag)
[+] Key: 34h produces flag key: 'khlin;leih<89m;;kmlik?>i98d;>d8m' (see other window for flag)
[+] Key: 35h produces flag key: 'jimho:mdhi=98l::jlmhj>?h89e:?e9l' (see other window for flag)
[+] Key: 36h produces flag key: 'ijnkl9ngkj>:;o99ionki=<k;:f9<f:o' (see other window for flag)
[+] Key: 37h produces flag key: 'hkojm8ofjk?;:n88hnojh<=j:;g8=g;n' (see other window for flag)
[+] Key: 38h produces flag key: 'gd`eb7`ied045a77ga`eg32e54h72h4a' (see other window for flag)
[+] Key: 39h produces flag key: 'feadc6ahde154`66f`adf23d45i63i5`' (see other window for flag)
[+] Key: 3Ah produces flag key: 'efbg`5bkgf267c55ecbge10g76j50j6c' (see other window for flag)
[+] Key: 3Bh produces flag key: 'dgcfa4cjfg376b44dbcfd01f67k41k7b' (see other window for flag)
[+] Key: 3Ch produces flag key: 'c`daf3dma`401e33cedac76a10l36l0e' (see other window for flag)
[+] Key: 3Dh produces flag key: 'bae`g2el`a510d22bde`b67`01m27m1d' (see other window for flag)
[+] Key: 3Eh produces flag key: 'abfcd1focb623g11agfca54c32n14n2g' (see other window for flag)
[+] Key: 3Fh produces flag key: '`cgbe0gnbc732f00`fgb`45b23o05o3f' (see other window for flag)
[+] Key: 60h produces flag key: '?<8=:o81=<hlm9oo?98=?kj=ml0oj0l9' (see other window for flag)
[+] Key: 61h produces flag key: '>=9<;n90<=iml8nn>89<>jk<lm1nk1m8' (see other window for flag)
[+] Key: 62h produces flag key: '=>:?8m:3?>jno;mm=;:?=ih?on2mh2n;' (see other window for flag)
[+] Key: 63h produces flag key: '<?;>9l;2>?kon:ll<:;><hi>no3li3o:' (see other window for flag)
[+] Key: 64h produces flag key: ';8<9>k<598lhi=kk;=<9;on9ih4kn4h=' (see other window for flag)
[+] Key: 65h produces flag key: ':9=8?j=489mih<jj:<=8:no8hi5jo5i<' (see other window for flag)
[+] Key: 66h produces flag key: '9:>;<i>7;:njk?ii9?>;9ml;kj6il6j?' (see other window for flag)
[+] Key: 67h produces flag key: '8;?:=h?6:;okj>hh8>?:8lm:jk7hm7k>' (see other window for flag)
[+] Key: 68h produces flag key: '74052g0954`de1gg71057cb5ed8gb8d1' (see other window for flag)
[+] Key: 69h produces flag key: '65143f1845aed0ff60146bc4de9fc9e0' (see other window for flag)
[+] Key: 6Ah produces flag key: '56270e2;76bfg3ee53275a`7gf:e`:f3' (see other window for flag)
[+] Key: 6Bh produces flag key: '47361d3:67cgf2dd42364`a6fg;da;g2' (see other window for flag)
[+] Key: 6Ch produces flag key: '30416c4=10d`a5cc35413gf1a`<cf<`5' (see other window for flag)
[+] Key: 6Dh produces flag key: '21507b5<01ea`4bb24502fg0`a=bg=a4' (see other window for flag)
[+] Key: 6Eh produces flag key: '12634a6?32fbc7aa17631ed3cb>ad>b7' (see other window for flag)
[+] Key: 6Fh produces flag key: '03725`7>23gcb6``06720de2bc?`e?c6' (see other window for flag)
[+] Key: 76h produces flag key: ")*.+,y.'+*~z{/yy)/.+)}|+{z&y|&z/" (see other window for flag)
[+] Key: 7Bh produces flag key: '$\'#&!t#*&\'swv"tt$"#&$pq&vw+tq+w"' (see other window for flag)
[+] Key: 7Eh produces flag key: '!"&#$q&/#"vrs\'qq!\'&#!ut#sr.qt.r\'' (see other window for flag)
[+] Program finished. Bye bye :)


* * * * * OUTPUT IN THE CHALLENGE WINDOW (TETRIS) * * * * *
^U
3ss$r6M?B(r5FJ`#=3dI-)vf
ZL 7oa)$=Sow|rtE*j3d3p0=
;9svQ&y{djf'7Zrt2` s8cq(i

" sw!?`b}}dA \/#<zw%e<o5w

#!sw">$9!W5n'6+ruEgaSs9i0q
"sw#=b`k'6*ru@daRs9j3r
!#sw$<ca~k'6)ruCeaUs9k2s
&$sw%;dfyk:<ruD*};f<l}+
'%sw&:egxk;=ruG*|:g=m}+
Warning: Binary output can mess up your terminal. Use "--output -" to tell 
Warning: curl to output it to your terminal anyway, or consider "--output 
Warning: <FILE>" to save to a file.

%'n+=j*"}}d@ \(>7T<y<bp4
Gyz3&Pr7?x^<g60`qand&3mf5=-
+)`%3d>$}a23Y1c0?]6pd913mq
Warning: Binary output can mess up your terminal. Use "--output -" to tell 
Warning: curl to output it to your terminal anyway, or consider "--output 
Warning: <FILE>" to save to a file.

4 aaa63/                                                                                                         '
hc24    ^T.7"T3ln4
duejX3ua<46ht
�j|f#U2m*'
9b35
etdkYw fhc0}.
,.g4c9?f31%g1%ddd36*
ZMR,-4!W0omr
ked5_rp6i[03`:a2:*
ZH$jy|BdE*"z7o3 \c5LT>{oe:"k^
ZH'jy}BdB*"y6n2 \c5KU?znd;"k]
ZH&jyaT$<W5r1D\ru@*|8ep4�u
ZH!jyaT$<T4r1G]ruC*}9dp4t
ZH woe^r2Jzk7<W;.o*}=/fE}+
Warning: Binary output can mess up your terminal. Use "--output -" to tell 
Warning: curl to output it to your terminal anyway, or consider "--output 
Warning: <FILE>" to save to a file.

F^QoeBdC*"x1r1@XruD*x<ap4q
oeBd@*"0r1CYruG*y=`p4p                                                                                                                         G^Q
HORzx1t^b5*'
<23`w6:
1tco1??z
INS{y0u_c4nt_h1d3_fr0m_fr333da}
JMPxz3vBdC8'Y>01`
bu48	33`:b`>=
KLQy{2wBd@9&X?10a
ct5w fkca?=
LKV~|5pBdE>!_}a2dZ4%5c%1ldf}.
MJW}4qBdB? ^9r45[5$4;	b$0me"n(
7rei7"k]                                                NIT|~7rBdG<#]:45dfq0<
OHU}srW`$<T	k0agYrp6*
b&`=g7<}
ZI[jxjBeC*#x!y'7XrtD*h,/bEwa
ZIVjxaaUd$='jfv ]dc4N` s8bt/n
ZISjxdaUa$="jcs ]ai#=w$d|'t}*
"""
# ----------------------------------------------------------------------------------------

