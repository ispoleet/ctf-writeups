##  Insomni'Hack CTF Finals 2024 - LUKSury (misc)
##### 26/04/2024 (10hr)
___


In this challenge we are given an encrypted disk file:
```
┌─[12:27:26]─[ispo@ispo-glaptop2]─[~/ctf/insomnihack_finals_2024/LUKSury]
└──> file disk-c366f3b77e8164b1f684dff0dd25c714264eddd65393c146b1904805af211ff1.img 
disk-c366f3b77e8164b1f684dff0dd25c714264eddd65393c146b1904805af211ff1.img: LUKS encrypted file, ver 2, header size 16384, ID 5, algo sha256, salt 0xad7174d78159f31..., UUID: 6dbc6504-4250-4be3-a6d1-40625f28fcc7, crc 0x14646ce585791892..., at 0x1000 {"keyslots":{"1":{"type":"luks2","key_size":64,"af":{"type":"luks1","stripes":4000,"hash":"sha256"},"area":{"type":"raw","offse
```

The hint says to use the `rockyou.txt` wordlist. After some online searching we find `bruteforce-luks` tool.
Directly bruteforcing it, does not work:
```
┌─[12:37:33]─[ispo@ispo-glaptop2]─[~/ctf/insomnihack_finals_2024/LUKSury]
└──> bruteforce-luks -f ~/ctf/insomnihack_finals_2024/LUKSury/rockyou.txt -t16 -v10 disk-c366f3b77e8164b1f684dff0dd25c714264eddd65393c146b1904805af211ff1.img 
Warning: using dictionary mode, ignoring options -b, -e, -l, -m and -s.

Tried passwords: 0
Tried passwords per second: 0.000000
Last tried password: michael

Tried passwords: 0
Tried passwords per second: 0.000000
Last tried password: michael

Tried passwords: 0
Tried passwords per second: 0.000000
Last tried password: michael
```

After some research we find that we need to remove **keyslot 0** (don't forget the `-q` option):
```
┌─[12:08:52]─[ispo@ispo-glaptop2]─[~/ctf/insomnihack_finals_2024/LUKSury]
└──>1 cryptsetup -q luksKillSlot disk-c366f3b77e8164b1f684dff0dd25c714264eddd65393c146b1904805af211ff1.img 0 
```

Then we try again:
```
┌─[12:37:33]─[ispo@ispo-glaptop2]─[~/ctf/insomnihack_finals_2024/LUKSury]
└──> bruteforce-luks -f ~/ctf/insomnihack_finals_2024/LUKSury/rockyou.txt -t16 -v10 disk-c366f3b77e8164b1f684dff0dd25c714264eddd65393c146b1904805af211ff1.img 
Warning: using dictionary mode, ignoring options -b, -e, -l, -m and -s.

Tried passwords: 1683
Tried passwords per second: 168.300000
Last tried password: lasvegas

Tried passwords: 3365
Tried passwords per second: 168.250000
Last tried password: blonde1

Tried passwords: 5036
Tried passwords per second: 167.866667
Last tried password: fiona

Tried passwords: 6704
Tried passwords per second: 167.600000
Last tried password: 123456r

Tried passwords: 8128
Tried passwords per second: 162.560000
Last tried password: sexy1234

Tried passwords: 9383
Tried passwords per second: 156.383333
Last tried password: anissa

Tried passwords: 10651
Tried passwords per second: 152.157143
Last tried password: gollum

Tried passwords: 10952
Tried passwords per second: 152.111111
Last tried password: audition

Password found: deluxe
```

The correct password is `deluxe`. We use it to decrypt the whole disk. Inside this
disk there is a single `flag.pdf` file. We open it and we get the flag.

So, the flag is: `INS{LUK$ury_is_time_and_spac3!}`
___
