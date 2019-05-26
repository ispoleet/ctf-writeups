## Boston Key Party CTF 2014 - VM (RE 300pt)
##### 28/02 - 02/03/2014 (48hr)
___

### Description: 
    this vm needs a license to run. we don't have the license!

```
    http://bostonkeyparty.net/challenges/vm-2fbed3f5a894d56be6b2ba328f9e2411
```

### Solution


After reversing the VM (using the crack file) we can dump the emulated program (trace.txt).

The emulated program is easy to reverse, so we can find the valid license file (*license.drm*):
```
xxd license.drm 
0000000: 5f27 8bdc e7ee 6652 3a86 bfdb 3039 00eb  _'....fR:...09..
0000010: 0a                                       .
```

```
ispo@nogirl:~/ctf/boston_key_party$ python -c "print '\x5f\x27\x8b\xdc' '\xe7\xee\x66\x52' '\x3a\x86\xbf\xdb' '\x30\x39\x00\xeb'" > license.drm 

ispo@nogirl:~/ctf/boston_key_party$ ./vm-2fbed3f5a894d56be6b2ba328f9e2411 
Stage 1 complete! That was easy, wasn't it?
Stage 2 complete! Keep moving!
Stage 3 complete! You are nearly there!
Stage 4 complete! Hope you liked it.

Now you can haz key: 'Vm_ReVeRsInG_Is_FuN'

```

For more details please take a look at the crack file.


___