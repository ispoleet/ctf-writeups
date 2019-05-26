## CSAW CTF 2017 - Prophecy (RE 200pt)
##### 15/09 - 17/09/2017 (48hr)
___

### Description: 
	The prophecy is more important than either of us! Reveal its secrets, Zeratul! The future rests on it!"

	-Karass-

```
	nc reversing.chal.csaw.io 7668
```

	prophecy


### Solution
	Binary is obfuscated with Control Flow Flattening. Kinda annoying, but if you look at the 
	CFG and analyze the leaves only it's not hard.

	
	Please take a look at the "crack" file.
___
