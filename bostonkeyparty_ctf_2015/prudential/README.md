## Boston Key Party 2015 - Prudential (Web 25)
##### 27/02 - 01/03/2015 (43hr)
___

### Description: 
I dont think that sha1 is broken. Prove me wrong.
___
### Solution

That's a type confusion and not a collision on SHA1. If we supply sha1() with an non-string argument
then it will return NULL. Because NULL === NULL, we'll get the flag. Let's set name and password to
arrays - must be different to bypass the first check - and get the flag:
```
	http://52.10.107.64:8001/?name[]=1&password[]=2
```

Flag: **I_think_that_you_just_broke_sha1**
___