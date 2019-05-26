<html>
<link href='http://fonts.googleapis.com/css?family=Lato' rel='stylesheet' type='text/css'>
<body bgcolor="#AD72A0">
<h1 style='font-family:Lato;font-size:100px;margin-top:100px' align='center'>GOD SAVE THE QUEEN</h1>
<img src="queen.gif" style='display:block;margin-left:auto;margin-right:auto;margin-bottom:50px'>
<?php
include("database.php");

if(isset($_POST['username'])) {
  $username = mysql_real_escape_string($_POST['username']);
  $password = mysql_real_escape_string($_POST['password']);

  $sql = "INSERT INTO users VALUES ('$username', '$password');";

  mysql_query($sql, $db);
?>
<h4 align='center'>Registered successfully!</h4>
<?php
}
else {
?>
<form action="/register.php" method="post" align='center'>
  <label for="username">Name:</label>
  <input type="text" name="username" />
  <label for="password">Password:</label>
  <input type="password" name="password" />
  <input type="submit">
</form>
<?php
}
?>
<div style='text-align:center'><a href='/login.php'>Login</a></div>
<br>
</body>
</html>
