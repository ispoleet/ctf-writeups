<html>
<link href='http://fonts.googleapis.com/css?family=Lato' rel='stylesheet' type='text/css'>
<body bgcolor="#AD72A0">
<h1 style='font-family:Lato;font-size:100px;margin-top:100px' align='center'>GOD SAVE THE QUEEN</h1>
<img src="queen.gif" style='display:block;margin-left:auto;margin-right:auto;margin-bottom:50px'>
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
<h4 align='center'>ERROR logging in</h4>
<?php
}
}
else {
?>
<form action="/login.php" method="post" align='center'>
  <label for="username">Name:</label>
  <input type="text" name="username" />
  <label for="password">Password:</label>
  <input type="password" name="password" />
  <button>Login</button>
</form>
<div style='text-align:center'><a href='/register.php'>Register an account</a></div>
<?php
}
?>
<br>
</body>
</html>
