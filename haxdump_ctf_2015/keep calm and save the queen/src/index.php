<html>
<link href='http://fonts.googleapis.com/css?family=Lato' rel='stylesheet' type='text/css'>
<body bgcolor="#AD72A0">
<h1 style='font-family:Lato;font-size:100px;margin-top:100px' align='center'>GOD SAVE THE QUEEN</h1>
<img src="queen.gif" style='display:block;margin-left:auto;margin-right:auto;margin-bottom:50px'>
<?php
include("database.php");

session_start();

if (isset($_SESSION['wow']) && $_SESSION['wow'] == true) {
?>
<h4 align='center'>You naughty you</h4>
<div style='text-align:center'><a href='/logout.php'>Logout</a></div>
<?php
}
else {
  header("Location: http://godsavethequeen.haxdump.com/login.php");
  exit();
}
?>
</body>
</html>
