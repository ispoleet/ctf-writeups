<?php

session_start();
if(isset($_SESSION['wow'])) {
  unset($_SESSION['wow']);
  session_unset();
  session_destroy();
}
header("Location: http://godsavethequeen.haxdump.com/login.php");
?>
