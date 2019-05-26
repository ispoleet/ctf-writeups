<?php
if (!defined('INCLUDED_INDEX')) {
define('INCLUDED_INDEX', true);
ini_set('display_errors', 1);
include "flag.php";
?>
<!doctype html>
<html>
<head>
<meta charset=utf-8>
<title>Global Page</title>
<style>
.rtl {
  direction: rtl;
}
</style>
</head>

<body>
<?php
$dir = "";
if(isset($_GET['page'])) {
	$dir = str_replace(['.', '/'], '', $_GET['page']);
}

if(empty($dir)) {
?>
<ul>
	<li><a href="/?page=tokyo">Tokyo</a></li>
	<li><del>Westerns</del></li>
	<li><a href="/?page=ctf">CTF</a></li>
</ul>
<?php
}
else {
	foreach(explode(",", $_SERVER['HTTP_ACCEPT_LANGUAGE']) as $lang) {
		$l = trim(explode(";", $lang)[0]);
?>
<p<?=($l==='he')?" class=rtl":""?>>
<?php
		include "$dir/$l.php";
?>
</p>
<?php
	}
}
?>
</body>
</html>
<?php
}
?>
