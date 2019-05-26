<?php
require "./db.php";
if (isset($_FILES["file"])) {
    if ($_FILES['file']['type'] == "image/jpeg") {
        $ext = ".jpg";
    }
    else if ($_FILES['file']['type'] == "image/gif") {
        $ext = ".gif";
    }
    else if ($_FILES['file']['type'] == "image/png") {
        $ext = ".png";
    }
    $filename = "avators/" . $_SESSION["user"] . sha1_file($_FILES['file']['tmp_name']) . $ext;
    move_uploaded_file($_FILES['file']['tmp_name'], $filename);
    
    $_SESSION["avator"] = $filename;
    $db = connect_db();
    $db->query("UPDATE users SET avator = '$filename' WHERE name = '".$_SESSION['user']."'");
}
?>
<div class="page-header"><h1>Settings</h1></div>
<h2>Avator</h2>
<?php
if (isset($_SESSION["avator"])) {
?>
<img src="<?php echo $_SESSION['avator']; ?>" width="64" height="64">
<?php
}
?>
<h3>New avator</h3>
<form method="POST" enctype="multipart/form-data">
<input type="file" name="file">
<input type="submit">
</form>
