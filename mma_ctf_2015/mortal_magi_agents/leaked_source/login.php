<?php
require "./db.php";
session_start();
if (!isset($_POST["user"]) or !isset($_POST["password"])) {
    header("Location: index.php");
    exit;
}

if (isset($_POST["signup"])) {
    $user = $_POST["user"];
    $password = $_POST["password"];
    if (preg_match("/^[a-zA-Z0-9]+$/", $user)) {
        $hashed_password = sha1($password);

        $db = connect_db();
        $db->query("INSERT INTO users (name, hashed_password) VALUES ('$user', '$hashed_password')");
        
        $_SESSION["user"] = $user;
        header("Location: index.php");
        exit;
    }
    else {
        $message = "Invalid user name";
    }
}
else {
    $user = $_POST['user'];
    $password = $_POST["password"];
    
    $db = connect_db();
    $results = $db->query("SELECT * FROM users WHERE (name = '$user' AND not banned)");
    $row = $results->fetch_array();
    if ($row["hashed_password"] === sha1($password)) {
        $_SESSION["user"] = $user;
        if ($row["avator"]) {
            $_SESSION["avator"] = $row["avator"];
        }
        
        $results = $db->query("SELECT * FROM admins");
        while ($row = $results->fetch_array()) {
            if ($row["name"] === $user) {
                $_SESSION["admin"] = true;
                break;
            }
        }
        header("Location: index.php");
        exit;
    }
    else {
        # failure
        $message = "Username or password is wrong.";
    }
}
if (isset($message)) {
    echo $message;
}
?>

