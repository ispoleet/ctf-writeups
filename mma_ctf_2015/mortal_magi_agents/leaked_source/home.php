<div class="page-header"><h1>Home</h1></div>

<img src="magi.jpg">

<?php
if (isset($_SESSION["admin"]) && $_SESSION["admin"]) {
    echo file_get_contents("../flag");
}
