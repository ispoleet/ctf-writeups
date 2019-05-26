<?php
session_start();

if (!isset($_GET["page"]) || isset($page))
    $page = "home";
else
    $page = $_GET["page"];
?>
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <!-- The above 3 meta tags *must* come first in the head; any other head content must come *after* these tags -->
    <meta name="description" content="">
    <meta name="author" content="">
    <link rel="icon" href="favicon.ico">

    <title>Mortal Magi Agents</title>

    <!-- Bootstrap core CSS -->
    <link href="css/bootstrap.min.css" rel="stylesheet">

    <!-- Custom styles for this template -->
    <link href="css/jumbotron.css" rel="stylesheet">

    <!-- HTML5 shim and Respond.js for IE8 support of HTML5 elements and media queries -->
    <!--[if lt IE 9]>
      <script src="https://oss.maxcdn.com/html5shiv/3.7.2/html5shiv.min.js"></script>
      <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
    <![endif]-->
  </head>

  <body>

    <nav class="navbar navbar-inverse navbar-fixed-top">
      <div class="container">
        <div class="navbar-header">
          <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
            <span class="sr-only">Toggle navigation</span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
          </button>
          <a class="navbar-brand" href="index.php">Mortal Magi Agents</a>
        </div>
        <div id="navbar" class="collapse navbar-collapse">
          <ul class="nav navbar-nav">
            <li class="active"><a href="?page=home">Home</a></li>
            <li><a href="?page=news">News</a></li>
            <li><a href="#contact">Contact</a></li>
          </ul>
<?php if (isset($_SESSION["user"])) { ?>
          <ul class="nav navbar-nav navbar-right">
            <li class='dropdown'>
              <a href="#" aria-expanded="false" class="dropdown-toggle" data-toggle="dropdown" role="button">
              <?php
              if (isset($_SESSION["avator"])) {
                  echo '<img src="'.$_SESSION['avator'].'" width="32" height="32">';
              }
              echo $_SESSION["user"];
              ?><span class='caret'></span></a>
              <ul class='dropdown-menu' role='menu'>
              <li><a href="?page=settings">Settings</a></li>
              <li><a href="logout.php">Sign out</a></li>
              </ul>
            </li>
          </ul>
<?php } else { ?>
          <form class="navbar-form navbar-right" action="login.php" method="post">
            <div class="form-group">
              <input type="text" placeholder="User" class="form-control" name="user">
            </div>
            <div class="form-group">
              <input type="password" placeholder="Password" class="form-control" name="password">
            </div>
            <button type="submit" class="btn btn-success" name="signin">Sign in</button>
            <button type="submit" class="btn btn-danger" name="signup">Sign up</button>
          </form>
<?php } ?>
        </div><!--/.nav-collapse -->
      </div>
    </nav>

    <!-- Main jumbotron for a primary marketing message or call to action -->
    <!--
    <div class="jumbotron">
    </div>
    -->
    <div class="container">
<?php
include("$page.php");
?>
      </div>


      <hr>

      <footer>
        <p>Mortal Magi Agents 2015</p>
      </footer>
    </div> <!-- /container -->


    <!-- Bootstrap core JavaScript
    ================================================== -->
    <!-- Placed at the end of the document so the pages load faster -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.11.3/jquery.min.js"></script>
    <script src="js/bootstrap.min.js"></script>
  </body>
</html>

