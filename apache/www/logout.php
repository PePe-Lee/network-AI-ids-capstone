<?php
header('Content-Type: text/html; charset=UTF-8');
require_once __DIR__ . '/db.php';
$_SESSION = [];
session_destroy();
setcookie('remember_user', '', time() - 3600, '/');
header('Location: index.php');
exit;
?>
