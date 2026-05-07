<?php
header('Content-Type: text/html; charset=UTF-8');
// DB 연결 및 세션 헬퍼. 시연을 위해 의도적으로 prepared statement 미사용.
session_start();

$DB_HOST = getenv('DB_HOST') ?: 'mysql_server';
$DB_NAME = getenv('DB_NAME') ?: 'vuln_db';
$DB_USER = getenv('DB_USER') ?: 'vuln_user';
$DB_PASS = getenv('DB_PASS') ?: 'vuln_pass';

function db_connect() {
    global $DB_HOST, $DB_NAME, $DB_USER, $DB_PASS;
    $conn = @new mysqli($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);
    if ($conn->connect_error) {
        die("DB connection failed: " . $conn->connect_error);
    }
    $conn->set_charset('utf8mb4');
    return $conn;
}

function client_ip() {
    foreach (['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR'] as $key) {
        if (!empty($_SERVER[$key])) {
            return explode(',', $_SERVER[$key])[0];
        }
    }
    return 'unknown';
}

function log_login_attempt($conn, $username, $ip, $success) {
    $u = $conn->real_escape_string($username);
    $i = $conn->real_escape_string($ip);
    $s = $success ? 1 : 0;
    @$conn->query("INSERT INTO login_log (username, ip, success) VALUES ('$u', '$i', $s)");
}

function current_user() {
    return $_SESSION['user'] ?? null;
}

function require_login() {
    if (!current_user()) {
        header('Location: login.php');
        exit;
    }
}
?>
