<?php
header('Content-Type: text/html; charset=UTF-8');
require_once __DIR__ . '/db.php';
require_login();

$type = $_GET['type'] ?? 'post';   // 'post' | 'notice'
$id   = (int)($_GET['id'] ?? 0);
$user = current_user();
$is_admin = ($user['role'] ?? '') === 'admin';
$conn = db_connect();

if ($id <= 0) {
    $conn->close();
    header('Location: board.php');
    exit;
}

if ($type === 'notice') {
    // 공지 삭제: admin 전용
    if ($is_admin) {
        $conn->query("DELETE FROM notice WHERE id = $id");
    }
    $conn->close();
    header('Location: board.php');
    exit;
}

// 게시글 삭제: admin은 전체, 일반 사용자는 본인 글만
$post = @$conn->query("SELECT author FROM board WHERE id = $id")->fetch_assoc();
if ($post && ($is_admin || $post['author'] === $user['username'])) {
    $conn->query("DELETE FROM board WHERE id = $id");
    $conn->query("DELETE FROM comments WHERE board_id = $id");
}

$conn->close();
header('Location: board.php');
exit;
?>
