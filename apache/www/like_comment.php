<?php
header('Content-Type: application/json; charset=UTF-8');
require_once __DIR__ . '/db.php';

$user = current_user();
if (!$user) {
    echo json_encode(['error' => '로그인이 필요합니다.']);
    exit;
}

$comment_id = (int)($_POST['comment_id'] ?? 0);
$type       = $_POST['type'] ?? '';

if (!$comment_id || !in_array($type, ['like', 'dislike'])) {
    echo json_encode(['error' => '잘못된 요청입니다.']);
    exit;
}

$conn = db_connect();
$uid  = (int)$user['id'];
$t    = $conn->real_escape_string($type);

$comment = @$conn->query("SELECT author FROM comments WHERE id = $comment_id")->fetch_assoc();
if (!$comment) {
    echo json_encode(['error' => '댓글이 없습니다.']);
    $conn->close();
    exit;
}
if ($comment['author'] === $user['username']) {
    echo json_encode(['error' => '자신의 댓글에는 반응할 수 없습니다.']);
    $conn->close();
    exit;
}

$existing = @$conn->query("SELECT type FROM comment_likes WHERE comment_id = $comment_id AND user_id = $uid")->fetch_assoc();

if ($existing) {
    if ($existing['type'] === $type) {
        $conn->query("DELETE FROM comment_likes WHERE comment_id = $comment_id AND user_id = $uid");
        $my_type = null;
    } else {
        $conn->query("UPDATE comment_likes SET type = '$t' WHERE comment_id = $comment_id AND user_id = $uid");
        $my_type = $type;
    }
} else {
    $conn->query("INSERT INTO comment_likes (comment_id, user_id, type) VALUES ($comment_id, $uid, '$t')");
    $my_type = $type;
}

$likes    = (int)@$conn->query("SELECT COUNT(*) AS n FROM comment_likes WHERE comment_id = $comment_id AND type = 'like'")->fetch_assoc()['n'];
$dislikes = (int)@$conn->query("SELECT COUNT(*) AS n FROM comment_likes WHERE comment_id = $comment_id AND type = 'dislike'")->fetch_assoc()['n'];

echo json_encode(['likes' => $likes, 'dislikes' => $dislikes, 'my_type' => $my_type]);
$conn->close();
