<?php
header('Content-Type: application/json; charset=UTF-8');
require_once __DIR__ . '/db.php';

$user = current_user();
if (!$user) {
    echo json_encode(['error' => '로그인이 필요합니다.']);
    exit;
}

$post_id = (int)($_POST['post_id'] ?? 0);
$type    = $_POST['type'] ?? '';

if (!$post_id || !in_array($type, ['like', 'dislike'])) {
    echo json_encode(['error' => '잘못된 요청입니다.']);
    exit;
}

$conn = db_connect();
$uid  = (int)$user['id'];
$t    = $conn->real_escape_string($type);

$post = @$conn->query("SELECT author FROM board WHERE id = $post_id")->fetch_assoc();
if (!$post) {
    echo json_encode(['error' => '게시글이 없습니다.']);
    $conn->close();
    exit;
}
if ($post['author'] === $user['username']) {
    echo json_encode(['error' => '자신의 글에는 반응할 수 없습니다.']);
    $conn->close();
    exit;
}

$existing = @$conn->query("SELECT type FROM post_likes WHERE post_id = $post_id AND user_id = $uid")->fetch_assoc();

if ($existing) {
    if ($existing['type'] === $type) {
        $conn->query("DELETE FROM post_likes WHERE post_id = $post_id AND user_id = $uid");
        $my_type = null;
    } else {
        $conn->query("UPDATE post_likes SET type = '$t' WHERE post_id = $post_id AND user_id = $uid");
        $my_type = $type;
    }
} else {
    $conn->query("INSERT INTO post_likes (post_id, user_id, type) VALUES ($post_id, $uid, '$t')");
    $my_type = $type;
}

$likes    = (int)@$conn->query("SELECT COUNT(*) AS n FROM post_likes WHERE post_id = $post_id AND type = 'like'")->fetch_assoc()['n'];
$dislikes = (int)@$conn->query("SELECT COUNT(*) AS n FROM post_likes WHERE post_id = $post_id AND type = 'dislike'")->fetch_assoc()['n'];

echo json_encode(['likes' => $likes, 'dislikes' => $dislikes, 'my_type' => $my_type]);
$conn->close();
