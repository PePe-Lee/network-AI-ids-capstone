<?php
header('Content-Type: application/json; charset=UTF-8');
require_once __DIR__ . '/db.php';

$user = current_user();
if (!$user) {
    echo json_encode(['unread' => 0]);
    exit;
}

$conn   = db_connect();
$uid    = (int)$user['id'];
$unread = (int)@$conn->query("SELECT COUNT(*) AS n FROM messages WHERE receiver_id = $uid AND is_read = 0")->fetch_assoc()['n'];
echo json_encode(['unread' => $unread]);
$conn->close();
