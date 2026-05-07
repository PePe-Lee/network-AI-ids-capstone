<?php
header('Content-Type: text/html; charset=UTF-8');
require_once __DIR__ . '/db.php';
$page = 'messages'; $title = '쪽지 읽기';
require_login();

$conn = db_connect();
$user = current_user();
$uid  = (int)$user['id'];
$mid  = (int)($_GET['id'] ?? 0);
$tab  = $_GET['tab'] ?? 'received';

$base_sql = "SELECT m.*, su.nickname AS sender_nickname, su.username AS sender_username,
    ru.nickname AS receiver_nickname, ru.username AS receiver_username
FROM messages m
JOIN users su ON m.sender_id = su.id
JOIN users ru ON m.receiver_id = ru.id
WHERE m.id = $mid";

if ($tab === 'sent') {
    $msg = @$conn->query($base_sql . " AND m.sender_id = $uid")->fetch_assoc();
} else {
    $msg = @$conn->query($base_sql . " AND m.receiver_id = $uid")->fetch_assoc();
    if ($msg && !$msg['is_read']) {
        $conn->query("UPDATE messages SET is_read = 1 WHERE id = $mid");
    }
}

include __DIR__ . '/header.php';
?>
<div class="container full">
    <main style="max-width:700px; margin:30px auto;">
        <div class="card">
            <?php if (!$msg): ?>
                <div class="alert error">쪽지를 찾을 수 없습니다.</div>
                <a href="messages.php" class="btn secondary">쪽지함으로</a>
            <?php else: ?>
                <h2>✉️ <?= htmlspecialchars($msg['title']) ?></h2>
                <p style="color:#888; font-size:0.9em;">
                    보낸 사람: <b><?= htmlspecialchars($msg['sender_nickname']) ?></b>
                    (<?= htmlspecialchars($msg['sender_username']) ?>)
                    &nbsp;→&nbsp;
                    받는 사람: <b><?= htmlspecialchars($msg['receiver_nickname']) ?></b>
                    (<?= htmlspecialchars($msg['receiver_username']) ?>)
                    &nbsp;·&nbsp; <?= $msg['created_at'] ?>
                </p>
                <hr>
                <!-- 의도적으로 raw 출력 (XSS 시연용) -->
                <div style="min-height:120px; padding:8px 0;"><?= nl2br($msg['content']) ?></div>
                <hr>
                <a href="messages.php?tab=<?= htmlspecialchars($tab) ?>" class="btn secondary">쪽지함으로</a>
                <?php if ($tab === 'received'): ?>
                    <a href="send_message.php?to=<?= htmlspecialchars($msg['sender_username']) ?>"
                       class="btn" style="margin-left:6px;">답장</a>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    </main>
</div>
<?php
$conn->close();
include __DIR__ . '/footer.php';
?>
