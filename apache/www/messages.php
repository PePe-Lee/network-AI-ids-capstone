<?php
header('Content-Type: text/html; charset=UTF-8');
require_once __DIR__ . '/db.php';
$page = 'messages'; $title = '쪽지함';
require_login();

$conn = db_connect();
$user = current_user();
$uid  = (int)$user['id'];
$tab  = $_GET['tab'] ?? 'received';

// 삭제 처리
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'delete') {
    $mid = (int)($_POST['id'] ?? 0);
    if ($tab === 'sent') {
        $conn->query("DELETE FROM messages WHERE id = $mid AND sender_id = $uid");
    } else {
        $conn->query("DELETE FROM messages WHERE id = $mid AND receiver_id = $uid");
    }
    $conn->close();
    header("Location: messages.php?tab=" . urlencode($tab));
    exit;
}

$unread = (int)@$conn->query("SELECT COUNT(*) AS n FROM messages WHERE receiver_id = $uid AND is_read = 0")->fetch_assoc()['n'];

if ($tab === 'sent') {
    $msgs = $conn->query(
        "SELECT m.*, u.nickname AS other_nickname, u.username AS other_username
         FROM messages m JOIN users u ON m.receiver_id = u.id
         WHERE m.sender_id = $uid ORDER BY m.id DESC"
    );
} else {
    $msgs = $conn->query(
        "SELECT m.*, u.nickname AS other_nickname, u.username AS other_username
         FROM messages m JOIN users u ON m.sender_id = u.id
         WHERE m.receiver_id = $uid ORDER BY m.id DESC"
    );
}

include __DIR__ . '/header.php';
?>
<div class="container">
    <?php include __DIR__ . '/sidebar.php'; ?>
    <main>
        <div class="card">
            <h2>
                ✉️ 쪽지함
                <?php if ($unread > 0): ?>
                    <span class="badge-msg"><?= $unread ?></span>
                <?php endif; ?>
            </h2>

            <div class="tab-bar">
                <a href="messages.php?tab=received"
                   class="tab-btn <?= $tab === 'received' ? 'active' : '' ?>">
                    받은 쪽지
                    <?php if ($unread > 0 && $tab !== 'received'): ?>
                        <span class="badge-msg"><?= $unread ?></span>
                    <?php endif; ?>
                </a>
                <a href="messages.php?tab=sent"
                   class="tab-btn <?= $tab === 'sent' ? 'active' : '' ?>">보낸 쪽지</a>
                <a href="send_message.php" class="btn" style="margin-left:auto;">✉️ 쪽지 보내기</a>
            </div>

            <?php if (!$msgs || $msgs->num_rows === 0): ?>
                <p style="color:#888; padding:16px 0;">쪽지가 없습니다.</p>
            <?php else: ?>
                <table>
                    <thead>
                        <tr>
                            <th>제목</th>
                            <th class="author"><?= $tab === 'sent' ? '받는 사람' : '보낸 사람' ?></th>
                            <th class="date">날짜</th>
                            <th style="width:50px; text-align:center;">삭제</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php while ($msg = $msgs->fetch_assoc()): ?>
                        <tr class="<?= ($tab === 'received' && !$msg['is_read']) ? 'msg-unread' : '' ?>">
                            <td>
                                <?php if ($tab === 'received' && !$msg['is_read']): ?>
                                    <span style="color:#e74c3c; font-size:0.75em; vertical-align:middle;">●&nbsp;</span>
                                <?php endif; ?>
                                <a href="read_message.php?id=<?= $msg['id'] ?>&tab=<?= htmlspecialchars($tab) ?>">
                                    <?= htmlspecialchars($msg['title']) ?>
                                </a>
                            </td>
                            <td class="author">
                                <?= htmlspecialchars($msg['other_nickname']) ?>
                                <span style="color:#aaa;">(<?= htmlspecialchars($msg['other_username']) ?>)</span>
                            </td>
                            <td class="date"><?= substr($msg['created_at'], 0, 16) ?></td>
                            <td style="text-align:center;">
                                <form method="post" action="messages.php?tab=<?= htmlspecialchars($tab) ?>" style="display:inline;">
                                    <input type="hidden" name="action" value="delete">
                                    <input type="hidden" name="id" value="<?= $msg['id'] ?>">
                                    <button type="submit" class="btn"
                                            style="background:#e74c3c; padding:2px 8px; font-size:0.8em;"
                                            onclick="return confirm('삭제하시겠습니까?')">삭제</button>
                                </form>
                            </td>
                        </tr>
                    <?php endwhile; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </main>
</div>
<?php
$conn->close();
include __DIR__ . '/footer.php';
?>
