<?php
header('Content-Type: text/html; charset=UTF-8');
require_once __DIR__ . '/db.php';
$page = 'messages'; $title = '쪽지 보내기';
require_login();

$conn    = db_connect();
$user    = current_user();
$uid     = (int)$user['id'];
$to      = $_GET['to'] ?? '';
$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $receiver_username = $_POST['receiver'] ?? '';
    $title_val         = $_POST['title']    ?? '';
    $content_val       = $_POST['content']  ?? '';

    if ($receiver_username !== '' && $title_val !== '' && $content_val !== '') {
        $ru       = $conn->real_escape_string($receiver_username);
        $receiver = @$conn->query("SELECT id FROM users WHERE username = '$ru'")->fetch_assoc();
        if ($receiver) {
            $rid = (int)$receiver['id'];
            $t   = $conn->real_escape_string($title_val);
            $c   = $conn->real_escape_string($content_val);
            $conn->query("INSERT INTO messages (sender_id, receiver_id, title, content) VALUES ($uid, $rid, '$t', '$c')");
            $conn->close();
            header('Location: messages.php?tab=sent');
            exit;
        } else {
            $message = '존재하지 않는 사용자입니다: ' . htmlspecialchars($receiver_username);
        }
    } else {
        $message = '모든 필드를 입력해주세요.';
    }
}

include __DIR__ . '/header.php';
?>
<div class="container full">
    <main style="max-width:600px; margin:30px auto;">
        <div class="card">
            <h2>✉️ 쪽지 보내기</h2>
            <?php if ($message): ?>
                <div class="alert error"><?= $message ?></div>
            <?php endif; ?>
            <form method="post">
                <div class="row">
                    <label>받는 사람 (아이디)</label>
                    <input type="text" name="receiver" value="<?= htmlspecialchars($to) ?>" placeholder="username" required>
                </div>
                <div class="row">
                    <label>제목</label>
                    <input type="text" name="title" placeholder="제목을 입력하세요" required>
                </div>
                <div class="row">
                    <label>내용</label>
                    <textarea name="content" rows="6" placeholder="내용을 입력하세요" required></textarea>
                </div>
                <div class="actions">
                    <button type="submit" class="btn">전송</button>
                    <a href="messages.php" class="btn secondary">취소</a>
                </div>
            </form>
        </div>
    </main>
</div>
<?php
$conn->close();
include __DIR__ . '/footer.php';
?>
