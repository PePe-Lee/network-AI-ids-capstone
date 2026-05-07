<?php
header('Content-Type: text/html; charset=UTF-8');
require_once __DIR__ . '/db.php';
require_login();   // 비로그인 시 로그인 페이지로 리다이렉트
$page = 'write'; $title = '글쓰기';

$message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $t = $_POST['title'] ?? '';
    $c = $_POST['content'] ?? '';
    $author = current_user()['username'];
    if (!$t) {
        $message = '제목을 입력해주세요.';
    } else {
        $conn = db_connect();
        // 의도적으로 escape 만 적용. content 는 출력 시 raw 렌더링되어 XSS 시연 가능.
        $te = $conn->real_escape_string($t);
        $ce = $conn->real_escape_string($c);
        $ae = $conn->real_escape_string($author);
        $conn->query("INSERT INTO board (title, content, author) VALUES ('$te', '$ce', '$ae')");
        $new_id = $conn->insert_id;
        $conn->close();
        header("Location: post.php?id=" . $new_id);
        exit;
    }
}

include __DIR__ . '/header.php';
?>
<div class="container">
    <?php include __DIR__ . '/sidebar.php'; ?>
    <main>
        <div class="card">
            <h2>✏️ 글쓰기</h2>
            <?php if ($message): ?>
                <div class="alert error"><?= htmlspecialchars($message) ?></div>
            <?php endif; ?>
            <form method="post">
                <div class="row">
                    <label>제목</label>
                    <input type="text" name="title" required>
                </div>
                <div class="row">
                    <label>내용</label>
                    <textarea name="content" placeholder="내용을 입력하세요"></textarea>
                </div>
                <div class="actions">
                    <button type="submit" class="btn">등록</button>
                    <a href="board.php" class="btn secondary">취소</a>
                </div>
            </form>
        </div>
    </main>
</div>
<?php include __DIR__ . '/footer.php'; ?>
