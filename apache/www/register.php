<?php
header('Content-Type: text/html; charset=UTF-8');
require_once __DIR__ . '/db.php';
$page = 'register'; $title = '회원가입';

$message = '';
$message_type = 'error';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $email    = trim($_POST['email'] ?? '');
    $nickname = trim($_POST['nickname'] ?? '');

    if (!$username || !$password || !$email || !$nickname) {
        $message = '모든 필드를 입력해주세요.';
    } else {
        $conn = db_connect();

        // 아이디 중복 체크
        $u = $conn->real_escape_string($username);
        $check = @$conn->query("SELECT id FROM users WHERE username = '$u' LIMIT 1");
        if ($check && $check->num_rows > 0) {
            $message = '이미 사용 중인 아이디입니다.';
        } else {
            // 의도적 취약 - INSERT 시 escape 미처리 (시연용)
            $sql = "INSERT INTO users (username, password, email, nickname) VALUES ('$username', '$password', '$email', '$nickname')";
            if (@$conn->query($sql)) {
                $message = '회원가입 완료! 로그인해주세요.';
                $message_type = 'ok';
            } else {
                $message = '회원가입 실패: ' . $conn->error;
            }
        }
        $conn->close();
    }
}

include __DIR__ . '/header.php';
?>
<div class="container full">
    <main style="max-width: 420px; margin: 30px auto;">
        <div class="card">
            <h2>회원가입</h2>
            <?php if ($message): ?>
                <div class="alert <?= $message_type ?>"><?= htmlspecialchars($message) ?></div>
            <?php endif; ?>
            <form method="post">
                <div class="row">
                    <label>아이디</label>
                    <input type="text" name="username" required>
                </div>
                <div class="row">
                    <label>비밀번호</label>
                    <input type="password" name="password" required>
                </div>
                <div class="row">
                    <label>이메일</label>
                    <input type="email" name="email" required>
                </div>
                <div class="row">
                    <label>닉네임</label>
                    <input type="text" name="nickname" required>
                </div>
                <div class="actions">
                    <button type="submit" class="btn">가입하기</button>
                    <a href="login.php" class="btn secondary">로그인으로</a>
                </div>
            </form>
        </div>
    </main>
</div>
<?php include __DIR__ . '/footer.php'; ?>
