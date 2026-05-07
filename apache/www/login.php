<?php
header('Content-Type: text/html; charset=UTF-8');
require_once __DIR__ . '/db.php';
$page = 'login'; $title = '로그인';

$message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $remember = isset($_POST['remember']);

    $conn = db_connect();
    // 의도적 취약 - SQL Injection 가능, Brute Force 제한 없음
    $sql = "SELECT id, username, nickname, email, role FROM users WHERE username = '$username' AND password = '$password'";
    $res = @$conn->query($sql);
    $success = $res && $res->num_rows > 0;

    log_login_attempt($conn, $username, client_ip(), $success);

    if ($success) {
        $row = $res->fetch_assoc();
        $_SESSION['user'] = [
            'id'       => $row['id'],
            'username' => $row['username'],
            'nickname' => $row['nickname'],
            'email'    => $row['email'],
            'role'     => $row['role'] ?? 'user',
        ];
        if ($remember) {
            setcookie('remember_user', $row['username'], time() + 60*60*24*30, '/');
        }
        $conn->close();
        header('Location: index.php');
        exit;
    } else {
        $message = '로그인 실패. 아이디 또는 비밀번호가 올바르지 않습니다.';
    }
    $conn->close();
}

$remembered = $_COOKIE['remember_user'] ?? '';
include __DIR__ . '/header.php';
?>
<div class="container full">
    <main style="max-width: 380px; margin: 30px auto;">
        <div class="card">
            <h2>로그인</h2>
            <?php if ($message): ?>
                <div class="alert error"><?= htmlspecialchars($message) ?></div>
            <?php endif; ?>
            <form method="post">
                <div class="row">
                    <label>아이디</label>
                    <input type="text" name="username" value="<?= htmlspecialchars($remembered) ?>" required>
                </div>
                <div class="row">
                    <label>비밀번호</label>
                    <input type="password" name="password" required>
                </div>
                <div class="row checkbox">
                    <input type="checkbox" name="remember" id="remember" <?= $remembered?'checked':'' ?>>
                    <label for="remember" style="margin:0;">로그인 상태 유지</label>
                </div>
                <div class="actions">
                    <button type="submit" class="btn">로그인</button>
                    <a href="register.php" class="btn secondary">회원가입</a>
                </div>
            </form>
            <p style="margin-top: 14px; font-size: 0.85em; color: #888;">
                테스트 계정: admin / admin123
            </p>
        </div>
    </main>
</div>
<?php include __DIR__ . '/footer.php'; ?>
