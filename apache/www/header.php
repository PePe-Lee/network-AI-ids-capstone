<?php
header('Content-Type: text/html; charset=UTF-8');
require_once __DIR__ . '/db.php';
$page  = $page  ?? '';
$title = $title ?? 'Capstone 카페';
$user  = current_user();
?>
<!doctype html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title><?= htmlspecialchars($title) ?></title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
<header class="header">
    <div class="header-inner">
        <a href="index.php" class="logo">Capstone<small>NIDS Demo Cafe</small></a>
        <nav class="nav">
            <a href="index.php"  class="<?= $page === 'home'     ? 'active' : '' ?>">홈</a>
            <a href="board.php"  class="<?= $page === 'board'    ? 'active' : '' ?>">게시판</a>
            <a href="hot.php"    class="<?= $page === 'hot'      ? 'active' : '' ?>" style="color:#e74c3c;">🔥 핫게시판</a>
            <?php if ($user): ?>
                <a href="write.php"    class="<?= $page === 'write'    ? 'active' : '' ?>">글쓰기</a>
                <a href="mypage.php"   class="<?= $page === 'mypage'   ? 'active' : '' ?>">마이페이지</a>
                <span class="nav-msg-wrap">
                    <a href="messages.php" class="<?= $page === 'messages' ? 'active' : '' ?>" id="nav-msg-link">
                        ✉️ 쪽지함
                    </a><span id="nav-msg-badge" class="badge-msg" style="display:none;"></span>
                </span>
            <?php endif; ?>
        </nav>
        <div class="user-area">
            <?php if ($user): ?>
                <span class="greet"><?= htmlspecialchars($user['nickname']) ?></span>님
                &nbsp;<a href="logout.php" class="btn secondary">로그아웃</a>
            <?php else: ?>
                <a href="login.php"    class="btn">로그인</a>
                <a href="register.php" class="btn secondary">회원가입</a>
            <?php endif; ?>
        </div>
    </div>
</header>
<?php if ($user): ?>
<script>
(function poll() {
    fetch('message_api.php')
        .then(function(r) { return r.json(); })
        .then(function(d) {
            var b = document.getElementById('nav-msg-badge');
            if (b) {
                b.textContent = d.unread;
                b.style.display = d.unread > 0 ? 'inline-block' : 'none';
            }
        })
        .catch(function() {});
    setTimeout(poll, 5000);
})();
</script>
<?php endif; ?>
