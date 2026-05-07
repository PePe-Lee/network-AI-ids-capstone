<aside class="sidebar">
    <h3>📌 게시판 카테고리</h3>
    <ul>
        <li><a href="index.php">🏠 홈</a></li>
        <li><a href="board.php">📋 자유게시판</a></li>
        <li><a href="hot.php" style="color:#e74c3c;">🔥 핫게시판</a></li>
        <li><a href="board.php?q=공지">📢 공지사항</a></li>
    </ul>
    <h3>👥 멤버 메뉴</h3>
    <ul>
        <?php if (current_user()): ?>
            <li><a href="write.php">✏️ 글쓰기</a></li>
            <li><a href="mypage.php">👤 마이페이지</a></li>
            <li>
                <a href="messages.php">✉️ 쪽지함</a>
                <?php
                    $mc = db_connect();
                    $mu = (int)current_user()['id'];
                    $mr = $mc->query("SELECT COUNT(*) AS n FROM messages WHERE receiver_id = $mu AND is_read = 0");
                    $mn = $mr ? (int)$mr->fetch_assoc()['n'] : 0;
                    $mc->close();
                    if ($mn > 0): ?>
                    <span class="badge-msg"><?= $mn ?></span>
                <?php endif; ?>
            </li>
            <li><a href="logout.php">🚪 로그아웃</a></li>
        <?php else: ?>
            <li><a href="login.php">🔑 로그인</a></li>
            <li><a href="register.php">📝 회원가입</a></li>
        <?php endif; ?>
    </ul>
    <h3>ℹ️ 카페 정보</h3>
    <ul>
        <li>회원수: <?php
            $c = db_connect();
            $r = $c->query('SELECT COUNT(*) AS n FROM users');
            echo $r ? $r->fetch_assoc()['n'] : 0;
            $c->close();
        ?>명</li>
        <li>등급: 새싹</li>
    </ul>
</aside>
