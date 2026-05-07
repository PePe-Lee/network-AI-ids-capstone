<?php
header('Content-Type: text/html; charset=UTF-8');
require_once __DIR__ . '/db.php';
require_login();
$page = 'mypage'; $title = '마이페이지';
$user = current_user();
$conn = db_connect();

$author = $conn->real_escape_string($user['username']);
$mine        = $conn->query("SELECT id, title, views, created_at FROM board WHERE author = '$author' ORDER BY id DESC LIMIT 100");
$myComments  = $conn->query("SELECT id, board_id, content, created_at FROM comments WHERE author = '$author' ORDER BY id DESC LIMIT 20");

include __DIR__ . '/header.php';
?>
<div class="container">
    <?php include __DIR__ . '/sidebar.php'; ?>
    <main>
        <div class="card">
            <h2>👤 내 정보</h2>
            <table style="max-width: 480px;">
                <tr><th style="width: 100px;">아이디</th><td><?= htmlspecialchars($user['username']) ?></td></tr>
                <tr><th>닉네임</th><td><?= htmlspecialchars($user['nickname']) ?></td></tr>
                <tr><th>이메일</th><td><?= htmlspecialchars($user['email']) ?></td></tr>
            </table>
        </div>

        <div class="card">
            <h2>📝 내가 쓴 글</h2>
            <table>
                <thead>
                    <tr>
                        <th class="num">#</th>
                        <th>제목</th>
                        <th class="views">조회</th>
                        <th class="date">날짜</th>
                    </tr>
                </thead>
                <tbody>
                <?php if ($mine && $mine->num_rows > 0): ?>
                    <?php while ($r = $mine->fetch_assoc()): ?>
                        <tr>
                            <td class="num"><?= $r['id'] ?></td>
                            <td>
                                <a href="post.php?id=<?= $r['id'] ?>"><?= htmlspecialchars($r['title']) ?></a>
                                <?php if ((int)$r['views'] >= 50): ?>
                                    <span class="badge hot">HOT</span>
                                <?php endif; ?>
                            </td>
                            <td class="views"><?= $r['views'] ?></td>
                            <td class="date"><?= substr($r['created_at'], 0, 10) ?></td>
                        </tr>
                    <?php endwhile; ?>
                <?php else: ?>
                    <tr><td colspan="4" style="text-align:center; color:#888;">작성한 글이 없습니다.</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>💬 내가 쓴 댓글</h2>
            <table>
                <thead>
                    <tr>
                        <th class="num">글번호</th>
                        <th>댓글</th>
                        <th class="date">날짜</th>
                    </tr>
                </thead>
                <tbody>
                <?php if ($myComments && $myComments->num_rows > 0): ?>
                    <?php while ($r = $myComments->fetch_assoc()): ?>
                        <tr>
                            <td class="num"><a href="post.php?id=<?= $r['board_id'] ?>"><?= $r['board_id'] ?></a></td>
                            <td><?= htmlspecialchars(mb_substr($r['content'], 0, 60)) ?></td>
                            <td class="date"><?= substr($r['created_at'], 0, 10) ?></td>
                        </tr>
                    <?php endwhile; ?>
                <?php else: ?>
                    <tr><td colspan="3" style="text-align:center; color:#888;">작성한 댓글이 없습니다.</td></tr>
                <?php endif; ?>
                </tbody>
            </table>
        </div>
    </main>
</div>
<?php
$conn->close();
include __DIR__ . '/footer.php';
?>
