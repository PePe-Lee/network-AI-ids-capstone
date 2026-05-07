<?php
header('Content-Type: text/html; charset=UTF-8');
require_once __DIR__ . '/db.php';
$page = 'home'; $title = 'Capstone 카페 - 홈';
include __DIR__ . '/header.php';

$conn     = db_connect();
$notices  = $conn->query("SELECT id, title, author, created_at FROM notice ORDER BY id DESC LIMIT 5");
$posts    = $conn->query("SELECT id, title, author, views, created_at FROM board ORDER BY id DESC LIMIT 8");
$is_admin = $user && ($user['role'] ?? '') === 'admin';
?>
<div class="container">
    <?php include __DIR__ . '/sidebar.php'; ?>
    <main>
        <div class="warn-banner">
            ⚠️ 본 사이트는 NIDS 시연용으로 의도적으로 취약하게 설계되어 있습니다. 격리된 환경에서만 사용하세요.
        </div>

        <section class="card">
            <h2>📢 공지사항</h2>
            <table>
                <thead>
                    <tr>
                        <th class="num">번호</th>
                        <th>제목</th>
                        <th class="author">작성자</th>
                        <th class="date">날짜</th>
                    </tr>
                </thead>
                <tbody>
                <?php while ($notices && $row = $notices->fetch_assoc()): ?>
                    <tr class="notice-row">
                        <td class="num"><span class="badge notice">공지</span></td>
                        <td>
                            <a href="board.php?notice=<?= $row['id'] ?>"><?= htmlspecialchars($row['title']) ?></a>
                            <?php if ($is_admin): ?>
                                <a href="delete.php?type=notice&id=<?= $row['id'] ?>"
                                   style="font-size:.75em;padding:2px 6px;margin-left:6px;background:#e74c3c;color:#fff;border-radius:3px;text-decoration:none;vertical-align:middle;"
                                   onclick="return confirm('공지를 삭제하시겠습니까?')">삭제</a>
                            <?php endif; ?>
                        </td>
                        <td class="author"><?= htmlspecialchars($row['author']) ?></td>
                        <td class="date"><?= substr($row['created_at'], 0, 10) ?></td>
                    </tr>
                <?php endwhile; ?>
                </tbody>
            </table>
        </section>

        <section class="card">
            <h2>📋 최신글</h2>
            <table>
                <thead>
                    <tr>
                        <th class="num">#</th>
                        <th>제목</th>
                        <th class="author">작성자</th>
                        <th class="views">조회</th>
                        <th class="date">날짜</th>
                    </tr>
                </thead>
                <tbody>
                <?php while ($posts && $row = $posts->fetch_assoc()): ?>
                    <tr>
                        <td class="num"><?= $row['id'] ?></td>
                        <td>
                            <a href="post.php?id=<?= $row['id'] ?>"><?= htmlspecialchars($row['title']) ?></a>
                            <?php if ((int)$row['views'] >= 50): ?>
                                <span class="badge hot">HOT</span>
                            <?php endif; ?>
                        </td>
                        <td class="author"><?= htmlspecialchars($row['author']) ?></td>
                        <td class="views"><?= $row['views'] ?></td>
                        <td class="date"><?= substr($row['created_at'], 0, 10) ?></td>
                    </tr>
                <?php endwhile; ?>
                </tbody>
            </table>
            <p style="margin-top: 8px;"><a href="board.php">전체 게시판 가기 →</a></p>
        </section>
    </main>
</div>
<?php
$conn->close();
include __DIR__ . '/footer.php';
?>
