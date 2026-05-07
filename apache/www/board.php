<?php
header('Content-Type: text/html; charset=UTF-8');
require_once __DIR__ . '/db.php';
$page = 'board'; $title = '게시판';
include __DIR__ . '/header.php';

$conn     = db_connect();
$keyword  = $_GET['q']    ?? '';
$sort     = $_GET['sort'] ?? 'newest';
$user     = current_user();
$is_admin = $user && ($user['role'] ?? '') === 'admin';

// 의도적으로 취약 - 검색 키워드를 그대로 SQL에 삽입 (SQLi 가능)
$post_sql = "SELECT b.id, b.title, b.author, b.views, b.created_at,
    (SELECT COUNT(*) FROM post_likes WHERE post_id = b.id AND type = 'like') AS likes,
    (SELECT COUNT(*) FROM comments WHERE board_id = b.id) AS comment_count
FROM board b";
if ($keyword !== '') {
    $post_sql .= " WHERE b.title LIKE '%$keyword%' OR b.content LIKE '%$keyword%'";
}
switch ($sort) {
    case 'likes':    $post_sql .= " ORDER BY likes DESC, b.id DESC LIMIT 100";         break;
    case 'views':    $post_sql .= " ORDER BY b.views DESC, b.id DESC LIMIT 100";       break;
    case 'comments': $post_sql .= " ORDER BY comment_count DESC, b.id DESC LIMIT 100"; break;
    default:         $post_sql .= " ORDER BY b.id DESC LIMIT 100";                     break;
}
$posts = @$conn->query($post_sql);

// 공지사항: 검색이 없을 때만 상단 고정 표시
$notices = null;
if ($keyword === '') {
    $notices = $conn->query("SELECT id, title, author, created_at FROM notice ORDER BY id DESC LIMIT 5");
}

// 단일 공지 상세 보기 모드
$notice_view = null;
if (isset($_GET['notice'])) {
    $nid         = (int)$_GET['notice'];
    $notice_view = @$conn->query("SELECT * FROM notice WHERE id = $nid")->fetch_assoc();
}
?>
<div class="container">
    <?php include __DIR__ . '/sidebar.php'; ?>
    <main>
        <?php if ($notice_view): ?>
            <div class="card">
                <h2><span class="badge notice">공지</span> <?= htmlspecialchars($notice_view['title']) ?></h2>
                <p style="color:#888; font-size:0.9em;">
                    <?= htmlspecialchars($notice_view['author']) ?> · <?= $notice_view['created_at'] ?>
                </p>
                <hr>
                <div style="min-height:100px;"><?= nl2br(htmlspecialchars($notice_view['content'])) ?></div>
                <hr>
                <a href="board.php" class="btn secondary">목록으로</a>
                <?php if ($is_admin): ?>
                    <a href="delete.php?type=notice&id=<?= $notice_view['id'] ?>"
                       class="btn" style="background:#e74c3c; margin-left:6px;"
                       onclick="return confirm('공지를 삭제하시겠습니까?')">삭제</a>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <div class="card">
            <h2>📋 자유게시판</h2>

            <form class="search-bar" method="get">
                <input type="text" name="q" value="<?= htmlspecialchars($keyword) ?>" placeholder="제목 또는 내용으로 검색">
                <select name="sort" onchange="this.form.submit()"
                        style="padding:7px 8px; border:1px solid #ddd; border-radius:4px; font-size:0.92em;">
                    <option value="newest"   <?= $sort === 'newest'   ? 'selected' : '' ?>>최신순</option>
                    <option value="views"    <?= $sort === 'views'    ? 'selected' : '' ?>>조회수순</option>
                    <option value="likes"    <?= $sort === 'likes'    ? 'selected' : '' ?>>좋아요순</option>
                    <option value="comments" <?= $sort === 'comments' ? 'selected' : '' ?>>댓글많은순</option>
                </select>
                <button type="submit" class="btn">검색</button>
                <?php if (current_user()): ?>
                    <a href="write.php" class="btn secondary">글쓰기</a>
                <?php endif; ?>
            </form>

            <table>
                <thead>
                    <tr>
                        <th class="num">번호</th>
                        <th>제목</th>
                        <th class="author">작성자</th>
                        <th class="date">날짜</th>
                        <th class="views">조회</th>
                        <th class="views">👍</th>
                        <th class="views">💬</th>
                    </tr>
                </thead>
                <tbody>
                <?php /* 공지 상단 고정 */ ?>
                <?php while ($notices && $n = $notices->fetch_assoc()): ?>
                    <tr class="notice-row">
                        <td class="num"><span class="badge notice">공지</span></td>
                        <td>
                            <a href="board.php?notice=<?= $n['id'] ?>"><?= htmlspecialchars($n['title']) ?></a>
                            <?php if ($is_admin): ?>
                                <a href="delete.php?type=notice&id=<?= $n['id'] ?>"
                                   style="font-size:.75em; padding:2px 6px; margin-left:6px; background:#e74c3c; color:#fff; border-radius:3px; text-decoration:none; vertical-align:middle;"
                                   onclick="return confirm('공지를 삭제하시겠습니까?')">삭제</a>
                            <?php endif; ?>
                        </td>
                        <td class="author"><?= htmlspecialchars($n['author']) ?></td>
                        <td class="date"><?= substr($n['created_at'], 0, 10) ?></td>
                        <td class="views">-</td>
                        <td class="views">-</td>
                        <td class="views">-</td>
                    </tr>
                <?php endwhile; ?>

                <?php if ($posts && $posts->num_rows > 0): ?>
                    <?php while ($row = $posts->fetch_assoc()): ?>
                        <tr>
                            <td class="num"><?= $row['id'] ?></td>
                            <td>
                                <a href="post.php?id=<?= $row['id'] ?>"><?= htmlspecialchars($row['title']) ?></a>
                                <?php if ((int)$row['views'] >= 50): ?>
                                    <span class="badge hot">HOT</span>
                                <?php endif; ?>
                                <?php if ($is_admin || ($user && $row['author'] === $user['username'])): ?>
                                    <a href="delete.php?type=post&id=<?= $row['id'] ?>"
                                       style="font-size:.75em; padding:2px 6px; margin-left:6px; background:#e74c3c; color:#fff; border-radius:3px; text-decoration:none; vertical-align:middle;"
                                       onclick="return confirm('게시글을 삭제하시겠습니까?')">삭제</a>
                                <?php endif; ?>
                            </td>
                            <td class="author"><?= htmlspecialchars($row['author']) ?></td>
                            <td class="date"><?= substr($row['created_at'], 0, 10) ?></td>
                            <td class="views"><?= $row['views'] ?></td>
                            <td class="views" style="color:#03c75a; font-weight:600;"><?= (int)$row['likes'] ?></td>
                            <td class="views" style="color:#555;"><?= (int)$row['comment_count'] ?></td>
                        </tr>
                    <?php endwhile; ?>
                <?php else: ?>
                    <tr><td colspan="7" style="text-align:center; color:#888;">결과 없음</td></tr>
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
