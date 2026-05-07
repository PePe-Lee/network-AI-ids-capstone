<?php
header('Content-Type: text/html; charset=UTF-8');
require_once __DIR__ . '/db.php';

define('HOT_LIKE_THRESHOLD', 5);

$page  = 'hot';
$title = '🔥 HOT 게시판';

$conn = db_connect();

// 좋아요 HOT_LIKE_THRESHOLD 이상, 좋아요 많은 순 → 같으면 최신순
// 의도적으로 취약 - SQLi 유지 (NIDS 테스트용)
$sql = "SELECT b.id, b.title, b.author,
    COALESCE(u.nickname, b.author) AS nickname,
    b.views, b.created_at,
    (SELECT COUNT(*) FROM post_likes WHERE post_id = b.id AND type = 'like') AS likes,
    (SELECT COUNT(*) FROM comments WHERE board_id = b.id) AS comment_count
FROM board b
LEFT JOIN users u ON u.username = b.author
WHERE (SELECT COUNT(*) FROM post_likes WHERE post_id = b.id AND type = 'like') >= " . HOT_LIKE_THRESHOLD . "
ORDER BY likes DESC, b.created_at DESC
LIMIT 50";

$posts = @$conn->query($sql);

$medal = ['🥇', '🥈', '🥉'];
$rank_bg = ['#fff9e6', '#f5f5f5', '#fff3e6'];

include __DIR__ . '/header.php';
?>
<div class="container">
    <?php include __DIR__ . '/sidebar.php'; ?>
    <main>
        <div class="card">
            <h2>🔥 HOT 게시판
                <span style="font-size:0.75em; font-weight:normal; color:#888; margin-left:8px;">
                    좋아요 <?= HOT_LIKE_THRESHOLD ?>개 이상 인기 게시물
                </span>
            </h2>

            <?php if (!$posts || $posts->num_rows === 0): ?>
                <div style="text-align:center; padding:48px 0; color:#aaa;">
                    <div style="font-size:2.5em; margin-bottom:12px;">🔥</div>
                    <p style="font-size:1em;">아직 핫 게시물이 없습니다.</p>
                    <p style="font-size:0.85em;">좋아요 <?= HOT_LIKE_THRESHOLD ?>개 이상을 받은 게시물이 여기 표시됩니다.</p>
                </div>
            <?php else: ?>
                <table class="hot-table">
                    <thead>
                        <tr>
                            <th style="width:56px; text-align:center;">순위</th>
                            <th>제목</th>
                            <th class="author">작성자</th>
                            <th class="date">날짜</th>
                            <th class="views">조회</th>
                            <th class="views">🔥</th>
                            <th class="views">💬</th>
                        </tr>
                    </thead>
                    <tbody>
                    <?php $rank = 0; while ($row = $posts->fetch_assoc()): $rank++; ?>
                        <?php
                        $bg    = isset($rank_bg[$rank - 1]) ? 'background:' . $rank_bg[$rank - 1] . ';' : '';
                        $medal_str = isset($medal[$rank - 1]) ? $medal[$rank - 1] . ' ' : '';
                        ?>
                        <tr style="<?= $bg ?>">
                            <td style="text-align:center; font-weight:bold; font-size:<?= $rank <= 3 ? '1.1' : '0.95' ?>em;">
                                <?= $medal_str ?><?= $rank ?>위
                            </td>
                            <td>
                                <a href="post.php?id=<?= $row['id'] ?>"><?= htmlspecialchars($row['title']) ?></a>
                                <span class="badge hot">HOT</span>
                                <?php if ((int)$row['views'] >= 50): ?>
                                    <span class="badge" style="background:#fff0f0; color:#e74c3c; border:1px solid #f5c6cb;">인기</span>
                                <?php endif; ?>
                            </td>
                            <td class="author"><?= htmlspecialchars($row['nickname']) ?></td>
                            <td class="date"><?= substr($row['created_at'], 0, 10) ?></td>
                            <td class="views"><?= (int)$row['views'] ?></td>
                            <td class="views" style="color:#e74c3c; font-weight:700;"><?= (int)$row['likes'] ?></td>
                            <td class="views" style="color:#555;"><?= (int)$row['comment_count'] ?></td>
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
