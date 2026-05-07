<?php
header('Content-Type: text/html; charset=UTF-8');
require_once __DIR__ . '/db.php';
$page = 'board';
$conn = db_connect();
$id   = (int)($_GET['id'] ?? 0);

// 댓글 작성 (로그인 필수)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!current_user()) {
        $conn->close();
        header('Location: login.php');
        exit;
    }
    $author  = current_user()['username'];
    $content = $_POST['content'] ?? '';
    $a = $conn->real_escape_string($author);
    $c = $conn->real_escape_string($content);
    if ($content !== '') {
        $conn->query("INSERT INTO comments (board_id, author, content) VALUES ($id, '$a', '$c')");
    }
    header("Location: post.php?id=$id");
    exit;
}

// 조회수 자동 증가
$conn->query("UPDATE board SET views = views + 1 WHERE id = $id");

$post     = @$conn->query("SELECT * FROM board WHERE id = $id")->fetch_assoc();
$user     = current_user();
$is_admin = $user && ($user['role'] ?? '') === 'admin';

// 게시물 좋아요/싫어요
$post_likes    = 0;
$post_dislikes = 0;
$my_post_like  = null;
if ($post) {
    $post_likes    = (int)@$conn->query("SELECT COUNT(*) AS n FROM post_likes WHERE post_id = $id AND type = 'like'")->fetch_assoc()['n'];
    $post_dislikes = (int)@$conn->query("SELECT COUNT(*) AS n FROM post_likes WHERE post_id = $id AND type = 'dislike'")->fetch_assoc()['n'];
    if ($user) {
        $uid          = (int)$user['id'];
        $row          = @$conn->query("SELECT type FROM post_likes WHERE post_id = $id AND user_id = $uid")->fetch_assoc();
        $my_post_like = $row ? $row['type'] : null;
    }
}

// 댓글 + 좋아요 집계 (베스트 댓글 우선 정렬)
$comments_data = [];
if ($post) {
    $csql = "SELECT c.id, c.board_id, c.author, c.content, c.created_at,
        (SELECT COUNT(*) FROM comment_likes WHERE comment_id = c.id AND type = 'like')    AS likes,
        (SELECT COUNT(*) FROM comment_likes WHERE comment_id = c.id AND type = 'dislike') AS dislikes
    FROM comments c
    WHERE c.board_id = $id
    ORDER BY
        (SELECT COUNT(*) FROM comment_likes WHERE comment_id = c.id AND type = 'like') >= 10 DESC,
        c.id ASC";
    $cres = $conn->query($csql);
    if ($cres) {
        while ($row = $cres->fetch_assoc()) $comments_data[] = $row;
    }
}

// 내 댓글 반응
$my_comment_likes = [];
if ($user && !empty($comments_data)) {
    $uid = (int)$user['id'];
    $ids = implode(',', array_column($comments_data, 'id'));
    $res = $conn->query("SELECT comment_id, type FROM comment_likes WHERE comment_id IN ($ids) AND user_id = $uid");
    if ($res) {
        while ($row = $res->fetch_assoc()) $my_comment_likes[(int)$row['comment_id']] = $row['type'];
    }
}

$comment_count = count($comments_data);
$is_own_post   = $user && $post && $post['author'] === $user['username'];
$can_like_post = $user && !$is_own_post;

$title = $post ? $post['title'] : '게시글';
include __DIR__ . '/header.php';
?>
<div class="container">
    <?php include __DIR__ . '/sidebar.php'; ?>
    <main>
        <div class="card">
            <?php if (!$post): ?>
                <div class="alert error">게시글을 찾을 수 없습니다.</div>
                <a href="board.php" class="btn secondary">목록으로</a>
            <?php else: ?>
                <h2>
                    <?= htmlspecialchars($post['title']) ?>
                    <?php if ((int)$post['views'] >= 50): ?>
                        <span class="badge hot">HOT</span>
                    <?php endif; ?>
                </h2>
                <p style="color:#888; font-size:0.9em;">
                    <?= htmlspecialchars($post['author']) ?>
                    · <?= $post['created_at'] ?>
                    · 조회 <?= $post['views'] ?>
                </p>
                <hr>
                <!-- 의도적으로 raw 출력 (XSS 시연용) -->
                <div style="min-height:120px; padding:8px 0;"><?= nl2br($post['content']) ?></div>
                <hr>

                <!-- 게시물 좋아요/싫어요 -->
                <div class="like-area">
                    <button id="btn-like"
                            class="like-btn like-type <?= $my_post_like === 'like' ? 'active' : '' ?>"
                            <?= !$can_like_post ? 'disabled title="' . ($user ? '자신의 글입니다' : '로그인이 필요합니다') . '"' : '' ?>
                            onclick="likePost('like')">
                        👍 좋아요 <span id="cnt-like"><?= $post_likes ?></span>
                    </button>
                    <button id="btn-dislike"
                            class="like-btn dislike-type <?= $my_post_like === 'dislike' ? 'active' : '' ?>"
                            <?= !$can_like_post ? 'disabled' : '' ?>
                            onclick="likePost('dislike')">
                        👎 싫어요 <span id="cnt-dislike"><?= $post_dislikes ?></span>
                    </button>
                </div>

                <a href="board.php" class="btn secondary">목록</a>
                <?php if ($user && ($is_admin || $post['author'] === $user['username'])): ?>
                    <a href="delete.php?type=post&id=<?= $post['id'] ?>"
                       class="btn" style="background:#e74c3c; margin-left:6px;"
                       onclick="return confirm('게시글을 삭제하시겠습니까?')">삭제</a>
                <?php endif; ?>
            <?php endif; ?>
        </div>

        <?php if ($post): ?>
        <div class="card">
            <h2>💬 댓글 (<?= $comment_count ?>)</h2>

            <?php if (!empty($comments_data)): ?>
                <?php foreach ($comments_data as $cm):
                    $is_best   = (int)$cm['likes'] >= 10;
                    $cm_id     = (int)$cm['id'];
                    $is_own_cm = $user && $cm['author'] === $user['username'];
                    $my_cm_lk  = $my_comment_likes[$cm_id] ?? null;
                ?>
                    <div class="comment <?= $is_best ? 'best-comment' : '' ?>" data-cid="<?= $cm_id ?>">
                        <div class="meta">
                            <b><?= htmlspecialchars($cm['author']) ?></b>
                            <?php if ($is_best): ?>
                                <span class="badge-best">⭐ BEST</span>
                            <?php endif; ?>
                            · <?= $cm['created_at'] ?>
                        </div>
                        <!-- 의도적으로 raw 출력 (XSS 시연용) -->
                        <div class="body"><?= $cm['content'] ?></div>
                        <div class="comment-like-area">
                            <button class="comment-like-btn like-type <?= $my_cm_lk === 'like' ? 'active' : '' ?>"
                                    <?= (!$user || $is_own_cm) ? 'disabled' : '' ?>
                                    onclick="likeComment(<?= $cm_id ?>, 'like', this)">
                                👍 <span class="cl-cnt"><?= (int)$cm['likes'] ?></span>
                            </button>
                            <button class="comment-like-btn dislike-type <?= $my_cm_lk === 'dislike' ? 'active' : '' ?>"
                                    <?= (!$user || $is_own_cm) ? 'disabled' : '' ?>
                                    onclick="likeComment(<?= $cm_id ?>, 'dislike', this)">
                                👎 <span class="cl-cnt"><?= (int)$cm['dislikes'] ?></span>
                            </button>
                        </div>
                    </div>
                <?php endforeach; ?>
            <?php else: ?>
                <p style="color:#888;">아직 댓글이 없습니다.</p>
            <?php endif; ?>

            <?php if (current_user()): ?>
                <form method="post" style="margin-top:12px;">
                    <textarea name="content" placeholder="댓글을 입력하세요" rows="3" required></textarea>
                    <div class="actions" style="margin-top:6px;">
                        <button type="submit" class="btn">댓글 등록</button>
                    </div>
                </form>
            <?php else: ?>
                <p style="color:#888; margin-top:12px;">
                    댓글을 작성하려면 <a href="login.php">로그인</a>하세요.
                </p>
            <?php endif; ?>
        </div>
        <?php endif; ?>
    </main>
</div>

<script>
function likePost(type) {
    fetch('like_post.php', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: 'post_id=<?= $id ?>&type=' + type
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.error) { alert(d.error); return; }
        document.getElementById('cnt-like').textContent    = d.likes;
        document.getElementById('cnt-dislike').textContent = d.dislikes;
        document.getElementById('btn-like').classList.toggle('active',    d.my_type === 'like');
        document.getElementById('btn-dislike').classList.toggle('active', d.my_type === 'dislike');
    });
}

function likeComment(cid, type, btn) {
    fetch('like_comment.php', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: 'comment_id=' + cid + '&type=' + type
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
        if (d.error) { alert(d.error); return; }
        var wrap = btn.closest('[data-cid]');
        var btns = wrap.querySelectorAll('.comment-like-btn');
        btns[0].querySelector('.cl-cnt').textContent = d.likes;
        btns[1].querySelector('.cl-cnt').textContent = d.dislikes;
        btns[0].classList.toggle('active', d.my_type === 'like');
        btns[1].classList.toggle('active', d.my_type === 'dislike');
    });
}
</script>

<?php
$conn->close();
include __DIR__ . '/footer.php';
?>
