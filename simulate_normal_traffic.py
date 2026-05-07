"""duration 기반 continuous 정상 트래픽 시뮬레이션.

핵심 설계:
  - duration 동안 계속 새 사용자 세션 생성 (기존: 방문자 수 고정)
  - --users 는 최대 제한 (0 = 무제한)
  - duration 종료 후 이미 시작된 세션은 자연스럽게 완료 대기
  - 컨테이너 1개 = src IP 1개 → 10개 컨테이너 = 10개 다른 IP
  - 공격 트래픽 완전 배제 (SQLi / XSS / 로그인 실패 반복 없음)

실행:
    python -m model.simulate_normal_traffic --client-id normal-client-1 --no-pcap
    python -m model.simulate_normal_traffic \\
        --base-url http://apache_server --users 80 --duration 600 \\
        --max-workers 8 --arrival-min 0.8 --arrival-max 3.0 \\
        --client-id normal-client-1 --no-pcap
"""
from __future__ import annotations

import argparse
import random
import string
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import requests
    HAVE_REQUESTS = True
except ImportError:
    HAVE_REQUESTS = False

# ── 기본 설정 ──────────────────────────────────────────────────────────────
DEFAULT_BASE_URL    = "http://apache_server"
DEFAULT_USERS       = 0         # 0 이면 무제한 (duration이 상한선)
DEFAULT_DURATION    = 600
DEFAULT_MAX_WORKERS = 8
DEFAULT_ARRIVAL_MIN = 0.8
DEFAULT_ARRIVAL_MAX = 3.0
DEFAULT_CLIENT_ID   = "normal-client"
PCAP_DIR            = Path("/pcap")
PROGRESS_INTERVAL   = 60        # 진행 출력 주기 (초)

# ── 정상 계정 목록 (seed_normal_users.sql 과 반드시 일치) ──────────────────
ACCOUNTS: List[Dict[str, str]] = [
    {"username": f"user{i}", "password": f"pass{i}"}
    for i in range(1, 51)
]
ACCOUNTS += [
    {"username": "admin",   "password": "admin123"},
    {"username": "test",    "password": "test123"},
    {"username": "bob",     "password": "bob123"},
    {"username": "alice",   "password": "alice123"},
    {"username": "charlie", "password": "charlie123"},
]

POST_ID_RANGE   = (1, 20)
SEARCH_KEYWORDS = ["정보", "공유", "좋은", "오늘", "감사", "질문", "추천"]

# ── User-Agent 목록 ────────────────────────────────────────────────────────
UA_LIST: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
    "Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 14; Mobile; rv:121.0) "
    "Gecko/121.0 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
]

# ── 게시글 제목 / 내용 / 댓글 ──────────────────────────────────────────────
_TITLES = [
    "오늘 배운 것을 공유합니다", "자유롭게 이야기해요",
    "좋은 하루 보내세요", "유용한 정보 나눔", "일상 이야기",
    "추천 콘텐츠", "도움 요청합니다", "오늘의 생각",
    "궁금한 것이 있어요", "정보 공유합니다",
    "처음 가입했습니다", "오늘 하루 어떠셨나요",
]
_CONTENTS = [
    "오늘은 날씨가 정말 좋았습니다. 모두 좋은 하루 보내시길 바랍니다.",
    "여러분과 좋은 정보를 나누고 싶어서 글을 작성했습니다.",
    "카페를 이용하면서 느낀 점을 공유합니다. 잘 부탁드립니다.",
    "궁금한 점이 있어서 글을 남깁니다. 답변 부탁드립니다.",
    "오늘도 열심히 활동하겠습니다. 모두 파이팅!",
    "처음 가입해서 첫 글을 남겨봅니다. 잘 부탁드려요.",
    "좋은 정보가 많네요. 앞으로 자주 방문하겠습니다.",
    "오늘 있었던 일을 간단히 기록해 봅니다.",
]
_COMMENTS = [
    "Very helpful information",
    "Thanks for posting this",
    "Interesting point of view",
    "좋은 글 감사합니다!", "정말 유용한 정보네요.",
    "공감합니다!", "좋은 하루 되세요.",
    "감사합니다. 많은 도움이 됐어요.", "잘 읽었습니다.",
    "응원합니다!", "저도 같은 생각이에요.", "좋은 정보 감사해요.",
]

# ── 시나리오 정의 ──────────────────────────────────────────────────────────
# S1  Quick Visitor      (15%) : 1~5초
# S2  Board Reader       (30%) : 20~60초
# S3  Login and Browse   (15%) : 30~90초
# S4  Writer             ( 8%) : 25~70초
# S5  Commenter          ( 8%) : 25~70초
# S6  Board Searcher     ( 5%) : 15~40초
# S7  My Page Visitor    ( 7%) : 20~50초
# S8  Message User       ( 5%) : 20~50초
# S9  Hot Board Visitor  ( 2%) : 15~45초
# S10 Keep-Alive Power   ( 5%) : 60~180초
_SCENARIO_IDS = ["s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10"]
_WEIGHTS      = [15,   30,   15,   8,    8,    5,    7,    5,    2,    5  ]

_SCENARIO_LABEL: Dict[str, str] = {
    "s1":  "Quick Visitor     ",
    "s2":  "Board Reader      ",
    "s3":  "Login and Browse  ",
    "s4":  "Writer            ",
    "s5":  "Commenter         ",
    "s6":  "Board Searcher    ",
    "s7":  "My Page Visitor   ",
    "s8":  "Message User      ",
    "s9":  "Hot Board Visitor ",
    "s10": "Keep-Alive Power  ",
}

# ── Connection: close 공통 헤더 ────────────────────────────────────────────
_CLOSE_HEADERS = {
    "Accept":          "text/html,application/xhtml+xml,application/xml;"
                       "q=0.9,*/*;q=0.8",
    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8",
    "Accept-Encoding": "gzip, deflate",
    "Connection":      "close",
}


def _rand_suffix(n: int = 6) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


# ── 공유 통계 (thread-safe) ────────────────────────────────────────────────
_lock  = threading.Lock()
_plock = threading.Lock()

_stats: Dict[str, Any] = {
    "arrived":    0,
    "completed":  0,
    "active":     0,
    "max_active": 0,
    "total_req":  0,
    "success":    0,
    "fail":       0,
    "times":      [],
    "by_type":    {s: 0 for s in _SCENARIO_IDS},
}


def _record(status: int, elapsed: float) -> None:
    with _lock:
        _stats["total_req"] += 1
        _stats["times"].append(elapsed)
        if 200 <= status < 400:
            _stats["success"] += 1
        else:
            _stats["fail"] += 1


def _log(msg: str) -> None:
    with _plock:
        print(msg, flush=True)


# ── HTTP 헬퍼 ──────────────────────────────────────────────────────────────

def _get(url: str, sess: Optional[requests.Session] = None) -> int:
    t0 = time.time()
    status = 0
    try:
        if sess is not None:
            r = sess.get(url, timeout=10, allow_redirects=True)
        else:
            hdrs = {**_CLOSE_HEADERS, "User-Agent": random.choice(UA_LIST)}
            r = requests.get(url, headers=hdrs, timeout=10, allow_redirects=True)
        status = r.status_code
        r.close()
    except Exception:
        status = 0
    finally:
        _record(status, time.time() - t0)
    return status


def _post(url: str, data: Dict[str, str],
          sess: Optional[requests.Session] = None) -> int:
    t0 = time.time()
    status = 0
    try:
        if sess is not None:
            r = sess.post(url, data=data, timeout=10, allow_redirects=True)
        else:
            hdrs = {**_CLOSE_HEADERS, "User-Agent": random.choice(UA_LIST)}
            r = requests.post(url, data=data, headers=hdrs,
                              timeout=10, allow_redirects=True)
        status = r.status_code
        r.close()
    except Exception:
        status = 0
    finally:
        _record(status, time.time() - t0)
    return status


def _pause(lo: float, hi: float) -> None:
    time.sleep(random.uniform(lo, hi))


def _new_sess(keep_alive: bool = False) -> requests.Session:
    sess = requests.Session()
    sess.headers.update({
        "Accept":          "text/html,application/xhtml+xml,application/xml;"
                           "q=0.9,*/*;q=0.8",
        "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Connection":      "keep-alive" if keep_alive else "close",
        "User-Agent":      random.choice(UA_LIST),
    })
    return sess


def _login(base: str, sess: requests.Session) -> None:
    """세션에 로그인 쿠키를 심는다."""
    _get(base + "/login.php", sess=sess)
    _pause(2.0, 5.0)
    creds = random.choice(ACCOUNTS)
    _post(base + "/login.php",
          data={"username": creds["username"], "password": creds["password"]},
          sess=sess)


# ── 시나리오별 행동 ────────────────────────────────────────────────────────

def _s1_quick_visitor(base: str) -> None:
    """Quick Visitor (15%): 메인/게시판만 빠르게 보고 이탈. 전체 1~5초."""
    _get(base + random.choice(["/index.php", "/board.php"]))
    _pause(1.0, 3.0)


def _s2_board_reader(base: str) -> None:
    """Board Reader (30%): 게시판 탐색 + 게시글 1~3개 읽기. 전체 20~60초."""
    _get(base + random.choice(["/index.php", "/board.php"]))
    _pause(3.0, 8.0)
    _get(base + "/board.php")
    _pause(3.0, 8.0)
    for _ in range(random.randint(1, 3)):
        pid = random.randint(*POST_ID_RANGE)
        _get(base + f"/post.php?id={pid}")
        _pause(5.0, 15.0)


def _s3_login_browse(base: str) -> None:
    """Login and Browse (15%): 로그인 후 게시글 탐색. 전체 30~90초.
    Session + Connection: close (쿠키 유지, TCP는 매번 닫기)
    """
    with _new_sess(keep_alive=False) as sess:
        _login(base, sess)
        _pause(5.0, 10.0)
        pool = [
            "/board.php",
            "/board.php?sort=views",
            "/board.php?sort=likes",
            f"/post.php?id={random.randint(*POST_ID_RANGE)}",
            f"/post.php?id={random.randint(*POST_ID_RANGE)}",
            "/hot.php",
        ]
        for path in random.sample(pool, k=random.randint(2, 4)):
            _get(base + path, sess=sess)
            _pause(5.0, 12.0)
        _get(base + "/logout.php", sess=sess)


def _s4_writer(base: str) -> None:
    """Writer (8%): 로그인 후 게시글 1편 작성. 전체 25~70초."""
    with _new_sess(keep_alive=False) as sess:
        _login(base, sess)
        _pause(3.0, 8.0)
        _get(base + "/write.php", sess=sess)
        _pause(8.0, 20.0)    # 글 작성 시간
        title   = random.choice(_TITLES)   + f" [{_rand_suffix()}]"
        content = random.choice(_CONTENTS) + f" ({_rand_suffix(8)})"
        _post(base + "/write.php",
              data={"title": title, "content": content}, sess=sess)
        _pause(3.0, 8.0)
        _get(base + "/board.php", sess=sess)
        _pause(3.0, 8.0)
        _get(base + "/logout.php", sess=sess)


def _s5_commenter(base: str) -> None:
    """Commenter (8%): 로그인 후 게시글 읽고 댓글 작성. 전체 25~70초."""
    with _new_sess(keep_alive=False) as sess:
        _login(base, sess)
        _pause(3.0, 8.0)
        pid = random.randint(*POST_ID_RANGE)
        _get(base + f"/post.php?id={pid}", sess=sess)
        _pause(8.0, 20.0)    # 읽는 시간
        _post(base + f"/post.php?id={pid}",
              data={"content": random.choice(_COMMENTS)}, sess=sess)
        _pause(2.0, 5.0)
        _get(base + "/logout.php", sess=sess)


def _s6_searcher(base: str) -> None:
    """Board Searcher (5%): 검색 후 결과 탐색. 전체 15~40초."""
    kw = random.choice(SEARCH_KEYWORDS)
    _get(base + f"/board.php?q={kw}")
    _pause(3.0, 8.0)
    for _ in range(random.randint(1, 2)):
        pid = random.randint(*POST_ID_RANGE)
        _get(base + f"/post.php?id={pid}")
        _pause(4.0, 12.0)


def _s7_mypage(base: str) -> None:
    """My Page Visitor (7%): 로그인 후 마이페이지 확인. 전체 20~50초."""
    with _new_sess(keep_alive=False) as sess:
        _login(base, sess)
        _pause(3.0, 8.0)
        _get(base + "/mypage.php", sess=sess)
        _pause(8.0, 20.0)
        # 가끔 게시판도 둘러봄
        if random.random() < 0.4:
            _get(base + "/board.php", sess=sess)
            _pause(3.0, 8.0)
        _get(base + "/logout.php", sess=sess)


def _s8_message_user(base: str) -> None:
    """Message User (5%): 로그인 후 쪽지함 확인. 전체 20~50초."""
    with _new_sess(keep_alive=False) as sess:
        _login(base, sess)
        _pause(3.0, 8.0)
        _get(base + "/messages.php", sess=sess)
        _pause(5.0, 12.0)
        if random.random() < 0.4:
            _get(base + "/messages.php?tab=sent", sess=sess)
            _pause(3.0, 8.0)
        _get(base + "/logout.php", sess=sess)


def _s9_hot_visitor(base: str) -> None:
    """Hot Board Visitor (2%): 핫게시판 중심 탐색. 전체 15~45초."""
    _get(base + "/hot.php")
    _pause(5.0, 15.0)
    pid = random.randint(*POST_ID_RANGE)
    _get(base + f"/post.php?id={pid}")
    _pause(5.0, 15.0)
    _get(base + "/board.php")


def _s10_power_user(base: str) -> None:
    """Keep-Alive Power User (5%): 장시간 세션 + 좋아요 활동. 전체 60~180초.
    Session + Connection: keep-alive
    """
    with _new_sess(keep_alive=True) as sess:
        _login(base, sess)
        _pause(8.0, 15.0)
        _get(base + "/board.php", sess=sess)
        _pause(8.0, 15.0)
        # 게시글 3~6개 읽기
        for _ in range(random.randint(3, 6)):
            pid = random.randint(*POST_ID_RANGE)
            _get(base + f"/post.php?id={pid}", sess=sess)
            _pause(8.0, 25.0)
        # 좋아요 2~3번
        for _ in range(random.randint(2, 3)):
            pid  = random.randint(*POST_ID_RANGE)
            _post(base + "/like_post.php",
                  data={"post_id": str(pid), "type": "like"}, sess=sess)
            _pause(2.0, 5.0)
        _get(base + "/hot.php", sess=sess)
        _pause(8.0, 15.0)
        _get(base + "/mypage.php", sess=sess)
        _pause(5.0, 10.0)
        _get(base + "/logout.php", sess=sess)


_SCENARIO_FN = {
    "s1":  _s1_quick_visitor,
    "s2":  _s2_board_reader,
    "s3":  _s3_login_browse,
    "s4":  _s4_writer,
    "s5":  _s5_commenter,
    "s6":  _s6_searcher,
    "s7":  _s7_mypage,
    "s8":  _s8_message_user,
    "s9":  _s9_hot_visitor,
    "s10": _s10_power_user,
}


# ── 사용자 태스크 ──────────────────────────────────────────────────────────

def _run_user(scenario: str, base_url: str) -> None:
    with _lock:
        _stats["active"] += 1
        _stats["by_type"][scenario] += 1
        if _stats["active"] > _stats["max_active"]:
            _stats["max_active"] = _stats["active"]
    try:
        _SCENARIO_FN[scenario](base_url)
    except Exception:
        pass
    finally:
        with _lock:
            _stats["active"]    -= 1
            _stats["completed"] += 1


# ── tcpdump ────────────────────────────────────────────────────────────────

def _start_tcpdump(pcap_path: Path) -> Optional[subprocess.Popen]:
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    cmd = ["tcpdump", "-i", "eth0", "port", "80", "-w", str(pcap_path)]
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1.0)
        _log(f"[tcpdump] 캡처 시작 → {pcap_path}")
        return proc
    except FileNotFoundError:
        _log("[tcpdump] WARNING: 명령어 없음 — pcap 저장 생략")
        return None
    except Exception as exc:
        _log(f"[tcpdump] WARNING: 시작 실패 ({exc})")
        return None


def _stop_tcpdump(proc: Optional[subprocess.Popen]) -> None:
    if proc is None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    _log("[tcpdump] 캡처 종료")


# ── 진행 출력 스레드 (60초마다) ────────────────────────────────────────────

def _progress_thread(start_ts: float, end_ts: float,
                     done: threading.Event, client_id: str) -> None:
    next_at = float(PROGRESS_INTERVAL)
    while not done.wait(timeout=1.0):
        now     = time.time()
        elapsed = now - start_ts
        if elapsed >= next_at:
            mm        = int(elapsed) // 60
            ss        = int(elapsed) % 60
            remaining = max(0, int(end_ts - now))
            with _lock:
                arrived   = _stats["arrived"]
                completed = _stats["completed"]
                active    = _stats["active"]
                total_req = _stats["total_req"]
                success   = _stats["success"]
            _log(
                f"[{mm:02d}:{ss:02d}] client={client_id} | "
                f"유입: {arrived}명 | 완료: {completed}명 | "
                f"활성: {active}명 | 요청: {total_req}건 | "
                f"성공: {success}건 | 남은시간: {remaining}초"
            )
            next_at += PROGRESS_INTERVAL


# ── 최종 통계 ──────────────────────────────────────────────────────────────

def _print_final(elapsed_actual: float, duration: int,
                 client_id: str, pcap_path: Optional[Path]) -> None:
    with _lock:
        arrived   = _stats["arrived"]
        total_req = _stats["total_req"]
        success   = _stats["success"]
        fail      = _stats["fail"]
        times     = list(_stats["times"])
        by_type   = dict(_stats["by_type"])

    avg_ms = (sum(times) / len(times) * 1000) if times else 0.0

    def pr(n: int) -> str:
        return f"{n / total_req * 100:.1f}%" if total_req else "0.0%"

    mins = duration // 60
    sep  = "=" * 50
    print(f"\n{sep}")
    print(f"  === {mins}분 정상 트래픽 시뮬레이션 완료 ===")
    print(sep)
    print(f"  client_id        : {client_id}")
    print(f"  총 유입 사용자   : {arrived}명")
    print(f"  실제 실행 시간   : {int(elapsed_actual)}초")
    print(f"  총 요청 수       : {total_req:,}건")
    print(f"  성공 (2xx/3xx)   : {success:,}건 ({pr(success)})")
    print(f"  실패 (4xx/5xx)   : {fail:,}건 ({pr(fail)})")
    print(f"  평균 응답시간    : {avg_ms:.0f}ms")
    print(f"  시나리오별:")
    for sid in _SCENARIO_IDS:
        n = by_type.get(sid, 0)
        print(f"    {_SCENARIO_LABEL[sid]}: {n:3d}명")
    if pcap_path:
        print(f"  저장 pcap        : {pcap_path}")
    else:
        print(f"  pcap             : 비활성 (--no-pcap)")
    print(sep)


# ── 시뮬레이션 오케스트레이터 ──────────────────────────────────────────────

def run_simulation(
    n_users:     int,
    duration:    int,
    max_workers: int,
    base_url:    str,
    arrival_min: float,
    arrival_max: float,
    client_id:   str,
    pcap_path:   Optional[Path],
) -> None:
    sep = "=" * 50
    print(f"\n{sep}")
    print(f"  정상 트래픽 시뮬레이션 시작 (duration 기반 continuous)")
    print(sep)
    print(f"  client_id       : {client_id}")
    print(f"  대상 서버       : {base_url}")
    print(f"  최대 방문자     : 무제한 (duration={duration}초가 상한선)")
    print(f"  생성 지속 시간  : {duration}초 ({duration // 60}분)")
    print(f"  최대 동시 활성  : {max_workers}명")
    print(f"  유입 간격       : {arrival_min}~{arrival_max}초")
    print(f"  pcap 저장       : {pcap_path or '비활성 (--no-pcap)'}")
    print(f"{sep}\n")

    if not HAVE_REQUESTS:
        print("[ERROR] requests 라이브러리 필요: pip install requests",
              file=sys.stderr)
        sys.exit(1)

    tcpdump_proc = _start_tcpdump(pcap_path) if pcap_path else None

    start_ts  = time.time()
    end_ts    = start_ts + duration
    prog_done = threading.Event()

    threading.Thread(
        target=_progress_thread,
        args=(start_ts, end_ts, prog_done, client_id),
        daemon=True,
    ).start()

    submitted = 0

    # duration 동안 계속 새 세션 제출
    # with 블록 종료 시 executor.shutdown(wait=True) → 실행 중 세션 완료 대기
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        while time.time() < end_ts:
            # users 제한 없음 — max_workers가 동시 활성 상한선 역할
            scenario = random.choices(_SCENARIO_IDS, weights=_WEIGHTS, k=1)[0]
            executor.submit(_run_user, scenario, base_url)
            submitted += 1
            with _lock:
                _stats["arrived"] += 1
            time.sleep(random.uniform(arrival_min, arrival_max))
        # duration 종료 → 루프 탈출, 이미 시작된 세션만 자연 완료 대기

    prog_done.set()
    elapsed_actual = time.time() - start_ts
    _stop_tcpdump(tcpdump_proc)
    _print_final(elapsed_actual, duration, client_id, pcap_path)


# ── CLI ────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="duration 기반 continuous 정상 트래픽 시뮬레이션",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--base-url",    default=DEFAULT_BASE_URL,
                        metavar="URL",  help="대상 서버 URL")
    parser.add_argument("--users",       type=int, default=DEFAULT_USERS,
                        metavar="N",    help="최대 방문자 수 (0 = 무제한)")
    parser.add_argument("--duration",    type=int, default=DEFAULT_DURATION,
                        metavar="SEC",  help="새 사용자 생성 지속 시간 (초)")
    parser.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS,
                        metavar="N",    help="동시 활성 세션 수")
    parser.add_argument("--arrival-min", type=float, default=DEFAULT_ARRIVAL_MIN,
                        metavar="SEC",  help="유입 최소 간격 (초)")
    parser.add_argument("--arrival-max", type=float, default=DEFAULT_ARRIVAL_MAX,
                        metavar="SEC",  help="유입 최대 간격 (초)")
    parser.add_argument("--client-id",   default=DEFAULT_CLIENT_ID,
                        metavar="ID",   help="컨테이너 식별자 (로그/파일명)")
    parser.add_argument("--no-pcap",     action="store_true",
                        help="pcap 캡처 없이 트래픽만 생성")
    args = parser.parse_args()

    pcap_path = (
        None if args.no_pcap
        else PCAP_DIR / f"normal_{args.client_id}.pcap"
    )

    run_simulation(
        n_users=args.users,
        duration=args.duration,
        max_workers=args.max_workers,
        base_url=args.base_url,
        arrival_min=args.arrival_min,
        arrival_max=args.arrival_max,
        client_id=args.client_id,
        pcap_path=pcap_path,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
