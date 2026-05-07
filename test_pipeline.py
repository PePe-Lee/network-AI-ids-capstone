"""Snort → ML 순차 교차 검증 테스트 파이프라인.

동작:
    1. 각 플로우에 Snort 시그니처 탐지 실행
    2. ML 이상탐지 항상 실행 (교차 검증)
    3. 결과 비교:
       - 둘 다 탐지  → 확실한 공격 (Snort + ML 모두 탐지)
       - Snort만     → Snort만 탐지 (시그니처 매칭, ML은 정상 판단)
       - ML만        → ML만 탐지   (이상탐지, Snort 패턴 없음)
       - 둘 다 정상  → 정상 트래픽

사용법:
    # PCAP 파일 분석
    python -m model.test_pipeline /pcap/test_attack.pcap

    # 내장 샘플 플로우로 빠른 테스트
    python -m model.test_pipeline --sample

    # 임계값 조정
    python -m model.test_pipeline --sample --sig-threshold 0.3 --ml-threshold 0.4
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

DEFAULT_SIG_THRESHOLD = float(os.getenv("SIGNATURE_THRESHOLD", "0.5"))
DEFAULT_ML_THRESHOLD  = float(os.getenv("ML_THRESHOLD",        "0.5"))

# CICIDS2017 Flow Duration 정상 범위 (단위: ms)
_CICIDS_DURATION_MIN_MS = 10.0
_CICIDS_DURATION_MAX_MS = 10_000.0


def _check_environment(flows: List[Dict[str, Any]]) -> None:
    """Flow Duration 분포를 확인하고 CICIDS 범위 및 지연 설정 여부를 출력한다."""
    # Flow Duration은 CICIDS2017 기준 마이크로초(μs) 단위
    durations_ms = [
        f["flow"]["Flow Duration"] / 1_000
        for f in flows
        if f.get("flow", {}).get("Flow Duration") is not None
    ]
    if not durations_ms:
        print("[환경 체크] Flow Duration 데이터 없음")
    else:
        avg_ms = sum(durations_ms) / len(durations_ms)
        in_range = sum(
            1 for d in durations_ms
            if _CICIDS_DURATION_MIN_MS <= d <= _CICIDS_DURATION_MAX_MS
        )
        pct = in_range / len(durations_ms) * 100
        print(
            f"[환경 체크] Flow Duration 평균: {avg_ms:.1f}ms"
            f"  (CICIDS 정상범위: {_CICIDS_DURATION_MIN_MS:.0f}~{_CICIDS_DURATION_MAX_MS:.0f}ms)"
        )
        print(f"[환경 체크] CICIDS 범위 내 플로우: {in_range}/{len(durations_ms)} ({pct:.0f}%)")

    delay_ms = int(os.getenv("NETWORK_DELAY_MS", "0"))
    if delay_ms > 0:
        print(f"[환경 체크] 지연 설정 감지됨 (NETWORK_DELAY_MS={delay_ms}ms)")
    else:
        print("[환경 체크] 지연 설정 미감지 (NETWORK_DELAY_MS 미설정)")

# ── 내장 샘플 플로우 ──────────────────────────────────────────────────
_SAMPLE_FLOWS: List[Dict[str, Any]] = [
    {
        "label": "정상 HTTP GET",
        "src_ip": "10.0.0.1", "dst_ip": "172.18.0.2", "src_port": 12001, "dst_port": 80,
        "payload":     "GET /index.php HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "http_method": "GET", "http_path": "/index.php",
        "flow": {
            "Flow Duration": 500_000.0, "Total Fwd Packets": 3.0,
            "Total Backward Packets": 2.0, "Fwd Packets/s": 6.0,
            "Bwd Packets/s": 4.0, "SYN Flag Count": 1.0,
            "ACK Flag Count": 5.0, "RST Flag Count": 0.0,
            "Average Packet Size": 320.0,
        },
    },
    {
        "label": "정상 HTTP POST (로그인 성공)",
        "src_ip": "10.0.0.2", "dst_ip": "172.18.0.2", "src_port": 12002, "dst_port": 80,
        "payload":     "POST /login.php HTTP/1.1\r\nContent: username=alice&password=alice2024",
        "http_method": "POST", "http_path": "/login.php",
        "flow": {
            "Flow Duration": 300_000.0, "Total Fwd Packets": 2.0,
            "Total Backward Packets": 2.0, "Fwd Packets/s": 6.7,
            "Bwd Packets/s": 6.7, "SYN Flag Count": 1.0,
            "ACK Flag Count": 4.0, "RST Flag Count": 0.0,
            "Average Packet Size": 400.0,
        },
    },
    {
        "label": "SQL Injection (OR 1=1)",
        "src_ip": "10.0.0.5", "dst_ip": "172.18.0.2", "src_port": 54301, "dst_port": 80,
        "payload":     "POST /login.php HTTP/1.1\r\nContent: username=admin&password=' OR '1'='1",
        "http_method": "POST", "http_path": "/login.php",
        "flow": {
            "Flow Duration": 100_000.0, "Total Fwd Packets": 2.0,
            "Total Backward Packets": 1.0, "Fwd Packets/s": 20.0,
            "Bwd Packets/s": 10.0, "SYN Flag Count": 1.0,
            "ACK Flag Count": 2.0, "RST Flag Count": 0.0,
            "Average Packet Size": 580.0,
        },
    },
    {
        "label": "SQL Injection (UNION SELECT)",
        "src_ip": "10.0.0.5", "dst_ip": "172.18.0.2", "src_port": 54302, "dst_port": 80,
        "payload":     "GET /board.php?q=1' UNION SELECT 1,username,password FROM users-- HTTP/1.1",
        "http_method": "GET", "http_path": "/board.php",
        "flow": {
            "Flow Duration": 120_000.0, "Total Fwd Packets": 1.0,
            "Total Backward Packets": 1.0, "Fwd Packets/s": 8.3,
            "Bwd Packets/s": 8.3, "SYN Flag Count": 1.0,
            "ACK Flag Count": 2.0, "RST Flag Count": 0.0,
            "Average Packet Size": 490.0,
        },
    },
    {
        "label": "XSS 공격 (<script>)",
        "src_ip": "10.0.0.6", "dst_ip": "172.18.0.2", "src_port": 54401, "dst_port": 80,
        "payload":     "POST /write.php HTTP/1.1\r\ncontent=<script>alert(document.cookie)</script>",
        "http_method": "POST", "http_path": "/write.php",
        "flow": {
            "Flow Duration": 80_000.0, "Total Fwd Packets": 2.0,
            "Total Backward Packets": 1.0, "Fwd Packets/s": 25.0,
            "Bwd Packets/s": 12.0, "SYN Flag Count": 1.0,
            "ACK Flag Count": 3.0, "RST Flag Count": 0.0,
            "Average Packet Size": 400.0,
        },
    },
    {
        "label": "XSS 공격 (onerror=)",
        "src_ip": "10.0.0.6", "dst_ip": "172.18.0.2", "src_port": 54402, "dst_port": 80,
        "payload":     "POST /write.php HTTP/1.1\r\ncontent=<img src=x onerror=alert(1)>",
        "http_method": "POST", "http_path": "/write.php",
        "flow": {
            "Flow Duration": 60_000.0, "Total Fwd Packets": 2.0,
            "Total Backward Packets": 1.0, "Fwd Packets/s": 33.0,
            "Bwd Packets/s": 16.0, "SYN Flag Count": 1.0,
            "ACK Flag Count": 3.0, "RST Flag Count": 0.0,
            "Average Packet Size": 360.0,
        },
    },
    {
        "label": "DoS / SYN 플러드",
        "src_ip": "10.0.0.10", "dst_ip": "172.18.0.2", "src_port": 53000, "dst_port": 80,
        "payload":     "",
        "http_method": "", "http_path": "",
        "flow": {
            "Flow Duration": 10_000.0, "Total Fwd Packets": 50.0,
            "Total Backward Packets": 0.0, "Fwd Packets/s": 5_000.0,
            "Bwd Packets/s": 0.0, "SYN Flag Count": 50.0,
            "ACK Flag Count": 0.0, "RST Flag Count": 0.0,
            "Average Packet Size": 60.0,
        },
    },
]

# Brute Force: 동일 IP에서 /login.php POST 반복 (10회 → 슬라이딩 윈도우 발동)
_BF_TEMPLATE: Dict[str, Any] = {
    "label": "Brute Force 로그인 시도",
    "src_ip": "10.0.0.7", "dst_ip": "172.18.0.2", "src_port": 55000, "dst_port": 80,
    "payload":     "POST /login.php HTTP/1.1\r\nContent: username=admin&password=wrong",
    "http_method": "POST", "http_path": "/login.php",
    "flow": {
        "Flow Duration": 50_000.0, "Total Fwd Packets": 1.0,
        "Total Backward Packets": 0.0, "Fwd Packets/s": 20.0,
        "Bwd Packets/s": 0.0, "SYN Flag Count": 1.0,
        "ACK Flag Count": 0.0, "RST Flag Count": 0.0,
        "Average Packet Size": 200.0,
    },
}


# ── 출력 헬퍼 ─────────────────────────────────────────────────────────

def _mark(label: str, conf: float, is_attack: bool) -> str:
    icon = "🔴" if is_attack else "🟢"
    return f"{icon} {label}({conf:.3f})"


_VERDICT_TEXT = {
    "BOTH":       "✅  확실한 공격   (둘 다 탐지)",
    "SNORT_ONLY": "⚠️   Snort만 탐지  (ML은 정상 판단)",
    "ML_ONLY":    "🤖  ML만 탐지    (이상탐지)",
    "BENIGN":     "✓   정상 트래픽",
}


# ── 파이프라인 ────────────────────────────────────────────────────────

def run_pipeline(
    flows: List[Dict[str, Any]],
    sig_threshold: float = DEFAULT_SIG_THRESHOLD,
    ml_threshold:  float = DEFAULT_ML_THRESHOLD,
) -> List[Dict[str, Any]]:
    """Snort + ML 순차 교차 검증.  같은 SignatureModel 인스턴스를 재사용하므로
    Brute Force 슬라이딩 윈도우가 플로우를 처리하면서 누적된다."""
    import numpy as np
    import joblib
    from model.anomaly_model   import AnomalyModel
    from model.signature_model import SignatureModel
    from model.fusion          import _normalize_label

    sig_model = SignatureModel()

    # adaptive_model 로드 시도
    _MODEL_DIR      = Path("/app/model")
    _ADAPTIVE_PATH  = _MODEL_DIR / "adaptive_model.pkl"
    _LOCAL_BASELINE = _MODEL_DIR / "local_baseline.pkl"
    _BENIGN_BASELINE = _MODEL_DIR / "benign_baseline.pkl"

    adaptive_model: Any = None
    baseline: Any = None
    model_name = "AnomalyModel"

    if _ADAPTIVE_PATH.exists():
        adaptive_model = joblib.load(_ADAPTIVE_PATH)
        print("[test_pipeline] adaptive_model 사용")
        model_name = "adaptive_model"
        baseline_path = _LOCAL_BASELINE if _LOCAL_BASELINE.exists() else _BENIGN_BASELINE
        baseline = joblib.load(baseline_path)

        # dict면 BenignBaseline으로 변환
        if isinstance(baseline, dict):
            from model.benign_baseline import BenignBaseline
            bb = BenignBaseline()
            bb.stats = baseline.get("stats", baseline)
            bb.n_samples = baseline.get("n_samples", 0)
            baseline = bb

        # transform 없으면 benign_baseline.pkl로 재시도
        if not hasattr(baseline, "transform"):
            print("[test_pipeline] baseline transform 없음 → benign_baseline.pkl 사용")
            from model.benign_baseline import BenignBaseline
            baseline = BenignBaseline.load(str(_BENIGN_BASELINE))
    else:
        ml_model = AnomalyModel()

    results: List[Dict[str, Any]] = []
    for f in flows:
        feat     = f.get("flow", {})
        payload  = f.get("payload", "")
        src_ip   = f.get("src_ip", "")
        method   = f.get("http_method", "")
        path     = f.get("http_path", "")
        dst_port = int(f.get("dst_port", 0))

        # 포트 3306(MySQL 내부 통신)은 CICIDS 학습 범위 밖 → ML 제외
        skip_ml = dst_port == 3306

        # 1. Snort (전 포트 실행)
        sig_label, sig_conf, sig_matches = sig_model.evaluate(
            payload=payload, src_ip=src_ip, http_method=method, path=path
        )
        sig_label    = _normalize_label(sig_label)
        snort_attack = sig_label != "BENIGN" and sig_conf >= sig_threshold

        # 2. ML (포트 80/443만 실행, 3306은 제외)
        if skip_ml:
            ml_label, ml_conf = "SKIPPED", 0.0
            ml_attack = False
        elif adaptive_model is not None:
            # baseline Z-Score 변환 후 adaptive_model 예측
            if hasattr(baseline, "feature_names_in_"):
                feature_names = list(baseline.feature_names_in_)
            else:
                feature_names = sorted(feat.keys())
            X_raw = np.array([[feat.get(k, 0.0) for k in feature_names]], dtype=float)
            X = baseline.transform(X_raw)
            pred = adaptive_model.predict(X)[0]
            if hasattr(adaptive_model, "predict_proba"):
                proba = adaptive_model.predict_proba(X)[0]
                ml_conf = float(max(proba))
            else:
                ml_conf = 1.0 if pred != 0 else 0.0
            ml_label  = _normalize_label("ATTACK" if pred != 0 else "BENIGN")
            ml_attack = ml_label != "BENIGN" and ml_conf >= ml_threshold
        else:
            ml_label, ml_conf, _ = ml_model.predict_flow(feat)
            ml_label  = _normalize_label(ml_label)
            ml_attack = ml_label != "BENIGN" and ml_conf >= ml_threshold

        # 3. 비교 판정
        if snort_attack and ml_attack:
            verdict = "BOTH"
        elif snort_attack:
            verdict = "SNORT_ONLY"
        elif ml_attack:
            verdict = "ML_ONLY"
        else:
            verdict = "BENIGN"

        results.append({
            "src_ip":       src_ip,
            "src_port":     f.get("src_port", 0),
            "dst_ip":       f.get("dst_ip", ""),
            "dst_port":     dst_port,
            "label":        f.get("label", ""),
            "snort_label":  sig_label,
            "snort_conf":   sig_conf,
            "snort_attack": snort_attack,
            "ml_label":     ml_label,
            "ml_conf":      ml_conf,
            "ml_attack":    ml_attack,
            "ml_skipped":   skip_ml,
            "verdict":      verdict,
            "matches":      sig_matches,
            "model_name":   model_name,
        })
    return results


def print_results(results: List[Dict[str, Any]]) -> None:
    for r in results:
        print(
            f"\n[FLOW] {r['src_ip']}:{r['src_port']} → "
            f"{r['dst_ip']}:{r['dst_port']}"
            + (f"  ({r['label']})" if r.get("label") else "")
        )
        snort_str = _mark(r["snort_label"], r["snort_conf"], r["snort_attack"])
        if r.get("matches"):
            types = ", ".join(sorted({m["type"] for m in r["matches"]}))
            snort_str += f"  [rules: {types}]"
        print(f"  Snort  : {snort_str}")
        if r.get("ml_skipped"):
            print(f"  ML     : ⚪ SKIPPED (포트 3306 - Snort 전용)")
        else:
            print(f"  ML     : {_mark(r['ml_label'], r['ml_conf'], r['ml_attack'])}")
        print(f"  최종   : {_VERDICT_TEXT[r['verdict']]}")

    snort_cnt    = sum(1 for r in results if r["snort_attack"])
    ml_cnt       = sum(1 for r in results if r["ml_attack"])
    both_cnt     = sum(1 for r in results if r["verdict"] == "BOTH")
    benign       = sum(1 for r in results if r["verdict"] == "BENIGN")
    db_port_cnt  = sum(1 for r in results if r.get("ml_skipped"))
    web_port_cnt = len(results) - db_port_cnt

    model_name = results[0]["model_name"] if results else "unknown"

    print("\n" + "=" * 62)
    print("  [SUMMARY]")
    print(f"  사용 모델  : {model_name}")
    print(f"  총 플로우  : {len(results)}")
    print(f"  Snort 탐지 : {snort_cnt}")
    print(f"  ML 탐지    : {ml_cnt}")
    print(f"  둘 다 탐지 : {both_cnt}  (확실한 공격)")
    print(f"  Snort만    : {snort_cnt - both_cnt}")
    print(f"  ML만       : {ml_cnt - both_cnt}")
    print(f"  정상       : {benign}")
    print(f"  포트별 분석: 80/443(ML+Snort)={web_port_cnt} / 3306(Snort전용)={db_port_cnt}")
    print("=" * 62)


# ── CLI ──────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Snort → ML 순차 교차 검증 파이프라인"
    )
    parser.add_argument("pcap",            nargs="?",  help="분석할 PCAP 파일 경로")
    parser.add_argument("--sample",        action="store_true",
                        help="내장 샘플 플로우로 테스트")
    parser.add_argument("--sig-threshold", type=float, default=DEFAULT_SIG_THRESHOLD)
    parser.add_argument("--ml-threshold",  type=float, default=DEFAULT_ML_THRESHOLD)
    parser.add_argument("--max-packets",   type=int,   default=50_000)
    args = parser.parse_args()

    if args.sample or not args.pcap:
        print("[test_pipeline] 내장 샘플 플로우 사용")
        # Brute Force 슬라이딩 윈도우 발동을 위해 10회 반복
        bf_flows: List[Dict[str, Any]] = []
        for i in range(10):
            bf = _BF_TEMPLATE.copy()
            bf["label"]    = f"Brute Force #{i+1}"
            bf["src_port"] = 55000 + i
            bf["flow"]     = dict(_BF_TEMPLATE["flow"])
            bf_flows.append(bf)
        flows: List[Dict[str, Any]] = _SAMPLE_FLOWS + bf_flows
    else:
        pcap_path = Path(args.pcap)
        if not pcap_path.exists():
            print(f"[test_pipeline] 파일 없음: {pcap_path}", file=sys.stderr)
            return 1
        print(f"[test_pipeline] PCAP 분석: {pcap_path}")
        try:
            from model.pcap_predict import extract_flows
        except ImportError as e:
            print(f"[test_pipeline] scapy 필요: {e}", file=sys.stderr)
            return 1
        raw = extract_flows(pcap_path, max_packets=args.max_packets)
        print(f"[test_pipeline] {len(raw)}개 플로우 추출")
        meta_keys = {"src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                     "payload", "http_method", "http_path"}
        flows = [
            {
                "src_ip":      f.get("src_ip", ""),
                "dst_ip":      f.get("dst_ip", ""),
                "src_port":    f.get("src_port", 0),
                "dst_port":    f.get("dst_port", 0),
                "payload":     f.get("payload", ""),
                "http_method": f.get("http_method", ""),
                "http_path":   f.get("http_path", ""),
                "flow":        {k: v for k, v in f.items() if k not in meta_keys},
                "label":       "",
            }
            for f in raw
        ]

    _check_environment(flows)
    print(f"\n{'='*62}")
    print(f"  Snort 임계값: {args.sig_threshold}  /  ML 임계값: {args.ml_threshold}")
    print(f"{'='*62}")

    results = run_pipeline(
        flows,
        sig_threshold=args.sig_threshold,
        ml_threshold=args.ml_threshold,
    )
    print_results(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
