"""Flask REST API — adaptive ML 통합 버전.

기존 app.py의 모든 기능을 그대로 유지하면서
AdaptiveModel(XGBoost + IsolationForest)을 추가한다.

변경 사항:
    POST /predict  → "pipeline" 필드 추가 (snort / adaptive_ml 개별 결과)
    GET  /health   → adaptive_model_loaded / baseline_type / baseline_flows 추가

신규 모델 없으면 기존 anomaly_model.pkl로 자동 fallback.
기존 필드는 모두 유지 (하위 호환).

실행:
    FLASK_APP=api.app_adaptive flask run --host 0.0.0.0 --port 5000
    또는 docker-compose에서 command를 아래로 교체:
        python -m api.app_adaptive
"""
from __future__ import annotations

import os
import threading
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Tuple

from flask import Flask, jsonify, request
from flask_cors import CORS

from model.auto_monitor import AutoMonitor
from model.fusion import FusionDetector, _normalize_label
from model.adaptive_model import AdaptiveModel

try:
    from model.pcap_predict import extract_flows as _pcap_extract_flows
    HAVE_SCAPY = True
except Exception as exc:
    print(f"[app_adaptive] pcap_predict 사용 불가 ({exc})")
    HAVE_SCAPY = False
    _pcap_extract_flows = None  # type: ignore


MAX_LOG_ENTRIES = 1000

app = Flask(__name__)
CORS(app)

# ── 기존 Fusion 탐지기 (Snort + anomaly_model.pkl) ─────────────────────────
detector = FusionDetector()

# ── 피처 보정 (optional: calibrator.pkl 있을 때만 활성) ─────────────────────
_CALIBRATOR_ACTIVE = False
_calibrator_path   = Path(os.getenv("CALIBRATOR_PATH", "/pcap/calibrator.pkl"))
try:
    if _calibrator_path.exists():
        from model.feature_calibrator import FeatureCalibrator as _FC
        _cal = _FC.load(_calibrator_path)
        if _cal.fitted:
            detector.anomaly.calibrator = _cal
            _CALIBRATOR_ACTIVE = True
            print(f"[app_adaptive] 피처 보정 활성 — {_calibrator_path}")
except Exception as _cal_exc:
    print(f"[app_adaptive] calibrator 로드 실패 (무시): {_cal_exc}")

# ── 적응형 모델 (XGBoost + IsolationForest) — 없으면 fallback ───────────────
_adaptive = AdaptiveModel()

# ── 로그 / 통계 ──────────────────────────────────────────────────────────────
log_lock = threading.Lock()
detection_log: Deque[Dict[str, Any]] = deque(maxlen=MAX_LOG_ENTRIES)

stats_lock       = threading.Lock()
_total_inspected = 0
_snort_only_cnt  = 0
_ml_only_cnt     = 0
_both_cnt        = 0
_benign_cnt      = 0
_timeline: Deque[Tuple[float, bool]] = deque()


# ── PCAP 추출 ────────────────────────────────────────────────────────────────

_FLOW_META_KEYS = frozenset(
    {"src_ip", "dst_ip", "src_port", "dst_port", "protocol",
     "payload", "http_method", "http_path"}
)


def _summarize_pcap(pcap_path: Path, max_packets: int = 100_000) -> List[Dict[str, Any]]:
    if not HAVE_SCAPY or _pcap_extract_flows is None:
        return []
    raw_flows = _pcap_extract_flows(pcap_path, max_packets=max_packets)
    summaries: List[Dict[str, Any]] = []
    for flow in raw_flows:
        summaries.append({
            "src_ip":      flow.get("src_ip", ""),
            "dst_ip":      flow.get("dst_ip", ""),
            "dst_port":    flow.get("dst_port", 0),
            "flow":        {k: v for k, v in flow.items() if k not in _FLOW_META_KEYS},
            "payload":     flow.get("payload", ""),
            "http_method": flow.get("http_method", ""),
            "http_path":   flow.get("http_path", ""),
        })
    return summaries


# ── 탐지 핵심 로직 ───────────────────────────────────────────────────────────

def _pipeline_label(label: str, conf: float, is_attack: bool) -> str:
    """pipeline 필드용 짧은 문자열."""
    if not is_attack or label == "BENIGN":
        return "PASS"
    return f"ATTACK ({label}, {conf:.2f})"


def _detect_both(
    flow: Dict[str, Any],
    payload: str,
    src_ip: str,
    http_method: str,
    http_path: str,
) -> Dict[str, Any]:
    """Snort + 기존 ML + AdaptiveML 모두 실행하여 교차 검증 결과 반환.

    "pipeline" 필드: snort / adaptive_ml 개별 요약 문자열.
    "detail"  필드: xgb_score, iforest_score, detected_by, baseline_used.
    최종 판정은 기존 파이프라인(Snort OR 기존 ML) 기준 — 하위 호환 유지.
    """
    # ── 1. Snort 시그니처 탐지 ─────────────────────────────────────────
    sig_label, sig_conf, sig_matches = detector.signature.evaluate(
        payload=payload, src_ip=src_ip,
        http_method=http_method, path=http_path,
    )
    sig_label    = _normalize_label(sig_label)
    snort_attack = sig_label != "BENIGN" and sig_conf >= detector.sig_threshold

    # ── 2. 기존 ML 이상탐지 ─────────────────────────────────────────────
    ml_label, ml_conf, ml_proba = detector.anomaly.predict_flow(flow)
    ml_label  = _normalize_label(ml_label)
    ml_attack = ml_label != "BENIGN" and ml_conf >= detector.ml_threshold

    # ── 3. 적응형 ML (XGBoost + IsolationForest) ─────────────────────────
    adp_detail = _adaptive.predict_detailed(flow)
    adp_label  = _normalize_label(adp_detail["label"])
    adp_conf   = adp_detail["confidence"]
    adp_proba  = adp_detail["proba"]

    # ── 4. 최종 판정 (기존 파이프라인 기준 — 하위 호환) ─────────────────
    both_detected = snort_attack and ml_attack
    is_attack     = snort_attack or ml_attack

    if both_detected:
        attack_type = sig_label
        stage       = "both"
        confidence  = round(max(sig_conf, ml_conf), 4)
    elif snort_attack:
        attack_type = sig_label
        stage       = "signature"
        confidence  = round(sig_conf, 4)
    elif ml_attack:
        attack_type = "ML Anomaly" if ml_label == "ATTACK" else ml_label
        stage       = "ml"
        confidence  = round(ml_conf, 4)
    else:
        attack_type = "BENIGN"
        stage       = "none"
        confidence  = round(1.0 - ml_proba.get("ATTACK", 0.0), 4)

    return {
        # ── 신규 필드 ──────────────────────────────────────────────────
        "pipeline": {
            "snort":       _pipeline_label(sig_label, sig_conf, snort_attack),
            "adaptive_ml": _pipeline_label(adp_label, adp_conf,
                                           adp_label != "BENIGN"),
        },
        "detail": {
            "xgb_score":     adp_detail["xgb_score"],
            "iforest_score": adp_detail["iforest_score"],
            "detected_by":   stage if is_attack else "none",
            "baseline_used": _adaptive.baseline_type,
        },
        # ── 기존 교차 검증 필드 (하위 호환) ──────────────────────────
        "snort_result": {
            "label":      sig_label,
            "confidence": round(sig_conf, 4),
            "matches":    sig_matches,
        },
        "ml_result": {
            "label":      ml_label,
            "confidence": round(ml_conf, 4),
            "proba":      {k: round(v, 4) for k, v in ml_proba.items()},
        },
        "adaptive_result": {
            "label":      adp_label,
            "confidence": adp_conf,
            "proba":      adp_proba,
            "model_type": _adaptive.model_type,
            "baseline":   _adaptive.baseline_type,
        },
        "both_detected": both_detected,
        "final_verdict": "ATTACK" if is_attack else "BENIGN",
        # ── 기존 최소 필드 (완전 하위 호환) ──────────────────────────
        "is_attack":   is_attack,
        "attack_type": attack_type,
        "confidence":  confidence,
        "stage":       stage,
        "signature": {
            "label":      sig_label,
            "confidence": round(sig_conf, 4),
            "matches":    sig_matches,
        },
        "ml": {
            "label":      ml_label,
            "confidence": round(ml_conf, 4),
            "proba":      {k: round(v, 4) for k, v in ml_proba.items()},
            "model_type": getattr(detector.anomaly, "model_type", "binary"),
        },
        "calibrated": _CALIBRATOR_ACTIVE,
    }


def _record_attack(entry: Dict[str, Any]) -> None:
    entry["ts"] = entry.get("ts") or time.strftime("%Y-%m-%d %H:%M:%S")
    with log_lock:
        detection_log.append(entry)


def _record_stats(verdict: Dict[str, Any]) -> None:
    global _total_inspected, _snort_only_cnt, _ml_only_cnt, _both_cnt, _benign_cnt
    now = time.time()
    with stats_lock:
        _total_inspected += 1
        if verdict["is_attack"]:
            if verdict.get("both_detected"):
                _both_cnt += 1
            elif verdict["stage"] == "signature":
                _snort_only_cnt += 1
            else:
                _ml_only_cnt += 1
        else:
            _benign_cnt += 1
        _timeline.append((now, bool(verdict["is_attack"])))
        cutoff = now - 600
        while _timeline and _timeline[0][0] < cutoff:
            _timeline.popleft()


# ── 자동 모니터 ──────────────────────────────────────────────────────────────

_auto_monitor = AutoMonitor(
    interface=os.getenv("MONITOR_INTERFACE", "eth1"),
    port=int(os.getenv("MONITOR_PORT", "80")),
    interval_sec=int(os.getenv("MONITOR_INTERVAL_SEC", "60")),
    pcap_dir=os.getenv("PCAP_DIR", "/pcap"),
    on_detect=_record_attack,
    on_stats=_record_stats,
    summarize_pcap=_summarize_pcap if HAVE_SCAPY else None,
    detect_flow=_detect_both,
)
_auto_monitor.start()


# ── 엔드포인트 ───────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    bl = _adaptive.baseline
    return jsonify({
        # 기존 필드
        "status":                  "ok",
        "anomaly_model_loaded":    detector.anomaly.is_trained,
        "feature_count":           detector.anomaly.feature_count,
        "model_type":              detector.anomaly.model_type,
        "signature_rules":         len(detector.signature.rules),
        "thresholds": {
            "signature": detector.sig_threshold,
            "ml":        detector.ml_threshold,
        },
        "multiclass_model_loaded": detector.multiclass is not None,
        "scapy_available":         HAVE_SCAPY,
        "calibrator_loaded":       _CALIBRATOR_ACTIVE,
        "auto_monitor":            _auto_monitor.status(),
        # 신규 적응형 모델 필드
        "adaptive_model_loaded":   _adaptive.is_trained,
        "baseline_type":           _adaptive.baseline_type,
        "baseline_flows":          bl.n_samples if bl is not None else 0,
    })


@app.route("/monitor/status", methods=["GET"])
def monitor_status():
    return jsonify(_auto_monitor.status())


@app.route("/predict", methods=["POST"])
def predict():
    body = request.get_json(silent=True) or {}

    # ── PCAP 파일 모드 ─────────────────────────────────────────────────
    if "pcap_path" in body:
        pcap_path = Path(body["pcap_path"])
        if not pcap_path.exists():
            return jsonify({"error": f"pcap not found: {pcap_path}"}), 404
        summaries = _summarize_pcap(pcap_path)
        results: List[Dict[str, Any]] = []
        for s in summaries:
            verdict = _detect_both(
                flow=s["flow"],
                payload=s["payload"],
                src_ip=s["src_ip"],
                http_method=s["http_method"],
                http_path=s["http_path"],
            )
            _record_stats(verdict)
            entry = {
                "src_ip":   s["src_ip"],
                "dst_ip":   s["dst_ip"],
                "dst_port": s["dst_port"],
                **verdict,
            }
            results.append(entry)
            if verdict["is_attack"]:
                _record_attack(entry)
        return jsonify({
            "pcap":    str(pcap_path),
            "flows":   len(summaries),
            "results": results,
        })

    # ── 단일 플로우 / 페이로드 모드 ───────────────────────────────────
    flow        = body.get("flow") or {}
    payload     = body.get("payload", "")
    src_ip      = body.get("src_ip", "")
    http_method = body.get("http_method", "")
    http_path   = body.get("http_path", "")

    verdict = _detect_both(
        flow=flow,
        payload=payload,
        src_ip=src_ip,
        http_method=http_method,
        http_path=http_path,
    )
    _record_stats(verdict)
    entry = {"src_ip": src_ip, **verdict}
    if verdict["is_attack"]:
        _record_attack(entry)
    return jsonify(entry)


@app.route("/logs", methods=["GET"])
def logs():
    with log_lock:
        items = list(detection_log)[-100:]
    return jsonify({"count": len(items), "logs": list(reversed(items))})


@app.route("/stats", methods=["GET"])
def stats():
    with log_lock:
        items = list(detection_log)

    with stats_lock:
        total_insp = _total_inspected
        benign_cnt = _benign_cnt
        snort_only = _snort_only_cnt
        ml_only    = _ml_only_cnt
        both       = _both_cnt
        tl_copy    = list(_timeline)

    total_atk = total_insp - benign_cnt

    type_counts  = Counter(i["attack_type"] for i in items if i.get("is_attack"))
    ip_counts    = Counter(
        i["src_ip"] for i in items if i.get("is_attack") and i.get("src_ip")
    )
    stage_counts = Counter(
        i.get("stage", "unknown") for i in items if i.get("is_attack")
    )

    now    = time.time()
    cutoff = now - 600
    buckets: Dict[str, Dict[str, Any]] = {}
    for ts, is_atk in tl_copy:
        if ts < cutoff:
            continue
        minute = time.strftime("%H:%M", time.localtime(ts))
        if minute not in buckets:
            buckets[minute] = {"time": minute, "attack": 0, "benign": 0}
        if is_atk:
            buckets[minute]["attack"] += 1
        else:
            buckets[minute]["benign"] += 1
    timeline = sorted(buckets.values(), key=lambda x: x["time"])

    return jsonify({
        "total_attacks":    sum(type_counts.values()),
        "by_type":          dict(type_counts),
        "by_stage":         dict(stage_counts),
        "top_ips":          ip_counts.most_common(10),
        "total_inspected":  total_insp,
        "total_attack":     total_atk,
        "total_benign":     benign_cnt,
        "attack_ratio":     round(total_atk / total_insp, 4) if total_insp > 0 else 0.0,
        "snort_only":       snort_only,
        "ml_only":          ml_only,
        "both_detected":    both,
        "timeline":         timeline,
        "top_attack_types": dict(type_counts.most_common(10)),
        "top_attacker_ips": [
            {"ip": ip, "count": cnt} for ip, cnt in ip_counts.most_common(10)
        ],
    })


if __name__ == "__main__":
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "5000"))
    app.run(host=host, port=port, debug=False)
