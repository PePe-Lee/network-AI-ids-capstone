"""Flask REST API for the hybrid 5-stage NIDS.

Endpoints:
    POST /predict : 5단계 하이브리드 파이프라인 탐지
    GET  /logs    : 최근 탐지 로그 100건
    GET  /health  : 서버 상태
    GET  /stats   : 확장 통계 (total_inspected, snort_only, ml_only,
                    both_detected, timeline, top_attack_types, top_attacker_ips)
    GET  /monitor/status : 자동 모니터 상태

통계: 메모리 내 누적 → 컨테이너 재시작 시 초기화 (by design)
"""
from __future__ import annotations

import os
import threading
import time
from collections import Counter, deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Tuple

import numpy as np

from flask import Flask, jsonify, request
from flask_cors import CORS

from model.auto_monitor import AutoMonitor
from model.ae_lof_pipeline import AeLofPipeline

try:
    from model.pcap_predict import extract_flows as _pcap_extract_flows
    HAVE_SCAPY = True
except Exception as exc:  # pragma: no cover
    print(f"[app] pcap_predict unavailable ({exc}); pcap parsing disabled")
    HAVE_SCAPY = False
    _pcap_extract_flows = None  # type: ignore


MAX_LOG_ENTRIES = 1000

app     = Flask(__name__)
CORS(app)

pipeline = AeLofPipeline()

log_lock        = threading.Lock()
detection_log: Deque[Dict[str, Any]] = deque(maxlen=MAX_LOG_ENTRIES)

# ── 확장 통계 (메모리 내, 재시작 시 초기화) ────────────────────────────
stats_lock       = threading.Lock()
_total_inspected = 0
_snort_only_cnt  = 0
_ml_only_cnt     = 0
_both_cnt        = 0
_benign_cnt      = 0
_timeline: Deque[Tuple[float, bool]] = deque()  # (timestamp, is_attack)
_risk_level_counts: Dict[str, int] = {
    "BENIGN-like": 0, "BORDERLINE": 0, "SUSPICIOUS": 0, "ATTACK-like": 0
}

latest_lock = threading.Lock()
latest_pcap: str | None = None
latest_results: List[Dict[str, Any]] = []
latest_scaled_features: List[List[float]] = []


# ── 탐지 핵심 로직 ─────────────────────────────────────────────────────

def _detect_both(
    flow: Dict[str, Any],
    payload: str,
    src_ip: str,
    http_method: str,
    http_path: str,
    debug: bool = False,
) -> Dict[str, Any]:
    """HybridPipeline 5단계 탐지. 기존 _detect_both 인터페이스 유지."""
    return pipeline.detect(
        flow=flow,
        payload=payload,
        src_ip=src_ip,
        http_method=http_method,
        http_path=http_path,
        debug=debug,
    )


def _record_attack(entry: Dict[str, Any]) -> None:
    """공격 탐지 로그 저장 (thread-safe)."""
    entry["ts"] = entry.get("ts") or time.strftime("%Y-%m-%d %H:%M:%S")
    with log_lock:
        detection_log.append(entry)


def _record_stats(verdict: Dict[str, Any]) -> None:
    """전체 통계 누적 — attack + benign 모두 집계 (thread-safe)."""
    global _total_inspected, _snort_only_cnt, _ml_only_cnt, _both_cnt, _benign_cnt
    now = time.time()
    with stats_lock:
        _total_inspected += 1
        if verdict["is_attack"]:
            stage = verdict.get("stage", "")
            if verdict.get("signature_hit") or stage == "signature":
                _snort_only_cnt += 1
            elif verdict.get("ml_checked"):
                _ml_only_cnt += 1
            elif stage in ("ml", "iforest", "autoencoder", "behavior",
                           "lof", "ae+lof", "ae", "fusion_distance",
                           "ae+lof", "lof+fusion_distance",
                           "ae+fusion_distance", "ae+lof+fusion_distance"):
                _ml_only_cnt += 1
            else:
                _both_cnt += 1
        else:
            _benign_cnt += 1
        _timeline.append((now, bool(verdict["is_attack"])))
        cutoff = now - 600
        while _timeline and _timeline[0][0] < cutoff:
            _timeline.popleft()
        rl = verdict.get("risk_level")
        if rl in _risk_level_counts:
            _risk_level_counts[rl] += 1


# ── PCAP 추출 ──────────────────────────────────────────────────────────

_FLOW_META_KEYS = frozenset(
    {"src_ip", "dst_ip", "src_port", "dst_port", "protocol",
     "proto", "timestamp", "payload", "http_method", "http_path"}
)


def _summarize_pcap(pcap_path: Path, max_packets: int = 100_000) -> List[Dict[str, Any]]:
    """pcap_predict.extract_flows로 CICIDS 호환 플로우 특징 추출."""
    if not HAVE_SCAPY or _pcap_extract_flows is None:
        return []
    raw_flows = _pcap_extract_flows(pcap_path, max_packets=max_packets)
    summaries: List[Dict[str, Any]] = []
    for flow in raw_flows:
        summaries.append({
            "src_ip":      flow.get("src_ip", ""),
            "dst_ip":      flow.get("dst_ip", ""),
            "src_port":    flow.get("src_port", 0),
            "dst_port":    flow.get("dst_port", 0),
            "proto":       flow.get("proto", flow.get("protocol", 0)),
            "timestamp":   flow.get("timestamp", 0.0),
            "flow":        {
                **{k: v for k, v in flow.items() if k not in _FLOW_META_KEYS},
                "timestamp": flow.get("timestamp", 0.0),
            },
            "payload":     flow.get("payload", ""),
            "http_method": flow.get("http_method", ""),
            "http_path":   flow.get("http_path", ""),
        })
    return summaries


def _build_flow_entry(
    summary: Dict[str, Any],
    verdict: Dict[str, Any],
    flow_id: int,
) -> Dict[str, Any]:
    signature_hit = verdict.get("stage") == "signature"
    detected_by = "snort_signature" if signature_hit else verdict.get("detected_by", "none")
    attack_type = verdict.get("attack_type", "BENIGN-like")
    if not verdict.get("is_attack") and attack_type == "BENIGN":
        attack_type = "BENIGN-like"

    return {
        "flow_id": flow_id,
        "src_ip": summary.get("src_ip", ""),
        "src_port": summary.get("src_port", 0),
        "dst_ip": summary.get("dst_ip", ""),
        "dst_port": summary.get("dst_port", 0),
        "proto": summary.get("proto", 0),
        "timestamp": summary.get("timestamp", 0.0),
        **verdict,
        "verdict": verdict.get("verdict", verdict.get("final_verdict", "BENIGN")),
        "final_verdict": verdict.get("final_verdict", verdict.get("verdict", "BENIGN")),
        "attack_type": attack_type,
        "detected_by": detected_by,
        "signature_hit": signature_hit,
        "ml_checked": not signature_hit,
    }


def _finite_float(value: Any) -> float | None:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    return v if np.isfinite(v) else None


def _quantiles(values: List[float] | np.ndarray) -> Dict[str, float | None]:
    arr = np.asarray(values, dtype=float)
    arr = arr[np.isfinite(arr)]
    if arr.size == 0:
        return {"p50": None, "p90": None, "p95": None, "p99": None, "p995": None}
    qs = np.quantile(arr, [0.5, 0.9, 0.95, 0.99, 0.995])
    return {
        "p50": float(qs[0]),
        "p90": float(qs[1]),
        "p95": float(qs[2]),
        "p99": float(qs[3]),
        "p995": float(qs[4]),
    }


def _histogram(
    baseline: np.ndarray,
    latest: np.ndarray,
    threshold: float | None,
    bins_count: int = 30,
) -> Dict[str, Any]:
    vals = np.concatenate([
        baseline[np.isfinite(baseline)],
        latest[np.isfinite(latest)],
    ])
    if threshold is not None and np.isfinite(threshold):
        vals = np.concatenate([vals, np.asarray([threshold], dtype=float)])
    if vals.size == 0:
        return {"bins": [], "baseline_counts": [], "latest_counts": [], "threshold": threshold}
    lo, hi = float(np.min(vals)), float(np.max(vals))
    if lo == hi:
        hi = lo + 1.0
    bins = np.linspace(lo, hi, bins_count + 1)
    b_counts, _ = np.histogram(baseline[np.isfinite(baseline)], bins=bins)
    l_counts, _ = np.histogram(latest[np.isfinite(latest)], bins=bins)
    return {
        "bins": [float(x) for x in bins],
        "baseline_counts": [int(x) for x in b_counts],
        "latest_counts": [int(x) for x in l_counts],
        "threshold": threshold,
    }


def _score_array(results: List[Dict[str, Any]], key: str) -> np.ndarray:
    vals = [_finite_float(r.get(key)) for r in results]
    return np.asarray([v for v in vals if v is not None], dtype=float)


# ── 자동 모니터 (백그라운드 tcpdump → 자동 분석) ──────────────────────

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


# ── 엔드포인트 ────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    st = pipeline.status()
    return jsonify({
        "status":               "ok",
        "pipeline":             "ae_lof_5stage",
        "flow_mode":            "pcap",
        "model_dir":            st.get("model_dir", ""),
        "signature_loaded":     st["signature_rules"] > 0,
        "anomaly_model_loaded": bool(st["ae_loaded"] and st.get("lof_loaded", False)),
        "model_files_present":  st.get("model_files_present", {}),
        "preprocessing_order":  st.get("preprocessing_order", ""),
        "signature_rules":      st["signature_rules"],
        "baseline_loaded":      st["baseline_loaded"],
        "baseline_used":        st["baseline_used"],
        "iforest_loaded":       st.get("iforest_loaded", False),
        "ae_loaded":            st["ae_loaded"],
        "encoder_loaded":       st.get("encoder_loaded", False),
        "lof_loaded":           st.get("lof_loaded", False),
        "rf_loaded":            st.get("rf_loaded", False),
        "fallback_active":      st.get("fallback_active", False),
        "feature_count":        st["feature_count"],
        "thresholds":           st["thresholds"],
        "tensorflow_available": st.get("tensorflow_available", False),
        "scapy_available":      HAVE_SCAPY,
        "auto_monitor":         _auto_monitor.status(),
    })


@app.route("/monitor/status", methods=["GET"])
def monitor_status():
    return jsonify(_auto_monitor.status())


@app.route("/score-distribution", methods=["GET"])
def score_distribution():
    st = pipeline.status()
    thresholds = st.get("thresholds", {})
    baseline = pipeline.baseline_scores()
    with latest_lock:
        results = list(latest_results)
        scaled_rows = list(latest_scaled_features)
        pcap_name = latest_pcap

    latest_scores = {
        "ae_error": _score_array(results, "ae_error"),
        "lof_score": _score_array(results, "lof_score"),
        "fusion_distance": _score_array(results, "fusion_distance"),
    }
    threshold_map = {
        "ae_error": _finite_float(thresholds.get("ae_mse", thresholds.get("ae_threshold"))),
        "lof_score": _finite_float(thresholds.get("lof", thresholds.get("lof_threshold"))),
        "fusion_distance": _finite_float(
            thresholds.get("fusion_distance", thresholds.get("fusion_threshold"))
        ),
    }

    baseline_quantiles = {
        name: _quantiles(values) for name, values in baseline.items()
    }
    latest_quantiles = {
        name: _quantiles(values) for name, values in latest_scores.items()
    }
    histograms = {
        name: _histogram(baseline[name], latest_scores[name], threshold_map[name])
        for name in ("ae_error", "lof_score", "fusion_distance")
    }

    score_summary = []
    for name in ("ae_error", "lof_score", "fusion_distance"):
        latest_arr = latest_scores[name]
        thr = threshold_map[name]
        above_rate = None
        if latest_arr.size and thr is not None:
            above_rate = float(np.mean(latest_arr > thr))
        bq = baseline_quantiles[name]
        lq = latest_quantiles[name]
        score_summary.append({
            "score": name,
            "baseline_p50": bq["p50"],
            "baseline_p90": bq["p90"],
            "baseline_p95": bq["p95"],
            "baseline_threshold": thr,
            "test_p50": lq["p50"],
            "test_p90": lq["p90"],
            "test_p95": lq["p95"],
            "test_p995": lq["p995"],
            "test_above_threshold_rate": above_rate,
        })

    top_shifted_features: List[Dict[str, Any]] = []
    if scaled_rows:
        arr = np.asarray(scaled_rows, dtype=float)
        names = pipeline.feature_names()
        med = np.nanmedian(arr, axis=0)
        for i, feature in enumerate(names[: len(med)]):
            test_median = float(med[i]) if np.isfinite(med[i]) else None
            shift = abs(test_median) if test_median is not None else None
            top_shifted_features.append({
                "feature": feature,
                "normal_scaled_median": 0.0,
                "test_scaled_median": test_median,
                "median_shift_abs": shift,
            })
        top_shifted_features.sort(
            key=lambda row: row["median_shift_abs"] if row["median_shift_abs"] is not None else -1,
            reverse=True,
        )
        top_shifted_features = top_shifted_features[:20]

    return jsonify({
        "status": "ok",
        "model_dir": st.get("model_dir", ""),
        "latest_pcap": pcap_name,
        "latest_flow_count": len(results),
        "thresholds": {
            "ae_threshold": threshold_map["ae_error"],
            "lof_threshold": threshold_map["lof_score"],
            "fusion_threshold": threshold_map["fusion_distance"],
        },
        "baseline_quantiles": baseline_quantiles,
        "latest_quantiles": latest_quantiles,
        "histograms": histograms,
        "score_summary": score_summary,
        "top_shifted_features": top_shifted_features,
    })


@app.route("/predict", methods=["POST"])
def predict():
    body = request.get_json(silent=True) or {}

    # ── PCAP 파일 모드 ─────────────────────────────────────────────
    if "pcap_path" in body:
        pcap_path = Path(body["pcap_path"])
        if not pcap_path.exists():
            return jsonify({"error": f"pcap not found: {pcap_path}"}), 404
        if hasattr(pipeline.signature, "reset_state"):
            pipeline.signature.reset_state()
        summaries = _summarize_pcap(pcap_path)
        results: List[Dict[str, Any]] = []
        scaled_rows: List[List[float]] = []
        debug_enabled = bool(body.get("debug", False))
        debug_limit = int(body.get("debug_flows", 3))
        for flow_id, s in enumerate(summaries, start=1):
            verdict = _detect_both(
                flow=s["flow"],
                payload=s["payload"],
                src_ip=s["src_ip"],
                http_method=s["http_method"],
                http_path=s["http_path"],
                debug=debug_enabled and flow_id <= debug_limit,
            )
            entry = _build_flow_entry(s, verdict, flow_id)
            _record_stats(entry)
            results.append(entry)
            try:
                scaled_rows.append([float(x) for x in pipeline.scaled_feature_vector(s["flow"])])
            except Exception as exc:
                print(f"[app] scaled feature debug failed: {exc}")
            if entry["is_attack"]:
                _record_attack(entry)
        risk_level_arr = np.array([r.get("risk_level", "BENIGN-like") for r in results])
        risk_level_counts = {
            "BENIGN-like": int((risk_level_arr == "BENIGN-like").sum()),
            "BORDERLINE":  int((risk_level_arr == "BORDERLINE").sum()),
            "SUSPICIOUS":  int((risk_level_arr == "SUSPICIOUS").sum()),
            "ATTACK-like": int((risk_level_arr == "ATTACK-like").sum()),
        }
        signature_detected = sum(1 for r in results if r.get("signature_hit"))
        ml_detected = sum(
            1 for r in results
            if r.get("ml_checked") and r.get("is_attack")
        )
        benign_count = sum(1 for r in results if not r.get("is_attack"))
        attack_count = sum(1 for r in results if r.get("is_attack"))
        ae_anomaly_count = sum(1 for r in results if r.get("ae_anomaly"))
        lof_anomaly_count = sum(1 for r in results if r.get("lof_anomaly"))
        fusion_anomaly_count = sum(1 for r in results if r.get("fusion_distance_anomaly"))
        final_ml_anomaly_count = sum(1 for r in results if r.get("final_ml_anomaly"))
        behavior_hit_count = sum(1 for r in results if r.get("behavior_hit"))
        detected_by_counts = Counter(r.get("detected_by", "none") for r in results)
        thresholds_used = pipeline.status().get("thresholds", {})
        model_dir = pipeline.status().get("model_dir", "")
        global latest_pcap, latest_results, latest_scaled_features
        with latest_lock:
            latest_pcap = str(pcap_path)
            latest_results = list(results)
            latest_scaled_features = list(scaled_rows)
        response = {
            "pcap":              str(pcap_path),
            "flows":             len(summaries),
            "flow_count":         len(summaries),
            "flow_mode":         "pcap",
            "signature_detected": signature_detected,
            "ml_detected":       ml_detected,
            "benign":            benign_count,
            "attack":            attack_count,
            "ae_anomaly":         ae_anomaly_count,
            "lof_anomaly":        lof_anomaly_count,
            "fusion_anomaly":     fusion_anomaly_count,
            "final_ml_anomaly":   final_ml_anomaly_count,
            "behavior_hit":       behavior_hit_count,
            "detected_by_counts": dict(detected_by_counts),
            "thresholds_used":    thresholds_used,
            "model_dir":          model_dir,
            "results":           results,
            "risk_level_counts": risk_level_counts,
        }
        if debug_enabled:
            feature_names = pipeline.feature_names()
            first_5 = []
            for idx, s in enumerate(summaries[:5], start=1):
                flow_features = s["flow"]
                first_5.append({
                    "flow_id": idx,
                    "features": {
                        name: flow_features.get(name, None)
                        for name in feature_names
                    },
                })
            first_flow = summaries[0]["flow"] if summaries else {}
            missing = [name for name in feature_names if name not in first_flow]
            response.update({
                "first_5_flows_raw_features": first_5,
                "missing_feature_count": len(missing),
                "missing_features_sample": missing[:20],
                "feature_names_first_10": feature_names[:10],
                "feature_names_last_10": feature_names[-10:],
            })
        return jsonify(response)

    # ── 단일 플로우 / 페이로드 모드 ───────────────────────────────
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
        debug=bool(body.get("debug", False)),
    )
    entry = _build_flow_entry({
        "src_ip": src_ip,
        "src_port": body.get("src_port", 0),
        "dst_ip": body.get("dst_ip", ""),
        "dst_port": body.get("dst_port", 0),
        "proto": body.get("proto", body.get("protocol", 0)),
        "timestamp": body.get("timestamp", time.time()),
    }, verdict, 1)
    _record_stats(entry)
    if verdict["is_attack"]:
        _record_attack(entry)
    risk_level_arr = np.array([verdict.get("risk_level", "BENIGN-like")])
    risk_level_counts = {
        "BENIGN-like": int((risk_level_arr == "BENIGN-like").sum()),
        "BORDERLINE":  int((risk_level_arr == "BORDERLINE").sum()),
        "SUSPICIOUS":  int((risk_level_arr == "SUSPICIOUS").sum()),
        "ATTACK-like": int((risk_level_arr == "ATTACK-like").sum()),
    }
    entry["risk_level_counts"] = risk_level_counts
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
        rl_counts  = dict(_risk_level_counts)

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
        # 기존 필드 (하위 호환)
        "total_attacks": sum(type_counts.values()),
        "by_type":       dict(type_counts),
        "by_stage":      dict(stage_counts),
        "top_ips":       ip_counts.most_common(10),
        # 확장 필드
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
        "risk_level_counts": rl_counts,
    })


if __name__ == "__main__":
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "5000"))
    app.run(host=host, port=port, debug=False)
