"""AE+LOF 5?④퀎 ?섏씠釉뚮━??NIDS ?뚯씠?꾨씪??

Stage 1 ??Signature     : SQL Injection / XSS 利됱떆 ATTACK (signature_model.py ?좎?)
Stage 2 ??Feature ?꾩쿂由?: feature_names 湲곗? ?뺣젹, 寃곗륫 0, imputer ??scaler ??pca
Stage 3 ??AutoEncoder   : autoencoder.keras ?ш뎄???ㅼ감(MSE) > ae_threshold
Stage 5 ??Final Verdict : percentile + threshold 湲곕컲 risk_level 寃곗젙

risk_level 怨꾩궛 ?쒖꽌 (?쒖꽌 以묒슂):
    BENIGN-like ??BORDERLINE (max_pct >= 0.95) ??SUSPICIOUS (final_ml_anomaly)
    ??ATTACK-like (ensemble_score >= 2 or behavior_hit)

紐⑤뜽 ?뚯씪 ?놁쑝硫?寃쎄퀬留?異쒕젰, tensorflow import ?ㅽ뙣??寃쎄퀬留?異쒕젰.
HybridPipeline 怨??숈씪??detect() / status() ?명꽣?섏씠??
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd

from .signature_model import SignatureModel

try:
    import tensorflow as tf
    HAVE_TF = True
except Exception as _tf_exc:
    print(f"[AeLofPipeline] WARNING: tensorflow import failed ({_tf_exc}); AE/Encoder disabled")
    HAVE_TF = False

MODEL_DIR = Path(os.getenv("AE_LOF_MODEL_DIR", "/models/direct_ae_lof_only"))
_EXPECTED_MODEL_FILES = [
    "autoencoder.keras",
    "encoder.keras",
    "feature_names.pkl",
    "imputer.pkl",
    "scaler.pkl",
    "pca.pkl",
    "lof.pkl",
    "thresholds.pkl",
    "local_baseline.pkl",
    "ae_lof_only_pack.pkl",
]

_SIG_THRESHOLD = float(os.getenv("SIGNATURE_THRESHOLD", "0.5"))
_AE_DEFAULT    = float(os.getenv("AE_THRESHOLD",        "0.5"))
_LOF_DEFAULT   = float(os.getenv("LOF_THRESHOLD",       "0.0"))

_IMMEDIATE_SIG = {"SQL Injection", "XSS"}

_LABEL_MAP: Dict[str, str] = {
    "ddos":           "DDoS",
    "dos":            "DoS",
    "dos_flood":      "DoS_Flood",
    "dosflood":       "DoS_Flood",
    "portscan":       "PortScan",
    "port_scan":      "PortScan",
    "brute force":    "Brute Force",
    "brute_force":    "Brute Force",
    "sql injection":  "SQL Injection",
    "sql_injection":  "SQL Injection",
    "xss":            "XSS",
    "benign":         "BENIGN",
    "normal":         "BENIGN",
    "attack":         "ATTACK",
}


def _norm(label: str) -> str:
    return _LABEL_MAP.get(label.lower(), label)


def robust_positive_z(scores, reference):
    """IQR-based positive robust z-score used by the Jupyter pipeline."""
    import numpy as np
    reference = np.asarray(reference, dtype=float)
    scores = np.asarray(scores, dtype=float)
    med = np.median(reference)
    q25 = np.quantile(reference, 0.25)
    q75 = np.quantile(reference, 0.75)
    iqr = q75 - q25
    if not np.isfinite(iqr) or iqr == 0:
        iqr = np.std(reference) + 1e-9
    z = (scores - med) / (iqr + 1e-9)
    return np.maximum(z, 0.0)


def percentile_rank_against_reference(scores, reference):
    """媛?score媛 reference 遺꾪룷?먯꽌 紐?踰덉㎏ percentile?몄? 諛섑솚 (0~1).

    scores[i] >= reference??紐?%?몄? 怨꾩궛.
    """
    import numpy as np
    reference = np.asarray(reference)
    scores = np.asarray(scores)
    return np.array([np.mean(reference <= v) for v in scores])


def _array_stats(arr: np.ndarray) -> Dict[str, Any]:
    arr = np.asarray(arr)
    finite = arr[np.isfinite(arr)]
    if finite.size == 0:
        return {"shape": list(arr.shape), "min": None, "max": None, "mean": None}
    return {
        "shape": list(arr.shape),
        "min": float(np.min(finite)),
        "max": float(np.max(finite)),
        "mean": float(np.mean(finite)),
    }


def _add_flat_debug_stats(debug: Dict[str, Any], name: str, arr: np.ndarray) -> None:
    stats = _array_stats(arr)
    debug[f"{name}_shape"] = stats["shape"]
    debug[f"{name}_min"] = stats["min"]
    debug[f"{name}_max"] = stats["max"]
    debug[f"{name}_mean"] = stats["mean"]


def _normalize_local_baseline(obj: Any) -> Optional[Dict[str, Any]]:
    """Normalize baseline key aliases to the names used by inference."""
    if not isinstance(obj, dict):
        return None

    ae_error = obj.get("ae_error")
    if ae_error is None:
        ae_error = obj.get("ae_error_val")

    lof_score = obj.get("lof_score")
    if lof_score is None:
        lof_score = obj.get("lof_score_val")

    if ae_error is None or lof_score is None:
        return None

    normalized: Dict[str, Any] = dict(obj)
    normalized["ae_error"] = np.asarray(ae_error)
    normalized["lof_score"] = np.asarray(lof_score)

    fusion_distance = obj.get("fusion_distance")
    if fusion_distance is None:
        fusion_distance = obj.get("fusion_distance_val")
    if fusion_distance is not None:
        normalized["fusion_distance"] = np.asarray(fusion_distance)

    if "behavior_baseline" in obj:
        normalized["behavior_baseline"] = obj["behavior_baseline"]

    return normalized


def _normalize_thresholds(obj: Any) -> Dict[str, float]:
    if not isinstance(obj, dict):
        return {}
    normalized = dict(obj)
    if "ae_mse" not in normalized and "ae_threshold" in normalized:
        normalized["ae_mse"] = float(normalized["ae_threshold"])
    if "lof" not in normalized and "lof_threshold" in normalized:
        normalized["lof"] = float(normalized["lof_threshold"])
    if "fusion_distance" not in normalized and "fusion_threshold" in normalized:
        normalized["fusion_distance"] = float(normalized["fusion_threshold"])
    return normalized


class AeLofPipeline:
    """AE+LOF 湲곕컲 5?④퀎 NIDS ?먯?湲?

    HybridPipeline 怨??숈씪??detect() / status() ?명꽣?섏씠?ㅻ? ?쒓났?섎?濡?    app.py ?먯꽌 洹몃?濡?援먯껜 媛??
    """

    def __init__(self) -> None:
        # Stage 1
        self.signature = SignatureModel()

        # Stage 2 ?꾩쿂由?        self._feature_names: List[str] = []
        self._imputer = None
        self._scaler  = None
        self._pca     = None

        # Stage 3
        self._autoencoder = None

        # Stage 4
        self._encoder = None
        self._lof     = None

        # baseline: dict with keys ae_error, lof_score, fusion_distance (np.ndarray)
        self._local_baseline: Optional[Dict[str, Any]] = None
        self._baseline_used  = "none"
        self._thresholds: Dict[str, float] = {
            "signature":       _SIG_THRESHOLD,
            "ae_mse":          _AE_DEFAULT,
            "lof":             _LOF_DEFAULT,
            "fusion_distance": 0.5,
        }

        self._load_all()

    # ?? 濡쒕뜑 ?????????????????????????????????????????????????????????????

    def _load_all(self) -> None:
        d = MODEL_DIR

        # thresholds 癒쇱? 濡쒕뱶 (?섎㉧吏 湲곕낯媛??ㅻ쾭?쇱씠??
        _load_pkl(
            d / "thresholds.pkl",
            "thresholds",
            lambda v: self._thresholds.update(_normalize_thresholds(v)),
        )

        # feature_names
        fn = _load_pkl(d / "feature_names.pkl", "feature_names")
        if fn is not None:
            self._feature_names = list(fn)
            print(f"[AeLofPipeline] feature_names: {len(self._feature_names)}")

        # ?꾩쿂由?紐⑤뜽
        self._imputer = _load_pkl(d / "imputer.pkl", "imputer")
        self._scaler  = _load_pkl(d / "scaler.pkl",  "scaler")
        self._pca     = _load_pkl(d / "pca.pkl",     "pca", required=False)

        # local_baseline: dict with keys ae_error, lof_score, fusion_distance
        lb = _load_pkl(d / "local_baseline.pkl", "local_baseline", required=False)
        if lb is not None:
            normalized_lb = _normalize_local_baseline(lb)
            if normalized_lb is not None:
                self._local_baseline = normalized_lb
                self._baseline_used  = "local"
                n = len(normalized_lb.get("ae_error", []))
                has_fusion = "fusion_distance" in normalized_lb
                print(
                    f"[AeLofPipeline] baseline 濡쒕뱶: {n}媛??섑뵆 "
                    f"(fusion_distance={'?덉쓬' if has_fusion else '?놁쓬'})"
                )
            else:
                print(
                    "[AeLofPipeline] WARNING: local_baseline.pkl format mismatch "
                    "(ae_error/lof_score missing); percentile disabled"
                )

        # AE (keras)
        self._autoencoder = _load_keras(d / "autoencoder.keras", "autoencoder")
        self._encoder     = _load_keras(d / "encoder.keras",     "encoder")

        # LOF
        self._lof = _load_pkl(d / "lof.pkl", "lof")

    # ?? ?쇱쿂 ?뺣젹 / ?꾩쿂由????????????????????????????????????????????????

    def _align(self, flow: Dict[str, Any]) -> np.ndarray:
        """feature_names 湲곗? ?뺣젹; ?녿뒗 ?댁? 0, inf/NaN ??0."""
        cols = self._feature_names
        if cols:
            row = [float(flow.get(c, 0.0)) for c in cols]
        else:
            row = [float(v) for v in flow.values() if isinstance(v, (int, float))]
        arr = np.array([row], dtype=np.float32)
        arr = np.where(np.isfinite(arr), arr, 0.0)
        return arr

    def _missing_features(self, flow: Dict[str, Any]) -> List[str]:
        return [c for c in self._feature_names if c not in flow]

    def _signed_log1p_array(self, X: np.ndarray) -> np.ndarray:
        """Apply the signed log transform used during model training."""
        X = np.asarray(X, dtype=np.float32)
        return np.sign(X) * np.log1p(np.abs(X))

    def _preprocess(self, X: np.ndarray) -> np.ndarray:
        """imputer -> signed_log1p -> scaler -> pca, matching training."""
        if self._imputer is not None:
            try:
                X = self._imputer.transform(X)
            except Exception as e:
                print(f"[AeLofPipeline] imputer ?ㅻ쪟: {e}")
        X = self._signed_log1p_array(X)
        if self._scaler is not None:
            try:
                X = self._scaler.transform(X)
            except Exception as e:
                print(f"[AeLofPipeline] scaler ?ㅻ쪟: {e}")
        if self._pca is not None:
            try:
                X = self._pca.transform(X)
            except Exception as e:
                print(f"[AeLofPipeline] pca ?ㅻ쪟: {e}")
        return X.astype("float32")

    def _preprocess_debug(self, X: np.ndarray) -> Tuple[np.ndarray, Dict[str, Any]]:
        debug: Dict[str, Any] = {"raw": _array_stats(X)}
        _add_flat_debug_stats(debug, "raw", X)
        cur = X
        if self._imputer is not None:
            cur = self._imputer.transform(cur)
        debug["imputed"] = _array_stats(cur)
        _add_flat_debug_stats(debug, "imputed", cur)
        cur = self._signed_log1p_array(cur)
        debug["signed_log1p"] = _array_stats(cur)
        _add_flat_debug_stats(debug, "signed_log1p", cur)
        if self._scaler is not None:
            cur = self._scaler.transform(cur)
        debug["scaled"] = _array_stats(cur)
        _add_flat_debug_stats(debug, "scaled", cur)
        if self._pca is not None:
            cur = self._pca.transform(cur)
        cur = cur.astype("float32")
        debug["pca"] = _array_stats(cur)
        _add_flat_debug_stats(debug, "pca", cur)
        return cur, debug

    def scaled_feature_vector(self, flow: Dict[str, Any]) -> np.ndarray:
        X = self._align(flow)
        if self._imputer is not None:
            X = self._imputer.transform(X)
        X = self._signed_log1p_array(X)
        if self._scaler is not None:
            X = self._scaler.transform(X)
        return np.asarray(X, dtype=np.float32)[0]

    def baseline_scores(self) -> Dict[str, np.ndarray]:
        lb = self._local_baseline or {}
        return {
            "ae_error": np.asarray(lb.get("ae_error", []), dtype=float),
            "lof_score": np.asarray(lb.get("lof_score", []), dtype=float),
            "fusion_distance": np.asarray(lb.get("fusion_distance", []), dtype=float),
        }

    def feature_names(self) -> List[str]:
        return list(self._feature_names)

    # ?? Stage 3: AutoEncoder MSE ?????????????????????????????????????????

    def _ae_mse(self, X: np.ndarray) -> float:
        if self._autoencoder is None:
            return 0.0
        try:
            recon = self._autoencoder.predict(X, verbose=0)
            if X.shape != recon.shape:
                raise ValueError(f"AE shape mismatch: input={X.shape}, recon={recon.shape}")
            return float(np.mean(np.square(X - recon), axis=1)[0])
        except Exception as e:
            print(f"[AeLofPipeline] ae ?ㅻ쪟: {e}")
            return 0.0

    def _ae_mse_with_recon(self, X: np.ndarray) -> Tuple[float, Optional[np.ndarray]]:
        if self._autoencoder is None:
            return 0.0, None
        try:
            recon = self._autoencoder.predict(X, verbose=0)
            if X.shape != recon.shape:
                raise ValueError(f"AE shape mismatch: input={X.shape}, recon={recon.shape}")
            return float(np.mean(np.square(X - recon), axis=1)[0]), recon
        except Exception as e:
            print(f"[AeLofPipeline] ae ?ㅻ쪟: {e}")
            return 0.0, None

    # Stage 4: LOF anomaly score (-score_samples, larger is more anomalous)

    def _lof_decision(self, X: np.ndarray) -> float:
        """LOF anomaly score; larger means more anomalous.

        Matches the Jupyter path: lof_score = -lof.score_samples(X_final).
        """
        if self._lof is None:
            return 1.0  # LOF ?놁쑝硫??뺤긽 痍④툒
        inp = X
        lof_features = getattr(self._lof, "n_features_in_", None)
        if lof_features == X.shape[1]:
            inp = X
        elif self._encoder is not None:
            try:
                inp = self._encoder.predict(X, verbose=0)
            except Exception as e:
                print(f"[AeLofPipeline] encoder ?ㅻ쪟: {e}")
        try:
            return float(-self._lof.score_samples(inp)[0])
        except Exception as e:
            print(f"[AeLofPipeline] lof ?ㅻ쪟: {e}")
            return 1.0

    def _lof_decision_with_input(self, X: np.ndarray) -> Tuple[float, np.ndarray]:
        """Return the Jupyter-compatible LOF anomaly score and LOF input."""
        if self._lof is None:
            return 1.0, X
        inp = X
        lof_features = getattr(self._lof, "n_features_in_", None)
        if lof_features == X.shape[1]:
            inp = X
        elif self._encoder is not None:
            try:
                inp = self._encoder.predict(X, verbose=0)
            except Exception as e:
                print(f"[AeLofPipeline] encoder ?ㅻ쪟: {e}")
        try:
            return float(-self._lof.score_samples(inp)[0]), inp
        except Exception as e:
            print(f"[AeLofPipeline] lof ?ㅻ쪟: {e}")
            return 1.0, inp

    # ?? Fusion Distance ??????????????????????????????????????????????????

    def _compute_fusion_distance(self, ae_error: float, lof_raw: float) -> float:
        """Legacy fallback fusion when local baseline is unavailable.

        Normal detection uses local-baseline IQR robust z fusion with
        Jupyter-compatible LOF scores (-score_samples).
        """
        ae_thr = max(self._thresholds.get("ae_mse", _AE_DEFAULT), 1e-9)
        ae_component  = ae_error / ae_thr
        lof_thr = max(self._thresholds.get("lof", _LOF_DEFAULT), 1e-9)
        lof_component = max(0.0, lof_raw / lof_thr)
        return 0.5 * ae_component + 0.5 * lof_component

    # ?? Percentile (baseline ?鍮? ????????????????????????????????????????

    def _compute_percentiles(
        self,
        ae_error: float,
        lof_score: float,
        fusion_distance: float,
    ) -> Tuple[float, float, float, float]:
        """baseline 遺꾪룷 ?鍮?媛??먯닔??percentile 怨꾩궛.

        諛섑솚: (ae_pct, lof_pct, fusion_pct, max_pct)
        baseline ?녾굅?????꾨씫 ??寃쎄퀬 異쒕젰 ??紐⑤몢 0.0 諛섑솚 (BENIGN-like 泥섎━).
        """
        lb = self._local_baseline
        if lb is None:
            print(
                "[AeLofPipeline] WARNING: baseline ?놁쓬 ??"
                "percentile=0.0?쇰줈 泥섎━ (?꾨? BENIGN-like)"
            )
            return 0.0, 0.0, 0.0, 0.0

        ae_val     = lb.get("ae_error")
        lof_val    = lb.get("lof_score")
        fusion_val = lb.get("fusion_distance")

        if ae_val is None or lof_val is None:
            print(
                "[AeLofPipeline] WARNING: baseline??ae_error/lof_score ?놁쓬 ??"
                "percentile=0.0?쇰줈 泥섎━"
            )
            return 0.0, 0.0, 0.0, 0.0

        ae_pct  = float(np.mean(ae_val  <= ae_error))
        lof_pct = float(np.mean(lof_val <= lof_score))

        if fusion_val is not None:
            fusion_pct = float(np.mean(fusion_val <= fusion_distance))
        else:
            print(
                "[AeLofPipeline] WARNING: baseline??fusion_distance ?놁쓬 ??"
                "fusion_pct=0.0?쇰줈 泥섎━"
            )
            fusion_pct = 0.0

        max_pct = max(ae_pct, lof_pct, fusion_pct)
        return ae_pct, lof_pct, fusion_pct, max_pct

    # ?? detected_by ??????????????????????????????????????????????????????

    @staticmethod
    def _make_detected_by(
        ae_anomaly,
        lof_anomaly,
        fusion_anomaly,
        behavior_hit,
        i: int = 0,
    ) -> str:
        detectors = []
        if ae_anomaly[i]:     detectors.append("ae")
        if lof_anomaly[i]:    detectors.append("lof")
        if fusion_anomaly[i]: detectors.append("fusion_distance")
        if behavior_hit[i]:   detectors.append("behavior_rule")
        return "+".join(detectors) if detectors else "none"

    # ?? 怨듦컻 API ?????????????????????????????????????????????????????????

    def detect(
        self,
        flow: Optional[Dict[str, Any]] = None,
        payload: str = "",
        src_ip: str = "",
        http_method: str = "",
        http_path: str = "",
        debug: bool = False,
    ) -> Dict[str, Any]:
        flow = flow or {}
        ts = float(flow.get("timestamp", time.time()))

        # Stage 1: Signature ?????????????????????????????????????????????
        sig_lbl, sig_conf, sig_matches = self.signature.evaluate(
            payload=payload, src_ip=src_ip,
            http_method=http_method, path=http_path, ts=ts,
        )
        sig_lbl   = _norm(sig_lbl)
        sig_block = {
            "label":      sig_lbl,
            "confidence": round(float(sig_conf), 4),
            "matches":    sig_matches,
        }

        if sig_lbl != "BENIGN" and sig_conf >= self._thresholds["signature"]:
            # Snort/Signature 怨듦꺽 ?먯? ??利됱떆 ATTACK ?뺤젙, ML ?④퀎 嫄대꼫?
            ml_block: Dict[str, Any] = {
                "label":      sig_lbl,
                "confidence": round(float(sig_conf), 4),
                "proba":      {sig_lbl: round(float(sig_conf), 4)},
                "model_type": "signature",
            }
            return self._build_result(
                is_attack=True,
                attack_type=sig_lbl,
                confidence=sig_conf,
                stage="signature",
                sig=sig_block,
                ml=ml_block,
                ae_error=0.0,
                lof_score=0.0,
                fusion_distance=0.0,
                ae_anomaly=False,
                lof_anomaly=False,
                fusion_distance_anomaly=False,
                final_ml_anomaly=False,
                ensemble_score=0,
                ae_percentile=0.0,
                lof_percentile=0.0,
                fusion_percentile=0.0,
                max_percentile=0.0,
                risk_level="ATTACK-like",
                behavior_rule_type=sig_lbl,
                behavior_hit=True,
                verdict="ATTACK",
                detected_by="signature",
            )

        # Stage 2: Feature ?꾩쿂由?????????????????????????????????????????
        raw_X = self._align(flow)
        missing_features = self._missing_features(flow)
        if debug:
            X, debug_block = self._preprocess_debug(raw_X)
            debug_block["missing_feature_count"] = len(missing_features)
            debug_block["missing_features_sample"] = missing_features[:10]
        else:
            X = self._preprocess(raw_X)
            debug_block = None

        # Stage 3: AutoEncoder ???????????????????????????????????????????
        if debug:
            _ae_err, _ae_recon = self._ae_mse_with_recon(X)
            debug_block["ae_input_shape"] = list(X.shape)
            debug_block["ae_recon_shape"] = (
                list(_ae_recon.shape) if _ae_recon is not None else None
            )
        else:
            _ae_err = self._ae_mse(X)
        ae_thr  = self._thresholds.get("ae_mse", _AE_DEFAULT)

        # Stage 4: LOF ???????????????????????????????????????????????????
        if debug:
            _lof_raw, _lof_input = self._lof_decision_with_input(X)
            debug_block["lof_input_shape"] = list(_lof_input.shape)
        else:
            _lof_raw = self._lof_decision(X)
        lof_thr  = self._thresholds.get("lof", _LOF_DEFAULT)

        # 1-element 諛곗뿴濡??섑븨 (踰≫꽣???곗궛 ?듭씪) ???????????????????????
        ae_error  = np.array([_ae_err])
        lof_score = np.array([_lof_raw])

        # ?댁긽 ?뚮옒洹?(raw threshold) ????????????????????????????????????
        ae_anomaly  = (ae_error  > ae_thr)  if ae_thr  > 0 else np.array([False])
        lof_anomaly = (lof_score > lof_thr)

        # baseline 諛곗뿴 異붿텧 ??????????????????????????????????????????????
        lb = self._local_baseline
        if lb is not None and "ae_error" in lb and "lof_score" in lb:
            ae_error_val    = lb["ae_error"]
            lof_score_val   = lb["lof_score"]
            fusion_distance_val = lb.get("fusion_distance")

            # Fusion distance: robust z-score 湲곕컲 ????????????????????????
            z_ae  = robust_positive_z(ae_error,  ae_error_val)
            z_lof = robust_positive_z(lof_score, lof_score_val)
            fusion_distance = np.sqrt(z_ae ** 2 + z_lof ** 2)

            # Percentile ??????????????????????????????????????????????????
            ae_pct  = percentile_rank_against_reference(ae_error,  ae_error_val)
            lof_pct = percentile_rank_against_reference(lof_score, lof_score_val)
            if fusion_distance_val is not None:
                fusion_pct = percentile_rank_against_reference(
                    fusion_distance, fusion_distance_val
                )
            else:
                print(
                    "[AeLofPipeline] WARNING: baseline??fusion_distance ?놁쓬 ??"
                    "fusion_pct=0.0?쇰줈 泥섎━"
                )
                fusion_pct = np.zeros(1)
            max_pct = np.maximum(ae_pct, np.maximum(lof_pct, fusion_pct))
        else:
            if lb is None:
                print(
                    "[AeLofPipeline] WARNING: baseline ?놁쓬 ??"
                    "percentile=0.0?쇰줈 泥섎━ (?꾨? BENIGN-like)"
                )
            else:
                print(
                    "[AeLofPipeline] WARNING: baseline??ae_error/lof_score ?놁쓬 ??"
                    "percentile=0.0?쇰줈 泥섎━"
                )
            ae_thr_pos = max(ae_thr, 1e-9)
            fusion_distance = np.array(
                [0.5 * (_ae_err / ae_thr_pos) + 0.5 * max(0.0, -_lof_raw)]
            )
            fusion_distance_val = None
            ae_pct = lof_pct = fusion_pct = max_pct = np.zeros(1)

        # Fusion distance ?댁긽 ?뚮옒洹?????????????????????????????????????
        fusion_thr = self._thresholds.get("fusion_distance", 0.5)
        if fusion_thr > 0:
            fusion_distance_anomaly = fusion_distance > fusion_thr
        else:
            fusion_distance_anomaly = np.array([False])

        # Behavior rule (???뚯씠?꾨씪?몄뿉?쒕뒗 誘멸뎄??????긽 None/False) ???
        behavior_rule_type: Optional[str] = None
        behavior_hit = pd.Series([behavior_rule_type]).notna().values  # np.array([False])

        # Ensemble score (iforest ?쒖쇅: ae + lof留? ??????????????????????
        ensemble_score = ae_anomaly.astype(int) + lof_anomaly.astype(int)

        # Final ML anomaly ????????????????????????????????????????????????
        final_ml_anomaly = ae_anomaly | lof_anomaly | fusion_distance_anomaly

        # Risk level (諛섎뱶?????쒖꽌濡???뼱?) ??????????????????????????
        risk_level = np.full(len(ae_error), "BENIGN-like", dtype=object)
        risk_level[max_pct >= 0.95] = "BORDERLINE"
        risk_level[final_ml_anomaly] = "SUSPICIOUS"
        risk_level[(ensemble_score >= 2) | behavior_hit] = "ATTACK-like"

        # Debug 異쒕젰 ?????????????????????????????????????????????????????
        print("[DEBUG] ae_anomaly:", int(ae_anomaly.sum()))
        print("[DEBUG] lof_anomaly:", int(lof_anomaly.sum()))
        print("[DEBUG] fusion_anomaly:", int(fusion_distance_anomaly.sum()))
        print("[DEBUG] final_ml_anomaly:", int(final_ml_anomaly.sum()))
        print("[DEBUG] ensemble_score>=2:", int((ensemble_score >= 2).sum()))
        print("[DEBUG] max_pct>=0.95:", int((max_pct >= 0.95).sum()))
        print("[DEBUG] risk_level 遺꾪룷:", pd.Series(risk_level).value_counts().to_dict())

        # ?ㅼ뭡??異붿텧 (寃곌낵 dict 議곕┰?? ?????????????????????????????????
        _ae_err_out  = float(ae_error[0])
        _lof_raw_out = float(lof_score[0])
        _fus_out     = float(fusion_distance[0])
        _ae_anom     = bool(ae_anomaly[0])
        _lof_anom    = bool(lof_anomaly[0])
        _fus_anom    = bool(fusion_distance_anomaly[0])
        _final_anom  = bool(final_ml_anomaly[0])
        _ens_score   = int(ensemble_score[0])
        _ae_pct      = float(ae_pct[0])
        _lof_pct     = float(lof_pct[0])
        _fus_pct     = float(fusion_pct[0])
        _max_pct     = float(max_pct[0])
        _risk        = str(risk_level[0])
        _beh_hit     = bool(behavior_hit[0])

        # Verdict & detected_by ??????????????????????????????????????????
        verdict   = "ATTACK" if (_final_anom or _beh_hit) else "BENIGN"
        is_attack = verdict == "ATTACK"
        detected_by = self._make_detected_by(
            ae_anomaly, lof_anomaly, fusion_distance_anomaly, behavior_hit, i=0
        )

        # Confidence ?????????????????????????????????????????????????????
        if is_attack:
            ae_conf  = float(np.clip(_ae_err_out / ae_thr, 0.0, 1.0)) if ae_thr > 0 else 0.0
            lof_conf = float(1.0 / (1.0 + np.exp(_lof_raw_out))) if _lof_anom else 0.0
            confidence = max(ae_conf, lof_conf, _max_pct)
        else:
            confidence = max(1.0 - _max_pct, 0.5)

        # Attack type ????????????????????????????????????????????????????
        attack_type = "Zero_Day_Like_Anomaly" if is_attack else "BENIGN-like"
        stage       = detected_by if is_attack else "none"

        ml_block = {
            "label":           verdict,
            "confidence":      round(float(confidence), 4),
            "proba":           {
                "ATTACK": round(float(confidence), 4),
                "BENIGN": round(1.0 - float(confidence), 4),
            },
            "model_type":      "ae+lof",
            "ae_error":        round(_ae_err_out, 6),
            "lof_score":       round(_lof_raw_out, 6),
            "fusion_distance": round(_fus_out, 6),
        }

        result = self._build_result(
            is_attack=is_attack,
            attack_type=attack_type,
            confidence=confidence,
            stage=stage,
            sig=sig_block,
            ml=ml_block,
            ae_error=_ae_err_out,
            lof_score=_lof_raw_out,
            fusion_distance=_fus_out,
            ae_anomaly=_ae_anom,
            lof_anomaly=_lof_anom,
            fusion_distance_anomaly=_fus_anom,
            final_ml_anomaly=_final_anom,
            ensemble_score=_ens_score,
            ae_percentile=_ae_pct,
            lof_percentile=_lof_pct,
            fusion_percentile=_fus_pct,
            max_percentile=_max_pct,
            risk_level=_risk,
            behavior_rule_type=behavior_rule_type,
            behavior_hit=_beh_hit,
            verdict=verdict,
            detected_by=detected_by,
        )
        if debug and debug_block is not None:
            debug_block.update({
                "ae_error": _ae_err_out,
                "lof_score": _lof_raw_out,
                "fusion_distance": _fus_out,
            })
            result["debug_preprocess"] = debug_block
        return result

    # ?? 寃곌낵 dict 議곕┰ ????????????????????????????????????????????????????

    def _build_result(
        self,
        *,
        is_attack: bool,
        attack_type: str,
        confidence: float,
        stage: str,
        sig: Dict[str, Any],
        ml: Dict[str, Any],
        ae_error: float,
        lof_score: float,
        fusion_distance: float,
        ae_anomaly: bool,
        lof_anomaly: bool,
        fusion_distance_anomaly: bool,
        final_ml_anomaly: bool,
        ensemble_score: int,
        ae_percentile: float,
        lof_percentile: float,
        fusion_percentile: float,
        max_percentile: float,
        risk_level: str,
        behavior_rule_type: Optional[str],
        behavior_hit: bool,
        verdict: str,
        detected_by: str,
    ) -> Dict[str, Any]:
        return {
            # 湲곗〈 ?명솚 ?꾨뱶
            "is_attack":              is_attack,
            "attack_type":            attack_type,
            "confidence":             round(float(confidence), 4),
            "stage":                  stage,
            "signature":              sig,
            "ml":                     ml,
            "snort_result":           sig,
            "ml_result":              ml,
            "both_detected":          False,
            "final_verdict":          verdict,
            "calibrated":             False,
            "baseline_used":          self._baseline_used,
            # AE / LOF ?먯닔 (湲곗〈 ae_score/lof_score ?꾨뱶 ?명솚 ?좎?)
            "ae_score":               round(float(ae_error), 6),
            # ML ?곸꽭 ?꾨뱶
            "ae_error":               round(float(ae_error), 6),
            "lof_score":              round(float(lof_score), 6),
            "fusion_distance":        round(float(fusion_distance), 6),
            "ae_anomaly":             bool(ae_anomaly),
            "lof_anomaly":            bool(lof_anomaly),
            "fusion_distance_anomaly": bool(fusion_distance_anomaly),
            "final_ml_anomaly":       bool(final_ml_anomaly),
            "ensemble_score":         int(ensemble_score),
            "ae_percentile":          round(float(ae_percentile), 6),
            "lof_percentile":         round(float(lof_percentile), 6),
            "fusion_percentile":      round(float(fusion_percentile), 6),
            "max_percentile":         round(float(max_percentile), 6),
            "risk_level":             risk_level,
            "behavior_rule_type":     behavior_rule_type,
            "behavior_hit":           bool(behavior_hit),
            "verdict":                verdict,
            "detected_by":            detected_by,
            "signature_hit":          stage == "signature",
            "ml_checked":             stage != "signature",
        }

    def status(self) -> Dict[str, Any]:
        return {
            "signature_rules":      len(self.signature.rules),
            "baseline_loaded":      self._local_baseline is not None,
            "baseline_used":        self._baseline_used,
            "iforest_loaded":       False,
            "ae_loaded":            self._autoencoder is not None,
            "encoder_loaded":       self._encoder is not None,
            "lof_loaded":           self._lof is not None,
            "rf_loaded":            False,
            "fallback_active":      False,
            "feature_count":        len(self._feature_names),
            "model_dir":            str(MODEL_DIR),
            "model_files_present":  {
                name: (MODEL_DIR / name).exists() for name in _EXPECTED_MODEL_FILES
            },
            "preprocessing_order":   (
                "raw_features -> imputer -> signed_log1p -> scaler -> pca -> ae_lof"
            ),
            "thresholds":           self._thresholds,
            "tensorflow_available": HAVE_TF,
        }


# ?? ?ы띁 ?????????????????????????????????????????????????????????????????

def _load_pkl(path: Path, name: str, callback=None, required: bool = True):
    if not path.exists():
        if required:
            print(f"[AeLofPipeline] WARNING: {path.name} ?놁쓬")
        return None
    try:
        obj = joblib.load(path)
        if callback:
            callback(obj)
        else:
            print(f"[AeLofPipeline] {name} 濡쒕뱶")
        return obj
    except Exception as e:
        print(f"[AeLofPipeline] WARNING: {path.name} 濡쒕뱶 ?ㅽ뙣: {e}")
        return None


def _load_keras(path: Path, name: str):
    if not HAVE_TF:
        return None
    if not path.exists():
        print(f"[AeLofPipeline] WARNING: {path.name} ?놁쓬")
        return None
    try:
        model = tf.keras.models.load_model(str(path))
        print(f"[AeLofPipeline] {name} ({path.name}) 濡쒕뱶")
        return model
    except Exception as e:
        print(f"[AeLofPipeline] WARNING: {path.name} 濡쒕뱶 ?ㅽ뙣: {e}")
        return None

