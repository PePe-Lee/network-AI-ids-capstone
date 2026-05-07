"""시그니처 기반 탐지 모델.

- snort_rules.txt 의 패턴을 정규식으로 컴파일.
- HTTP 페이로드 매칭으로 SQL Injection 등을 식별.
- 동일 IP의 로그인 POST 빈도 추적으로 Brute Force 식별.
"""
from __future__ import annotations

import os
import re
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Deque, Dict, List, Tuple

RULES_PATH = Path(os.getenv("SIGNATURE_RULES_PATH", "/app/rules/snort_rules.txt"))
BRUTE_FORCE_THRESHOLD = int(os.getenv("BRUTE_FORCE_THRESHOLD", "5"))
BRUTE_FORCE_WINDOW_SEC = int(os.getenv("BRUTE_FORCE_WINDOW_SEC", "60"))


class SignatureRule:
    __slots__ = ("attack_type", "pattern", "regex", "description")

    def __init__(self, attack_type: str, pattern: str, description: str) -> None:
        self.attack_type = attack_type
        self.pattern = pattern
        self.regex = re.compile(pattern)
        self.description = description


def _load_rules(path: Path) -> List[SignatureRule]:
    rules: List[SignatureRule] = []
    if not path.exists():
        print(f"[SignatureModel] rules file not found: {path}")
        return rules
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "|" not in line:
            continue
        attack_type, rest = line.split("|", 1)
        if "|" in rest:
            pattern, description = rest.rsplit("|", 1)
        else:
            pattern, description = rest, ""
        attack_type = attack_type.strip().upper()
        pattern = pattern.strip()
        description = description.strip()
        try:
            rules.append(SignatureRule(attack_type, pattern, description))
        except re.error as exc:
            print(f"[SignatureModel] invalid regex skipped: {pattern} ({exc})")
    return rules


class SignatureModel:
    def __init__(self, rules_path: Path = RULES_PATH) -> None:
        self.rules: List[SignatureRule] = _load_rules(rules_path)
        # ip -> deque[timestamps]
        self._login_attempts: Dict[str, Deque[float]] = defaultdict(deque)
        print(f"[SignatureModel] loaded {len(self.rules)} rules")

    def reset_state(self) -> None:
        """Clear stateful signature windows before a new offline PCAP analysis."""
        self._login_attempts.clear()

    def _record_login(self, src_ip: str, ts: float) -> int:
        dq = self._login_attempts[src_ip]
        dq.append(ts)
        cutoff = ts - BRUTE_FORCE_WINDOW_SEC
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def evaluate(
        self,
        payload: str,
        src_ip: str = "",
        http_method: str = "",
        path: str = "",
        ts: float | None = None,
    ) -> Tuple[str, float, List[Dict[str, str]]]:
        """페이로드/메타데이터로부터 (label, confidence, matched_rules)를 반환."""
        ts = ts if ts is not None else time.time()
        matches: List[Dict[str, str]] = []
        scores: Dict[str, float] = defaultdict(float)

        text = payload or ""
        for rule in self.rules:
            if rule.attack_type == "BRUTE_FORCE":
                # 본문 매칭 + 빈도 검사 결합
                target = f"{http_method} {path}"
                if rule.regex.search(target):
                    count = self._record_login(src_ip or "unknown", ts)
                    matches.append({
                        "rule": rule.pattern,
                        "type": rule.attack_type,
                        "description": rule.description,
                        "occurrences": str(count),
                    })
                    if count >= BRUTE_FORCE_THRESHOLD:
                        # threshold 도달 시 강한 확신
                        ratio = min(count / (BRUTE_FORCE_THRESHOLD * 2), 1.0)
                        scores["Brute Force"] = max(scores["Brute Force"], 0.6 + 0.4 * ratio)
                continue

            if rule.regex.search(text):
                matches.append({
                    "rule": rule.pattern,
                    "type": rule.attack_type,
                    "description": rule.description,
                })
                if rule.attack_type == "SQL_INJECTION":
                    scores["SQL Injection"] = max(scores["SQL Injection"], 0.95)
                elif rule.attack_type == "DOS":
                    scores["DoS"] = max(scores["DoS"], 0.7)
                else:
                    scores[rule.attack_type.title()] = max(
                        scores[rule.attack_type.title()], 0.7
                    )

        if not scores:
            return "BENIGN", 0.0, matches

        label = max(scores, key=scores.get)
        return label, float(scores[label]), matches
