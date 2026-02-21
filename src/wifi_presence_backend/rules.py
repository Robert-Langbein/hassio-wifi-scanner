from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from .db import Database
from .types import FingerprintRule, NetworkObservation


@dataclass(slots=True)
class RuleMatchResult:
    matched: bool
    confidence: float
    reason: dict[str, Any]


class RuleEngine:
    def __init__(self, db: Database) -> None:
        self._db = db

    @staticmethod
    def _split_csv(value: str | None) -> list[str]:
        if not value:
            return []
        return [item.strip() for item in value.split(",") if item.strip()]

    def evaluate(
        self,
        *,
        observation: NetworkObservation,
        active_record: dict[str, Any],
    ) -> list[tuple[FingerprintRule, RuleMatchResult]]:
        matches: list[tuple[FingerprintRule, RuleMatchResult]] = []
        rules = self._db.list_rules()
        for rule in rules:
            if not rule.enabled:
                continue
            result = self._match_rule(rule=rule, observation=observation, active_record=active_record)
            if result.matched and self._cooldown_allows(rule=rule, bssid=observation.bssid):
                matches.append((rule, result))
        return matches

    def _cooldown_allows(self, *, rule: FingerprintRule, bssid: str) -> bool:
        if rule.cooldown_sec <= 0:
            return True
        last_match_at = self._db.last_rule_match_at(rule_id=rule.id or 0, bssid=bssid)
        if not last_match_at:
            return True
        last = datetime.fromisoformat(last_match_at)
        return datetime.now(tz=timezone.utc) - last >= timedelta(seconds=rule.cooldown_sec)

    def _match_rule(
        self,
        *,
        rule: FingerprintRule,
        observation: NetworkObservation,
        active_record: dict[str, Any],
    ) -> RuleMatchResult:
        reason: dict[str, Any] = {}
        score = 0.0
        score_possible = 0.0

        if rule.ssid_regex:
            score_possible += 1.0
            if re.search(rule.ssid_regex, observation.ssid):
                score += 1.0
                reason["ssid_regex"] = "matched"
            else:
                return RuleMatchResult(matched=False, confidence=0.0, reason={"ssid_regex": "not_matched"})

        prefixes = self._split_csv(rule.bssid_prefix_csv)
        if prefixes:
            score_possible += 1.0
            normalized = observation.bssid.upper()
            if any(normalized.startswith(prefix.upper()) for prefix in prefixes):
                score += 1.0
                reason["bssid_prefix"] = "matched"
            else:
                return RuleMatchResult(matched=False, confidence=0.0, reason={"bssid_prefix": "not_matched"})

        vendors = self._split_csv(rule.oui_vendor_csv)
        if vendors:
            score_possible += 1.0
            vendor = (observation.oui_vendor or "").lower()
            if any(vendor == item.lower() for item in vendors):
                score += 1.0
                reason["oui_vendor"] = "matched"
            else:
                return RuleMatchResult(matched=False, confidence=0.0, reason={"oui_vendor": "not_matched"})

        if rule.min_rssi is not None:
            score_possible += 1.0
            if observation.rssi >= rule.min_rssi:
                score += 1.0
                reason["min_rssi"] = "matched"
            else:
                return RuleMatchResult(matched=False, confidence=0.0, reason={"min_rssi": "below_threshold"})

        if rule.max_duration_sec is not None:
            score_possible += 1.0
            first_seen = datetime.fromisoformat(active_record["first_seen"])
            duration = int((datetime.fromisoformat(observation.seen_at.isoformat()) - first_seen).total_seconds())
            if duration <= rule.max_duration_sec:
                score += 1.0
                reason["max_duration_sec"] = "matched"
            else:
                return RuleMatchResult(matched=False, confidence=0.0, reason={"max_duration_sec": "too_long"})

        if rule.min_reappear_count is not None:
            score_possible += 1.0
            short_stats = self._db.short_repeat_stats(
                max_duration_sec=rule.max_duration_sec or 120,
                min_reappear_count=rule.min_reappear_count,
                window_hours=24,
            )
            if any(item["bssid"] == observation.bssid for item in short_stats):
                score += 1.0
                reason["min_reappear_count"] = "matched"
            else:
                return RuleMatchResult(
                    matched=False,
                    confidence=0.0,
                    reason={"min_reappear_count": "not_reached"},
                )

        confidence = 1.0 if score_possible == 0 else score / score_possible
        return RuleMatchResult(matched=True, confidence=confidence, reason=reason)
