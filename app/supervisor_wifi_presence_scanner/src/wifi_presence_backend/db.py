from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from .types import FingerprintRule, NetworkObservation


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _row_to_rule(row: sqlite3.Row) -> FingerprintRule:
    return FingerprintRule(
        id=row["id"],
        name=row["name"],
        enabled=bool(row["enabled"]),
        ssid_regex=row["ssid_regex"],
        bssid_prefix_csv=row["bssid_prefix_csv"],
        oui_vendor_csv=row["oui_vendor_csv"],
        min_rssi=row["min_rssi"],
        max_duration_sec=row["max_duration_sec"],
        min_reappear_count=row["min_reappear_count"],
        cooldown_sec=row["cooldown_sec"],
    )


class Database:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._tx_state = threading.local()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self.migrate()

    @property
    def db_path(self) -> str:
        return self._db_path

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        depth = getattr(self._tx_state, "depth", 0)
        if depth > 0:
            self._tx_state.depth = depth + 1
            try:
                yield self._conn
            finally:
                self._tx_state.depth = depth
            return

        with self._lock:
            self._tx_state.depth = 1
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
            finally:
                self._tx_state.depth = 0

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._tx() as conn:
            yield conn

    def _rebuild_network_catalog(self, *, conn: sqlite3.Connection) -> None:
        conn.execute("DROP TABLE IF EXISTS temp.network_catalog_backup")
        conn.execute(
            """
            CREATE TEMP TABLE network_catalog_backup AS
            SELECT *
            FROM network_catalog
            """
        )
        conn.execute("DELETE FROM network_catalog")
        conn.execute(
            """
            WITH
            session_agg AS (
                SELECT
                    bssid,
                    MIN(first_seen) AS first_seen,
                    MAX(last_seen) AS last_seen,
                    SUM(scans_seen) AS total_seen_count,
                    COUNT(*) AS total_sessions
                FROM presence_sessions
                GROUP BY bssid
            ),
            latest_session AS (
                SELECT bssid, ssid
                FROM (
                    SELECT
                        bssid,
                        ssid,
                        ROW_NUMBER() OVER (PARTITION BY bssid ORDER BY last_seen DESC, id DESC) AS rn
                    FROM presence_sessions
                )
                WHERE rn = 1
            ),
            observation_agg AS (
                SELECT
                    bssid,
                    MIN(seen_at) AS first_seen_obs,
                    MAX(seen_at) AS last_seen_obs,
                    MAX(rssi) AS strongest_rssi
                FROM network_observations
                GROUP BY bssid
            ),
            latest_observation AS (
                SELECT bssid, ssid, bssid_hash, oui_vendor, rssi, channel, frequency_mhz
                FROM (
                    SELECT
                        bssid,
                        ssid,
                        bssid_hash,
                        oui_vendor,
                        rssi,
                        channel,
                        frequency_mhz,
                        seen_at,
                        id,
                        ROW_NUMBER() OVER (PARTITION BY bssid ORDER BY seen_at DESC, id DESC) AS rn
                    FROM network_observations
                )
                WHERE rn = 1
            ),
            known_bssids AS (
                SELECT bssid FROM presence_sessions
                UNION
                SELECT bssid FROM network_observations
                UNION
                SELECT bssid FROM active_networks
            )
            INSERT INTO network_catalog(
                bssid,
                ssid,
                bssid_hash,
                oui_vendor,
                first_seen,
                last_seen,
                total_seen_count,
                total_sessions,
                strongest_rssi,
                last_rssi,
                last_channel,
                last_frequency_mhz
            )
            SELECT
                kb.bssid,
                COALESCE(a.ssid, lo.ssid, ls.ssid, b.ssid, '') AS ssid,
                COALESCE(a.bssid_hash, lo.bssid_hash, b.bssid_hash) AS bssid_hash,
                COALESCE(a.oui_vendor, lo.oui_vendor, b.oui_vendor) AS oui_vendor,
                COALESCE(sa.first_seen, a.first_seen, oa.first_seen_obs, b.first_seen) AS first_seen,
                COALESCE(a.last_seen, sa.last_seen, oa.last_seen_obs, b.last_seen) AS last_seen,
                COALESCE(sa.total_seen_count, a.seen_count, b.total_seen_count, 0) AS total_seen_count,
                COALESCE(sa.total_sessions, CASE WHEN a.bssid IS NOT NULL THEN 1 ELSE NULL END, b.total_sessions, 0) AS total_sessions,
                CASE
                    WHEN oa.strongest_rssi IS NULL AND a.last_rssi IS NULL THEN b.strongest_rssi
                    WHEN oa.strongest_rssi IS NULL THEN a.last_rssi
                    WHEN a.last_rssi IS NULL THEN oa.strongest_rssi
                    ELSE MAX(oa.strongest_rssi, a.last_rssi)
                END AS strongest_rssi,
                COALESCE(a.last_rssi, lo.rssi, b.last_rssi) AS last_rssi,
                COALESCE(a.last_channel, lo.channel, b.last_channel) AS last_channel,
                COALESCE(a.last_frequency_mhz, lo.frequency_mhz, b.last_frequency_mhz) AS last_frequency_mhz
            FROM known_bssids kb
            LEFT JOIN session_agg sa ON sa.bssid = kb.bssid
            LEFT JOIN latest_session ls ON ls.bssid = kb.bssid
            LEFT JOIN observation_agg oa ON oa.bssid = kb.bssid
            LEFT JOIN latest_observation lo ON lo.bssid = kb.bssid
            LEFT JOIN active_networks a ON a.bssid = kb.bssid
            LEFT JOIN network_catalog_backup b ON b.bssid = kb.bssid
            WHERE COALESCE(sa.first_seen, a.first_seen, oa.first_seen_obs, b.first_seen) IS NOT NULL
            """
        )
        conn.execute("DROP TABLE IF EXISTS temp.network_catalog_backup")

    def _upsert_network_catalog(
        self,
        *,
        conn: sqlite3.Connection,
        bssid: str,
        ssid: str,
        timestamp_iso: str,
        rssi: int,
        channel: int,
        frequency_mhz: int,
        bssid_hash: str | None,
        oui_vendor: str | None,
        session_delta: int,
    ) -> None:
        conn.execute(
            """
            INSERT INTO network_catalog(
                bssid,
                ssid,
                bssid_hash,
                oui_vendor,
                first_seen,
                last_seen,
                total_seen_count,
                total_sessions,
                strongest_rssi,
                last_rssi,
                last_channel,
                last_frequency_mhz
            ) VALUES(?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
            ON CONFLICT(bssid) DO UPDATE SET
                ssid = excluded.ssid,
                bssid_hash = COALESCE(excluded.bssid_hash, network_catalog.bssid_hash),
                oui_vendor = COALESCE(excluded.oui_vendor, network_catalog.oui_vendor),
                first_seen = CASE
                    WHEN network_catalog.first_seen <= excluded.first_seen THEN network_catalog.first_seen
                    ELSE excluded.first_seen
                END,
                last_seen = excluded.last_seen,
                total_seen_count = network_catalog.total_seen_count + 1,
                total_sessions = network_catalog.total_sessions + ?,
                strongest_rssi = CASE
                    WHEN network_catalog.strongest_rssi IS NULL THEN excluded.strongest_rssi
                    WHEN excluded.strongest_rssi IS NULL THEN network_catalog.strongest_rssi
                    WHEN network_catalog.strongest_rssi >= excluded.strongest_rssi THEN network_catalog.strongest_rssi
                    ELSE excluded.strongest_rssi
                END,
                last_rssi = excluded.last_rssi,
                last_channel = excluded.last_channel,
                last_frequency_mhz = excluded.last_frequency_mhz
            """,
            (
                bssid,
                ssid,
                bssid_hash,
                oui_vendor,
                timestamp_iso,
                timestamp_iso,
                1,
                rssi,
                rssi,
                channel,
                frequency_mhz,
                session_delta,
            ),
        )

    def migrate(self) -> None:
        with self._tx() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scan_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    source TEXT NOT NULL,
                    interface TEXT NOT NULL,
                    trigger TEXT NOT NULL DEFAULT 'scheduled',
                    status TEXT NOT NULL,
                    error TEXT,
                    seen_total INTEGER NOT NULL DEFAULT 0,
                    new_count INTEGER NOT NULL DEFAULT 0,
                    disappeared_count INTEGER NOT NULL DEFAULT 0,
                    rule_matches INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS network_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_run_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
                    ssid TEXT NOT NULL,
                    bssid TEXT NOT NULL,
                    bssid_hash TEXT,
                    oui_vendor TEXT,
                    rssi INTEGER NOT NULL,
                    channel INTEGER NOT NULL,
                    frequency_mhz INTEGER NOT NULL,
                    seen_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS presence_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ssid TEXT NOT NULL,
                    bssid TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    duration_sec INTEGER NOT NULL,
                    scans_seen INTEGER NOT NULL,
                    ended_reason TEXT
                );

                CREATE TABLE IF NOT EXISTS active_networks (
                    bssid TEXT PRIMARY KEY,
                    ssid TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    seen_count INTEGER NOT NULL,
                    missed_scans INTEGER NOT NULL,
                    session_id INTEGER NOT NULL REFERENCES presence_sessions(id) ON DELETE CASCADE,
                    last_rssi INTEGER,
                    last_channel INTEGER,
                    last_frequency_mhz INTEGER,
                    bssid_hash TEXT,
                    oui_vendor TEXT
                );

                CREATE TABLE IF NOT EXISTS network_catalog (
                    bssid TEXT PRIMARY KEY,
                    ssid TEXT NOT NULL,
                    bssid_hash TEXT,
                    oui_vendor TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    total_seen_count INTEGER NOT NULL,
                    total_sessions INTEGER NOT NULL,
                    strongest_rssi INTEGER,
                    last_rssi INTEGER,
                    last_channel INTEGER,
                    last_frequency_mhz INTEGER
                );

                CREATE TABLE IF NOT EXISTS fingerprint_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    ssid_regex TEXT,
                    bssid_prefix_csv TEXT,
                    oui_vendor_csv TEXT,
                    min_rssi INTEGER,
                    max_duration_sec INTEGER,
                    min_reappear_count INTEGER,
                    cooldown_sec INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS rule_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id INTEGER NOT NULL REFERENCES fingerprint_rules(id) ON DELETE CASCADE,
                    bssid TEXT NOT NULL,
                    matched_at TEXT NOT NULL,
                    confidence REAL,
                    reason_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS emitted_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS novel_network_clears (
                    bssid TEXT PRIMARY KEY,
                    cleared_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_network_observations_seen_at ON network_observations(seen_at);
                CREATE INDEX IF NOT EXISTS idx_network_observations_bssid ON network_observations(bssid);
                CREATE INDEX IF NOT EXISTS idx_presence_sessions_last_seen ON presence_sessions(last_seen);
                CREATE INDEX IF NOT EXISTS idx_presence_sessions_bssid_first_seen ON presence_sessions(bssid, first_seen);
                CREATE INDEX IF NOT EXISTS idx_network_catalog_last_seen ON network_catalog(last_seen);
                CREATE INDEX IF NOT EXISTS idx_network_catalog_total_sessions ON network_catalog(total_sessions);
                CREATE INDEX IF NOT EXISTS idx_rule_matches_matched_at ON rule_matches(matched_at);
                CREATE INDEX IF NOT EXISTS idx_rule_matches_rule_id ON rule_matches(rule_id);
                CREATE INDEX IF NOT EXISTS idx_emitted_events_created_at ON emitted_events(created_at);
                CREATE INDEX IF NOT EXISTS idx_scan_runs_started_at ON scan_runs(started_at);
                CREATE INDEX IF NOT EXISTS idx_scan_runs_status ON scan_runs(status);
                CREATE INDEX IF NOT EXISTS idx_novel_network_clears_cleared_at ON novel_network_clears(cleared_at);
                """
            )

            columns = {
                row["name"]
                for row in conn.execute("PRAGMA table_info(scan_runs)").fetchall()
            }
            for statement in (
                "ALTER TABLE scan_runs ADD COLUMN trigger TEXT NOT NULL DEFAULT 'scheduled'",
                "ALTER TABLE scan_runs ADD COLUMN seen_total INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE scan_runs ADD COLUMN new_count INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE scan_runs ADD COLUMN disappeared_count INTEGER NOT NULL DEFAULT 0",
                "ALTER TABLE scan_runs ADD COLUMN rule_matches INTEGER NOT NULL DEFAULT 0",
            ):
                column_name = statement.split("ADD COLUMN ", maxsplit=1)[1].split(" ", maxsplit=1)[0]
                if column_name not in columns:
                    conn.execute(statement)

            cur = conn.execute("SELECT COUNT(*) AS cnt FROM schema_migrations WHERE version = 1")
            if cur.fetchone()["cnt"] == 0:
                conn.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES(1, ?)",
                    (_utc_now_iso(),),
                )

            cur = conn.execute("SELECT COUNT(*) AS cnt FROM schema_migrations WHERE version = 2")
            if cur.fetchone()["cnt"] == 0:
                self._rebuild_network_catalog(conn=conn)
                conn.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES(2, ?)",
                    (_utc_now_iso(),),
                )

    def begin_scan_run(self, *, source: str, interface: str, trigger: str) -> int:
        with self._tx() as conn:
            cursor = conn.execute(
                """
                INSERT INTO scan_runs(started_at, source, interface, trigger, status)
                VALUES(?, ?, ?, ?, ?)
                """,
                (_utc_now_iso(), source, interface, trigger, "running"),
            )
            return int(cursor.lastrowid)

    def finish_scan_run(
        self,
        *,
        scan_run_id: int,
        status: str,
        error: str | None,
        seen_total: int = 0,
        new_count: int = 0,
        disappeared_count: int = 0,
        rule_matches: int = 0,
    ) -> None:
        with self._tx() as conn:
            conn.execute(
                """
                UPDATE scan_runs
                SET finished_at = ?,
                    status = ?,
                    error = ?,
                    seen_total = ?,
                    new_count = ?,
                    disappeared_count = ?,
                    rule_matches = ?
                WHERE id = ?
                """,
                (
                    _utc_now_iso(),
                    status,
                    error,
                    seen_total,
                    new_count,
                    disappeared_count,
                    rule_matches,
                    scan_run_id,
                ),
            )

    def insert_observations(self, *, scan_run_id: int, observations: list[NetworkObservation]) -> None:
        if not observations:
            return
        with self._tx() as conn:
            conn.executemany(
                """
                INSERT INTO network_observations(
                    scan_run_id,
                    ssid,
                    bssid,
                    bssid_hash,
                    oui_vendor,
                    rssi,
                    channel,
                    frequency_mhz,
                    seen_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_run_id,
                        obs.ssid,
                        obs.bssid,
                        obs.bssid_hash,
                        obs.oui_vendor,
                        obs.rssi,
                        obs.channel,
                        obs.frequency_mhz,
                        obs.seen_at.isoformat(),
                    )
                    for obs in observations
                ],
            )

    def get_active_networks(self) -> list[dict[str, Any]]:
        with self._tx() as conn:
            rows = conn.execute("SELECT * FROM active_networks").fetchall()
            return [dict(row) for row in rows]

    def upsert_active_network(
        self,
        *,
        bssid: str,
        ssid: str,
        timestamp_iso: str,
        rssi: int,
        channel: int,
        frequency_mhz: int,
        bssid_hash: str | None,
        oui_vendor: str | None,
    ) -> tuple[bool, dict[str, Any]]:
        with self._tx() as conn:
            existing = conn.execute(
                "SELECT * FROM active_networks WHERE bssid = ?", (bssid,)
            ).fetchone()
            if existing is None:
                cursor = conn.execute(
                    """
                    INSERT INTO presence_sessions(
                        ssid,
                        bssid,
                        first_seen,
                        last_seen,
                        duration_sec,
                        scans_seen,
                        ended_reason
                    ) VALUES(?, ?, ?, ?, 0, 1, NULL)
                    """,
                    (ssid, bssid, timestamp_iso, timestamp_iso),
                )
                session_id = int(cursor.lastrowid)
                conn.execute(
                    """
                    INSERT INTO active_networks(
                        bssid,
                        ssid,
                        first_seen,
                        last_seen,
                        seen_count,
                        missed_scans,
                        session_id,
                        last_rssi,
                        last_channel,
                        last_frequency_mhz,
                        bssid_hash,
                        oui_vendor
                    ) VALUES(?, ?, ?, ?, 1, 0, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        bssid,
                        ssid,
                        timestamp_iso,
                        timestamp_iso,
                        session_id,
                        rssi,
                        channel,
                        frequency_mhz,
                        bssid_hash,
                        oui_vendor,
                    ),
                )
                self._upsert_network_catalog(
                    conn=conn,
                    bssid=bssid,
                    ssid=ssid,
                    timestamp_iso=timestamp_iso,
                    rssi=rssi,
                    channel=channel,
                    frequency_mhz=frequency_mhz,
                    bssid_hash=bssid_hash,
                    oui_vendor=oui_vendor,
                    session_delta=1,
                )
                row = conn.execute(
                    "SELECT * FROM active_networks WHERE bssid = ?", (bssid,)
                ).fetchone()
                return True, dict(row)

            seen_count = int(existing["seen_count"]) + 1
            first_seen = existing["first_seen"]
            start_dt = datetime.fromisoformat(first_seen)
            end_dt = datetime.fromisoformat(timestamp_iso)
            duration_sec = max(int((end_dt - start_dt).total_seconds()), 0)

            conn.execute(
                """
                UPDATE active_networks
                SET ssid = ?,
                    last_seen = ?,
                    seen_count = ?,
                    missed_scans = 0,
                    last_rssi = ?,
                    last_channel = ?,
                    last_frequency_mhz = ?,
                    bssid_hash = ?,
                    oui_vendor = ?
                WHERE bssid = ?
                """,
                (
                    ssid,
                    timestamp_iso,
                    seen_count,
                    rssi,
                    channel,
                    frequency_mhz,
                    bssid_hash,
                    oui_vendor,
                    bssid,
                ),
            )
            conn.execute(
                """
                UPDATE presence_sessions
                SET ssid = ?,
                    last_seen = ?,
                    duration_sec = ?,
                    scans_seen = ?
                WHERE id = ?
                """,
                (
                    ssid,
                    timestamp_iso,
                    duration_sec,
                    seen_count,
                    existing["session_id"],
                ),
            )
            self._upsert_network_catalog(
                conn=conn,
                bssid=bssid,
                ssid=ssid,
                timestamp_iso=timestamp_iso,
                rssi=rssi,
                channel=channel,
                frequency_mhz=frequency_mhz,
                bssid_hash=bssid_hash,
                oui_vendor=oui_vendor,
                session_delta=0,
            )
            row = conn.execute("SELECT * FROM active_networks WHERE bssid = ?", (bssid,)).fetchone()
            return False, dict(row)

    def increment_missed_scans(self, *, bssid: str) -> dict[str, Any] | None:
        with self._tx() as conn:
            row = conn.execute("SELECT * FROM active_networks WHERE bssid = ?", (bssid,)).fetchone()
            if row is None:
                return None
            missed = int(row["missed_scans"]) + 1
            conn.execute(
                "UPDATE active_networks SET missed_scans = ? WHERE bssid = ?",
                (missed, bssid),
            )
            row = conn.execute("SELECT * FROM active_networks WHERE bssid = ?", (bssid,)).fetchone()
            return dict(row)

    def close_active_network(self, *, bssid: str, ended_reason: str) -> dict[str, Any] | None:
        with self._tx() as conn:
            row = conn.execute("SELECT * FROM active_networks WHERE bssid = ?", (bssid,)).fetchone()
            if row is None:
                return None
            conn.execute(
                "UPDATE presence_sessions SET ended_reason = ? WHERE id = ?",
                (ended_reason, row["session_id"]),
            )
            session = conn.execute(
                "SELECT * FROM presence_sessions WHERE id = ?",
                (row["session_id"],),
            ).fetchone()
            conn.execute("DELETE FROM active_networks WHERE bssid = ?", (bssid,))
            return dict(session) if session else None

    def list_rules(self) -> list[FingerprintRule]:
        with self._tx() as conn:
            rows = conn.execute("SELECT * FROM fingerprint_rules ORDER BY id ASC").fetchall()
            return [_row_to_rule(row) for row in rows]

    def create_rule(self, payload: dict[str, Any]) -> FingerprintRule:
        now = _utc_now_iso()
        with self._tx() as conn:
            cursor = conn.execute(
                """
                INSERT INTO fingerprint_rules(
                    name,
                    enabled,
                    ssid_regex,
                    bssid_prefix_csv,
                    oui_vendor_csv,
                    min_rssi,
                    max_duration_sec,
                    min_reappear_count,
                    cooldown_sec,
                    created_at,
                    updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["name"],
                    1 if payload.get("enabled", True) else 0,
                    payload.get("ssid_regex"),
                    payload.get("bssid_prefix_csv"),
                    payload.get("oui_vendor_csv"),
                    payload.get("min_rssi"),
                    payload.get("max_duration_sec"),
                    payload.get("min_reappear_count"),
                    int(payload.get("cooldown_sec", 0)),
                    now,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM fingerprint_rules WHERE id = ?", (cursor.lastrowid,)
            ).fetchone()
            return _row_to_rule(row)

    def patch_rule(self, *, rule_id: int, patch: dict[str, Any]) -> FingerprintRule | None:
        if not patch:
            with self._tx() as conn:
                row = conn.execute("SELECT * FROM fingerprint_rules WHERE id = ?", (rule_id,)).fetchone()
                return _row_to_rule(row) if row else None

        allowed = {
            "name",
            "enabled",
            "ssid_regex",
            "bssid_prefix_csv",
            "oui_vendor_csv",
            "min_rssi",
            "max_duration_sec",
            "min_reappear_count",
            "cooldown_sec",
        }
        updates: list[str] = []
        args: list[Any] = []
        for key, value in patch.items():
            if key not in allowed:
                continue
            updates.append(f"{key} = ?")
            args.append(1 if key == "enabled" and bool(value) else value)
        if not updates:
            with self._tx() as conn:
                row = conn.execute("SELECT * FROM fingerprint_rules WHERE id = ?", (rule_id,)).fetchone()
                return _row_to_rule(row) if row else None

        updates.append("updated_at = ?")
        args.append(_utc_now_iso())
        args.append(rule_id)

        with self._tx() as conn:
            conn.execute(
                f"UPDATE fingerprint_rules SET {', '.join(updates)} WHERE id = ?",
                tuple(args),
            )
            row = conn.execute("SELECT * FROM fingerprint_rules WHERE id = ?", (rule_id,)).fetchone()
            return _row_to_rule(row) if row else None

    def delete_rule(self, *, rule_id: int) -> bool:
        with self._tx() as conn:
            cursor = conn.execute("DELETE FROM fingerprint_rules WHERE id = ?", (rule_id,))
            return cursor.rowcount > 0

    def record_rule_match(
        self,
        *,
        rule_id: int,
        bssid: str,
        confidence: float,
        reason: dict[str, Any],
    ) -> None:
        with self._tx() as conn:
            conn.execute(
                """
                INSERT INTO rule_matches(rule_id, bssid, matched_at, confidence, reason_json)
                VALUES(?, ?, ?, ?, ?)
                """,
                (rule_id, bssid, _utc_now_iso(), confidence, json.dumps(reason, separators=(",", ":"))),
            )

    def last_rule_match_at(self, *, rule_id: int, bssid: str) -> str | None:
        with self._tx() as conn:
            row = conn.execute(
                """
                SELECT matched_at FROM rule_matches
                WHERE rule_id = ? AND bssid = ?
                ORDER BY matched_at DESC
                LIMIT 1
                """,
                (rule_id, bssid),
            ).fetchone()
            return row["matched_at"] if row else None

    def record_emitted_event(self, *, event_type: str, payload: dict[str, Any]) -> int:
        with self._tx() as conn:
            cursor = conn.execute(
                """
                INSERT INTO emitted_events(event_type, payload_json, created_at)
                VALUES(?, ?, ?)
                """,
                (event_type, json.dumps(payload, separators=(",", ":")), _utc_now_iso()),
            )
            return int(cursor.lastrowid)

    def list_emitted_events(self, *, after_id: int, limit: int) -> list[dict[str, Any]]:
        with self._tx() as conn:
            rows = conn.execute(
                """
                SELECT id, event_type, payload_json, created_at
                FROM emitted_events
                WHERE id > ?
                ORDER BY id ASC
                LIMIT ?
                """,
                (after_id, limit),
            ).fetchall()
            return [
                {
                    "id": int(row["id"]),
                    "event_type": row["event_type"],
                    "payload": json.loads(row["payload_json"]),
                    "created_at": row["created_at"],
                }
                for row in rows
            ]

    def list_networks(
        self,
        *,
        query: str | None,
        from_dt: str | None,
        to_dt: str | None,
        rule_id: int | None,
        short_repeat: bool,
        limit: int,
        offset: int,
    ) -> list[dict[str, Any]]:
        where_parts: list[str] = []
        args: list[Any] = []
        if query:
            where_parts.append("(n.ssid LIKE ? OR n.bssid LIKE ? OR IFNULL(n.oui_vendor,'') LIKE ?)")
            like = f"%{query}%"
            args.extend([like, like, like])
        if from_dt:
            where_parts.append("n.last_seen >= ?")
            args.append(from_dt)
        if to_dt:
            where_parts.append("n.first_seen <= ?")
            args.append(to_dt)
        if rule_id is not None:
            where_parts.append(
                "EXISTS (SELECT 1 FROM rule_matches rm WHERE rm.rule_id = ? AND rm.bssid = n.bssid)"
            )
            args.append(rule_id)
        if short_repeat:
            where_parts.append(
                "EXISTS (SELECT 1 FROM presence_sessions ps WHERE ps.bssid = n.bssid AND ps.duration_sec <= 120 GROUP BY ps.bssid HAVING COUNT(*) >= 3)"
            )

        where_clause = ""
        if where_parts:
            where_clause = "WHERE " + " AND ".join(where_parts)

        sql = f"""
            SELECT
                n.bssid,
                n.bssid_hash,
                n.ssid,
                n.oui_vendor,
                n.first_seen,
                n.last_seen,
                n.total_seen_count AS seen_count,
                n.strongest_rssi,
                n.last_channel AS channel,
                n.last_frequency_mhz AS frequency_mhz,
                EXISTS (SELECT 1 FROM active_networks a WHERE a.bssid = n.bssid) AS currently_visible
            FROM network_catalog n
            {where_clause}
            ORDER BY n.last_seen DESC
            LIMIT ? OFFSET ?
        """
        args.extend([limit, offset])

        with self._tx() as conn:
            rows = conn.execute(sql, tuple(args)).fetchall()
            return [dict(row) for row in rows]

    def list_novel_networks(
        self,
        *,
        window_hours: int,
        max_sessions: int,
        query: str | None,
        limit: int,
        offset: int,
    ) -> list[dict[str, Any]]:
        window_days = window_hours / 24.0
        where_parts: list[str] = [
            "n.total_sessions <= ?",
            "julianday('now') >= julianday(n.first_seen) + ?",
            "nc.bssid IS NULL",
        ]
        args: list[Any] = [max_sessions, window_days]
        if query:
            like = f"%{query}%"
            where_parts.append("(coalesce(n.ssid, '') LIKE ? OR n.bssid LIKE ? OR coalesce(n.oui_vendor, '') LIKE ?)")
            args.extend([like, like, like])

        where_clause = "WHERE " + " AND ".join(where_parts)
        sql = f"""
            SELECT
                n.bssid,
                n.ssid,
                n.oui_vendor,
                n.first_seen,
                n.last_seen,
                n.strongest_rssi,
                n.last_channel AS channel,
                n.last_frequency_mhz AS frequency_mhz,
                n.last_seen AS seen_at,
                EXISTS (SELECT 1 FROM active_networks a WHERE a.bssid = n.bssid) AS currently_visible
            FROM network_catalog n
            LEFT JOIN novel_network_clears nc ON nc.bssid = n.bssid
            {where_clause}
            ORDER BY n.first_seen DESC
            LIMIT ? OFFSET ?
        """
        args.extend([limit, offset])
        with self._tx() as conn:
            rows = conn.execute(sql, tuple(args)).fetchall()
            return [dict(row) for row in rows]

    def clear_novel_network(self, *, bssid: str) -> bool:
        with self._tx() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO novel_network_clears(bssid, cleared_at)
                VALUES(?, ?)
                """,
                (bssid, _utc_now_iso()),
            )
            return True

    def clear_novel_networks(self, *, window_hours: int, max_sessions: int, query: str | None) -> int:
        window_days = window_hours / 24.0
        where_parts: list[str] = [
            "n.total_sessions <= ?",
            "julianday('now') >= julianday(n.first_seen) + ?",
            "nc.bssid IS NULL",
        ]
        args: list[Any] = [max_sessions, window_days]
        if query:
            like = f"%{query}%"
            where_parts.append("(coalesce(n.ssid, '') LIKE ? OR n.bssid LIKE ? OR coalesce(n.oui_vendor, '') LIKE ?)")
            args.extend([like, like, like])

        where_clause = "WHERE " + " AND ".join(where_parts)
        sql = f"""
            WITH candidates AS (
                SELECT n.bssid
                FROM network_catalog n
                LEFT JOIN novel_network_clears nc ON nc.bssid = n.bssid
                {where_clause}
            )
            INSERT OR REPLACE INTO novel_network_clears(bssid, cleared_at)
            SELECT c.bssid, ?
            FROM candidates c
        """
        now = _utc_now_iso()
        args.append(now)
        with self._tx() as conn:
            before = conn.total_changes
            conn.execute(sql, tuple(args))
            return int(conn.total_changes - before)

    def get_network_sessions(self, *, bssid: str) -> list[dict[str, Any]]:
        with self._tx() as conn:
            rows = conn.execute(
                """
                SELECT id, ssid, bssid, first_seen, last_seen, duration_sec, scans_seen, ended_reason
                FROM presence_sessions
                WHERE bssid = ?
                ORDER BY last_seen DESC
                """,
                (bssid,),
            ).fetchall()
            return [dict(row) for row in rows]

    def short_repeat_stats(
        self,
        *,
        max_duration_sec: int,
        min_reappear_count: int,
        window_hours: int,
    ) -> list[dict[str, Any]]:
        lower_bound = (datetime.now(tz=timezone.utc) - timedelta(hours=window_hours)).isoformat()
        with self._tx() as conn:
            rows = conn.execute(
                """
                SELECT
                    bssid,
                    MAX(ssid) AS ssid,
                    COUNT(*) AS short_sessions,
                    MAX(last_seen) AS last_seen,
                    AVG(duration_sec) AS avg_duration_sec
                FROM presence_sessions
                WHERE duration_sec <= ?
                  AND first_seen >= ?
                GROUP BY bssid
                HAVING COUNT(*) >= ?
                ORDER BY short_sessions DESC, last_seen DESC
                """,
                (max_duration_sec, lower_bound, min_reappear_count),
            ).fetchall()
            return [dict(row) for row in rows]

    def purge_history(self, *, retention_days: int, observation_retention_days: int) -> dict[str, int]:
        cutoff = (datetime.now(tz=timezone.utc) - timedelta(days=retention_days)).isoformat()
        observation_cutoff = (
            datetime.now(tz=timezone.utc) - timedelta(days=observation_retention_days)
        ).isoformat()
        deleted: dict[str, int] = {}
        with self._tx() as conn:
            network_catalog_before = conn.execute("SELECT COUNT(*) AS cnt FROM network_catalog").fetchone()
            for table, column, current_cutoff in (
                ("network_observations", "seen_at", observation_cutoff),
                ("presence_sessions", "last_seen", cutoff),
                ("rule_matches", "matched_at", cutoff),
                ("emitted_events", "created_at", cutoff),
                ("scan_runs", "started_at", cutoff),
            ):
                cursor = conn.execute(f"DELETE FROM {table} WHERE {column} < ?", (current_cutoff,))
                deleted[table] = int(cursor.rowcount)
            self._rebuild_network_catalog(conn=conn)
            network_catalog_after = conn.execute("SELECT COUNT(*) AS cnt FROM network_catalog").fetchone()
            deleted["network_catalog"] = max(
                int(network_catalog_before["cnt"]) - int(network_catalog_after["cnt"]),
                0,
            )
        return deleted

    def latest_scan_state(self) -> dict[str, Any]:
        with self._tx() as conn:
            row = conn.execute(
                """
                SELECT
                    id,
                    started_at,
                    finished_at,
                    status,
                    error,
                    source,
                    interface,
                    trigger,
                    seen_total,
                    new_count,
                    disappeared_count,
                    rule_matches
                FROM scan_runs
                ORDER BY id DESC
                LIMIT 1
                """
            ).fetchone()
            return dict(row) if row else {}

    def list_scan_runs(
        self,
        *,
        status: str | None,
        from_dt: str | None,
        to_dt: str | None,
        limit: int,
        offset: int,
    ) -> list[dict[str, Any]]:
        where_parts: list[str] = []
        args: list[Any] = []
        if status:
            where_parts.append("sr.status = ?")
            args.append(status)
        if from_dt:
            where_parts.append("sr.started_at >= ?")
            args.append(from_dt)
        if to_dt:
            where_parts.append("sr.started_at <= ?")
            args.append(to_dt)

        where_clause = ""
        if where_parts:
            where_clause = "WHERE " + " AND ".join(where_parts)

        sql = f"""
            SELECT
                sr.id,
                sr.started_at,
                sr.finished_at,
                sr.source,
                sr.interface,
                sr.trigger,
                sr.status,
                sr.error,
                sr.seen_total,
                sr.new_count,
                sr.disappeared_count,
                sr.rule_matches,
                CASE
                    WHEN sr.finished_at IS NULL THEN NULL
                    ELSE CAST((julianday(sr.finished_at) - julianday(sr.started_at)) * 86400000 AS INTEGER)
                END AS duration_ms
            FROM scan_runs sr
            {where_clause}
            ORDER BY sr.id DESC
            LIMIT ? OFFSET ?
        """
        args.extend([limit, offset])
        with self._tx() as conn:
            rows = conn.execute(sql, tuple(args)).fetchall()
            return [dict(row) for row in rows]

    def get_scan_run(self, *, scan_run_id: int) -> dict[str, Any] | None:
        with self._tx() as conn:
            row = conn.execute(
                """
                SELECT
                    sr.id,
                    sr.started_at,
                    sr.finished_at,
                    sr.source,
                    sr.interface,
                    sr.trigger,
                    sr.status,
                    sr.error,
                    sr.seen_total,
                    sr.new_count,
                    sr.disappeared_count,
                    sr.rule_matches,
                    CASE
                        WHEN sr.finished_at IS NULL THEN NULL
                        ELSE CAST((julianday(sr.finished_at) - julianday(sr.started_at)) * 86400000 AS INTEGER)
                    END AS duration_ms,
                    COUNT(no.id) AS observation_count
                FROM scan_runs sr
                LEFT JOIN network_observations no ON no.scan_run_id = sr.id
                WHERE sr.id = ?
                GROUP BY sr.id
                """,
                (scan_run_id,),
            ).fetchone()
            return dict(row) if row else None

    def list_scan_run_observations(
        self,
        *,
        scan_run_id: int,
        limit: int,
        offset: int,
    ) -> list[dict[str, Any]]:
        with self._tx() as conn:
            rows = conn.execute(
                """
                SELECT
                    id,
                    ssid,
                    bssid,
                    bssid_hash,
                    oui_vendor,
                    rssi,
                    channel,
                    frequency_mhz,
                    seen_at
                FROM network_observations
                WHERE scan_run_id = ?
                ORDER BY id ASC
                LIMIT ? OFFSET ?
                """,
                (scan_run_id, limit, offset),
            ).fetchall()
            return [dict(row) for row in rows]

    def count_currently_visible(self) -> int:
        with self._tx() as conn:
            row = conn.execute("SELECT COUNT(*) AS cnt FROM active_networks").fetchone()
            return int(row["cnt"]) if row else 0

    def close(self) -> None:
        with self._lock:
            self._conn.close()
