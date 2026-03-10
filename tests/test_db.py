import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from wifi_presence_backend.db import Database
from wifi_presence_backend.types import NetworkObservation


class DatabaseTests(unittest.TestCase):
    def test_observation_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(f"{tmp}/scanner.db")
            scan_id = db.begin_scan_run(source="agent", interface="wlan0", trigger="scheduled")
            obs = NetworkObservation(
                scanner_source="agent",
                interface="wlan0",
                ssid="Test",
                bssid="AA:BB:CC:11:22:33",
                bssid_hash=None,
                oui_vendor=None,
                rssi=-55,
                channel=1,
                frequency_mhz=2412,
                seen_at=datetime.now(tz=timezone.utc),
            )
            db.insert_observations(scan_run_id=scan_id, observations=[obs])
            db.finish_scan_run(
                scan_run_id=scan_id,
                status="ok",
                error=None,
                seen_total=1,
                new_count=1,
                disappeared_count=0,
                rule_matches=0,
            )
            db.upsert_active_network(
                bssid=obs.bssid,
                ssid=obs.ssid,
                timestamp_iso=obs.seen_at.isoformat(),
                rssi=obs.rssi,
                channel=obs.channel,
                frequency_mhz=obs.frequency_mhz,
                bssid_hash=obs.bssid_hash,
                oui_vendor=obs.oui_vendor,
            )
            items = db.list_networks(
                query="Test",
                from_dt=None,
                to_dt=None,
                rule_id=None,
                short_repeat=False,
                limit=10,
                offset=0,
            )
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]["bssid"], "AA:BB:CC:11:22:33")
            runs = db.list_scan_runs(
                status=None,
                from_dt=None,
                to_dt=None,
                limit=10,
                offset=0,
            )
            self.assertEqual(len(runs), 1)
            self.assertEqual(runs[0]["seen_total"], 1)
            db.close()

    def test_migration_backfills_network_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = f"{tmp}/scanner.db"
            old_seen_at = (datetime.now(tz=timezone.utc) - timedelta(hours=6)).isoformat()
            conn = sqlite3.connect(db_path)
            conn.executescript(
                """
                CREATE TABLE schema_migrations (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );
                CREATE TABLE scan_runs (
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
                CREATE TABLE network_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_run_id INTEGER NOT NULL,
                    ssid TEXT NOT NULL,
                    bssid TEXT NOT NULL,
                    bssid_hash TEXT,
                    oui_vendor TEXT,
                    rssi INTEGER NOT NULL,
                    channel INTEGER NOT NULL,
                    frequency_mhz INTEGER NOT NULL,
                    seen_at TEXT NOT NULL
                );
                CREATE TABLE presence_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ssid TEXT NOT NULL,
                    bssid TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    duration_sec INTEGER NOT NULL,
                    scans_seen INTEGER NOT NULL,
                    ended_reason TEXT
                );
                CREATE TABLE active_networks (
                    bssid TEXT PRIMARY KEY,
                    ssid TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    seen_count INTEGER NOT NULL,
                    missed_scans INTEGER NOT NULL,
                    session_id INTEGER NOT NULL,
                    last_rssi INTEGER,
                    last_channel INTEGER,
                    last_frequency_mhz INTEGER,
                    bssid_hash TEXT,
                    oui_vendor TEXT
                );
                CREATE TABLE fingerprint_rules (
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
                CREATE TABLE rule_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id INTEGER NOT NULL,
                    bssid TEXT NOT NULL,
                    matched_at TEXT NOT NULL,
                    confidence REAL,
                    reason_json TEXT NOT NULL
                );
                CREATE TABLE emitted_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE novel_network_clears (
                    bssid TEXT PRIMARY KEY,
                    cleared_at TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES(1, ?)",
                (old_seen_at,),
            )
            conn.execute(
                """
                INSERT INTO scan_runs(id, started_at, finished_at, source, interface, trigger, status, seen_total)
                VALUES(1, ?, ?, 'agent', 'wlan0', 'manual', 'ok', 1)
                """,
                (old_seen_at, old_seen_at),
            )
            conn.execute(
                """
                INSERT INTO network_observations(
                    scan_run_id, ssid, bssid, bssid_hash, oui_vendor, rssi, channel, frequency_mhz, seen_at
                ) VALUES(1, 'Legacy-Network', 'AA:BB:CC:11:22:33', NULL, 'Legacy Vendor', -42, 11, 2462, ?)
                """,
                (old_seen_at,),
            )
            conn.execute(
                """
                INSERT INTO presence_sessions(
                    id, ssid, bssid, first_seen, last_seen, duration_sec, scans_seen, ended_reason
                ) VALUES(1, 'Legacy-Network', 'AA:BB:CC:11:22:33', ?, ?, 0, 1, NULL)
                """,
                (old_seen_at, old_seen_at),
            )
            conn.execute(
                """
                INSERT INTO active_networks(
                    bssid, ssid, first_seen, last_seen, seen_count, missed_scans, session_id,
                    last_rssi, last_channel, last_frequency_mhz, bssid_hash, oui_vendor
                ) VALUES('AA:BB:CC:11:22:33', 'Legacy-Network', ?, ?, 1, 0, 1, -42, 11, 2462, NULL, 'Legacy Vendor')
                """,
                (old_seen_at, old_seen_at),
            )
            conn.commit()
            conn.close()

            db = Database(db_path)
            items = db.list_networks(
                query="Legacy-Network",
                from_dt=None,
                to_dt=None,
                rule_id=None,
                short_repeat=False,
                limit=10,
                offset=0,
            )
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]["seen_count"], 1)
            self.assertEqual(items[0]["strongest_rssi"], -42)
            migration_count = db._conn.execute(
                "SELECT COUNT(*) AS cnt FROM schema_migrations WHERE version = 2"
            ).fetchone()
            catalog_row = db._conn.execute(
                "SELECT total_seen_count, total_sessions FROM network_catalog WHERE bssid = ?",
                ("AA:BB:CC:11:22:33",),
            ).fetchone()
            self.assertEqual(int(migration_count["cnt"]), 1)
            self.assertEqual(int(catalog_row["total_seen_count"]), 1)
            self.assertEqual(int(catalog_row["total_sessions"]), 1)
            db.close()

    def test_purge_history_keeps_network_catalog_parity_after_raw_observation_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(f"{tmp}/scanner.db")
            seen_at = datetime.now(tz=timezone.utc) - timedelta(days=5)
            scan_id = db.begin_scan_run(source="agent", interface="wlan0", trigger="manual")
            db.insert_observations(
                scan_run_id=scan_id,
                observations=[
                    NetworkObservation(
                        scanner_source="agent",
                        interface="wlan0",
                        ssid="Parity",
                        bssid="AA:BB:CC:11:22:99",
                        bssid_hash=None,
                        oui_vendor="Parity Vendor",
                        rssi=-48,
                        channel=6,
                        frequency_mhz=2437,
                        seen_at=seen_at,
                    )
                ],
            )
            db.finish_scan_run(
                scan_run_id=scan_id,
                status="ok",
                error=None,
                seen_total=1,
                new_count=1,
                disappeared_count=1,
                rule_matches=0,
            )
            db.upsert_active_network(
                bssid="AA:BB:CC:11:22:99",
                ssid="Parity",
                timestamp_iso=seen_at.isoformat(),
                rssi=-48,
                channel=6,
                frequency_mhz=2437,
                bssid_hash=None,
                oui_vendor="Parity Vendor",
            )
            db.close_active_network(bssid="AA:BB:CC:11:22:99", ended_reason="test")

            deleted = db.purge_history(retention_days=30, observation_retention_days=1)
            self.assertEqual(deleted["network_observations"], 1)
            self.assertEqual(len(db.list_scan_run_observations(scan_run_id=scan_id, limit=50, offset=0)), 0)

            items = db.list_networks(
                query="Parity",
                from_dt=None,
                to_dt=None,
                rule_id=None,
                short_repeat=False,
                limit=10,
                offset=0,
            )
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]["seen_count"], 1)
            self.assertEqual(items[0]["strongest_rssi"], -48)
            novel = db.list_novel_networks(
                window_hours=24,
                max_sessions=1,
                query="Parity",
                limit=10,
                offset=0,
            )
            self.assertEqual(len(novel), 1)
            db.close()

    def test_novel_networks_window_and_clear(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(f"{tmp}/scanner.db")

            old = datetime.now(tz=timezone.utc) - timedelta(hours=30)
            old_plus_twenty_six = old + timedelta(hours=26)
            recent = datetime.now(tz=timezone.utc) - timedelta(hours=2)

            def record_single_session(
                *,
                bssid: str,
                ssid: str,
                at: datetime,
                frequency_mhz: int,
                channel: int,
                rssi: int,
            ) -> None:
                scan_id = db.begin_scan_run(source="agent", interface="wlan0", trigger="manual")
                db.insert_observations(
                    scan_run_id=scan_id,
                    observations=[
                        NetworkObservation(
                            scanner_source="agent",
                            interface="wlan0",
                            ssid=ssid,
                            bssid=bssid,
                            bssid_hash=None,
                            oui_vendor=None,
                            rssi=rssi,
                            channel=channel,
                            frequency_mhz=frequency_mhz,
                            seen_at=at,
                        )
                    ],
                )
                db.finish_scan_run(
                    scan_run_id=scan_id,
                    status="ok",
                    error=None,
                    seen_total=1,
                    new_count=1,
                    disappeared_count=1,
                    rule_matches=0,
                )
                db.upsert_active_network(
                    bssid=bssid,
                    ssid=ssid,
                    timestamp_iso=at.isoformat(),
                    rssi=rssi,
                    channel=channel,
                    frequency_mhz=frequency_mhz,
                    bssid_hash=None,
                    oui_vendor=None,
                )
                db.close_active_network(bssid=bssid, ended_reason="test")

            # Should be included: one session, older than window.
            record_single_session(
                bssid="AA:BB:CC:11:22:33",
                ssid="Novel-One",
                at=old,
                frequency_mhz=2412,
                channel=1,
                rssi=-54,
            )

            # Should be excluded for max_sessions=1, even though the repeat is after the window.
            record_single_session(
                bssid="AA:BB:CC:11:22:44",
                ssid="Repeat-After-Window",
                at=old,
                frequency_mhz=2412,
                channel=1,
                rssi=-60,
            )
            record_single_session(
                bssid="AA:BB:CC:11:22:44",
                ssid="Repeat-After-Window",
                at=old_plus_twenty_six,
                frequency_mhz=2412,
                channel=1,
                rssi=-63,
            )

            # Should be excluded: not old enough for classification.
            record_single_session(
                bssid="AA:BB:CC:11:22:55",
                ssid="Too-Recent",
                at=recent,
                frequency_mhz=5180,
                channel=36,
                rssi=-72,
            )

            # Should be included for max_sessions=2.
            record_single_session(
                bssid="AA:BB:CC:11:22:77",
                ssid="Rare-Two-Sessions",
                at=old,
                frequency_mhz=2462,
                channel=11,
                rssi=-58,
            )
            record_single_session(
                bssid="AA:BB:CC:11:22:77",
                ssid="Rare-Two-Sessions",
                at=old_plus_twenty_six,
                frequency_mhz=2462,
                channel=11,
                rssi=-59,
            )

            novel = db.list_novel_networks(
                window_hours=24,
                max_sessions=1,
                query=None,
                limit=50,
                offset=0,
            )
            self.assertEqual(len(novel), 1)
            self.assertEqual(novel[0]["bssid"], "AA:BB:CC:11:22:33")

            rare_two_sessions = db.list_novel_networks(
                window_hours=24,
                max_sessions=2,
                query="Rare-Two-Sessions",
                limit=50,
                offset=0,
            )
            self.assertEqual(len(rare_two_sessions), 1)
            self.assertEqual(rare_two_sessions[0]["bssid"], "AA:BB:CC:11:22:77")
            repeated_after_window = db.list_novel_networks(
                window_hours=24,
                max_sessions=1,
                query="Repeat-After-Window",
                limit=50,
                offset=0,
            )
            self.assertEqual(len(repeated_after_window), 0)

            db.clear_novel_network(bssid="AA:BB:CC:11:22:33")
            after_single_clear = db.list_novel_networks(
                window_hours=24,
                max_sessions=1,
                query=None,
                limit=50,
                offset=0,
            )
            self.assertEqual(len(after_single_clear), 0)

            # Re-create another candidate and clear via bulk mode with query.
            record_single_session(
                bssid="AA:BB:CC:11:22:66",
                ssid="Novel-Bulk",
                at=old,
                frequency_mhz=2417,
                channel=2,
                rssi=-51,
            )
            record_single_session(
                bssid="AA:BB:CC:11:22:88",
                ssid="Novel-Bulk-Two",
                at=old,
                frequency_mhz=2422,
                channel=3,
                rssi=-50,
            )
            record_single_session(
                bssid="AA:BB:CC:11:22:88",
                ssid="Novel-Bulk-Two",
                at=old_plus_twenty_six,
                frequency_mhz=2422,
                channel=3,
                rssi=-52,
            )
            cleared = db.clear_novel_networks(window_hours=24, max_sessions=1, query="Novel-Bulk")
            self.assertGreaterEqual(cleared, 1)

            after_bulk_clear = db.list_novel_networks(
                window_hours=24,
                max_sessions=1,
                query="Novel-Bulk",
                limit=50,
                offset=0,
            )
            self.assertEqual(len(after_bulk_clear), 0)
            remaining_bulk_two = db.list_novel_networks(
                window_hours=24,
                max_sessions=2,
                query="Novel-Bulk",
                limit=50,
                offset=0,
            )
            self.assertEqual(len(remaining_bulk_two), 1)
            self.assertEqual(remaining_bulk_two[0]["bssid"], "AA:BB:CC:11:22:88")
            db.close()


if __name__ == "__main__":
    unittest.main()
