import copy
from contextlib import closing
import json
from pathlib import Path
import queue
import sqlite3
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer
from unittest.mock import Mock, patch
from urllib.request import Request, urlopen

import os_monitor as osmon
import radar

NOW = datetime(2026, 11, 26, 19, tzinfo=timezone.utc)
LIMITS = {"medium_pct": 11.5, "critical_pct": 17.25}


def fixture(end_at=NOW):
    result = {"meta": {"normalization": "MIN0_MAX", "aggInterval": "ONE_HOUR",
                       "lastUpdated": osmon.stamp(end_at), "dateRange": []}}
    for index, name in enumerate(("recent", "prior")):
        start, end = end_at - (index + 1) * 28 * osmon.DAY, end_at - index * 28 * osmon.DAY
        times = [start + i * osmon.HOUR for i in range(671)]
        result["meta"]["dateRange"].append({"startTime": osmon.stamp(start), "endTime": osmon.stamp(end)})
        result[name] = {"timestamps": [osmon.stamp(t) for t in times]}
        for system in osmon.SYSTEMS:
            result[name][system] = [.45 if t == end_at - 2 * osmon.DAY else .5 for t in times]
    return result


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "radar.sqlite3"
        self.conn = radar.connect(self.path)
        self.conn.execute("UPDATE alert_state SET initialized=1")
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        self.temp.cleanup()

    def sample(self, hour, drop, system="WINDOWS"):
        value = {"current": (100-drop)/100, "baseline": 1, "drop_pct": drop, "controls": []}
        with self.conn:
            return osmon.record_sample(self.conn, system, hour, value, LIMITS, NOW, NOW)

    def outage(self, identifier="outage"):
        return radar.record_outage_alerts(self.conn, [{"id": identifier, "startDate": radar.stamp(NOW)}])

    def test_episode_escalation_ack_and_recovery(self):
        first = self.sample(NOW, 12)
        self.assertEqual(len(first), 1)
        self.assertEqual(self.sample(NOW, 25), [])  # Same completed hour never alerts twice.
        self.assertEqual(self.sample(NOW + osmon.HOUR, 14), [])
        self.outage()
        radar.acknowledge_alerts(self.conn, "os")
        escalated = self.sample(NOW + 2*osmon.HOUR, 18)
        self.assertEqual(len(escalated), 1)
        state = osmon.status(self.conn, NOW)
        self.assertEqual((state["total"], state["pending"], state["pending_sounds"]), (1, 1, 1))
        self.assertEqual(radar.alert_counts(self.conn)["pending"], 1)
        self.sample(NOW + 3*osmon.HOUR, 0)
        self.sample(NOW + 4*osmon.HOUR, 13)  # One normal hour does not create another episode.
        self.sample(NOW + 5*osmon.HOUR, 0)
        self.sample(NOW + 6*osmon.HOUR, 0)
        self.assertEqual(len(self.sample(NOW + 7*osmon.HOUR, 13)), 1)
        self.assertEqual(osmon.status(self.conn, NOW)["total"], 2)

    def test_queue_order_sounds_and_independent_ack(self):
        ids = self.outage() + self.sample(NOW, 12) + self.sample(NOW+osmon.HOUR, 19)
        self.assertEqual([r["notification_id"] for r in radar.pending_notifications(self.conn)], ids)
        self.assertEqual(osmon.status(self.conn, NOW)["pending_sounds"], 2)
        self.assertEqual(osmon.status(self.conn, NOW)["pending"], 1)
        player = radar.AlertSound(self.path)
        player.stopped = Mock(is_set=Mock(return_value=False), wait=Mock(return_value=False))
        audio = Mock(SND_FILENAME=1, SND_NODEFAULT=2)
        player._play_pending(self.conn, list(reversed(ids)), audio)
        self.assertEqual([Path(call.args[0]).name for call in audio.PlaySound.call_args_list],
                         ["apito_04_subida.wav", "apito_03_grave.wav", "apito_09_harmonico.wav"])
        self.assertTrue(all(call.args[0] >= .49 for call in player.stopped.wait.call_args_list[1:]))
        player._play_pending(self.conn, ids, audio, only_new=True)
        self.assertEqual(audio.PlaySound.call_count, 3)
        radar.acknowledge_alerts(self.conn)
        self.assertEqual(osmon.status(self.conn, NOW)["pending"], 1)
        radar.acknowledge_alerts(self.conn, "os")
        player._play_pending(self.conn, ids, audio)
        self.assertEqual(audio.PlaySound.call_count, 3)

    def test_replay_every_minute_without_real_audio_or_sleep(self):
        ids = self.outage() + self.sample(NOW, 12)
        clock = [100.0]
        player = radar.AlertSound(self.path)
        done = [False]
        class Stop:
            def is_set(self): return done[0]
            def wait(self, seconds): clock[0] += seconds; return done[0]
        class Inbox:
            initial = True
            def get(self, timeout):
                if self.initial:
                    self.initial = False
                    return ids
                clock[0] += timeout
                raise queue.Empty
        calls = []
        def play(path, flags):
            calls.append((clock[0], Path(path).name))
            if len(calls) == 4: done[0] = True
        player.queue, player.stopped = Inbox(), Stop()
        audio = Mock(SND_FILENAME=1, SND_NODEFAULT=2, PlaySound=play)
        with patch.object(radar.time, "monotonic", side_effect=lambda: clock[0]):
            player._run_player(audio)
        self.assertEqual([c[1] for c in calls[:2]], [c[1] for c in calls[2:]])
        self.assertEqual(calls[2][0] - calls[0][0], 60)
        self.assertEqual(calls[1][0] - calls[0][0], .5)

    def test_one_failed_sound_does_not_block_following_notifications(self):
        ids = self.outage() + self.sample(NOW, 12)
        player = radar.AlertSound(self.path)
        player.stopped = Mock(is_set=Mock(return_value=False), wait=Mock(return_value=False))
        audio = Mock(SND_FILENAME=1, SND_NODEFAULT=2)
        audio.PlaySound.side_effect = [RuntimeError("audio failure"), None]
        with self.assertLogs(level="ERROR"):
            player._play_pending(self.conn, ids, audio)
        self.assertEqual(audio.PlaySound.call_count, 2)
        self.assertIn(ids[1], player.announced)

    def test_calibration_is_frozen_auditable_and_excludes_live_hour(self):
        data = fixture()
        data["recent"]["WINDOWS"][-1] = .3
        client = Mock(conn=self.conn, get=Mock(return_value=data))
        ids = osmon.collect(client, NOW)
        self.assertEqual(len(ids), 1)
        stored = self.conn.execute("SELECT * FROM os_calibration").fetchone()
        limits = json.loads(stored["limits_json"])
        self.assertAlmostEqual(limits["WINDOWS"]["peak_pct"], 10)
        self.assertAlmostEqual(limits["WINDOWS"]["critical_pct"], 17.25)
        self.assertEqual(json.loads(stored["response_json"]), data)
        self.assertEqual(osmon.collect(client, NOW), [])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM os_samples").fetchone()[0], 5)
        self.assertEqual(self.conn.execute("SELECT limits_json FROM os_calibration").fetchone()[0], stored["limits_json"])
        self.assertEqual([v for k,v in client.get.call_args.args[1] if k=="botClass"], ["LIKELY_HUMAN"]*2)

    def test_invalid_missing_zero_and_stale_data(self):
        data = fixture()
        data["recent"]["WINDOWS"][-1] = None
        client = Mock(conn=self.conn, get=Mock(return_value=data))
        osmon.collect(client, NOW)
        self.assertEqual(osmon.status(self.conn, NOW)["total"], 0)
        self.assertIn("WINDOWS", osmon.status(self.conn, NOW)["error"])
        self.assertTrue(osmon.status(self.conn, NOW)["systems"][1]["available"])
        data["recent"]["WINDOWS"][-1] = 0
        self.assertEqual(len(osmon.collect(client, NOW)), 1)  # A real zero is a valid 100% drop.
        self.assertEqual(osmon.status(self.conn, NOW)["total"], 1)
        self.assertFalse(osmon.status(self.conn, NOW + 4*osmon.HOUR)["systems"][0]["available"])
        invalid = copy.deepcopy(data)
        invalid["meta"]["normalization"] = "PERCENTAGE"
        with self.assertRaises(ValueError): osmon.parse_series(invalid, NOW)
        invalid = copy.deepcopy(data)
        invalid["recent"]["WINDOWS"][-1] = float("nan")
        with self.assertRaises(ValueError): osmon.parse_series(invalid, NOW)
        invalid["recent"]["WINDOWS"][-1] = {}
        with self.assertRaises(ValueError): osmon.parse_series(invalid, NOW)

    def test_existing_latest_sample_becomes_unavailable_if_api_withdraws_it(self):
        data = fixture()
        client = Mock(conn=self.conn, get=Mock(return_value=data))
        osmon.collect(client, NOW)
        self.assertTrue(osmon.status(self.conn, NOW)["systems"][0]["available"])
        data["recent"]["WINDOWS"][-1] = None
        osmon.collect(client, NOW)
        state = osmon.status(self.conn, NOW)
        self.assertFalse(state["systems"][0]["available"])
        self.assertTrue(state["systems"][1]["available"])
        self.assertIn("WINDOWS", state["error"])

    def test_os_cards_become_unavailable_when_collection_stops(self):
        client = Mock(conn=self.conn, get=Mock(return_value=fixture()))
        osmon.collect(client, NOW)
        self.assertTrue(osmon.status(self.conn, NOW)["systems"][0]["available"])
        self.assertFalse(osmon.status(self.conn, NOW + timedelta(minutes=30))["systems"][0]["available"])

    def test_withdrawing_the_entire_latest_hour_invalidates_saved_values(self):
        data = fixture()
        client = Mock(conn=self.conn, get=Mock(return_value=data))
        osmon.collect(client, NOW)
        for values in data["recent"].values():
            values.pop()
        osmon.collect(client, NOW)
        state = osmon.status(self.conn, NOW)
        self.assertFalse(state["systems"][0]["available"])
        self.assertEqual(state["total"], 0)

    def test_pending_items_show_each_os_notice_in_queue_order(self):
        self.sample(NOW, 12)
        self.sample(NOW + osmon.HOUR, 19)
        items = osmon.status(self.conn, NOW)["pending_items"]
        self.assertEqual([(item["os"], item["level"]) for item in items],
                         [("WINDOWS", 1), ("WINDOWS", 2)])
        self.assertEqual(items[0]["episode_id"], items[1]["episode_id"])
        radar.acknowledge_alerts(self.conn, "os")
        self.assertEqual(osmon.status(self.conn, NOW)["pending_items"], [])

    def test_acknowledging_seen_items_keeps_new_outage_and_escalation(self):
        outage_first = self.outage("first")[0]
        os_first = self.sample(NOW, 12)[0]
        outage_second = self.outage("second")[0]
        os_second = self.sample(NOW + osmon.HOUR, 19)[0]
        radar.acknowledge_alerts(self.conn, "outage", outage_first)
        radar.acknowledge_alerts(self.conn, "os", os_first)
        self.assertEqual([item["notification_id"] for item in radar.pending_notifications(self.conn)],
                         [outage_second, os_second])
        self.assertEqual([item["outage_id"] for item in radar.pending_alerts(self.conn)], ["second"])
        self.assertEqual(osmon.status(self.conn, NOW)["pending"], 1)

    def test_inclusive_cloudflare_end_does_not_mix_two_series(self):
        data = fixture()
        for name, stop in (("recent", NOW), ("prior", NOW - 28*osmon.DAY)):
            data[name]["timestamps"].append(osmon.stamp(stop))
            for system in osmon.SYSTEMS:
                data[name][system].append(.99)
        values, recent, _ = osmon.parse_series(data, NOW)
        self.assertNotIn(NOW, values["WINDOWS"])
        self.assertNotIn(NOW, recent)
        self.assertEqual(values["WINDOWS"][NOW-28*osmon.DAY], .5)

    def test_corrects_initial_calibration_and_replays_subsequent_hours(self):
        initial = fixture()
        client = Mock(conn=self.conn, get=Mock(return_value=initial))
        osmon.collect(client, NOW)
        self.conn.execute("UPDATE os_calibration SET method='OS_WEEKLY_MEDIAN_4_V1'")
        self.conn.commit()
        later = fixture(NOW + 3*osmon.HOUR)
        later["recent"]["WINDOWS"][-2:] = [.43, .40]
        client.get.side_effect = [initial, later]
        ids = osmon.collect(client, NOW + 3*osmon.HOUR)
        self.assertEqual(len(ids), 2)
        self.assertEqual([row["level"] for row in radar.pending_notifications(self.conn)], [1,2])
        self.assertEqual(osmon.status(self.conn, NOW+3*osmon.HOUR)["total"], 1)
        self.assertEqual(self.conn.execute("SELECT method FROM os_calibration").fetchone()[0], osmon.METHOD)
        self.assertEqual(self.conn.execute("SELECT level FROM os_samples WHERE os='WINDOWS' ORDER BY hour DESC LIMIT 1").fetchone()[0], 2)

    def test_fixing_calibration_preserves_existing_episodes_and_queue(self):
        initial = fixture()
        initial["recent"]["WINDOWS"][-1] = .43
        client = Mock(conn=self.conn, get=Mock(return_value=initial))
        osmon.collect(client, NOW)
        self.conn.execute("UPDATE os_calibration SET method='OS_WEEKLY_MEDIAN_4_CAL_20261126_19Z_V1'")
        self.conn.commit()
        existing = radar.pending_notifications(self.conn)
        self.assertEqual(len(existing), 1)
        self.assertEqual(osmon.collect(client, NOW), [])
        self.assertEqual(radar.pending_notifications(self.conn), existing)
        self.assertEqual(osmon.status(self.conn, NOW)["method"], osmon.METHOD)

    def test_restart_preserves_pending_and_never_replays_history_as_new(self):
        self.outage()
        self.sample(NOW, 19)
        self.conn.close()
        self.conn = radar.connect(self.path)
        self.assertEqual(len(radar.pending_notifications(self.conn)), 2)
        self.assertEqual(self.sample(NOW+osmon.HOUR, 25), [])
        self.assertEqual(osmon.status(self.conn, NOW)["total"], 1)

    def test_migration_preserves_legacy_outage_counts_and_ack(self):
        path = Path(self.temp.name)/"legacy.sqlite3"
        with closing(sqlite3.connect(path)) as conn:
            conn.executescript("""CREATE TABLE schema_meta(version INTEGER NOT NULL);
                INSERT INTO schema_meta VALUES (3);
                CREATE TABLE outage_alerts(outage_id TEXT PRIMARY KEY,start_at TEXT,location TEXT NOT NULL,
                    alerted_at TEXT,acknowledged_at TEXT,is_simulation INTEGER NOT NULL DEFAULT 0);
                INSERT INTO outage_alerts VALUES ('a',NULL,'A','2026-01-01',NULL,0);
                INSERT INTO outage_alerts VALUES ('b',NULL,'B','2026-01-02','2026-01-03',0);
                INSERT INTO outage_alerts VALUES ('baseline',NULL,'C',NULL,NULL,0);""")
        conn = radar.connect(path)
        self.assertEqual(radar.alert_counts(conn), {"total":2,"pending":1,"simulation_pending":0})
        self.assertEqual([r["event_key"] for r in radar.pending_notifications(conn)], ["a"])
        conn.close()

    def test_http_status_and_acknowledge(self):
        self.outage()
        self.sample(NOW, 12)
        server = ThreadingHTTPServer(("127.0.0.1",0),radar.dashboard_handler(self.path,900,"UTC"))
        worker = threading.Thread(target=server.serve_forever,daemon=True)
        worker.start()
        base = "http://127.0.0.1:"+str(server.server_port)
        try:
            with urlopen(base+"/api/status") as response:
                status = json.load(response)
            self.assertEqual((status["alerts"]["pending"],status["os"]["pending"]),(1,1))
            request = Request(base+"/api/alerts/os/acknowledge",method="POST",headers={
                "X-Requested-With":"internet-radar",
                "X-Alert-Through":str(status["os"]["pending_items"][0]["notification_id"])})
            with urlopen(request) as response: self.assertEqual(json.load(response)["acknowledged"],1)
            self.assertEqual(radar.alert_counts(self.conn)["pending"],1)
            self.assertEqual(osmon.status(self.conn,NOW)["pending"],0)
        finally:
            server.shutdown(); server.server_close(); worker.join()

    def test_http_status_keeps_counts_and_items_in_one_read_snapshot(self):
        self.outage("first")
        original = radar.alert_counts
        def insert_between_reads(conn):
            result = original(conn)
            with closing(sqlite3.connect(self.path)) as writer:
                writer.row_factory = sqlite3.Row
                radar.record_outage_alerts(writer, [{"id":"arrived-during-status", "startDate":radar.stamp(NOW)}])
            return result
        server = ThreadingHTTPServer(("127.0.0.1",0),radar.dashboard_handler(self.path,900,"UTC"))
        worker = threading.Thread(target=server.serve_forever,daemon=True)
        worker.start()
        try:
            with patch.object(radar, "alert_counts", side_effect=insert_between_reads):
                with urlopen("http://127.0.0.1:"+str(server.server_port)+"/api/status") as response:
                    state = json.load(response)
            self.assertEqual(state["alerts"]["pending"], len(state["alerts"]["pending_items"]))
            self.assertEqual(state["alerts"]["pending"], 1)
            self.assertEqual(original(self.conn)["pending"], 2)
        finally:
            server.shutdown(); server.server_close(); worker.join()

    @unittest.skipUnless(sys.platform == "win32", "Windows audio ownership")
    def test_two_launch_modes_share_one_windows_audio_owner(self):
        first, second = radar.AlertSound(self.path), radar.AlertSound(self.path)
        entered, release, second_entered = threading.Event(), threading.Event(), threading.Event()
        first._run_player = Mock(side_effect=lambda audio: (entered.set(), release.wait(3)))
        second._run_player = Mock(side_effect=lambda audio: second_entered.set())
        first.start()
        try:
            self.assertTrue(entered.wait(2))
            second.start()
            self.assertFalse(second_entered.wait(.1))
            release.set()
            self.assertTrue(second_entered.wait(2))
        finally:
            release.set(); first.stop(); second.stop()


if __name__ == "__main__":
    unittest.main()
