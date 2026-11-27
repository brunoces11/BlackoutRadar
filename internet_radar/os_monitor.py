"""Hourly OS traffic monitoring; all ratios use values from one API response."""

import json
import math
import statistics
from datetime import datetime, timedelta, timezone

SYSTEMS = {"WINDOWS": "Windows", "MACOSX": "macOS", "LINUX": "Linux",
           "IOS": "iOS", "ANDROID": "Android"}
ENDPOINT = "/radar/http/timeseries_groups/OS"
METHOD = "OS_WEEKLY_MEDIAN_4_CAL_20261126_19Z_V2"
CALIBRATION_END = datetime(2026, 11, 26, 19, tzinfo=timezone.utc)
CALIBRATION_LAST = datetime(2026, 11, 26, 16, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)
DAY = timedelta(days=1)
MAX_AGE = timedelta(hours=3)


def stamp(value):
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def date(value):
    if not isinstance(value, str):
        raise ValueError("OS: horario ausente")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("OS: horario sem fuso")
    return parsed.astimezone(timezone.utc)


def initialize(conn):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS os_calibration (
            id INTEGER PRIMARY KEY CHECK(id=1), created_at TEXT NOT NULL,
            method TEXT NOT NULL, params_json TEXT NOT NULL, response_json TEXT NOT NULL,
            limits_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS os_episodes (
            episode_id INTEGER PRIMARY KEY, os TEXT NOT NULL, started_at TEXT NOT NULL,
            detected_at TEXT NOT NULL, ended_at TEXT, highest_level INTEGER NOT NULL,
            normal_hours INTEGER NOT NULL DEFAULT 0, last_normal_at TEXT
        );
        CREATE UNIQUE INDEX IF NOT EXISTS os_one_active ON os_episodes(os)
            WHERE ended_at IS NULL;
        CREATE TABLE IF NOT EXISTS os_samples (
            os TEXT NOT NULL, hour TEXT NOT NULL, current REAL NOT NULL, baseline REAL NOT NULL,
            drop_pct REAL NOT NULL, level INTEGER NOT NULL, controls_json TEXT NOT NULL,
            retrieved_at TEXT NOT NULL, source_updated_at TEXT NOT NULL,
            PRIMARY KEY(os,hour)
        );
        CREATE TABLE IF NOT EXISTS os_collection (
            id INTEGER PRIMARY KEY CHECK(id=1), attempted_at TEXT NOT NULL,
            succeeded_at TEXT, error TEXT, unavailable_json TEXT NOT NULL DEFAULT '[]'
        );
    """)


def parameters(end):
    params = [("aggInterval", "1h"), ("normalization", "MIN0_MAX")]
    for name, start, stop in (("recent", end - 28 * DAY, end),
                              ("prior", end - 56 * DAY, end - 28 * DAY)):
        # Filters are positional arrays: repeat botClass for BOTH series.
        params.extend((("name", name), ("dateStart", stamp(start)),
                       ("dateEnd", stamp(stop)), ("botClass", "LIKELY_HUMAN")))
    return params


def parse_series(result, end):
    meta = result.get("meta", {})
    if not isinstance(meta, dict) or meta.get("normalization") != "MIN0_MAX" or meta.get("aggInterval") != "ONE_HOUR":
        raise ValueError("OS: normalizacao ou intervalo inesperado")
    updated = date(meta.get("lastUpdated"))
    ranges = meta.get("dateRange")
    if not isinstance(ranges, list) or len(ranges) != 2:
        raise ValueError("OS: periodos ausentes")
    values = {system: {} for system in SYSTEMS}
    recent = []
    for index, name in enumerate(("recent", "prior")):
        stop, start = end - index * 28 * DAY, end - (index + 1) * 28 * DAY
        returned = ranges[index]
        if not isinstance(returned, dict) or date(returned.get("startTime")) != start or date(returned.get("endTime")) != stop:
            raise ValueError("OS: API ajustou os periodos solicitados")
        series = result.get(name)
        if not isinstance(series, dict) or not isinstance(series.get("timestamps"), list):
            raise ValueError("OS: serie ausente")
        times = [date(t) for t in series["timestamps"]]
        if len(set(times)) != len(times) or times != sorted(times):
            raise ValueError("OS: horarios duplicados ou fora de ordem")
        # Cloudflare documents dateEnd as inclusive; boundary belongs to the next window.
        if any(t < start or t > stop or t.minute or t.second for t in times):
            raise ValueError("OS: hora fora do intervalo solicitado")
        for system in SYSTEMS:
            raw = series.get(system)
            if not isinstance(raw, list) or len(raw) != len(times):
                raise ValueError("OS: valores ausentes para " + system)
            for t, v in zip(times, raw):
                if t == stop:
                    continue
                try:
                    value = None if v is None else float(v)
                except (TypeError, ValueError, OverflowError):
                    raise ValueError("OS: valor nao numerico para " + system) from None
                if value is not None and (not math.isfinite(value) or not 0 <= value <= 1):
                    raise ValueError("OS: valor normalizado invalido")
                values[system][t] = value
        if name == "recent":
            recent = [t for t in times if t < stop and t + HOUR <= min(end, updated)]
    if not recent:
        raise ValueError("OS: nenhuma hora completa disponivel")
    return values, recent, updated


def measurement(values, hour):
    current = values.get(hour)
    controls = [(hour - weeks * 7 * DAY, values.get(hour - weeks * 7 * DAY))
                for weeks in range(1, 5)]
    if current is None or any(value is None for _, value in controls):
        return None
    baseline = statistics.median(value for _, value in controls)
    if baseline <= 0:
        return None
    return {"current": current, "baseline": baseline,
            "drop_pct": (baseline - current) / baseline * 100,
            "controls": [{"hour": stamp(t), "value": value} for t, value in controls]}


def calibrate(values, recent):
    limits = {}
    for system in SYSTEMS:
        # Fix the exact last historical hour used for the agreed peak analysis.
        samples = [(t, measurement(values[system], t)) for t in recent if t <= CALIBRATION_LAST]
        samples = [(t, m) for t, m in samples if m is not None]
        if len(samples) < 600:
            raise ValueError("OS: amostra de calibracao insuficiente para " + system)
        peak_hour, peak = max(samples, key=lambda item: item[1]["drop_pct"])
        peak_pct = max(0, peak["drop_pct"])
        if peak_pct <= 0:
            raise ValueError("OS: pico historico invalido para " + system)
        limits[system] = {"peak_pct": peak_pct, "medium_pct": peak_pct * 1.15,
                          "critical_pct": peak_pct * 1.15 * 1.5,
                          "peak_hour": stamp(peak_hour), "peak_measurement": peak,
                          "sample_count": len(samples)}
    return limits


def record_sample(conn, system, hour, sample, limits, observed, updated, reprocess=False):
    level = (2 if sample["drop_pct"] >= limits["critical_pct"] else
             1 if sample["drop_pct"] >= limits["medium_pct"] else 0)
    cursor = conn.execute("""INSERT OR IGNORE INTO os_samples
        (os,hour,current,baseline,drop_pct,level,controls_json,retrieved_at,source_updated_at)
        VALUES (?,?,?,?,?,?,?,?,?)""", (system, stamp(hour), sample["current"], sample["baseline"],
        sample["drop_pct"], level, json.dumps(sample["controls"]), stamp(observed), stamp(updated)))
    if not cursor.rowcount:
        if not reprocess:
            return []
        conn.execute("""UPDATE os_samples SET current=?,baseline=?,drop_pct=?,level=?,
            controls_json=?,retrieved_at=?,source_updated_at=? WHERE os=? AND hour=?""",
            (sample["current"], sample["baseline"], sample["drop_pct"], level,
             json.dumps(sample["controls"]), stamp(observed), stamp(updated), system, stamp(hour)))
    active = conn.execute("SELECT * FROM os_episodes WHERE os=? AND ended_at IS NULL",
                          (system,)).fetchone()
    if not level:
        if active:
            consecutive = active["last_normal_at"] == stamp(hour - HOUR)
            count = active["normal_hours"] + 1 if consecutive else 1
            conn.execute("""UPDATE os_episodes SET normal_hours=?,last_normal_at=?,ended_at=?
                WHERE episode_id=?""", (count, stamp(hour), stamp(hour + HOUR) if count >= 2 else None,
                                       active["episode_id"]))
        return []
    if active:
        episode = active["episode_id"]
        conn.execute("UPDATE os_episodes SET normal_hours=0,last_normal_at=NULL WHERE episode_id=?",
                     (episode,))
        if level <= active["highest_level"]:
            return []
        conn.execute("UPDATE os_episodes SET highest_level=? WHERE episode_id=?", (level, episode))
    else:
        episode = conn.execute("""INSERT INTO os_episodes
            (os,started_at,detected_at,highest_level) VALUES (?,?,?,?)""",
            (system, stamp(hour), stamp(observed), level)).lastrowid
    notification = conn.execute("""INSERT INTO alert_notifications
        (source,event_key,level,created_at) VALUES ('os',?,?,?)""",
        (str(episode), level, stamp(observed))).lastrowid
    return [notification]


def collect(client, now):
    end = now.replace(minute=0, second=0, microsecond=0)
    conn = client.conn
    stored = conn.execute("SELECT method,limits_json FROM os_calibration WHERE id=1").fetchone()
    calibrating = not stored or stored["method"] != METHOD
    has_episodes = bool(stored and conn.execute("SELECT EXISTS(SELECT 1 FROM os_episodes)").fetchone()[0])
    calibration_result = None
    calibration_recent = None
    calibration_params = parameters(CALIBRATION_END)
    if calibrating and end != CALIBRATION_END:
        calibration_result = client.get(ENDPOINT, calibration_params)
        calibration_values, calibration_recent, _ = parse_series(calibration_result, CALIBRATION_END)
        limits = calibrate(calibration_values, calibration_recent)
    params = parameters(end)
    result = client.get(ENDPOINT, params)
    values, recent, updated = parse_series(result, end)
    if now - (recent[-1] + HOUR) > MAX_AGE:
        raise ValueError("OS: ultima hora completa esta defasada mais de 3 horas")
    if calibrating and end == CALIBRATION_END:
        calibration_result, calibration_recent = result, recent
        limits = calibrate(values, recent)
    elif not calibrating:
        limits = json.loads(stored["limits_json"])
    if calibrating and has_episodes:
        if stored["method"] != "OS_WEEKLY_MEDIAN_4_CAL_20261126_19Z_V1":
            raise ValueError("OS: calibracao anterior tem episodios; revisao manual necessaria")
        for row in conn.execute("SELECT os,drop_pct,level FROM os_samples"):
            threshold = limits[row["os"]]
            revised = (2 if row["drop_pct"] >= threshold["critical_pct"] else
                       1 if row["drop_pct"] >= threshold["medium_pct"] else 0)
            if revised != row["level"]:
                raise ValueError("OS: ajuste altera alertas existentes; revisao manual necessaria")
    notifications = []
    missing = []
    with conn:
        if calibrating:
            conn.execute("""INSERT INTO os_calibration VALUES (1,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET created_at=excluded.created_at,method=excluded.method,
                params_json=excluded.params_json,response_json=excluded.response_json,
                limits_json=excluded.limits_json""", (stamp(now), METHOD, json.dumps(calibration_params),
                json.dumps(calibration_result), json.dumps(limits)))
        previous = {system: conn.execute("SELECT MAX(hour) FROM os_samples WHERE os=?",
                                        (system,)).fetchone()[0] for system in SYSTEMS}
        # Chronological samples, deterministic OS order for simultaneous hourly detections.
        for hour in recent:
            for system in SYSTEMS:
                last = previous[system]
                if last and stamp(recent[-1]) < last:
                    if system not in missing:
                        missing.append(system)
                    continue
                correcting = bool(stored and calibrating and not has_episodes)
                if correcting and hour <= CALIBRATION_LAST:
                    continue
                if not correcting and ((last is None and hour != recent[-1]) or (last and stamp(hour) <= last)):
                    if hour == recent[-1] and measurement(values[system], hour) is None:
                        missing.append(system)
                    continue
                sample = measurement(values[system], hour)
                if hour == recent[-1] and sample is None:
                    missing.append(system)
                if sample is not None:
                    notifications.extend(record_sample(conn, system, hour, sample,
                                                       limits[system], now, updated, reprocess=correcting))
        conn.execute("""INSERT INTO os_collection VALUES (1,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET attempted_at=excluded.attempted_at,
            succeeded_at=excluded.succeeded_at,error=excluded.error,
            unavailable_json=excluded.unavailable_json""",
            (stamp(now), stamp(now), "Controles incompletos: " + ", ".join(missing) if missing else None,
             json.dumps(missing)))
    return notifications


def record_error(conn, now, error):
    with conn:
        conn.execute("""INSERT INTO os_collection(id,attempted_at,error,unavailable_json) VALUES (1,?,?,?)
            ON CONFLICT(id) DO UPDATE SET attempted_at=excluded.attempted_at,error=excluded.error,
            unavailable_json=excluded.unavailable_json""", (stamp(now), str(error), json.dumps(list(SYSTEMS))))


def status(conn, now, interval_seconds=900):
    calibration = conn.execute("SELECT created_at,method,limits_json FROM os_calibration WHERE id=1").fetchone()
    limits = json.loads(calibration["limits_json"]) if calibration else {}
    collection = conn.execute("SELECT * FROM os_collection WHERE id=1").fetchone()
    collection_current = bool(collection and
        now - date(collection["attempted_at"]) <= timedelta(seconds=interval_seconds * 1.5))
    total = conn.execute("SELECT COUNT(*) FROM os_episodes").fetchone()[0]
    pending, sounds = conn.execute("""SELECT COUNT(DISTINCT event_key),COUNT(*)
        FROM alert_notifications WHERE source='os' AND acknowledged_at IS NULL""").fetchone()
    pending_items = [dict(row) for row in conn.execute("""SELECT n.notification_id, n.level,
        n.created_at, e.episode_id, e.os, e.started_at FROM alert_notifications n
        JOIN os_episodes e ON CAST(n.event_key AS INTEGER)=e.episode_id
        WHERE n.source='os' AND n.acknowledged_at IS NULL ORDER BY n.notification_id""")]
    items = []
    for system, label in SYSTEMS.items():
        row = conn.execute("SELECT * FROM os_samples WHERE os=? ORDER BY hour DESC LIMIT 1",
                           (system,)).fetchone()
        item = {"os": system, "label": label, "limits": limits.get(system), "sample": None,
                "available": False}
        if row:
            item["sample"] = dict(row)
            item["sample"]["controls"] = json.loads(item["sample"].pop("controls_json"))
            item["available"] = bool(collection_current and system not in json.loads(collection["unavailable_json"])
                and now - (date(row["hour"]) + HOUR) <= MAX_AGE)
        items.append(item)
    return {"total": total, "pending": pending, "pending_sounds": sounds,
            "pending_items": pending_items, "systems": items,
            "error": (collection["error"] or (None if collection_current else "Coleta OS atrasada"))
                     if collection else None,
            "last_attempt": collection["attempted_at"] if collection else None,
            "calibrated_at": calibration["created_at"] if calibration else None,
            "method": calibration["method"] if calibration else None}
