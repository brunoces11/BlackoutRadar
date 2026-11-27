"""Cloudflare Radar anomaly thermometer (experimental v1).

All calculations and timestamps use UTC; no third-party Python packages are needed.
"""

from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
import math
import os
import queue
import signal
import sqlite3
import statistics
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, time as datetime_time, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import os_monitor


UTC = timezone.utc
HOUR = timedelta(hours=1)
DAY = timedelta(days=1)
ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parent
BASE_URL = "https://api.cloudflare.com/client/v4"
SCHEMA_VERSION = 4
METHOD_VERSION = "IAI_EXPERIMENTAL_V1_2"
STOP = False


def utc_now() -> datetime:
    return datetime.now(UTC)


def stamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_date(value: str | None) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return result.astimezone(UTC) if result.tzinfo else None


def env_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    values = {}
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("\"'")
    return values


def config_value(name: str, default: str | None = None) -> str | None:
    if os.environ.get(name):
        return os.environ[name]
    for path in (PROJECT / ".env", PROJECT / "env.txt", ROOT / ".env"):
        value = env_file(path).get(name)
        if value:
            return value
    return default


def config_int(name: str, default: int, minimum: int, maximum: int) -> int:
    value = int(config_value(name, str(default)))
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} deve estar entre {minimum} e {maximum}")
    return value


def path_setting(name: str, default: Path) -> Path:
    raw = config_value(name)
    if not raw:
        return default
    path = Path(raw)
    return path if path.is_absolute() else PROJECT / path


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS schema_meta (version INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS events (
            source TEXT NOT NULL, event_id TEXT NOT NULL, start_at TEXT,
            end_at TEXT, status TEXT, event_type TEXT, country_codes TEXT NOT NULL,
            linked_outage_id TEXT, payload_hash TEXT NOT NULL, raw_json TEXT NOT NULL,
            first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
            PRIMARY KEY (source, event_id)
        );
        CREATE INDEX IF NOT EXISTS events_start ON events(source, start_at);
        CREATE TABLE IF NOT EXISTS event_revisions (
            revision_id INTEGER PRIMARY KEY, source TEXT NOT NULL, event_id TEXT NOT NULL,
            observed_at TEXT NOT NULL, payload_hash TEXT NOT NULL, raw_json TEXT NOT NULL,
            FOREIGN KEY (source, event_id) REFERENCES events(source, event_id)
        );
        CREATE TABLE IF NOT EXISTS api_calls (
            call_id INTEGER PRIMARY KEY, endpoint TEXT NOT NULL, params_json TEXT NOT NULL,
            retrieved_at TEXT NOT NULL, http_status INTEGER, success INTEGER NOT NULL,
            error TEXT, row_count INTEGER
        );
        CREATE TABLE IF NOT EXISTS traffic_windows (
            location TEXT NOT NULL, window_end TEXT NOT NULL, drop_3h REAL NOT NULL,
            drop_24h REAL NOT NULL, confidence INTEGER NOT NULL,
            source_last_updated_at TEXT, retrieved_at TEXT NOT NULL,
            request_json TEXT NOT NULL, response_json TEXT NOT NULL,
            PRIMARY KEY (location, window_end)
        );
        CREATE TABLE IF NOT EXISTS index_runs (
            run_id INTEGER PRIMARY KEY, calculated_at TEXT NOT NULL, reference_at TEXT,
            state TEXT NOT NULL, score REAL, components_json TEXT NOT NULL,
            coverage_json TEXT NOT NULL, method_version TEXT NOT NULL
        );
    """)
    versions = [row[0] for row in conn.execute("SELECT version FROM schema_meta")]
    if versions and versions not in ([1], [2], [3], [SCHEMA_VERSION]):
        raise RuntimeError("Versao de schema desconhecida; banco preservado sem migracao")
    os_monitor.initialize(conn)
    with conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS outage_alerts (
            outage_id TEXT PRIMARY KEY, start_at TEXT, location TEXT NOT NULL,
            alerted_at TEXT, acknowledged_at TEXT,
            is_simulation INTEGER NOT NULL DEFAULT 0
        )""")
        columns = {row[1] for row in conn.execute("PRAGMA table_info(outage_alerts)")}
        if "is_simulation" not in columns:
            conn.execute("ALTER TABLE outage_alerts ADD COLUMN is_simulation INTEGER NOT NULL DEFAULT 0")
        conn.execute("""CREATE TABLE IF NOT EXISTS alert_state (
            id INTEGER PRIMARY KEY CHECK(id=1), initialized INTEGER NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS alert_notifications (
            notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL CHECK(source IN ('outage','os')),
            event_key TEXT NOT NULL, level INTEGER NOT NULL,
            created_at TEXT NOT NULL, acknowledged_at TEXT,
            UNIQUE(source,event_key,level)
        )""")
        conn.execute("""INSERT OR IGNORE INTO alert_notifications
            (source,event_key,level,created_at,acknowledged_at)
            SELECT 'outage',outage_id,1,alerted_at,acknowledged_at FROM outage_alerts
            WHERE alerted_at IS NOT NULL ORDER BY alerted_at,rowid""")
        if not versions:
            conn.execute("INSERT INTO schema_meta(version) VALUES (?)", (SCHEMA_VERSION,))
        elif versions != [SCHEMA_VERSION]:
            conn.execute("UPDATE schema_meta SET version=?", (SCHEMA_VERSION,))
        if not conn.execute("SELECT 1 FROM alert_state WHERE id=1").fetchone():
            conn.execute("""
                INSERT OR IGNORE INTO outage_alerts(outage_id,start_at,location)
                SELECT event_id,start_at,'Local não informado' FROM events
                WHERE source='outages' AND event_type='OUTAGE'
            """)
            existing = conn.execute("SELECT EXISTS(SELECT 1 FROM outage_alerts)").fetchone()[0]
            conn.execute("INSERT INTO alert_state(id,initialized) VALUES (1,?)", (existing,))
    return conn


class RadarError(Exception):
    pass


class BudgetError(RadarError):
    pass


class RadarClient:
    def __init__(self, token: str, conn: sqlite3.Connection, timeout: int, budget: int):
        self.token = token
        self.conn = conn
        self.timeout = timeout
        self.budget = budget
        self.used = 0

    def get(self, endpoint: str, params: list[tuple[str, str]]) -> dict:
        last_error = ""
        for attempt in range(3):
            if self.used >= self.budget:
                raise BudgetError("Orcamento de requisicoes esgotado")
            self.used += 1
            status = None
            try:
                url = BASE_URL + endpoint + "?" + urllib.parse.urlencode(params)
                request = urllib.request.Request(url, headers={
                    "Authorization": "Bearer " + self.token,
                    "Accept": "application/json",
                    "User-Agent": "internet-anomaly-radar/1.0",
                })
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    status = response.status
                    payload = json.load(response)
                if not isinstance(payload, dict) or payload.get("success") is not True:
                    raise RadarError("Resposta JSON sem success=true")
                result = payload.get("result")
                if not isinstance(result, dict):
                    raise RadarError("result ausente ou invalido")
                self._record(endpoint, params, status, True, None, None)
                return result
            except urllib.error.HTTPError as exc:
                status = exc.code
                last_error = f"HTTP {status}"
                retry_after = exc.headers.get("Retry-After")
                self._record(endpoint, params, status, False, last_error, None)
                if status == 429:
                    raise RadarError(f"HTTP 429; Retry-After={retry_after or 'nao informado'}") from None
                if status not in (500, 502, 503, 504) or attempt == 2:
                    raise RadarError(last_error) from None
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = type(exc).__name__
                self._record(endpoint, params, status, False, last_error, None)
                if attempt == 2:
                    raise RadarError(last_error) from None
            except (ValueError, RadarError) as exc:
                last_error = str(exc)
                self._record(endpoint, params, status, False, last_error, None)
                raise RadarError(last_error) from None
            time.sleep(min(2 ** attempt, 4))
        raise RadarError(last_error)

    def _record(self, endpoint, params, status, success, error, row_count):
        self.conn.execute(
            "INSERT INTO api_calls(endpoint,params_json,retrieved_at,http_status,success,error,row_count) "
            "VALUES (?,?,?,?,?,?,?)",
            (endpoint, json.dumps(params), stamp(utc_now()), status, int(success), error, row_count),
        )
        self.conn.commit()


def event_pages(client: RadarClient, source: str, start: datetime, end: datetime) -> list[dict]:
    endpoint, field = (
        ("/radar/traffic_anomalies", "trafficAnomalies") if source == "anomalies"
        else ("/radar/annotations/outages", "annotations")
    )
    rows: list[dict] = []
    ids: set[str] = set()
    limit = 200  # Validated with authenticated calls; not claimed to be an API maximum.
    first_page = None
    for page in range(30):
        params = [("dateStart", stamp(start)), ("dateEnd", stamp(end)),
                  ("limit", str(limit)), ("offset", str(page * limit))]
        result = client.get(endpoint, params)
        batch = result.get(field)
        if not isinstance(batch, list):
            raise RadarError(f"{source}: lista ausente")
        if page == 0:
            first_page = batch
        for item in batch:
            if not isinstance(item, dict):
                raise RadarError(f"{source}: registro invalido")
            event_id = item.get("uuid" if source == "anomalies" else "id")
            if not isinstance(event_id, str) or not event_id:
                raise RadarError(f"{source}: ID ausente")
            if parse_date(item.get("startDate")) is None:
                raise RadarError(f"{source}: startDate invalido")
            if item.get("endDate") is not None and parse_date(item.get("endDate")) is None:
                raise RadarError(f"{source}: endDate invalido")
            if (item.get("endDate") is not None
                    and parse_date(item["endDate"]) < parse_date(item["startDate"])):
                raise RadarError(f"{source}: endDate anterior a startDate")
            if source == "anomalies" and item.get("status") not in {"UNVERIFIED", "TP", "VERIFIED"}:
                raise RadarError("anomalies: status novo ou desconhecido")
            if event_id in ids:
                raise RadarError(f"{source}: ID duplicado entre paginas")
            ids.add(event_id)
            rows.append(item)
        if len(batch) < limit:
            # Confirm that the page was not silently truncated.
            check = client.get(endpoint, [("dateStart", stamp(start)), ("dateEnd", stamp(end)),
                                          ("limit", str(limit)),
                                          ("offset", str(page * limit + len(batch)))])
            if check.get(field) != []:
                raise RadarError(f"{source}: paginacao nao confirmada")
            repeated = client.get(endpoint, [("dateStart", stamp(start)),
                                             ("dateEnd", stamp(end)),
                                             ("limit", str(limit)), ("offset", "0")])
            if repeated.get(field) != first_page:
                raise RadarError(f"{source}: primeira pagina mudou durante a coleta")
            return rows
    raise RadarError(f"{source}: limite local de paginas atingido")


def countries(source: str, item: dict) -> list[str]:
    if source == "anomalies":
        details = item.get("locationDetails") if item.get("type") == "LOCATION" else None
        code = details.get("code") if isinstance(details, dict) else None
        return [code] if isinstance(code, str) and len(code) == 2 else []
    return sorted({code for code in (item.get("locations") or [])
                   if isinstance(code, str) and len(code) == 2})


def candidate_countries(source: str, item: dict) -> list[str]:
    """ASN home countries guide queries; they do not prove geographic impact."""
    codes = set(countries(source, item))
    details = item.get("asnDetails") if source == "anomalies" else None
    asns = [details] if isinstance(details, dict) else item.get("asnsDetails") or []
    for asn in asns:
        location = asn.get("location") if isinstance(asn, dict) else None
        code = location.get("code") if isinstance(location, dict) else None
        if isinstance(code, str) and len(code) == 2:
            codes.add(code)
    return sorted(codes)


def save_events(conn: sqlite3.Connection, source: str, rows: list[dict]) -> None:
    observed = stamp(utc_now())
    with conn:
        for item in rows:
            event_id = item["uuid" if source == "anomalies" else "id"]
            raw = json.dumps(item, sort_keys=True, separators=(",", ":"))
            digest = hashlib.sha256(raw.encode()).hexdigest()
            previous = conn.execute(
                "SELECT payload_hash FROM events WHERE source=? AND event_id=?", (source, event_id)
            ).fetchone()
            conn.execute("""
                INSERT INTO events(source,event_id,start_at,end_at,status,event_type,country_codes,
                    linked_outage_id,payload_hash,raw_json,first_seen_at,last_seen_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(source,event_id) DO UPDATE SET
                    start_at=excluded.start_at,end_at=excluded.end_at,status=excluded.status,
                    event_type=excluded.event_type,country_codes=excluded.country_codes,
                    linked_outage_id=excluded.linked_outage_id,payload_hash=excluded.payload_hash,
                    raw_json=excluded.raw_json,last_seen_at=excluded.last_seen_at
            """, (source, event_id, item.get("startDate"), item.get("endDate"),
                  item.get("status"), item.get("type") or item.get("eventType"),
                  json.dumps(countries(source, item)), item.get("outageId"),
                  digest, raw, observed, observed))
            if previous is None or previous["payload_hash"] != digest:
                conn.execute(
                    "INSERT INTO event_revisions(source,event_id,observed_at,payload_hash,raw_json) "
                    "VALUES (?,?,?,?,?)", (source, event_id, observed, digest, raw)
                )


def outage_location(item: dict) -> str:
    for key in ("locationsDetails", "geoIds"):
        details = item.get(key) or []
        for location in ([details] if isinstance(details, dict) else details):
            if isinstance(location, dict):
                name = location.get("name") or location.get("code")
            else:
                name = location
            if isinstance(name, str) and name:
                return name
    codes = countries("outages", item)
    return ", ".join(codes) if codes else "Local não informado"


def record_outage_alerts(conn: sqlite3.Connection, outages: list[dict],
                         simulation: bool = False) -> list[int]:
    """Register each unique outage; the first successful collection is a baseline."""
    observed = stamp(utc_now())
    new_ids = []
    with conn:
        initialized = conn.execute("SELECT initialized FROM alert_state WHERE id=1").fetchone()[0]
        for item in sorted(outages, key=lambda item: (item.get("startDate") or "", item["id"])):
            event_id = item["id"]
            cursor = conn.execute("""
                INSERT OR IGNORE INTO outage_alerts
                    (outage_id,start_at,location,alerted_at,is_simulation)
                VALUES (?,?,?,?,?)
            """, (event_id, item.get("startDate"), outage_location(item),
                  observed if initialized else None, int(simulation)))
            if initialized and cursor.rowcount:
                notification = conn.execute("""INSERT INTO alert_notifications
                    (source,event_key,level,created_at) VALUES ('outage',?,1,?)""",
                    (event_id, observed)).lastrowid
                new_ids.append(notification)
        if not initialized:
            conn.execute("UPDATE alert_state SET initialized=1 WHERE id=1")
    return new_ids


def alert_counts(conn: sqlite3.Connection) -> dict:
    row = conn.execute("""
        SELECT COUNT(CASE WHEN alerted_at IS NOT NULL THEN 1 END) AS total,
               COUNT(CASE WHEN alerted_at IS NOT NULL AND acknowledged_at IS NULL THEN 1 END)
                   AS pending,
               COUNT(CASE WHEN is_simulation=1 AND alerted_at IS NOT NULL
                   AND acknowledged_at IS NULL THEN 1 END) AS simulation_pending
        FROM outage_alerts
    """).fetchone()
    return {"total": row["total"], "pending": row["pending"],
            "simulation_pending": row["simulation_pending"]}


def pending_alerts(conn: sqlite3.Connection) -> list[dict]:
    return [dict(row) for row in conn.execute("""
        SELECT o.outage_id,o.start_at,o.location,o.alerted_at,o.is_simulation,
               n.notification_id FROM outage_alerts o
        JOIN alert_notifications n ON n.source='outage' AND n.event_key=o.outage_id
        WHERE o.alerted_at IS NOT NULL AND o.acknowledged_at IS NULL
          AND n.acknowledged_at IS NULL ORDER BY n.notification_id
    """)]


def pending_notifications(conn: sqlite3.Connection) -> list[dict]:
    return [dict(row) for row in conn.execute("""SELECT * FROM alert_notifications
        WHERE acknowledged_at IS NULL ORDER BY notification_id""")]


def acknowledge_alerts(conn: sqlite3.Connection, source: str = "outage",
                       through_id: int | None = None) -> int:
    if source not in ("outage", "os"):
        raise ValueError("Fonte de alerta invalida")
    with conn:
        observed = stamp(utc_now())
        through_id = through_id if through_id is not None else 2**63 - 1
        if not 0 <= through_id <= 2**63 - 1:
            raise ValueError("Limite de notificacao invalido")
        if source == "outage":
            conn.execute("""UPDATE outage_alerts SET acknowledged_at=?
                WHERE alerted_at IS NOT NULL AND acknowledged_at IS NULL AND outage_id IN (
                    SELECT event_key FROM alert_notifications WHERE source='outage'
                    AND acknowledged_at IS NULL AND notification_id<=?)""", (observed, through_id))
        cursor = conn.execute("""UPDATE alert_notifications SET acknowledged_at=?
            WHERE source=? AND acknowledged_at IS NULL AND notification_id<=?""",
            (observed, source, through_id))
    return cursor.rowcount


class AlertSound:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.queue: queue.Queue[list[int] | None] = queue.Queue()
        self.stopped = threading.Event()
        self.last_beep_end = 0.0
        self.announced: set[int] = set()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def notify(self, ids: list[int]) -> None:
        if ids:
            self.queue.put(ids)

    def stop(self) -> None:
        self.stopped.set()
        self.queue.put(None)
        self.thread.join(timeout=2)

    def _run(self) -> None:
        try:
            import winsound
        except ImportError:
            logging.error("Audio indisponivel: winsound requer Windows")
            return
        # One audio owner per database and Windows session, including manual launches.
        import ctypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateMutexW.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p)
        kernel.CreateMutexW.restype = ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes = (ctypes.c_void_p, ctypes.c_ulong)
        kernel.ReleaseMutex.argtypes = (ctypes.c_void_p,)
        kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
        key = hashlib.sha256(str(self.db_path.resolve()).casefold().encode()).hexdigest()[:24]
        handle = kernel.CreateMutexW(None, False, "Local\\InternetRadarAudio_" + key)
        if not handle:
            logging.error("Falha ao reservar a sessao de audio: %s", ctypes.get_last_error())
            return
        acquired = False
        try:
            while not self.stopped.is_set():
                result = kernel.WaitForSingleObject(handle, 0)
                if result in (0, 0x80):
                    acquired = True
                    self._run_player(winsound)
                    break
                if result != 0x102:
                    logging.error("Falha no mutex de audio: %s", result)
                    break
                self.stopped.wait(1)
        finally:
            if acquired:
                kernel.ReleaseMutex(handle)
            kernel.CloseHandle(handle)

    def _run_player(self, winsound) -> None:
        with closing(sqlite3.connect(self.db_path, timeout=10)) as conn:
            conn.row_factory = sqlite3.Row
            next_replay = time.monotonic() + 60
            while not self.stopped.is_set():
                try:
                    ids = self.queue.get(timeout=max(0, next_replay - time.monotonic()))
                except queue.Empty:
                    ids = None
                if self.stopped.is_set():
                    break
                if ids:
                    self._play_pending(conn, ids, winsound, only_new=True)
                if time.monotonic() >= next_replay:
                    try:
                        pending = [row["notification_id"] for row in pending_notifications(conn)]
                        self._play_pending(conn, pending, winsound)
                    except sqlite3.Error:
                        logging.exception("Falha ao consultar alertas para o apito")
                    next_replay += 60
                    if next_replay <= time.monotonic():
                        # A long queue must not create overlapping or catch-up replay loops.
                        next_replay = time.monotonic() + 60

    def _play_pending(self, conn: sqlite3.Connection, ids: list[int], winsound,
                      only_new: bool = False) -> None:
        for event_id in sorted(set(ids)):
            if self.stopped.is_set():
                break
            if only_new and event_id in self.announced:
                continue
            try:
                gap = max(0.0, self.last_beep_end + 0.5 - time.monotonic())
                if self.stopped.wait(gap):
                    break
                pending = conn.execute("""
                    SELECT source,level FROM alert_notifications WHERE notification_id=?
                    AND acknowledged_at IS NULL
                """, (event_id,)).fetchone()
                if not pending:
                    continue
                name = ("apito_04_subida.wav" if pending["source"] == "outage" else
                        "apito_09_harmonico.wav" if pending["level"] == 2 else "apito_03_grave.wav")
                sound_path = ROOT / "sounds" / name
                if not sound_path.is_file():
                    raise OSError("Arquivo de som ausente: " + name)
                winsound.PlaySound(str(sound_path), winsound.SND_FILENAME | winsound.SND_NODEFAULT)
                self.last_beep_end = time.monotonic()
                self.announced.add(event_id)
                logging.info("Som %s emitido para notificacao %s", name, event_id)
            except (OSError, RuntimeError, sqlite3.Error):
                logging.exception("Falha ao tocar notificacao %s", event_id)
                continue


def choose_reference(client: RadarClient) -> tuple[datetime, str]:
    end = utc_now().replace(minute=0, second=0, microsecond=0)
    start = end - 2 * DAY
    params = [("dateStart", stamp(start)), ("dateEnd", stamp(end)),
              ("aggInterval", "1h"), ("normalization", "MIN0_MAX"), ("product", "ALL")]
    result = client.get("/radar/netflows/timeseries", params)
    meta = result.get("meta")
    if not isinstance(meta, dict):
        raise RadarError("NetFlows: metadados invalidos")
    if meta.get("aggInterval") != "ONE_HOUR" or meta.get("normalization") != "MIN0_MAX":
        raise RadarError("NetFlows: granularidade ou normalizacao incompativel")
    series = [v for k, v in result.items() if k != "meta" and isinstance(v, dict)]
    if len(series) != 1 or not isinstance(series[0].get("timestamps"), list):
        raise RadarError("NetFlows: serie de diagnostico invalida")
    times = [parse_date(t) for t in series[0]["timestamps"]]
    times = [t for t in times if t is not None]
    if not times:
        raise RadarError("NetFlows: sem medicoes recentes")
    reference = max(times) + HOUR
    last_updated = meta.get("lastUpdated")
    if parse_date(last_updated) is None:
        raise RadarError("NetFlows: lastUpdated invalido")
    if utc_now() - reference > timedelta(hours=6):
        raise RadarError("NetFlows: dados defasados mais de 6 horas")
    if parse_date(last_updated) < reference:
        raise RadarError("NetFlows: fonte ainda nao atualizou o periodo escolhido")
    return reference, last_updated


def cached_window(conn: sqlite3.Connection, location: str, end: datetime) -> dict | None:
    row = conn.execute("SELECT * FROM traffic_windows WHERE location=? AND window_end=?",
                       (location, stamp(end))).fetchone()
    if not row:
        return None
    age = utc_now() - parse_date(row["retrieved_at"])
    ttl = timedelta(minutes=55) if end > utc_now() - 2 * DAY else DAY
    return dict(row) if age < ttl else None


def traffic_window(client: RadarClient, location: str, end: datetime) -> dict:
    cached = cached_window(client.conn, location, end)
    if cached:
        return cached
    start = end - DAY
    params = [("name", "current"), ("dateStart", stamp(start)), ("dateEnd", stamp(end))]
    if location != "GLOBAL":
        params.append(("location", location))
    params.extend([("name", "previous"), ("dateStart", stamp(start - 7 * DAY)),
                   ("dateEnd", stamp(end - 7 * DAY))])
    if location != "GLOBAL":
        params.append(("location", location))
    params.extend([("aggInterval", "1h"), ("normalization", "MIN0_MAX"), ("product", "ALL")])
    result = client.get("/radar/netflows/timeseries", params)
    meta = result.get("meta")
    if not isinstance(meta, dict):
        raise RadarError(f"NetFlows {location}: metadados invalidos")
    if meta.get("aggInterval") != "ONE_HOUR" or meta.get("normalization") != "MIN0_MAX":
        raise RadarError(f"NetFlows {location}: metadados incompativeis")
    confidence_info = meta.get("confidenceInfo")
    confidence = confidence_info.get("level") if isinstance(confidence_info, dict) else None
    if confidence != 5:
        raise RadarError(f"NetFlows {location}: nivel de confianca {confidence}")
    units = meta.get("units") or []
    if not any(isinstance(unit, dict) and unit.get("value") == "bytes" for unit in units):
        raise RadarError(f"NetFlows {location}: unidade nao validada")
    ranges = meta.get("dateRange")
    if not isinstance(ranges, list) or len(ranges) != 2:
        raise RadarError(f"NetFlows {location}: intervalos nao validados")
    expected_ranges = ((start, end), (start - 7 * DAY, end - 7 * DAY))
    for returned, (expected_start, expected_end) in zip(ranges, expected_ranges):
        if (not isinstance(returned, dict)
                or parse_date(returned.get("startTime")) != expected_start
                or parse_date(returned.get("endTime")) != expected_end):
            raise RadarError(f"NetFlows {location}: intervalo ajustado inesperadamente")
    if end > utc_now() - 2 * DAY and (
            parse_date(meta.get("lastUpdated")) is None
            or parse_date(meta.get("lastUpdated")) < end):
        raise RadarError(f"NetFlows {location}: medicao ainda nao atualizada")
    series = []
    for name in ("current", "previous"):
        data = result.get(name)
        if not isinstance(data, dict):
            raise RadarError(f"NetFlows {location}: serie ausente")
        timestamps, values = data.get("timestamps"), data.get("values")
        if not isinstance(timestamps, list) or not isinstance(values, list) or len(timestamps) != len(values):
            raise RadarError(f"NetFlows {location}: serie invalida")
        try:
            mapping = {parse_date(t): float(v) for t, v in zip(timestamps, values)}
        except (TypeError, ValueError):
            raise RadarError(f"NetFlows {location}: valor nao numerico") from None
        if None in mapping or len(mapping) != len(timestamps):
            raise RadarError(f"NetFlows {location}: timestamps invalidos ou duplicados")
        series.append(mapping)
    pairs = []
    for hour in range(24):
        instant = start + hour * HOUR
        try:
            current = series[0][instant]
            previous = series[1][instant - 7 * DAY]
        except KeyError:
            raise RadarError(f"NetFlows {location}: ponto horario ausente") from None
        if not all(math.isfinite(v) and v >= 0 for v in (current, previous)):
            raise RadarError(f"NetFlows {location}: valor invalido")
        pairs.append((current, previous))
    previous_sum = sum(p for _, p in pairs)
    if previous_sum <= 0:
        raise RadarError(f"NetFlows {location}: denominador zero")
    drop_24 = max(0.0, 1 - sum(c for c, _ in pairs) / previous_sum)
    drop_3 = 0.0
    for start_hour in range(22):
        block = pairs[start_hour:start_hour + 3]
        prior = sum(p for _, p in block)
        if prior > 0:
            drop_3 = max(drop_3, max(0.0, 1 - sum(c for c, _ in block) / prior))
    retrieved = stamp(utc_now())
    row = (location, stamp(end), drop_3, drop_24, confidence, meta.get("lastUpdated"),
           retrieved, json.dumps(params), json.dumps(result, separators=(",", ":")))
    with client.conn:
        client.conn.execute("""
            INSERT INTO traffic_windows(location,window_end,drop_3h,drop_24h,confidence,
                source_last_updated_at,retrieved_at,request_json,response_json)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(location,window_end) DO UPDATE SET
                drop_3h=excluded.drop_3h,drop_24h=excluded.drop_24h,
                confidence=excluded.confidence,source_last_updated_at=excluded.source_last_updated_at,
                retrieved_at=excluded.retrieved_at,request_json=excluded.request_json,
                response_json=excluded.response_json
        """, row)
    return dict(client.conn.execute(
        "SELECT * FROM traffic_windows WHERE location=? AND window_end=?", (location, stamp(end))
    ).fetchone())


def event_metrics(anomalies: list[dict], outages: list[dict], end: datetime) -> dict:
    start = end - DAY
    new_anomalies = [item for item in anomalies if (date := parse_date(item.get("startDate")))
                     and start <= date < end]
    geographic = {code for item in new_anomalies for code in countries("anomalies", item)}
    active_outages = [item for item in outages
                      if item.get("eventType") == "OUTAGE"
                      and (begin := parse_date(item.get("startDate"))) is not None
                      and (finish := parse_date(item.get("endDate"))) is not None
                      and begin <= end < finish]
    outage_ids = {item.get("id") for item in active_outages}
    active_anomalies = [item for item in anomalies
                        if (begin := parse_date(item.get("startDate"))) is not None
                        and (finish := parse_date(item.get("endDate"))) is not None
                        and begin <= end < finish and item.get("outageId") not in outage_ids]
    active_by_country: dict[str, int] = {}
    for source, items in (("outages", active_outages), ("anomalies", active_anomalies)):
        for item in items:
            for code in countries(source, item):
                active_by_country[code] = active_by_country.get(code, 0) + 1
    return {"new": len(new_anomalies), "countries": len(geographic),
            "active": len(active_outages) + len(active_anomalies),
            "active_outages": len(active_outages),
            "active_by_country": active_by_country}


def historical_position(value: float, history: list[float]) -> float:
    if len(history) != 12 or not all(math.isfinite(v) for v in [value, *history]):
        raise RadarError("Historico insuficiente ou invalido")
    return 100 * sum(past < value for past in history) / 12


def traffic_component(current: dict, previous: list[dict], short_scale: float,
                      daily_scale: float) -> float:
    """Historical rank times drop size; use the latest 3h and the full 24h."""
    short_current = latest_three_drop(current)
    short_history = [latest_three_drop(window) for window in previous]
    return max(
        historical_position(short_current, short_history)
        * min(1, short_current / short_scale),
        historical_position(current["drop_24h"], [x["drop_24h"] for x in previous])
        * min(1, current["drop_24h"] / daily_scale),
    )


def latest_three_drop(window: dict) -> float:
    try:
        result = json.loads(window["response_json"])
        end = parse_date(window["window_end"])
        if end is None:
            raise ValueError("fim ausente")
        maps = []
        for key in ("current", "previous"):
            series = result[key]
            maps.append({parse_date(t): float(v) for t, v in
                         zip(series["timestamps"], series["values"])})
        pairs = [(maps[0][end - (3 - hour) * HOUR],
                  maps[1][end - (3 - hour) * HOUR - 7 * DAY])
                 for hour in range(3)]
        if any(not math.isfinite(a) or not math.isfinite(b) or a < 0 or b < 0
               for a, b in pairs):
            raise ValueError("valor invalido")
        baseline = sum(b for _, b in pairs)
        if baseline <= 0:
            raise ValueError("denominador zero")
        return max(0.0, 1 - sum(a for a, _ in pairs) / baseline)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RadarError("NetFlows: janela de tres horas invalida") from exc


def relevant_countries(anomalies: list[dict], outages: list[dict], reference: datetime) -> list[str]:
    scores: dict[str, int] = {}
    for source, items in (("outages", outages), ("anomalies", anomalies)):
        for item in items:
            if source == "outages" and item.get("eventType") != "OUTAGE":
                continue
            start = parse_date(item.get("startDate"))
            end = parse_date(item.get("endDate"))
            if not start or start >= reference:
                continue
            if end is None:
                if start < reference - DAY:
                    continue  # Missing endDate does not establish an ongoing event.
                weight = 1
            elif end <= reference - DAY:
                continue
            else:
                weight = 2 if end > reference else 1
            for code in candidate_countries(source, item):
                scores[code] = scores.get(code, 0) + weight
    return sorted(scores, key=lambda code: (-scores[code], code))


def calculate(client: RadarClient, anomalies: list[dict], outages: list[dict],
              reference: datetime, max_regions: int, outages_available: bool = True
              ) -> tuple[float | None, str, dict, dict]:
    """IAI = max(.40F+.20G+.25A+.15T, max_region(.70R+.30A_region))."""
    metrics = [event_metrics(anomalies, outages, reference - week * 7 * DAY)
               for week in range(13)]
    windows: dict[str, list[dict]] = {"GLOBAL": []}
    errors = []
    for week in range(13):
        try:
            windows["GLOBAL"].append(traffic_window(client, "GLOBAL", reference - week * 7 * DAY))
        except RadarError as exc:
            errors.append(str(exc))
            break
    regions = relevant_countries(anomalies, outages, reference)
    regions_fetched = 0
    for location in regions:
        existing = [cached_window(client.conn, location, reference - week * 7 * DAY)
                    for week in range(13)]
        if all(existing):
            windows[location] = existing
            continue
        if regions_fetched >= max_regions:
            continue
        regions_fetched += 1
        windows[location] = []
        for week in range(13):
            try:
                windows[location].append(traffic_window(client, location, reference - week * 7 * DAY))
            except RadarError as exc:
                errors.append(str(exc))
                break
    coverage = {"outages_available": outages_available,
                "region_selection": "explicit locations and ASN home-country candidates",
                "regions_required": regions, "regions_complete": [
        code for code in regions if len(windows.get(code, [])) == 13],
        "global_complete": len(windows["GLOBAL"]) == 13,
        "errors": errors, "requests_used": client.used}
    components: dict = {"events_24h": metrics[0], "regional": {}}
    if len(windows["GLOBAL"]) != 13:
        return None, "INDISPONIVEL", components, coverage
    frequency = [m["new"] for m in metrics]
    geography = [m["countries"] for m in metrics]
    active = [m["active"] for m in metrics]
    f = historical_position(frequency[0], frequency[1:]) * min(
        1, max(0, frequency[0] - statistics.median(frequency[1:])) / 5)
    g = historical_position(geography[0], geography[1:]) * min(
        1, max(0, geography[0] - statistics.median(geography[1:])) / 3)
    a = historical_position(active[0], active[1:]) * min(1, active[0] / 2)
    t = traffic_component(windows["GLOBAL"][0], windows["GLOBAL"][1:], .20, .20)
    global_score = .40 * f + .20 * g + .25 * a + .15 * t
    regional_score = 0.0
    for code in regions:
        if len(windows.get(code, [])) != 13:
            continue
        r = traffic_component(windows[code][0], windows[code][1:], .30, .20)
        region_active = [m["active_by_country"].get(code, 0) for m in metrics]
        a_region = historical_position(region_active[0], region_active[1:]) * min(
            1, region_active[0] / 2)
        candidate = .70 * r + .30 * a_region
        regional_score = max(regional_score, candidate)
        components["regional"][code] = {
            "signal": round(r, 2),
            "active_signal": round(a_region, 2),
            "active_events": region_active[0],
            "drop_last_3h": round(latest_three_drop(windows[code][0]) * 100, 2),
            "peak_drop_3h_in_24h": round(windows[code][0]["drop_3h"] * 100, 2),
            "drop_24h": round(windows[code][0]["drop_24h"] * 100, 2),
        }
    components.update({"F": round(f, 2), "G": round(g, 2), "A": round(a, 2),
                       "T": round(t, 2), "global_branch": round(global_score, 2),
                       "regional_branch": round(regional_score, 2),
                       "global_drop_last_3h": round(latest_three_drop(windows["GLOBAL"][0]) * 100, 2),
                       "global_peak_drop_3h_in_24h": round(windows["GLOBAL"][0]["drop_3h"] * 100, 2),
                       "global_drop_24h": round(windows["GLOBAL"][0]["drop_24h"] * 100, 2)})
    if len(coverage["regions_complete"]) != len(regions):
        state = "PARCIAL"
        coverage["score_is_lower_bound"] = True
    else:
        state = "EXPERIMENTAL" if outages_available else "PRELIMINAR"
    return round(max(global_score, regional_score), 2), state, components, coverage


def display_time(value: datetime, tz_name: str) -> str:
    try:
        return value.astimezone(ZoneInfo(tz_name)).isoformat(timespec="minutes")
    except ZoneInfoNotFoundError:
        return stamp(value) + " (fuso configurado indisponivel)"


def diagnostic_report(conn: sqlite3.Connection, first_call_id: int,
                      requested_start: datetime | None, requested_end: datetime,
                      reference: datetime | None, anomalies: list[dict] | None,
                      annotations: list[dict] | None, global_complete: bool) -> dict:
    """Report observed capabilities without inferring retention from empty ranges."""
    calls = conn.execute(
        "SELECT endpoint,http_status,success FROM api_calls WHERE call_id>? ORDER BY call_id",
        (first_call_id,),
    ).fetchall()
    endpoints = {}
    for label, path, rows in (
        ("traffic_anomalies", "/radar/traffic_anomalies", anomalies),
        ("internet_outages", "/radar/annotations/outages", annotations),
    ):
        observed = [row for row in calls if row["endpoint"] == path]
        dates = [parse_date(row.get("startDate")) for row in (rows or [])]
        dates = [date for date in dates if date is not None]
        endpoints[label] = {
            "status": "SUPPORTED" if rows is not None else (
                "UNSUPPORTED" if any(row["http_status"] in (401, 403) for row in observed)
                else "NOT_VALIDATED"),
            "http_statuses": sorted({row["http_status"] for row in observed
                                     if row["http_status"] is not None}),
            "records": len(rows) if rows is not None else None,
            "oldest_record_at": stamp(min(dates)) if dates else None,
            "latest_record_at": stamp(max(dates)) if dates else None,
            "fields_observed": sorted({key for row in (rows or []) for key in row}),
            "pagination": ("SUPPORTED" if len(rows) > 200 else "PARTIALLY_SUPPORTED")
            if rows is not None else "NOT_VALIDATED",
            "historical_retention": "NOT_VALIDATED",
        }
    traffic_calls = [row for row in calls if row["endpoint"] == "/radar/netflows/timeseries"]
    window = conn.execute(
        "SELECT response_json FROM traffic_windows WHERE location='GLOBAL' AND window_end=?",
        (stamp(reference),),
    ).fetchone() if reference else None
    meta = json.loads(window["response_json"]).get("meta", {}) if window else {}
    endpoints["netflows_timeseries"] = {
        "status": "SUPPORTED" if global_complete else (
            "PARTIALLY_SUPPORTED" if reference else (
                "UNSUPPORTED" if any(row["http_status"] in (401, 403) for row in traffic_calls)
                else "NOT_VALIDATED")),
        "http_statuses": sorted({row["http_status"] for row in traffic_calls
                                 if row["http_status"] is not None}),
        "aggregation_interval": meta.get("aggInterval"),
        "normalization": meta.get("normalization"),
        "units": meta.get("units"),
        "confidence_level": (meta.get("confidenceInfo") or {}).get("level"),
        "source_last_updated_at": meta.get("lastUpdated"),
        "paired_weekly_windows": "SUPPORTED" if global_complete else "NOT_VALIDATED",
        "historical_retention": "NOT_VALIDATED",
    }
    return {
        "authentication": "SUPPORTED" if any(row["success"] for row in calls) else (
            "UNSUPPORTED" if any(row["http_status"] in (401, 403) for row in calls)
            else "NOT_VALIDATED"),
        "requested_start_at": stamp(requested_start) if requested_start else None,
        "requested_end_at": stamp(requested_end),
        "reference_at": stamp(reference) if reference else None,
        "endpoints": endpoints,
        "limitation": "A janela consultada nao comprova retencao total nem ausencia de eventos fora da cobertura.",
    }


def run_cycle(conn: sqlite3.Connection, token: str, args, sound: AlertSound | None = None) -> bool:
    started = utc_now()
    client = RadarClient(token, conn, args.timeout, args.request_budget)
    first_call_id = conn.execute("SELECT COALESCE(MAX(call_id), 0) FROM api_calls").fetchone()[0]
    first_run = conn.execute(
        "SELECT NOT EXISTS(SELECT 1 FROM index_runs WHERE state!='INDISPONIVEL')"
    ).fetchone()[0]
    reference = None
    start = None
    anomalies = None
    annotations = None
    outages = []
    outages_available = False
    outage_error = None
    os_error = None
    score, state, components = None, "INDISPONIVEL", {}
    coverage = {"errors": []}
    try:
        start = started - 93 * DAY
        try:
            annotations = event_pages(client, "outages", start, started)
            outages = [item for item in annotations if item.get("eventType") == "OUTAGE"]
            outages_available = True
            save_events(conn, "outages", outages)
            new_ids = record_outage_alerts(conn, outages)
            if new_ids:
                logging.info("Novos alertas de outage: %s", len(new_ids))
                if sound:
                    sound.notify(new_ids)
        except RadarError as exc:
            outage_error = str(exc)
            logging.warning("Outages indisponivel: %s", exc)
        try:
            os_ids = os_monitor.collect(client, started)
            if os_ids:
                logging.info("Novos avisos de anomalia OS: %s", len(os_ids))
                if sound:
                    sound.notify(os_ids)
        except (RadarError, ValueError, sqlite3.Error) as exc:
            os_error = str(exc)
            os_monitor.record_error(conn, started, os_error)
            logging.warning("Monitoramento OS indisponivel: %s", exc)
        reference, source_update = choose_reference(client)
        start = reference - 93 * DAY
        anomalies = event_pages(client, "anomalies", start, started)
        save_events(conn, "anomalies", anomalies)
        score, state, components, coverage = calculate(
            client, anomalies, outages, reference, args.max_regions, outages_available)
        coverage.update({"anomalies_collected": len(anomalies),
                         "outages_collected": len(outages),
                         "source_last_updated_at": source_update,
                         "observation_age_minutes": round((started - reference).total_seconds() / 60, 1)})
    except (RadarError, ValueError, sqlite3.Error) as exc:
        coverage["errors"].append(str(exc))
        logging.warning("Ciclo incompleto: %s", exc)
    if outage_error:
        coverage["errors"].append("Outages: " + outage_error)
    if os_error:
        coverage["errors"].append("OS: " + os_error)
    if first_run or args.diagnose:
        report = diagnostic_report(conn, first_call_id, start, started, reference,
                                   anomalies, annotations, coverage.get("global_complete", False))
        coverage["diagnostic"] = report
        print("Diagnostico:", json.dumps(report, ensure_ascii=False, sort_keys=True))
    coverage["requests_used"] = client.used
    coverage["cycle_duration_seconds"] = round((utc_now() - started).total_seconds(), 1)
    with conn:
        conn.execute(
            "INSERT INTO index_runs(calculated_at,reference_at,state,score,components_json,"
            "coverage_json,method_version) VALUES (?,?,?,?,?,?,?)",
            (stamp(started), stamp(reference) if reference else None, state, score,
             json.dumps(components), json.dumps(coverage), METHOD_VERSION),
        )
    logging.info("Ciclo concluido: estado=%s IAI=%s referencia=%s requisicoes=%s erros=%s",
                 state, score, stamp(reference) if reference else "indisponivel",
                 client.used, len(coverage.get("errors", [])))
    print(f"IAI {score if score is not None else 'indisponivel'}/100 | {state} | "
          f"referencia {display_time(reference, args.display_timezone) if reference else 'indisponivel'}")
    if components:
        print("Componentes:", json.dumps(components, ensure_ascii=False, sort_keys=True))
    print("Cobertura:", json.dumps(coverage, ensure_ascii=False, sort_keys=True))
    return state != "INDISPONIVEL"


def stop_signal(_signal, _frame):
    global STOP
    STOP = True


def dashboard_status(conn: sqlite3.Connection, interval: int, tz_name: str) -> dict:
    row = conn.execute(
        "SELECT calculated_at,reference_at,state,score,components_json,coverage_json "
        "FROM index_runs ORDER BY run_id DESC LIMIT 1"
    ).fetchone()
    totals = dict(conn.execute(
        "SELECT source,COUNT(*) FROM events GROUP BY source"
    ).fetchall())
    alerts = alert_counts(conn)
    alerts["pending_items"] = pending_alerts(conn)
    operating_systems = os_monitor.status(conn, utc_now(), interval)
    if row is None:
        return {"last_run": None, "totals": totals, "interval_seconds": interval,
                "timezone": tz_name, "alerts": alerts, "os": operating_systems}
    return {"last_run": {
        "calculated_at": row["calculated_at"], "reference_at": row["reference_at"],
        "state": row["state"], "score": row["score"],
        "components": json.loads(row["components_json"]),
        "coverage": json.loads(row["coverage_json"]),
    }, "totals": totals, "alerts": alerts, "os": operating_systems,
        "interval_seconds": interval, "timezone": tz_name,
        "server_time": stamp(utc_now())}


def dashboard_timeline(conn: sqlite3.Connection, days: int, tz_name: str) -> dict:
    if days == 1:
        last_hour = utc_now().replace(minute=0, second=0, microsecond=0)
        buckets = [last_hour - (23 - index) * HOUR for index in range(24)]
        first = buckets[0]
        key = lambda value: value.replace(minute=0, second=0, microsecond=0)
        labels = [value.astimezone(ZoneInfo(tz_name)).strftime("%d/%m %Hh")
                  for value in buckets]
    else:
        zone = ZoneInfo(tz_name)
        today = utc_now().astimezone(zone).date()
        buckets = [today - timedelta(days=days - 1 - index) for index in range(days)]
        first = datetime.combine(buckets[0], datetime_time.min, zone).astimezone(UTC)
        key = lambda value: value.astimezone(zone).date()
        labels = [value.strftime("%d/%m") for value in buckets]
    counts = {bucket: {"anomalies": 0, "outages": 0} for bucket in buckets}
    for row in conn.execute(
        "SELECT source,start_at FROM events WHERE start_at>=? AND source IN ('anomalies','outages')",
        (stamp(first),),
    ):
        value = parse_date(row["start_at"])
        bucket = key(value) if value else None
        if bucket in counts:
            counts[bucket][row["source"]] += 1
    return {"days": days, "labels": labels,
            "anomalies": [counts[bucket]["anomalies"] for bucket in buckets],
            "outages": [counts[bucket]["outages"] for bucket in buckets]}


def dashboard_runs(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT calculated_at,reference_at,state,score,coverage_json "
        "FROM index_runs ORDER BY run_id DESC LIMIT 20"
    ).fetchall()
    result = []
    for row in rows:
        coverage = json.loads(row["coverage_json"])
        result.append({"calculated_at": row["calculated_at"],
                       "reference_at": row["reference_at"], "state": row["state"],
                       "score": row["score"], "requests": coverage.get("requests_used"),
                       "errors": coverage.get("errors", []),
                       "regions": coverage.get("regions_complete", [])})
    return result


def dashboard_handler(db_path: Path, interval: int, tz_name: str,
                      sound: AlertSound | None = None):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path not in ("/api/alerts/acknowledge", "/api/alerts/os/acknowledge", "/api/alerts/simulate"):
                return self._error(404, "Nao encontrado")
            if self.headers.get("X-Requested-With") != "internet-radar":
                return self._error(403, "Requisicao nao autorizada")
            try:
                if self.path == "/api/alerts/simulate":
                    item = json.loads((ROOT / "simulated_outage.json").read_text(encoding="utf-8"))
                    if not isinstance(item, dict) or item.get("eventType") != "OUTAGE" or item.get("id") != "SIMULATED-OUTAGE":
                        return self._error(400, "Arquivo de simulacao invalido")
                    item["id"] += "-" + uuid.uuid4().hex
                    item["startDate"] = stamp(utc_now())
                with closing(sqlite3.connect(db_path, timeout=10)) as conn:
                    conn.row_factory = sqlite3.Row
                    if self.path == "/api/alerts/simulate":
                        initialized = conn.execute("SELECT initialized FROM alert_state WHERE id=1").fetchone()[0]
                        if not initialized:
                            return self._error(409, "Aguarde a primeira coleta")
                        new_ids = record_outage_alerts(conn, [item], simulation=True)
                        payload = {"id": item["id"], "alerts": alert_counts(conn)}
                    else:
                        source = "os" if self.path == "/api/alerts/os/acknowledge" else "outage"
                        through = self.headers.get("X-Alert-Through")
                        acknowledged = acknowledge_alerts(conn, source,
                            int(through) if through is not None else None)
                        payload = {"acknowledged": acknowledged}
                if self.path == "/api/alerts/simulate":
                    if sound is not None:
                        sound.notify(new_ids)
                    logging.info("Outage de teste disparado: %s", item["id"])
                else:
                    logging.info("Avisos de %s reconhecidos: %s", source, acknowledged)
                body = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
            except (OSError, sqlite3.Error, ValueError, TypeError):
                logging.exception("Falha na operacao de alertas")
                self._error(503, "Falha na operacao de alertas")

        def do_GET(self):
            parsed = urllib.parse.urlsplit(self.path)
            try:
                if parsed.path == "/":
                    body = (ROOT / "dashboard.html").read_bytes()
                    content_type = "text/html; charset=utf-8"
                elif parsed.path == "/target-mode/target-mode.js":
                    body = (ROOT / "target-mode" / "target-mode.js").read_bytes()
                    content_type = "text/javascript; charset=utf-8"
                elif parsed.path == "/target-mode/target-mode.css":
                    body = (ROOT / "target-mode" / "target-mode.css").read_bytes()
                    content_type = "text/css; charset=utf-8"
                elif parsed.path in ("/api/status", "/api/timeline", "/api/runs"):
                    with closing(sqlite3.connect(db_path, timeout=5)) as conn:
                        conn.row_factory = sqlite3.Row
                        conn.execute("PRAGMA query_only=ON")
                        conn.execute("BEGIN")  # Counts and items must share the same read snapshot.
                        if parsed.path == "/api/status":
                            payload = dashboard_status(conn, interval, tz_name)
                        elif parsed.path == "/api/runs":
                            payload = dashboard_runs(conn)
                        else:
                            query = urllib.parse.parse_qs(parsed.query)
                            try:
                                days = int(query.get("days", ["30"])[0])
                            except ValueError:
                                return self._error(400, "Periodo invalido")
                            if days not in (1, 7, 30, 90):
                                return self._error(400, "Periodo invalido")
                            payload = dashboard_timeline(conn, days, tz_name)
                    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                    content_type = "application/json; charset=utf-8"
                else:
                    return self._error(404, "Nao encontrado")
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy", "default-src 'none'; "
                                 "script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                                 "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
                self.end_headers()
                self.wfile.write(body)
            except (OSError, sqlite3.Error, ValueError, ZoneInfoNotFoundError):
                logging.exception("Falha ao responder dashboard")
                self._error(503, "Dashboard indisponivel")

        def _error(self, status: int, message: str):
            body = json.dumps({"error": message}).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            pass

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(description="Termometro experimental do Cloudflare Radar")
    parser.add_argument("--once", action="store_true", help="Executa um ciclo e encerra")
    parser.add_argument("--no-audio", action="store_true",
                        help="Executa monitoramento e dashboard sem tocar audio nesta sessao")
    parser.add_argument("--diagnose", action="store_true",
                        help="Exibe diagnostico das capacidades observadas neste ciclo")
    parser.add_argument("--interval", type=int, default=config_int("RADAR_INTERVAL_SECONDS", 900, 60, 86400))
    parser.add_argument("--timeout", type=int, default=config_int("RADAR_REQUEST_TIMEOUT_SECONDS", 30, 5, 120))
    parser.add_argument("--request-budget", type=int, default=config_int("RADAR_REQUEST_BUDGET", 48, 3, 200))
    parser.add_argument("--max-regions", type=int, default=config_int("RADAR_MAX_REGIONS_PER_CYCLE", 2, 0, 20))
    parser.add_argument("--display-timezone", default=config_value("RADAR_DISPLAY_TIMEZONE", "America/Sao_Paulo"))
    parser.add_argument("--dashboard-port", type=int,
                        default=config_int("RADAR_DASHBOARD_PORT", 8765, 1, 65535))
    args = parser.parse_args()
    token = config_value("CLOUDFLARE_API_TOKEN") or config_value("CLOUDFLARE_RADAR_API_TOKEN")
    if not token:
        print("Token ausente: configure CLOUDFLARE_API_TOKEN ou CLOUDFLARE_RADAR_API_TOKEN", file=sys.stderr)
        return 2
    log_path = path_setting("RADAR_LOG_PATH", ROOT / "logs" / "radar.log")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(handlers=[RotatingFileHandler(log_path, maxBytes=2_000_000,
                                                       backupCount=3, encoding="utf-8")],
                        level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    db_path = path_setting("RADAR_DATABASE_PATH", ROOT / "data" / "radar.sqlite3")
    conn = connect(db_path)
    signal.signal(signal.SIGINT, stop_signal)
    signal.signal(signal.SIGTERM, stop_signal)
    server = None
    sound = None
    if not args.once:
        if not args.no_audio:
            sound = AlertSound(db_path)
            sound.start()
        try:
            server = ThreadingHTTPServer(
                ("127.0.0.1", args.dashboard_port),
                dashboard_handler(db_path, args.interval, args.display_timezone, sound),
            )
            threading.Thread(target=server.serve_forever, daemon=True).start()
            print(f"Dashboard: http://127.0.0.1:{args.dashboard_port}", flush=True)
            logging.info("Dashboard iniciado em 127.0.0.1:%s", args.dashboard_port)
        except OSError as exc:
            logging.warning("Dashboard indisponivel: %s", exc)
            print(f"Dashboard indisponivel: {exc}", file=sys.stderr)
    try:
        while not STOP:
            cycle_started = time.time()
            successful = run_cycle(conn, token, args, sound)
            if args.once:
                return 0 if successful else 1
            if time.time() - cycle_started > args.interval:
                logging.warning("Ciclo excedeu o intervalo configurado")
            now = time.time()
            next_start = (math.floor(now / args.interval) + 1) * args.interval
            while not STOP and time.time() < next_start:
                time.sleep(min(1, next_start - time.time()))
    finally:
        if sound is not None:
            sound.stop()
        if server is not None:
            server.shutdown()
            server.server_close()
        conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
