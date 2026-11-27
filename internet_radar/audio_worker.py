"""Play pending Radar alerts in the logged-in Windows user's audio session."""

from __future__ import annotations

from contextlib import closing
import logging
from logging.handlers import RotatingFileHandler
import signal
import sqlite3
import threading

from radar import AlertSound, ROOT, path_setting, pending_notifications


STOP = threading.Event()


def stop_signal(_signal, _frame):
    STOP.set()


def main() -> int:
    log_path = path_setting("RADAR_LOG_PATH", ROOT / "logs" / "radar.log")
    audio_log_path = log_path.with_name("radar-audio.log")
    audio_log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        handlers=[RotatingFileHandler(audio_log_path, maxBytes=1_000_000,
                                     backupCount=2, encoding="utf-8")],
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    signal.signal(signal.SIGINT, stop_signal)
    signal.signal(signal.SIGTERM, stop_signal)
    db_path = path_setting("RADAR_DATABASE_PATH", ROOT / "data" / "radar.sqlite3")

    while not STOP.is_set():
        try:
            conn = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True, timeout=10)
            break
        except sqlite3.Error:
            logging.warning("Aguardando banco de dados do monitor")
            STOP.wait(15)
    else:
        return 0

    with closing(conn):
        conn.row_factory = sqlite3.Row
        sound = AlertSound(db_path)
        sound.start()
        known_ids: set[int] = set()
        logging.info("Audio do Internet Radar iniciado na sessao do usuario")
        try:
            while not STOP.is_set():
                if not sound.thread.is_alive():
                    logging.error("Thread de audio encerrada inesperadamente")
                    return 1
                try:
                    pending_ids = {row["notification_id"] for row in pending_notifications(conn)}
                    sound.notify(sorted(pending_ids - known_ids))
                    known_ids = pending_ids
                except sqlite3.Error:
                    logging.exception("Falha ao consultar alertas pendentes")
                STOP.wait(5)
        finally:
            sound.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
