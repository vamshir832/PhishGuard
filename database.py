import sqlite3
from urllib.parse import urlsplit, urlunsplit

from config import DB_PATH, HISTORY_RETENTION_DAYS


def connect_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = connect_db()
    try:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                predicted_label TEXT NOT NULL,
                confidence REAL,
                phishing_probability REAL,
                risk_score INTEGER NOT NULL,
                risk_score_version INTEGER NOT NULL DEFAULT 2,
                explanation TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(analysis_history)").fetchall()
        }
        if "phishing_probability" not in columns:
            connection.execute("ALTER TABLE analysis_history ADD COLUMN phishing_probability REAL")
            for row in connection.execute("SELECT id, url FROM analysis_history").fetchall():
                connection.execute(
                    "UPDATE analysis_history SET url = ? WHERE id = ?",
                    (_remove_query_and_fragment(row["url"]), row["id"]),
                )
        if "risk_score_version" not in columns:
            connection.execute(
                "ALTER TABLE analysis_history ADD COLUMN risk_score_version INTEGER NOT NULL DEFAULT 1"
            )
        connection.execute(
            "DELETE FROM analysis_history WHERE created_at < datetime('now', ?)",
            (f"-{HISTORY_RETENTION_DAYS} days",),
        )
        connection.commit()
    finally:
        connection.close()


def ensure_database_ready():
    initialize_database()


def _remove_query_and_fragment(url):
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        if hostname is None:
            netloc = ""
        else:
            netloc = f"[{hostname}]" if ":" in hostname else hostname
            if parsed.port is not None:
                netloc = f"{netloc}:{parsed.port}"
        return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
    except (TypeError, ValueError):
        return ""


def add_analysis_result(
    url: str,
    predicted_label: str,
    confidence: float | None,
    risk_score: int,
    explanation: str,
    phishing_probability: float | None = None,
):
    ensure_database_ready()
    connection = connect_db()
    try:
        connection.execute(
            "INSERT INTO analysis_history (url, predicted_label, confidence, phishing_probability, risk_score, risk_score_version, explanation) VALUES (?, ?, ?, ?, ?, 2, ?)",
            (
                _remove_query_and_fragment(url),
                predicted_label,
                float(confidence) if confidence is not None else None,
                float(phishing_probability) if phishing_probability is not None else None,
                int(risk_score),
                explanation,
            ),
        )
        connection.commit()
    finally:
        connection.close()


def get_analysis_history(limit: int = 20):
    ensure_database_ready()
    connection = connect_db()
    try:
        rows = connection.execute(
            "SELECT id, url, predicted_label, confidence, phishing_probability, risk_score, risk_score_version, explanation, created_at FROM analysis_history ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def clear_analysis_history():
    ensure_database_ready()
    connection = connect_db()
    try:
        connection.execute("DELETE FROM analysis_history")
        connection.commit()
    finally:
        connection.close()


def get_dashboard_stats():
    ensure_database_ready()
    connection = connect_db()
    try:
        summary = connection.execute(
            """
            SELECT
                COUNT(*) AS total_urls,
                SUM(CASE WHEN predicted_label = 'Potential Phishing' THEN 1 ELSE 0 END) AS phishing_count,
                SUM(CASE WHEN predicted_label = 'Likely Legitimate' THEN 1 ELSE 0 END) AS legitimate_count
            FROM analysis_history
            """
        ).fetchone()
        return {
            "total_urls": summary["total_urls"] or 0,
            "phishing_count": summary["phishing_count"] or 0,
            "legitimate_count": summary["legitimate_count"] or 0,
        }
    finally:
        connection.close()
