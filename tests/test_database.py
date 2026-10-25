import sqlite3

import database


def test_database_initialization_and_history_privacy(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "history.db")
    database.initialize_database()
    database.add_analysis_result(
        "https://example.com/login?token=secret#fragment",
        "Potential Phishing",
        0.9,
        42,
        "Test explanation",
        phishing_probability=0.9,
    )

    rows = database.get_analysis_history()
    assert len(rows) == 1
    assert rows[0]["url"] == "https://example.com/login"
    assert rows[0]["phishing_probability"] == 0.9
    assert "secret" not in rows[0]["url"]
    assert database.get_dashboard_stats()["total_urls"] == 1


def test_database_migration_preserves_rows_and_scrubs_existing_query(tmp_path, monkeypatch):
    db_path = tmp_path / "legacy.db"
    monkeypatch.setattr(database, "DB_PATH", db_path)
    connection = sqlite3.connect(db_path)
    connection.execute(
        """
        CREATE TABLE analysis_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            predicted_label TEXT NOT NULL,
            confidence REAL NOT NULL,
            risk_score INTEGER NOT NULL,
            explanation TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    connection.execute(
        "INSERT INTO analysis_history (url, predicted_label, confidence, risk_score, explanation) VALUES (?, ?, ?, ?, ?)",
        ("https://example.com/path?password=secret", "Likely Legitimate", 0.8, 5, "legacy"),
    )
    connection.commit()
    connection.close()

    database.initialize_database()

    rows = database.get_analysis_history()
    assert len(rows) == 1
    assert rows[0]["url"] == "https://example.com/path"
    assert rows[0]["phishing_probability"] is None
    assert rows[0]["risk_score_version"] == 1


def test_clear_history_removes_records(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "history.db")
    database.add_analysis_result("https://example.com", "Likely Legitimate", 0.8, 1, "ordinary")
    database.clear_analysis_history()
    assert database.get_analysis_history() == []


def test_configured_history_retention_removes_only_expired_rows(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "history.db")
    monkeypatch.setattr(database, "HISTORY_RETENTION_DAYS", 30)
    database.add_analysis_result("https://recent.example", "Likely Legitimate", 0.8, 1, "recent")
    connection = database.connect_db()
    try:
        connection.execute(
            "UPDATE analysis_history SET created_at = datetime('now', '-31 days') WHERE url = ?",
            ("https://recent.example",),
        )
        connection.execute(
            "INSERT INTO analysis_history (url, predicted_label, confidence, risk_score, explanation, created_at) "
            "VALUES (?, ?, ?, ?, ?, datetime('now', '-5 days'))",
            ("https://within-retention.example", "Likely Legitimate", 0.8, 1, "within retention"),
        )
        connection.commit()
    finally:
        connection.close()

    rows = database.get_analysis_history()
    assert len(rows) == 1
    assert rows[0]["url"] == "https://within-retention.example"
