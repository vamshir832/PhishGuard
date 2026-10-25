import pytest
from flask import Flask
from pathlib import Path

import database
import app as app_module
from app import app, handle_unexpected_error
from config import SYNTHETIC_DATASET_PATH
from train_model import train_models


@pytest.fixture(scope="module", autouse=True)
def trained_model():
    train_models(SYNTHETIC_DATASET_PATH)


@pytest.fixture(autouse=True)
def isolated_database(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test-history.db")
    database.initialize_database()


def test_home_page_and_csrf_form_token():
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert b"PhishGuard" in response.data
    with client.session_transaction() as browser_session:
        token = browser_session["csrf_token"]
    assert token.encode() in response.data


def test_health_endpoint_reports_model_ready():
    response = app.test_client().get("/api/health")
    assert response.status_code == 200
    assert response.get_json()["model_loaded"] is True


@pytest.mark.parametrize("path", ["/history", "/about", "/how-it-works", "/privacy"])
def test_application_pages_load(path):
    response = app.test_client().get(path)
    assert response.status_code == 200


def test_analysis_requires_valid_csrf_and_persists_scrubbed_url():
    client = app.test_client()
    with client.session_transaction() as browser_session:
        browser_session["csrf_token"] = "valid-token"

    rejected = client.post("/analyze", data={"url": "https://example.com?token=secret"})
    assert rejected.status_code == 400

    response = client.post(
        "/analyze",
        data={"url": "https://example.com/path?token=secret", "csrf_token": "valid-token"},
    )
    assert response.status_code == 200
    assert b"Model phishing probability" in response.data
    history = database.get_analysis_history()
    assert history[0]["url"] == "https://example.com/path"
    assert history[0]["phishing_probability"] is not None


def test_clear_history_requires_valid_csrf():
    client = app.test_client()
    with client.session_transaction() as browser_session:
        browser_session["csrf_token"] = "another-token"
    assert client.post("/clear-history").status_code == 400
    response = client.post("/clear-history", data={"csrf_token": "another-token"})
    assert response.status_code == 302
    assert database.get_analysis_history() == []


def test_analysis_rate_limit_applies_when_bound_externally(monkeypatch):
    monkeypatch.setattr(app_module, "HOST", "0.0.0.0")
    monkeypatch.setattr(app_module, "EXTERNAL_REQUESTS_PER_MINUTE", 1)
    app_module._analysis_requests.clear()
    client = app.test_client()
    with client.session_transaction() as browser_session:
        browser_session["csrf_token"] = "rate-limit-token"
    form_data = {"url": "https://example.com", "csrf_token": "rate-limit-token"}

    assert client.post("/analyze", data=form_data).status_code == 200
    assert client.post("/analyze", data=form_data).status_code == 429


def test_request_body_limit_returns_safe_response():
    client = app.test_client()
    with client.session_transaction() as browser_session:
        browser_session["csrf_token"] = "large-request-token"
    response = client.post(
        "/analyze",
        data={"url": "x" * 5000, "csrf_token": "large-request-token"},
    )
    assert response.status_code == 413
    assert b"4,096 characters" in response.data


def test_unexpected_error_does_not_expose_details():
    error_test_app = Flask(
        "error-handler-test",
        template_folder=str(Path(__file__).resolve().parents[1] / "templates"),
    )
    error_test_app.errorhandler(Exception)(handle_unexpected_error)

    @error_test_app.route("/test-internal-error")
    def test_internal_error():
        raise RuntimeError("secret filesystem path")

    response = error_test_app.test_client().get("/test-internal-error")
    assert response.status_code == 500
    assert b"secret filesystem path" not in response.data
    assert b"internal error" in response.data.lower()
