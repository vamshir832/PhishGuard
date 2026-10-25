import secrets
import threading
import time
from collections import defaultdict, deque

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.exceptions import HTTPException

from config import (
    DEBUG,
    EXTERNAL_REQUESTS_PER_MINUTE,
    HOST,
    MAX_CONTENT_LENGTH,
    MODEL_PATH,
    PORT,
    SECRET_KEY,
    SESSION_COOKIE_SECURE,
)
from database import add_analysis_result, clear_analysis_history, get_analysis_history, get_dashboard_stats, initialize_database
from detector import ModelArtifactError, ModelNotFoundError, analyze_url, public_health_status

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    DEBUG=DEBUG,
    MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE,
)
_rate_limit_lock = threading.Lock()
_analysis_requests = defaultdict(deque)


def generate_csrf_token():
    session["csrf_token"] = secrets.token_urlsafe(32)


@app.before_request
def ensure_csrf_session():
    if "csrf_token" not in session:
        generate_csrf_token()


@app.before_request
def enforce_csrf_on_post():
    if request.method == "POST":
        token = session.get("csrf_token", "")
        submitted = request.form.get("csrf_token", "")
        if not token or not secrets.compare_digest(token, submitted):
            abort(400)


def _is_local_bind():
    return HOST.lower() == "localhost" or HOST in {"127.0.0.1", "::1"}


def _rate_limit_analysis():
    if _is_local_bind():
        return
    now = time.monotonic()
    key = request.remote_addr or "unknown"
    with _rate_limit_lock:
        request_times = _analysis_requests[key]
        while request_times and now - request_times[0] >= 60:
            request_times.popleft()
        if len(request_times) >= EXTERNAL_REQUESTS_PER_MINUTE:
            abort(429)
        request_times.append(now)


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


@app.errorhandler(HTTPException)
def handle_http_error(error):
    messages = {
        400: "The request could not be accepted. Refresh the page and try again.",
        404: "The requested page was not found.",
        413: "The request is too large. URLs must be no longer than 4,096 characters.",
        429: "Too many analyses were submitted. Wait a minute before trying again.",
    }
    message = messages.get(error.code, "The request could not be completed.")
    return render_template("error.html", code=error.code, message=message), error.code


@app.errorhandler(Exception)
def handle_unexpected_error(error):
    if isinstance(error, HTTPException):
        return error
    app.logger.exception("Unhandled PhishGuard request error")
    return render_template(
        "error.html",
        code=500,
        message="An internal error prevented this request. No internal details are shown here.",
    ), 500


@app.route("/")
def index():
    return render_template(
        "index.html",
        model_status=public_health_status(MODEL_PATH),
        sample_urls=[
            "https://www.google.com",
            "https://www.paypal.com/signin",
            "https://accounts-secure-login-update-example.com",
            "http://185.234.72.5/login.php",
        ],
    )


@app.route("/analyze", methods=["POST"])
def analyze():
    _rate_limit_analysis()
    submitted_url = request.form.get("url", "").strip()
    if not submitted_url:
        flash("Please enter a valid URL before analyzing.")
        return redirect(url_for("index"))

    try:
        result = analyze_url(submitted_url, model_path=MODEL_PATH)
    except ValueError as exc:
        flash(str(exc))
        return redirect(url_for("index"))
    except ModelNotFoundError:
        flash("No trained model is available yet. Run 'python train_model.py' to train the phishing detector.")
        return redirect(url_for("index"))
    except ModelArtifactError:
        flash("The saved model files are incompatible or unreadable. Retrain the model before analyzing URLs.")
        return redirect(url_for("index"))

    add_analysis_result(
        url=result["url"],
        predicted_label=result["label"],
        confidence=result["confidence"],
        phishing_probability=result["model_probability"],
        risk_score=result["risk_score"],
        explanation=result["explanation"],
    )
    return render_template("result.html", result=result, recent_history=get_analysis_history(5))


@app.route("/history")
def history():
    history_rows = get_analysis_history(20)
    stats = get_dashboard_stats()
    return render_template("history.html", history=history_rows, stats=stats)


@app.route("/clear-history", methods=["POST"])
def clear_history():
    clear_analysis_history()
    flash("Analysis history was cleared.")
    return redirect(url_for("history"))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/how-it-works")
def how_it_works():
    return render_template("how_it_works.html")


@app.route("/api/health")
def health():
    status = public_health_status(MODEL_PATH)
    response_code = 200 if status["model_loaded"] else 503
    return jsonify(
        {
            "status": "ok" if status["model_loaded"] else "warning",
            "model_loaded": status["model_loaded"],
            "message": status.get("message", "Application ready"),
        }
    ), response_code


if __name__ == "__main__":
    initialize_database()
    app.run(host=HOST, port=PORT, debug=False)
