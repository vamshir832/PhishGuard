# PhishGuard — Phishing URL Detection System

PhishGuard is an educational, local Flask application that extracts URL-only features and uses a trained Scikit-learn model to classify URLs as likely legitimate or potentially phishing. The app never visits submitted destinations. It maintains a local SQLite history with query strings and fragments removed.

> A model result is not proof that a website is safe or malicious. URL-only classifiers can produce false positives and false negatives.

## Project abstract and problem statement

Phishing messages often direct people to URLs crafted to resemble trusted services. PhishGuard explores whether URL structure can help identify suspicious patterns before a person visits a link. Its feature extractor examines the parsed hostname and URL components, and its training pipeline compares Random Forest and Gradient Boosting classifiers.

The project is intended for Computer Networks and Cybersecurity coursework. It demonstrates feature extraction, grouped model evaluation, local storage, web security controls, and user-facing explanations. It is not a production threat-intelligence service.

## Architecture

- `feature_extraction.py`: strict HTTP(S) URL validation, IDN normalization, hostname-aware features, and the canonical feature order.
- `train_model.py`: CSV validation and cleaning, grouped train/validation/test split, model selection, held-out evaluation, and Joblib artifacts.
- `detector.py`: validates model artifacts and schema, predicts the class, calculates phishing probability from class `1` when supported, and separately calculates a feature-only heuristic score.
- `app.py`: Flask pages, CSRF checks, request-size limits, generic error pages, and analysis rate limiting when bound beyond loopback.
- `database.py`: parameterized SQLite history storage, query/fragment scrubbing, migration, and retention.
- `templates/`, `static/`: responsive dashboard and result/history views.
- `start.py` and `Start PhishGuard.bat`: Windows one-click setup and launch.

## Dataset format, provenance, and limitations

Training CSV files must have these columns:

| Column | Content |
|---|---|
| `url` | Full URL, or a hostname that can be normalized to HTTPS |
| `label` | `legitimate`/`0` or `phishing`/`1` (also accepts documented synonyms such as `benign`, `safe`, `malicious`, and `fraud`) |

No external or real-world phishing dataset is bundled or downloaded by this project. `data/synthetic_urls.csv` is a small, hand-authored synthetic demonstration fixture. It is not a benchmark, has no real-world provenance, and must not be used to claim real-world accuracy. If no real dataset is at `data/phishing_urls.csv`, the default training command explicitly warns that it is using the synthetic demonstration fixture.

For research, obtain a labeled URL dataset from a reputable public source under terms that permit your use, record its publisher, version/date, license, and any preprocessing in your project report, and save it as `data/phishing_urls.csv` or pass its path with `--dataset`. Do not commit real datasets or private URL records.

Training rejects unknown labels, conflicting labels for duplicate normalized URLs, and data missing either class. It skips rows with missing fields or malformed URLs, removes duplicate normalized URLs with consistent labels, and requires at least three independent domain groups per class.

## Evaluation procedure

1. Related URLs are grouped by an approximate registrable domain (including common two-level suffix patterns) before splitting; one group cannot appear in multiple partitions.
2. Reproducible grouped splits allocate approximately 60% of records to training, 20% to validation, and 20% to the untouched test partition. The split seed is searched deterministically until all three partitions contain both classes; training stops with an error if that is impossible.
3. Random Forest and Gradient Boosting are trained on the training partition. The model is selected using validation F1, with validation recall and accuracy as tie-breakers.
4. Both selected candidate models are refit on training plus validation data and evaluated on the untouched test groups. Accuracy, precision, recall, F1, and confusion matrices are saved to `models/evaluation_metrics.json`.

The score shown as **Heuristic risk score** is a separately calculated feature-based 0–100 score; it is not a probability and does not incorporate the model output. **P(phishing)** is the model probability for class `1`, if supported by the estimator. Prediction confidence is the probability of the predicted class. Scores generated from the synthetic fixture are for software demonstration only.

Domain grouping is a practical safeguard, not a perfect public-suffix implementation. Dataset duplicates under alternate encodings, URL shorteners, brand variants, or related organizations may still create dependence between records. Report this limitation when discussing model metrics.

## Windows 11 one-click setup

1. Install Python 3.11 or later and open the project folder.
2. Double-click `Start PhishGuard.bat` (or run `python start.py` from PowerShell).
3. On first launch, the launcher creates `.venv`, installs the packages in `requirements.txt`, trains the demonstration model if no valid model artifact exists, starts Flask, and opens `http://127.0.0.1:5000`.
4. Keep the launcher terminal window open while using the app. Press **Ctrl+C** in that window to stop the server.

First launch requires internet access to install Python dependencies. The app itself does not send submitted URLs to a third party.

### Manual setup

Open PowerShell in the project folder:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python train_model.py
python app.py
```

If PowerShell blocks virtual-environment activation, use this temporary policy for the current PowerShell process and retry activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Open `http://127.0.0.1:5000` in a browser. To run the tests:

```powershell
python -m pytest -q
```

## Train with a real dataset

Put the CSV at `data/phishing_urls.csv` and run:

```powershell
.\.venv\Scripts\Activate.ps1
python train_model.py
```

Or specify a dataset path explicitly; this always takes precedence over the default dataset:

```powershell
python train_model.py --dataset "C:\path\to\labeled_urls.csv"
```

The default command chooses `data/phishing_urls.csv` when it exists. Otherwise it prints a demonstration-only warning and uses `data/synthetic_urls.csv`. Explicit paths are never replaced by the synthetic fixture. Training creates ignored model files under `models/`; older or incompatible model artifacts must be retrained.

## Configuration and security

Configuration is read from environment variables; a local `.env` file is supported through `python-dotenv`. Start with `.env.example` and copy it to `.env` if you need custom settings. `.env` is ignored by Git.

| Variable | Default | Purpose |
|---|---|---|
| `PHISHGUARD_SECRET_KEY` | Random per process | Flask session signing; a unique key of at least 32 characters is required for non-loopback binding |
| `PHISHGUARD_HOST` | `127.0.0.1` | Bind address; non-loopback binding requires a configured secret |
| `PHISHGUARD_PORT` | `5000` | Local server port |
| `PHISHGUARD_COOKIE_SECURE` | `0` on localhost, `1` otherwise | Set to `1` when served over HTTPS; non-loopback binding refuses insecure cookies |
| `PHISHGUARD_HISTORY_RETENTION_DAYS` | `90` | Delete older SQLite history rows during database initialization/access |
| `PHISHGUARD_RATE_LIMIT_PER_MINUTE` | `30` | Per-source-IP analysis limit when bound beyond localhost |

CSRF tokens are generated per session and checked on every POST. Session cookies are HTTP-only and SameSite=Lax. Requests are limited to 4,096 bytes, and generic server errors do not disclose stack traces or filesystem details. The basic in-process rate limiter applies only when the configured bind address is not loopback; it is not a substitute for a production reverse proxy or WSGI deployment.

URL analysis parses submitted text only. It does not resolve DNS, fetch pages, follow redirects, or execute links. SQLite history removes query parameters and fragments, which may contain tokens or personal data. History retention is configurable; clearing history removes stored analysis records. Existing history is preserved during schema migration; historical scores produced by the earlier blended formula are explicitly marked as legacy. The database remains local to the machine unless its files are deliberately shared.

## Troubleshooting

- **Missing package:** activate `.venv` and run `python -m pip install -r requirements.txt`.
- **No model / invalid model:** run `python train_model.py`; the saved schema and model must be generated together.
- **Dataset missing:** place a CSV with `url` and `label` columns at `data/phishing_urls.csv`, or use the explicitly labeled synthetic demonstration data.
- **Both classes/groups required:** include legitimate and phishing labels across at least three distinct registrable-domain groups per class.
- **Port already in use:** set `PHISHGUARD_PORT` to an available local port before launching.
- **Binding beyond localhost:** set `PHISHGUARD_SECRET_KEY` before configuring `PHISHGUARD_HOST` to a non-loopback address. Do not use Flask's development server as a production deployment.

## Continuous integration

GitHub Actions runs Pytest, `pip check`, and `pip-audit` on Windows with Python 3.11, 3.12, and 3.13 for pushes and pull requests.

## Future enhancements

- Benchmark on a reputable, properly licensed, documented public dataset.
- Add a verified public-suffix dataset for more accurate registrable-domain grouping.
- Add model calibration and monitor drift using a held-out, representative dataset.
- Add analyst review and privacy-preserving aggregate reporting.
