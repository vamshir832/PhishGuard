# 🛡️ PhishGuard — Phishing URL Detection System

**An educational cybersecurity project that analyzes URL structure to identify potentially suspicious and phishing URLs.**

PhishGuard is a Python and Flask web application that uses machine learning and URL-based security features to classify submitted URLs as **Likely Legitimate** or **Potential Phishing**. It provides an explanation of suspicious patterns and maintains a local history of analyses.

> ⚠️ **Security notice:** A prediction is an estimate, not a guarantee. PhishGuard is an educational project and should not be used as the sole basis for security decisions.


## ✨ Features

- **URL Analysis:** Analyze submitted HTTP and HTTPS URLs without visiting the destination.
- **Machine Learning:** Uses a trained Scikit-learn classifier to estimate phishing risk.
- **Suspicious Pattern Detection:** Examines IP-based hostnames, URL shorteners, suspicious keywords, unusual ports, encoding patterns, and hostname structure.
- **Explainable Results:** Provides reasons that may indicate suspicious URL characteristics.
- **Risk Indicators:** Displays a heuristic risk score separately from the model's phishing probability.
- **Analysis History:** Stores local analysis records using SQLite.
- **Responsive Interface:** Flask templates, HTML, CSS, and JavaScript provide the web interface.
- **Privacy-Focused Design:** Removes query strings and URL fragments from stored history.
- **Automated Tests:** Includes Pytest tests and a GitHub Actions workflow.
- **Windows Launcher:** Includes a batch file for convenient local setup and startup.

## 🧰 Technology Stack

| Technology | Purpose |
|---|---|
| Python | Application and machine-learning logic |
| Flask | Web application |
| Scikit-learn | URL classification models |
| Pandas | Dataset preparation |
| Joblib | Model artifact storage |
| SQLite | Local analysis history |
| HTML, CSS, JavaScript | User interface |
| Pytest | Automated testing |
| Git and GitHub Actions | Version control and continuous integration |

## 🏗️ Project Architecture

```text
PhishGuard/
├── app.py                    # Flask application
├── start.py                  # Setup and launch helper
├── Start PhishGuard.bat      # Windows launcher
├── config.py                 # Configuration
├── database.py               # SQLite history
├── detector.py               # Prediction and explanations
├── feature_extraction.py     # URL feature extraction
├── train_model.py            # Model training and evaluation
├── requirements.txt          # Python dependencies
├── data/
│   ├── README.md
│   └── synthetic_urls.csv
├── models/
│   └── README.md
├── templates/                # HTML pages
├── static/
│   ├── css/
│   └── js/
├── tests/                    # Automated tests
├── .github/workflows/        # GitHub Actions
├── .env.example
└── README.md
```

## ⚙️ Installation and Setup

### Requirements

- Windows 10/11, macOS, or Linux
- Python 3.11 or later
- Git (optional if downloading the ZIP)
- Internet access for installing dependencies on first setup

### Option 1: Quick Start on Windows

1. Clone the repository:

   ```powershell
   git clone https://github.com/vamshir832/PhishGuard.git
   cd PhishGuard
   ```

2. Run the launcher:

   ```powershell
   python start.py
   ```

   Alternatively, double-click `Start PhishGuard.bat`.

3. The launcher creates a virtual environment, installs dependencies, prepares the model if required, and starts the application.

4. Open the local address in your browser:

   **http://127.0.0.1:5000**

Keep the launcher terminal open while using the application.

### Option 2: Manual Setup

Open a terminal in the project directory and run:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python train_model.py
python app.py
```

Then visit http://127.0.0.1:5000.

If PowerShell blocks activation, run this in the current terminal and retry:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

## 🧠 How It Works

1. **Input:** The user submits a URL through the web interface.
2. **Validation:** PhishGuard validates and normalizes the URL.
3. **Feature Extraction:** The application examines URL structure and suspicious indicators.
4. **Prediction:** The trained machine-learning model estimates the URL's class.
5. **Explanation:** The result page displays the prediction and relevant suspicious patterns.
6. **History:** The analysis is stored locally in SQLite with query strings and fragments removed.

PhishGuard does not fetch the submitted webpage, follow redirects, or execute the link.

## 🤖 Model Training and Dataset

PhishGuard compares Random Forest and Gradient Boosting classifiers using a grouped training, validation, and test workflow.

The training pipeline:

- Validates and cleans labeled URL records.
- Removes duplicate normalized URLs where appropriate.
- Groups related URLs by approximate registrable domain before splitting.
- Selects a model using validation F1 score, with recall and accuracy as tie-breakers.
- Evaluates the selected model on held-out test groups.

### Dataset format

A labeled CSV file must contain:

| Column | Description |
|---|---|
| `url` | URL or hostname to analyze |
| `label` | Legitimate (`0`) or phishing (`1`), including supported label names |

To train using your own dataset:

```powershell
python train_model.py --dataset "C:\path\to\labeled_urls.csv"
```

The included `data/synthetic_urls.csv` is a small, hand-authored demonstration dataset. **Its results must not be presented as real-world model accuracy.** Use a reputable, documented, properly licensed dataset for meaningful evaluation.

## 🧪 Run Tests

Activate your virtual environment and run:

```powershell
python -m pytest -q
```

The repository includes tests for configuration, database behavior, URL detection, feature extraction, web routes, and model training.

GitHub Actions is configured to run automated checks on supported Python versions.

## 🔐 Privacy and Security

- Submitted URLs are analyzed from their text rather than by visiting their destinations.
- Query strings and fragments are removed from stored history.
- SQLite history remains local to the running installation.
- The application includes CSRF checks, request-size limits, and other web security controls.

**Important:** Machine-learning systems can produce false positives and false negatives. A URL classified as legitimate may still be malicious, and a flagged URL may be legitimate. Do not enter sensitive information into an unfamiliar website based solely on this tool's result.

## 🚀 Future Improvements

- Evaluate performance using reputable real-world phishing datasets.
- Improve domain grouping and model calibration.
- Add additional model evaluation visualizations.
- Expand automated security testing.
- Explore deployment with a production-ready web server and secure hosting configuration.

## 👨‍💻 Project Information

**Project:** PhishGuard — Phishing URL Detection System  
**Domain:** Cybersecurity and Machine Learning  
**Purpose:** Educational and research demonstration

## 📄 License

Choose and add an appropriate open-source license before claiming that this project is licensed for reuse. Until then, check the repository's licensing terms before redistributing or modifying the project.
