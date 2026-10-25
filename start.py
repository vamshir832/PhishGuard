"""One-click Windows launcher for the local PhishGuard application."""

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent
VENV_DIR = PROJECT_DIR / ".venv"
APP_URL = "http://127.0.0.1:5000"
REQUIRED_MODULES = ("flask", "pandas", "numpy", "sklearn", "joblib", "dotenv")


def venv_python():
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def run_setup_command(command, description):
    print(f"\n{description}...")
    try:
        subprocess.run(command, cwd=PROJECT_DIR, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"\nSetup failed while {description.lower()}: {exc}")
        input("Press Enter to close this window...")
        raise SystemExit(1) from exc


def install_dependencies_if_needed(python_executable):
    check_script = (
        "import importlib.util, sys; "
        "sys.exit(0 if all(importlib.util.find_spec(name) for name in "
        f"{REQUIRED_MODULES!r}) else 1)"
    )
    check = subprocess.run(
        [str(python_executable), "-c", check_script],
        cwd=PROJECT_DIR,
        check=False,
    )
    if check.returncode != 0:
        run_setup_command(
            [str(python_executable), "-m", "pip", "install", "-r", "requirements.txt"],
            "Installing required packages (first run may take a few minutes)",
        )


def model_is_available(python_executable):
    check_script = (
        "from detector import load_model; "
        "load_model(); "
        "from config import FEATURE_SCHEMA_PATH; "
        "raise SystemExit(0 if FEATURE_SCHEMA_PATH.is_file() else 1)"
    )
    check = subprocess.run(
        [str(python_executable), "-c", check_script],
        cwd=PROJECT_DIR,
        check=False,
        capture_output=True,
        text=True,
    )
    if check.returncode != 0:
        print("The saved model is missing or invalid; it will be retrained.")
    return check.returncode == 0


def open_browser():
    if not webbrowser.open(APP_URL):
        print(f"Could not open a browser automatically. Visit {APP_URL}")


def prepare_model(python_executable):
    if not model_is_available(python_executable):
        run_setup_command(
            [str(python_executable), "train_model.py"],
            "Training the model using the included test dataset",
        )


def get_health_status():
    try:
        with urllib.request.urlopen(f"{APP_URL}/api/health", timeout=1.5) as response:
            payload = json.loads(response.read().decode("utf-8"))
            if response.status == 200 and payload.get("model_loaded"):
                return True
    except (OSError, urllib.error.URLError, json.JSONDecodeError):
        return False
    return False


def main():
    os.chdir(PROJECT_DIR)
    print("PhishGuard launcher")
    print(f"Project folder: {PROJECT_DIR}")

    if not VENV_DIR.exists():
        run_setup_command(
            [sys.executable, "-m", "venv", str(VENV_DIR)],
            "Creating the project virtual environment",
        )

    python_executable = venv_python()
    if not python_executable.is_file():
        print(f"Could not find the virtual environment Python at: {python_executable}")
        input("Press Enter to close this window...")
        raise SystemExit(1)

    install_dependencies_if_needed(python_executable)
    prepare_model(python_executable)

    if get_health_status():
        print(f"\nPhishGuard is already running at {APP_URL}")
        open_browser()
        input("Press Enter to close this window...")
        return

    print("\nStarting the local PhishGuard server...")
    try:
        server = subprocess.Popen(
            [str(python_executable), "app.py"],
            cwd=PROJECT_DIR,
        )
    except OSError as exc:
        print(f"Could not start the server: {exc}")
        input("Press Enter to close this window...")
        raise SystemExit(1) from exc

    try:
        for _ in range(60):
            if server.poll() is not None:
                print("\nThe server stopped before it became ready. Check the error shown above.")
                input("Press Enter to close this window...")
                raise SystemExit(server.returncode or 1)
            if get_health_status():
                print(f"\nPhishGuard is ready at {APP_URL}")
                open_browser()
                print("Leave this window open while using PhishGuard. Press Ctrl+C to stop it.")
                server.wait()
                return
            time.sleep(0.5)

        print("\nPhishGuard did not become ready in time. Check whether port 5000 is already in use.")
        server.terminate()
        server.wait(timeout=10)
        input("Press Enter to close this window...")
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("\nStopping PhishGuard...")
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()


if __name__ == "__main__":
    main()
