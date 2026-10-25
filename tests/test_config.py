import os
import subprocess
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]


def clean_environment():
    return {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("PHISHGUARD_")
    }


def test_default_configuration_is_loopback_and_non_debug():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import config; print(config.HOST, config.DEBUG, len(config.SECRET_KEY))",
        ],
        cwd=PROJECT_DIR,
        env=clean_environment(),
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip().split() == ["127.0.0.1", "False", "64"]


def test_external_bind_requires_strong_key_and_secure_cookie():
    env = clean_environment()
    env["PHISHGUARD_HOST"] = "0.0.0.0"
    missing_key = subprocess.run(
        [sys.executable, "-c", "import config"],
        cwd=PROJECT_DIR,
        env=env,
        capture_output=True,
        text=True,
    )
    assert missing_key.returncode != 0
    assert "PHISHGUARD_SECRET_KEY" in missing_key.stderr

    env["PHISHGUARD_SECRET_KEY"] = "a" * 48
    env.pop("PHISHGUARD_COOKIE_SECURE", None)
    secure_default = subprocess.run(
        [
            sys.executable,
            "-c",
            "import config; print(config.SESSION_COOKIE_SECURE)",
        ],
        cwd=PROJECT_DIR,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert secure_default.stdout.strip() == "True"
