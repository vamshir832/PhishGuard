import joblib
import numpy as np
import pytest

from detector import (
    ModelArtifactError,
    _heuristic_risk_score,
    analyze_url,
    load_model,
    public_health_status,
)
from feature_extraction import FEATURE_ORDER


class FixedProbabilityModel:
    def __init__(self, prediction, class_probabilities):
        self.classes_ = np.array([1, 0])
        self.n_features_in_ = len(FEATURE_ORDER)
        self.prediction = prediction
        self.class_probabilities = class_probabilities

    def predict(self, features):
        return np.array([self.prediction])

    def predict_proba(self, features):
        return np.array([self.class_probabilities])


class PredictionOnlyModel:
    classes_ = np.array([0, 1])
    n_features_in_ = len(FEATURE_ORDER)

    def predict(self, features):
        return np.array([0])


def save_bundle(tmp_path, model, schema=FEATURE_ORDER, bundle_schema=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    model_path = tmp_path / "model.joblib"
    schema_path = tmp_path / "schema.joblib"
    bundle = {
        "artifact_format_version": 2,
        "selected_model": "test_model",
        "model": model,
        "models": {"test_model": model},
        "feature_order": list(schema if bundle_schema is None else bundle_schema),
        "metrics": {},
    }
    joblib.dump(bundle, model_path)
    joblib.dump(list(schema), schema_path)
    return model_path, schema_path


def test_missing_model_reports_warning(tmp_path):
    status = public_health_status(tmp_path / "missing.joblib", tmp_path / "missing-schema.joblib")
    assert status["status"] == "warning"
    assert status["model_loaded"] is False


def test_legitimate_prediction_probability_and_risk_are_distinct(tmp_path):
    model = FixedProbabilityModel(prediction=0, class_probabilities=[0.12, 0.88])
    model_path, schema_path = save_bundle(tmp_path, model)

    result = analyze_url("https://example.com", model_path=model_path, schema_path=schema_path)

    assert result["label"] == "Likely Legitimate"
    assert result["confidence"] == pytest.approx(0.88)
    assert result["model_probability"] == pytest.approx(0.12)
    assert result["risk_score"] == _heuristic_risk_score(result["features"])
    assert result["risk_label"] == "Heuristic risk score (not model probability)"


def test_phishing_prediction_probability_uses_class_label_one(tmp_path):
    model = FixedProbabilityModel(prediction=1, class_probabilities=[0.91, 0.09])
    model_path, schema_path = save_bundle(tmp_path, model)

    result = analyze_url("http://185.234.72.5/login.php", model_path=model_path, schema_path=schema_path)

    assert result["label"] == "Potential Phishing"
    assert result["confidence"] == pytest.approx(0.91)
    assert result["model_probability"] == pytest.approx(0.91)
    assert result["risk_score"] == _heuristic_risk_score(result["features"])


def test_model_without_probability_support_reports_probability_as_unavailable(tmp_path):
    model_path, schema_path = save_bundle(tmp_path, PredictionOnlyModel())

    result = analyze_url("https://example.com", model_path=model_path, schema_path=schema_path)

    assert result["confidence"] is None
    assert result["model_probability"] is None


def test_invalid_model_probabilities_are_rejected(tmp_path):
    model = FixedProbabilityModel(prediction=0, class_probabilities=[2.0, -1.0])
    model_path, schema_path = save_bundle(tmp_path, model)

    with pytest.raises(ModelArtifactError, match="invalid class probabilities"):
        analyze_url("https://example.com", model_path=model_path, schema_path=schema_path)


def test_heuristic_risk_does_not_change_with_model_probability(tmp_path):
    first_model = FixedProbabilityModel(prediction=0, class_probabilities=[0.1, 0.9])
    first_model_path, first_schema_path = save_bundle(tmp_path / "first", first_model)
    second_model = FixedProbabilityModel(prediction=0, class_probabilities=[0.9, 0.1])
    second_model_path, second_schema_path = save_bundle(tmp_path / "second", second_model)
    url = "https://example.com"

    lower_probability = analyze_url(url, first_model_path, first_schema_path)
    higher_probability = analyze_url(url, second_model_path, second_schema_path)

    assert lower_probability["model_probability"] == pytest.approx(0.1)
    assert higher_probability["model_probability"] == pytest.approx(0.9)
    assert lower_probability["risk_score"] == higher_probability["risk_score"]


def test_schema_mismatch_is_rejected(tmp_path):
    invalid_schema = FEATURE_ORDER[:-1]
    model = FixedProbabilityModel(prediction=0, class_probabilities=[0.1, 0.9])
    model_path, schema_path = save_bundle(tmp_path, model, schema=invalid_schema)

    with pytest.raises(ModelArtifactError, match="feature schema"):
        load_model(model_path, schema_path)


def test_corrupt_artifact_is_reported_clearly(tmp_path):
    model_path = tmp_path / "broken.joblib"
    schema_path = tmp_path / "schema.joblib"
    model_path.write_text("not a joblib artifact", encoding="utf-8")
    joblib.dump(FEATURE_ORDER, schema_path)

    with pytest.raises(ModelArtifactError, match="unreadable or corrupted"):
        load_model(model_path, schema_path)
