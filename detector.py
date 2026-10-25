from pathlib import Path

import joblib
import numpy as np

from config import FEATURE_SCHEMA_PATH, MODEL_PATH
from feature_extraction import FEATURE_ORDER, extract_url_features, feature_vector_from_dict, validate_url


class ModelNotFoundError(FileNotFoundError):
    pass


class ModelArtifactError(ValueError):
    pass


def _read_model_bundle(model_path=MODEL_PATH, schema_path=FEATURE_SCHEMA_PATH):
    model_path = Path(model_path)
    schema_path = Path(schema_path)
    if not model_path.is_file() or not schema_path.is_file():
        raise ModelNotFoundError("Trained model artifacts are missing. Run the training script.")
    try:
        bundle = joblib.load(model_path)
        schema = joblib.load(schema_path)
    except Exception as exc:
        raise ModelArtifactError("Trained model artifacts are unreadable or corrupted.") from exc
    return bundle, schema


def load_model(model_path=MODEL_PATH, schema_path=FEATURE_SCHEMA_PATH):
    bundle, schema = _read_model_bundle(model_path=model_path, schema_path=schema_path)
    if not isinstance(bundle, dict) or bundle.get("artifact_format_version") != 2:
        raise ModelArtifactError("Model artifact format is incompatible. Retrain the model.")
    if not isinstance(schema, list) or not all(isinstance(name, str) for name in schema) or schema != FEATURE_ORDER:
        raise ModelArtifactError("Saved feature schema does not match the current feature extraction order.")
    bundle_schema = bundle.get("feature_order")
    if (
        not isinstance(bundle_schema, list)
        or not all(isinstance(name, str) for name in bundle_schema)
        or bundle_schema != schema
    ):
        raise ModelArtifactError("Model and saved feature schema do not match.")

    selected_model_name = bundle.get("selected_model")
    if not isinstance(selected_model_name, str):
        raise ModelArtifactError("Model artifact does not identify its selected estimator.")
    selected_model = bundle.get("model")
    if selected_model is None:
        models = bundle.get("models", {})
        if isinstance(models, dict):
            selected_model = models.get(selected_model_name)
    if selected_model is None or not callable(getattr(selected_model, "predict", None)):
        raise ModelArtifactError("Model artifact does not contain a valid selected estimator.")
    if getattr(selected_model, "n_features_in_", None) != len(schema):
        raise ModelArtifactError("Model feature count does not match the saved schema.")

    try:
        classes = list(getattr(selected_model, "classes_", []))
        has_expected_classes = len(classes) == 2 and set(classes) == {0, 1}
    except (TypeError, ValueError):
        has_expected_classes = False
    if not has_expected_classes:
        raise ModelArtifactError("Selected model must contain both binary classes: 0 (legitimate) and 1 (phishing).")
    return selected_model, schema, bundle


def _build_explanation(features, prediction_label):
    reasons = []
    if features["has_ip_address"]:
        reasons.append("The hostname uses an IP address instead of a normal domain name.")
    if features["has_at_symbol"]:
        reasons.append("The URL contains an @ symbol, which can mislead users by hiding the real hostname.")
    if features["has_url_shortening_indicator"]:
        reasons.append("The URL appears to use a shortening service, which can hide the destination.")
    if features["has_suspicious_encoding"]:
        reasons.append("The URL contains encoded patterns that may obscure its destination.")
    if features["has_misleading_hostname"]:
        reasons.append("The hostname structure looks unusually deceptive or manipulated.")
    if features["suspicious_keyword_count"] > 0:
        reasons.append("The domain or path includes account-related terms sometimes used in phishing.")
    if features["has_unusual_port"]:
        reasons.append("The URL uses an uncommon port.")
    if features["num_subdomains"] > 2:
        reasons.append("The URL contains multiple subdomains.")
    if not features["is_https"]:
        reasons.append("The URL does not use HTTPS; HTTPS alone would not prove legitimacy.")
    if not reasons:
        reasons.append("The URL has no obvious structural warning from the features examined.")
    if prediction_label == "Potential Phishing":
        reasons.append("Avoid entering sensitive information until the destination is verified through a trusted source.")
    else:
        reasons.append("This is only a model estimate and does not guarantee legitimacy.")
    return " ".join(reasons)


def _heuristic_risk_score(features):
    score = 0
    score += features["has_ip_address"] * 18
    score += features["has_at_symbol"] * 16
    score += features["has_url_shortening_indicator"] * 18
    score += features["has_suspicious_encoding"] * 12
    score += features["has_misleading_hostname"] * 12
    score += min(features["suspicious_keyword_count"] * 10, 25)
    score += features["has_unusual_port"] * 10
    score += (1 - features["is_https"]) * 7
    score += min(features["num_subdomains"] * 5, 20)
    score += min(features["domain_length"] / 12, 10)
    return max(0, min(100, int(round(score))))


def _class_index(classes, target):
    for index, label in enumerate(classes):
        if label == target:
            return index
    raise ModelArtifactError(f"Model is missing expected class {target}.")


def analyze_url(url, model_path=MODEL_PATH, schema_path=FEATURE_SCHEMA_PATH):
    normalized_url = validate_url(url)
    features = extract_url_features(normalized_url)
    model, schema, bundle = load_model(model_path=model_path, schema_path=schema_path)
    x = feature_vector_from_dict(features, schema)

    try:
        predictions = np.asarray(model.predict(x))
    except Exception as exc:
        raise ModelArtifactError("Selected model could not produce a prediction.") from exc
    if predictions.shape != (1,):
        raise ModelArtifactError("Selected model returned an invalid prediction shape.")
    prediction = predictions[0]
    if prediction not in (0, 1):
        raise ModelArtifactError("Model returned an unsupported prediction class.")
    label = "Potential Phishing" if int(prediction) == 1 else "Likely Legitimate"

    confidence = None
    phishing_probability = None
    if callable(getattr(model, "predict_proba", None)):
        try:
            probabilities = np.asarray(model.predict_proba(x), dtype=float)
            classes = list(model.classes_)
        except Exception as exc:
            raise ModelArtifactError("Selected model returned invalid class probabilities.") from exc
        if (
            probabilities.shape != (1, len(classes))
            or not np.isfinite(probabilities).all()
            or np.any(probabilities < 0)
            or np.any(probabilities > 1)
            or not np.allclose(probabilities.sum(axis=1), 1.0, atol=1e-6)
        ):
            raise ModelArtifactError("Model returned invalid class probabilities.")
        confidence = float(probabilities[0][_class_index(classes, prediction)])
        phishing_probability = float(probabilities[0][_class_index(classes, 1)])

    return {
        "url": normalized_url,
        "label": label,
        "confidence": confidence,
        "risk_score": _heuristic_risk_score(features),
        "risk_label": "Heuristic risk score (not model probability)",
        "model_probability": phishing_probability,
        "features": features,
        "explanation": _build_explanation(features, label),
        "selected_model": bundle.get("selected_model", "unknown"),
        "model_metrics": bundle.get("metrics", {}),
    }


def public_health_status(model_path=MODEL_PATH, schema_path=FEATURE_SCHEMA_PATH):
    try:
        load_model(model_path=model_path, schema_path=schema_path)
        return {"status": "ok", "model_loaded": True}
    except (ModelNotFoundError, ModelArtifactError):
        return {"status": "warning", "model_loaded": False, "message": "Trained model is missing or needs retraining."}
