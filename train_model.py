import argparse
import json
import warnings
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import GroupShuffleSplit

from config import (
    DATA_DIR,
    DEFAULT_DATASET_PATH,
    FEATURE_SCHEMA_PATH,
    METRICS_PATH,
    MODEL_PATH,
    SYNTHETIC_DATASET_PATH,
)
from feature_extraction import FEATURE_ORDER, extract_url_features, validate_url


LABEL_MAP = {
    "legitimate": 0, "legit": 0, "safe": 0, "benign": 0, "good": 0, "0": 0,
    "phishing": 1, "phish": 1, "malicious": 1, "fraud": 1, "bad": 1, "1": 1,
}
SECOND_LEVEL_SUFFIXES = {"ac", "co", "com", "edu", "gov", "net", "org"}


def normalize_label(raw_label):
    if raw_label is None or pd.isna(raw_label):
        return None
    normalized = str(raw_label).strip().casefold()
    if not normalized:
        return None
    if normalized not in LABEL_MAP:
        raise ValueError(f"Unsupported label {raw_label!r}; use legitimate/0 or phishing/1.")
    return LABEL_MAP[normalized]


def _domain_group(url):
    hostname = urlsplit(url).hostname or ""
    labels = hostname.lower().split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else hostname.lower()


def build_dataset(csv_path):
    csv_path = Path(csv_path)
    if not csv_path.is_file():
        raise FileNotFoundError(f"Dataset not found: {csv_path}")
    try:
        df = pd.read_csv(csv_path)
    except (OSError, UnicodeError, pd.errors.EmptyDataError, pd.errors.ParserError) as exc:
        raise ValueError(f"Could not read dataset CSV: {exc}") from exc

    required_columns = {"url", "label"}
    missing = required_columns - set(df.columns)
    if missing:
        raise ValueError(f"Dataset is missing required columns: {sorted(missing)}")
    if df.empty:
        raise ValueError("Dataset contains no records.")

    records_by_url = {}
    skipped_missing = 0
    skipped_invalid = 0
    for row_number, row in df.iterrows():
        raw_url = row["url"]
        raw_label = row["label"]
        if pd.isna(raw_url) or not str(raw_url).strip() or pd.isna(raw_label) or not str(raw_label).strip():
            skipped_missing += 1
            continue
        label = normalize_label(raw_label)
        try:
            normalized_url = validate_url(str(raw_url))
            features = extract_url_features(normalized_url)
        except ValueError:
            skipped_invalid += 1
            continue
        previous = records_by_url.get(normalized_url)
        if previous is not None:
            if previous["label"] != label:
                raise ValueError(
                    f"Conflicting labels for duplicate URL on CSV row {row_number + 2}. "
                    "Resolve the conflict before training."
                )
            continue
        records_by_url[normalized_url] = {
            **features,
            "label": label,
            "_url": normalized_url,
            "_group": _domain_group(normalized_url),
        }

    if skipped_missing or skipped_invalid:
        warnings.warn(
            f"Skipped {skipped_missing} row(s) with missing fields and "
            f"{skipped_invalid} row(s) with invalid URLs.",
            stacklevel=2,
        )
    if not records_by_url:
        raise ValueError("No valid labeled URLs were found in the dataset.")
    labels = {record["label"] for record in records_by_url.values()}
    if labels != {0, 1}:
        raise ValueError("Dataset must contain both legitimate (0) and phishing (1) classes.")

    dataset = pd.DataFrame(records_by_url.values())
    group_class_counts = dataset.groupby("_group")["label"].agg(lambda values: set(values))
    for label in (0, 1):
        groups_with_label = sum(label in group_labels for group_labels in group_class_counts)
        if groups_with_label < 3:
            raise ValueError(
                "At least three independent registrable-domain groups per class are required "
                "for train/validation/test evaluation."
            )
    return dataset[FEATURE_ORDER + ["label", "_url", "_group"]]


def compute_metrics(y_true, y_pred):
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
    }


def _split_by_domain_groups(dataset):
    X = dataset[FEATURE_ORDER].values
    y = dataset["label"].values
    groups = dataset["_group"].values
    for seed in range(42, 242):
        outer_split = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=seed)
        train_validation_indices, test_indices = next(outer_split.split(X, y, groups))
        inner_split = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed + 1000)
        relative_train, relative_validation = next(
            inner_split.split(
                X[train_validation_indices],
                y[train_validation_indices],
                groups[train_validation_indices],
            )
        )
        train_indices = train_validation_indices[relative_train]
        validation_indices = train_validation_indices[relative_validation]
        if all(set(y[indices]) == {0, 1} for indices in (train_indices, validation_indices, test_indices)):
            return X, y, train_indices, validation_indices, test_indices
    raise ValueError(
        "Could not create train, validation, and test sets containing both classes "
        "without splitting related domains. Add more independent domains per class."
    )


def _new_models():
    return {
        "random_forest": RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            class_weight="balanced",
        ),
        "gradient_boosting": GradientBoostingClassifier(random_state=42),
    }


def train_models(csv_path):
    csv_path = Path(csv_path)
    dataset = build_dataset(csv_path)
    X, y, train_indices, validation_indices, test_indices = _split_by_domain_groups(dataset)
    models = _new_models()

    validation_metrics = {}
    for name, estimator in models.items():
        estimator.fit(X[train_indices], y[train_indices])
        validation_metrics[name] = compute_metrics(y[validation_indices], estimator.predict(X[validation_indices]))

    selected_model_name = max(
        validation_metrics,
        key=lambda name: (
            validation_metrics[name]["f1_score"],
            validation_metrics[name]["recall"],
            validation_metrics[name]["accuracy"],
        ),
    )

    evaluation = {}
    for name, estimator in models.items():
        estimator.fit(X[train_indices.tolist() + validation_indices.tolist()], y[train_indices.tolist() + validation_indices.tolist()])
        evaluation[name] = compute_metrics(y[test_indices], estimator.predict(X[test_indices]))

    selected_model = models[selected_model_name]
    synthetic_demo = csv_path.resolve() == SYNTHETIC_DATASET_PATH.resolve()
    model_bundle = {
        "artifact_format_version": 2,
        "selected_model": selected_model_name,
        "model": selected_model,
        "models": {selected_model_name: selected_model},
        "feature_order": FEATURE_ORDER,
        "validation_metrics": validation_metrics,
        "metrics": evaluation,
        "dataset": {
            "path_name": csv_path.name,
            "synthetic_demonstration_only": synthetic_demo,
            "record_count": int(len(dataset)),
            "group_count": int(dataset["_group"].nunique()),
            "train_count": int(len(train_indices)),
            "validation_count": int(len(validation_indices)),
            "test_count": int(len(test_indices)),
            "split_method": "registrable-domain grouped train/validation/test",
        },
    }

    DATA_DIR.mkdir(exist_ok=True)
    MODEL_PATH.parent.mkdir(exist_ok=True, parents=True)
    joblib.dump(model_bundle, MODEL_PATH)
    joblib.dump(FEATURE_ORDER, FEATURE_SCHEMA_PATH)
    with METRICS_PATH.open("w", encoding="utf-8") as fp:
        json.dump(
            {
                "selected_model": selected_model_name,
                "selection_metric": "validation F1, then validation recall, then validation accuracy",
                "validation": validation_metrics,
                "untouched_test": evaluation,
                "dataset": model_bundle["dataset"],
            },
            fp,
            indent=2,
        )
    return model_bundle


def main(argv=None):
    parser = argparse.ArgumentParser(description="Train PhishGuard URL classifiers.")
    parser.add_argument(
        "--dataset",
        type=Path,
        help="Explicit labeled CSV path (requires 'url' and 'label' columns).",
    )
    args = parser.parse_args(argv)
    if args.dataset is not None:
        dataset_path = args.dataset
    elif DEFAULT_DATASET_PATH.is_file():
        dataset_path = DEFAULT_DATASET_PATH
    else:
        dataset_path = SYNTHETIC_DATASET_PATH
        print(
            "DEMONSTRATION ONLY: no real dataset was selected; using the included synthetic dataset. "
            "Do not use its results as real-world performance evidence."
        )
    print(f"Training dataset: {dataset_path}")
    bundle = train_models(dataset_path)
    if bundle["dataset"]["synthetic_demonstration_only"]:
        print("WARNING: evaluation metrics below are from synthetic demonstration data only.")
    print(f"Selected using validation data: {bundle['selected_model']}")
    print(f"Final untouched test metrics: {bundle['metrics']}")
    return bundle


if __name__ == "__main__":
    main()
