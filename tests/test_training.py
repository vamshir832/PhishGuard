import pandas as pd
import pytest

from config import SYNTHETIC_DATASET_PATH
import train_model


def write_dataset(path, rows):
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


def balanced_domain_rows(groups_per_class=10):
    rows = []
    for label_name, domain_prefix in (("legitimate", "good"), ("phishing", "bad")):
        for index in range(groups_per_class):
            domain = f"{domain_prefix}{index}-sample{index}.com"
            rows.append({"url": f"https://{domain}/path", "label": label_name})
    return rows


def test_dataset_requires_url_and_label_columns(tmp_path):
    dataset_path = write_dataset(tmp_path / "missing-column.csv", [{"link": "https://example.com", "label": 0}])
    with pytest.raises(ValueError, match="missing required columns"):
        train_model.build_dataset(dataset_path)


def test_missing_dataset_fails_clearly(tmp_path):
    with pytest.raises(FileNotFoundError, match="Dataset not found"):
        train_model.build_dataset(tmp_path / "not-present.csv")


def test_empty_dataset_fails_clearly(tmp_path):
    empty_path = tmp_path / "empty.csv"
    empty_path.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="Could not read dataset CSV"):
        train_model.build_dataset(empty_path)


def test_unknown_label_is_rejected(tmp_path):
    rows = balanced_domain_rows()
    rows[0]["label"] = "unknown-class"
    dataset_path = write_dataset(tmp_path / "unknown-label.csv", rows)
    with pytest.raises(ValueError, match="Unsupported label"):
        train_model.build_dataset(dataset_path)


def test_dataset_normalizes_labels_deduplicates_and_skips_invalid_rows(tmp_path):
    rows = balanced_domain_rows()
    rows.extend(
        [
            {"url": "HTTPS://GOOD0-SAMPLE0.COM/path", "label": "safe"},
            {"url": "not a url", "label": "phishing"},
            {"url": None, "label": "legitimate"},
        ]
    )
    dataset_path = write_dataset(tmp_path / "dataset.csv", rows)

    with pytest.warns(UserWarning, match="Skipped"):
        dataset = train_model.build_dataset(dataset_path)

    assert len(dataset) == 20
    assert set(dataset["label"]) == {0, 1}


def test_dataset_rejects_conflicting_duplicate_labels(tmp_path):
    rows = balanced_domain_rows()
    rows.append({"url": "https://GOOD0-SAMPLE0.COM/path", "label": "phishing"})
    dataset_path = write_dataset(tmp_path / "conflicts.csv", rows)
    with pytest.raises(ValueError, match="Conflicting labels"):
        train_model.build_dataset(dataset_path)


def test_dataset_requires_both_classes(tmp_path):
    rows = [{"url": f"https://good{index}-sample{index}.com", "label": "legitimate"} for index in range(5)]
    dataset_path = write_dataset(tmp_path / "one-class.csv", rows)
    with pytest.raises(ValueError, match="both legitimate"):
        train_model.build_dataset(dataset_path)


def test_group_split_keeps_related_domains_in_one_partition(tmp_path):
    dataset_path = write_dataset(tmp_path / "balanced.csv", balanced_domain_rows())
    dataset = train_model.build_dataset(dataset_path)
    _, _, train_indices, validation_indices, test_indices = train_model._split_by_domain_groups(dataset)

    group_sets = [
        set(dataset.iloc[indices]["_group"])
        for indices in (train_indices, validation_indices, test_indices)
    ]
    assert group_sets[0].isdisjoint(group_sets[1])
    assert group_sets[0].isdisjoint(group_sets[2])
    assert group_sets[1].isdisjoint(group_sets[2])


def test_train_model_writes_held_out_evaluation_artifacts(tmp_path, monkeypatch):
    dataset_path = write_dataset(tmp_path / "balanced.csv", balanced_domain_rows())
    monkeypatch.setattr(train_model, "MODEL_PATH", tmp_path / "model.joblib")
    monkeypatch.setattr(train_model, "FEATURE_SCHEMA_PATH", tmp_path / "schema.joblib")
    monkeypatch.setattr(train_model, "METRICS_PATH", tmp_path / "metrics.json")
    bundle = train_model.train_models(dataset_path)

    assert bundle["artifact_format_version"] == 2
    assert bundle["dataset"]["synthetic_demonstration_only"] is False
    assert set(bundle["validation_metrics"]) == {"random_forest", "gradient_boosting"}
    assert set(bundle["metrics"]) == {"random_forest", "gradient_boosting"}
    assert {
        "accuracy",
        "precision",
        "recall",
        "f1_score",
        "confusion_matrix",
    } <= set(bundle["metrics"]["random_forest"])
    assert (tmp_path / "model.joblib").is_file()
    assert (tmp_path / "schema.joblib").is_file()
    assert (tmp_path / "metrics.json").is_file()


def test_explicit_dataset_path_is_not_replaced_by_default(monkeypatch, tmp_path):
    selected = tmp_path / "explicit.csv"
    monkeypatch.setattr(
        train_model,
        "train_models",
        lambda path: {
            "selected_path": path,
            "dataset": {"synthetic_demonstration_only": False},
            "selected_model": "test",
            "metrics": {},
        },
    )

    result = train_model.main(["--dataset", str(selected)])

    assert result["selected_path"] == selected


def test_default_prefers_real_dataset_when_available(monkeypatch, tmp_path):
    real_dataset = tmp_path / "phishing_urls.csv"
    synthetic_dataset = tmp_path / "synthetic_urls.csv"
    monkeypatch.setattr(train_model, "DEFAULT_DATASET_PATH", real_dataset)
    monkeypatch.setattr(train_model, "SYNTHETIC_DATASET_PATH", synthetic_dataset)
    monkeypatch.setattr(
        train_model,
        "train_models",
        lambda path: {
            "selected_path": path,
            "dataset": {"synthetic_demonstration_only": False},
            "selected_model": "test",
            "metrics": {},
        },
    )
    real_dataset.touch()
    synthetic_dataset.touch()

    result = train_model.main([])

    assert result["selected_path"] == real_dataset


def test_default_marks_synthetic_fallback_as_demonstration(monkeypatch, capsys, tmp_path):
    synthetic_dataset = tmp_path / "synthetic_urls.csv"
    synthetic_dataset.touch()
    monkeypatch.setattr(train_model, "DEFAULT_DATASET_PATH", tmp_path / "missing-real.csv")
    monkeypatch.setattr(train_model, "SYNTHETIC_DATASET_PATH", synthetic_dataset)
    monkeypatch.setattr(
        train_model,
        "train_models",
        lambda path: {
            "selected_path": path,
            "dataset": {"synthetic_demonstration_only": True},
            "selected_model": "test",
            "metrics": {},
        },
    )

    result = train_model.main([])

    assert result["selected_path"] == synthetic_dataset
    assert "DEMONSTRATION ONLY" in capsys.readouterr().out


def test_synthetic_training_is_marked_as_demonstration(tmp_path, monkeypatch):
    monkeypatch.setattr(train_model, "MODEL_PATH", tmp_path / "model.joblib")
    monkeypatch.setattr(train_model, "FEATURE_SCHEMA_PATH", tmp_path / "schema.joblib")
    monkeypatch.setattr(train_model, "METRICS_PATH", tmp_path / "metrics.json")

    bundle = train_model.train_models(SYNTHETIC_DATASET_PATH)

    assert bundle["dataset"]["synthetic_demonstration_only"] is True
