# Model artifacts

This folder stores trained model artifacts and evaluation results. These files are created by running:

```powershell
python train_model.py
```

The application expects the following files after training:

- `phishguard_model.joblib`
- `feature_schema.joblib`
- `evaluation_metrics.json`

Do not commit generated model files to version control unless your project intentionally tracks them.
