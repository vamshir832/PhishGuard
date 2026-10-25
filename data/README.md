# Dataset guidance

This project accepts a CSV dataset with two required columns:

- `url`: the full URL to evaluate
- `label`: the class label, such as `legitimate` or `phishing`

The synthetic file in this folder is only for local testing and software validation. It is not suitable for measuring real-world phishing detection performance. It is selected only when `phishing_urls.csv` does not exist and no `--dataset` path is supplied.

For actual research or benchmarking, use a reputable phishing URL dataset from a trusted public source, then place the CSV in this folder as `phishing_urls.csv` and run:

```powershell
python train_model.py
```

Alternatively, specify a dataset path:

```powershell
python train_model.py --dataset "C:\path\to\dataset.csv"
```

Expected dataset usage:

- Keep one URL per row
- Remove rows with missing or malformed URLs
- Use consistent labels such as `legitimate` or `phishing`
- Do not fabricate results or claim performance metrics from synthetic data
