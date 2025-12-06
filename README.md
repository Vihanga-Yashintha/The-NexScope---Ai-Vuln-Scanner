![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Development-yellow)

# AI-Vuln-Scanner

AI-Vuln-Scanner is a Linux desktop GUI that orchestrates common web/network scanners (Nmap, Gobuster, Nikto), normalizes their outputs into feature vectors, and uses machine learning models to predict web application vulnerabilities and an estimated CVSS score. The project also generates HTML/PDF reports and maintains a scan history.

## Features
- Run Nmap, Gobuster, Nikto (or use simulation stubs)
- Parser modules to extract features into JSON feature vectors
- Preprocessing: one-hot encoding for selected categorical fields, missing-value handling, StandardScaler
- Multi-label classification (One-vs-Rest) for vuln types and regression for CVSS score
- GUI (CustomTkinter) with Scan, History, Settings tabs
- HTML report generation + PDF export (WeasyPrint or wkhtmltopdf)
- Plotting utilities for confusion matrices, ROC curves and regression performance

## Requirements
See `requirements.txt`. Use a Python 3.9+ virtual environment.

## Quick start (development)
```bash
# from project root
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# run GUI
python3 gui-main-2.py
```

## Training models
Prepare labeled JSON files in `data/Trainning Data/` (one record per file or newline JSON). Then run:
```bash
python3 train_models.py \
  --data-dir "data/Trainning Data" \
  --save-dir "models/trained" \
  --test-size 0.2 --random-state 42 --force
```
Trained artifacts: `models/trained/` (scaler.joblib, classifier.joblib, regressor.joblib, feature_columns.json, training_report.txt).

## Generate performance figures
```bash
python3 scripts/plot_model_performance.py \
  --models-dir ./models/trained \
  --test-data "data/Trainning Data" \
  --out-dir ./models/trained/figures
```
Or generate a single regression plot:
```bash
python3 scripts/plot_regression_performance.py \
  --models-dir ./models/trained \
  --test-data "data/Trainning Data" \
  --out-dir ./models/trained/figures
```

## Report export
- HTML is the canonical report format; convert to PDF with:
  - WeasyPrint: `weasyprint report.html report.pdf`
  - wkhtmltopdf: `wkhtmltopdf --enable-local-file-access report.html report.pdf`
- The GUI uses `report_generator.py` to create HTML and invoke PDF conversion.

## Data & ethics
- Only scan authorized targets. Do not scan systems without permission.
- Store and share only sanitized/labeled data. Raw scanner outputs may contain sensitive info.

## Project layout (important files)
- `gui-main-2.py` — GUI entrypoint
- `models/models.py` — training pipeline, preprocessing
- `models/predict_api.py` — prediction API used by GUI
- `src/` — parser modules (nmap/gobuster/nikto) and helpers
- `report_generator.py` — HTML/PDF generator
- `scripts/` — plotting utilities
- `data/` — scan features, labeled data, history
- `models/trained/` — saved artifacts

## Contributing
- Create issues for bugs or feature requests.
- Provide labeled data as `labeled_<target>.json`.
- Run tests (if available) via `pytest`.

## License

This project is released under the MIT License — see the included `LICENSE` file for details.
