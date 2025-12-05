#!/usr/bin/env python3
"""
Plot a single Regression Performance Graph:
 - Scatter: True CVSS vs Predicted CVSS with y=x reference
 - Residuals histogram (right panel)
Saves PNG to out-dir/fig_regression_performance.png

Usage:
python3 scripts/plot_regression_performance.py \
  --models-dir ./models/trained \
  --test-data "/home/kali/Desktop/FYP/Ai-Vuln-Scanner/data/Trainning Data" \
  --out-dir ./models/trained/figures
"""
from pathlib import Path
import argparse
import json
import os
from glob import glob

import joblib
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd

# Robust file discovery for JSON test files
def discover_json_files(path):
    p = Path(path)
    if p.is_dir():
        patterns = ["*.json", "*.jsonl", "*.ndjson"]
        files = []
        for pat in patterns:
            files.extend(sorted(p.glob("**/" + pat)))
        return [str(x) for x in files]
    if p.is_file():
        return [str(p)]
    return []

# Load features and cvss_score targets from JSON files (simple normalization)
def load_features_and_cvss(json_files, feature_cols=None):
    rows = []
    y_reg = []
    for jf in json_files:
        try:
            j = json.load(open(jf, "r", encoding="utf-8"))
        except Exception:
            continue
        # try nested "features" or flattened
        feats = {}
        if isinstance(j, dict):
            if isinstance(j.get("features"), dict):
                feats = dict(j.get("features"))
            else:
                for k, v in j.items():
                    if k in ("features", "labels", "label"):
                        continue
                    if isinstance(v, (int, float)):
                        feats[k] = float(v)
                    elif isinstance(v, bool):
                        feats[k] = 1.0 if v else 0.0
                    elif isinstance(v, str) and v.strip().isdigit():
                        feats[k] = float(v.strip())
        # extract cvss_score
        cv = None
        if isinstance(j.get("labels"), dict):
            cv = j["labels"].get("cvss_score")
        if cv is None:
            cv = j.get("cvss_score") or j.get("cvss")
        try:
            y_reg.append(float(cv) if cv is not None else np.nan)
        except Exception:
            y_reg.append(np.nan)
        rows.append(feats)
    if not rows:
        return None, None
    X_df = pd.DataFrame(rows).fillna(0.0)
    # ensure training feature columns order
    if feature_cols:
        for c in feature_cols:
            if c not in X_df.columns:
                X_df[c] = 0.0
        X_df = X_df[feature_cols].fillna(0.0)
    return X_df, np.asarray(y_reg, dtype=float)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--models-dir", default="./models/trained", help="Path to trained models/artifacts")
    parser.add_argument("--test-data", required=True, help="Path to test JSON files (dir or single file)")
    parser.add_argument("--out-dir", default=None, help="Output folder for figure (defaults to models_dir/figures)")
    args = parser.parse_args()

    models_dir = Path(args.models_dir)
    out_dir = Path(args.out_dir) if args.out_dir else (models_dir / "figures")
    out_dir.mkdir(parents=True, exist_ok=True)

    # load models/scaler/feature columns
    try:
        from models.models import load_models
        models_obj = load_models(str(models_dir))
        scaler = models_obj.get("scaler")
        reg = models_obj.get("regressor")
        feature_cols = models_obj.get("feature_columns")
    except Exception as e:
        print("[!] Failed to load models via models.load_models():", e)
        # fallback: load individual artifacts
        try:
            scaler = joblib.load(models_dir / "scaler.joblib")
        except Exception:
            scaler = None
        try:
            reg = joblib.load(models_dir / "regressor.joblib")
        except Exception as e2:
            print("[!] Failed to load regressor:", e2)
            reg = None
        try:
            feature_cols = json.load(open(models_dir / "feature_columns.json", "r", encoding="utf-8"))
        except Exception:
            feature_cols = None

    json_files = discover_json_files(args.test_data)
    if not json_files:
        print("[!] No JSON test files found at:", args.test_data)
        return

    X_df, y_true = load_features_and_cvss(json_files, feature_cols=feature_cols)
    if X_df is None:
        print("[!] No usable test records found.")
        return

    # --- SANITIZE X_df: flatten list-like cells, coerce columns to numeric ---
    def _first_or_nan(v):
        if v is None:
            return np.nan
        if isinstance(v, (list, tuple, np.ndarray)):
            try:
                if len(v) == 0:
                    return np.nan
                return v[0]
            except Exception:
                return np.nan
        return v

    for col in list(X_df.columns):
        ser = X_df[col]
        # if any element is list-like, replace by first element
        if ser.apply(lambda v: isinstance(v, (list, tuple, np.ndarray))).any():
            X_df[col] = ser.map(_first_or_nan)
        # coerce to numeric, fill NaN with 0.0
        X_df[col] = pd.to_numeric(X_df[col], errors="coerce").fillna(0.0)

    X_arr = X_df.astype(float).values

    if scaler is not None:
        try:
            X_scaled = scaler.transform(X_arr)
        except Exception:
            X_scaled = X_arr
    else:
        X_scaled = X_arr

    if reg is None:
        print("[!] Regressor not available; cannot produce regression plot.")
        return

    try:
        y_pred = reg.predict(X_scaled)
        y_pred = np.asarray(y_pred, dtype=float).ravel()
    except Exception as e:
        print("[!] Regression predict failed:", e)
        return

    # align true/pred by filtering out NaN true entries
    mask = ~np.isnan(y_true)
    y_true_f = y_true[mask]
    y_pred_f = y_pred[mask]
    if y_true_f.size == 0:
        print("[!] No ground-truth cvss_score values available in test data.")
        return

    # Compute metrics
    from sklearn.metrics import mean_squared_error, r2_score
    mse = mean_squared_error(y_true_f, y_pred_f)
    r2 = r2_score(y_true_f, y_pred_f)

    # Plot scatter + residuals
    fig, (ax_scatter, ax_hist) = plt.subplots(ncols=2, figsize=(12,6), gridspec_kw={"width_ratios":[3,1]})
    ax_scatter.scatter(y_true_f, y_pred_f, alpha=0.7, s=40, color="#1f77b4", edgecolor="k", linewidth=0.3)
    mn = min(y_true_f.min(), y_pred_f.min())
    mx = max(y_true_f.max(), y_pred_f.max())
    padding = (mx - mn) * 0.05 if mx > mn else 1.0
    ax_scatter.plot([mn-padding, mx+padding], [mn-padding, mx+padding], "--", color="gray", linewidth=1)
    ax_scatter.set_xlim(mn-padding, mx+padding)
    ax_scatter.set_ylim(mn-padding, mx+padding)
    ax_scatter.set_xlabel("True CVSS")
    ax_scatter.set_ylabel("Predicted CVSS")
    ax_scatter.set_title(f"Figure 4.7 — Regression Performance\nMSE={mse:.4f}, R2={r2:.4f}")

    # residuals
    residuals = y_pred_f - y_true_f
    ax_hist.hist(residuals, bins=30, color="#ff7f0e", edgecolor="k", alpha=0.9)
    ax_hist.axvline(0, color="k", linestyle="--", linewidth=1)
    ax_hist.set_xlabel("Residual")
    ax_hist.set_ylabel("Count")
    ax_hist.set_title("Residuals")

    fig.tight_layout()
    out_path = out_dir / "fig_regression_performance.png"
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print("[+] Regression performance figure saved to:", out_path)

if __name__ == "__main__":
    main()