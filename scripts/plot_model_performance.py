#!/usr/bin/env python3
"""
Plot model performance:
- Figure 4.5 — Confusion Matrix (per-label heatmaps saved)
- Figure 4.6 — ROC Curve (per-label ROC saved, AUC annotated)
- Figure 4.7 — Regression Performance Graph (true vs predicted + residuals)

Usage:
python3 scripts/plot_model_performance.py \
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
import pandas as pd
import matplotlib.pyplot as plt
# removed unconditional sns usage here
try:
    import seaborn as sns
    sns.set_theme(style="darkgrid")
    sns.set_context("talk")
    HAS_SEABORN = True
except Exception:
    HAS_SEABORN = False
    # fallback style that always exists
    try:
        plt.style.use("dark_background")
    except Exception:
        pass

# --- ADDED: metrics imports ---
from sklearn.metrics import confusion_matrix, roc_curve, auc, mean_squared_error, r2_score

def discover_json_files(path):
    p = Path(path)
    if p.is_dir():
        return sorted([str(x) for x in p.glob("**/*.json")])
    if p.is_file():
        return [str(p)]
    return []

def load_examples_from_json_files(json_files, label_names):
    X_rows = []
    y_rows = []
    y_reg = []
    for jf in json_files:
        try:
            j = json.load(open(jf, "r", encoding="utf-8"))
        except Exception:
            continue
        # feature extraction
        feats = {}
        if isinstance(j, dict):
            if "features" in j and isinstance(j["features"], dict):
                feats = j["features"].copy()
            else:
                # flatten numeric fields and boolean
                for k, v in j.items():
                    if isinstance(v, (int, float)):
                        feats[k] = v
                    elif isinstance(v, bool):
                        feats[k] = int(v)
                    elif isinstance(v, str) and v.isdigit():
                        feats[k] = int(v)
        X_rows.append(feats)
        # labels
        labs = {}
        for ln in (label_names or []):
            val = None
            if isinstance(j.get("labels"), dict):
                val = j["labels"].get(ln)
            if val is None:
                # try top-level key
                val = j.get(ln)
            labs[ln] = 1 if val in (1, True, "1", "true", "True") else 0
        y_rows.append(labs)
        # regression target (cvss_score)
        cv = None
        if isinstance(j.get("labels"), dict):
            cv = j["labels"].get("cvss_score")
        if cv is None:
            cv = j.get("cvss_score") or j.get("cvss")
        try:
            y_reg.append(float(cv) if cv is not None else np.nan)
        except Exception:
            y_reg.append(np.nan)
    X_df = pd.DataFrame(X_rows).fillna(0)
    y_df = pd.DataFrame(y_rows).fillna(0).astype(int) if y_rows else pd.DataFrame(columns=label_names)
    y_reg_arr = np.array(y_reg, dtype=float) if y_reg else np.array([], dtype=float)
    return X_df, y_df, y_reg_arr

def ensure_features_order(X_df, feature_cols):
    if feature_cols is None:
        return X_df
    # ensure all columns exist
    for c in feature_cols:
        if c not in X_df.columns:
            X_df[c] = 0
    return X_df[feature_cols].fillna(0)

def plot_confusion_matrices(y_true, y_pred, labels, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for i, lbl in enumerate(labels):
        try:
            cm = confusion_matrix(y_true[:, i], y_pred[:, i], labels=[0,1])
            fig, ax = plt.subplots(figsize=(6,5))
            if HAS_SEABORN:
                sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", cbar=False, ax=ax)
            else:
                # simple matplotlib fallback heatmap with annotations
                im = ax.imshow(cm, cmap="Blues", interpolation="nearest")
                for (row, col), val in np.ndenumerate(cm):
                    ax.text(col, row, int(val), ha="center", va="center", color="white" if im.cmap(im.norm(val))[0] < 0.6 else "black")
                fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
            ax.set_xlabel("Predicted")
            ax.set_ylabel("Actual")
            ax.set_title(f"Figure 4.5 — Confusion Matrix (Placeholder)\nLabel: {lbl}")
            ax.set_xticks([0,1]); ax.set_yticks([0,1])
            ax.set_xticklabels(["0","1"])
            ax.set_yticklabels(["0","1"])
            fpath = out_dir / f"fig4_5_confusion_{lbl}.png"
            fig.tight_layout()
            fig.savefig(fpath, dpi=150)
            plt.close(fig)
        except Exception as e:
            print(f"[!] Failed to plot confusion for {lbl}: {e}")

def plot_roc_curves(y_true, y_scores, labels, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for i, lbl in enumerate(labels):
        try:
            y_t = y_true[:, i]
            y_s = y_scores[:, i]
            # need both classes present
            if len(np.unique(y_t[~np.isnan(y_t)])) < 2:
                print(f"[!] Skipping ROC for {lbl}: only one class present in y_true")
                continue
            fpr, tpr, _ = roc_curve(y_t, y_s)
            roc_auc = auc(fpr, tpr)
            fig, ax = plt.subplots(figsize=(6,5))
            ax.plot(fpr, tpr, label=f"AUC={roc_auc:.3f}")
            ax.plot([0,1],[0,1],"--", color="gray")
            ax.set_xlabel("False Positive Rate")
            ax.set_ylabel("True Positive Rate")
            ax.set_title(f"Figure 4.6 — ROC Curve (Placeholder)\nLabel: {lbl}")
            ax.legend(loc="lower right")
            fpath = out_dir / f"fig4_6_roc_{lbl}.png"
            fig.tight_layout()
            fig.savefig(fpath, dpi=150)
            plt.close(fig)
        except Exception as e:
            print(f"[!] Failed to plot ROC for {lbl}: {e}")

def plot_regression_performance(y_true_reg, y_pred_reg, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    # filter nan in ground truth
    mask = ~np.isnan(y_true_reg)
    # sanitize true values
    try:
        y_true = np.asarray(y_true_reg, dtype=float)[mask]
    except Exception:
        y_true = np.array([float(x) for x in np.asarray(y_true_reg, dtype=object) if not (isinstance(x, float) and np.isnan(x))], dtype=float)

    # sanitize predicted values into 1D numeric array
    y_pred_arr = np.asarray(y_pred_reg, dtype=object)
    try:
        # flatten trivial extra dims
        if y_pred_arr.ndim > 1:
            if y_pred_arr.shape[1] == 1:
                y_pred_arr = y_pred_arr.ravel()
            else:
                # take first column as fallback
                y_pred_arr = y_pred_arr[:, 0]
        y_pred = np.asarray(y_pred_arr, dtype=float)
    except Exception:
        # attempt per-element conversion
        flat = []
        for v in y_pred_arr.ravel():
            try:
                flat.append(float(v))
            except Exception:
                # fallback to nan
                flat.append(np.nan)
        y_pred = np.asarray(flat, dtype=float)

    # align lengths using mask if possible
    if y_pred.shape[0] == len(y_true_reg):
        y_pred = y_pred[mask]
    else:
        # if cannot align, try to trim/pad to y_true length
        y_pred = y_pred.ravel()
        if y_pred.shape[0] >= y_true.shape[0]:
            y_pred = y_pred[: y_true.shape[0]]
        else:
            # pad with nan
            pad = np.full((y_true.shape[0] - y_pred.shape[0],), np.nan)
            y_pred = np.concatenate([y_pred, pad])

    if len(y_true) == 0:
        print("[!] No regression ground truth available to plot.")
        return
    # drop any pairs with nan in prediction
    valid_mask = ~np.isnan(y_pred)
    y_true = y_true[valid_mask]
    y_pred = y_pred[valid_mask]
    if len(y_true) == 0:
        print("[!] No valid regression pairs after sanitization.")
        return

    mse = mean_squared_error(y_true, y_pred)
    r2 = r2_score(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(7,6))
    ax.scatter(y_true, y_pred, alpha=0.7)
    lims = [min(min(y_true), min(y_pred)) - 0.5, max(max(y_true), max(y_pred)) + 0.5]
    ax.plot(lims, lims, "--", color="gray")
    ax.set_xlim(lims)
    ax.set_ylim(lims)
    ax.set_xlabel("True CVSS")
    ax.set_ylabel("Predicted CVSS")
    ax.set_title(f"Figure 4.7 — Regression Performance Graph (Placeholder)\nMSE={mse:.4f}, R2={r2:.4f}")
    fpath = out_dir / "fig4_7_regression_performance.png"
    fig.tight_layout()
    fig.savefig(fpath, dpi=150)
    plt.close(fig)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--models-dir", default="./models/trained", help="Path to trained models/artifacts")
    parser.add_argument("--test-data", required=True, help="Path to test JSON files (dir or single file)")
    parser.add_argument("--out-dir", default=None, help="Output folder for figures (defaults to models_dir/figures)")
    args = parser.parse_args()

    models_dir = Path(args.models_dir)
    out_dir = Path(args.out_dir) if args.out_dir else (models_dir / "figures")
    out_dir.mkdir(parents=True, exist_ok=True)

    # load meta
    meta_path = models_dir / "training_meta.json"
    feature_cols = None
    label_names = None
    if meta_path.exists():
        try:
            meta = json.load(open(meta_path, "r", encoding="utf-8"))
            feature_cols = meta.get("feature_columns", None) or None
            label_names = meta.get("label_names", None)
        except Exception:
            pass

    # fallback label names
    if not label_names:
        # default set (matches models.py default)
        label_names = [
            "vuln_sqli","vuln_xss","vuln_directory_traversal",
            "vuln_command_injection","vuln_misconfiguration","vuln_outdated_service"
        ]

    # load scaler + models
    scaler = None
    clf = None
    reg = None
    try:
        scaler = joblib.load(models_dir / "scaler.joblib")
    except Exception as e:
        print(f"[!] Failed to load scaler: {e}")
    try:
        clf = joblib.load(models_dir / "classifier.joblib")
    except Exception as e:
        print(f"[!] Failed to load classifier: {e}")
    try:
        reg = joblib.load(models_dir / "regressor.joblib")
    except Exception as e:
        print(f"[!] Failed to load regressor: {e}")

    # build test dataset
    json_files = discover_json_files(args.test_data)
    if not json_files:
        print("[!] No JSON test files found at:", args.test_data)
        return

    X_df, y_df, y_reg = load_examples_from_json_files(json_files, label_names)
    if feature_cols is None:
        feature_cols = list(X_df.columns)
    X_df = ensure_features_order(X_df, feature_cols)

    # scale
    X_arr = X_df.values
    if scaler is not None:
        try:
            X_scaled = scaler.transform(X_arr)
        except Exception:
            X_scaled = X_arr
    else:
        X_scaled = X_arr

    # classifier predictions / probs
    if clf is not None and not y_df.empty:
        try:
            # get probability matrix if available
            if hasattr(clf, "predict_proba"):
                y_scores = clf.predict_proba(X_scaled)
                # OneVsRestClassifier.predict_proba may return list/array; ensure shape
                y_scores = np.array(y_scores)
                # if shape mismatch, try per-estimator
                if y_scores.ndim == 3:
                    # shape (n_labels, n_samples, 2) -> take [:, :, 1] and transpose
                    y_scores = np.array([arr[:,1] if arr.shape[1] > 1 else arr[:,0] for arr in y_scores]).T
                elif y_scores.ndim == 2 and y_scores.shape[1] == len(label_names):
                    # maybe already (n_samples, n_labels)
                    pass
                # ensure (n_samples, n_labels)
                if y_scores.shape[0] == len(label_names) and y_scores.shape[1] == X_scaled.shape[0]:
                    y_scores = y_scores.T
            else:
                # fall back to decision_function or predict
                if hasattr(clf, "decision_function"):
                    y_scores = clf.decision_function(X_scaled)
                else:
                    y_scores = clf.predict(X_scaled)
        except Exception:
            # Fall back: predict then use 0/1 as scores
            try:
                y_pred_bin = clf.predict(X_scaled)
                y_scores = y_pred_bin.astype(float)
            except Exception:
                y_scores = np.zeros((X_scaled.shape[0], len(label_names)))

        # get binary predictions at 0.5 threshold
        try:
            y_pred_bin = (y_scores >= 0.5).astype(int)
        except Exception:
            y_pred_bin = clf.predict(X_scaled)

        # prepare y_true matrix
        y_true_mat = y_df.values if not y_df.empty else np.zeros_like(y_pred_bin)

        # Plot confusion matrices
        plot_confusion_matrices(y_true_mat, y_pred_bin, label_names, out_dir)
        # Plot ROC curves (use scores)
        # ensure y_scores shape (n_samples, n_labels)
        if isinstance(y_scores, np.ndarray) and y_scores.ndim == 2 and y_scores.shape[1] == len(label_names):
            plot_roc_curves(y_true_mat, y_scores, label_names, out_dir)
        else:
            print("[!] y_scores shape unexpected; skipping ROC plots")
    else:
        print("[!] Classifier or label truths not available; skipping classification plots")

    # regression plots
    if reg is not None and y_reg.size > 0:
        try:
            y_pred_reg = reg.predict(X_scaled)
            plot_regression_performance(y_reg, y_pred_reg, out_dir)
        except Exception as e:
            print(f"[!] Failed regression plotting: {e}")
    else:
        print("[!] Regressor or regression ground truth not available; skipping regression plots")

    print("[+] Figures saved to:", out_dir)

if __name__ == "__main__":
    main()