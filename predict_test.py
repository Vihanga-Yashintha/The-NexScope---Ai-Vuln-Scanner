#!/usr/bin/env python3
"""
predict_test.py
Quick test script to make predictions using trained AI-Vuln-Scanner models.
"""

import json
import sys
from pathlib import Path
from models.models import load_models, predict_from_features  # using your existing helper functions

# --- CHANGE THIS to the directory where you saved trained models ---
SAVE_DIR = Path("models")   # or Path("/home/kali/Desktop/FYP/Ai-Vuln-Scanner/models")

# Example: minimal test feature set.
# You can include any feature keys that existed in training (found in feature_columns.json)
sample_features = {
  "port_80_open": 1,
  "http_title_contains_login": 1,
  "http_header_x_powered_by_php": 1,
  "cgi_bin_present": 1,
  "sql_error_in_body": 1,   # if present in feature list
  "waf_bypassed_flag": 1    # example
}

# --- Load models ---
try:
    models_obj = load_models(str(SAVE_DIR))
except Exception as e:
    print("Failed to load models:", e)
    sys.exit(1)

# --- Run prediction ---
result = predict_from_features(sample_features, models_obj)

# --- Pretty print results ---
print(json.dumps(result, indent=2))
