#!/usr/bin/env python3
"""
train_models.py - simple wrapper to call models.train_all from project root.
"""

import argparse
import sys
from pathlib import Path
import traceback

# Make the project's models package importable when script run from project root
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Import the module file (models/models.py)
from models import models as models_module  # type: ignore

def main():
    parser = argparse.ArgumentParser(description="Train AI-Vuln-Scanner models.")
    parser.add_argument("--data-dir", type=str, default=str(ROOT / "data" / "Trainning Data"), help="Directory with training data")
    parser.add_argument("--save-dir", type=str, default=str(ROOT / "models"), help="Directory to save trained models")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--force", action="store_true", help="Overwrite saved models")
    args = parser.parse_args()

    try:
        print("[INFO] Starting training...")
        models_module.train_all(save_dir=args.save_dir, data_dir=args.data_dir, test_size=args.test_size, random_state=args.random_state, force=args.force)
        print("[INFO] Training completed successfully.")
    except Exception as e:
        print("[ERROR] Training failed:", e)
        traceback.print_exc()
        raise SystemExit(1)

if __name__ == "__main__":
    main()
