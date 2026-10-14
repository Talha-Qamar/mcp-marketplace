#!/usr/bin/env python3
"""
Install a trained Model B into the service and register it with the marketplace.

  1. copies the model files from a Kaggle output folder into model_b_v8/;
  2. runs parity_check.py: local CPU scores must match the Kaggle scores on the test sets;
  3. pins the model hash in the marketplace ruleset (analyzerPins.model_b). Policy-v4 refuses to
     PASS with a Model B whose hash is not pinned, because its thresholds were tuned for that model.

Usage: python release.py <kaggle-output-dir> [--ruleset ../src/mcpsecure/ruleset.json]
"""
import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = ("adapter_model.safetensors", "adapter_config.json", "model_b_config.json",
         "tokenizer.json", "tokenizer_config.json")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kaggle_dir")
    ap.add_argument("--ruleset", default=str(HERE.parent / "src" / "mcpsecure" / "ruleset.json"))
    a = ap.parse_args()
    src = Path(a.kaggle_dir)
    dst = HERE / "model_b_v8"
    dst.mkdir(exist_ok=True)
    for f in FILES:
        shutil.copy2(src / "model_b_v8" / f, dst / f)
    for f in ("final_report.json", "test_predictions.json"):   # evaluation record, kept with the model
        if (src / f).exists():
            shutil.copy2(src / f, dst / f)
    print("copied model files ->", dst)

    r = subprocess.run([sys.executable, str(HERE / "parity_check.py"), str(src / "test_predictions.json")],
                       capture_output=True, text=True)
    print(r.stdout.strip().splitlines()[-3:] if r.stdout else r.stderr[-2000:])
    if r.returncode != 0 or not r.stdout.strip().endswith("PASS"):
        sys.exit("parity check failed: not releasing")

    import model_b
    h = model_b.model_hash(dst)
    rs_path = Path(a.ruleset)
    rs = json.loads(rs_path.read_text())
    rs.setdefault("analyzerPins", {})["model_b"] = "sha256:" + h
    rs_path.write_text(json.dumps(rs, indent=2, ensure_ascii=False) + "\n")
    print(f"model_b pinned to sha256:{h} -> {rs_path}")


if __name__ == "__main__":
    main()
