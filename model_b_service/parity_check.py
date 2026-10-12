#!/usr/bin/env python3
"""
Packaging check: local CPU inference must reproduce the scores the model produced on Kaggle (GPU,
fp16) for the held-back test sets. Uses the stored model_code (skips text prep) for the score
comparison, then separately checks that textprep turns the raw code into the same model_code.

Usage: python parity_check.py [path/to/test_predictions.json]
"""
import json
import sys
import time
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import model_b  # noqa: E402
import textprep  # noqa: E402

import os
# the v8 dataset (mcp_secure/dataset_v8/data next to this repo, or MODEL_B_DATA)
DATA = Path(os.environ.get("MODEL_B_DATA", HERE.parents[1] / "mcp_secure" / "dataset_v8" / "data"))
if not (DATA / "test_v6.jsonl").exists():
    sys.exit(f"dataset not found at {DATA}; set MODEL_B_DATA to the model-b-v8-data folder")
preds = json.load(open(sys.argv[1] if len(sys.argv) > 1 else HERE / "model_b_v8" / "test_predictions.json"))
m = model_b.ModelB()
worst, n, prep_same, prep_n = 0.0, 0, 0, 0
for name in ("test_v6", "test_fresh_cmdi", "test_mcp_new"):
    rows = {json.loads(l)["id"]: json.loads(l) for l in open(DATA / f"{name}.jsonl")}
    ref = preds[name]
    t0 = time.time()
    S = m.raw_scores([rows[p["id"]]["model_code"] for p in ref])
    R = np.array([[p["scores"][c] for c in m.classes] for p in ref])
    d = np.abs(S - R).max(1)
    worst = max(worst, d.max()); n += len(ref)
    print(f"{name}: {len(ref)} functions in {time.time() - t0:.1f}s, max |local - kaggle| = {d.max():.4f}, "
          f"mean {d.mean():.5f}")
    sample = [dict(id=k, language=r["language"], code=r["code"]) for k, r in list(rows.items())[:40]]
    textprep.prepare(sample)
    prep_n += len(sample); prep_same += sum(s["model_code"] == rows[s["id"]]["model_code"] for s in sample)
print(f"\nscore parity: worst difference {worst:.4f} over {n} functions (fp16 GPU vs fp32 CPU; < 0.02 is fine)")
print(f"text prep parity: {prep_same}/{prep_n} identical model_code")
print("PASS" if worst < 0.02 and prep_same == prep_n else "CHECK")
