#!/bin/sh
# Rebuild the lab from the repository and rerun one experiment (lab/README.md).
# Usage: lab/reproduce.sh [lab_data_dir]    (default: $FIRSTREAD_LAB_DATA or ./lab-data)
# Needs: Rust (cargo), Python 3.13, curl, tar, 7z, git. Python packages go into <lab_data>/venv.
set -eu
REPO="$(cd "$(dirname "$0")/.." && pwd)"
LAB="${1:-${FIRSTREAD_LAB_DATA:-$REPO/lab-data}}"
export FIRSTREAD_LAB_DATA="$LAB" HF_HOME="$LAB/hf"
cd "$REPO"

if [ ! -f "$LAB/venv/.installed" ]; then                    # pinned packages, once (lab/requirements.txt)
  python3 -m venv "$LAB/venv"
  "$LAB/venv/bin/pip" install -q --index-url https://download.pytorch.org/whl/cpu torch==2.14.1+cpu
  "$LAB/venv/bin/pip" install -q -r lab/requirements.txt
  touch "$LAB/venv/.installed"
fi
export PATH="$LAB/venv/bin:$PATH"                          # every python3 below, and the sidecar, use it

cargo build --release -q                                   # filter, daemon, CLI
python3 -I lab/harness/fetch.py "$LAB"                     # archives, lore, models; sha256-checked
python3 -I lab/harness/prepare.py "$LAB"                   # items and splits; checked against lab/data/
python3 -I lab/harness/render.py "$LAB"                    # provider texts via the real renderer
HF_HUB_OFFLINE=1 python3 -I ml/sidecar/export_onnx.py e5-small "$LAB/onnx"   # fp32 parity-checked, int8
python3 -I -c "import json,sys; a=json.load(open('$LAB/onnx/e5-small/manifest.json'))['files']; b=json.load(open('lab/data/onnx-e5-small.json'))['files']; \
  [print(f'warning: onnx {k} differs from the recorded export (sha256); results may differ slightly') for k in a if a[k]['sha256'] != b[k]['sha256']]"
# The lock covers lab-data/manifest.json, whose content is location-independent.
HF_HUB_OFFLINE=1 python3 -I lab/harness/run.py "$LAB/runs/reproduce" # fills the embedding cache on first use
