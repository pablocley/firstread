#!/bin/bash
# lab/loop/exp.sh "<description>": one iteration of the loop (lab/program.md) on the current
# run branch. Commits lab/experiment.toml and ml/heads/train.py, runs the harness, appends the
# result to lab/results.tsv and lab/pareto.tsv, and keeps (points lab/runs/champion at the run)
# or discards (resets the branch) exactly as the harness's `keep` line says.
set -e
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"
start=$(git rev-parse HEAD)
if git diff --quiet -- lab/experiment.toml ml/heads/train.py; then
  echo "NO CHANGE: $1"; exit 2
fi
git add lab/experiment.toml ml/heads/train.py
git commit -q -m "lab: $1"
c=$(git rev-parse --short HEAD)
if ! timeout 2700 python3 -I lab/harness/run.py "lab/runs/$c" > lab/run.log 2>&1; then
  tail -20 lab/run.log
  printf '%s\t0\t0\t0\t0\tcrash\tcrash\t%s\n' "$c" "$1" >> lab/results.tsv
  git reset -q --hard "$start"
  echo "CRASH $c"; exit 1
fi
sed -n '/^---$/,$p' lab/run.log
python3 -I lab/loop/log.py "$c" "$1"
status=$(tail -1 lab/results.tsv | cut -f7)
if [ "$status" = keep ]; then
  ln -sfn "$c" lab/runs/champion
  echo "KEEP $c"
else
  git reset -q --hard "$start"
  echo "DISCARD $c"
fi
