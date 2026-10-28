#!/usr/bin/env bash
# Usage: bench/bench.sh CORPUS_DIR [RUNS]
# Times (warm page cache, median of RUNS) hashing every file in CORPUS_DIR with:
#   1. find | xargs sha256sum           (single process)
#   2. find | xargs -P$(nproc) sha256sum (parallel)
#   3. hashdog baseline                  (full Merkle build + sign + JSON write)
#   4. go test -bench: full build vs stat-cached rescan (what an fsnotify event costs)
set -euo pipefail
DIR=${1:?corpus dir}; RUNS=${2:-7}
cd "$(dirname "$0")/.."
BIN=$(mktemp -d)/hashdog; go build -o "$BIN" .
K=$(dirname "$BIN")/k; "$BIN" keygen -out "$K" >/dev/null
median() { python3 -c 'import sys,statistics as s;v=[float(x) for x in sys.argv[1:]];print(f"{s.median(v)*1000:.0f} ms (min {min(v)*1000:.0f}, max {max(v)*1000:.0f})")' "$@"; }
timeit() { local t=(); for ((i=0;i<RUNS;i++)); do local s=$(date +%s.%N); "$@" >/dev/null; t+=($(python3 -c "print($(date +%s.%N)-$s)")); done; median "${t[@]}"; }
find "$DIR" -type f | wc -l | xargs echo "files:"; du -sm "$DIR" | cut -f1 | xargs echo "MB:"
find "$DIR" -type f >/dev/null; cat "$DIR"/*/* >/dev/null   # warm cache
echo -n "find|xargs sha256sum:        "; timeit bash -c "find '$DIR' -type f -print0 | xargs -0 sha256sum"
echo -n "find|xargs -P sha256sum:     "; timeit bash -c "find '$DIR' -type f -print0 | xargs -0 -P$(nproc) -n200 sha256sum"
echo -n "hashdog baseline (full):     "; timeit "$BIN" baseline -dir "$DIR" -key "$K.key" -out "$(dirname "$BIN")/b.json"
HASHDOG_BENCH_DIR=$DIR go test ./internal/merkle -run '^$' -bench . -benchtime=5x 2>&1 | grep -E 'Benchmark|cpu'
