#!/usr/bin/env bash
#
# perf-flame.sh — collect a perf profile and build a flame graph
#                 for an already-built binary (no compilation)
#
# Usage:
#   ./perf-flame.sh <path_to_binary> [program arguments...]
#
# Example:
#   ./perf-flame.sh ./build/my_app --input data.txt
#
set -euo pipefail

# ---------- settings ----------
FLAMEGRAPH_DIR="${FLAMEGRAPH_DIR:-$HOME/FlameGraph}"
OUT_DIR="${OUT_DIR:-./perf-out}"
PERF_FREQ="${PERF_FREQ:-999}"

# ---------- checks ----------
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <binary> [program arguments...]" >&2
    exit 1
fi

BIN="$1"; shift
PROG_ARGS=("$@")

if [[ ! -f "$BIN" ]]; then
    echo "Error: file '$BIN' not found" >&2
    exit 1
fi

if [[ ! -x "$BIN" ]]; then
    echo "Error: '$BIN' is not executable (chmod +x?)" >&2
    exit 1
fi

if ! command -v perf >/dev/null 2>&1; then
    echo "Error: 'perf' is not installed (sudo apt install linux-perf)" >&2
    exit 1
fi

# ---------- FlameGraph: clone if missing ----------
if [[ ! -x "$FLAMEGRAPH_DIR/flamegraph.pl" ]]; then
    echo ">>> Cloning FlameGraph into $FLAMEGRAPH_DIR"
    git clone --depth 1 https://github.com/brendangregg/FlameGraph.git "$FLAMEGRAPH_DIR"
fi

# ---------- prepare output directory ----------
mkdir -p "$OUT_DIR"
PERF_DATA="$OUT_DIR/perf.data"
rm -f "$PERF_DATA"

# ---------- profiling ----------
echo ">>> Collecting profile (perf record, freq=$PERF_FREQ Hz)"
echo "    binary: $BIN"
echo "    arguments: ${PROG_ARGS[*]:-<none>}"

# -g           : collect call graph
# -F           : sampling frequency
# -o           : output file
# --call-graph : stack type (fp = frame pointer)
perf record -g -F "$PERF_FREQ" --call-graph fp -o "$PERF_DATA" \
    -- "$BIN" "${PROG_ARGS[@]}"

# ---------- build flame graph ----------
echo ">>> Building flame graph"
FOLDED="$OUT_DIR/perf.folded"
SVG="$OUT_DIR/flamegraph.svg"

perf script -i "$PERF_DATA" \
    | "$FLAMEGRAPH_DIR/stackcollapse-perf.pl" \
    > "$FOLDED"

"$FLAMEGRAPH_DIR/flamegraph.pl" \
    --title "Flame Graph: $(basename "$BIN")" \
    "$FOLDED" > "$SVG"

# ---------- console report ----------
echo
echo ">>> Top functions by CPU (perf report --stdio)"
perf report -i "$PERF_DATA" --stdio --percent-limit 1 2>/dev/null \
    | head -n 40 || true

# ---------- open the result ----------
echo
echo ">>> Done:"
echo "    SVG   : $SVG"
echo "    Folded: $FOLDED"
echo "    Data  : $PERF_DATA"
