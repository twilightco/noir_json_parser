#!/usr/bin/env bash
#
# Run the compiler's missing-Brillig-constraint check where it can actually see anything.
#
# `bug: Brillig function call isn't properly covered by a manual constraint` is the
# compiler telling us a value produced by an unconstrained function reaches constrained
# code without being pinned to its inputs -- the exact shape of every soundness bug in
# this repository's history. It is on by default, and `--skip-brillig-constraints-check`
# should never be used here.
#
# But it runs during compilation, on MONOMORPHISED code. A library has no `main` and
# nothing concrete to compile, so it never reaches the lint at all:
#
#     nargo check           on the library     -> misses it
#     nargo test            on the library     -> misses it
#     nargo compile         on a bin consumer  -> catches it
#
# Measured, not assumed: `scripts/brillig-check/canary.py` inserts a call that is
# genuinely uncovered, and only the third command reports it. A CI job that greps
# `nargo check` output for `^bug:` therefore cannot fail, which is worse than no job --
# it is a green tick that means nothing.
#
# So this script does two things:
#
#   1. compiles a real bin consumer of the library and fails on any `bug:`
#   2. compiles the SAME consumer against a copy of the library with the canary applied,
#      and fails if the lint does NOT fire
#
# Step 2 is the one that keeps step 1 honest. Without it, a future toolchain that quietly
# drops the lint would turn this job green forever.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC="$ROOT/scripts/brillig-check"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; git -C "$ROOT" worktree prune' EXIT

# A package under the library's own directory is not resolvable as a separate crate, so
# the consumer is materialised outside it, pointing back by path.
make_pkg() {   # <dir> <library-path> <main.nr> <Prover.toml>
  mkdir -p "$1/src"
  cp "$3" "$1/src/main.nr"
  cp "$4" "$1/Prover.toml"
  cat > "$1/Nargo.toml" <<EOF
[package]
name = "consumer"
type = "bin"
authors = [""]
compiler_version = ">=1.0.0"

[dependencies]
json_parser = { path = "$2" }
EOF
}

status=0

# --- 1: the real library must be clean -------------------------------------------
echo "== the library, compiled as a consumer would compile it"
make_pkg "$WORK/real" "$ROOT" "$SRC/main.nr" "$SRC/Prover.toml"
( cd "$WORK/real" && nargo compile --force ) >"$WORK/real.log" 2>&1
if ! [ -f "$WORK/real/target/consumer.json" ]; then
  echo "   FAIL: the consumer did not compile at all -- the check proves nothing"
  sed -n '1,20p' "$WORK/real.log" | sed 's/^/     /'
  status=1
elif grep -qE '^bug:' "$WORK/real.log"; then
  echo "   FAIL: missing Brillig constraint"
  grep -A6 '^bug:' "$WORK/real.log" | sed 's/^/     /'
  status=1
else
  echo "   clean"
fi

# --- 2: and the check must still be capable of failing ----------------------------
echo "== canary: an uncovered call the lint is required to catch"
git -C "$ROOT" worktree add -f --detach "$WORK/canary-lib" HEAD >/dev/null 2>&1
( cd "$WORK/canary-lib" && python3 - "$SRC/canary.py" <<'PY'
import sys, runpy
spec = runpy.run_path(sys.argv[1])
for path, old, new in [(spec["apply_to"], spec["old"], spec["new"])] + list(spec.get("also", [])):
    s = open(path).read()
    if old not in s:
        raise SystemExit("canary does not apply to " + path)
    open(path, "w").write(s.replace(old, new, 1))
PY
) || { echo "   FAIL: could not apply the canary"; status=1; }

make_pkg "$WORK/canary" "$WORK/canary-lib" "$SRC/canary_main.nr" "$SRC/canary_Prover.toml"
( cd "$WORK/canary" && nargo compile --force ) >"$WORK/canary.log" 2>&1
if grep -qE '^bug:' "$WORK/canary.log"; then
  echo "   caught, as required"
else
  echo "   FAIL: the lint did not fire on a call that is definitely uncovered."
  echo "         This check is no longer evidence of anything. Do not trust step 1"
  echo "         until this is understood -- the toolchain may have dropped the lint."
  sed -n '1,20p' "$WORK/canary.log" | sed 's/^/     /'
  status=1
fi

exit $status
