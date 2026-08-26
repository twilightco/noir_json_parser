#!/usr/bin/env bash
#
# Does the proof system agree with the ACVM?
#
# Every soundness claim in this repository is checked by `nargo test`, which runs the
# ACVM. That is only worth anything if the ACVM is not *stricter* than the proving
# backend -- if it were, a circuit `nargo test` accepts might still be unsatisfiable in a
# real proof, and, far worse, our evidence that a constraint is missing would be evidence
# about the wrong system.
#
# So for each attack under `scripts/attacks/`:
#
#   1. build the library as it stood BEFORE the fix, apply the attack's patch (if it has
#      one -- some attacks need no lie at all), and run the driver circuit.
#      `nargo execute` must SUCCEED: the constraint system is satisfiable.
#   2. `bb write_vk`, `bb prove`, `bb verify` on that witness must SUCCEED. This is the
#      claim being tested: where the ACVM accepted, the proof system accepts too.
#   3. build the library at HEAD, apply the same patch, run the same driver.
#      `nargo execute` must FAIL, with the message the fix introduced.
#
# An attack that fails step 1 or 2 means the experiment is not measuring what it thinks.
# An attack that fails step 3 means the fix does not hold.
#
# Usage:  scripts/proof-system-check.sh [attack-name ...]
#
# Needs `bb` on PATH or in ~/.bb. Slow: each attack builds the library twice and proves
# once, so budget a couple of minutes each.
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BB=${BB:-$(command -v bb || echo "$HOME/.bb/bb")}
WORK=${WORK:-$(mktemp -d)}
trap '[ -n "${KEEP:-}" ] || rm -rf "$WORK"; git -C "$ROOT" worktree prune' EXIT

[ -x "$BB" ] || { echo "bb not found (set BB=/path/to/bb)"; exit 1; }

attacks=("$@")
if [ ${#attacks[@]} -eq 0 ]; then
  attacks=($(ls "$ROOT/scripts/attacks"))
fi

pass=0
fail=0

# Resolve a fix commit by its subject rather than its hash, so the harness survives a
# rebase. The library "before the fix" is that commit's parent.
base_of() {
  local subject="$1"
  local c
  c=$(git -C "$ROOT" log --format='%H %s' HEAD | grep -F -- "$subject" | head -1 | cut -d' ' -f1)
  [ -n "$c" ] || return 1
  git -C "$ROOT" rev-parse "$c^"
}

build_library() {   # <dest> <commit> <attack-dir>
  local dest="$1" commit="$2" dir="$3"
  git -C "$ROOT" worktree add -f --detach "$dest" "$commit" >/dev/null 2>&1 || return 1
  if [ -f "$dir/patch.py" ]; then
    ( cd "$dest" && python3 - "$dir/patch.py" <<'PY'
import sys, runpy
spec = runpy.run_path(sys.argv[1])
edits = [(spec["apply_to"], spec["old"], spec["new"])] + list(spec.get("also", []))
for path, old, new in edits:
    s = open(path).read()
    if old not in s:
        raise SystemExit("patch does not apply to " + path)
    open(path, "w").write(s.replace(old, new, 1))
PY
    ) || return 1
  fi
}

make_driver() {   # <dest> <library> <attack-dir>
  local dest="$1" lib="$2" dir="$3"
  mkdir -p "$dest/src"
  cp "$dir/main.nr" "$dest/src/main.nr"
  cp "$dir/Prover.toml" "$dest/Prover.toml"
  cat > "$dest/Nargo.toml" <<EOF
[package]
name = "attack"
type = "bin"
authors = [""]
compiler_version = ">=1.0.0"

[dependencies]
json_parser = { path = "$lib" }
EOF
}

for name in "${attacks[@]}"; do
  dir="$ROOT/scripts/attacks/$name"
  [ -d "$dir" ] || { echo "no such attack: $name"; fail=$((fail+1)); continue; }

  subject=$(sed -n 's/^subject=//p' "$dir/meta")
  expect_reject=$(sed -n 's/^reject=//p' "$dir/meta")
  base=$(base_of "$subject") || { echo "FAIL $name: cannot resolve '$subject'"; fail=$((fail+1)); continue; }

  echo "== $name"
  echo "   before: $(git -C "$ROOT" rev-parse --short "$base")   after: $(git -C "$ROOT" rev-parse --short HEAD)"
  ok=1

  # --- 1 & 2: before the fix, the attack works, and the proof system agrees ---
  build_library "$WORK/$name-pre" "$base" "$dir" || { echo "   ! could not build the pre-fix library"; ok=0; }
  if [ $ok -eq 1 ]; then
    make_driver "$WORK/$name-pre-drv" "$WORK/$name-pre" "$dir"
    if ( cd "$WORK/$name-pre-drv" && nargo execute ) >"$WORK/$name.pre.log" 2>&1; then
      echo "   [1/3] pre-fix ACVM     accepts the attack"
    else
      echo "   [1/3] pre-fix ACVM     REJECTED -- the experiment is not set up right"
      sed -n '1,6p' "$WORK/$name.pre.log" | sed 's/^/         /'
      ok=0
    fi
  fi
  if [ $ok -eq 1 ]; then
    d="$WORK/$name-pre-drv"
    mkdir -p "$d/out"
    # bb resolves some defaults against the working directory, so run it from there
    if ( cd "$d" \
         && "$BB" write_vk -b target/attack.json -o target --scheme ultra_honk \
         && "$BB" prove -b target/attack.json -w target/attack.gz -o out --scheme ultra_honk \
         && "$BB" verify -k target/vk -p out/proof -i out/public_inputs --scheme ultra_honk \
       ) >>"$WORK/$name.pre.log" 2>&1; then
      echo "   [2/3] proof system     agrees: a proof of the attack verifies"
    else
      echo "   [2/3] proof system     DISAGREES with the ACVM -- see $WORK/$name.pre.log"
      ok=0
    fi
  fi

  # --- 3: at HEAD, the same attack is refused ---
  build_library "$WORK/$name-post" HEAD "$dir" || { echo "   ! could not build the current library"; ok=0; }
  if [ $ok -eq 1 ]; then
    make_driver "$WORK/$name-post-drv" "$WORK/$name-post" "$dir"
    if ( cd "$WORK/$name-post-drv" && nargo execute ) >"$WORK/$name.post.log" 2>&1; then
      echo "   [3/3] current ACVM     STILL ACCEPTS -- the fix does not hold"
      ok=0
    elif grep -qF -- "$expect_reject" "$WORK/$name.post.log"; then
      echo "   [3/3] current ACVM     rejects: $expect_reject"
    else
      echo "   [3/3] current ACVM     rejects, but not for the expected reason"
      grep -m1 "Assertion failed" "$WORK/$name.post.log" | sed 's/^/         /'
      ok=0
    fi
  fi

  if [ $ok -eq 1 ]; then pass=$((pass+1)); echo "   PASS"; else fail=$((fail+1)); echo "   FAIL"; fi
  echo
done

echo "$pass passed, $fail failed"
[ $fail -eq 0 ]
