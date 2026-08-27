#!/usr/bin/env bash
#
# Parse every workflow file with a real YAML parser.
#
# An invalid workflow does not fail a job -- it stops GitHub from scheduling ANY job, so
# the repository silently loses all of its CI while the branch looks untested rather than
# broken. Nothing inside CI can catch that, because nothing inside CI runs.
#
# This exists because a `run:` value ending in `::` (a `nargo test <module>::` filter) is
# read by YAML as a mapping indicator and takes the whole file down. Grepping the file
# with a regex is not a substitute for parsing it; that is exactly what let it through.
#
# Ruby ships with macOS and is on the GitHub runners, so this needs no install.
set -uo pipefail
cd "$(dirname "$0")/.."

status=0
for f in .github/workflows/*.yml .github/workflows/*.yaml; do
  [ -e "$f" ] || continue
  if msg=$(ruby -ryaml -e "YAML.load_file('$f')" 2>&1); then
    echo "ok      $f"
  else
    echo "INVALID $f"
    echo "$msg" | sed 's/^/        /'
    status=1
  fi
done

# The status job lists its dependencies by hand, so a job that is added without being
# listed there passes the branch even when it fails.
ruby -ryaml -e '
  d = YAML.load_file(".github/workflows/test.yml")
  jobs = d["jobs"].keys - ["tests-end"]
  needs = d["jobs"]["tests-end"]["needs"]
  missing = jobs - needs
  unknown = needs - d["jobs"].keys
  abort("tests-end does not gate on: #{missing.join(", ")}") unless missing.empty?
  abort("tests-end needs jobs that do not exist: #{unknown.join(", ")}") unless unknown.empty?
  puts "ok      tests-end gates on every job"
' || status=1

exit $status
