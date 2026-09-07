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


# A workflow can parse as YAML and still be rejected whole by GitHub, which fails the same
# way: no job is scheduled and there is nothing to read a failure from. The one that got
# through was `name: Test on Nargo ${{ env.NOIR_VERSION }}` -- a job `name:` may only read
# github, inputs, matrix, needs, strategy and vars, and `env` there is a file-level error,
# not a job-level one. So parsing is necessary and not sufficient; check the expressions a
# job name is allowed to contain, and check that a `matrix.` reference has a matrix behind
# it, which is how a matrix that was deleted leaves a name interpolating nothing.
ruby -ryaml -e '
  allowed = %w[github inputs matrix needs strategy vars]
  bad = []
  Dir[".github/workflows/*.yml", ".github/workflows/*.yaml"].sort.each do |f|
    doc = (YAML.load_file(f) rescue next)
    next unless doc.is_a?(Hash) && doc["jobs"].is_a?(Hash)
    doc["jobs"].each do |id, job|
      next unless job.is_a?(Hash)
      name = job["name"]
      next unless name.is_a?(String)
      name.scan(/\$\{\{(.+?)\}\}/) do |expr|
        ctx = expr.first.strip[/\A([A-Za-z_][A-Za-z0-9_-]*)/, 1]
        next if ctx.nil?
        unless allowed.include?(ctx)
          bad << "#{f}: job #{id}: name reads the #{ctx} context, which GitHub does not " \
                 "allow there (only #{allowed.join(", ")})"
          next
        end
        if ctx == "matrix" && !(job.dig("strategy", "matrix"))
          bad << "#{f}: job #{id}: name reads matrix.* but the job has no strategy.matrix"
        end
      end
    end
  end
  bad.each { |b| puts "INVALID #{b}" }
  abort unless bad.empty?
  puts "ok      job names only use contexts GitHub allows there"
' || status=1

# actionlint knows the rest of the schema, but it is not installed everywhere and this
# check must still run without it. Say so when it is skipped, so a silent skip is not
# mistaken for a pass.
if command -v actionlint >/dev/null 2>&1; then
  if actionlint -shellcheck= -pyflakes= .github/workflows/*.yml; then
    echo "ok      actionlint"
  else
    status=1
  fi
else
  echo "skip    actionlint not installed (brew install actionlint)"
fi

exit $status
