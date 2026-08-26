#!/usr/bin/env python3
"""Regenerate the lookup tables in `src/json_tables.nr`.

`src/json_tables.nr` is generated. The `test_make*` tests
*verify* the committed tables against the sub-tables in
`src/_table_generation/make_tables_subtables.nr`, but nothing that *prints* a
new one, so a change to the sub-tables used to leave you hand-editing 4096
literals. The `emit_table_*` tests print them; this script
splices their output back in.

    cd <package root>
    nargo test --show-output emit_table_ | grep '^EMIT ' > /tmp/tables.txt
    python3 scripts/splice_tables.py /tmp/tables.txt src/json_tables.nr
    nargo test test_make          # the verifiers are now the regression check

Optional extra arguments restrict the splice to the named tables.

Growing a table (adding a capture mode, say) is a chicken-and-egg problem: the
`test_make*` verifiers will not compile while the sizes disagree. Resize the
global to the new length with placeholder `0x00` entries first, run the
emitters, then splice.

The output reproduces `nargo fmt`'s array layout -- arrays whose widest element
is at most 10 characters are filled greedily to 100 columns, wider ones get one
element per line -- so a regenerated file is byte-identical to a formatted one.
Verified against the committed tables: re-emitting and re-splicing them
is a no-op.
"""
import collections
import re
import sys

emit_path, tables_path = sys.argv[1], sys.argv[2]
only = set(sys.argv[3:]) or None

values = collections.defaultdict(dict)
for line in open(emit_path):
    if not line.startswith("EMIT "):
        continue
    _, name, index, value = line.split()
    values[name][int(index)] = value

source = open(tables_path).read()


def render(items, indent="    "):
    width = max(len(x) for x in items)
    out = []
    if width > 10:
        return "\n".join(f"{indent}{x}," for x in items)
    line = indent
    for x in items:
        candidate = (line + x + ",") if line == indent else (line + " " + x + ",")
        if len(candidate) > 100:
            out.append(line.rstrip())
            line = indent + x + ","
        else:
            line = candidate
    if line.strip():
        out.append(line.rstrip())
    return "\n".join(out)


for name, by_index in values.items():
    if only and name not in only:
        continue
    n = max(by_index) + 1
    assert set(by_index) == set(range(n)), f"{name}: emitter output has holes"
    items = [by_index[i] for i in range(n)]
    pattern = re.compile(
        r"(pub\(crate\) global " + name + r": \[(?:Field|u8|bool); )([^\]]+)(\] = \[\n)(.*?)(\n\];)",
        re.S,
    )
    m = pattern.search(source)
    if not m:
        sys.exit(f"{name}: not found in {tables_path}")
    size = m.group(2)
    # keep symbolic sizes (NUM_TOKENS_MUL_2), rewrite numeric ones
    new_size = str(n) if size.strip().isdigit() else size
    source = (
        source[: m.start()]
        + m.group(1) + new_size + m.group(3) + render(items) + m.group(5)
        + source[m.end():]
    )

open(tables_path, "w").write(source)
print("spliced:", ", ".join(sorted(k for k in values if not only or k in only)))
