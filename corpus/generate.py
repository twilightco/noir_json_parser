#!/usr/bin/env python3
"""Build the conformance corpus and the Noir test file that runs it.

Every case is decided by Python's `json` module -- an independent implementation --
and the generated Noir tests assert that this parser agrees. That is the differential:
two parsers, one corpus, and a committed baseline so a disagreement that appears later
is a diff someone has to justify rather than a silent behaviour change.

Where the two are *expected* to disagree, the case carries a `deviation` naming the
reason. Those are the documented limits of this library, and the generated test asserts
the deviation still holds -- so if one is ever closed, this file fails and says which.

    python3 corpus/generate.py          # rewrite corpus/cases.json and src/conformance.nr
    python3 corpus/generate.py --check  # fail if either is out of date

`corpus/cases.json` is the baseline. It is committed; `git diff` on it is the record of
every accept/reject decision that ever changed.

The committed corpus is sized for CI. To search harder, raise the fuzz count -- it costs
nothing but time, and the generated tests are not meant to be committed at that size:

    FUZZ_COUNT=2000 python3 corpus/generate.py && nargo test conformance::

A sweep of 1,469 cases (1,310 of them generated) has been run at that setting against
this parser. It found one disagreement, `{"a":"\x7f"}`, which was a real bug and is
fixed; everything else either agreed or was explained by one of the four derived
deviations below.
"""
import json
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# ---------------------------------------------------------------------------------
# deviations: where this parser and a reference parser are expected to differ
# ---------------------------------------------------------------------------------
#
# A deviation is *derived* from the document, never hand-tagged. That is what makes the
# fuzz half of the corpus worth anything: a generated document nobody looked at is
# classified by the same rules as a hand-written one, so a disagreement the rules do not
# explain is a finding rather than a case somebody forgot to annotate.

SCALAR_ROOT = "scalar-root"
OPAQUE_UTF8 = "opaque-utf8"
DUPLICATE_KEYS = "duplicate-keys"
KEY_CAPACITY = "key-capacity"
NESTING_DEPTH = "nesting-depth"

DEVIATIONS = {
    SCALAR_ROOT: "the root must be an object or an array",
    OPAQUE_UTF8: "bytes >= 0x80 are opaque content, not validated as UTF-8",
    DUPLICATE_KEYS: "parse_json does not reject duplicate keys; assert_no_duplicate_keys is the caller's",
    KEY_CAPACITY: "a key is bounded by MaxKeyFields * 31, which is 62 bytes by default",
    NESTING_DEPTH: "the context stack holds 32 levels",
}

MAX_KEY_BYTES = 62
MAX_DEPTH = 31


class Dup(Exception):
    pass


def _no_dupes(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise Dup()
    return dict(pairs)


def _reference(raw):
    """Decode with an independent parser. Returns (accepted, value, had_duplicate_key)."""
    def reject_constant(_):
        raise ValueError("non-standard constant")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False, None, False
    try:
        return True, json.loads(text, parse_constant=reject_constant,
                                object_pairs_hook=_no_dupes), False
    except Dup:
        # valid JSON, just not something we want silently collapsed
        try:
            return True, json.loads(text, parse_constant=reject_constant), True
        except Exception:
            return False, None, True
    except Exception:
        return False, None, False


def _walk(value, depth=0):
    """(max nesting depth, longest key in bytes)"""
    if isinstance(value, dict):
        d, k = depth, 0
        for key, sub in value.items():
            k = max(k, len(key.encode("utf-8")))
            sd, sk = _walk(sub, depth + 1)
            d, k = max(d, sd), max(k, sk)
        return d, k
    if isinstance(value, list):
        d, k = depth, 0
        for sub in value:
            sd, sk = _walk(sub, depth + 1)
            d, k = max(d, sd), max(k, sk)
        return d, k
    return depth, 0


def classify(raw):
    """What this parser must do with these bytes, and every reason it differs.

    High bytes are modelled by mapping them to `z`: inside a string they are ordinary
    content, and outside one they are an error, which is exactly what `z` is. So the
    reference run on the mapped bytes predicts this parser, and any difference between
    the two runs is the opaque-UTF-8 deviation and nothing else.
    """
    devs = []
    text_ok, _, text_dup = _reference(raw)
    model = bytes(b if b < 0x80 else ord("z") for b in raw)
    model_ok, value, model_dup = _reference(model)

    if model_ok != text_ok:
        devs.append(OPAQUE_UTF8)

    expect = model_ok
    if expect:
        if not isinstance(value, (dict, list)):
            devs.append(SCALAR_ROOT)
            expect = False
        else:
            depth, key_len = _walk(value)
            if key_len > MAX_KEY_BYTES:
                devs.append(KEY_CAPACITY)
                expect = False
            if depth > MAX_DEPTH:
                devs.append(NESTING_DEPTH)
                expect = False
    if model_dup or text_dup:
        devs.append(DUPLICATE_KEYS)

    return expect, text_ok, devs


# ---------------------------------------------------------------------------------
# the corpus
# ---------------------------------------------------------------------------------

def slug(s):
    """A name fragment that survives becoming a Noir identifier without colliding.

    `1e5`, `1E5`, `1e+5` and `1e-5` are four different documents and must stay four
    different names; a naive sanitiser maps all four onto the same identifier."""
    special = {"+": "plus", "-": "neg", ".": "dot", " ": "sp", "_": "us",
               "\\": "bs", '"': "dq", "'": "sq", "/": "fs", "\t": "tab",
               "\n": "nl", "\r": "cr", "\x00": "nul"}
    out = []
    for ch in s:
        if ch.isdigit() or (ch.isalpha() and ch.islower() and ch.isascii()):
            out.append(ch)
        elif ch.isalpha() and ch.isascii():
            out.append("cap" + ch.lower())
        else:
            out.append(special.get(ch, "x%02x" % ord(ch)))
    return "".join(out)


def handwritten():
    """Cases chosen to sit on a boundary of the grammar, one per line of it."""
    c = []

    def case(name, doc, _unused=None):
        # deviations are derived in `classify`, never declared here
        c.append({"name": name, "doc": doc})

    # --- structure -----------------------------------------------------------
    case("empty-object", '{}')
    case("empty-array", '[]')
    case("one-pair", '{"a":1}')
    case("nested-object", '{"a":{"b":{"c":1}}}')
    case("nested-array", '[[1,[2,[3]]]]')
    case("object-in-array", '[{"a":1},{"b":2}]')
    case("array-in-object", '{"a":[1,2,3]}')
    case("empty-nested", '{"a":{},"b":[]}')
    case("trailing-comma-object", '{"a":1,}')
    case("trailing-comma-array", '[1,2,]')
    case("missing-comma", '{"a":1"b":2}')
    case("missing-colon", '{"a"1}')
    case("double-colon", '{"a"::1}')
    case("extra-close-brace", '{"a":1}}')
    case("extra-close-bracket", '[1,2]]')
    case("unclosed-object", '{"a":1')
    case("unclosed-array", '[1,2')
    case("mismatched-close", '{"a":1]')
    case("bare-comma", '{,}')
    case("leading-comma-array", '[,1]')
    case("unquoted-key", '{a:1}')
    case("single-quoted-key", "{'a':1}")
    case("single-quoted-value", "{\"a\":'b'}")
    case("duplicate-key", '{"a":1,"a":2}')

    # --- scalar roots (valid JSON, unsupported here) -------------------------
    for name, doc in [("root-number", "1"), ("root-string", '"a"'),
                      ("root-true", "true"), ("root-null", "null")]:
        case(name, doc, SCALAR_ROOT)

    # --- numbers -------------------------------------------------------------
    for n in ["0", "-0", "1", "-1", "12345", "1.5", "-1.5", "0.5", "-0.0",
              "1e5", "1E5", "1e+5", "1e-5", "2e+10", "1.5E-3", "1e05", "0e0",
              "18446744073709551615", "99999999999999999999",
              "123456789012345678901234567890"]:
        case("num-ok-" + slug(n), '{"a":%s}' % n)
    for n in ["01", "00", "-01", "1.", ".5", "-.5", "+1", "-", "1..2", "1.2.3",
              "1e", "1e-", "1e+", "1e++2", "1e2e3", "1e2.5", "-e5", "1-2",
              "0x1F", "1_000", "Infinity", "-Infinity", "NaN", "1 2"]:
        case("num-bad-" + slug(n), '{"a":%s}' % n)

    # --- literals ------------------------------------------------------------
    for n in ["true", "false", "null"]:
        case("lit-" + slug(n), '{"a":%s}' % n)
    for n in ["True", "FALSE", "nul", "nulll", "tru", "undefined", "None"]:
        case("lit-bad-" + slug(n), '{"a":%s}' % n)

    # --- strings and escapes -------------------------------------------------
    case("str-empty", '{"a":""}')
    case("str-plain", '{"a":"hello world"}')
    case("str-punctuation", '{"a":"!@#$%^&*()_+-=[]{};:,.<>?/|~`"}')
    for e in ['\\"', '\\\\', '\\/', '\\b', '\\f', '\\n', '\\r', '\\t']:
        case("esc-ok-" + slug(e[1:]), '{"a":"x%sy"}' % e)
    for u in ['\\u0041', '\\u00e9', '\\uABCD', '\\uabcd', '\\u0F9f', '\\uD800', '\\u0000']:
        case("esc-u-" + slug(u[2:]), '{"a":"%s"}' % u)
    for e in ['\\q', "\\'", '\\a', '\\v', '\\0', '\\x41', '\\U0041']:
        case("esc-bad-" + slug(e[1:]), '{"a":"x%sy"}' % e)
    for u in ['\\u12', '\\u00zz', '\\u00fg', '\\u', '\\u123']:
        case("esc-bad-u-" + slug(u[2:]), '{"a":"%s"}' % u)
    case("esc-trailing-backslash", '{"a":"x\\"}')
    case("esc-double-backslash-then-n", '{"a":"\\\\n"}')
    case("esc-four-backslashes", '{"a":"\\\\\\\\"}')
    case("esc-in-key", '{"a\\nb":1}')
    case("esc-bad-in-key", '{"a\\qb":1}')
    case("esc-u-in-key", '{"a\\u0041":1}')

    # --- raw control bytes ---------------------------------------------------
    for code, label in [(0x00, "nul"), (0x09, "tab"), (0x0A, "lf"), (0x0D, "cr"),
                        (0x1F, "us"), (0x7F, "del")]:
        case("ctrl-in-string-" + label, '{"a":"x%sy"}' % chr(code))
    case("ws-between-tokens", '{ "a" :\t1 ,\r\n"b" : 2 }')
    case("ws-leading-trailing", '   {"a":1}   ')
    for code, label in [(0x0B, "vt"), (0x0C, "ff")]:
        case("ws-bad-" + label, '{%s"a":1}' % chr(code))

    # --- high bytes ----------------------------------------------------------
    case("utf8-two-byte", '{"a":"é"}')
    case("utf8-three-byte", '{"a":"€"}')
    case("utf8-four-byte", '{"a":"\U0001F600"}')
    case("utf8-in-key", '{"é":1}')
    # malformed byte sequences: written as raw bytes, so they are latin-1 escaped below
    case("utf8-bad-lone-continuation", '{"a":"\udcc3"}')
    case("utf8-bad-truncated", '{"a":"\udce2\udc82"}')
    case("utf8-bad-overlong", '{"a":"\udcc0\udcaf"}')
    case("utf8-bad-surrogate", '{"a":"\udced\udca0\udc80"}')
    case("high-byte-outside-string", '{"a":\udcc3}')

    # --- keys ----------------------------------------------------------------
    case("key-empty", '{"":1}')
    for n in [1, 30, 31, 32, 61]:
        case("key-len-%d" % n, '{"%s":1}' % ("k" * n))
    case("key-len-62", '{"%s":1}' % ("k" * 62))
    case("key-len-63", '{"%s":1}' % ("k" * 63))

    return c


def fuzz(seed, count):
    """Randomly generated and randomly mutated documents.

    Two sources. Generated documents explore shapes a hand-written list will not think
    of; mutations of valid documents explore the neighbourhood of the accept/reject
    boundary, which is where a parser disagreement actually lives.
    """
    rng = random.Random(seed)
    out = []

    ATOMS = ['1', '0', '-1', '1.5', '-0.5', '1e3', '"s"', '""', 'true', 'false',
             'null', '"\\n"', '"\\u0041"', '"é"']
    KEYS = ['a', 'bb', 'ccc', 'k' * 31, 'k' * 62, 'é', 'with space', '\\n']

    def value(depth):
        if depth <= 0 or rng.random() < 0.5:
            return rng.choice(ATOMS)
        if rng.random() < 0.5:
            n = rng.randint(0, 3)
            return '[' + ','.join(value(depth - 1) for _ in range(n)) + ']'
        n = rng.randint(0, 3)
        items = ['"%s":%s' % (rng.choice(KEYS), value(depth - 1)) for _ in range(n)]
        return '{' + ','.join(items) + '}'

    def document():
        return value(3) if rng.random() < 0.2 else (
            '{' + ','.join('"%s":%s' % (rng.choice(KEYS), value(2))
                           for _ in range(rng.randint(1, 4))) + '}')

    MUTATIONS = list('{}[]",:.\\eE+-0198 \t\n')

    for i in range(count):
        doc = document()
        if i % 2 == 1 and len(doc) > 2:
            # mutate: replace, insert, or delete one byte
            pos = rng.randrange(len(doc))
            kind = rng.randrange(3)
            if kind == 0:
                doc = doc[:pos] + rng.choice(MUTATIONS) + doc[pos + 1:]
            elif kind == 1:
                doc = doc[:pos] + rng.choice(MUTATIONS) + doc[pos:]
            else:
                doc = doc[:pos] + doc[pos + 1:]
        out.append({"name": "fuzz-%04d" % i, "doc": doc})
    return out


# ---------------------------------------------------------------------------------
# emitting
# ---------------------------------------------------------------------------------

BUFFER = 128          # every document is space-padded to this, so one JSON type serves
                      # every case and the suite pays for one monomorphisation
MAX_TOKENS = 160      # generous: 128 bytes at maximum density is a token every 2 bytes
MAX_VALUES = 81
PACKED = (BUFFER + 30) // 31 + 3


def to_bytes(doc):
    """The document as raw bytes. Lone surrogates in the source stand for raw bytes that
    are not valid UTF-8, which is exactly what the malformed-UTF-8 cases need."""
    return doc.encode("utf-8", "surrogateescape")


def build():
    cases = handwritten() + fuzz(seed=20260826, count=FUZZ_COUNT)

    seen, out = set(), []
    for c in cases:
        raw = to_bytes(c["doc"])
        if len(raw) > BUFFER:
            continue
        if raw in seen:
            continue
        seen.add(raw)
        expect, reference, devs = classify(raw)
        out.append({
            "name": c["name"],
            "bytes": list(raw),
            "reference_accepts": reference,
            "expect_accept": expect,
            "deviations": devs,
        })
    return out


def expected(case):
    return case["expect_accept"]


HEADER = '''//! Conformance corpus. GENERATED -- do not edit; run `python3 corpus/generate.py`.
//!
//! Every case is decided by an independent reference parser, and each test below asserts
//! that this parser agrees. `corpus/cases.json` is the committed baseline: a diff on it
//! is the record of an accept/reject decision changing, which is a thing someone has to
//! justify rather than notice later.
//!
//! Cases carrying a `deviation` are the documented limits of this library, where the two
//! parsers are *expected* to disagree. Those tests assert the deviation still holds, so
//! closing one fails here and names itself.
//!
//! Every document is space-padded to a single buffer size, so the whole corpus shares one
//! `JSON` instantiation instead of monomorphising the parser once per case.
use crate::json::JSON;

type Case = JSON<{buffer}, {packed}, {tokens}, {values}, 2>;
'''

ACCEPT_TEMPLATE = '''
#[test]
fn accept_{ident}() {{
    let _: Case = JSON::parse_json({body});
}}
'''

REJECT_TEMPLATE = '''
#[test(should_fail)]
fn reject_{ident}() {{
    let _: Case = JSON::parse_json({body});
}}
'''


def ident(name):
    return "".join(ch if ch.isalnum() else "_" for ch in name).strip("_").lower()


def render_bytes(bs):
    padded = list(bs) + [32] * (BUFFER - len(bs))
    body = ", ".join(str(b) for b in padded)
    lines, line = [], "        "
    for tok in body.split(", "):
        candidate = (line + tok + ",") if line.strip() == "" else (line + " " + tok + ",")
        if len(candidate) > 100:
            lines.append(line.rstrip())
            line = "        " + tok + ","
        else:
            line = candidate
    lines.append(line.rstrip())
    # trailing comma on the last element: this is what `nargo fmt` emits, and the
    # generated file has to survive `nargo fmt --check` unchanged or the format job and
    # the baseline job spend their lives undoing each other
    return "[\n" + "\n".join(lines) + "\n    ]"


def emit(cases):
    idents = [ident(c["name"]) for c in cases]
    dupes = {i for i in idents if idents.count(i) > 1}
    if dupes:
        raise SystemExit("case names collide as identifiers: " + ", ".join(sorted(dupes)))

    parts = [HEADER.format(buffer=BUFFER, packed=PACKED,
                           tokens=MAX_TOKENS, values=MAX_VALUES)]
    for c in cases:
        tmpl = ACCEPT_TEMPLATE if expected(c) else REJECT_TEMPLATE
        note = ""
        if c["deviations"]:
            verb = "accepts" if c["reference_accepts"] else "rejects"
            agree = "and so do we" if c["reference_accepts"] == expected(c) else "we do not"
            lines = ["/// the reference %s this; %s:" % (verb, agree)]
            lines += ["///   %s: %s" % (d, DEVIATIONS[d]) for d in c["deviations"]]
            note = "\n" + "\n".join(lines) + "\n"
        parts.append(note + tmpl.format(ident=ident(c["name"]),
                                        body=render_bytes(c["bytes"])))
    return "".join(parts)


FUZZ_COUNT = int(os.environ.get("FUZZ_COUNT", "150"))

if __name__ == "__main__":
    check = "--check" in sys.argv
    cases = build()
    cases_json = json.dumps(cases, indent=2, sort_keys=True) + "\n"
    nr = emit(cases)

    cases_path = os.path.join(HERE, "cases.json")
    nr_path = os.path.join(ROOT, "src", "conformance.nr")

    if check:
        bad = False
        for path, want in [(cases_path, cases_json), (nr_path, nr)]:
            have = open(path).read() if os.path.exists(path) else None
            if have != want:
                print("out of date: " + os.path.relpath(path, ROOT))
                bad = True
        sys.exit(1 if bad else 0)

    open(cases_path, "w").write(cases_json)
    open(nr_path, "w").write(nr)
    n_accept = sum(1 for c in cases if expected(c))
    n_dev = sum(1 for c in cases if c["deviations"])
    print("%d cases: %d accept, %d reject, %d deviations"
          % (len(cases), n_accept, len(cases) - n_accept, n_dev))
