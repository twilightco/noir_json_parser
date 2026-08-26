# noir_json_parser

A JSON parsing library for the Noir language.

Features:

- handles _arbitrary-length_ JSON documents (up to a defined maximum bound)
- a flexible interface that can process arbitrary JSON schemas
- O(1) queries for whether a key exists

> **This is a hardened fork.** It parses a stricter grammar than the original, closes six
> soundness issues, and states its guarantees explicitly. Start with
> [What a proof asserts](#what-a-proof-asserts).

## Noir version compatibility

Developed and tested against `nargo` 1.0.0-beta.26.

---

## What a proof asserts

> These bytes are a syntactically valid JSON document, and the values read out of it by
> the getters the circuit called are the values that document contains.

Three things it deliberately does **not** assert. Read these before relying on the
library — each one is a decision, and each one is somebody's job further up.

**It does not assert the bytes are text.** Bytes ≥ 0x80 are opaque inside strings and
keys: an overlong encoding, a truncated sequence or a lone surrogate all parse, and
`get_string` hands back the raw bytes. The circuit attests bytes and JSON structure, not
UTF-8. This is on purpose. In the setting this fork exists for, the bytes arrive over TLS
and the prover cannot choose them, so malformed UTF-8 is not an attack — it is a question
of what the verifier is promised. Validating the whole document would also make one bad
byte in a field nobody reads sink the entire proof. Where well-formedness matters, check
it on the values you actually compare.

**It does not assert keys are unique.** `{"a":1,"a":2}` parses. `assert_no_duplicate_keys`
exists, is sound and is cheap, but it is a method you call — not part of `parse_json`.

**It does not assert a string has been decoded.** `get_string` replaces seven escape
sequences (`\"` `\\` `\b` `\f` `\n` `\r` `\t`). `\/` and `\uXXXX` are validated as syntax
but come back as the raw bytes that spell them, and surrogate pairs are not paired. If
you compare decoded text, either finish the decoding or refuse strings containing a
backslash.

---

## What changed against the original

### Soundness

Six issues, each one commit with its own tests:

- `lte_field_240_bit` had the wrong false branch — it evaluated to zero when
  `y == x + 1`, so a prover could claim `x > y` for any two adjacent values.
- The root entry was checked but not counted: a second parentless entry could sit in the
  map, and the prover chose which one the verifier saw.
- Container identities were neither bounded nor unique, so an entry could be re-parented.
- A child pointer written twice carried into `num_children`, which is what every array
  bounds check compares against.
- The transcript past its logical length was unconstrained.
- Keys longer than `MaxKeyFields * 31` were silently truncated into the capacity, so two
  keys sharing a 62-byte prefix shared a hash. The 62-byte key that *is* representable
  parsed and then aborted on lookup — an off-by-one, not a real limit.

The key lookup itself, `get_keys_at_root`, the `get_array` type check and
`assert_no_duplicate_keys` were fixed earlier on this fork; the attacks that motivated
them are in the audit.

### Grammar

The tokenizer is a 16-mode byte automaton where the original had four modes and a
single "the previous byte was a backslash" bit.

- **Numbers** are RFC 8259's `number`:
  `-? ( 0 | [1-9][0-9]* ) ( \. [0-9]+ )? ( [eE] [+-]? [0-9]+ )?`. Negatives, decimals and
  exponents parse; `1.`, `.5`, `01`, `1e`, `1e++2` and `1.2.3` are rejected inside
  `parse_json`, not deferred to a getter.
- **Escapes** are validated: `\ ( ["\\/bfnrt] | u [0-9a-fA-F]{4} )`. `\q`, `\u12` and
  `\u00zz` used to parse.
- **Raw control bytes** below 0x20 are rejected inside strings, as RFC 8259 requires.
  TAB, LF and CR were previously string content — and a raw TAB also silently shortened
  the token it was part of.
- **Bytes ≥ 0x80** are accepted as opaque string and key content. The original made them
  an error in every mode, so a single accented letter anywhere made a document
  unparseable. See [What a proof asserts](#what-a-proof-asserts) for what this does and
  does not promise.
- **Literals past byte 255** of the document parse (an 8-bit bound on a 16-bit index).

### API

- `get_value_from_array` returns an element of any type, with `value_type` saying which.
  It used to assert `STRING_TOKEN`, which made a number inside an array unreadable:
  `get_number_from_array` was the only door and it rejects decimals. `JSONValue` gains
  `is_object` and `is_array`.
- `get_string_from_path` and `get_value_from_path` resolve each segment against the node
  the previous one returned. They used to look every segment up in the root, so anything
  deeper than two segments never resolved.
- The getters are `pub` (several were `pub(crate)` by accident), and
  `layer_type_of_root` — with `OBJECT_LAYER` / `ARRAY_LAYER` — is public, so a caller can
  derive the shape of a document from the parse rather than from a constant it carries.
- Entry-level helpers (`adapter_entry_at`, `adapter_key_exists_at`, …) for callers whose
  query shape is only known at witness time.
- `get_number` rejects any byte that is not a digit and range-checks to 64 bits.
  `99999999999999999999` used to come back as `7766279631452241919`.
- `StringBytes` may be a multiple of 31.

### Diagnostics

Every rejection path now says what was wrong. `{"a":1}}` used to surface as
`call to assert_max_bit_size` on a negative number, deep inside the context stack; an
undersized `NumPackedFields` used to surface as `Index out of bounds` inside the string
tools. Each message is pinned by a test.

---

## Usage

```rust
use json_parser::JSON1kb;
use json_parser::JSONLiteral;

/*
{
    "hero": "Tony Harrison",
    "is_player": false,
    "stats": [
        { "hero_quote": "\"This is an outrage!\"", "power_level": 1 },
        { "hero_quote": "\"You know nothing of the crunch!\"", "power_level": 9001 }
    ],
    "dlc_enabled": true
}
*/
fn process_schema(text: [u8; 1024]) {
    let json: JSON1kb = JSON1kb::parse_json(text);

    // reject a record that repeats a key -- not implied by `parse_json`
    json.assert_no_duplicate_keys();

    // "unchecked" asserts the field exists
    let hero: BoundedVec<u8, 20> = json.get_string_unchecked("hero".as_bytes());
    assert(hero == BoundedVec::from_array("Tony Harrison".as_bytes()));

    // a literal can be `null`, which does not map onto a bool, hence the custom type
    let is_player: JSONLiteral = json.get_literal_unchecked("is_player".as_bytes());
    let _is_player = is_player.to_bool(); // null maps to false

    // descend with get_object / get_array
    let stats = json.get_array_unchecked("stats".as_bytes());
    let first = stats.get_object_from_array_unchecked(0);

    let power: u64 = first.get_number_unchecked("power_level".as_bytes());
    assert(power == 1);

    // every getter has a version returning an Option, for fields that may not exist
    let dlc: Option<JSONLiteral> = json.get_literal("dlc_enabled".as_bytes());
    assert(dlc.is_some());
}
```

Decimals, negatives and exponents are read as raw bytes through `get_value`, whose
`value_type` is `NUMERIC_TOKEN`; `get_number` is for plain unsigned integers and refuses
the rest.

---

## Sizing a `JSON` type

```rust
JSONGeneric<NumBytes, NumPackedFields, MaxNumTokens, MaxNumValues, MaxKeyFields>
```

> A _token_ is a distinct JSON element: `{` `}` `[` `]` `,` `:`, a string, a number or a
> literal. A _value_ is an object, array, string, number or literal.

Two of the five follow from `NumBytes`:

- `NumPackedFields >= ceil(NumBytes / 31) + 3`. The `+ 3` is not slack you may reclaim:
  `slice_fields` reads one limb past the end of the slice it is asked for. `parse_json`
  asserts the requirement, at no gate cost.
- `MaxKeyFields` is a choice about keys, not size. At the default of 2 a key may be up to
  **62 bytes**; a longer key is rejected during the parse.

The other two are a property of the **shape** of your documents, not their length. The
aliases below assume a token every 8 bytes and a value every 16 — roughly what
pretty-printed JSON with long string values looks like. Dense records are nothing like
that: `{"a":1,"b":2,...}` is a token every 3.5 bytes, so a real 511-byte record with 83
tokens does not fit in `JSON512b`, which stops at 64. It fails cleanly, but it fails. The
reverse costs money instead of proofs: `MaxNumValues` dominates the key map and the sort,
so an alias four times wider than your records pays for all four.

**Count the tokens in a real record, add the margin you want to declare, and name the
parameters.** Use an alias only once you have checked your documents fit it.

| alias | bytes | tokens | values |
| --- | ---: | ---: | ---: |
| `JSON512b` | 512 | 64 | 32 |
| `JSON1kb` | 1,024 | 128 | 64 |
| `JSON2kb` | 2,048 | 256 | 128 |
| `JSON4kb` | 4,096 | 512 | 256 |
| `JSON8kb` | 8,192 | 1,024 | 512 |
| `JSON16kb` | 16,384 | 2,048 | 1,024 |

### Keys of unknown length

Every query method accepts the key as a `BoundedVec`, for keys derived in-circuit.

---

## Remaining limitations

- **A single value is not a document here.** `JSON::parse_json("9999")` fails; the root
  must be an object or an array.
- **`get_number` is for `u64`.** Decimals, negatives, exponents and values above
  `u64::MAX` are refused. Read them with `get_value` and parse the bytes yourself.
- **UTF-8 and escape decoding**, as above.

---

## Development

```sh
nargo test                # the suite
nargo test mutations::    # the mutation suite alone
nargo check               # must be clean of `bug:` diagnostics
nargo test test_make      # the committed tables match their generators
```

`src/json_tables.nr` is generated. Never hand-edit it — change the sub-tables in
`src/_table_generation/` and regenerate:

```sh
nargo test --show-output emit_table_ | grep '^EMIT ' > /tmp/tables.txt
python3 scripts/splice_tables.py /tmp/tables.txt src/json_tables.nr
nargo test test_make
```

Growing a table is a chicken-and-egg problem: the `test_make*` verifiers will not compile
while the sizes disagree. Resize the global to the new length with placeholder `0x00`
entries first, then emit and splice.

Two invariants hold the table layout and are checked by tests: `ERROR_CAPTURE` must stay
one past the last real scan mode (a rejected byte is expressed as a lookup past the end
of `JSON_CAPTURE_TABLE`), and every mode that can close a token must sort below
`NUM_PUSHING_CAPTURE_MODES` (`ASCII_TO_TOKEN_TABLE` and `PROCESS_RAW_TRANSCRIPT_TABLE`
are sized to those modes alone).

## Acknowledgements

Many thanks to the authors of the original Noir JSON library
https://github.com/RontoSOFT/noir-json-parser
