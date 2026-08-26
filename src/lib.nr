pub(crate) mod _table_generation;
mod enums;
mod json;
mod json_tables;
mod keymap;
mod json_entry;
mod transcript_entry;
pub(crate) mod _string_tools;
pub(crate) mod _comparison_tools;
mod token_flags;
mod getters;
mod keyhash;
mod get_string;
mod get_number;
mod get_literal;
mod get_object;
mod get_array;
mod utils;
mod benchmarks;

use json::JSON;

// Re-export public API types whose implementation modules remain private.
pub use enums::Layer::{ARRAY_LAYER, OBJECT_LAYER};
pub use get_literal::JSONLiteral;
pub use getters::KeyHashable;
pub use json::{JSON as JSONGeneric, JSONValue};

// ## Sizing a `JSON` type
//
// `JSONGeneric` -- re-exported above as the explicit form -- takes five parameters:
//
// | parameter | what it bounds |
// | --- | --- |
// | `NumBytes` | the padded length of the document |
// | `NumPackedFields` | the 31-byte limbs the bytes are packed into |
// | `MaxNumTokens` | how many tokens the transcript can hold |
// | `MaxNumValues` | how many objects, arrays and scalars the document may contain, plus one |
// | `MaxKeyFields` | key capacity, in 31-byte limbs |
//
// Only two of the five are determined by `NumBytes`:
//
// * `NumPackedFields >= ceil(NumBytes / 31) + 3`. The `+ 3` is not slack you may
//   reclaim: `slice_fields` reads one limb past the end of the slice it is asked for
//   (the read is discarded, but it still has to be in bounds) and the string getters
//   slice from arbitrary positions. `parse_json` asserts it, at no gate cost.
// * `MaxKeyFields` is a choice about keys, not about size. At the default of 2, a key
//   may be up to 62 bytes; a longer key is rejected during the parse.
//
// The other two are a property of the *shape* of your documents, not their length, and
// the aliases below cannot know it. They assume a token every 8 bytes and a value every
// 16, which is roughly what pretty-printed JSON with long string values looks like.
// Dense records are nothing like that: `{"a":1,"b":2,...}` is a token every 3.5 bytes,
// so a real 511-byte record with 83 tokens does not fit in `JSON512b`, which stops at
// 64. It fails cleanly -- `build_transcript: MaxNumTokens limit exceeded!` -- but it
// fails.
//
// The reverse costs money rather than proofs: `MaxNumValues` is the dominant term in
// the key map and the sort, so an alias that is four times wider than the records it
// parses pays for all four.
//
// So: **count the tokens in a real record, add the margin you want to declare, and name
// the parameters.** Use the aliases only when you have checked that your documents fit
// them.
//
// ```noir
// // a 2000-byte record that really contains 240 tokens and 118 values
// type MyRecord = json_parser::JSONGeneric<2048, 70, 288, 145, 2>;
// ```

pub type JSON512b = JSON<512, 20, 64, 33, 2>;
pub type JSON1kb = JSON<1024, 37, 128, 65, 2>;
pub type JSON2kb = JSON<2048, 70, 256, 129, 2>;
pub type JSON4kb = JSON<4096, 136, 512, 257, 2>;
pub type JSON8kb = JSON<8192, 268, 1024, 513, 2>;
pub type JSON16kb = JSON<16384, 532, 2048, 1025, 2>;
mod mutations;
mod soundness_fix;
