// A concrete instantiation of the parser, so the compiler has something to monomorphise.
//
// The `bug:` lint -- "Brillig function call isn't properly covered by a manual
// constraint" -- runs during compilation, on monomorphised code. A library has no
// `main` and nothing concrete to compile, so `nargo check` and `nargo test` never
// reach it. This package is what gives the lint something to look at.
//
// Exercises the parse, the key map, the sort, and one getter of each kind, since the
// lint is per-call-site and only sees the sites a compilation reaches.
fn main(text: [u8; 256], key: [u8; 6]) -> pub u64 {
    let json: json_parser::JSONGeneric<256, 12, 64, 33, 2> =
        json_parser::JSONGeneric::parse_json(text);
    json.assert_no_duplicate_keys();

    let s: BoundedVec<u8, 31> = json.get_string_unchecked(BoundedVec::from_parts_unchecked(key, 4));
    let n = json.get_number_unchecked("amount".as_bytes());
    let lit = json.get_literal_unchecked("flag".as_bytes());
    let v: json_parser::JSONValue<31> = json.get_value(key).unwrap();
    let arr = json.get_array_unchecked("list".as_bytes());
    let first: json_parser::JSONValue<31> = arr.get_value_from_array_unchecked(0);

    n + s.len() as u64 + lit.to_bool() as u64 + v.value.len() as u64 + first.value.len() as u64
}
