//! Honest-prover regressions for the key-lookup soundness fix.
//!
//! These tests do not (and cannot) demonstrate the fix rejects a malicious hint --
//! that needs a mutated oracle, see the accompanying report. What they pin down is the
//! other half: that the new constraints in `key_exists_impl`, `get_keys_at_root` and
//! `assert_no_duplicate_keys` never reject an honest prover. Most of them would fail
//! against a naive version of the fix that asserted adjacency without teaching the
//! hint to return the *last* index of the largest entry below the target, because the
//! sorted hash list starts with a long run of identical padding entries.
use crate::json::JSON;

// {"amount":42,"user":"bob"}
pub type Flat = JSON<26, 4, 32, 17, 2>;
// {"amount":42,"user":"bob","isSanctioned":false,"nested":{"inner":1,"deep":"x"}}
pub type Nested = JSON<79, 6, 32, 17, 2>;

fn flat() -> Flat {
    JSON::parse_json_from_string("{\"amount\":42,\"user\":\"bob\"}")
}

fn nested() -> Nested {
    JSON::parse_json_from_string(
        "{\"amount\":42,\"user\":\"bob\",\"isSanctioned\":false,\"nested\":{\"inner\":1,\"deep\":\"x\"}}",
    )
}

// -------------------------------------------------------------------------------
// present keys
// -------------------------------------------------------------------------------

#[test]
fn fix_present_keys_at_root() {
    let json = nested();
    assert(json.key_exists("amount".as_bytes()), "amount");
    assert(json.key_exists("user".as_bytes()), "user");
    assert(json.key_exists("isSanctioned".as_bytes()), "isSanctioned");
    assert(json.key_exists("nested".as_bytes()), "nested");

    assert(json.get_number("amount".as_bytes()).unwrap() == 42);
    let user: BoundedVec<u8, 8> = json.get_string("user".as_bytes()).unwrap();
    assert(user == BoundedVec::from_array("bob".as_bytes()));
    assert(json.get_literal("isSanctioned".as_bytes()).unwrap().is_false());
}

#[test]
fn fix_present_keys_in_nested_object() {
    let json = nested();
    let inner = json.get_object("nested".as_bytes()).unwrap();
    assert(inner.key_exists("inner".as_bytes()), "inner");
    assert(inner.key_exists("deep".as_bytes()), "deep");
    assert(inner.get_number("inner".as_bytes()).unwrap() == 1);
    let deep: BoundedVec<u8, 4> = inner.get_string("deep".as_bytes()).unwrap();
    assert(deep == BoundedVec::from_array("x".as_bytes()));
}

// -------------------------------------------------------------------------------
// absent keys: one test per not-found branch
// -------------------------------------------------------------------------------

/// Middle branch with `lhs_index` sitting on the *last* padding entry: the target is
/// below every real key but above the padding run. This is the branch that breaks if
/// the honest hint returns the first index of a repeated entry instead of the last:
/// on this record the padding run spans indices 1..14, so lhs would be 1 and rhs 15.
#[test]
fn fix_absent_key_below_every_real_key() {
    let json = flat();
    assert(json.key_exists("a".as_bytes()) == false, "a must be absent");
    assert(json.get_number("a".as_bytes()).is_none(), "a must read as none");
    assert(json.key_exists("w".as_bytes()) == false, "w must be absent");
}

/// Middle branch strictly between two real keys.
#[test]
fn fix_absent_key_between_two_real_keys() {
    let json = flat();
    assert(json.key_exists("b".as_bytes()) == false, "b must be absent");
    assert(json.key_exists("c".as_bytes()) == false, "c must be absent");
    let absent: Option<BoundedVec<u8, 8>> = json.get_string("b".as_bytes());
    assert(absent.is_none(), "b must read as none");
}

/// `target_gt_largest_entry` branch: "dz" hashes above every entry of this record,
/// so the hint must anchor `lhs_index` to MaxNumValues - 1.
#[test]
fn fix_absent_key_above_every_entry() {
    let json = flat();
    assert(json.key_exists("dz".as_bytes()) == false, "dz must be absent");
    assert(json.get_number("dz".as_bytes()).is_none(), "dz must read as none");
}

/// Absent keys in a record that also has a nested object: the sorted list then holds
/// keys of two different parents, so the middle branch has to stay correct across the
/// boundary between the two groups.
#[test]
fn fix_absent_keys_with_nested_groups() {
    let json = nested();
    assert(json.key_exists("a".as_bytes()) == false, "a");
    assert(json.key_exists("w".as_bytes()) == false, "w");
    assert(json.key_exists("zzzzzz".as_bytes()) == false, "zzzzzz");
    // `inner` and `deep` exist, but inside `nested`, not at the root.
    assert(json.key_exists("inner".as_bytes()) == false, "inner is not a root key");
    assert(json.key_exists("deep".as_bytes()) == false, "deep is not a root key");
}

/// Absent keys looked up inside a nested object (different `root_id`, same list).
#[test]
fn fix_absent_keys_in_nested_object() {
    let json = nested();
    let inner = json.get_object("nested".as_bytes()).unwrap();
    assert(inner.key_exists("a".as_bytes()) == false, "a");
    assert(inner.key_exists("zzz".as_bytes()) == false, "zzz");
    // present at the root, absent inside `nested`.
    assert(inner.key_exists("amount".as_bytes()) == false, "amount is not a nested key");
    assert(inner.get_number("amount".as_bytes()).is_none(), "amount must read as none");
}

// -------------------------------------------------------------------------------
// degenerate shapes
// -------------------------------------------------------------------------------

#[test]
fn fix_single_key_object() {
    let json: JSON<7, 4, 32, 17, 2> = JSON::parse_json_from_string("{\"a\":1}");
    assert(json.key_exists("a".as_bytes()), "a must exist");
    assert(json.get_number("a".as_bytes()).unwrap() == 1);
    assert(json.key_exists("b".as_bytes()) == false, "b must be absent");
    assert(json.key_exists("zz".as_bytes()) == false, "zz must be absent");
    json.assert_no_duplicate_keys();
}

/// Empty object: every slot of `key_hashes` is padding, which is the case that makes
/// `get_validity_flags(num_padding)` hit `boundary == N`.
#[test]
fn fix_empty_object() {
    let json: JSON<2, 4, 32, 17, 2> = JSON::parse_json_from_string("{}");
    assert(json.key_exists("a".as_bytes()) == false, "a must be absent");
    assert(json.get_number("a".as_bytes()).is_none(), "a must read as none");
    json.assert_no_duplicate_keys();
    let keys: BoundedVec<BoundedVec<u8, 4>, 4> = json.get_keys_at_root();
    assert(keys.len() == 0, "no keys at root");
}

/// Capacity boundary. `json.nr:83` asserts `entry_ptr < MaxNumValues - 1` on *every*
/// iteration, and `entry_ptr` ends one past the last entry, so a record can hold at
/// most `MaxNumValues - 2` entries; one of them is the record's own root entry, hence
/// at most `MaxNumValues - 3` members. With `MaxNumValues = 7` that is four members,
/// and the sorted hash list then has a padding run of length one -- the opposite
/// extreme from the long runs the other tests exercise.
#[test]
fn fix_object_at_capacity_boundary() {
    let json: JSON<25, 4, 24, 7, 2> =
        JSON::parse_json_from_string("{\"a\":1,\"b\":2,\"c\":3,\"d\":4}");
    assert(json.key_exists("a".as_bytes()), "a");
    assert(json.key_exists("d".as_bytes()), "d");
    assert(json.get_number("d".as_bytes()).unwrap() == 4);
    assert(json.key_exists("e".as_bytes()) == false, "e must be absent");
    assert(json.key_exists("zz".as_bytes()) == false, "zz must be absent");
    json.assert_no_duplicate_keys();
    let keys: BoundedVec<BoundedVec<u8, 2>, 4> = json.get_keys_at_root();
    assert(keys.len() == 4, "four keys at root");
    assert(keys.get_unchecked(0) == BoundedVec::from_array("a".as_bytes()));
    assert(keys.get_unchecked(3) == BoundedVec::from_array("d".as_bytes()));
}

/// One member past the boundary above: the parse itself refuses, before any of the
/// key-lookup constraints are reached.
#[test(should_fail_with = "create_json_entries: MaxNumValues limit exceeded!")]
fn fix_object_one_past_capacity_boundary() {
    let json: JSON<31, 4, 28, 7, 2> =
        JSON::parse_json_from_string("{\"a\":1,\"b\":2,\"c\":3,\"d\":4,\"e\":5}");
    assert(json.key_exists("a".as_bytes()));
}

/// Keys of 40 bytes: two Poseidon limbs (`MaxKeyFields = 2`).
#[test]
fn fix_two_limb_keys() {
    let json: JSON<91, 6, 32, 17, 2> = JSON::parse_json_from_string(
        "{\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\":1,\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\":2}",
    );
    assert(
        json.key_exists("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".as_bytes()),
        "40-byte key a",
    );
    assert(
        json.get_number("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".as_bytes()).unwrap() == 2,
        "40-byte key b",
    );
    // absent, same length, and absent with a 40-byte prefix collision on the first limb
    assert(
        json.key_exists("cccccccccccccccccccccccccccccccccccccccc".as_bytes()) == false,
        "40-byte key c must be absent",
    );
    assert(
        json.key_exists("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab".as_bytes()) == false,
        "40-byte key differing in the second limb must be absent",
    );
    json.assert_no_duplicate_keys();
}

// -------------------------------------------------------------------------------
// assert_no_duplicate_keys
// -------------------------------------------------------------------------------

#[test]
fn fix_no_duplicate_keys_accepts_unique_keys() {
    flat().assert_no_duplicate_keys();
    nested().assert_no_duplicate_keys();
}

#[test(should_fail_with = "assert_no_duplicate_keys: duplicate key in the record")]
fn fix_no_duplicate_keys_rejects_duplicates() {
    let json: JSON<13, 4, 32, 17, 2> = JSON::parse_json_from_string("{\"a\":1,\"a\":2}");
    json.assert_no_duplicate_keys();
}

/// The same key in two *different* objects is not a duplicate: the entries differ in
/// `parent_id`.
#[test]
fn fix_no_duplicate_keys_allows_same_key_in_different_objects() {
    let json: JSON<19, 4, 32, 17, 2> = JSON::parse_json_from_string("{\"a\":1,\"n\":{\"a\":2}}");
    json.assert_no_duplicate_keys();
    assert(json.get_number("a".as_bytes()).unwrap() == 1);
    let inner = json.get_object("n".as_bytes()).unwrap();
    assert(inner.get_number("a".as_bytes()).unwrap() == 2);
}

/// Equal array elements are not duplicates either: their entries differ in
/// `array_index`.
#[test]
fn fix_no_duplicate_keys_allows_repeated_array_values() {
    let json: JSON<14, 4, 32, 17, 2> = JSON::parse_json_from_string("{\"xs\":[1,1,1]}");
    json.assert_no_duplicate_keys();
    let xs = json.get_array("xs".as_bytes()).unwrap();
    assert(xs.get_length() == 3);
}

// -------------------------------------------------------------------------------
// get_keys_at_root
// -------------------------------------------------------------------------------

/// The root's keys, and only those: `bar` is an object whose own key `one` must not
/// leak into the result.
#[test]
fn fix_get_keys_at_root_on_a_nested_record() {
    let json: JSON<51, 5, 32, 17, 2> = JSON::parse_json_from_string(
        "{\"A\":1,\"foo\":false,\"bar\":{\"one\":\"A\"},\"baz\":\"12345\"}",
    );
    let keys: BoundedVec<BoundedVec<u8, 3>, 8> = json.get_keys_at_root();
    assert(keys.len() == 4, "four keys at root");
    assert(keys.get_unchecked(0) == BoundedVec::from_array("A".as_bytes()));
    assert(keys.get_unchecked(1) == BoundedVec::from_array("foo".as_bytes()));
    assert(keys.get_unchecked(2) == BoundedVec::from_array("bar".as_bytes()));
    assert(keys.get_unchecked(3) == BoundedVec::from_array("baz".as_bytes()));
}

/// `MaxNumKeys` exactly equal to the number of children: the boundary that would make
/// `get_validity_flags(len)` revert if the flags array were not one element longer.
#[test]
fn fix_get_keys_at_root_at_exact_capacity() {
    let json: JSON<51, 5, 32, 17, 2> = JSON::parse_json_from_string(
        "{\"A\":1,\"foo\":false,\"bar\":{\"one\":\"A\"},\"baz\":\"12345\"}",
    );
    let keys: BoundedVec<BoundedVec<u8, 3>, 4> = json.get_keys_at_root();
    assert(keys.len() == 4, "four keys at root");
    assert(keys.get_unchecked(3) == BoundedVec::from_array("baz".as_bytes()));
}

/// `get_keys_at_root` after descending into an object: `self.root_id` changes, and the
/// parent check has to follow it.
#[test]
fn fix_get_keys_at_root_inside_a_nested_object() {
    let json = nested();
    let inner = json.get_object("nested".as_bytes()).unwrap();
    // MaxKeyBytes has to cover `key_data[0]` too, not just the keys actually returned:
    // the loop runs over all MaxNumKeys slots and the padding slots read index 0,
    // whose key here is the 6-byte "amount". This is established behavior.
    let keys: BoundedVec<BoundedVec<u8, 8>, 6> = inner.get_keys_at_root();
    assert(keys.len() == 2, "two keys in the nested object");
    assert(keys.get_unchecked(0) == BoundedVec::from_array("inner".as_bytes()));
    assert(keys.get_unchecked(1) == BoundedVec::from_array("deep".as_bytes()));
}

// -------------------------------------------------------------------------------
// get_array: the type check used to be gated on the inverted condition
// -------------------------------------------------------------------------------

type Ent15 = JSON<15, 4, 32, 17, 2>;
type Ent20 = JSON<20, 4, 32, 17, 2>;

#[test]
fn fix_get_array_on_an_array() {
    let empty: Ent15 = JSON::parse_json_from_string("{\"entities\":[]}");
    assert(empty.get_array("entities".as_bytes()).unwrap().get_length() == 0, "empty");

    let three: Ent20 = JSON::parse_json_from_string("{\"entities\":[1,2,3]}");
    let arr = three.get_array("entities".as_bytes()).unwrap();
    assert(arr.get_length() == 3, "three elements");
    assert(arr.get_number_from_array(1).unwrap() == 2, "second element");
}

/// The exact case of F1 mutation (e): an empty *string* must not pass for an empty
/// array. Before the fix this returned `Some` and `get_length() == 0`.
#[test(should_fail_with = "get_array: entry exists but is not an array!")]
fn fix_get_array_on_a_string_is_rejected() {
    let json: Ent15 = JSON::parse_json_from_string("{\"entities\":\"\"}");
    let arr = json.get_array("entities".as_bytes()).unwrap();
    assert(arr.get_length() == 0);
}

#[test(should_fail_with = "get_array: entry exists but is not an array!")]
fn fix_get_array_on_a_number_is_rejected() {
    let json: Ent15 = JSON::parse_json_from_string("{\"entities\":42}");
    let arr = json.get_array("entities".as_bytes()).unwrap();
    assert(arr.get_length() == 0);
}

#[test(should_fail_with = "get_array: entry exists but is not an array!")]
fn fix_get_array_on_an_object_is_rejected() {
    let json: Ent20 = JSON::parse_json_from_string("{\"entities\":{\"a\":1}}");
    let arr = json.get_array("entities".as_bytes()).unwrap();
    assert(arr.get_length() == 0);
}

#[test(should_fail_with = "get_array_unchecked: entry exists but is not an array!")]
fn fix_get_array_unchecked_on_a_string_is_rejected() {
    let json: Ent15 = JSON::parse_json_from_string("{\"entities\":\"\"}");
    let arr = json.get_array_unchecked("entities".as_bytes());
    assert(arr.get_length() == 0);
}

/// An absent key must return `none`, not assert on a phantom entry. Before the fix the
/// first record here returned `none` only by luck (the not-found witness index happened
/// to land on an array entry) and the other two reverted.
#[test]
fn fix_get_array_absent_key_returns_none() {
    let with_array: Ent15 = JSON::parse_json_from_string("{\"entities\":[]}");
    assert(with_array.get_array("missing".as_bytes()).is_none(), "record with an array");

    let no_array: JSON<7, 4, 32, 17, 2> = JSON::parse_json_from_string("{\"a\":1}");
    assert(no_array.get_array("b".as_bytes()).is_none(), "record with no array at all");

    let mixed = flat();
    assert(mixed.get_array("zz".as_bytes()).is_none(), "mixed record");
}

/// `get_object` is the reference implementation this fix mirrors; pin it too, so the
/// two stay symmetric.
#[test(should_fail_with = "get_object: entry exists but is not an object!")]
fn fix_get_object_on_an_array_is_rejected() {
    let json: Ent15 = JSON::parse_json_from_string("{\"entities\":[]}");
    let _ = json.get_object("entities".as_bytes()).unwrap();
}
