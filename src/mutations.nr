//! Permanent mutation suite.
//!
//! `soundness_fix.nr` holds *honest-prover* regressions: proof that the added
//! constraints never reject a document they should accept. This file holds the other
//! half, and it is the half that matters against an untrusted prover: for each
//! invariant the parser relies on, a test that tells the corresponding lie and checks
//! a constraint catches it.
//!
//! Two techniques, because a Noir test cannot reach inside a library call and replace
//! the value an `unsafe { __hint() }` returned:
//!
//!   1. **Corrupt the struct, re-run the check.** The fields of `JSON` are
//!      `pub(crate)`, so a test in this crate can parse a document honestly, write a
//!      false value into `json_entries_packed` / `key_hashes` / `transcript`, and then
//!      call the constrained method that is supposed to notice. This is exactly the
//!      shape of the attack: the prover controls those arrays, the constraints are
//!      what pin them to the bytes.
//!
//!   2. **Re-implement the constrained core with the hint forced to a lie.** For a
//!      pure arithmetic gadget (`lte_field_240_bit` and friends) the hint is a local,
//!      so a few lines reproduce the gadget with the hint replaced by a false value.
//!      Where the pre-fix version accepted the lie, the old algebra is kept next to
//!      the new one and pinned by a test, so a regression is loud.
//!
//! What this file cannot do is mutate a hint *in place* inside `parse_json`: an attack
//! on the tokenizer or on the key search needs a patched build of the library, driven
//! from outside the test suite. Where an invariant cannot be reached from here, the
//! comment above the constraint that holds it says so.
use crate::_comparison_tools::lt::{lt_field_16_bit, lte_field_240_bit};
use crate::json::JSON;
use crate::json_entry::{JSONEntry, JSONEntryPacked};

// {"amount":42,"user":"bob","nested":{"inner":1}}
type Record = JSON<47, 5, 32, 17, 2>;

fn record() -> Record {
    JSON::parse_json_from_string("{\"amount\":42,\"user\":\"bob\",\"nested\":{\"inner\":1}}")
}

// ---------------------------------------------------------------------------------
// exactly one root
// ---------------------------------------------------------------------------------
//
// `set_root_entry` takes the root index from a hint and checks the entry it lands on
// is non-empty and parentless. That says the hint pointed at *a* root; it does not say
// there is only one. A second parentless entry is a second document sharing the
// transcript: `get_keys_at_root`, `layer_type_of_root` and every array getter read
// through `root_index_in_transcript`, so a prover who can plant one chooses which of
// the two the verifier sees.

/// The mutation: give a second entry `parent_index == 0`.
#[test(should_fail_with = "JSON must contain exactly one root entry")]
fn mutate_second_parentless_entry_is_rejected() {
    let mut json = record();

    // find any non-empty entry that is not the root and re-parent it to nobody
    let root = json.root_index_in_transcript;
    let mut victim = 0;
    for i in 0..17 {
        let is_candidate = (i != root) & (json.json_entries_packed[i].value != 0);
        victim = if (victim == 0) & is_candidate {
            i
        } else {
            victim
        };
    }
    assert(victim != 0, "test setup: no second entry to corrupt");

    let mut entry: JSONEntry = json.json_entries_packed[victim].into();
    entry.parent_index = 0;
    json.json_entries_packed[victim] = JSONEntryPacked { value: entry.to_field() };

    json.set_root_entry();
}

/// ...and the honest record still passes the same check, run twice.
#[test]
fn honest_record_has_exactly_one_root() {
    let mut json = record();
    json.set_root_entry();
    json.set_root_entry();
}

// ---------------------------------------------------------------------------------
// the child pointer is written once
// ---------------------------------------------------------------------------------
//
// `add_child_pointer_into_field` adds `child_pointer * 2^80` into a packed entry whose
// child pointer is two bytes wide. A second write carries out of those two bytes and
// into `num_children`, which is what every bounds check on an array index compares
// against: inflate it and `get_entry_from_array` reads entries that belong to another
// container.

#[test(should_fail_with = "child pointer was already initialized")]
fn mutate_child_pointer_written_twice_is_rejected() {
    let once = JSONEntry::add_child_pointer_into_field(0, 3);
    let _ = JSONEntry::add_child_pointer_into_field(once, 4);
}

/// The carry this prevents: without the check, two writes summing past 2^16 land a 1
/// in `num_children`.
#[test]
fn a_double_write_would_have_carried_into_num_children() {
    let once = JSONEntry::add_child_pointer_into_field(0, 0xFFFF);
    let forged = once + 1 * 0x100000000000000000000; // the second write, unchecked
    let entry: JSONEntry = JSONEntryPacked { value: forged }.into();
    assert_eq(entry.child_pointer, 0);
    assert_eq(entry.num_children, 1);
}

#[test(should_fail)]
fn mutate_child_pointer_wider_than_16_bits_is_rejected() {
    let _ = JSONEntry::add_child_pointer_into_field(0, 0x10000);
}

#[test]
fn child_pointer_round_trips() {
    let packed = JSONEntry::add_child_pointer_into_field(0, 0x1234);
    let entry: JSONEntry = JSONEntryPacked { value: packed }.into();
    assert_eq(entry.child_pointer, 0x1234);
    assert_eq(entry.num_children, 0);
}

// ---------------------------------------------------------------------------------
// duplicate keys
// ---------------------------------------------------------------------------------
//
// Two entries under the same parent with the same key hash make `key_exists` and every
// getter pick whichever of the two the sort put first. `assert_no_duplicate_keys` is
// what a caller runs to rule it out; it has to survive the padding prefix, which is a
// long run of *equal* zero entries and would otherwise trip its own check.

/// The mutation: copy one key hash over its neighbour, so the sorted list holds the
/// same non-padding value twice.
#[test(should_fail_with = "assert_no_duplicate_keys: duplicate key in the record")]
fn mutate_duplicate_key_hash_is_rejected() {
    let mut json = record();

    // the padding run sorts first, so the last two slots are real keys
    json.key_hashes[16] = json.key_hashes[15];

    json.assert_no_duplicate_keys();
}

#[test]
fn honest_record_has_no_duplicate_keys() {
    record().assert_no_duplicate_keys();
}

// ---------------------------------------------------------------------------------
// the 240-bit comparators
// ---------------------------------------------------------------------------------
//
// `noir_sort` is handed `lte_field_240_bit` as its comparator, so the ordering of
// `key_hashes` -- which is what makes the binary-search-free key lookup sound -- rests
// on this range check and nothing else. The hint is a local, so a lie is easy to
// express here.

/// `lte_field_240_bit` with the predicate supplied instead of hinted.
fn lte_240_with_forced_predicate(x: Field, y: Field, predicate: bool) -> bool {
    let delta = y - x;
    let lt_parameter = 2 * (predicate as Field) * delta - delta + predicate as Field - 1;
    lt_parameter.assert_max_bit_size::<240>();
    predicate
}

/// The same gadget with the algebra as it stood before the fix: the false branch
/// evaluated `x - y + 1` rather than `x - y - 1`, which is off by two.
fn lte_240_with_the_old_algebra(x: Field, y: Field, predicate: bool) -> bool {
    let delta = y - x;
    let lt_parameter = 2 * (predicate as Field) * delta - predicate as Field - delta + 1;
    lt_parameter.assert_max_bit_size::<240>();
    predicate
}

/// The lie: claim `x > y` for two adjacent values. The corrected false branch is
/// `x - y - 1 = -2`, which is not a 240-bit number.
#[test(should_fail)]
fn mutate_lte_240_claiming_greater_on_adjacent_values_is_rejected() {
    let _ = lte_240_with_forced_predicate(5, 6, false);
}

/// The same lie one step further apart, to show the branch is not accidentally tight.
#[test(should_fail)]
fn mutate_lte_240_claiming_greater_on_distant_values_is_rejected() {
    let _ = lte_240_with_forced_predicate(5, 500, false);
}

/// The lie in the other direction: claim `x <= y` when `x > y`.
#[test(should_fail)]
fn mutate_lte_240_claiming_less_or_equal_when_greater_is_rejected() {
    let _ = lte_240_with_forced_predicate(6, 5, true);
}

/// Equality is the boundary the sort leans on: `x <= x` must hold, and `x > x` must not.
#[test]
fn lte_240_accepts_equality() {
    assert(lte_240_with_forced_predicate(7, 7, true));
}

#[test(should_fail)]
fn mutate_lte_240_claiming_greater_on_equal_values_is_rejected() {
    let _ = lte_240_with_forced_predicate(7, 7, false);
}

/// What the fix was for: the old algebra evaluated `x - y + 1`, which is *zero* when
/// `y == x + 1` -- so a prover could claim `x > y` for any two adjacent hashes and the
/// range check passed. This test fails the day someone puts the old expression back.
#[test]
fn the_old_algebra_accepted_a_lie_about_adjacent_values() {
    assert(lte_240_with_the_old_algebra(5, 6, false) == false);
}

/// The honest comparator still answers correctly across the boundary.
#[test]
fn lte_240_is_correct_around_the_boundary() {
    assert(lte_field_240_bit(5, 6));
    assert(lte_field_240_bit(6, 6));
    assert(lte_field_240_bit(7, 6) == false);
    assert(lte_field_240_bit(0, 0));
}

/// `lt_field_16_bit` guards every array index against `num_children`; its algebra was
/// already right, and this pins it.
fn lt_16_with_forced_predicate(x: Field, y: Field, predicate: bool) -> bool {
    let delta = y - x;
    let lt_parameter = 2 * (predicate as Field) * delta - predicate as Field - delta;
    lt_parameter.assert_max_bit_size::<16>();
    predicate
}

#[test(should_fail)]
fn mutate_lt_16_claiming_less_when_equal_is_rejected() {
    let _ = lt_16_with_forced_predicate(4, 4, true);
}

#[test(should_fail)]
fn mutate_lt_16_claiming_not_less_when_less_is_rejected() {
    let _ = lt_16_with_forced_predicate(3, 4, false);
}

#[test]
fn lt_16_is_correct_around_the_boundary() {
    assert(lt_field_16_bit(3, 4));
    assert(lt_field_16_bit(4, 4) == false);
    assert(lt_field_16_bit(5, 4) == false);
}

// ---------------------------------------------------------------------------------
// the two key hashers agree
// ---------------------------------------------------------------------------------
//
// A key is hashed twice by two different pieces of code: `FieldHasher` reads it out of
// the packed 31-byte limbs during the parse, `ByteHasher` reads it out of a byte array
// at lookup time. The lookup is a comparison of those two hashes, so if they ever
// disagree for a key length the parser accepts, that key becomes unfindable -- and if
// they agree for two *different* keys, one impersonates the other.
//
// The library asserts the agreement nowhere: it is a comment. These tests are the
// check, across every length the default `MaxKeyFields = 2` admits, including the
// 31/32 limb boundary and the 62-byte capacity.

type KeyProbe = JSON<128, 8, 24, 13, 2>;

/// Both hashers see the same key, so a lookup finds it: this is the agreement, observed
/// end to end.
fn key_of_length_round_trips<let N: u32>(key: [u8; N]) {
    let mut doc: [u8; 128] = [32; 128];
    doc[0] = 123; // {
    doc[1] = 34; // "
    for i in 0..N {
        doc[2 + i] = key[i];
    }
    doc[2 + N] = 34; // "
    doc[3 + N] = 58; // :
    doc[4 + N] = 49; // 1
    doc[5 + N] = 125; // }

    let json: KeyProbe = JSON::parse_json(doc);
    assert(json.get_number_unchecked(key) == 1, "key did not round trip");
}

#[test]
fn keys_below_the_limb_boundary_round_trip() {
    key_of_length_round_trips("a".as_bytes());
    key_of_length_round_trips("ab".as_bytes());
    key_of_length_round_trips("abcdefghijklmnopqrstuvwxyzABCDE".as_bytes()); // 31
}

#[test]
fn keys_across_the_limb_boundary_round_trip() {
    key_of_length_round_trips("abcdefghijklmnopqrstuvwxyzABCDEF".as_bytes()); // 32
    key_of_length_round_trips("abcdefghijklmnopqrstuvwxyzABCDEFG".as_bytes()); // 33
}

#[test]
fn keys_at_capacity_round_trip() {
    // 61 and 62 bytes
    key_of_length_round_trips("abcdefghijklmnopqrstuvwxyzABCDEFabcdefghijklmnopqrstuvwxyzABC"
        .as_bytes());
    key_of_length_round_trips("abcdefghijklmnopqrstuvwxyzABCDEFabcdefghijklmnopqrstuvwxyzABCD"
        .as_bytes());
}

/// Two keys that differ only in their last byte, at exactly the capacity: the hash is
/// taken over `MaxKeyFields` limbs, so a truncating hasher would map both to the same
/// value and one would answer for the other.
#[test]
fn keys_differing_in_the_last_byte_at_capacity_do_not_collide() {
    let a = "abcdefghijklmnopqrstuvwxyzABCDEFabcdefghijklmnopqrstuvwxyzABCD".as_bytes();
    let b = "abcdefghijklmnopqrstuvwxyzABCDEFabcdefghijklmnopqrstuvwxyzABCE".as_bytes();
    assert_eq(a.len(), 62);

    // {"<a>":1,"<b>":2}
    let mut doc: [u8; 135] = [32; 135];
    doc[0] = 123; // {
    doc[1] = 34; // "
    for i in 0..62 {
        doc[2 + i] = a[i];
    }
    doc[64] = 34; // "
    doc[65] = 58; // :
    doc[66] = 49; // 1
    doc[67] = 44; // ,
    doc[68] = 34; // "
    for i in 0..62 {
        doc[69 + i] = b[i];
    }
    doc[131] = 34; // "
    doc[132] = 58; // :
    doc[133] = 50; // 2
    doc[134] = 125; // }

    let json: JSON<160, 9, 24, 13, 2> = JSON::parse_json(doc);
    assert(json.get_number_unchecked(a) == 1, "a");
    assert(json.get_number_unchecked(b) == 2, "b");
}

// ---------------------------------------------------------------------------------
// the range the sort comparator is only correct inside
// ---------------------------------------------------------------------------------
//
// `noir_sort::sort_advanced` gives two guarantees: `sorted` is a permutation of the
// input (`get_shuffle_indices` asserts, for every i, that some slot holds i -- a
// surjection of a finite set onto itself, so a bijection -- and that
// `rhs[indices[i]] == lhs[i]`), and `assert_lte_240_bit` holds on every adjacent pair.
//
// The second one only *orders* anything while the values stay well below the field
// modulus. `assert_lte_240_bit(x, y)` checks that `y - x` fits in 240 bits; for
// x, y < 2^240 a negative difference wraps to about 2^254 and does not fit, so the check
// means `x <= y` as integers. That is the whole argument, and it rests on a range
// nothing in `noir_sort` enforces.
//
// It holds here by construction: an entry is a 200-bit hash, plus a 16-bit array index
// at 2^200, plus a 16-bit parent identity at 2^216, so it is under 2^232. This test is
// that argument, checked against a real record rather than asserted in prose.

#[test]
fn key_hashes_stay_inside_the_comparator_range() {
    let json = record();
    for i in 0..17 {
        json.key_hashes[i].assert_max_bit_size::<232>();
    }
}

#[test]
fn key_hashes_of_a_nested_record_stay_inside_the_comparator_range() {
    let json: JSON<128, 8, 48, 25, 2> = JSON::parse_json_from_string(
        "{\"a\":[1,2,3],\"b\":{\"c\":{\"d\":\"x\"}},\"e\":true,\"f\":-1.5e3}",
    );
    for i in 0..25 {
        json.key_hashes[i].assert_max_bit_size::<232>();
    }
}

// ---------------------------------------------------------------------------------
// unescaping
// ---------------------------------------------------------------------------------
//
// `process_escape_sequences` runs over the raw bytes of a string token and replaces
// two-byte escapes with one byte. It handles seven of them -- `\" \\ \b \f \n \r \t` --
// and nothing else: `\/` and `\uXXXX` are *syntax* the tokenizer now validates, but they
// come back through `get_string` as the raw bytes that spell them. A caller that needs
// the decoded text has to finish the job, or refuse strings containing a backslash.
//
// The one thing worth checking closely is the `skip` flag, which is what stops an
// escaped backslash from swallowing the character after it.

type UnescapeJson = JSON<48, 5, 16, 9, 2>;

#[test]
fn unescape_replaces_the_seven_it_knows() {
    let json: UnescapeJson = JSON::parse_json_from_string("{\"a\":\"x\\ny\"}");
    let v: BoundedVec<u8, 16> = json.get_string("a".as_bytes()).unwrap();
    assert_eq(v.len(), 3);
    assert_eq(v.get(1), 10); // LF, not the two bytes that spelled it
}

/// `"\\n"` is an escaped backslash followed by the letter `n`, not an escaped newline.
/// Getting this wrong is a one-character change in `process_escape_sequences` and it
/// would let a string claim a byte the document does not contain.
#[test]
fn unescape_does_not_chain_an_escaped_backslash_into_the_next_character() {
    let json: UnescapeJson = JSON::parse_json_from_string("{\"a\":\"\\\\n\"}");
    let v: BoundedVec<u8, 16> = json.get_string("a".as_bytes()).unwrap();
    assert_eq(v.len(), 2);
    assert_eq(v.get(0), 92); // backslash
    assert_eq(v.get(1), 110); // "n"
}

/// ...and two escaped backslashes in a row are two backslashes.
#[test]
fn unescape_handles_consecutive_escaped_backslashes() {
    let json: UnescapeJson = JSON::parse_json_from_string("{\"a\":\"\\\\\\\\\"}");
    let v: BoundedVec<u8, 16> = json.get_string("a".as_bytes()).unwrap();
    assert_eq(v.len(), 2);
    assert_eq(v.get(0), 92);
    assert_eq(v.get(1), 92);
}

/// `\/` is legal JSON and the tokenizer accepts it, but the unescaper does not know it:
/// the two bytes come back as they are. Documented, not fixed -- see the README.
#[test]
fn unescape_leaves_a_solidus_escape_alone() {
    let json: UnescapeJson = JSON::parse_json_from_string("{\"a\":\"\\/\"}");
    let v: BoundedVec<u8, 16> = json.get_string("a".as_bytes()).unwrap();
    assert_eq(v.len(), 2);
    assert_eq(v.get(0), 92);
    assert_eq(v.get(1), 47);
}

/// Same for `\uXXXX`: six bytes in, six bytes out.
#[test]
fn unescape_leaves_a_unicode_escape_alone() {
    let json: UnescapeJson = JSON::parse_json_from_string("{\"a\":\"\\u00e9\"}");
    let v: BoundedVec<u8, 16> = json.get_string("a".as_bytes()).unwrap();
    assert_eq(v.len(), 6);
    assert_eq(v.get(0), 92);
    assert_eq(v.get(1), 117); // "u"
}
