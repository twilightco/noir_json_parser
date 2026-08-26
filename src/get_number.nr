use crate::enums::Token::NUMERIC_TOKEN;
use crate::getters::KeyHashable;
use crate::json::{JSON, JSONValue};
use crate::json_tables::ASCII_TO_NUMBER;
use crate::utils::cast_num_to_u32;

global U64_LENGTH_AS_BASE10_STRING: u32 = 20;
global NUMBER_OFFSET_SHIFT: [Field; 21] = [
    100000000000000000000,
    10000000000000000000,
    1000000000000000000,
    100000000000000000,
    10000000000000000,
    1000000000000000,
    100000000000000,
    10000000000000,
    1000000000000,
    100000000000,
    10000000000,
    1000000000,
    100000000,
    10000000,
    1000000,
    100000,
    10000,
    1000,
    100,
    10,
    1,
];

/// Parse the (left-aligned, zero-padded) bytes of a numeric token as a `u64`.
///
/// Two things were missing here, and both of them made
/// `get_number` return a number the document does not contain:
///
///  1. `ASCII_TO_NUMBER` maps every non-digit to 0, so any byte that is not a
///     digit was silently read as a zero. Harmless while the tokenizer refused
///     `-` and `.`; once the tokenizer accepts `-3` and `1.5` as numeric tokens it
///     would turn them into `3` and `105`. The assert below rejects a token
///     byte that is neither an ASCII digit nor the zero padding, and it is
///     exact: for a digit `byte - value == 48`, and for every other byte
///     `value` is 0, so the first factor can only vanish at `byte == 48`, which
///     is a digit. Reading decimals and negatives is `get_value`'s job (raw
///     bytes); `get_number` is for plain unsigned integers.
///
///  2. 20 digits reach 10^20 - 1, above `u64::MAX`, and `as u64` truncated mod
///     2^64: `99999999999999999999` came back as `7766279631452241919` with no
///     error at all. A 64-bit range check is the cheapest sound fix -- a `lt`
///     against 2^64 would cost a full field decomposition -- and it is exact,
///     since `u64::MAX` is `2^64 - 1`. 21 digits or more never get here:
///     `extract_string_entry` already rejects `json_length > StringBytes`.
///
/// The failure of the range check carries the generic
/// `call to assert_max_bit_size` message, not a bespoke one.
fn extract_number_from_array(arr: [u8; U64_LENGTH_AS_BASE10_STRING], json_length: Field) -> u64 {
    let mut parsed_number: Field = 0;
    for i in 0..U64_LENGTH_AS_BASE10_STRING {
        parsed_number *= 10;

        let value = ASCII_TO_NUMBER[arr[i] as u32] as Field;
        let byte = arr[i] as Field;
        assert(
            (byte - value - 48) * byte == 0,
            "get_number: numeric token is not a plain unsigned integer",
        );
        parsed_number += value;
    }
    parsed_number /= NUMBER_OFFSET_SHIFT[cast_num_to_u32(json_length)];
    parsed_number.assert_max_bit_size::<64>();
    parsed_number as u64
}

/// getter methods for extracting numeric values out of a JSON struct
///
/// numeric values must fit into a `u64` type.
/// decimal values and scientific notation are not yet supported
impl<let NumBytes: u32, let NumPackedFields: u32, let MaxNumTokens: u32, let MaxNumValues: u32, let MaxKeyFields: u32> JSON<NumBytes, NumPackedFields, MaxNumTokens, MaxNumValues, MaxKeyFields> {

    /// if the root JSON is an object, extract a numeric value given by `key`
    ///
    /// returns an Option<u64> which will be null if the key does not exist
    pub fn get_number<K>(self, key: K) -> Option<u64>
    where
        K: KeyHashable,
    {
        let (exists, entry, _) = self.get_json_entry(key);
        assert(
            (entry.entry_type - NUMERIC_TOKEN as Field) * exists as Field == 0,
            "get_number: entry exists but is not a number!",
        );
        let parsed_string: [u8; U64_LENGTH_AS_BASE10_STRING] = self.extract_string_entry(entry);

        if exists {
            Option::some(extract_number_from_array(parsed_string, entry.json_length))
        } else {
            Option::none()
        }
    }

    /// if the root JSON is an object, extract a u64 value given by `key`
    ///
    /// will revert if the number does not exist
    pub fn get_number_unchecked<K>(self, key: K) -> u64
    where
        K: KeyHashable,
    {
        let entry = self.get_json_entry_unchecked(key);
        assert(
            entry.entry_type == NUMERIC_TOKEN as Field,
            "get_number_unchecked: entry exists but is not a number!",
        );
        let parsed_string: [u8; U64_LENGTH_AS_BASE10_STRING] = self.extract_string_entry(entry);

        extract_number_from_array(parsed_string, entry.json_length)
    }

    /// if the root JSON is an array, extract a numeric value given by the position of the target in the source array
    ///
    /// returns an Option<u64> which will be null if the number does not exist
    pub fn get_number_from_array(self, array_index: Field) -> Option<u64> {
        let (entry, valid, _) = self.get_entry_from_array(array_index);
        if valid {
            assert_eq(
                entry.entry_type,
                NUMERIC_TOKEN as Field,
                "get_number: entry exists but is not a number!",
            );
        }

        let parsed_string: [u8; U64_LENGTH_AS_BASE10_STRING] = self.extract_string_entry(entry);
        let result = extract_number_from_array(parsed_string, entry.json_length);

        if valid {
            Option::some(result)
        } else {
            Option::none()
        }
    }

    /// if the root JSON is an array, extract a numeric value given by the position of the target in the source array
    ///
    /// will revert if the number does not exist
    pub fn get_number_from_array_unchecked(self, array_index: Field) -> u64 {
        let result = self.get_number_from_array(array_index);
        result.expect(f"array index out of bounds")
    }
}

// ============================================================================
// `get_number` is sound only for plain unsigned integers
// ============================================================================

type NumJson = JSON<48, 5, 16, 9, 2>;

#[test]
fn number_u64_max_is_read_exactly() {
    let json: NumJson = JSON::parse_json_from_string("{\"a\":18446744073709551615}");
    assert(json.get_number_unchecked("a".as_bytes()) == 18446744073709551615);
}

#[test(should_fail)]
fn number_one_past_u64_max_fails() {
    let json: NumJson = JSON::parse_json_from_string("{\"a\":18446744073709551616}");
    let _ = json.get_number_unchecked("a".as_bytes());
}

/// F2 1.3: this used to return 7766279631452241919 (10^20 - 1 mod 2^64).
#[test(should_fail)]
fn number_twenty_nines_no_longer_wraps() {
    let json: NumJson = JSON::parse_json_from_string("{\"a\":99999999999999999999}");
    let _ = json.get_number_unchecked("a".as_bytes());
}

/// 21 digits never reach the range check: `extract_string_entry` refuses a
/// token longer than the 20-byte buffer first.
#[test(should_fail_with = "get_string, string size is larger than StringBytes")]
fn number_twenty_one_digits_fails() {
    let json: NumJson = JSON::parse_json_from_string("{\"a\":999999999999999999999}");
    let _ = json.get_number_unchecked("a".as_bytes());
}

#[test(should_fail_with = "get_number: numeric token is not a plain unsigned integer")]
fn number_negative_is_refused_by_get_number() {
    let json: NumJson = JSON::parse_json_from_string("{\"a\":-3}");
    let _ = json.get_number_unchecked("a".as_bytes());
}

#[test(should_fail_with = "get_number: numeric token is not a plain unsigned integer")]
fn number_decimal_is_refused_by_get_number() {
    let json: NumJson = JSON::parse_json_from_string("{\"a\":1.5}");
    let _ = json.get_number_unchecked("a".as_bytes());
}

/// ...but the raw bytes are readable, which is how the adapter reads decimals
/// and negatives.
#[test]
fn number_negative_raw_bytes_are_readable() {
    let json: NumJson = JSON::parse_json_from_string("{\"a\":-3}");
    let v: JSONValue<16> = json.get_value("a".as_bytes()).unwrap();
    assert(v.is_number());
    assert(v.value.len() == 2);
    assert(v.value.get(0) == 45); // '-'
    assert(v.value.get(1) == 51); // '3'
}

#[test]
fn number_decimal_raw_bytes_are_readable() {
    let json: NumJson = JSON::parse_json_from_string("{\"a\":1.5}");
    let v: JSONValue<16> = json.get_value("a".as_bytes()).unwrap();
    assert(v.value.len() == 3);
    assert(v.value.get(1) == 46); // '.'
}

/// the `Option::none` path must not trip the new per-byte assert
#[test]
fn number_missing_key_still_returns_none() {
    let json: NumJson = JSON::parse_json_from_string("{\"a\":1,\"b\":2}");
    assert(json.get_number("zz".as_bytes()).is_none());
}

#[test]
fn number_from_array_out_of_bounds_still_returns_none() {
    let json: NumJson = JSON::parse_json_from_string("[1,2,3]");
    assert(json.get_number_from_array(9).is_none());
}

#[test]
fn number_zero_and_leading_zero_free_values_still_work() {
    let json: NumJson = JSON::parse_json_from_string("{\"a\":0,\"b\":1000}");
    assert(json.get_number_unchecked("a".as_bytes()) == 0);
    assert(json.get_number_unchecked("b".as_bytes()) == 1000);
}
