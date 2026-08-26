use crate::_string_tools::slice_packed_field::slice_fields;

pub(crate) fn slice_string<let StringBytes: u32, let HaystackPackedFields: u32>(
    haystack: [Field; HaystackPackedFields],
    start_bytes: Field,
    num_bytes: Field,
) -> [u8; StringBytes] {
    // We want to round up the quotient of StringBytes to the next multiple of 31
    let sliced: [Field; (StringBytes + 30) / 31] = slice_fields(haystack, start_bytes, num_bytes);

    let num_slices = StringBytes / 31;
    let overflow = StringBytes % 31;

    let mut parsed_string: [u8; StringBytes] = [0; StringBytes];
    for i in 0..num_slices {
        let sliced_bytes: [u8; 31] = sliced[i].to_be_bytes();
        for j in 0..31 {
            parsed_string[i * 31 + j] = sliced_bytes[j];
        }
    }

    // Exact multiples of 31 have no tail limb. This compile-time branch avoids
    // reading one element past `sliced` for those capacities.
    if overflow != 0 {
        let sliced_bytes: [u8; 31] = sliced[num_slices].to_be_bytes();
        for j in 0..overflow {
            parsed_string[num_slices * 31 + j] = sliced_bytes[j];
        }
    }
    parsed_string
}

#[test]
fn test_slice_string_string_bytes_multiple_of_31() {
    let json: crate::json::JSON<26, 4, 32, 17, 2> =
        crate::json::JSON::parse_json_from_string("{\"amount\":42,\"user\":\"bob\"}");

    let at_30: BoundedVec<u8, 30> = json.get_string("user".as_bytes()).unwrap();
    let at_31: BoundedVec<u8, 31> = json.get_string("user".as_bytes()).unwrap();
    let at_32: BoundedVec<u8, 32> = json.get_string("user".as_bytes()).unwrap();
    let at_62: BoundedVec<u8, 62> = json.get_string("user".as_bytes()).unwrap();
    let at_93: BoundedVec<u8, 93> = json.get_string("user".as_bytes()).unwrap();

    assert(at_30 == BoundedVec::from_array("bob".as_bytes()));
    assert(at_31 == BoundedVec::from_array("bob".as_bytes()));
    assert(at_32 == BoundedVec::from_array("bob".as_bytes()));
    assert(at_62 == BoundedVec::from_array("bob".as_bytes()));
    assert(at_93 == BoundedVec::from_array("bob".as_bytes()));
}

#[test]
fn test_slice_string_full_buffer_at_31_and_62() {
    let expected_31 = "abcdefghijklmnopqrstuvwxyz01234".as_bytes();
    let json_31: crate::json::JSON<39, 5, 32, 17, 2> = crate::json::JSON::parse_json_from_string(
        "{\"v\":\"abcdefghijklmnopqrstuvwxyz01234\"}",
    );
    let v_31: BoundedVec<u8, 31> = json_31.get_string("v".as_bytes()).unwrap();
    assert(v_31.len() == 31, "31-byte value");
    for i in 0..31 {
        assert(v_31.get(i) == expected_31[i], "31-byte value, wrong byte");
    }

    let expected_62 =
        "abcdefghijklmnopqrstuvwxyz01234ABCDEFGHIJKLMNOPQRSTUVWXYZ56789".as_bytes();
    let json_62: crate::json::JSON<70, 6, 32, 17, 2> = crate::json::JSON::parse_json_from_string(
        "{\"v\":\"abcdefghijklmnopqrstuvwxyz01234ABCDEFGHIJKLMNOPQRSTUVWXYZ56789\"}",
    );
    let v_62: BoundedVec<u8, 62> = json_62.get_string("v".as_bytes()).unwrap();
    assert(v_62.len() == 62, "62-byte value");
    for i in 0..62 {
        assert(v_62.get(i) == expected_62[i], "62-byte value, wrong byte");
    }
}

#[test]
fn test_slice_string_get_value_at_31() {
    let json: crate::json::JSON<26, 4, 32, 17, 2> =
        crate::json::JSON::parse_json_from_string("{\"amount\":42,\"user\":\"bob\"}");
    let v = json.get_value::<_, 31>("user".as_bytes()).unwrap();
    assert(v.is_string(), "value is a string");
    assert(v.value == BoundedVec::from_array("bob".as_bytes()), "value is bob");
}
