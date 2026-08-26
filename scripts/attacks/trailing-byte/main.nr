fn main(text: [u8; 64]) -> pub u64 {
    let json: json_parser::JSONGeneric<64, 6, 24, 13, 2> =
        json_parser::JSONGeneric::parse_json(text);
    json.get_number_unchecked("a".as_bytes())
}
