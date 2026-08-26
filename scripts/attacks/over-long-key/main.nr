fn main(text: [u8; 200]) -> pub u64 {
    let json: json_parser::JSONGeneric<200, 10, 32, 17, 2> =
        json_parser::JSONGeneric::parse_json(text);
    json.get_number_unchecked("a".as_bytes())
}
