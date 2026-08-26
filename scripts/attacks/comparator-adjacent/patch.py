old = """pub unconstrained fn get_lte_predicate_large(x: Field, y: Field) -> bool {
    let r = x.lt(y) | (x == y);
    r
}"""
new = """pub unconstrained fn get_lte_predicate_large(x: Field, y: Field) -> bool {
    // ATTACK: always claim `x > y`
    let _ = x.lt(y) | (x == y);
    false
}"""
apply_to = "src/_comparison_tools/lt.nr"

# and a way in, since the gadget is crate-private
also = [(
    "src/lib.nr",
    "use json::JSON;",
    """use json::JSON;

pub fn attack_lte_240(x: Field, y: Field) -> bool {
    crate::_comparison_tools::lt::lte_field_240_bit(x, y)
}""",
)]
