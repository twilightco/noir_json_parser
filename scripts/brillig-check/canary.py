# A deliberately uncovered Brillig call, added to a throwaway copy of the library.
#
# The point is not to test the library -- it is to test the *detector*. If the lint stops
# firing on this, the check has gone vacuous and is no longer evidence of anything, which
# is exactly the failure this whole script exists to prevent.
apply_to = "src/utils.nr"
old = """pub(crate) fn cast_num_to_u32(field_val: Field) -> u32 {"""
new = """unconstrained fn __canary(x: Field) -> Field {
    x + 1
}

/// CANARY: nothing constrains the return value against the input.
pub fn canary_uncovered(x: Field) -> Field {
    // Safety: deliberately unsafe
    let y = unsafe { __canary(x) };
    y * 2
}

pub(crate) fn cast_num_to_u32(field_val: Field) -> u32 {"""

also = [(
    "src/lib.nr",
    "use json::JSON;",
    """use json::JSON;

pub fn canary_uncovered(x: Field) -> Field {
    crate::utils::canary_uncovered(x)
}""",
)]
