/**
 * @file helper methods that evaluate comparison operations on Field elements that are known to be of a fixed size (e.g. <2^16)
 **/
pub unconstrained fn get_lt_predicate_f(x: Field, y: Field) -> bool {
    let a = x as u32;
    let b = y as u32;
    let r = a < b;
    r
}

pub unconstrained fn get_lte_predicate_large(x: Field, y: Field) -> bool {
    let r = x.lt(y) | (x == y);
    r
}

pub fn lte_field_240_bit(x: Field, y: Field) -> bool {
    // Safety: check the comments below
    let predicate = unsafe { get_lte_predicate_large(x, y) };
    let delta = y as Field - x as Field;

    // Select `y - x` when the predicate is true and `x - y - 1` when it is false.
    // The selected value is non-negative exactly when the hint is correct:
    //   p = 1 -> y - x     >= 0  <=>  x <= y
    //   p = 0 -> x - y - 1 >= 0  <=>  x >  y
    // Expanding the selector:
    //   p * delta + (1 - p) * (-delta - 1) = 2 * p * delta - delta + p - 1
    let lt_parameter = 2 * (predicate as Field) * delta - delta + predicate as Field - 1;
    // checks that the bit length of lt_parameter is 240
    // i.e. checks the sign of lt_parameter
    lt_parameter.assert_max_bit_size::<240>();

    predicate
}

pub fn assert_lte_240_bit(x: Field, y: Field) {
    let delta = y as Field - x as Field;

    // no hint to check here: `x <= y` is exactly `y - x >= 0`
    delta.assert_max_bit_size::<240>();
}

pub fn lt_field_16_bit(x: Field, y: Field) -> bool {
    // Safety: check the comments below
    let predicate = unsafe { get_lt_predicate_f(x, y) };
    let delta = y as Field - x as Field;
    let lt_parameter = 2 * (predicate as Field) * delta - predicate as Field - delta;
    // checks that the bit length of lt_parameter is 16
    // i.e. checks the sign of lt_parameter
    lt_parameter.assert_max_bit_size::<16>();

    predicate
}

pub fn assert_gt_240_bit(lhs: Field, rhs: Field) {
    // lhs > rhs
    // -> lhs - rhs > 0
    // -> lhs - rhs - 1 >= 0
    let diff = lhs - rhs - 1;
    diff.assert_max_bit_size::<240>();
}

pub fn assert_lt_240_bit(lhs: Field, rhs: Field) {
    // lhs < rhs
    // -> rhs - lhs > 0
    // -> rhs - lhs - 1 >= 0
    let diff = rhs - lhs - 1;
    diff.assert_max_bit_size::<240>();
}
