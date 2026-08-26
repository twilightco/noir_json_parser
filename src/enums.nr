/// Scan modes of the tokenizer's byte automaton.
///
/// The mode is the whole state of the scanner: `JSON_CAPTURE_TABLE` is indexed by
/// `mode * 256 + byte`, so a mode is worth 256 table entries.
///
/// The original implementation had four modes, a single `NUMERIC_CAPTURE`, and a separate
/// "the previous byte was a backslash" bit that doubled the table. Neither a single
/// numeric mode nor a single escape bit can remember *where* in a construct the scanner
/// is, so `1.2.3`, `\q` and `\u00zz` all parsed. The modes below turn both into real
/// automata:
///
///     number: -? ( 0 | [1-9][0-9]* ) ( \. [0-9]+ )? ( [eE] [+-]? [0-9]+ )?
///     escape: \ ( ["\\/bfnrt] | u [0-9a-fA-F]{4} )
///
/// Every mode that is not an accepting state of its grammar (`NUMERIC_MINUS_CAPTURE`,
/// `NUMERIC_DOT_CAPTURE`, `NUMERIC_EXP_CAPTURE`, `NUMERIC_EXP_SIGN_CAPTURE`, and all five
/// escape modes) makes the value terminators an error, which is exactly how "a byte is
/// mandatory here" is expressed in a table that only ever sees one byte at a time.
///
/// ORDER MATTERS. A token can only close in a mode that is an accepting state, so only
/// the first `NUM_PUSHING_CAPTURE_MODES` modes can ever push a transcript entry -- and
/// `ASCII_TO_TOKEN_TABLE` and `PROCESS_RAW_TRANSCRIPT_TABLE`, which are indexed by the
/// `mode * 256 + byte` of a *pushed* entry, are sized to just those. Moving a pushing
/// mode above the line reads past the end of both. `test_pushing_modes_come_first` holds
/// the ordering to it.
///
/// `ERROR_CAPTURE` must stay one past the last real mode: it is not a state the scanner
/// can be in, it is the value that flags a rejected byte, and it works by pushing the
/// next `JSON_CAPTURE_TABLE` lookup out of bounds.
pub(crate) mod CaptureMode {
    // -- accepting states: a value terminator closes the token being scanned ----------
    pub(crate) global GRAMMAR_CAPTURE: Field = 0;
    pub(crate) global STRING_CAPTURE: Field = 1;
    /// integer digits, entered from a leading `1`..`9`
    pub(crate) global NUMERIC_CAPTURE: Field = 2;
    pub(crate) global LITERAL_CAPTURE: Field = 3;
    /// the integer part is exactly `0`: no second integer digit, `01` is not JSON
    pub(crate) global NUMERIC_ZERO_CAPTURE: Field = 4;
    /// fraction digits: digits, an exponent or a terminator, never a second `.`
    pub(crate) global NUMERIC_FRAC_CAPTURE: Field = 5;
    /// exponent digits: `1e05` is legal, so no leading-zero rule applies here
    pub(crate) global NUMERIC_EXP_DIGITS_CAPTURE: Field = 6;
    /// how many modes can close a token; see the ordering note above
    pub(crate) global NUM_PUSHING_CAPTURE_MODES: u32 = 7;

    // -- non-accepting states: a specific byte is mandatory ---------------------------
    /// after `-`: a digit is mandatory, and it decides between `0` and `1`..`9`
    pub(crate) global NUMERIC_MINUS_CAPTURE: Field = 7;
    /// after `.`: a digit is mandatory, `1.` is not JSON
    pub(crate) global NUMERIC_DOT_CAPTURE: Field = 8;
    /// after `e`/`E`: a digit or a sign is mandatory
    pub(crate) global NUMERIC_EXP_CAPTURE: Field = 9;
    /// after the exponent's `+`/`-`: a digit is mandatory, and no second sign
    pub(crate) global NUMERIC_EXP_SIGN_CAPTURE: Field = 10;
    /// after `\` inside a string: one of `"\/bfnrtu`
    pub(crate) global STRING_ESCAPE_CAPTURE: Field = 11;
    /// inside `\uXXXX`, n hex digits read
    pub(crate) global STRING_UNICODE_1_CAPTURE: Field = 12;
    pub(crate) global STRING_UNICODE_2_CAPTURE: Field = 13;
    pub(crate) global STRING_UNICODE_3_CAPTURE: Field = 14;
    pub(crate) global STRING_UNICODE_4_CAPTURE: Field = 15;

    /// number of real scan modes
    pub(crate) global NUM_CAPTURE_MODES: u32 = 16;
    pub(crate) global ERROR_CAPTURE: Field = 16;

    /// size of `JSON_CAPTURE_TABLE`
    pub(crate) global CAPTURE_TABLE_SIZE: u32 = 4096;
    /// size of `ASCII_TO_TOKEN_TABLE` and `PROCESS_RAW_TRANSCRIPT_TABLE`
    pub(crate) global PUSHED_TABLE_SIZE: u32 = 1792;
}

pub(crate) mod Token {
    pub(crate) global NO_TOKEN: u32 = 0;
    pub(crate) global BEGIN_OBJECT_TOKEN: u32 = 1;
    pub(crate) global END_OBJECT_TOKEN: u32 = 2;
    pub(crate) global BEGIN_ARRAY_TOKEN: u32 = 3;
    pub(crate) global END_ARRAY_TOKEN: u32 = 4;
    pub(crate) global KEY_SEPARATOR_TOKEN: u32 = 5;
    pub(crate) global VALUE_SEPARATOR_TOKEN: u32 = 6;
    pub(crate) global STRING_TOKEN: u32 = 7;
    pub(crate) global NUMERIC_TOKEN: u32 = 8;
    pub(crate) global LITERAL_TOKEN: u32 = 9;
    pub(crate) global KEY_TOKEN: u32 = 10;
    pub(crate) global NUM_TOKENS: u32 = 11;
    pub(crate) global NUM_TOKENS_MUL_2: u32 = 22;
}

pub mod Layer {
    pub global OBJECT_LAYER: u32 = 0;
    pub global ARRAY_LAYER: u32 = 1;
}
