/// Scan modes of the tokenizer's byte automaton.
///
/// The mode is the whole state of the scanner: `JSON_CAPTURE_TABLE` is indexed
/// by `previous_was_potential_escape_sequence * 2048 + mode * 256 + byte`, so a
/// mode is worth 256 table entries and the modes must stay in `0..8`.
///
/// The original implementation had four modes and a single `NUMERIC_CAPTURE`, which
/// can only classify bytes -- it cannot remember *where* in a number it is. The
/// four extra numeric modes below turn the number scanner into an automaton for
///
///     -? ( 0 | [1-9][0-9]* ) ( \. [0-9]+ )?
///
/// so that a leading zero, a bare `-`, a trailing `.` and a second `.` are all
/// rejected inside `parse_json`, not left to the getter. Every mode that is not
/// an accepting state of that grammar (`NUMERIC_MINUS_CAPTURE`,
/// `NUMERIC_DOT_CAPTURE`) makes the value terminators an error, which is exactly
/// how "a digit is mandatory here" is expressed.
///
/// `ERROR_CAPTURE` must stay one past the last real mode: it is not a state the
/// scanner can be in, it is the value that flags a rejected byte.
pub(crate) mod CaptureMode {
    pub(crate) global GRAMMAR_CAPTURE: Field = 0;
    pub(crate) global STRING_CAPTURE: Field = 1;
    /// integer digits, entered from a leading `1`..`9`
    pub(crate) global NUMERIC_CAPTURE: Field = 2;
    pub(crate) global LITERAL_CAPTURE: Field = 3;
    /// after `-`: a digit is mandatory, nothing else may follow
    pub(crate) global NUMERIC_MINUS_CAPTURE: Field = 4;
    /// the integer part is exactly `0`: only `.` or a value terminator may follow
    pub(crate) global NUMERIC_ZERO_CAPTURE: Field = 5;
    /// after `.`: a digit is mandatory, nothing else may follow
    pub(crate) global NUMERIC_DOT_CAPTURE: Field = 6;
    /// fraction digits: digits or a value terminator, never a second `.`
    pub(crate) global NUMERIC_FRAC_CAPTURE: Field = 7;
    pub(crate) global ERROR_CAPTURE: Field = 8;
    /// number of real scan modes
    pub(crate) global NUM_CAPTURE_MODES: u32 = 8;
    /// stride of one `previous_was_potential_escape_sequence` half of
    /// `JSON_CAPTURE_TABLE`, and the full size of `ASCII_TO_TOKEN_TABLE` and
    /// `PROCESS_RAW_TRANSCRIPT_TABLE` (a transcript entry is never pushed from
    /// the escape half, so those two only need the first half)
    pub(crate) global CAPTURE_TABLE_HALF: u32 = 2048;
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
