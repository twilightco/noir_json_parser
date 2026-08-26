//! Contains methods used to generate tables in `json_tables.nr`. These table generation methods shouldn't be used inside of actual circuits.
use crate::enums::CaptureMode::{
    CAPTURE_TABLE_SIZE, NUM_CAPTURE_MODES, NUM_PUSHING_CAPTURE_MODES, PUSHED_TABLE_SIZE,
    STRING_CAPTURE,
};
use crate::enums::Layer::{ARRAY_LAYER, OBJECT_LAYER};
use crate::enums::Token::{
    BEGIN_ARRAY_TOKEN, BEGIN_OBJECT_TOKEN, END_ARRAY_TOKEN, END_OBJECT_TOKEN, KEY_SEPARATOR_TOKEN,
    KEY_TOKEN, LITERAL_TOKEN, NO_TOKEN, NUM_TOKENS, NUMERIC_TOKEN, STRING_TOKEN,
    VALUE_SEPARATOR_TOKEN,
};
use crate::json_tables::ASCII_TO_TOKEN_TABLE;
use crate::json_tables::JSON_CAPTURE_TABLE;
use crate::json_tables::PROCESS_RAW_TRANSCRIPT_TABLE;
use crate::json_tables::TOKEN_FLAGS_TABLE;
use crate::json_tables::TOKEN_VALIDATION_TABLE;
use crate::token_flags::TokenFlags;
use crate::transcript_entry::ValidationFlags;
use super::make_tables_subtables::{
    escape_capture_rows, GRAMMAR_CAPTURE_ERROR_FLAG, GRAMMAR_CAPTURE_INCREASE_LENGTH,
    GRAMMAR_CAPTURE_PUSH_TRANSCRIPT, GRAMMAR_CAPTURE_TABLE, GRAMMAR_CAPTURE_TOKEN,
    LITERAL_CAPTURE_ERROR_FLAG, LITERAL_CAPTURE_INCREASE_LENGTH, LITERAL_CAPTURE_PUSH_TRANSCRIPT,
    LITERAL_CAPTURE_TABLE, LITERAL_CAPTURE_TOKEN, numeric_capture_rows, string_capture_row,
    TOKEN_IS_NUMERIC_OR_LITERAL,
};

/// The five parallel sub-tables, one row per scan mode, in `CaptureMode` order.
///
/// This used to be five `global`s of four rows each. The four
/// extra numeric modes are computed rather than written out (see
/// `extra_numeric_capture_rows`), so the rows are assembled here instead.
struct CaptureSubTables {
    capture: [[Field; 128]; NUM_CAPTURE_MODES],
    token: [[u32; 128]; NUM_CAPTURE_MODES],
    push_transcript: [[bool; 128]; NUM_CAPTURE_MODES],
    increase_length: [[bool; 128]; NUM_CAPTURE_MODES],
    error_flag: [[bool; 128]; NUM_CAPTURE_MODES],
}

unconstrained fn capture_sub_tables() -> CaptureSubTables {
    // `n` holds NUMERIC, ZERO, FRAC, EXP_DIGITS, MINUS, DOT, EXP, EXP_SIGN and
    // `e` holds STRING_ESCAPE, STRING_UNICODE_1..4, both in that order. Together
    // with the four hand-written rows they cover all 16 modes.
    let n = numeric_capture_rows();
    let e = escape_capture_rows();
    let string = string_capture_row();
    CaptureSubTables {
        capture: [
            GRAMMAR_CAPTURE_TABLE,
            string.capture,
            n[0].capture,
            LITERAL_CAPTURE_TABLE,
            n[1].capture,
            n[2].capture,
            n[3].capture,
            n[4].capture,
            n[5].capture,
            n[6].capture,
            n[7].capture,
            e[0].capture,
            e[1].capture,
            e[2].capture,
            e[3].capture,
            e[4].capture,
        ],
        token: [
            GRAMMAR_CAPTURE_TOKEN,
            string.token,
            n[0].token,
            LITERAL_CAPTURE_TOKEN,
            n[1].token,
            n[2].token,
            n[3].token,
            n[4].token,
            n[5].token,
            n[6].token,
            n[7].token,
            e[0].token,
            e[1].token,
            e[2].token,
            e[3].token,
            e[4].token,
        ],
        push_transcript: [
            GRAMMAR_CAPTURE_PUSH_TRANSCRIPT,
            string.push_transcript,
            n[0].push_transcript,
            LITERAL_CAPTURE_PUSH_TRANSCRIPT,
            n[1].push_transcript,
            n[2].push_transcript,
            n[3].push_transcript,
            n[4].push_transcript,
            n[5].push_transcript,
            n[6].push_transcript,
            n[7].push_transcript,
            e[0].push_transcript,
            e[1].push_transcript,
            e[2].push_transcript,
            e[3].push_transcript,
            e[4].push_transcript,
        ],
        increase_length: [
            GRAMMAR_CAPTURE_INCREASE_LENGTH,
            string.increase_length,
            n[0].increase_length,
            LITERAL_CAPTURE_INCREASE_LENGTH,
            n[1].increase_length,
            n[2].increase_length,
            n[3].increase_length,
            n[4].increase_length,
            n[5].increase_length,
            n[6].increase_length,
            n[7].increase_length,
            e[0].increase_length,
            e[1].increase_length,
            e[2].increase_length,
            e[3].increase_length,
            e[4].increase_length,
        ],
        error_flag: [
            GRAMMAR_CAPTURE_ERROR_FLAG,
            string.error_flag,
            n[0].error_flag,
            LITERAL_CAPTURE_ERROR_FLAG,
            n[1].error_flag,
            n[2].error_flag,
            n[3].error_flag,
            n[4].error_flag,
            n[5].error_flag,
            n[6].error_flag,
            n[7].error_flag,
            e[0].error_flag,
            e[1].error_flag,
            e[2].error_flag,
            e[3].error_flag,
            e[4].error_flag,
        ],
    }
}

/// Sized to `NUM_PUSHING_CAPTURE_MODES`, not `NUM_CAPTURE_MODES`: it is indexed by the
/// `mode * 256 + byte` of a transcript entry, and an entry can only be pushed from an
/// accepting mode. See the ordering note in `CaptureMode`.
unconstrained fn make_ascii_to_token_table() -> [Field; PUSHED_TABLE_SIZE] {
    let sub = capture_sub_tables();
    let mut result: [Field; PUSHED_TABLE_SIZE] = [0; PUSHED_TABLE_SIZE];
    for i in 0..NUM_PUSHING_CAPTURE_MODES {
        for j in 0..128 {
            let token = sub.token[i][j];
            result[i * 256 + j] = token as Field;
        }
        for j in 0..128 {
            result[i * 256 + j + 128] = 0;
        }
    }
    result
}

unconstrained fn make_token_validation_table() -> [Field; NUM_TOKENS * NUM_TOKENS * 2] {
    // index = layer type, current token and next token
    // output is layer type
    // 11 tokens , 2 layers = 11 * 11 * 2 = 121 * 2 = 242
    // object contexts
    let no_change =
        ValidationFlags { push_layer: false, push_layer_type_of_root: false, pop_layer: false };
    let error_flags_field = 0x1000000;
    let begin_new_object_flags = ValidationFlags {
        push_layer: true,
        push_layer_type_of_root: OBJECT_LAYER != 0,
        pop_layer: false,
    };
    let begin_new_array_flags = ValidationFlags {
        push_layer: true,
        push_layer_type_of_root: ARRAY_LAYER != 0,
        pop_layer: false,
    };
    let end_object_or_array_flags: ValidationFlags =
        ValidationFlags { push_layer: false, push_layer_type_of_root: false, pop_layer: true };

    let token_ids: [u32; NUM_TOKENS] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

    let error_token_outcomes: [Field; NUM_TOKENS] = token_ids.map(|_| error_flags_field);
    let object_layer_begin_object_token_outcomes: [Field; NUM_TOKENS] = token_ids.map(|token| {
        let mut result = error_flags_field;
        if (token == KEY_TOKEN) {
            result = no_change.to_field();
        }
        if (token == END_OBJECT_TOKEN) {
            result = end_object_or_array_flags.to_field();
        }
        result
    });

    let object_layer_key_token_outcomes: [Field; NUM_TOKENS] = token_ids.map(|token| {
        let mut result = no_change.to_field();
        if (token != KEY_SEPARATOR_TOKEN) {
            result = error_flags_field;
        }
        result
    });

    let object_layer_key_separator_token_outcomes: [Field; NUM_TOKENS] = token_ids.map(|token| {
        let mut result = error_flags_field;
        if (token == STRING_TOKEN) | (token == LITERAL_TOKEN) | (token == NUMERIC_TOKEN) {
            result = no_change.to_field();
        }
        if (token == BEGIN_ARRAY_TOKEN) {
            result = begin_new_array_flags.to_field();
        }
        if (token == BEGIN_OBJECT_TOKEN) {
            result = begin_new_object_flags.to_field();
        }
        result
    });

    let object_layer_value_token_outcomes: [Field; NUM_TOKENS] = token_ids.map(|token| {
        let mut result = error_flags_field;
        if (token == VALUE_SEPARATOR_TOKEN) {
            result = no_change.to_field();
        }
        if (token == END_OBJECT_TOKEN) {
            result = end_object_or_array_flags.to_field();
        }
        result
    });

    let object_layer_end_object_outcomes: [Field; NUM_TOKENS] = token_ids.map(|token| {
        let mut result = error_flags_field;
        if (token == VALUE_SEPARATOR_TOKEN) {
            result = no_change.to_field();
        }
        if (token == END_OBJECT_TOKEN) {
            result = end_object_or_array_flags.to_field();
        }
        // we can reach the end of the JSON via this path
        if (token == NO_TOKEN) {
            result = no_change.to_field();
        }
        result
    });

    let object_layer_value_separator_token_outcomes: [Field; NUM_TOKENS] = token_ids.map(|token| {
        let mut result = error_flags_field;
        if (token == KEY_TOKEN) {
            result = no_change.to_field();
        }
        result
    });

    let mut object_layer_flags: [[Field; NUM_TOKENS]; NUM_TOKENS] = [[0; NUM_TOKENS]; NUM_TOKENS];
    let mut array_layer_flags: [[Field; NUM_TOKENS]; NUM_TOKENS] = [[0; NUM_TOKENS]; NUM_TOKENS];
    let no_token_outcomes: [Field; NUM_TOKENS] = token_ids.map(|token| {
        let mut result = error_flags_field;
        if (token == NO_TOKEN) {
            result = no_change.to_field();
        }
        result
    });

    object_layer_flags[NO_TOKEN] = no_token_outcomes;
    object_layer_flags[BEGIN_OBJECT_TOKEN] = object_layer_begin_object_token_outcomes;
    object_layer_flags[END_OBJECT_TOKEN] = object_layer_end_object_outcomes;
    object_layer_flags[BEGIN_ARRAY_TOKEN] = error_token_outcomes;
    object_layer_flags[END_ARRAY_TOKEN] = object_layer_value_token_outcomes;
    object_layer_flags[KEY_SEPARATOR_TOKEN] = object_layer_key_separator_token_outcomes;
    object_layer_flags[VALUE_SEPARATOR_TOKEN] = object_layer_value_separator_token_outcomes;
    object_layer_flags[STRING_TOKEN] = object_layer_value_token_outcomes;
    object_layer_flags[NUMERIC_TOKEN] = object_layer_value_token_outcomes;
    object_layer_flags[LITERAL_TOKEN] = object_layer_value_token_outcomes;
    object_layer_flags[KEY_TOKEN] = object_layer_key_token_outcomes;

    let array_layer_begin_array_token_outcomes: [Field; NUM_TOKENS] = token_ids.map(|token: u32| {
        let mut result = error_flags_field;
        if (token == STRING_TOKEN) | (token == LITERAL_TOKEN) | (token == NUMERIC_TOKEN) {
            result = no_change.to_field();
        }
        if (token == BEGIN_OBJECT_TOKEN) {
            result = begin_new_object_flags.to_field();
        }
        if (token == BEGIN_ARRAY_TOKEN) {
            result = begin_new_array_flags.to_field();
        }
        if (token == END_ARRAY_TOKEN) {
            result = end_object_or_array_flags.to_field();
        }
        result
    });

    let array_layer_value_token_outcomes: [Field; NUM_TOKENS] = token_ids.map(|token| {
        let mut result = error_flags_field;
        if (token == VALUE_SEPARATOR_TOKEN) {
            result = no_change.to_field();
        }
        if (token == END_ARRAY_TOKEN) {
            result = end_object_or_array_flags.to_field();
        }
        result
    });

    let array_layer_value_separator_token_outcomes: [Field; NUM_TOKENS] = token_ids.map(|token| {
        let mut result = error_flags_field;
        if (token == STRING_TOKEN) | (token == LITERAL_TOKEN) | (token == NUMERIC_TOKEN) {
            result = no_change.to_field();
        }
        if (token == BEGIN_OBJECT_TOKEN) {
            result = begin_new_object_flags.to_field();
        }
        if (token == BEGIN_ARRAY_TOKEN) {
            result = begin_new_array_flags.to_field();
        }
        result
    });

    let array_layer_value_token_outcomes: [Field; NUM_TOKENS] = token_ids.map(|token| {
        let mut result = error_flags_field;
        if (token == VALUE_SEPARATOR_TOKEN) {
            result = no_change.to_field();
        }
        if (token == END_ARRAY_TOKEN) {
            result = end_object_or_array_flags.to_field();
        }
        result
    });
    let array_layer_end_array_outcomes: [Field; NUM_TOKENS] = token_ids.map(|token| {
        let mut result = error_flags_field;
        if (token == VALUE_SEPARATOR_TOKEN) {
            result = no_change.to_field();
        }
        if (token == END_ARRAY_TOKEN) {
            result = end_object_or_array_flags.to_field();
        }
        // we can reach the end of the JSON via this path
        if (token == NO_TOKEN) {
            result = no_change.to_field();
        }
        result
    });
    let array_layer_end_object_outcomes: [Field; NUM_TOKENS] = token_ids.map(|token| {
        let mut result = error_flags_field;
        if (token == VALUE_SEPARATOR_TOKEN) {
            result = no_change.to_field();
        }
        if (token == END_ARRAY_TOKEN) {
            result = end_object_or_array_flags.to_field();
        }
        result
    });

    array_layer_flags[NO_TOKEN] = no_token_outcomes;
    array_layer_flags[BEGIN_OBJECT_TOKEN] = error_token_outcomes;
    array_layer_flags[END_OBJECT_TOKEN] = array_layer_end_object_outcomes;
    array_layer_flags[BEGIN_ARRAY_TOKEN] = array_layer_begin_array_token_outcomes;
    array_layer_flags[END_ARRAY_TOKEN] = array_layer_end_array_outcomes;
    array_layer_flags[KEY_SEPARATOR_TOKEN] = error_token_outcomes;
    array_layer_flags[VALUE_SEPARATOR_TOKEN] = array_layer_value_separator_token_outcomes;
    array_layer_flags[STRING_TOKEN] = array_layer_value_token_outcomes;
    array_layer_flags[NUMERIC_TOKEN] = array_layer_value_token_outcomes;
    array_layer_flags[LITERAL_TOKEN] = array_layer_value_token_outcomes;
    array_layer_flags[KEY_TOKEN] = error_token_outcomes;
    let mut flattened_flags: [Field; NUM_TOKENS * NUM_TOKENS * 2] =
        [0; NUM_TOKENS * NUM_TOKENS * 2];
    let NN = (NUM_TOKENS * NUM_TOKENS);
    for j in 0..NUM_TOKENS {
        for k in 0..NUM_TOKENS {
            flattened_flags[OBJECT_LAYER * NN + j * NUM_TOKENS + k] = object_layer_flags[j][k];
            flattened_flags[ARRAY_LAYER * NN + j * NUM_TOKENS + k] = array_layer_flags[j][k];
        }
    }
    flattened_flags
}

unconstrained fn make_json_capture_table() -> [Field; CAPTURE_TABLE_SIZE] {
    let sub = capture_sub_tables();
    let mut result: [Field; CAPTURE_TABLE_SIZE] = [0; CAPTURE_TABLE_SIZE];
    for i in 0..NUM_CAPTURE_MODES {
        for j in 0..128 {
            let scan_token = sub.capture[i][j];
            let push_transcript = sub.push_transcript[i][j] as Field;
            let increase_length = sub.increase_length[i][j] as Field;
            let error = sub.error_flag[i][j] as Field;

            let full = scan_token
                + push_transcript * 0x100
                + increase_length * 0x10000
                + error * 0x100000000;
            result[i * 256 + j] = full;
        }
        // bytes 0x80..0xFF
        //
        // The original implementation makes every one of them an error in every
        // mode, which is why a single accented letter anywhere in a document
        // makes the whole document unparseable. RFC 8259 allows any Unicode
        // scalar value inside a string, and a key *is* a string, so inside
        // `STRING_CAPTURE` they are ordinary string content (same encoding as
        // any other content byte: stay in the mode, extend the token, do not
        // push, no error). Outside a string they stay an error: no JSON token
        // starts with a high byte, and no escape sequence contains one.
        //
        // This is byte transparency, NOT UTF-8 validation: an overlong
        // encoding, a truncated sequence or a lone continuation byte all get
        // through, and `get_string` hands back the raw bytes. That is a
        // deliberate, documented guarantee (see the README), not an oversight:
        // the bytes come from the
        // server over TLS, so malformed UTF-8 is not something a prover can
        // introduce, and validating the whole record would make one bad byte in
        // a field no predicate reads sink the entire proof.
        for j in 0..128 {
            let index = i * 256 + j + 128;
            if i as Field == STRING_CAPTURE {
                // scan_token = STRING_CAPTURE, push = 0, increase_length = 1
                result[index] = STRING_CAPTURE + 0x10000;
            } else {
                result[index] = 0x100000000; // error flag
            }
        }
    }

    result
}

/// Sized to `NUM_PUSHING_CAPTURE_MODES` for the same reason as
/// `make_ascii_to_token_table`.
unconstrained fn make_process_raw_transcript_table() -> [Field; PUSHED_TABLE_SIZE] {
    let sub = capture_sub_tables();
    let mut result: [Field; PUSHED_TABLE_SIZE] = [0; PUSHED_TABLE_SIZE];
    for i in 0..NUM_PUSHING_CAPTURE_MODES {
        for j in 0..128 {
            let token = sub.token[i][j];
            let token_is_numeric_or_literal = TOKEN_IS_NUMERIC_OR_LITERAL[token];
            let new_grammar = GRAMMAR_CAPTURE_PUSH_TRANSCRIPT[j] as Field;
            let scan_token = GRAMMAR_CAPTURE_TOKEN[j];
            let new_grammar = ((new_grammar == 1) & (token_is_numeric_or_literal == 1)) as Field;
            result[i * 256 + j] =
                token as Field + new_grammar * 0x100 + scan_token as Field * 0x10000;
        }
        for j in 128..256 {
            result[i * 256 + j] = 0;
        }
    }
    result
}

unconstrained fn generate_token_flags_table() -> [Field; NUM_TOKENS * 2] {
    let mut flags: [TokenFlags; NUM_TOKENS * 2] = std::mem::zeroed();

    let mut no_token_flags: TokenFlags = TokenFlags {
        create_json_entry: false,
        is_end_of_object_or_array: false,
        is_start_of_object_or_array: false,
        new_context: OBJECT_LAYER != 0,
        is_key_token: false,
        is_value_token: false,
        preserve_num_entries: true,
    };
    let mut key_token_flags: TokenFlags = TokenFlags {
        create_json_entry: false,
        is_end_of_object_or_array: false,
        is_start_of_object_or_array: false,
        new_context: OBJECT_LAYER != 0,
        is_key_token: true,
        is_value_token: false,
        preserve_num_entries: true,
    };
    let begin_object_flags = TokenFlags {
        create_json_entry: false,
        is_end_of_object_or_array: false,
        is_start_of_object_or_array: true,
        new_context: OBJECT_LAYER != 0,
        is_key_token: false,
        is_value_token: false,
        preserve_num_entries: false,
    };

    let begin_array_flags = TokenFlags {
        create_json_entry: false,
        is_end_of_object_or_array: false,
        is_start_of_object_or_array: true,
        new_context: ARRAY_LAYER != 0,
        is_key_token: false,
        is_value_token: false,
        preserve_num_entries: false,
    };

    let end_object_flags = TokenFlags {
        create_json_entry: true,
        is_end_of_object_or_array: true,
        is_start_of_object_or_array: false,
        new_context: false,
        is_key_token: false,
        is_value_token: false,
        preserve_num_entries: false,
    };

    let end_array_flags = TokenFlags {
        create_json_entry: true,
        is_end_of_object_or_array: true,
        is_start_of_object_or_array: false,
        new_context: false,
        is_key_token: false,
        is_value_token: false,
        preserve_num_entries: false,
    };

    let mut string_flags = TokenFlags {
        create_json_entry: true,
        is_end_of_object_or_array: false,
        is_start_of_object_or_array: false,
        new_context: OBJECT_LAYER != 0,
        is_key_token: false,
        is_value_token: true,
        preserve_num_entries: true,
    };

    let mut numeric_flags = TokenFlags {
        create_json_entry: true,
        is_end_of_object_or_array: false,
        is_start_of_object_or_array: false,
        new_context: OBJECT_LAYER != 0,
        is_key_token: false,
        is_value_token: true,
        preserve_num_entries: true,
    };

    let mut literal_flags = TokenFlags {
        create_json_entry: true,
        is_end_of_object_or_array: false,
        is_start_of_object_or_array: false,
        new_context: OBJECT_LAYER != 0,
        is_key_token: false,
        is_value_token: true,
        preserve_num_entries: true,
    };

    flags[NO_TOKEN] = no_token_flags;
    flags[BEGIN_OBJECT_TOKEN] = begin_object_flags;
    flags[END_OBJECT_TOKEN] = end_object_flags;
    flags[BEGIN_ARRAY_TOKEN] = begin_array_flags;
    flags[END_ARRAY_TOKEN] = end_array_flags;
    flags[KEY_SEPARATOR_TOKEN] = no_token_flags;
    flags[VALUE_SEPARATOR_TOKEN] = no_token_flags;
    flags[STRING_TOKEN] = string_flags;
    flags[NUMERIC_TOKEN] = numeric_flags;
    flags[LITERAL_TOKEN] = literal_flags;
    flags[KEY_TOKEN] = key_token_flags;

    no_token_flags.new_context = ARRAY_LAYER != 0;
    key_token_flags.new_context = ARRAY_LAYER != 0;
    string_flags.new_context = ARRAY_LAYER != 0;
    numeric_flags.new_context = ARRAY_LAYER != 0;
    literal_flags.new_context = ARRAY_LAYER != 0;

    flags[NUM_TOKENS + NO_TOKEN] = no_token_flags;
    flags[NUM_TOKENS + BEGIN_OBJECT_TOKEN] = begin_object_flags;
    flags[NUM_TOKENS + END_OBJECT_TOKEN] = end_object_flags;
    flags[NUM_TOKENS + BEGIN_ARRAY_TOKEN] = begin_array_flags;
    flags[NUM_TOKENS + END_ARRAY_TOKEN] = end_array_flags;
    flags[NUM_TOKENS + KEY_SEPARATOR_TOKEN] = no_token_flags;
    flags[NUM_TOKENS + VALUE_SEPARATOR_TOKEN] = no_token_flags;
    flags[NUM_TOKENS + STRING_TOKEN] = string_flags;
    flags[NUM_TOKENS + NUMERIC_TOKEN] = numeric_flags;
    flags[NUM_TOKENS + LITERAL_TOKEN] = literal_flags;
    flags[NUM_TOKENS + KEY_TOKEN] = key_token_flags;

    let mut result: [Field; NUM_TOKENS * 2] = [0; NUM_TOKENS * 2];
    for i in 0..(NUM_TOKENS * 2) {
        result[i] = flags[i].to_field();
    }
    result
}

#[test]
fn test_generate_token_flags_table() {
    // Safety: test code
    unsafe {
        let r = generate_token_flags_table();
        assert(r == TOKEN_FLAGS_TABLE);
    }
}

/// `ASCII_TO_TOKEN_TABLE` and `PROCESS_RAW_TRANSCRIPT_TABLE` are sized to
/// `NUM_PUSHING_CAPTURE_MODES * 256`, not `NUM_CAPTURE_MODES * 256`, because they are
/// indexed by the `mode * 256 + byte` of a transcript entry. That is only sound while
/// every mode that can push a transcript entry sorts below the line: a pushing mode
/// above it would read past the end of both tables on a perfectly valid document.
///
/// Nothing in the type system holds the ordering, so hold it here.
#[test]
fn test_pushing_modes_come_first() {
    // Safety: test code
    unsafe {
        let sub = capture_sub_tables();
        for i in NUM_PUSHING_CAPTURE_MODES..NUM_CAPTURE_MODES {
            for j in 0..128 {
                assert(
                    !sub.push_transcript[i][j],
                    "a capture mode above NUM_PUSHING_CAPTURE_MODES can push a transcript entry",
                );
            }
        }
    }
}

/// ...and the line is not slack either: every mode below it really does push something,
/// so the two tables are no bigger than they need to be.
#[test]
fn test_no_idle_mode_below_the_pushing_line() {
    // Safety: test code
    unsafe {
        let sub = capture_sub_tables();
        for i in 0..NUM_PUSHING_CAPTURE_MODES {
            let mut pushes = false;
            for j in 0..128 {
                pushes |= sub.push_transcript[i][j];
            }
            assert(pushes, "a capture mode below NUM_PUSHING_CAPTURE_MODES never pushes");
        }
    }
}

#[test]
fn test_make_json_capture_table() {
    // Safety: test code
    unsafe {
        let r = make_json_capture_table();
        assert(r == JSON_CAPTURE_TABLE);
    }
}

#[test]
fn test_make_validation_flags() {
    // Safety: test code
    unsafe {
        let f = make_token_validation_table();
        assert(f == TOKEN_VALIDATION_TABLE);
    }
}
#[test]
fn test_make_ascii_to_token_table() {
    // Safety: test code
    unsafe {
        let r = make_ascii_to_token_table();
        assert(r == ASCII_TO_TOKEN_TABLE);
    }
}

#[test]
fn test_make_process_raw_transcript_table() {
    // Safety: test code
    unsafe {
        let r = make_process_raw_transcript_table();
        assert(r == PROCESS_RAW_TRANSCRIPT_TABLE);
    }
}

// Emitters for the generated tables in `src/json_tables.nr`.
//
// The `test_make*` tests above only *verify* that the committed tables still
// match the sub-tables; the original implementation has no way of *printing* a new table after the
// sub-tables change. These tests do. The regeneration cycle is:
//
//   nargo test --show-output emit_table_ | grep '^EMIT ' > /tmp/tables.txt
//   python3 <splicer> /tmp/tables.txt src/json_tables.nr
//   nargo test test_make        # the verifiers become the regression check
//
// `json_tables.nr` is generated: never hand-edit it.
//
// A format string cannot index an array, hence the temporary `v`.
#[test]
fn emit_table_json_capture() {
    // Safety: test code
    unsafe {
        let r = make_json_capture_table();
        for i in 0..r.len() {
            let v = r[i];
            println(f"EMIT JSON_CAPTURE_TABLE {i} {v}");
        }
    }
}

#[test]
fn emit_table_ascii_to_token() {
    // Safety: test code
    unsafe {
        let r = make_ascii_to_token_table();
        for i in 0..r.len() {
            let v = r[i];
            println(f"EMIT ASCII_TO_TOKEN_TABLE {i} {v}");
        }
    }
}

#[test]
fn emit_table_process_raw_transcript() {
    // Safety: test code
    unsafe {
        let r = make_process_raw_transcript_table();
        for i in 0..r.len() {
            let v = r[i];
            println(f"EMIT PROCESS_RAW_TRANSCRIPT_TABLE {i} {v}");
        }
    }
}

#[test]
fn emit_table_token_validation() {
    // Safety: test code
    unsafe {
        let r = make_token_validation_table();
        for i in 0..r.len() {
            let v = r[i];
            println(f"EMIT TOKEN_VALIDATION_TABLE {i} {v}");
        }
    }
}

#[test]
fn emit_table_token_flags() {
    // Safety: test code
    unsafe {
        let r = generate_token_flags_table();
        for i in 0..r.len() {
            let v = r[i];
            println(f"EMIT TOKEN_FLAGS_TABLE {i} {v}");
        }
    }
}
