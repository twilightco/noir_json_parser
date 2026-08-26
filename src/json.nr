use crate::_comparison_tools::bounds_checker::get_validity_flags;
use crate::enums::CaptureMode::GRAMMAR_CAPTURE;
use crate::enums::Layer::{ARRAY_LAYER, OBJECT_LAYER};
use crate::enums::Token::{
    BEGIN_ARRAY_TOKEN, BEGIN_OBJECT_TOKEN, END_ARRAY_TOKEN, END_OBJECT_TOKEN, KEY_SEPARATOR_TOKEN,
    KEY_TOKEN, LITERAL_TOKEN, NUM_TOKENS, NUMERIC_TOKEN, STRING_TOKEN,
};
use crate::get_literal::JSONLiteral;
use crate::json_entry::{JSONContextStackEntry, JSONEntry, JSONEntryPacked};
use crate::json_tables::{
    JSON_CAPTURE_TABLE, PROCESS_RAW_TRANSCRIPT_TABLE, TOKEN_FLAGS_TABLE,
    TOKEN_IS_ARRAY_OBJECT_OR_VALUE, TOKEN_IS_STRING, TOKEN_VALIDATION_TABLE,
};
use crate::token_flags::TokenFlags;
use crate::transcript_entry::{
    PostProcessScanData, RawTranscriptEntry, ScanData, TranscriptEntry, ValidationFlags,
};
use crate::utils::cast_num_to_u32;

/**
 * @brief records a value in a json blob
 **/
pub struct JSONValue<let MaxLength: u32> {
    pub value: BoundedVec<u8, MaxLength>, // raw bytes that constitute the json value entry
    pub value_type: Field, // either STRING_TOKEN, NUMERIC_TOKEN or LITERAL_TOKEN
}

impl<let MaxLength: u32> JSONValue<MaxLength> {
    pub fn is_string(self) -> bool {
        self.value_type == STRING_TOKEN as Field
    }
    pub fn is_number(self) -> bool {
        self.value_type == NUMERIC_TOKEN as Field
    }
    pub fn is_literal(self) -> bool {
        self.value_type == LITERAL_TOKEN as Field
    }
    /// containers are recorded under their *closing* token
    pub fn is_object(self) -> bool {
        self.value_type == END_OBJECT_TOKEN as Field
    }
    pub fn is_array(self) -> bool {
        self.value_type == END_ARRAY_TOKEN as Field
    }
}

/**
 * @brief It's a JSON struct! Contains the raw and processed information required to extract data from a json blob
 * @description The "root" of the JSON refers to the parent object or array (or a value if the json is just a single value e.g. text = "\"foo\": \"bar\"")
 * @note text that describes just a single JSON value is not yet fully supported. Only use this library for processing objects or arrays for now
 **/
pub struct JSON<let NumBytes: u32, let NumPackedFields: u32, let MaxNumTokens: u32, let MaxNumValues: u32, let MaxKeyFields: u32> {
    pub(crate) json: [u8; NumBytes], // the raw json bytes
    pub(crate) json_packed: [Field; NumPackedFields], // raw bytes, but packed into 31-byte Field elements
    pub(crate) raw_transcript: [Field; MaxNumTokens], // transcript of json tokens after basic processing
    pub(crate) transcript: [Field; MaxNumTokens], // complete transcript of json tokens
    pub transcript_length: u32, // how big is the transcript?
    pub(crate) key_data: [Field; MaxNumValues], // description of each key, packed into a Field element
    pub(crate) key_hashes: [Field; MaxNumValues], // a sorted list of key hashes
    pub(crate) unsorted_json_entries_packed: [JSONEntryPacked; MaxNumValues], // a list of all the processed json values (objects, arrays, numerics, literals, strings)
    pub(crate) json_entries_packed: [JSONEntryPacked; MaxNumValues], // a sorted list of all the processed json values (objects, arrays, numerics, literals, strings)
    pub layer_type_of_root: u32, // is the root an OBJECT_LAYER, ARRAY_LAYER
    pub(crate) root_id: Field, // the unique identifier of the root (if an object or array)
    pub(crate) root_index_in_transcript: u32, // location in json_entries_packed of the root
}

/**
 * @brief are two JSON objects equal?
 * @note VERY EXPENSIVE! Currently only used in tests
 **/
impl<let NumBytes: u32, let NumPackedFields: u32, let MaxNumTokens: u32, let MaxNumValues: u32, let MaxKeyFields: u32> std::cmp::Eq for JSON<NumBytes, NumPackedFields, MaxNumTokens, MaxNumValues, MaxKeyFields> {
    fn eq(self, other: Self) -> bool {
        (self.json == other.json)
            & (self.raw_transcript == other.raw_transcript)
            & (self.transcript == other.transcript)
            & (self.transcript_length == other.transcript_length)
            & (self.key_data == other.key_data)
            & (self.key_hashes == other.key_hashes)
            & (self.layer_type_of_root == other.layer_type_of_root)
            & (self.root_id == other.root_id)
            & (self.root_index_in_transcript == other.root_index_in_transcript)
            & (self.json_entries_packed == other.json_entries_packed)
            & (self.json_packed == other.json_packed)
    }
}

unconstrained fn __check_entry_ptr_bounds(entry_ptr: Field, max: u32) {
    entry_ptr.assert_max_bit_size::<32>();
    // n.b. even though this assert is in an unconstrained function, an out of bounds error will be triggered when writing into self.key_data[entry_ptr]
    assert(entry_ptr as u32 < max - 1, "create_json_entries: MaxNumValues limit exceeded!");
}

impl<let NumBytes: u32, let NumPackedFields: u32, let MaxNumTokens: u32, let MaxNumValues: u32, let MaxKeyFields: u32> JSON<NumBytes, NumPackedFields, MaxNumTokens, MaxNumValues, MaxKeyFields> {

    /**
     * @brief pack the json bytes into Field elements, where each Field element represents 31 bytes
     * @description we do this because we need to extract substrings from the json bytes, where the position and length of the substring are witness values.
     *              Doing this on packed Field elements using `slice_string` is cheaper than the direct method of iterating byte-by-byte.
     *              Also, by extracting data at unknown locations exclusively from the packed json, we do not need to represent the raw bytes `self.json` as a ROM table
     *              (which would have an expensive initialization cost of 2*NumBytes gates)
     **/
    fn compute_json_packed(&mut self) {
        let NumWholeLimbs = NumBytes / 31;
        for i in 0..NumWholeLimbs {
            let mut limb: Field = 0;
            for j in 0..31 {
                limb *= 0x100;
                limb += self.json[i * 31 + j] as Field;
            }
            std::as_witness(limb);
            self.json_packed[i] = limb;
        }
        let NumRemainingBytes = NumBytes - NumWholeLimbs * 31;
        let mut limb: Field = 0;
        for j in 0..NumRemainingBytes {
            limb *= 0x100;
            limb += self.json[NumWholeLimbs * 31 + j] as Field;
        }
        for _ in NumRemainingBytes..31 {
            limb *= 0x100;
        }
        std::as_witness(limb);
        self.json_packed[NumWholeLimbs + (NumRemainingBytes == 0) as u32] = limb;
    }

    // TODO: when impl is more mature, merge this into create_json_entries
    fn keyswap(&mut self) {
        // TODO: this won't work if 1st entry is a key!
        let mut current = TranscriptEntry::from_field(self.transcript[0]);
        let mut next: TranscriptEntry = TranscriptEntry::new();

        for i in 0..MaxNumTokens - 1 {
            next = TranscriptEntry::from_field(self.transcript[i + 1]);

            let next_is_key = next.token == KEY_SEPARATOR_TOKEN as Field;

            let valid_token = TOKEN_IS_STRING[cast_num_to_u32(current.token)];
            if !valid_token {
                assert(!next_is_key, "Cannot find key/value straddling KEY_DELIMITER_TOKEN");
            }

            let old_transcript = self.transcript[i];
            let new_transcript = TranscriptEntry::to_field(
                TranscriptEntry {
                    token: KEY_TOKEN as Field,
                    index: current.index,
                    length: current.length,
                },
            );
            self.transcript[i] = if next_is_key {
                new_transcript
            } else {
                old_transcript
            };

            current = next;
        }
    }

    /**
     * @brief Once we have processed the json into a transcript of tokens, validate these tokens represent valid JSON!
     * @description To avoid a lot of painful if/else statements, we construct a state transition function out of the lookup table TOKEN_VALIDATION_TABLE
     *              The inputs to TOKEN_VALIDATION_TABLE are:
     *                  1. The current token (at some position `i` i.e. `self.transcript[i])
     *                  2. The previous token (`self.transcript[i-1]`)
     *                  3. The context of the previous token (i.e. is it within an object or an array?)
     *              The lookup table maps these inputs into the following outputs:
     *                  1. Are we moving into a new context? i.e. is current token a `{` or `[` character?
     *                  2. If so, what context are we moving into? (`OBJECT_LAYER` or `ARRAY_LAYER`)
     *                  3. Are we exiting from the current context? i.e. is the current token a `}` or `]` character?
     *                  4. Have we entered an error state? e.g. a `[` token followed by a `,` token would be invalid JSON
     * 
     * @note To shave some gates, we represent the error state in a nonstandard way.
     *       If we have entered an error state, the value of `push_layer` will be 0x1000000
     *       This will then update `depth` to a value that exceeds the size of `parent_layer_stack` (32),
     *       which will trigger an out-of-bounds array access, which creates unsatisfiable constraints
     **/
    fn validate_tokens(self, tokens: [Field; MaxNumTokens]) {
        let mut current_layer = self.layer_type_of_root;
        let mut parent_layer_stack: [Field; 32] = [0; 32];
        let mut depth = 0;
        let mut previous_token = tokens[0];
        let NN = NUM_TOKENS * NUM_TOKENS;

        let is_object = previous_token == BEGIN_OBJECT_TOKEN as Field;
        let is_array = previous_token == BEGIN_ARRAY_TOKEN as Field;

        depth = is_object as Field + is_array as Field;

        // todo is this correct?
        parent_layer_stack[0] =
            is_object as Field * OBJECT_LAYER as Field + is_array as Field * ARRAY_LAYER as Field;
        assert(
            TOKEN_IS_ARRAY_OBJECT_OR_VALUE[cast_num_to_u32(previous_token)],
            "first json token does not describe an object, array or key",
        );

        // 17 gates per iteration?
        for i in 1..MaxNumTokens {
            // 0 gates
            let current_token = tokens[i];

            // 1 gate
            let index = current_layer as Field * (NN as Field)
                + previous_token * (NUM_TOKENS as Field)
                + current_token;

            // 5 gates
            let ValidationFlags { push_layer, push_layer_type_of_root, pop_layer } =
                ValidationFlags::from_field(TOKEN_VALIDATION_TABLE[cast_num_to_u32(index)]);

            // 3.5 gates
            parent_layer_stack[cast_num_to_u32(depth)] = current_layer as Field;

            // 1 gate
            // we encode an error flag into `push_layer` by making its value such that `depth` will exceed the size of `parent_layer_stack`
            depth += push_layer as Field - pop_layer as Field;
            std::as_witness(depth);

            // 6.5 gates
            let parent_layer = parent_layer_stack[cast_num_to_u32(depth)];
            let mut updated_layer = (1 - pop_layer as Field - push_layer as Field);
            std::as_witness(updated_layer);
            updated_layer =
                updated_layer * current_layer as Field + push_layer_type_of_root as Field;
            std::as_witness(updated_layer);
            updated_layer = updated_layer + parent_layer as Field * pop_layer as Field;
            std::as_witness(updated_layer);
            current_layer = cast_num_to_u32(updated_layer);

            previous_token = current_token;
        }
        assert(depth == 0, "validate_tokens: unclosed objects or arrays");
    }

    /// Parses [`Self::transcript`] to populate [`Self::json_entries_packed`] and [`Self::key_data`]
    /// Given a processed transcript of json tokens, compute a list of json entries that describes the values within the JSON blob
    ///
    /// [`Self::json_entries_packed`] is a [JSONEntry] struct whose members have been packed into a single Field element.
    ///
    /// A 'value' here is either an Object, Array, String, Numeric or Literal.
    ///         e.g. "[ 1, 2, 3 ]" contains 4 values (3 Numeric types and the Array that contains them)
    ///
    ///         To avoid branches and if statements, we construct a state transition function out of the lookup table TOKEN_FLAGS_TABLE
    ///         This table takes as an input the following:
    ///             1. The token value of an element in the transcript
    ///             2. The layer type the previous token is located in (i.e. are we in an array or an object?)
    ///         The table outputs the following data:
    ///             1. Should we create a new json entry? (i.e. is the token a STRING_TOKEN, LITERAL_TOKEN, NUMERIC_TOKEN, END_ARRAY_TOKEN, END_OBJECT_TOKEN)
    ///             2. Is the token `}` or `]`?
    ///             3. Is the token `{` or `[`?
    ///             4. Given the current layer type and the token being queried, what should the new layer type be?
    ///             5. Is the token `KEY_TOKEN`?
    ///             6. Is the token a `STRING_TOKEN`, `NUMERIC_TOKEN` OR `VALUE_TOKEN`?
    ///             7. Is the token one that we should skip over? `,` or `:`
    ///
    /// ## explanation of `parent_context_stack`
    /// When recording a JSONEntry, we need to understand how many children (if any) a JSONEntry has,
    /// as well as a way of accessing children given the parent JSONEntry object
    /// Note: OBJECT_TOKEN and ARRAY_TOKEN have children. single values (NUMERIC_TOKEN, LITERAL_TOKEN, STRING_TOKEN) do not.
    /// We define a "context stack" via `parent_context_stack` to track this data.
    /// The front of `parent_context_stack` contains a JSONContextStackEntry (packed into a single Field for the purposes of efficient lookups) for the current parent
    /// If we parse a token that creates a new parent (BEGIN_OBJECT_TOKEN or BEGIN_ARRAY_TOKEN), we push a new parent onto the stack
    /// If we reach the end of an object or array (END_OBJECT_TOKEN, END_ARRAY_TOKEN) we pop the current parent off of the stack
    /// Note: "stack" is used loosely here. We have a fixed-size array of packed JSONContextStackEntry vals and a pointer to the head of the stack.
    /// (the array size defines the maximum number of entities the stack can contain, currently set at 32)
    /// Note: the size param `32` is a magic number we should replace with a defined const global variable
    /// To push: we increment the pointer by 1 and write a new entry at the pointer value
    /// To pop: we decrement the pointer by 1 (we don't need to delete data because new data is written every time the pointer is incremented)
    fn create_json_entries(&mut self) {
        let mut parent_context_stack: [Field; 32] = [0; 32];
        let mut entry_ptr = 0;
        // depth = points to the next unused slot in parent_context_stack
        // Note: parent_context_stack[0] = the root JSON object
        let mut depth: Field = 1;
        // how many children does the current parent have?
        let mut num_entries_at_current_depth: Field = 0;

        // current_identity_value = unique identifier for all JSON objects/arrays we create
        let mut current_identity_value: Field = 0;
        // next_identity_value = smallest integer that we've not yet assigned as a unique identifier to the JSON objects/arrays we create
        let mut next_identity_value: Field = 1;
        // context = is the current parent an object or array?
        let mut context = OBJECT_LAYER;

        // current_key_index_and_length encodes 2 bits of data in a single Field element (to save some gates)
        // note: would be more readable if we had a custom struct that wrapped a Field element with defined update methods
        // 1. what is the key index? (index = unique identifier, starts at 0)
        // 2. what is the size of the key in bytes?
        // current_key_index_and_length = index + length * 0x10000 (assumes index does not exceed 2^16. I don't think we check for this, there is an assumption that the size of the circuit would be too large to compile/run if the JSON blob has over 2^16 unique keys)
        let mut current_key_index_and_length: Field = 0;

        let mut tokens: [Field; MaxNumTokens] = [0; MaxNumTokens];
        //  maybe 71.75 gates per iteration
        for i in 0..MaxNumTokens {
            // Safety: check the comments below
            unsafe { __check_entry_ptr_bounds(entry_ptr, MaxNumValues) };
            // 5.25 gates
            let TranscriptEntry { token, index, length } =
                TranscriptEntry::from_field(self.transcript[i]);

            tokens[i] = token;

            // The TOKEN_FLAGS_TABLE table encodes the following information:
            // Given the current token and the context (whether the parent is an object or array),
            // we can extract the following information from TOKEN_FLAGS_TABLE via a simple lookup:
            // 1. Should we create a new JSONEntry object?
            //  - i.e is the token END_ARRAY_TOKEN, END_OBJECT_TOKEN, STRING_TOKEN, NUMERIC_TOKEN, LITERAL_TOKEN
            // 2. If the token creates a new parent (BEGIN_OBJECT_TOKEN or BEGIN_ARRAY_TOKEN), what is the context value? (0 = object, 1 = array)
            // 3. Has the parent entity changed?
            //  - `preserve_num_entries` = 1 if the parent entity changes, not the best variable name
            // 5. Various bools that describe the token, which are cheaper to acquire this way than via comparison operators
            // - `is_end_of_object_or_array, `is_start_of_object_or_array`, `is_key_token`, `is_value_token`
            // See comments in token_flags.nr for more details
            // 13 gates
            let TokenFlags {
                create_json_entry,
                is_end_of_object_or_array,
                is_start_of_object_or_array,
                new_context,
                is_key_token: update_key,
                is_value_token,
                preserve_num_entries,
            } = TokenFlags::from_field(
                TOKEN_FLAGS_TABLE[cast_num_to_u32(token) + context * NUM_TOKENS],
            );

            // Determine what the current key index is and the key size in bytes
            // (key index = byte location in the original JSON of the key)
            // Pseudocode equivalent:
            // current_key_index_and_length = update_key ? (index + length * 0x10000) : current_key_index_and_length
            // We convert these booleans into Fields so that we can use them in arithmetic operations.
            let create_json_entry = create_json_entry as Field;
            let is_end_of_object_or_array = is_end_of_object_or_array as Field;
            let is_start_of_object_or_array = is_start_of_object_or_array as Field;
            let new_context = new_context as Field;
            let update_key = update_key as Field;
            let is_value_token = is_value_token as Field;
            let preserve_num_entries = preserve_num_entries as Field;

            // 2 gates
            let diff = (index + length * 0x10000) - current_key_index_and_length;
            std::as_witness(diff);
            current_key_index_and_length = diff * update_key + current_key_index_and_length;
            std::as_witness(current_key_index_and_length);

            // If the current token is BEGIN_OBJECT_TOKEN or BEGIN_ARRAY_TOKEN,
            // we need to push a new parent object into `parent_context_stack`.
            // We apply a trick here to avoid branching: regardless of the token type,
            // we *always* write a new stack entry into `parent_context_stack[depth]`.
            // If the current token is not BEGIN_OBJECT_TOKEN or BEGIN_ARRAY_TOKEN,
            // the data we write never gets read.
            // Note: we only update the value of `depth` if token == BEGIN_OBJECT_TOKEN or BEGIN_ARRAY_TOKEN,
            // 2 gates
            let new_context_stack_entry = JSONContextStackEntry::to_field(
                JSONContextStackEntry {
                    num_entries: num_entries_at_current_depth,
                    context: context as Field,
                    current_key_index_and_length,
                    json_index: index,
                    current_identity: current_identity_value,
                },
            );
            // 3.5 gates
            parent_context_stack[cast_num_to_u32(depth)] = new_context_stack_entry;

            // `previous_stack_entry` = Extract information about the parent of the current token
            // If the current token = END_OBJECT_TOKEN or END_ARRAY_TOKEN, previous_stack_entry = data that describes the object or array we are about to create
            // 9.5 gates
            let depth_index: Field = (depth - 1);
            let previous_stack_entry_packed = parent_context_stack[cast_num_to_u32(depth_index)];
            let previous_stack_entry =
                JSONContextStackEntry::from_field(previous_stack_entry_packed);

            // update the depth of the context stack
            // 1 gate
            depth = depth + is_start_of_object_or_array - is_end_of_object_or_array;

            /* PSEUDOCODE FOR FOLLOWING BLOCK:
            let mut new_entry: JSONEntry = JSONEntry::default()
            if create_json_entry {
                let array_entry = object_or_array_entry_packed ? object_or_array_entry_packed : value_entry_packed;
                self.json_entries_packed[cast_num_to_u32(entry_ptr)] = array_entry;   }
            */
            {
                // If token = END_OBJECT_TOKEN or END_ARRAY_TOKEN, we derive the following:
                // array_pointer = if *this entity's parent is an array*, `array_pointer` will point to the index in the array where the current object/array is located
                // entry_type = END_OBJECT_TOKEN or END_ARRAY_TOKEN
                // child_pointer = points to the first child object, is set in compute_keyhash_and_sort_json_entries
                // num_children = how many entities does this object/array contain?
                // json_pointer = byte index of the original json where this object/array starts
                // parent_index = what's the ID of the object/array's parent?
                let object_or_array_entry: JSONEntry = JSONEntry {
                    array_pointer: previous_stack_entry.num_entries,
                    entry_type: token,
                    child_pointer: 0,
                    num_children: num_entries_at_current_depth,
                    json_pointer: previous_stack_entry.json_index,
                    json_length: length,
                    parent_index: previous_stack_entry.current_identity,
                    id: current_identity_value,
                };
                // If token = STRING_TOKEN, NUMERIC_TOKEN or LITERAL_TOKEN, we derive the following:
                // array_pointer = if *this entity's parent is an array*, `array_pointer` will point to the index in the array where the current string/number/literal is located
                // entry_type = STRING_TOKEN, NUMERIC_TOKEN or LITERAL_TOKEN
                // child_pointer = not relevant for value entries (cannot contain children)
                // num_children = not relevant for value entries (cannot contain children)
                // json_pointer = byte index of the original json where this string/number/literal starts
                // parent_index = what's the ID of the string/number/literal's parent?
                let value_entry: JSONEntry = JSONEntry {
                    array_pointer: num_entries_at_current_depth,
                    entry_type: token,
                    child_pointer: 0,
                    num_children: 0,
                    json_pointer: index,
                    json_length: length,
                    parent_index: current_identity_value,
                    id: 0,
                };
                // 3 gates
                let object_or_array_entry_packed = object_or_array_entry.to_field();
                // 2 gates
                let value_entry_packed = value_entry.to_field();
                // 2 gates
                let diff = object_or_array_entry_packed - value_entry_packed;
                std::as_witness(diff);
                let new_entry = diff * is_end_of_object_or_array + value_entry_packed;
                std::as_witness(new_entry);
                // 4.5 gates
                self.json_entries_packed[cast_num_to_u32(entry_ptr)] =
                    JSONEntryPacked { value: new_entry * create_json_entry };
            }
            // Update `next_identity_value` and `current_identity_value` (unique identfiers for JSON entries)
            // If we've ended an object/array, set `current_identity_value` to the value of the object/array's parent (whose context we're now in)
            // If we've started an object/array, set `current_identity_value` to `next_identity_value` (the next unused unique identifier)
            // If we've started an object/array, also increment `next_identity_value` to a new unique value
            // Pseudocode for the following:
            //
            //  if !preserve_num_entries {
            //      if is_start_of_object_or_array {
            //          current_identity_value = next_identity_value;
            //      }
            //      else if is_end_of_object_or_array {
            //          current_identity_value = previous_stack_entry.current_identity;
            //      }
            //      next_identity_value += is_start_of_object_or_array;
            //  }
            //
            // 4 gates
            {
                let old = current_identity_value;
                current_identity_value = (next_identity_value * is_start_of_object_or_array);
                std::as_witness(current_identity_value);
                current_identity_value = current_identity_value
                    + (previous_stack_entry.current_identity * is_end_of_object_or_array);
                std::as_witness(current_identity_value);
                current_identity_value = current_identity_value + old * preserve_num_entries;
                std::as_witness(current_identity_value);
                // If the current token creates an object or array, subsequent entries will be a child of this object
                // i.e. we need to assign them a new identifier so increase `next_identity_value`
                next_identity_value = next_identity_value + is_start_of_object_or_array;
                std::as_witness(next_identity_value);
            }

            // Update the number of entries in the parent object/array
            // Pseudocode:
            // if (!preserve_num_entries && is_value_token) {
            //  num_entries_at_current_depth += 1;
            // } else if (is_end_of_object_or_array) {
            //  num_entries_at_current_depth = previous_stack_entry.num_entries + 1;
            // }
            // 2 gates
            num_entries_at_current_depth =
                num_entries_at_current_depth * preserve_num_entries + is_value_token;
            std::as_witness(num_entries_at_current_depth);
            num_entries_at_current_depth = num_entries_at_current_depth
                + (previous_stack_entry.num_entries + 1) * is_end_of_object_or_array;
            std::as_witness(num_entries_at_current_depth);

            // Set the value of `context` (badly named: are we in an object or array? context == 0 => object, context == 1 => array)
            // If current token is END_OBJECT_TOKEN or END_ARRAY_TOKEN, set context to the context value in previous_stack_entry
            // (i.e. restore the context to whatever the parent of the object/array is)
            // Pseudocode:
            // if (is_end_of_object_or_array) {
            //   context = previous_stack_entry.context
            // } else {
            //   context = new_context
            // }
            // 1 gate
            // if `is_end_of_object_or_array == 1`, `new_context = 0` so we can do something cheaper than a conditional select:
            context = cast_num_to_u32(
                previous_stack_entry.context * is_end_of_object_or_array + new_context,
            );
            std::as_witness(context as Field);

            // Update data that describes the key for the current token.
            // If we are creating a JSON entry, we also populate `self.key_data` with info that describes the current entry's key
            // key_data contains 3 members that are packed into a Field:
            // * the key index (where in the original JSON blob does the key start?)
            // * the key length (length of the key in bytes)
            // * current_identity_value (unique identifier for the key's JSON object. starts at 0)
            // * in the current parent object/array, how many JSON entries deep is the key's associated JSON object?
            // TODO: would be much more readable if we have a custom struct `KeyData` that wrapped a Field elemenet with sensible helper methods
            // Pseudocode:
            // if (create_json_entry) {
            //   let mut new_key_data;
            //   if (is_value_token) {
            //     new_key_data = make_key(current_key_index_and_length, current_identity_value, num_entries_at_current_depth - 1);
            //   } else if (is_end_of_object_or_array) {
            //     new_key_data = make_key(previous_stack_entry.current_key_index_and_length, current_identity_value, num_entries_at_current_depth - 1);
            //   }
            //   self.key_data[entry_ptr] = new_key_data;
            // }
            // 3 gates
            let common_term = current_identity_value
                + context as Field * (num_entries_at_current_depth - 1) * 0x1000000000000;
            std::as_witness(common_term);
            let mut new_key_data =
                current_key_index_and_length * is_value_token * 0x10000 + common_term;
            std::as_witness(new_key_data);
            new_key_data = new_key_data
                + previous_stack_entry.current_key_index_and_length
                    * is_end_of_object_or_array
                    * 0x10000;
            std::as_witness(new_key_data);
            // 3.5 gates
            self.key_data[cast_num_to_u32(entry_ptr)] = new_key_data * create_json_entry;

            // Update `entry_ptr` (points to the head of self.key_data and self.json_entries_packed)
            // 1 gate
            entry_ptr += create_json_entry;
            std::as_witness(entry_ptr);

            // subtotal 66.75?
        }
        self.validate_tokens(tokens);
    }

    /**
     * @brief Construct a token transcript by iterating through self.json and using a lookup table `JSON_CAPTURE_TABLE` to define a state transition function
     * @details JSON_CAPTURE_TABLE takes the following as input:
     *          1. the ascii byte at the current location in the json
     *          2. the current scan mode (are we searching for grammar, strings, numbers or literals?)
     *          The table outputs the following flags:
     *          1. what token have we scanned? (listed in enums::Token)
     *          2. should we push this token to the transcript (no push if token == NO_TOKEN)
     *          3. should we increase the length of the current entry we're evaluating?
     *              (i.e. if token == STRING_TOKEN and scan_mode == STRING_CAPTURE, then increase the length because we're in the process of scanning a string)
     *          4. have we entered an error state? (i.e. invalid grammar e.g. ":" is followed by "}")
     *
     * NOTE: we represent error states in a nonstandard way to reduce gate count. Instead of handling an error flag,
     *       an error state will increase the value of `scan_token` by 0x100000000. This will cause the next access into `JSON_CAPTURE_TABLE` to trigger an out of bounds error
     *
     * NOTE: the scanned transcript will be missing some edge cases that are caught via `swap_keys` and `capture_missing_tokens`:
     *          1. If the scan mode is NUMERIC_CAPTURE or LITERAL_CAPTURE and the next character is a "," or "}" or "]",
     *             we will push a NUMERIC_TOKEN or LITERAL_TOKEN into the transcript but we will MISS the VALUE_SEPARATOR_TOKEN, END_OBJECT_TOKEN or END_ARRAY_TOKEN
     *             (accomodating this edge case requires conditionally pushing two transcript entries per iteration, so we do this in a separate step where we iterate over the transcript and not the json bytes)
     *          2. We can't yet tell if an entry is a KEY_TOKEN or a STRING_TOKEN. All keys are represented as STRING_TOKEN. This gets fixed after `swap_keys` is evaluated
     **/
    fn build_transcript(self) -> Self {
        let mut raw_transcript: [Field; MaxNumTokens] = [0; MaxNumTokens];
        let mut transcript_ptr: Field = 0;
        let mut scan_mode = GRAMMAR_CAPTURE;
        let mut length: Field = 0;

        // Safety: check the comments below
        let raw_transcript = unsafe { __build_transcript::<NumBytes, MaxNumTokens>(self.json) };

        // 14 gates per iteration, plus the fixed cost of initing the 4,096 entry lookup table
        for i in 0..NumBytes {
            let ascii = self.json[i];

            // 1 gate
            let encoded_ascii = scan_mode * 256 + ascii as Field;
            std::as_witness(encoded_ascii);

            // 2 gates
            let capture_flags = JSON_CAPTURE_TABLE[cast_num_to_u32(encoded_ascii)];
            // 5 gates
            let ScanData { scan_token, push_transcript, increase_length } =
                ScanData::from_field(capture_flags);

            // 2 gates
            let raw: Field = raw_transcript[cast_num_to_u32(transcript_ptr)];

            // TODO: document this
            // TODO: why are we comparing a derived quantity against `raw_transcript` instead of constructing `raw_transcript` directly (faster)
            // 1 gate
            let diff: Field = raw
                - RawTranscriptEntry::to_field(
                    RawTranscriptEntry { encoded_ascii, index: i as Field - length, length },
                );
            std::as_witness(diff);

            // 1 gate
            assert(diff * push_transcript as Field == 0);

            // 1 gate
            length = length * (1 - push_transcript as Field) + increase_length as Field;
            std::as_witness(length);

            // 1 gate
            transcript_ptr += push_transcript as Field;

            scan_mode = scan_token;
        }

        // we encode error flag into the scan_token value, which must be less than 8
        // the lookup into JSON_CAPTURE_TABLE applies an implicit range check on `scan_token`
        // however this does not get triggered if the final byte scanned produces an error state
        length.assert_max_bit_size::<2>();
        // ...and `length` is not what guards that case: an error
        // entry is `ERROR_CAPTURE + error * 0x100000000`, and `ScanData::from_field`
        // only asserts `scan_token + flags == f`, with `scan_token` unrestricted.
        // A prover can therefore absorb the error bit into `scan_token`. For every
        // byte but the last, the next `JSON_CAPTURE_TABLE` lookup then blows past
        // `cast_num_to_u32`; for the last byte nothing did. 1 gate closes it, and
        // it is the constraint the parser's mode encoding relies on.
        scan_mode.assert_max_bit_size::<3>();
        // ...and the bound alone is not enough either. The range check
        // says the mode is *small*; it does not say the scan *ended* in grammar mode.
        // If the last byte of the buffer legally STARTS a token (a digit, `-`, `"`,
        // `t`/`f`/`n`) the scan stops inside that token with a perfectly legal small
        // mode, no error entry is ever produced, and nothing above notices. The original implementation
        // does check this, but only inside the unconstrained `__build_transcript`,
        // where a malicious prover simply does not run it -- so up to 3 trailing junk
        // bytes could be dropped and the record still accepted as valid JSON
        // (`length.assert_max_bit_size::<2>()` above is what caps it at 3).
        //
        // The range check closes an illegal trailing mode; a legal token-start
        // trailing byte additionally needs the terminal grammar assertion below.
        //
        // Both need `StringBytes == NumBytes`. `parse_json` SPACE-pads a short input,
        // and that padding terminates the junk byte and turns it into a real token, so
        // the original implementation is accidentally safe whenever the caller passes a short string. Our
        // adapter does not: it hands over a fixed `[u8; NumBytes]` buffer it has padded
        // itself, i.e. `StringBytes == NumBytes` always, and the last byte of that
        // buffer is prover-chosen. The accidental protection does not apply to us.
        //
        // 1 gate, once per parse. Message deliberately different from the brillig one
        // in `__build_transcript`, which fires first on an honest run.
        assert(scan_mode == GRAMMAR_CAPTURE as Field, "build_transcript: scan ended mid-token");

        JSON {
            json: self.json,
            raw_transcript,
            transcript: self.transcript,
            transcript_length: transcript_ptr as u32,
            key_data: self.key_data,
            key_hashes: self.key_hashes,
            layer_type_of_root: self.layer_type_of_root,
            root_id: 1,
            root_index_in_transcript: 0,
            json_entries_packed: self.json_entries_packed,
            unsorted_json_entries_packed: self.unsorted_json_entries_packed,
            json_packed: self.json_packed,
        }
    }

    /**
     * @brief Check for missing tokens that we could have missed in `build_transcript`
     * @details If we had a json string where a NUMERIC_TOKEN or LITERAL_TOKEN is directly succeeded by a VALUE_SEPARATOR_TOKEN, END_OBJECT_TOKEN, END_ARRAY_TOKEN,
     *          we will have missed the latter token.
     *          We pick these up via the lookup table PROCESS_RAW_TRANSCRIPT_TABLE
     **/
    fn capture_missing_tokens(&mut self) {
        let mut transcript_ptr: Field = 0;
        // hmm probably need a null transcript value?!?!
        // Safety: check the comments below
        let updated_transcript = unsafe {
            __capture_missing_tokens::<MaxNumTokens>(self.raw_transcript, self.transcript_length)
        };
        // 26? gates per iteration
        let range_valid: [u32; MaxNumTokens] = get_validity_flags(self.transcript_length);
        for i in 0..MaxNumTokens {
            // 5.25 gates
            let RawTranscriptEntry { encoded_ascii, index, length } =
                RawTranscriptEntry::from_field(self.raw_transcript[i]);
            // 6.75 gates
            let PostProcessScanData { token, new_grammar, scan_token } = PostProcessScanData::from_field(
                PROCESS_RAW_TRANSCRIPT_TABLE[cast_num_to_u32(encoded_ascii)],
            );
            // 2 gates
            let index_valid: Field = range_valid[i] as Field;
            // 1 gate
            let entry = TranscriptEntry::to_field(TranscriptEntry { token, index, length });

            if token == LITERAL_TOKEN as Field {
                // 16 bits, not 8. `index` is the 16-bit index
                // field of `RawTranscriptEntry` (already range-checked there);
                // an 8-bit bound here rejected every `true`/`false`/`null` past
                // byte 255 of the document. The cast below still has to be
                // range-checked, and the four `self.json[...]` reads that follow
                // are ROM reads, so an index past the end of the buffer is a
                // failed constraint, not a wrap.
                index.assert_max_bit_size::<16>();
                let index_as_u32 = index as u32;
                let first_char = self.json[index_as_u32];
                let second_char = self.json[index_as_u32 + 1];
                let third_char = self.json[index_as_u32 + 2];
                let fourth_char = self.json[index_as_u32 + 3];
                if length == 5 {
                    let fifth_char = self.json[index_as_u32 + 4];
                    let is_false = (first_char == 102) // 'f'
                        & (second_char == 97) // 'a'
                        & (third_char == 108) // 'l'
                        & (fourth_char == 115) // 's'
                        & (fifth_char == 101); // 'e'
                    assert(is_false, "invalid literal");
                } else {
                    assert_eq(length, 4, "invalid literal");
                    let is_true = (first_char == 116) // 't'
                        & (second_char == 114) // 'r'
                        & (third_char == 117) // 'u'
                        & (fourth_char == 101); // 'e'

                    let is_null = (first_char == 110) // 'n'
                        & (second_char == 117) // 'u'
                        & (third_char == 108) // 'l'
                        & (fourth_char == 108); // 'l'
                    assert(is_null | is_true, "invalid literal");
                }
            }
            // 2 gates
            let diff = updated_transcript[cast_num_to_u32(transcript_ptr)] - entry;
            std::as_witness(diff);
            assert(diff * index_valid == 0);
            // 1 gate
            transcript_ptr += index_valid;
            // 0 gate (merged into TranscriptEntry::to_field)
            let index_of_possible_grammar = (index + length);
            // 0 gates
            let new_entry =
                TranscriptEntry { token: scan_token, index: index_of_possible_grammar, length: 0 };
            // 2 gates
            let update = new_grammar as Field * index_valid;
            std::as_witness(update);
            // 1 gate
            let new_transcript = TranscriptEntry::to_field(new_entry);
            // 4 gates
            let diff = updated_transcript[cast_num_to_u32(transcript_ptr)] - new_transcript;
            std::as_witness(diff);
            assert(diff * update == 0);
            // 1 gate
            transcript_ptr += update;
        }
        self.transcript = updated_transcript;
        self.transcript_length = transcript_ptr as u32;

        // The transcript returned by the unconstrained post-processing hint is
        // part of the parser's witness. Constrain every slot beyond the final
        // logical length to the canonical empty value.
        let final_valid: [u32; MaxNumTokens] = get_validity_flags(self.transcript_length);
        for i in 0..MaxNumTokens {
            assert(
                self.transcript[i] * (1 - final_valid[i] as Field) == 0,
                "capture_missing_tokens: non-empty transcript tail",
            );
        }

        // TODO we could make this more efficient...probably not a big deal though
        let first = TranscriptEntry::from_field(self.transcript[0]);
        self.layer_type_of_root = if (first.token == BEGIN_OBJECT_TOKEN as Field) {
            OBJECT_LAYER
        } else if (first.token == BEGIN_ARRAY_TOKEN as Field) {
            ARRAY_LAYER
        } else {
            self.layer_type_of_root
        };
    }

    pub fn parse_json<let StringBytes: u32>(stringbytes: [u8; StringBytes]) -> Self {
        assert(StringBytes <= NumBytes, "json length exceeds NumBytes!");
        // `slice_fields` reads one limb past the end of the slice it is asked for (the
        // read is discarded, but it still has to be in bounds), and the string getters
        // slice up to `StringBytes` bytes from any position. Both are why the packed
        // buffer carries slack over the `ceil(NumBytes / 31)` limbs the bytes need.
        // Getting this wrong shows up as `Index out of bounds` inside
        // `_string_tools/slice_packed_field.nr`, which says nothing about the alias that
        // caused it -- so say it here. Constant, so it costs no gates.
        assert(
            NumPackedFields >= (NumBytes + 30) / 31 + 3,
            "NumPackedFields too small: it must be at least ceil(NumBytes / 31) + 3",
        );
        let mut text: [u8; NumBytes] = [0; NumBytes];
        for i in 0..StringBytes {
            text[i] = stringbytes[i];
        }
        for i in StringBytes..NumBytes {
            text[i] = 32; // whitespace character
        }
        let mut json = JSON {
            json: text,
            raw_transcript: [0; MaxNumTokens],
            transcript: [0; MaxNumTokens],
            transcript_length: 0,
            key_data: [0; MaxNumValues],
            key_hashes: [0; MaxNumValues],
            layer_type_of_root: 0,
            root_id: 1,
            root_index_in_transcript: 0,
            json_entries_packed: [JSONEntryPacked::default(); MaxNumValues],
            unsorted_json_entries_packed: [JSONEntryPacked::default(); MaxNumValues],
            json_packed: [0; NumPackedFields],
        };

        json = json.build_transcript();
        json.capture_missing_tokens();
        json.keyswap();
        json.compute_json_packed();
        json.create_json_entries();

        json.compute_keyhash_and_sort_json_entries();

        json
    }

    pub fn parse_json_from_string<let StringBytes: u32>(s: str<StringBytes>) -> Self {
        JSON::parse_json(s.as_bytes())
    }
}

// TODO: our capture tables are not correctly set up to process a JSON blob that does not begin with an object or array
// #[test]
// fn test_single_value() {
//     let text = "100";
//     let mut json: JSON<3, 10, 20, 20> = JSON::parse_json_from_string(text);
//
//     assert(json.get_length() == 0);
//     assert(json.get_array_element_as_number(0) == 100);
// }

/**
    * @brief Perform the 1st transcript processing step as an unconstrained function
    *        We will validate this transcript is correct via a constrained function
    *        This is a bit cheaper than doing everything in a constrained function,
    *        because we can use ROM arrays instead of RAM arrays
    *        (i.e. we're only reading from our arrays, we don't write to them in constrained functions)
    **/
unconstrained fn __build_transcript<let NumBytes: u32, let MaxNumTokens: u32>(
    json_array: [u8; NumBytes],
) -> [Field; MaxNumTokens] {
    let mut raw_transcript: [Field; MaxNumTokens] = [0; MaxNumTokens];
    let mut transcript_ptr: u32 = 0;
    let mut scan_mode = GRAMMAR_CAPTURE;
    let mut length: Field = 0;
    for i in 0..NumBytes {
        // while this assert is in an unconstrained function, the out of bounds access `raw_transcript[transcript_ptr]` in build_transcript also generates failing constraints
        assert(transcript_ptr < MaxNumTokens, "build_transcript: MaxNumTokens limit exceeded!");
        let ascii = json_array[i];

        let encoded_ascii = scan_mode * 256 + ascii as Field;
        let ScanData { scan_token, push_transcript, increase_length } =
            ScanData::from_field(JSON_CAPTURE_TABLE[cast_num_to_u32(encoded_ascii)]);

        if push_transcript {
            let new_entry = RawTranscriptEntry::to_field(
                RawTranscriptEntry { encoded_ascii, index: i as Field - length, length },
            );

            raw_transcript[transcript_ptr] = new_entry;
            transcript_ptr += 1;
            length = increase_length as Field;
        } else {
            length += increase_length as Field;
        }

        scan_mode = scan_token;
    }

    // if we end in a scan mode where we're searching for a number, string or a literal (true/false/null), we have an incomplete token and this is invalid JSON
    // NOTE: if we upgrade this parser to be able to process single-value JSON (e,g, "999" or ""hello" : "world"" this logic needs to be upgraded)
    assert(
        scan_mode == GRAMMAR_CAPTURE as Field,
        "build_transcript: incomplete token (number, string or literal)",
    );

    // ensure an error isn't hiding in the last scanned token
    // 4 bits: there are 16 scan modes (`ERROR_CAPTURE` is 16, so it does not fit
    // and is still caught here)
    scan_mode.assert_max_bit_size::<4>();
    raw_transcript
}

/**
    * @brief We compute the output of `capture_missing_tokens` via an unconstrained function, then validate the result is correct.
    *        Saves some gates for same reason as in __build_transcript
    **/
unconstrained fn __capture_missing_tokens<let MaxNumTokens: u32>(
    raw_transcript: [Field; MaxNumTokens],
    transcript_length: u32,
) -> [Field; MaxNumTokens] {
    let mut updated_transcript: [Field; MaxNumTokens] = [0; MaxNumTokens];
    let mut transcript_ptr: u32 = 0;
    // TODO: do we need a null transcript value?!?!
    for i in 0..MaxNumTokens {
        let RawTranscriptEntry { encoded_ascii, index, length } =
            RawTranscriptEntry::from_field(raw_transcript[i]);

        let PostProcessScanData { token, new_grammar, scan_token } = PostProcessScanData::from_field(
            PROCESS_RAW_TRANSCRIPT_TABLE[cast_num_to_u32(encoded_ascii)],
        );

        let entry = TranscriptEntry::to_field(TranscriptEntry { token, index, length });
        updated_transcript[transcript_ptr] = entry;

        let index_valid: u32 = (i < transcript_length) as u32;
        transcript_ptr += index_valid;

        let index_of_possible_grammar = (index + length);
        let new_entry =
            TranscriptEntry { token: scan_token, index: index_of_possible_grammar, length: 0 };

        let update = new_grammar * index_valid as Field;
        let new_transcript = TranscriptEntry::to_field(new_entry);
        assert(
            transcript_ptr < MaxNumTokens,
            "capture_missing_tokens: MaxNumTokens limit exceeded!",
        );
        updated_transcript[transcript_ptr] = new_transcript;
        transcript_ptr += (update != 0) as u32;
    }
    updated_transcript
}

// ============================================================================
// a literal past byte 255
// ============================================================================
//
// `capture_missing_tokens` re-reads the four/five bytes of every `true`,
// `false`, `null` to check them, and bounded the byte offset with
// `index.assert_max_bit_size::<8>()` -- 255. `index` is a 16-bit field of
// `RawTranscriptEntry` and every other user of it treats it as such, so the
// `<8>` is simply too tight: ANY document longer than 256 bytes with a boolean
// or a null after byte 255 fails inside `parse_json`. It has nothing to do with
// the numeric grammar work; it showed up because `real-elliptic-severe` (651 B, `false`
// at offset 501) is the first record that got far enough to hit it.

/// `{"pad":"xxx...","b":true}`, 268 bytes, with the `true` starting at byte 263.
fn literal_past_byte_255_document() -> [u8; 268] {
    let mut doc: [u8; 268] = [120; 268]; // 'x'
    let head = "{\"pad\":\"".as_bytes();
    for i in 0..8 {
        doc[i] = head[i];
    }
    let tail = "\",\"b\":true}".as_bytes();
    for i in 0..11 {
        doc[257 + i] = tail[i];
    }
    doc
}

#[test]
fn literal_past_byte_255_parses() {
    let json: JSON<268, 12, 32, 17, 2> = JSON::parse_json(literal_past_byte_255_document());
    assert(json.get_literal_unchecked("b".as_bytes()).is_true());
}

#[test]
fn test_numbers() {
    let text = "{ \"a\": 9, \"b\": 99, \"c\": 999, \"d\": 9999, \"e\": 99999, \"f\": 999999, \"g\": 9999999, \"h\": 99999999, \"i\": 999999999, \"j\": 9999999999, \"k\": 99999999999, \"l\": 999999999999, \"m\": 9999999999999, \"n\": 99999999999999, \"o\": 999999999999999, \"p\": 999999999999999,\"q\": 9999999999999999, \"r\": 99999999999999999, \"s\": 999999999999999999, \"t\": 9999999999999999999, \"u\": 18446744073709551615}";
    let json: JSON<372, 16, 100, 24, 2> = JSON::parse_json_from_string(text);

    let a = json.get_number_unchecked("a".as_bytes());
    let b = json.get_number_unchecked("b".as_bytes());
    let c = json.get_number_unchecked("c".as_bytes());
    let d = json.get_number_unchecked("d".as_bytes());
    let e = json.get_number_unchecked("e".as_bytes());
    let f = json.get_number_unchecked(BoundedVec::from_parts("ftrololol".as_bytes(), 1));
    let g = json.get_number("g".as_bytes()).unwrap();
    let h = json.get_number(BoundedVec::from_parts("h".as_bytes(), 1)).unwrap();
    let i = json.get_number_unchecked("i".as_bytes());
    let j = json.get_number_unchecked("j".as_bytes());
    let k = json.get_number_unchecked("k".as_bytes());
    let l = json.get_number_unchecked("l".as_bytes());
    let m = json.get_number_unchecked("m".as_bytes());
    let n = json.get_number_unchecked("n".as_bytes());
    let o = json.get_number_unchecked("o".as_bytes());
    let p = json.get_number_unchecked("p".as_bytes());
    let q = json.get_number_unchecked("q".as_bytes());
    let r = json.get_number_unchecked("r".as_bytes());
    let s = json.get_number_unchecked("s".as_bytes());
    let t = json.get_number_unchecked("t".as_bytes());
    let u = json.get_number_unchecked("u".as_bytes());

    assert(a == 9);
    assert(b == 99);
    assert(c == 999);
    assert(d == 9999);
    assert(e == 99999);
    assert(f == 999999);
    assert(g == 9999999);
    assert(h == 99999999);
    assert(i == 999999999);
    assert(j == 9999999999);
    assert(k == 99999999999);
    assert(l == 999999999999);
    assert(m == 9999999999999);
    assert(n == 99999999999999);
    assert(o == 999999999999999);
    assert(p == 999999999999999);
    assert(q == 9999999999999999);
    assert(r == 99999999999999999);
    assert(s == 999999999999999999);
    assert(t == 9999999999999999999);
    assert(u == 18446744073709551615);
}

#[test]
fn test_parent_array() {
    let text = "[0,10,21,32,44]";
    let json: JSON<15, 10, 20, 20, 2> = JSON::parse_json_from_string(text);
    assert(json.get_length() == 5);
    assert(json.get_number_from_array_unchecked(0) == 0);
    assert(json.get_number_from_array_unchecked(1) == 10);
    assert(json.get_number_from_array_unchecked(2) == 21);
    assert(json.get_number_from_array_unchecked(3) == 32);
    assert(json.get_number_from_array_unchecked(4) == 44);
}

#[test]
fn test_escaped_strings() {
    let text = "{   \"name\": \"\\\"Ade\\nel Solangi\\\"\", \"testA\": false, \"testB\": true, \"testC\": null }                                                                   ";
    let json: JSON<148, 10, 20, 20, 2> = JSON::parse_json_from_string(text);
    let result: BoundedVec<u8, 19> = json.get_string_unchecked("name".as_bytes());
    assert(result.storage() == BoundedVec::from_array("\"Ade\nel Solangi\"".as_bytes()).storage());
    assert(result.len() == 16);
}

#[test]
fn test_parse_json() {
    let text = "{ \"foo\": 1234, \"bar\": { \"foo\": 9876, \"bar\": true }, \"baz\": \"hello\" }";
    let json: JSON<68, 7, 30, 30, 2> = JSON::parse_json_from_string(text);

    let result = json.get_string_unchecked("baz".as_bytes());
    assert(result.storage() == "hello".as_bytes());

    let result: Option<BoundedVec<u8, 5>> = json.get_string("baz".as_bytes());
    assert(result.is_some());
    assert(result.unwrap().storage() == "hello".as_bytes());

    let result: Option<BoundedVec<u8, 1>> = json.get_string("wibble".as_bytes());
    assert(result.is_some() == false);

    let result: u64 = json.get_number_unchecked("foo".as_bytes());
    assert(result == 1234);

    let result: Option<u64> = json.get_number("foo".as_bytes());
    assert(result.is_some());
    assert(result.unwrap() == 1234);

    let result: Option<u64> = json.get_number("fooo".as_bytes());
    assert(result.is_some() == false);

    let nested_json = json.get_object("bar".as_bytes()).unwrap();
    let result: Option<u64> =
        nested_json.get_number(BoundedVec::from_parts("foounusedkeybyteslolol".as_bytes(), 3));
    assert(result.is_some() == true);
    assert(result.unwrap() == 9876);

    let key0: BoundedVec<u8, 3> = BoundedVec::from_array("bar".as_bytes());
    let key1: BoundedVec<u8, 3> = BoundedVec::from_array("baz".as_bytes());

    let result: Option<BoundedVec<u8, 10>> = json.get_string_from_path([key0, key1]);
    assert(result.is_some() == false);
}

// ---------------------------------------------------------------------------
// multi-segment paths
// ---------------------------------------------------------------------------
//
// `get_string_from_path` / `get_value_from_path` walked every intermediate segment
// against `self` instead of against the object the previous segment resolved to. At
// depth 2 the two are the same thing, which is why it went unnoticed; from depth 3 on,
// every segment but the last was looked up in the root, so a genuinely nested path did
// not resolve at all.

type PathJson = JSON<96, 7, 32, 17, 2>;

fn nested_path_document() -> PathJson {
    JSON::parse_json_from_string("{\"a\":{\"b\":{\"c\":\"deep\"}},\"c\":\"shallow\"}")
}

#[test]
fn path_of_three_segments_resolves_through_the_nesting() {
    let json = nested_path_document();
    let path: [BoundedVec<u8, 1>; 3] = [
        BoundedVec::from_array("a".as_bytes()),
        BoundedVec::from_array("b".as_bytes()),
        BoundedVec::from_array("c".as_bytes()),
    ];

    let result: Option<BoundedVec<u8, 10>> = json.get_string_from_path(path);
    assert(result.is_some());
    let found = result.unwrap();
    assert_eq(found.len(), 4);
    assert_eq(found.storage()[0], "d".as_bytes()[0]);
}

#[test]
fn path_of_three_segments_returns_the_value_getter_too() {
    let json = nested_path_document();
    let path: [BoundedVec<u8, 1>; 3] = [
        BoundedVec::from_array("a".as_bytes()),
        BoundedVec::from_array("b".as_bytes()),
        BoundedVec::from_array("c".as_bytes()),
    ];

    let result: Option<JSONValue<10>> = json.get_value_from_path(path);
    assert(result.is_some());
    assert(result.unwrap().is_string());
}

/// `a.c` does not exist -- `c` only exists at the root and under `a.b`. Depth 2 was
/// always right, but it is the case the walk must keep getting right.
#[test]
fn path_does_not_fall_back_to_the_root() {
    let json = nested_path_document();
    let path: [BoundedVec<u8, 1>; 2] =
        [BoundedVec::from_array("a".as_bytes()), BoundedVec::from_array("c".as_bytes())];

    let result: Option<BoundedVec<u8, 10>> = json.get_string_from_path(path);
    assert(result.is_none());
}

#[test]
fn test_literal() {
    let text = "{   \"name\": \"Adeel Solangi\", \"testA\": false, \"testB\": true, \"testC\": null }                                                                   ";
    let json: JSON<142, 10, 20, 20, 2> = JSON::parse_json_from_string(text);

    let result: JSONLiteral = json.get_literal_unchecked("testA".as_bytes());
    assert(result.is_false() == true);
    assert(result.is_true() == false);
    assert(result.is_null() == false);
    assert(result.to_bool() == false);

    let result_option: Option<JSONLiteral> = json.get_literal("testA".as_bytes());
    assert(result_option.is_some());
    assert(result_option.unwrap().value == result.value);
}

#[test]
fn test_arrays() {
    let text = "{   \"name\": \"Adeel Solangi\", \"age\": 62, \"portfolio\": { \"vibe_ratings\": [1,2],\"elemental_lorem\": false }}                                                 ";
    let json: JSON<153, 10, 60, 60, 2> = JSON::parse_json_from_string(text);

    assert(json.key_exists(BoundedVec::from_parts("foo".as_bytes(), 3)) == false);
    assert(json.key_exists(BoundedVec::from_parts("name".as_bytes(), 4)));
    assert(json.key_exists(BoundedVec::from_parts("age".as_bytes(), 3)));
    assert(json.key_exists(BoundedVec::from_parts("portfolio".as_bytes(), 9)));
}

#[test(should_fail_with = "build_transcript: MaxNumTokens limit exceeded!")]
fn test_json_not_enough_tokens_fails() {
    let text = "{ \"hello \": \"world\" }";
    let _: JSON<26, 10, 2, 20, 2> = JSON::parse_json_from_string(text);
}

#[test(should_fail_with = "capture_missing_tokens: MaxNumTokens limit exceeded!")]
fn test_json_not_enough_tokens_fails_2() {
    // we should exceed the limit of 8 tokens here, when capturing the `,` token missed by build_transcript
    let text = "{ \"hello \": false,\"world\": true }";
    let _: JSON<33, 10, 8, 20, 2> = JSON::parse_json_from_string(text);
}

#[test(should_fail_with = "create_json_entries: MaxNumValues limit exceeded!")]
fn test_json_not_enough_values_fails() {
    let text = "{ \"hello \": false,\"world\": true }";
    let _: JSON<33, 10, 10, 4, 2> = JSON::parse_json_from_string(text);
}

#[test(should_fail_with = "ValidationFlags: grammar error")]
fn test_json_object_without_key_fails() {
    let text = "{ \"hello \": \"world\", 100 }";
    let _: JSON<26, 10, 20, 20, 2> = JSON::parse_json_from_string(text);
}

#[test(should_fail_with = "ValidationFlags: grammar error")]
fn test_json_array_with_key_fails() {
    let text = "[ \"hello \": \"world\" ]";
    let _: JSON<26, 10, 20, 20, 2> = JSON::parse_json_from_string(text);
}

#[test(should_fail_with = "ValidationFlags: grammar error")]
fn test_json_unclosed_object_fails() {
    let text = "{ \"hello \": \"world\" ";
    let _: JSON<26, 10, 20, 20, 2> = JSON::parse_json_from_string(text);
}

#[test(should_fail_with = "ValidationFlags: grammar error")]
fn test_json_object_closed_with_array_fails() {
    let text = "{ \"hello \": \"world\" ]";
    let _: JSON<26, 10, 20, 20, 2> = JSON::parse_json_from_string(text);
}

#[test(should_fail_with = "ValidationFlags: grammar error")]
fn test_json_object_with_trailing_comma_fails() {
    let text = "{ \"hello \" : \"world\", }";
    let _: JSON<26, 10, 20, 20, 2> = JSON::parse_json_from_string(text);
}

#[test(should_fail_with = "ValidationFlags: grammar error")]
fn test_json_unclosed_array_fails() {
    let text = "[ \"hello \", \"world\"";
    let _: JSON<19, 10, 20, 20, 2> = JSON::parse_json_from_string(text);
}

#[test(should_fail_with = "validate_tokens: unclosed objects or arrays")]
fn test_json_unclosed_array_fails_2() {
    let text = "[ \"hello \", \"world\", [1,2,3,4] ";
    let _: JSON<31, 10, 20, 20, 2> = JSON::parse_json_from_string(text);
}

#[test(should_fail_with = "ValidationFlags: grammar error")]
fn test_json_array_with_trailing_comma_fails() {
    let text = "[ \"hello \", \"world\", ]";
    let _: JSON<26, 10, 20, 20, 2> = JSON::parse_json_from_string(text);
}

#[test(should_fail_with = "ValidationFlags: grammar error")]
fn test_json_array_closed_with_object_fails() {
    let text = "[ \"hello \": \"world\" }";
    let _: JSON<26, 10, 20, 20, 2> = JSON::parse_json_from_string(text);
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn test_json_key_not_wrapped_in_quotes_fails() {
    let text = "{ false: \"world\" }";
    let _: JSON<26, 10, 20, 20, 2> = JSON::parse_json_from_string(text);
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn test_json_string_not_wrapped_in_quotes_fails() {
    let text = "{ \"hello \": world }";
    let _: JSON<26, 10, 20, 20, 2> = JSON::parse_json_from_string(text);
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn test_json_char_outside_of_string_fails() {
    let text = "{ \"hello \", \"world\" a}";
    let _: JSON<26, 10, 20, 20, 2> = JSON::parse_json_from_string(text);
}

#[test(should_fail_with = "ValidationFlags: grammar error")]
fn test_json_array_with_invalid_tokens_fails() {
    // n could be the start of the literal "null", so this passes the ScanData check but fails ValidationFlags
    let text = "[,,,]";
    let _: JSON<26, 10, 20, 20, 2> = JSON::parse_json_from_string(text);
}

#[test(should_fail_with = "Cannot find key/value straddling KEY_DELIMITER_TOKEN")]
fn test_json_object_with_invalid_tokens_fails() {
    // n could be the start of the literal "null", so this passes the ScanData check but fails ValidationFlags
    let text = "{:::}";
    let _: JSON<26, 10, 20, 20, 2> = JSON::parse_json_from_string(text);
}

#[test]
fn test_json_empty_object_passes() {
    // n could be the start of the literal "null", so this passes the ScanData check but fails ValidationFlags
    let text = "{}";
    let _: JSON<26, 10, 20, 20, 2> = JSON::parse_json_from_string(text);
}

#[test]
fn test_json_empty_array_passes() {
    // n could be the start of the literal "null", so this passes the ScanData check but fails ValidationFlags
    let text = "[]";
    let _: JSON<26, 10, 20, 20, 2> = JSON::parse_json_from_string(text);
}

#[test(should_fail)]
fn test_finishing_with_string_scan_fails() {
    let json_string = "{ } \"}";
    let _: JSON<26, 10, 20, 20, 2> = JSON::parse_json_from_string(json_string);
}

#[test(should_fail)]
fn test_finishing_with_literal_scan_fails() {
    let json_string = "{ } fa";
    let _: JSON<26, 10, 20, 20, 2> = JSON::parse_json_from_string(json_string);
}

#[test(should_fail)]
fn test_finishing_with_numeric_scan_fails() {
    let json_string = "{ } 123";
    let _: JSON<26, 10, 20, 20, 2> = JSON::parse_json_from_string(json_string);
}

#[test(should_fail)]
fn key_is_not_a_key() {
    let json_string = "{1\n:0}";
    let _: JSON<26, 10, 20, 20, 2> = JSON::parse_json_from_string(json_string);
}

#[test(should_fail_with = "invalid literal")]
fn test_invalid_literal() {
    let text = "{ \"name\":fal }";
    let _: JSON<153, 10, 60, 60, 2> = JSON::parse_json_from_string(text);
}

#[test(should_fail_with = "invalid literal")]
fn test_invalid_literal_2() {
    let text = "{ \"name\":treu}";
    let _: JSON<153, 10, 60, 60, 2> = JSON::parse_json_from_string(text);
}

#[test(should_fail_with = "invalid literal")]
fn test_invalid_literal_3() {
    let text = "{ \"name\":truea }";
    let _: JSON<153, 10, 60, 60, 2> = JSON::parse_json_from_string(text);
}

#[test(should_fail_with = "invalid literal")]
fn test_invalid_literal_4() {
    let text = "{ \"hello \", \"world\" n}";
    let _: JSON<26, 10, 20, 20, 2> = JSON::parse_json_from_string(text);
}

// ============================================================================
// number grammar: decimals and negatives
// ============================================================================
//
// The scanner recognises `-? ( 0 | [1-9][0-9]* ) ( . [0-9]+ )? ( [eE] [+-]? [0-9]+ )?`,
// which is exactly RFC 8259's `number`. Everything the grammar rejects is rejected
// *inside* `parse_json`, in the tokenizer, with `ScanData: Invalid token` -- not
// deferred to a getter.
//
// `get_value` returns the raw bytes and `value_type == NUMERIC_TOKEN`, so a
// decimal and an integer are indistinguishable by type: a reader that wants a
// u64 must use `get_number`, which rejects `.` and `-` (see get_number.nr).

/// 32 bytes covers every case below; `NumPackedFields = ceil(32/31) + 3 = 5`.
type NumberJson = JSON<32, 5, 16, 9, 2>;

/// assert that key "a" holds a numeric token whose raw bytes are `expected`
fn number_value_is<let N: u32>(json: NumberJson, expected: [u8; N]) {
    let v: JSONValue<16> = json.get_value("a".as_bytes()).unwrap();
    assert(v.is_number(), "number: value_type is not NUMERIC_TOKEN");
    assert(v.value.len() == N, "number: wrong token length");
    for i in 0..N {
        assert(v.value.get(i) == expected[i], "number: wrong token byte");
    }
}

#[test]
fn number_accepts_leading_zero_decimal() {
    let json: NumberJson = JSON::parse_json_from_string("{\"a\":0.5}");
    number_value_is(json, "0.5".as_bytes());
}

#[test]
fn number_accepts_one_digit_decimal() {
    let json: NumberJson = JSON::parse_json_from_string("{\"a\":9.6}");
    number_value_is(json, "9.6".as_bytes());
}

#[test]
fn number_accepts_trailing_zeros_in_fraction() {
    let json: NumberJson = JSON::parse_json_from_string("{\"a\":10.00}");
    number_value_is(json, "10.00".as_bytes());
}

#[test]
fn number_accepts_eight_decimals() {
    let json: NumberJson = JSON::parse_json_from_string("{\"a\":1.12345678}");
    number_value_is(json, "1.12345678".as_bytes());
}

#[test]
fn number_accepts_negative_integer() {
    let json: NumberJson = JSON::parse_json_from_string("{\"a\":-3}");
    number_value_is(json, "-3".as_bytes());
}

#[test]
fn number_accepts_negative_zero() {
    let json: NumberJson = JSON::parse_json_from_string("{\"a\":-0}");
    number_value_is(json, "-0".as_bytes());
}

#[test]
fn number_accepts_negative_decimal() {
    let json: NumberJson = JSON::parse_json_from_string("{\"a\":-1.5}");
    number_value_is(json, "-1.5".as_bytes());
}

#[test]
fn number_accepts_plain_zero() {
    let json: NumberJson = JSON::parse_json_from_string("{\"a\":0}");
    number_value_is(json, "0".as_bytes());
}

#[test]
fn number_accepts_negative_zero_decimal() {
    let json: NumberJson = JSON::parse_json_from_string("{\"a\":-0.0}");
    number_value_is(json, "-0.0".as_bytes());
}

#[test]
fn number_accepts_a_lowercase_exponent() {
    let json: NumberJson = JSON::parse_json_from_string("{\"a\":1e5}");
    number_value_is(json, "1e5".as_bytes());
}

#[test]
fn number_accepts_an_uppercase_exponent() {
    let json: NumberJson = JSON::parse_json_from_string("{\"a\":1E5}");
    number_value_is(json, "1E5".as_bytes());
}

#[test]
fn number_accepts_a_signed_exponent_on_a_decimal() {
    let json: NumberJson = JSON::parse_json_from_string("{\"a\":1.5E-3}");
    number_value_is(json, "1.5E-3".as_bytes());
}

#[test]
fn number_accepts_a_positive_exponent() {
    let json: NumberJson = JSON::parse_json_from_string("{\"a\":2e+10}");
    number_value_is(json, "2e+10".as_bytes());
}

/// `01` is not JSON but `1e05` is: the exponent has no leading-zero rule, which is why
/// `NUMERIC_EXP_DIGITS` cannot reuse `NUMERIC` / `NUMERIC_ZERO`.
#[test]
fn number_accepts_a_leading_zero_in_the_exponent() {
    let json: NumberJson = JSON::parse_json_from_string("{\"a\":1e05}");
    number_value_is(json, "1e05".as_bytes());
}

#[test]
fn number_accepts_an_exponent_on_zero() {
    let json: NumberJson = JSON::parse_json_from_string("{\"a\":0e0}");
    number_value_is(json, "0e0".as_bytes());
}

/// The tokenizer got wider; `get_number` did not. It reads plain unsigned integers and
/// nothing else, so an exponent is still refused there.
#[test(should_fail_with = "get_number: numeric token is not a plain unsigned integer")]
fn number_exponent_is_refused_by_get_number() {
    let json: NumberJson = JSON::parse_json_from_string("{\"a\":1e5}");
    let _ = json.get_number_unchecked("a".as_bytes());
}

#[test]
fn number_accepts_a_decimal_inside_an_array() {
    let json: NumberJson = JSON::parse_json_from_string("{\"a\":[-1.5,0.5]}");
    let inner = json.get_array_unchecked("a".as_bytes());
    assert(inner.get_length() == 2);
}

/// `get_value_from_array` used to assert `STRING_TOKEN`, mirroring the string getter,
/// while its object counterpart `get_value` asserts nothing. That made the raw bytes of
/// a *number* inside an array unreachable: `get_number_from_array` was the only door and
/// it rejects decimals. The getter now returns the entry whatever its type, with
/// `value_type` telling the caller what it got -- exactly like `get_value`.
#[test]
fn number_array_element_raw_bytes_are_readable() {
    let json: NumberJson = JSON::parse_json_from_string("{\"a\":[-1.5,0.5]}");
    let inner = json.get_array_unchecked("a".as_bytes());

    let first: JSONValue<16> = inner.get_value_from_array_unchecked(0);
    assert(first.is_number());
    assert(first.value.storage()[0] == "-".as_bytes()[0]);
    assert_eq(first.value.len(), 4);

    let second: JSONValue<16> = inner.get_value_from_array_unchecked(1);
    assert(second.is_number());
    assert_eq(second.value.len(), 3);
}

/// Literals and nested containers come back through the same door.
#[test]
fn array_element_values_carry_their_type() {
    let json: JSON<64, 6, 24, 13, 2> =
        JSON::parse_json_from_string("{\"a\":[true,\"s\",{\"b\":1}]}");
    let inner = json.get_array_unchecked("a".as_bytes());

    let literal: JSONValue<16> = inner.get_value_from_array_unchecked(0);
    assert(literal.is_literal());

    let string: JSONValue<16> = inner.get_value_from_array_unchecked(1);
    assert(string.is_string());

    let object: JSONValue<16> = inner.get_value_from_array_unchecked(2);
    assert(object.is_object());
}

/// The *string* getters keep their type assertion: they unescape, which only makes
/// sense for strings.
#[test(should_fail_with = "get_array_element_as_string: entry exists but is not a string!")]
fn number_array_element_is_still_not_a_string() {
    let json: NumberJson = JSON::parse_json_from_string("{\"a\":[-1.5,0.5]}");
    let inner = json.get_array_unchecked("a".as_bytes());
    let _: BoundedVec<u8, 16> = inner.get_string_from_array(0).unwrap();
}

#[test]
fn number_still_accepts_a_quoted_decimal_as_a_string() {
    let json: NumberJson = JSON::parse_json_from_string("{\"a\":\"1.5\"}");
    let v: JSONValue<16> = json.get_value("a".as_bytes()).unwrap();
    assert(v.is_string());
    assert(v.value.len() == 3);
}

// --- rejected by the tokenizer ---------------------------------------------

#[test(should_fail_with = "ScanData: Invalid token")]
fn number_rejects_trailing_dot() {
    let _: NumberJson = JSON::parse_json_from_string("{\"a\":1.}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn number_rejects_leading_dot() {
    let _: NumberJson = JSON::parse_json_from_string("{\"a\":.5}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn number_rejects_leading_zero_integer() {
    let _: NumberJson = JSON::parse_json_from_string("{\"a\":01}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn number_rejects_leading_zero_decimal() {
    let _: NumberJson = JSON::parse_json_from_string("{\"a\":01.5}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn number_rejects_double_zero() {
    let _: NumberJson = JSON::parse_json_from_string("{\"a\":00}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn number_rejects_bare_minus() {
    let _: NumberJson = JSON::parse_json_from_string("{\"a\":-}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn number_rejects_double_minus() {
    let _: NumberJson = JSON::parse_json_from_string("{\"a\":--1}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn number_rejects_minus_after_digits() {
    let _: NumberJson = JSON::parse_json_from_string("{\"a\":1-2}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn number_rejects_second_dot() {
    let _: NumberJson = JSON::parse_json_from_string("{\"a\":1.2.3}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn number_rejects_dot_after_fraction_start() {
    let _: NumberJson = JSON::parse_json_from_string("{\"a\":1..2}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn number_rejects_unary_plus() {
    let _: NumberJson = JSON::parse_json_from_string("{\"a\":+1}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn number_rejects_a_bare_exponent_marker() {
    let _: NumberJson = JSON::parse_json_from_string("{\"a\":1e}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn number_rejects_an_exponent_sign_with_no_digits() {
    let _: NumberJson = JSON::parse_json_from_string("{\"a\":1e-}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn number_rejects_a_second_exponent() {
    let _: NumberJson = JSON::parse_json_from_string("{\"a\":1e2e3}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn number_rejects_a_fraction_after_the_exponent() {
    let _: NumberJson = JSON::parse_json_from_string("{\"a\":1e2.5}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn number_rejects_an_exponent_after_a_bare_minus() {
    let _: NumberJson = JSON::parse_json_from_string("{\"a\":-e5}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn number_rejects_double_plus_exponent() {
    let _: NumberJson = JSON::parse_json_from_string("{\"a\":1e++2}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn number_rejects_a_minus_that_is_not_at_the_head() {
    let _: NumberJson = JSON::parse_json_from_string("{\"a\":1.-5}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn number_rejects_a_dot_after_a_minus() {
    let _: NumberJson = JSON::parse_json_from_string("{\"a\":-.5}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn number_rejects_a_number_followed_by_a_key_separator() {
    let _: NumberJson = JSON::parse_json_from_string("{\"a\":1:2}");
}

// ============================================================================
// Non-ASCII bytes inside strings and keys are preserved opaquely.
// ============================================================================
//
// Byte transparency, not UTF-8 validation: 0x80..0xFF are string content and
// come back out of `get_string` exactly as they went in. A malformed sequence
// is NOT rejected -- see the note in `make_json_capture_table`.

// ---------------------------------------------------------------------------
// key length boundary (MaxKeyFields limbs of 31 bytes)
// ---------------------------------------------------------------------------
//
// `MaxKeyFields = 2` buys keys of up to 62 bytes: the hash is taken over exactly
// `MaxKeyFields` 31-byte limbs. The lookup-side bound in `ByteHasher::get_keyhash_var`
// read `key_length < KeyFields * 31`, so a 62-byte key parsed happily and then aborted
// the moment anyone looked it up -- an off-by-one, not a real limit. Both hashers now
// bound at `<= KeyFields * 31`, and a key past that is rejected during the parse rather
// than truncated into a collision.

type KeyBoundaryJson = JSON<80, 6, 16, 9, 2>;

#[test]
fn key_of_61_bytes_round_trips() {
    let json: KeyBoundaryJson = JSON::parse_json_from_string(
        "{\"kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk\":1}",
    );
    let key = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk".as_bytes();
    assert_eq(key.len(), 61);
    assert(json.get_number_unchecked(key) == 1);
}

#[test]
fn key_of_62_bytes_round_trips() {
    let json: KeyBoundaryJson = JSON::parse_json_from_string(
        "{\"kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk\":1}",
    );
    let key = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk".as_bytes();
    assert_eq(key.len(), 62);
    assert(json.get_number_unchecked(key) == 1);
}

/// The exact-capacity key must also be distinguishable from every other key of the same
/// length: truncation would make these two collide.
#[test]
fn keys_of_62_bytes_are_not_truncated() {
    let json: JSON<160, 9, 24, 13, 2> = JSON::parse_json_from_string(
        "{\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA\":1,\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaB\":2}",
    );
    assert(
        json.get_number_unchecked("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA"
            .as_bytes())
            == 1,
    );
    assert(
        json.get_number_unchecked("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaB"
            .as_bytes())
            == 2,
    );
}

/// One byte past capacity is rejected by the parse itself, not by the getter.
#[test(should_fail_with = "key too large")]
fn key_of_63_bytes_is_rejected_at_parse() {
    let _: KeyBoundaryJson = JSON::parse_json_from_string(
        "{\"kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk\":1}",
    );
}

/// ... and a lookup with an over-long key is rejected too, even against a JSON that
/// contains no such key.
#[test(should_fail_with = "key too large")]
fn lookup_with_a_63_byte_key_is_rejected() {
    let json: KeyBoundaryJson = JSON::parse_json_from_string("{\"a\":1}");
    let _ = json.get_number("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"
        .as_bytes());
}

// ============================================================================
// string grammar: escapes and raw control bytes
// ============================================================================
//
// The original implementation tracks escapes with one bit ("the previous byte was a
// backslash"), which buys exactly one thing: a `"` straight after a `\` does not close
// the string. It cannot say which characters may follow a backslash and it cannot count,
// so `\q`, `\u12"` and `\u00zz` all parsed. Five scan modes replace the bit and
// recognise `\ ( ["\/bfnrt] | u [0-9a-fA-F]{4} )`. Dropping the bit halves
// `JSON_CAPTURE_TABLE`, which is what pays for them.
//
// Raw TAB, LF and CR inside a string were string content. RFC 8259 forbids every byte
// below 0x20 raw inside a string; the other 29 were already errors here.
//
// This is escape *syntax*. `\uD800` unpaired is still accepted and
// `process_escape_sequences` still unescapes only a subset -- see the README.

type EscapeJson = JSON<48, 5, 16, 9, 2>;

/// The eight one-character escapes, and `\uXXXX` in both hex cases.
#[test]
fn escape_accepts_every_legal_form() {
    let _: EscapeJson = JSON::parse_json_from_string("{\"a\":\"\\\"\"}");
    let _: EscapeJson = JSON::parse_json_from_string("{\"a\":\"\\\\\"}");
    let _: EscapeJson = JSON::parse_json_from_string("{\"a\":\"\\/\"}");
    let _: EscapeJson = JSON::parse_json_from_string("{\"a\":\"\\b\"}");
    let _: EscapeJson = JSON::parse_json_from_string("{\"a\":\"\\f\"}");
    let _: EscapeJson = JSON::parse_json_from_string("{\"a\":\"\\n\"}");
    let _: EscapeJson = JSON::parse_json_from_string("{\"a\":\"\\r\"}");
    let _: EscapeJson = JSON::parse_json_from_string("{\"a\":\"\\t\"}");
    let _: EscapeJson = JSON::parse_json_from_string("{\"a\":\"\\u00e9\"}");
    let _: EscapeJson = JSON::parse_json_from_string("{\"a\":\"\\uABCD\"}");
    let _: EscapeJson = JSON::parse_json_from_string("{\"a\":\"\\u0F9f\"}");
}

/// The one thing the old escape bit did get right, and the reason it existed.
#[test]
fn escape_quote_does_not_close_the_string() {
    let json: EscapeJson = JSON::parse_json_from_string("{\"a\":\"x\\\"y\"}");
    let v: JSONValue<16> = json.get_value("a".as_bytes()).unwrap();
    assert(v.is_string());
    assert_eq(v.value.len(), 4);
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn escape_rejects_an_unknown_escape_character() {
    let _: EscapeJson = JSON::parse_json_from_string("{\"a\":\"\\q\"}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn escape_rejects_a_single_quote_escape() {
    let _: EscapeJson = JSON::parse_json_from_string("{\"a\":\"\\'\"}");
}

/// A trailing backslash: the closing quote arrives while the scanner is waiting for the
/// escaped character, and `"` is a legal escape, so the string never closes and the
/// document ends mid-token.
#[test(should_fail)]
fn escape_rejects_a_trailing_backslash() {
    let _: EscapeJson = JSON::parse_json_from_string("{\"a\":\"x\\\"}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn escape_rejects_a_short_unicode_escape() {
    let _: EscapeJson = JSON::parse_json_from_string("{\"a\":\"\\u12\"}");
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn escape_rejects_a_non_hex_unicode_escape() {
    let _: EscapeJson = JSON::parse_json_from_string("{\"a\":\"\\u00zz\"}");
}

/// Three hex digits then a legal string byte: the fourth position accepts hex only.
#[test(should_fail_with = "ScanData: Invalid token")]
fn escape_rejects_a_unicode_escape_cut_short_by_content() {
    let _: EscapeJson = JSON::parse_json_from_string("{\"a\":\"\\u00fg\"}");
}

/// A high byte is string content, but not inside an escape.
#[test(should_fail)]
fn escape_rejects_a_high_byte_inside_a_unicode_escape() {
    let mut doc: [u8; 14] = "{\"a\":\"\\u00eF\"}".as_bytes();
    doc[11] = 0xC3; // the fourth hex digit
    let _: EscapeJson = JSON::parse_json(doc);
}

/// Keys are strings, so they go through the same modes.
#[test(should_fail_with = "ScanData: Invalid token")]
fn escape_rejects_a_bad_escape_in_a_key() {
    let _: EscapeJson = JSON::parse_json_from_string("{\"a\\q\":1}");
}

#[test]
fn escape_accepts_a_unicode_escape_in_a_key() {
    let json: EscapeJson = JSON::parse_json_from_string("{\"a\\u0041\":1}");
    assert(json.get_number_unchecked("a\\u0041".as_bytes()) == 1);
}

/// Raw TAB (0x09), LF (0x0A) and CR (0x0D) inside a string. They were the only three
/// control bytes still accepted, and the only three whose `increase_length` disagreed
/// with their `capture`, so a raw tab also silently shortened the token it was in.
fn document_with_raw_byte_in_a_string(byte: u8) -> [u8; 11] {
    let mut doc: [u8; 11] = "{\"a\":\"x y\"}".as_bytes();
    doc[7] = byte;
    doc
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn string_rejects_a_raw_tab() {
    let _: EscapeJson = JSON::parse_json(document_with_raw_byte_in_a_string(0x09));
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn string_rejects_a_raw_line_feed() {
    let _: EscapeJson = JSON::parse_json(document_with_raw_byte_in_a_string(0x0A));
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn string_rejects_a_raw_carriage_return() {
    let _: EscapeJson = JSON::parse_json(document_with_raw_byte_in_a_string(0x0D));
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn string_rejects_a_raw_null_byte() {
    let _: EscapeJson = JSON::parse_json(document_with_raw_byte_in_a_string(0x00));
}

/// The same three bytes stay legal *between* tokens, which is where JSON allows them.
#[test]
fn whitespace_between_tokens_is_still_accepted() {
    let mut doc: [u8; 13] = "{\"a\":   1   }".as_bytes();
    doc[5] = 0x09;
    doc[6] = 0x0A;
    doc[7] = 0x0D;
    let json: EscapeJson = JSON::parse_json(doc);
    assert(json.get_number_unchecked("a".as_bytes()) == 1);
}

type Utf8Json = JSON<24, 4, 16, 9, 2>;

global UTF8_EACUTE: [u8; 13] = [123, 34, 97, 34, 58, 34, 99, 97, 102, 195, 169, 34, 125];
global UTF8_JAPANESE: [u8; 14] = [123, 34, 97, 34, 58, 34, 230, 151, 165, 230, 156, 172, 34, 125];
global UTF8_EMOJI: [u8; 12] = [123, 34, 97, 34, 58, 34, 240, 159, 152, 128, 34, 125];
global UTF8_KEY: [u8; 12] = [123, 34, 99, 105, 116, 116, 195, 160, 34, 58, 49, 125];
global UTF8_LONE_HIGH_BYTE_IN_STRING: [u8; 9] = [123, 34, 97, 34, 58, 34, 255, 34, 125];
global UTF8_HIGH_BYTE_OUTSIDE_STRING: [u8; 7] = [123, 34, 97, 34, 58, 128, 125];

fn utf8_string_bytes_are<let N: u32>(json: Utf8Json, expected: [u8; N]) {
    let s: BoundedVec<u8, 16> = json.get_string("a".as_bytes()).unwrap();
    assert(s.len() == N, "utf8: wrong length");
    for i in 0..N {
        assert(s.get(i) == expected[i], "utf8: wrong byte");
    }
}

#[test]
fn utf8_two_byte_sequence_in_a_value() {
    let json = Utf8Json::parse_json(UTF8_EACUTE);
    utf8_string_bytes_are(json, [99, 97, 102, 195, 169]); // caf<c3><a9>
}

#[test]
fn utf8_three_byte_sequences_in_a_value() {
    let json = Utf8Json::parse_json(UTF8_JAPANESE);
    utf8_string_bytes_are(json, [230, 151, 165, 230, 156, 172]);
}

#[test]
fn utf8_four_byte_sequence_in_a_value() {
    let json = Utf8Json::parse_json(UTF8_EMOJI);
    utf8_string_bytes_are(json, [240, 159, 152, 128]);
}

#[test]
fn utf8_in_a_key() {
    let json = Utf8Json::parse_json(UTF8_KEY);
    // key "citt<c3><a0>", looked up by its raw bytes
    let key: [u8; 6] = [99, 105, 116, 116, 195, 160];
    assert(json.get_number_unchecked(key) == 1);
}

/// Documents the limit: this is not valid UTF-8 and it parses anyway.
#[test]
fn utf8_a_lone_high_byte_inside_a_string_is_accepted_unvalidated() {
    let json = Utf8Json::parse_json(UTF8_LONE_HIGH_BYTE_IN_STRING);
    utf8_string_bytes_are(json, [255]);
}

#[test(should_fail_with = "ScanData: Invalid token")]
fn utf8_a_high_byte_outside_a_string_still_fails() {
    let _ = Utf8Json::parse_json(UTF8_HIGH_BYTE_OUTSIDE_STRING);
}
