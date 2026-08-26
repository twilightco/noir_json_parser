use crate::_comparison_tools::bounds_checker::get_validity_flags;
use crate::_comparison_tools::lt::{assert_gt_240_bit, assert_lt_240_bit, lt_field_16_bit};
use crate::_string_tools::string_chopper::slice_string;
use crate::enums::Layer::ARRAY_LAYER;
use crate::json::JSON;
use crate::json_entry::{JSONEntry, JSONEntryPacked};
use crate::keyhash::ByteHasher;
use crate::keymap::KeyIndexData;
use crate::utils::cast_num_to_u32;

/// records data used to reason about whether a key exists in a json blob
pub struct KeySearchResult {
    found: bool, // does the key exist?
    target_lt_smallest_entry: bool, // is the target keyhash smaller than the smallest keyhash in self.key_hashes?
    target_gt_largest_entry: bool, // is the target keyhash larger than the largest keyhash in self.key_hashes?
    lhs_index: u32, // either the index of the key being searched for, or the index of the keyhash in self.key_hashes that is closest to keyhash (hash > lhs_index_hash)
    rhs_index: u32, // either the index of the key being searched for, or the index of the keyhash in self.key_hashes that is closest to keyhash (hash < rhs_index_hash)
}

pub trait KeyHashable {
    fn get_keyhash<let MaxKeyFields: u32>(self) -> Field;
}

impl<let N: u32> KeyHashable for [u8; N] {

    fn get_keyhash<let MaxKeyFields: u32>(self) -> Field {
        let hasher: ByteHasher<MaxKeyFields> = ByteHasher {};
        hasher.get_keyhash_var(self, 0, N)
    }
}

impl<let N: u32> KeyHashable for BoundedVec<u8, N> {
    fn get_keyhash<let MaxKeyFields: u32>(self) -> Field {
        let hasher: ByteHasher<MaxKeyFields> = ByteHasher {};
        hasher.get_keyhash_var(self.storage(), 0, self.len())
    }
}

impl<let N: u32> KeyHashable for str<N> {
    fn get_keyhash<let MaxKeyFields: u32>(self) -> Field {
        let hasher: ByteHasher<MaxKeyFields> = ByteHasher {};
        hasher.get_keyhash_var(self.as_bytes(), 0, N)
    }
}

/// helper methods for extracting data out of a processed JSON object
impl<let NumBytes: u32, let NumPackedFields: u32, let MaxNumTokens: u32, let MaxNumValues: u32, let MaxKeyFields: u32> JSON<NumBytes, NumPackedFields, MaxNumTokens, MaxNumValues, MaxKeyFields> {

    /// If the root JSON is an object, extract a JSONEntry that describes an array, object or value that maps to a given key
    ///
    /// returns an Option<JSONEntry> which will be null if the entry does not exist
    pub(crate) fn get_json_entry<K>(self, key: K) -> (bool, JSONEntry, u32)
    where
        K: KeyHashable,
    {
        assert(self.layer_type_of_root != ARRAY_LAYER, "cannot extract array elements via a key");

        let (exists, key_index) = self.key_exists_impl(key);
        let entry: JSONEntry = self.json_entries_packed[key_index].into();
        (exists, entry, key_index)
    }

    /// If the root JSON is an object, extract a JSONEntry that describes an array, object or value that maps to a given key
    ///
    /// will revert if the key does not exist
    pub(crate) fn get_json_entry_unchecked<K>(self, key: K) -> JSONEntry
    where
        K: KeyHashable,
    {
        self.get_json_entry_unchecked_with_key_index(key).0
    }

    /// same as `get_json_entry_unchecked` but also returns the position of the JSONEntry in `self.json_entries_packed`
    pub(crate) fn get_json_entry_unchecked_with_key_index<K>(self, key: K) -> (JSONEntry, u32)
    where
        K: KeyHashable,
    {
        assert(self.layer_type_of_root != ARRAY_LAYER, "cannot extract array elements via a key");
        let keyhash = key.get_keyhash::<MaxKeyFields>();
        let two_pow_216 = 0x100000000000000000000000000000000000000000000000000000000;

        let keyhash = keyhash + self.root_id * two_pow_216;

        // Safety: The assertion below checks that the keyhash is stored in the the index returned by the unconstrained function
        let key_index = unsafe { find_key_in_map::<MaxNumValues>(self.key_hashes, keyhash) };

        assert_eq(self.key_hashes[key_index], keyhash, "get_json_entry_unchecked: key not found");
        let entry: JSONEntry = self.json_entries_packed[key_index].into();

        (entry, key_index)
    }

    /// helper method that will extract an array of bytes that describes the value associated with a JSONEntry object
    ///
    /// e.g. if the JSONEntry describes "foo" : "bar" in the JSON, `extract_string_entry` will return "foo"
    pub(crate) fn extract_string_entry<let StringBytes: u32>(
        self,
        entry: JSONEntry,
    ) -> [u8; StringBytes] {
        // todo can we make this faster? witness gen for this method is slow
        // TODO: document that StringBytes parameter includes non-escaped characters
        assert(
            lt_field_16_bit(entry.json_length, StringBytes as Field + 1),
            "get_string, string size is larger than StringBytes",
        );

        let result: [u8; StringBytes] =
            slice_string(self.json_packed, entry.json_pointer, entry.json_length);

        result
    }

    /// returns a bool that describes whether a given key exists at the root of the JSON
    pub fn key_exists<K>(self, key: K) -> bool
    where
        K: KeyHashable,
    {
        self.key_exists_impl(key).0
    }

    /// implementation of `key_exists`. returns both a boolean and also the position in `self.json_entries_packed` of the key
    ///
    /// algorithm is O(1) because of the preprocessing we have done
    /// Method computes a key hash and checks whether key hash exists in the list of sorted preprocessed key hashes
    /// If it does *not* exist, we can find two adjacent entries in `key_hashes` where `key_hashes[i]` < target_key_hash < `key_hashes[i+1]`
    pub(crate) fn key_exists_impl<K>(self, key: K) -> (bool, u32)
    where
        K: KeyHashable,
    {
        /*
            Option A: key exists
            Option B: key does NOT exist
        If key does NOT exist. 3 cases
            case 1: keyhash < first entry
            case 2: keyhash > last entry
            case 3: entry A > keyhash > entryB
        */
        let keyhash = key.get_keyhash::<MaxKeyFields>();
        let HASH_MAXIMUM = 0x1000000000000000000000000000000000000000000000000000000000000 - 1;
        let two_pow_216 = 0x100000000000000000000000000000000000000000000000000000000;

        let keyhash = keyhash + self.root_id * two_pow_216;

        // Safety: the assertion (search_result.lhs_index - search_result.rhs_index) * found == 0 constraints this function
        let search_result =
            unsafe { search_for_key_in_map::<MaxNumValues>(self.key_hashes, keyhash) };
        if search_result.found {
            assert_eq(search_result.lhs_index, search_result.rhs_index);
        }

        let found = search_result.found as Field;
        let target_lt_smallest_entry = search_result.target_lt_smallest_entry;
        let target_gt_largest_entry = search_result.target_gt_largest_entry;

        // only one of "found", "target_lt_smallest_entry", "target_gt_largest_entry" can be true
        let exclusion_test =
            found + (target_gt_largest_entry as Field) + (target_lt_smallest_entry as Field);
        exclusion_test.assert_max_bit_size::<1>();

        /*
            [soundness fix] bind the not-found witness to the sorted list.

            INVARIANT USED. `self.key_hashes` is sorted non-decreasing:
                key_hashes[i] <= key_hashes[i + 1]  for every i in 0..MaxNumValues - 1.
            This is established in `keymap.nr:compute_keyhash_and_sort_json_entries`,
            which builds `hashlist` and sorts it with `noir_sort::sort_advanced`. The
            constrained part of that call proves (a) that `sorted` is a permutation of
            `hashlist` (`get_shuffle_indices`, proved in both directions) and (b) the
            chain `assert_lte_240_bit(sorted[i], sorted[i + 1])` over every adjacent
            pair. Every entry of `hashlist` is a 200-bit key hash plus a 16-bit
            `array_index` at 2^200 plus a 16-bit `parent_id` at 2^216, all range
            checked (`slice_200_bits_from_field`, `KeyIndexData::from_field`), hence
            < 2^232: the 240-bit comparison cannot wrap and really orders the list.
            The same bound holds for `keyhash` below (200-bit hash + 16-bit `root_id`
            at 2^216), so all the comparisons in this function are over integers.

            NON-MEMBERSHIP. On a sorted list, "keyhash is not in key_hashes" is proved
            by exactly one of three witnesses:
              (a) keyhash < key_hashes[0]                    -> below every entry;
              (b) key_hashes[MaxNumValues - 1] < keyhash     -> above every entry;
              (c) key_hashes[j] < keyhash < key_hashes[j+1]  -> strictly between two
                                                                *adjacent* entries.
            The `assert_gt_240_bit` / `assert_lt_240_bit` pair further down proves the
            inequalities; the missing piece was binding the *indices*.
            Without it (c) degenerates into "between two arbitrary entries", which a
            key that is actually present can simply be jumped over, and (b) is a free
            pass: `target_gt_largest_entry` hands out rhs = HASH_MAXIMUM without ever
            being compared to the last entry. The three asserts below are the missing
            binding:
              (a) target_lt_smallest_entry => rhs_index == 0
              (b) target_gt_largest_entry  => lhs_index == MaxNumValues - 1
              (c) none of the three flags  => rhs_index == lhs_index + 1
            `middle` is boolean because `exclusion_test` is range checked to 1 bit.

            PADDING. Unused slots of `key_data` hold 0, so they all hash to the *same*
            constant (Poseidon of an empty key, array_index 0, parent_id 0), and
            `keymap.nr:67` additionally forces one entry to 0. The sorted list is
            therefore `0`, then a run of equal padding entries, then the real keys:
            the smallest real key is *not* at index 0, and equal adjacent entries are
            the norm rather than the exception. Two consequences:
              * case (c) has to mean "adjacent in `key_hashes`", not "adjacent among
                real keys" -- which it does, and the honest hint was taught to return
                the *last* index of the largest entry below the target so that the two
                indices really are consecutive (see `search_for_key_in_map`);
              * anchoring (a) to index 0 costs an honest prover nothing: key_hashes[0]
                is the forced 0 and every real target is >= 2^216 (root_id >= 1), so
                branch (a) is never taken honestly, and a malicious prover taking it
                must prove `keyhash < 0`, which is unsatisfiable.
            Padding entries are all < 2^216 (parent_id == 0), so they can never be hit
            by a lookup and their duplication is harmless here.

            DEPTH. `get_object` / `get_array` only change `self.root_id`, and the
            target is `key_hash + root_id * 2^216`: keys of every object in the record
            live in the same sorted list, grouped by `parent_id` in the high bits.
            Proving non-membership in the whole list implies non-membership in the
            group, so the argument holds at every depth.
        */
        let middle = 1 - exclusion_test;
        let lhs_index_f = search_result.lhs_index as Field;
        let rhs_index_f = search_result.rhs_index as Field;
        assert(
            middle * (rhs_index_f - lhs_index_f - 1) == 0,
            "key_exists: not-found witness entries are not adjacent",
        );
        assert(
            (target_lt_smallest_entry as Field) * rhs_index_f == 0,
            "key_exists: target_lt_smallest_entry must point at index 0",
        );
        assert(
            (target_gt_largest_entry as Field) * (lhs_index_f - (MaxNumValues as Field - 1)) == 0,
            "key_exists: target_gt_largest_entry must point at the last index",
        );

        // case where hash < self.key_hashes[0]
        // 0 < hash < hashes[0]
        let lhs = self.key_hashes[search_result.lhs_index];
        let mut lhs = if target_lt_smallest_entry { 0 } else { lhs };

        // case where hash > self.key_hashes[last]
        // largest < x < -1
        let rhs = self.key_hashes[search_result.rhs_index];
        let mut rhs = if target_gt_largest_entry {
            HASH_MAXIMUM
        } else {
            rhs
        };

        // case where hash == self.key_hashes[found_index]
        lhs -= found;
        rhs += found;

        assert_gt_240_bit(keyhash, lhs);
        assert_lt_240_bit(keyhash, rhs);

        (search_result.found, search_result.lhs_index)
    }

    pub fn get_keys_at_root<let MaxNumKeys: u32, let MaxKeyBytes: u32>(
        self,
    ) -> BoundedVec<BoundedVec<u8, MaxKeyBytes>, MaxNumKeys> {
        let root_object: JSONEntry =
            JSONEntry::from(self.json_entries_packed[self.root_index_in_transcript]);
        // Safety: the length of the index is constrained later.
        let key_indices: BoundedVec<Field, MaxNumKeys> = unsafe {
            __get_keys_at_root::<MaxNumKeys, MaxNumValues>(
                self.root_id,
                self.root_index_in_transcript,
                self.json_entries_packed,
                self.unsorted_json_entries_packed,
            )
        };

        assert(key_indices.len() as Field == root_object.num_children);

        /*
            The original implementation constrained only the *number* of indices returned
            by `__get_keys_at_root`, never which slots they point at, so the prover was
            free to return `num_children` copies of a single index, or indices of keys
            belonging to nested objects. Two constraints pin the set exactly:

              1. every returned slot is a direct child of the current root, i.e.
                 `key_data[idx].parent_id == self.root_id`. `KeyIndexData.parent_id` is
                 the identity of the enclosing object/array, the same value that ends
                 up in `JSONEntry.parent_index` for the same slot (`json.nr` writes
                 both from `current_identity_value`), and it is the field that
                 `keymap.nr` folds into the key hash at 2^216 -- the very thing a key
                 lookup matches against. `self.root_id` is >= 1 (1 for the document
                 root, the object's identity after `get_object`), while unused slots of
                 `key_data` are 0 and so carry `parent_id == 0`: the check also rules
                 out padding slots.

              2. the indices strictly increase, hence are pairwise distinct. The honest
                 hint scans `unsorted_json_entries_packed` from 0 upwards and appends,
                 so it already returns them sorted; requiring a strictly increasing
                 index is the cheapest way to constrain that, and as a bonus it pins
                 the result to document order.

            Together with the pre-existing length check, `num_children` distinct slots
            all having `parent_id == root_id` is exactly the set of the root's children,
            since that set has `num_children` elements.

            Both checks are masked by `valid[i] = i < key_indices.len()`: the loop runs
            over all `MaxNumKeys` slots, and the entries past the length are padding
            that `BoundedVec::from_parts_unchecked` discards. `valid` is monotone
            (1 ... 1 0 ... 0) by construction, so once the mask is 0 it stays 0 and
            `previous_index` can be left to drift. Note the flags array is one element
            longer than the loop: `get_validity_flags` rejects `boundary == N`, and
            `key_indices.len()` may legitimately equal `MaxNumKeys`.
        */
        let valid: [u32; MaxNumKeys + 1] = get_validity_flags(key_indices.len());
        let mut previous_index: Field = 0;

        let mut result: [BoundedVec<u8, MaxKeyBytes>; MaxNumKeys] = [BoundedVec::new(); MaxNumKeys];
        for i in 0..MaxNumKeys {
            let raw_index = key_indices.get_unchecked(i);
            let is_valid = valid[i] as Field;
            let key = KeyIndexData::from_field(self.key_data[cast_num_to_u32(raw_index)]);

            assert(
                (key.parent_id - self.root_id) * is_valid == 0,
                "get_keys_at_root: returned key does not belong to the root object",
            );
            // `i != 0` is a comptime loop index, so the branch itself costs nothing:
            // the first slot simply has no predecessor to compare against.
            if i != 0 {
                let increasing = lt_field_16_bit(previous_index, raw_index);
                assert(
                    (1 - increasing as Field) * is_valid == 0,
                    "get_keys_at_root: returned indices are not strictly increasing",
                );
            }
            previous_index = raw_index;

            // just a workaround to the interface for `extract_string_entry`
            let mut fake_entry = JSONEntry::new();
            fake_entry.json_pointer = key.json_index;
            fake_entry.json_length = key.json_length;
            result[i] = BoundedVec::from_parts(
                self.extract_string_entry(fake_entry),
                key.json_length as u32,
            );
        }
        BoundedVec::from_parts(result, key_indices.len())
    }

    /*
        [soundness fix] Asserts that the record contains no duplicate key, i.e. that no
        two entries of the same object carry the same key.

        This does *not* fix a hole in the lookup: with `{"a":1,"a":2}` both occurrences
        satisfy `key_hashes[i] == keyhash`, so which one `get_number("a")` returns is
        the prover's choice, and no local constraint can decide between two equal
        entries. The fix is to reject such records outright, which is also what the
        JSON semantics where a key means one value requires. Call it
        once per record, before reading anything out of it.

        How it works. `self.key_hashes` is sorted (see `key_exists_impl` for why that is
        constrained), so duplicates are adjacent and one pass over the adjacent pairs is
        enough. The list is not made only of keys, though: it also holds the padding
        slots (all hashing to the same constant), the forced 0 of `keymap.nr:67` and the
        record's own root entry. Those all have `parent_id == 0`, hence a value < 2^216,
        while every real key of every object has `parent_id >= 1`, hence a value
        >= 2^216. Since the list is sorted, the sub-2^216 entries form a *prefix*, and
        the check has to skip exactly that prefix -- otherwise the repeated padding
        would make every honest record fail.

        `num_padding` is a hint: its length is bound by a single comparison,
        `key_hashes[num_padding - 1] < 2^216`, which by sortedness proves that the whole
        skipped prefix has `parent_id == 0` and therefore contains no key. A prover
        cannot enlarge the skipped region to hide a duplicate; shrinking it only adds
        constraints. `num_padding >= 1` always holds, because `key_hashes[0]` is the
        forced 0.

        For `i` inside the prefix the mask makes the assert read `diff + 1 != 0`, which
        is free: `diff >= 0` by sortedness. For `i` past it the assert is `diff != 0`,
        i.e. strictly increasing, i.e. no duplicate.

        Array elements are not false positives: two elements of the same array share
        `parent_id` but differ in `array_index` (bits 200..215), so their entries
        differ. Two members of the same object share `array_index == 0`, so their
        entries are equal exactly when the key bytes are equal.

        Cost: ~5 gates per `MaxNumValues` slot plus one 240-bit range check.
    */
    pub fn assert_no_duplicate_keys(self) {
        let two_pow_216 = 0x100000000000000000000000000000000000000000000000000000000;

        // Safety: `num_padding` only selects which adjacent pairs are checked. The
        // assert below pins the skipped prefix to entries with `parent_id == 0`, which
        // no key lookup can ever target, so a wrong hint cannot hide a duplicate key.
        let num_padding =
            unsafe { __count_non_key_entries::<MaxNumValues>(self.key_hashes) };
        assert(num_padding != 0, "assert_no_duplicate_keys: empty padding prefix");
        assert_lt_240_bit(self.key_hashes[num_padding - 1], two_pow_216);

        // `valid[j] = j < num_padding - 1`, so `valid[i - 1] = i < num_padding`.
        // Shifting by one keeps the boundary below the array length even when every
        // entry is padding (an empty record `{}`), which `get_validity_flags` requires.
        let valid: [u32; MaxNumValues] = get_validity_flags(num_padding - 1);
        for i in 1..MaxNumValues {
            let diff = self.key_hashes[i] - self.key_hashes[i - 1];
            assert(
                diff + valid[i - 1] as Field != 0,
                "assert_no_duplicate_keys: duplicate key in the record",
            );
        }
    }

    /// Helper function to get an entry from an array at a given index
    ///
    /// # Arguments
    ///
    /// * `array_index` - The index within the array
    ///
    /// # Returns
    ///
    /// (entry, valid, entry_index) where:
    ///   - entry: The JSONEntry at the given index
    ///   - valid: Indicates if the index is within bounds
    ///   - entry_index: The actual index in json_entries_packed where the entry is stored
    pub(crate) fn get_entry_from_array(self, array_index: Field) -> (JSONEntry, bool, u32) {
        assert_eq(
            self.layer_type_of_root,
            ARRAY_LAYER,
            "can only access array elements from array",
        );

        let parent_entry: JSONEntry =
            self.json_entries_packed[self.root_index_in_transcript].into();

        let valid = lt_field_16_bit(array_index, parent_entry.num_children);
        let entry_index = (parent_entry.child_pointer + array_index) * valid as Field;

        let entry: JSONEntry = self.json_entries_packed[cast_num_to_u32(entry_index)].into();

        (entry, valid, cast_num_to_u32(entry_index))
    }

    // Entry-level helpers for callers whose query shape is known only at
    // witness time. Such callers need
    //
    //   * ONE lookup that hands back the entry and lets the caller decide what
    //     its `entry_type` means, instead of `get_string` / `get_number` /
    //     `get_object` / `get_array` each asserting their own
    //     (`adapter_entry_under` + `adapter_value_bytes`);
    //   * a lookup under an EXPLICIT parent identity, so `a.b` does not have to
    //     materialise a child `JSON` and mux the whole struct -- the identity
    //     of the object found at `a` is its `entry.id`, which is precisely what
    //     `get_object` would have written into `root_id`;
    //   * the root shape taken from the parse instead of a compile-time global
    //     (`adapter_effective_root`), which a generic attestor cannot have;
    //   * the raw sorted key-hash list, for the one predicate the O(1) lookup
    //     cannot express -- "every occurrence of this key at ANY depth"
    //     (`adapter_key_hashes` + `adapter_entry_at`);
    //   * a key hash taken from limbs the caller already holds
    //     (`adapter_keyhash_of_limbs`).
    // -----------------------------------------------------------------------

    /// 200-bit key hash of a key already packed into `MaxKeyFields` limbs of 31
    /// big-endian bytes each.
    ///
    /// Identical by construction to `KeyHashable::get_keyhash` on the same
    /// bytes: all three trait impls end in this same
    /// `Poseidon2::hash(limbs, MaxKeyFields)` + `slice_200_bits_from_field`.
    /// It is offered separately because `get_keyhash_var` re-derives the limbs
    /// with `31 * MaxKeyFields` reads at witness-dependent indices, work a
    /// caller whose key already sits in a fixed, zero-padded buffer does not
    /// need to pay.
    pub fn adapter_keyhash_of_limbs(self, limbs: [Field; MaxKeyFields]) -> Field {
        let _ = self;
        let hashed = poseidon::poseidon2::Poseidon2::hash(limbs, MaxKeyFields);
        crate::_string_tools::slice_field::slice_200_bits_from_field(hashed)
    }

    /// `key_exists_impl`, with the lookup target supplied by the caller.
    ///
    /// The body below is the body of `key_exists_impl` from the point where the
    /// target is known: the same three not-found bindings added by the
    /// soundness fix, the same two 240-bit comparisons, the same return. Only
    /// the head differs -- the original builds the target as
    /// `key.get_keyhash() + self.root_id * 2^216`, this one receives it. Read
    /// the invariant written above those bindings in `key_exists_impl`: nothing
    /// in it depends on where the high bits came from, because `root_id` was
    /// never more to that proof than "the high 16 bits of the target".
    ///
    /// PRECONDITION: `target < 2^232`. Every target this crate builds satisfies
    /// it (a 200-bit hash plus a 16-bit identity at 2^216), and it is what
    /// makes the two 240-bit comparisons order integers rather than wrap.
    pub fn adapter_key_exists_at(self, target: Field) -> (bool, u32) {
        let HASH_MAXIMUM = 0x1000000000000000000000000000000000000000000000000000000000000 - 1;
        target.assert_max_bit_size::<232>();

        // Safety: exactly as in `key_exists_impl` -- the asserts below bind
        // every field of the returned witness to the sorted list.
        let search_result =
            unsafe { search_for_key_in_map::<MaxNumValues>(self.key_hashes, target) };
        if search_result.found {
            assert_eq(search_result.lhs_index, search_result.rhs_index);
        }

        let found = search_result.found as Field;
        let target_lt_smallest_entry = search_result.target_lt_smallest_entry;
        let target_gt_largest_entry = search_result.target_gt_largest_entry;

        let exclusion_test =
            found + (target_gt_largest_entry as Field) + (target_lt_smallest_entry as Field);
        exclusion_test.assert_max_bit_size::<1>();

        let middle = 1 - exclusion_test;
        let lhs_index_f = search_result.lhs_index as Field;
        let rhs_index_f = search_result.rhs_index as Field;
        assert(
            middle * (rhs_index_f - lhs_index_f - 1) == 0,
            "key_exists: not-found witness entries are not adjacent",
        );
        assert(
            (target_lt_smallest_entry as Field) * rhs_index_f == 0,
            "key_exists: target_lt_smallest_entry must point at index 0",
        );
        assert(
            (target_gt_largest_entry as Field) * (lhs_index_f - (MaxNumValues as Field - 1)) == 0,
            "key_exists: target_gt_largest_entry must point at the last index",
        );

        let lhs = self.key_hashes[search_result.lhs_index];
        let mut lhs = if target_lt_smallest_entry { 0 } else { lhs };

        let rhs = self.key_hashes[search_result.rhs_index];
        let mut rhs = if target_gt_largest_entry {
            HASH_MAXIMUM
        } else {
            rhs
        };

        lhs -= found;
        rhs += found;

        assert_gt_240_bit(target, lhs);
        assert_lt_240_bit(target, rhs);

        (search_result.found, search_result.lhs_index)
    }

    /// One lookup, raw and untyped:
    /// `(exists, entry_type, id, num_children, json_pointer, json_length)` for
    /// the entry that `keyhash` names inside the object whose identity is
    /// `parent_id`.
    ///
    /// No type assertion, deliberately. `get_object` / `get_array` /
    /// `get_string` / `get_number` each assert their own `entry_type`, which is
    /// what a caller with a witness-shaped predicate cannot afford: it would
    /// have to call every one of them. The type comes back as a value instead,
    /// and the caller asserts the one its predicate asked for.
    ///
    /// PRECONDITION: `keyhash < 2^200` and `parent_id < 2^16`, so that the
    /// target stays inside the bound `adapter_key_exists_at` documents. Both
    /// hold for the values this crate hands out -- `adapter_keyhash_of_limbs`
    /// and `KeyHashable` end in `slice_200_bits_from_field`, and `JSONEntry.id`
    /// is range checked to 16 bits by `JSONEntry::from_field`.
    pub fn adapter_entry_under(
        self,
        parent_id: Field,
        keyhash: Field,
    ) -> (bool, Field, Field, Field, Field, Field) {
        let two_pow_216 = 0x100000000000000000000000000000000000000000000000000000000;
        let (exists, key_index) = self.adapter_key_exists_at(keyhash + parent_id * two_pow_216);
        let entry: JSONEntry = self.json_entries_packed[key_index].into();
        (
            exists, entry.entry_type, entry.id, entry.num_children, entry.json_pointer,
            entry.json_length,
        )
    }

    /// The entry at `index` of the sorted entry list, as
    /// `(entry_type, num_children, json_pointer, json_length)`.
    ///
    /// Index-aligned with `adapter_key_hashes`: entry `i` is the value whose
    /// key hashes to `key_hashes[i]`. That alignment is not new -- the whole of
    /// `get_json_entry_unchecked_with_key_index` rests on it.
    pub fn adapter_entry_at(self, index: u32) -> (Field, Field, Field, Field) {
        let entry: JSONEntry = self.json_entries_packed[index].into();
        (entry.entry_type, entry.num_children, entry.json_pointer, entry.json_length)
    }

    /// The type, identity and parent identity of the entry at `index`, i.e.
    /// `(entry_type, id, parent_index)`.
    ///
    /// A cheaper partial decode than `adapter_entry_at`: it goes through
    /// `extract_entry_type_id_and_parent_index_from_field` (three 16-bit range
    /// checks and one recomposition) instead of unpacking all eight members.
    /// A caller that walks the whole list -- to answer "is the parent of this
    /// entry an object or an array?", which nothing else in the crate can say
    /// -- pays that once per slot and nothing more.
    pub fn adapter_entry_type_id_parent(self, index: u32) -> (Field, Field, Field) {
        let (id, parent_index, entry_type) = JSONEntry::extract_entry_type_id_and_parent_index_from_field(
            self.json_entries_packed[index].value,
        );
        (entry_type, id, parent_index)
    }

    /// The sorted key-hash list. Element `i` is
    /// `keyhash + array_index * 2^200 + parent_id * 2^216` (`keymap.nr`), so a
    /// caller that decomposes it can ask "which entries carry THIS key,
    /// whatever their parent" -- a question the O(1) lookup cannot pose,
    /// because the parent identity is part of the thing being matched.
    pub fn adapter_key_hashes(self) -> [Field; MaxNumValues] {
        self.key_hashes
    }

    /// Raw bytes of a value, from the pointer/length pair of its entry. Same
    /// path `get_value` takes, without the `Option` and without the type
    /// dispatch: `extract_string_entry` still asserts
    /// `json_length <= StringBytes`, so an over-long value fails closed rather
    /// than truncating.
    pub fn adapter_value_bytes<let StringBytes: u32>(
        self,
        json_pointer: Field,
        json_length: Field,
    ) -> [u8; StringBytes] {
        let mut entry = JSONEntry::new();
        entry.json_pointer = json_pointer;
        entry.json_length = json_length;
        self.extract_string_entry(entry)
    }

    /// The identity of the object that a root-level key resolves against,
    /// DERIVED FROM THE PARSE: the document root when it is an object, and the
    /// single element of the root array when it is an array.
    ///
    /// `get_length` and
    /// `key_exists` assert instead of answering, and `layer_type_of_root` is
    /// `pub(crate)`, so a caller had to know the shape at compile time -- fine
    /// for one provider, not for an attestor over arbitrary endpoints. The two
    /// asserts are the shape policy: an array root must hold exactly one
    /// element and that element must be an object.
    pub fn adapter_effective_root(self) -> Field {
        let root_entry: JSONEntry = self.json_entries_packed[self.root_index_in_transcript].into();
        let is_array = root_entry.entry_type == crate::enums::Token::END_ARRAY_TOKEN as Field;

        // Read unconditionally so the branch muxes one Field instead of two
        // array reads; when the root is an object the value is discarded.
        let child: JSONEntry =
            self.json_entries_packed[cast_num_to_u32(root_entry.child_pointer)].into();

        if is_array {
            assert(
                root_entry.num_children == 1,
                "adapter_effective_root: root array must hold exactly one element",
            );
            assert_eq(
                child.entry_type,
                crate::enums::Token::END_OBJECT_TOKEN as Field,
                "adapter_effective_root: root array element must be an object",
            );
        } else {
            assert_eq(
                root_entry.entry_type,
                crate::enums::Token::END_OBJECT_TOKEN as Field,
                "adapter_effective_root: root must be an object or an array",
            );
        }

        if is_array {
            child.id
        } else {
            self.root_id
        }
    }
}

unconstrained fn find_key_in_map<let MaxNumValues: u32>(
    key_hashes: [Field; MaxNumValues],
    target: Field,
) -> u32 {
    let mut found_index: u32 = 0;
    let mut found: bool = false;
    for i in 0..MaxNumValues {
        let key_hash = key_hashes[i];
        if (key_hash == target) {
            found_index = i;
            found = true;
            break;
        }
    }
    assert(found, "find_key_in_map, key not found");
    found_index
}

/// figures out if `target` exists as a key in `self.key_hashes`
///
/// if `target` does not exist, we return the two indices of adjacent
/// entries in `self.key_hashes`, lhs_index, rhs_index, where
/// lhs_index < key_hash < rhs_index
unconstrained fn search_for_key_in_map<let MaxNumValues: u32>(
    key_hashes: [Field; MaxNumValues],
    target: Field,
) -> KeySearchResult {
    let mut found_index: Field = 0;
    let mut found: bool = false;

    let mut lhs_maximum: Field = 0;
    let mut rhs_minimum: Field = -1;
    let mut lhs_maximum_index: Field = 0;
    let mut rhs_minimum_index: Field = 0;
    for i in 0..MaxNumValues {
        let key_hash = key_hashes[i];
        if (key_hash == target) {
            found_index = i as Field;
            found = true;
            break;
        } else {
            // [soundness fix] `!key_hash.lt(lhs_maximum)` is `lhs_maximum <= key_hash`.
            // The comparison has to be non-strict so that a repeated entry updates
            // `lhs_maximum_index` again: we must hand back the *last* index holding
            // the largest entry below the target, otherwise `lhs_index` and
            // `rhs_index` are not consecutive whenever that entry is duplicated --
            // which is the common case, since every unused slot of `key_data` hashes
            // to the same padding value. `rhs_minimum` stays strict on purpose: it
            // already yields the *first* index of the smallest entry above the target.
            if key_hash.lt(target) & !(key_hash.lt(lhs_maximum)) {
                lhs_maximum = key_hash;
                lhs_maximum_index = i as Field;
            }
            if (target.lt(key_hash)) & (key_hash.lt(rhs_minimum)) {
                rhs_minimum = key_hash;
                rhs_minimum_index = i as Field;
            }
        }
    }
    let target_lt_smallest_entry = target.lt(key_hashes[0]);
    let target_gt_largest_entry = key_hashes[MaxNumValues - 1].lt(target);

    let result_not_first_or_last = !target_lt_smallest_entry & !target_gt_largest_entry & !found;

    let mut lhs_index = result_not_first_or_last as Field * lhs_maximum_index;
    let mut rhs_index = result_not_first_or_last as Field * rhs_minimum_index;

    // if target_lt_smallest_entry, rhs_index = 0
    // if target_gt_largest_entry, lhs_index = TranscriptEntries - 1
    rhs_index = rhs_index * (1 - target_lt_smallest_entry as Field);

    // we rely here on the fact that target_gt_largest_entry and result_not_first_or_last are mutually exclusive
    lhs_index = lhs_index + target_gt_largest_entry as Field * (MaxNumValues as Field - 1);

    // If target is FOUND, we want the following:
    // keyhash[target_index] - 1 < hash < keyhash[target_index] + 1
    lhs_index = lhs_index + found as Field * found_index;
    rhs_index = rhs_index + found as Field * found_index;

    KeySearchResult {
        found,
        target_lt_smallest_entry,
        target_gt_largest_entry,
        lhs_index: lhs_index as u32,
        rhs_index: rhs_index as u32,
    }
}

/// counts the leading entries of the sorted `key_hashes` that are *not* keys, i.e.
/// the ones whose `parent_id` (bits 216..239) is zero: padding slots, the forced zero
/// entry and the record's own root entry. See `assert_no_duplicate_keys`.
unconstrained fn __count_non_key_entries<let MaxNumValues: u32>(
    key_hashes: [Field; MaxNumValues],
) -> u32 {
    let two_pow_216 = 0x100000000000000000000000000000000000000000000000000000000;
    let mut count: u32 = 0;
    for i in 0..MaxNumValues {
        if key_hashes[i].lt(two_pow_216) {
            count += 1;
        }
    }
    count
}

unconstrained fn __get_keys_at_root<let MaxNumKeys: u32, let MaxNumValues: u32>(
    root_id: Field,
    root_index_in_transcript: u32,
    json_entries_packed: [JSONEntryPacked; MaxNumValues],
    unsorted_json_entries_packed: [JSONEntryPacked; MaxNumValues],
) -> BoundedVec<Field, MaxNumKeys> {
    let root_object: JSONEntry = JSONEntry::from(json_entries_packed[root_index_in_transcript]);

    let mut result_ptr = 0;
    let mut result: [Field; MaxNumKeys] = [0; MaxNumKeys];
    for i in 0..MaxNumValues {
        let target_entry: JSONEntry = JSONEntry::from(unsorted_json_entries_packed[i]);
        if (target_entry.parent_index == root_id) {
            result[result_ptr] = i as Field;
            result_ptr += 1;
        }
    }
    assert_eq(result_ptr as Field, root_object.num_children);

    BoundedVec::from_parts(result, result_ptr as u32)
}

#[test]
fn test_get_keys_at_root() {
    let s = "{ \"A\": 1, \"foo\": false, \"bar\": { \"one\" : \"A\", \"two\" : \"B\"}, \"baz\": \"12345\"  }";

    let json: JSON<77, 6, 30, 30, 2> = JSON::parse_json_from_string(s);

    let keys: BoundedVec<BoundedVec<u8, 5>, 5> = json.get_keys_at_root();

    assert(keys.len() == 4);
    assert(keys.get_unchecked(0) == BoundedVec::from_array("A".as_bytes()));
    assert(keys.get_unchecked(1) == BoundedVec::from_array("foo".as_bytes()));
    assert(keys.get_unchecked(2) == BoundedVec::from_array("bar".as_bytes()));
    assert(keys.get_unchecked(3) == BoundedVec::from_array("baz".as_bytes()));
}
