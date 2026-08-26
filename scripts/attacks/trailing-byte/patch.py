old = """    assert(
        scan_mode == GRAMMAR_CAPTURE as Field,
        "build_transcript: incomplete token (number, string or literal)",
    );
"""
new = "    // ATTACK: the unconstrained assert, not run\n"
apply_to = "src/json.nr"
