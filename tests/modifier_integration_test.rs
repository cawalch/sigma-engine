//! Integration tests for SIGMA modifiers with the full engine pipeline.

use sigma_engine::matcher::{
    register_comprehensive_modifiers, register_defaults_with_comprehensive_modifiers,
};
use sigma_engine::{Compiler, MatcherBuilder};

#[test]
fn test_comprehensive_modifiers_registration() {
    // Test that comprehensive modifiers can be registered successfully
    let mut match_registry = std::collections::HashMap::new();
    let mut modifier_registry = std::collections::HashMap::new();
    register_defaults_with_comprehensive_modifiers(&mut match_registry, &mut modifier_registry);

    // Verify key modifiers are available
    let expected_modifiers = vec![
        "base64_decode",
        "base64",
        "url_decode",
        "url_encode",
        "html_decode",
        "utf16_decode",
        "utf16le_decode",
        "utf16be_decode",
        "wide_decode",
        "lowercase",
        "uppercase",
        "trim",
        "reverse",
        "normalize_whitespace",
        "normalize_path",
        "basename",
        "dirname",
        "hex_decode",
        "hex_encode",
        "to_int",
        "to_float",
        "md5",
        "sha1",
        "sha256",
    ];

    for modifier in expected_modifiers {
        assert!(
            modifier_registry.contains_key(modifier),
            "Missing modifier: {modifier}"
        );
    }

    // Verify we have a substantial number of modifiers
    assert!(
        modifier_registry.len() >= 25,
        "Expected at least 25 modifiers, got {}",
        modifier_registry.len()
    );
}

#[test]
fn test_modifier_functionality() {
    // Test that individual modifiers work correctly
    let mut modifier_registry = std::collections::HashMap::new();
    register_comprehensive_modifiers(&mut modifier_registry);

    // Test base64 decode
    if let Some(base64_decode) = modifier_registry.get("base64_decode") {
        let result = base64_decode("aGVsbG8=").expect("base64 decode should work");
        assert_eq!(result, "hello");
    }

    // Test hex encode
    if let Some(hex_encode) = modifier_registry.get("hex_encode") {
        let result = hex_encode("hello").expect("hex encode should work");
        assert_eq!(result, "68656c6c6f");
    }

    // Test uppercase
    if let Some(uppercase) = modifier_registry.get("uppercase") {
        let result = uppercase("hello").expect("uppercase should work");
        assert_eq!(result, "HELLO");
    }

    // Test trim
    if let Some(trim) = modifier_registry.get("trim") {
        let result = trim("  hello  ").expect("trim should work");
        assert_eq!(result, "hello");
    }
}

#[test]
fn test_modifier_builder_integration() {
    // Test that modifiers can be registered with MatcherBuilder
    let mut builder = MatcherBuilder::new();
    let mut modifier_registry = std::collections::HashMap::new();
    register_comprehensive_modifiers(&mut modifier_registry);

    // Register a few key modifiers with the builder
    let key_modifiers = vec!["base64_decode", "hex_encode", "uppercase", "trim"];
    for modifier_name in key_modifiers {
        if let Some(modifier_fn) = modifier_registry.get(modifier_name) {
            let modifier_fn_clone = modifier_fn.clone();
            builder.register_modifier(modifier_name, move |input| modifier_fn_clone(input));
        }
    }

    // Verify the modifiers were registered
    assert!(builder.has_modifier("base64_decode"));
    assert!(builder.has_modifier("hex_encode"));
    assert!(builder.has_modifier("uppercase"));
    assert!(builder.has_modifier("trim"));
    assert!(!builder.has_modifier("nonexistent_modifier"));
}

#[test]
fn test_compiler_modifier_parsing() {
    // Test that the compiler correctly parses SIGMA modifiers
    let compiler = Compiler::new();

    // Test various modifier combinations
    let test_cases = vec![
        ("Image", ("Image", "equals", vec![])),
        ("Image|endswith", ("Image", "endswith", vec![])),
        ("CommandLine|contains", ("CommandLine", "contains", vec![])),
        ("User|cased", ("User", "equals", vec!["case_sensitive"])),
        ("Hash|re", ("Hash", "regex", vec![])),
        ("Data|base64", ("Data", "equals", vec!["base64_decode"])),
        ("Data|utf16", ("Data", "equals", vec!["utf16_decode"])),
        ("Data|wide", ("Data", "equals", vec!["wide_decode"])),
        (
            "Data|contains|base64|cased",
            ("Data", "contains", vec!["base64_decode", "case_sensitive"]),
        ),
    ];

    for (input, expected) in test_cases {
        let (field, match_type, modifiers) = compiler.parse_field_with_modifiers(input);
        assert_eq!(field, expected.0, "Field mismatch for input: {input}");
        assert_eq!(
            match_type, expected.1,
            "Match type mismatch for input: {input}"
        );
        assert_eq!(
            modifiers, expected.2,
            "Modifiers mismatch for input: {input}"
        );
    }
}

#[test]
fn test_modifier_error_handling() {
    // Test that modifiers handle errors gracefully
    let mut modifier_registry = std::collections::HashMap::new();
    register_comprehensive_modifiers(&mut modifier_registry);

    // Test base64 decode with invalid input
    if let Some(base64_decode) = modifier_registry.get("base64_decode") {
        let result = base64_decode("invalid_base64!");
        assert!(result.is_err(), "Invalid base64 should return error");
    }

    // Test hex decode with invalid input
    if let Some(hex_decode) = modifier_registry.get("hex_decode") {
        let result = hex_decode("invalid_hex");
        assert!(result.is_err(), "Invalid hex should return error");
    }

    // Test to_int with invalid input
    if let Some(to_int) = modifier_registry.get("to_int") {
        let result = to_int("not_a_number");
        assert!(result.is_err(), "Invalid integer should return error");
    }
}
