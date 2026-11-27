use std::fs;
use std::path::Component;

use dandi_core::archive::parse_zip_raw_headers_from_bytes;
use dandi_core::{
    inspect, normalize_for_pack, sanitize_entry_path, InspectOptions, PathPolicy, SafetyBudget,
};
use proptest::prelude::*;
use tempfile::TempDir;
use unicode_normalization::UnicodeNormalization;

fn adversarial_segment_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("..".to_string()),
        Just(".".to_string()),
        Just("CON".to_string()),
        Just("CON.txt".to_string()),
        Just("NUL ".to_string()),
        Just("com1.log".to_string()),
        Just("LPT9.tar.gz".to_string()),
        Just("C:".to_string()),
        Just("a:b*c?\"<>|".to_string()),
        Just("trailing...   ".to_string()),
        Just("e\u{0301}_\u{1100}\u{1161}\u{11ab}".to_string()), // NFD Latin + Hangul
        Just("か\u{3099}_が".to_string()),                      // NFD Japanese dakuten
        Just("\x00bad".to_string()),
        Just("\x01\x02\x1fctrl".to_string()),
        "\\PC{0,24}",
    ]
}

fn adversarial_path_strategy() -> impl Strategy<Value = String> {
    (
        prop_oneof![
            Just(String::new()),
            Just("/".to_string()),
            Just("\\".to_string()),
            Just("\\\\server\\share\\".to_string()),
            Just("C:\\".to_string()),
            Just("D:/".to_string()),
            Just("./".to_string()),
        ],
        prop::collection::vec(adversarial_segment_strategy(), 0..=5),
        prop::collection::vec(prop_oneof![Just("/"), Just("\\"), Just("//")], 0..=5),
    )
        .prop_map(|(prefix, segs, seps)| {
            let mut s = prefix;
            for (i, seg) in segs.into_iter().enumerate() {
                if i > 0 {
                    let sep = seps.get(i % seps.len().max(1)).copied().unwrap_or("/");
                    s.push_str(sep);
                }
                s.push_str(&seg);
            }
            s
        })
}

fn is_windows_reserved_stem(seg: &str) -> bool {
    let stem = seg.split('.').next().unwrap_or(seg).trim_end();
    matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

fn assert_common_sanitized_invariants(
    p: &dandi_core::SanitizedPath,
    check_win_rules: bool,
) -> Result<(), TestCaseError> {
    let norm = p.normalized();
    prop_assert!(!norm.is_empty());
    prop_assert!(!norm.starts_with('/') && !norm.ends_with('/'));
    prop_assert!(!norm.contains('\0'));
    prop_assert!(!norm.contains('\\'));
    prop_assert_eq!(norm, norm.nfc().collect::<String>());

    let rel = p.relative();
    prop_assert!(!rel.is_absolute());
    let mut comp_count = 0usize;
    for comp in rel.components() {
        match comp {
            Component::Normal(os) => {
                comp_count += 1;
                let s = os.to_string_lossy();
                prop_assert!(!s.is_empty());
                prop_assert_ne!(s.as_ref(), ".");
                prop_assert_ne!(s.as_ref(), "..");
            }
            other => {
                prop_assert!(false, "unexpected non-normal component: {:?}", other);
            }
        }
    }
    prop_assert!(comp_count >= 1);

    for seg in norm.split('/') {
        prop_assert!(!seg.is_empty());
        prop_assert_ne!(seg, ".");
        prop_assert_ne!(seg, "..");
        if check_win_rules {
            prop_assert!(
                !seg.chars()
                    .any(|c| matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|')
                        || (c as u32) <= 0x1F),
                "illegal Windows char remained in segment {seg:?}"
            );
            prop_assert!(
                !seg.ends_with('.') && !seg.ends_with(' '),
                "trailing dot/space remained in segment {seg:?}"
            );
            prop_assert!(
                !is_windows_reserved_stem(seg),
                "Windows reserved device name remained in segment {seg:?}"
            );
        }
    }

    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn sanitize_entry_path_always_enforces_invariants_windows_compat(raw in adversarial_path_strategy()) {
        if let Ok(sanitized) = sanitize_entry_path(&raw, PathPolicy::WindowsCompat) {
            assert_common_sanitized_invariants(&sanitized, true)?;
        }
    }

    #[test]
    fn sanitize_entry_path_always_enforces_invariants_native(raw in adversarial_path_strategy()) {
        if let Ok(sanitized) = sanitize_entry_path(&raw, PathPolicy::Native) {
            assert_common_sanitized_invariants(&sanitized, cfg!(windows))?;
        }
    }

    #[test]
    fn sanitize_entry_path_handles_arbitrary_unicode(raw in ".*") {
        if let Ok(sanitized) = sanitize_entry_path(&raw, PathPolicy::WindowsCompat) {
            assert_common_sanitized_invariants(&sanitized, true)?;
        }
    }

    #[test]
    fn normalize_for_pack_is_nfc_and_idempotent(raw in prop_oneof![adversarial_path_strategy(), ".*"]) {
        let once = normalize_for_pack(&raw);
        let twice = normalize_for_pack(&once);

        prop_assert_eq!(&once, &twice, "normalize_for_pack must be idempotent");
        prop_assert_eq!(&once, &once.nfc().collect::<String>(), "must be strict NFC");
        prop_assert!(!once.contains('\\'), "must convert all backslashes to POSIX /");
        prop_assert!(!once.starts_with('/'), "must strip leading /");
        prop_assert!(!once.starts_with("./"), "must strip leading ./");
        prop_assert!(!once.contains("//"), "must collapse duplicate slashes");
    }

    #[test]
    fn raw_zip_header_parser_never_panics_on_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..=4096)) {
        let _ = parse_zip_raw_headers_from_bytes(&data, 1024);
    }

    #[test]
    fn raw_zip_header_parser_never_panics_on_mutated_valid_zip(
        mutations in prop::collection::vec((any::<usize>(), any::<u8>()), 1..=24),
        truncate_pct in 0u8..=100u8,
    ) {
        let corpus_zip = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/corpus/macos_nfd.zip");
        let mut bytes = fs::read(corpus_zip).unwrap();
        let len = bytes.len();
        for (idx, val) in mutations {
            if len > 0 {
                bytes[idx % len] = val;
            }
        }
        let new_len = (len * truncate_pct as usize) / 100;
        bytes.truncate(new_len);

        let _ = parse_zip_raw_headers_from_bytes(&bytes, 1024);
    }
}

#[test]
fn inspect_zip_never_panics_on_mutated_buffers_on_disk() {
    let corpus_zip =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/legacy_cp949.zip");
    let base = fs::read(corpus_zip).unwrap();
    let tmp = TempDir::new().unwrap();

    let opts = InspectOptions {
        budget: SafetyBudget::new(1024 * 1024, 256, 100.0, 64 * 1024),
        ..InspectOptions::default()
    };

    // Test systematic truncations and single-byte flips across the whole archive.
    for cut in [
        0,
        1,
        4,
        21,
        22,
        base.len() / 3,
        base.len() / 2,
        base.len() - 1,
    ] {
        let p = tmp.path().join(format!("trunc_{cut}.zip"));
        fs::write(&p, &base[..cut.min(base.len())]).unwrap();
        let _ = inspect(&p, &opts);
    }
    for pos in (0..base.len()).step_by(7) {
        let mut mutated = base.clone();
        mutated[pos] ^= 0xFF;
        let p = tmp.path().join(format!("flip_{pos}.zip"));
        fs::write(&p, &mutated).unwrap();
        let _ = inspect(&p, &opts);
    }
}
