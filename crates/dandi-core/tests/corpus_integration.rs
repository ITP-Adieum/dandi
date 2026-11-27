use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;

use dandi_core::{
    inspect, unpack, EncodingId, EntryKind, InspectOptions, NoopProgressObserver, UnpackOptions,
};
use tempfile::TempDir;
use unicode_normalization::UnicodeNormalization;

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus")
}

#[test]
fn corpus_total_size_stays_tiny() {
    let mut total = 0u64;
    let mut count = 0usize;
    for entry in fs::read_dir(corpus_dir()).unwrap() {
        let entry = entry.unwrap();
        let meta = entry.metadata().unwrap();
        if meta.is_file() {
            total += meta.len();
            count += 1;
        }
    }
    assert!(
        count >= 5,
        "expected at least 5 corpus archives, got {count}"
    );
    assert!(
        total < 20 * 1024,
        "corpus must stay tiny (< 20 KiB), got {total} bytes"
    );
}

#[test]
fn corpus_macos_nfd_normalizes_to_nfc_on_inspect_and_unpack() {
    let archive = corpus_dir().join("macos_nfd.zip");
    let summary = inspect(&archive, &InspectOptions::default()).unwrap();

    let paths: HashSet<&str> = summary.entries.iter().map(|e| e.path.as_str()).collect();
    for expected in [
        "nfd_bundle/가나다_보고서.txt",
        "nfd_bundle/がぎぐ_メモ.txt",
        "nfd_bundle/café_résumé.txt",
    ] {
        assert!(
            paths.contains(expected),
            "expected NFC path '{expected}' in {paths:?}"
        );
        assert_eq!(expected, expected.nfc().collect::<String>());
    }

    let tmp = TempDir::new().unwrap();
    let report = unpack(
        &archive,
        tmp.path(),
        &UnpackOptions::default(),
        &NoopProgressObserver,
    )
    .unwrap();
    assert_eq!(report.files_extracted, 3);
    assert!(report.warnings.is_empty());
    assert_eq!(
        fs::read(tmp.path().join("nfd_bundle/가나다_보고서.txt")).unwrap(),
        b"korean nfd fixture"
    );
    assert_eq!(
        fs::read(tmp.path().join("nfd_bundle/がぎぐ_メモ.txt")).unwrap(),
        b"japanese nfd fixture"
    );
    assert_eq!(
        fs::read(tmp.path().join("nfd_bundle/café_résumé.txt")).unwrap(),
        b"latin nfd fixture"
    );
}

#[test]
fn corpus_legacy_cp949_auto_detects_and_unpacks() {
    let archive = corpus_dir().join("legacy_cp949.zip");
    let summary = inspect(&archive, &InspectOptions::default()).unwrap();
    assert_eq!(summary.applied_encoding, EncodingId::Cp949);

    let tmp = TempDir::new().unwrap();
    let report = unpack(
        &archive,
        tmp.path(),
        &UnpackOptions::default(),
        &NoopProgressObserver,
    )
    .unwrap();
    assert_eq!(report.applied_encoding, EncodingId::Cp949);
    assert_eq!(report.files_extracted, 3);
    assert_eq!(
        fs::read(tmp.path().join("프로젝트/보고서_최종.txt")).unwrap(),
        b"cp949 corpus 1"
    );
    assert_eq!(
        fs::read(tmp.path().join("프로젝트/가나다라_회의록.md")).unwrap(),
        b"cp949 corpus 2"
    );
    assert_eq!(
        fs::read(tmp.path().join("프로젝트/단디_테스트.csv")).unwrap(),
        b"cp949 corpus 3"
    );
}

#[test]
fn corpus_legacy_shift_jis_5c_preserves_trailing_5c_files() {
    let archive = corpus_dir().join("legacy_shift_jis_5c.zip");
    let summary = inspect(&archive, &InspectOptions::default()).unwrap();
    assert_eq!(summary.applied_encoding, EncodingId::ShiftJis);

    for expected in ["日本語/一覧表.txt", "日本語/機能", "日本語/ソ"] {
        let entry = summary
            .entries
            .iter()
            .find(|e| e.path == expected)
            .unwrap_or_else(|| panic!("missing Shift_JIS entry {expected}"));
        assert_eq!(
            entry.kind,
            EntryKind::File,
            "trailing-0x5C entry {expected} must remain a File"
        );
    }

    let tmp = TempDir::new().unwrap();
    let report = unpack(
        &archive,
        tmp.path(),
        &UnpackOptions::default(),
        &NoopProgressObserver,
    )
    .unwrap();
    assert_eq!(report.files_extracted, 3);
    assert_eq!(
        fs::read(tmp.path().join("日本語/一覧表.txt")).unwrap(),
        b"sjis corpus 1"
    );
    assert_eq!(
        fs::read(tmp.path().join("日本語/機能")).unwrap(),
        b"sjis corpus trailing 5c nou"
    );
    assert_eq!(
        fs::read(tmp.path().join("日本語/ソ")).unwrap(),
        b"sjis corpus trailing 5c so"
    );
}

#[test]
fn corpus_implicit_dirs_synthesized_and_unpacked() {
    let archive = corpus_dir().join("implicit_dirs.zip");
    let summary = inspect(&archive, &InspectOptions::default()).unwrap();

    let synth: HashSet<&str> = summary
        .entries
        .iter()
        .filter(|e| e.is_synthesized && e.kind == EntryKind::Directory)
        .map(|e| e.path.as_str())
        .collect();
    assert!(synth.contains("alpha/"), "got {synth:?}");
    assert!(synth.contains("alpha/beta/"), "got {synth:?}");
    assert!(synth.contains("gamma/"), "got {synth:?}");

    let tmp = TempDir::new().unwrap();
    let report = unpack(
        &archive,
        tmp.path(),
        &UnpackOptions::default(),
        &NoopProgressObserver,
    )
    .unwrap();
    assert_eq!(report.files_extracted, 2);
    assert_eq!(
        fs::read(tmp.path().join("implicit_dirs/alpha/beta/leaf.txt")).unwrap(),
        b"implicit leaf payload"
    );
    assert_eq!(
        fs::read(tmp.path().join("implicit_dirs/gamma/item.txt")).unwrap(),
        b"implicit gamma payload"
    );
}

#[test]
fn corpus_extra_7075_honors_valid_and_ignores_tampered() {
    let archive = corpus_dir().join("extra_7075_valid_and_tampered.zip");
    let summary = inspect(&archive, &InspectOptions::default()).unwrap();
    assert_eq!(summary.applied_encoding, EncodingId::Cp949);

    let paths: HashSet<&str> = summary.entries.iter().map(|e| e.path.as_str()).collect();
    assert!(paths.contains("정상_유니코드_경로.txt"), "got {paths:?}");
    assert!(paths.contains("변조_회의록_문서.txt"), "got {paths:?}");
    assert!(
        !paths.contains("위조_경로.txt"),
        "tampered 0x7075 must not be trusted: {paths:?}"
    );

    let tmp = TempDir::new().unwrap();
    let report = unpack(
        &archive,
        tmp.path(),
        &UnpackOptions::default(),
        &NoopProgressObserver,
    )
    .unwrap();
    assert_eq!(report.files_extracted, 2);
    let out = &report.output_dir;
    assert_eq!(
        fs::read(out.join("정상_유니코드_경로.txt")).unwrap(),
        b"valid 7075 payload"
    );
    assert_eq!(
        fs::read(out.join("변조_회의록_문서.txt")).unwrap(),
        b"tampered 7075 payload"
    );
}
