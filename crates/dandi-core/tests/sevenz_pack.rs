use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use dandi_core::{
    inspect, pack, unpack, CancellationToken, DandiError, EntryKind, ExtractMode, InspectOptions,
    NoopProgressObserver, PackFormat, PackOptions, PackReport, ProgressEvent, ProgressObserver,
    ProgressPhase, SafetyBudget, SplitStyle, UnpackOptions, MIN_SPLIT_SIZE_BYTES,
};
use sevenz_rust2::{ArchiveEntry, ArchiveReader, ArchiveWriter, Password};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use unicode_normalization::UnicodeNormalization;

const KOREAN_PW: &str = "단디-7z!2026";

fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

fn hash_tree(root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(root).sort_by_file_name() {
        let entry = entry.unwrap();
        if entry.file_type().is_file() {
            let rel = entry
                .path()
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let digest = Sha256::digest(fs::read(entry.path()).unwrap());
            out.push((rel.nfc().collect(), format!("{digest:x}")));
        }
    }
    out
}

/// `docs/` with NFD names, compressible text, incompressible media and OS junk.
fn make_tree(root: &Path) -> PathBuf {
    let docs = root.join("docs");
    let hangul_dir: String = "보고서".nfd().collect();
    let kana_file: String = "がぎぐ_ぱぴぷ.txt".nfd().collect();
    let accent_file: String = "café_über.md".nfd().collect();
    fs::create_dir_all(docs.join(&hangul_dir)).unwrap();
    fs::write(
        docs.join(&hangul_dir).join(&kana_file),
        "日本語".repeat(500),
    )
    .unwrap();
    fs::write(docs.join(&accent_file), "accents ".repeat(2000)).unwrap();
    fs::write(docs.join("photo.jpg"), pseudo_random(200_000, 3)).unwrap();
    fs::write(docs.join("empty.txt"), b"").unwrap();
    fs::write(docs.join(".DS_Store"), b"junk").unwrap();
    fs::write(docs.join("._photo.jpg"), b"appledouble").unwrap();
    fs::write(docs.join("Icon\r"), b"icon").unwrap();
    docs
}

fn pack_7z(input: &Path, out: &Path, password: Option<&str>, split: Option<u64>) -> PackReport {
    pack(
        &[input.to_path_buf()],
        out,
        &PackOptions {
            format: PackFormat::SevenZ,
            password: password.map(str::to_string),
            split_size_bytes: split,
            ..PackOptions::default()
        },
        &NoopProgressObserver,
    )
    .unwrap()
}

fn unpack_opts(password: Option<&str>) -> UnpackOptions {
    UnpackOptions {
        mode: ExtractMode::Direct,
        password: password.map(str::to_string),
        ..UnpackOptions::default()
    }
}

fn expected_without_junk(docs: &Path) -> Vec<(String, String)> {
    hash_tree(docs)
        .into_iter()
        .filter(|(p, _)| !p.contains(".DS_Store") && !p.contains("._") && !p.contains("Icon\r"))
        .collect()
}

#[test]
fn pack_7z_writes_nfc_names_and_skips_os_junk() {
    let tmp = TempDir::new().unwrap();
    let docs = make_tree(&tmp.path().join("src"));
    let out = tmp.path().join("docs.7z");
    let report = pack_7z(&docs, &out, None, None);
    assert_eq!(report.output_volumes, vec![out.clone()]);
    assert_eq!(report.junk_skipped, 3);
    assert!(!report.encrypted);

    // Read back with sevenz-rust2 directly rather than through Dandi's reader.
    let reader = ArchiveReader::open(&out, Password::empty()).unwrap();
    let names: Vec<String> = reader
        .archive()
        .files
        .iter()
        .map(|f| f.name().to_string())
        .collect();
    for name in &names {
        let nfc: String = name.nfc().collect();
        assert_eq!(name, &nfc, "entry name is not NFC");
        assert!(!name.contains('\\'));
        assert!(!name.contains(".DS_Store") && !name.contains("._") && !name.contains("Icon\r"));
    }
    assert!(names.iter().any(|n| n == "docs/보고서/がぎぐ_ぱぴぷ.txt"));

    let dest = tmp.path().join("x");
    unpack(&out, &dest, &unpack_opts(None), &NoopProgressObserver).unwrap();
    assert_eq!(hash_tree(&dest.join("docs")), expected_without_junk(&docs));
}

#[test]
fn aes_7z_round_trips_with_korean_password_and_encrypts_names() {
    let tmp = TempDir::new().unwrap();
    let docs = make_tree(&tmp.path().join("src"));
    let out = tmp.path().join("secret.7z");
    let report = pack_7z(&docs, &out, Some(KOREAN_PW), None);
    assert!(report.encrypted);

    // Encrypted header: even the file list needs the password.
    assert!(matches!(
        ArchiveReader::open(&out, Password::empty()),
        Err(sevenz_rust2::Error::PasswordRequired)
    ));
    let raw = fs::read(&out).unwrap();
    assert!(
        !raw.windows("보고서".len())
            .any(|w| w == "보고서".as_bytes()),
        "file names leaked in plaintext"
    );

    let no_pw = inspect(&out, &InspectOptions::default());
    assert!(
        matches!(no_pw, Err(DandiError::PasswordRequired)),
        "{no_pw:?}"
    );
    let bad_inspect = inspect(
        &out,
        &InspectOptions {
            password: Some("wrong".to_string()),
            ..InspectOptions::default()
        },
    );
    assert!(
        matches!(bad_inspect, Err(DandiError::InvalidPassword)),
        "{bad_inspect:?}"
    );

    let bad_dest = tmp.path().join("bad");
    let bad = unpack(
        &out,
        &bad_dest,
        &unpack_opts(Some("wrong")),
        &NoopProgressObserver,
    );
    assert!(matches!(bad, Err(DandiError::InvalidPassword)), "{bad:?}");
    assert!(!bad_dest.exists());

    let summary = inspect(
        &out,
        &InspectOptions {
            password: Some(KOREAN_PW.to_string()),
            ..InspectOptions::default()
        },
    )
    .unwrap();
    assert!(summary.encrypted);

    // The password is NFC-normalized on both sides, so an NFD-typed password still works.
    let nfd_pw: String = KOREAN_PW.nfd().collect();
    let dest = tmp.path().join("ok");
    unpack(
        &out,
        &dest,
        &unpack_opts(Some(&nfd_pw)),
        &NoopProgressObserver,
    )
    .unwrap();
    assert_eq!(hash_tree(&dest.join("docs")), expected_without_junk(&docs));
}

#[test]
fn split_7z_uses_numeric_volumes_and_round_trips() {
    let tmp = TempDir::new().unwrap();
    let docs = make_tree(&tmp.path().join("src"));
    let out = tmp.path().join("vol.7z");
    // `PkwareZip` is the default style; 7z has no PKWARE layout and always splits numerically.
    let report = pack(
        std::slice::from_ref(&docs),
        &out,
        &PackOptions {
            format: PackFormat::SevenZ,
            password: Some(KOREAN_PW.to_string()),
            split_size_bytes: Some(MIN_SPLIT_SIZE_BYTES),
            split_style: SplitStyle::PkwareZip,
            ..PackOptions::default()
        },
        &NoopProgressObserver,
    )
    .unwrap();
    assert!(report.output_volumes.len() >= 3);
    for (i, vol) in report.output_volumes.iter().enumerate() {
        assert_eq!(
            vol.file_name().unwrap().to_string_lossy(),
            format!("vol.7z.{:03}", i + 1)
        );
    }
    assert!(!out.exists());

    let dest = tmp.path().join("x");
    unpack(
        &report.output_volumes[1],
        &dest,
        &unpack_opts(Some(KOREAN_PW)),
        &NoopProgressObserver,
    )
    .unwrap();
    assert_eq!(hash_tree(&dest.join("docs")), expected_without_junk(&docs));

    fs::remove_file(&report.output_volumes[1]).unwrap();
    match inspect(
        &report.output_volumes[0],
        &InspectOptions {
            password: Some(KOREAN_PW.to_string()),
            ..InspectOptions::default()
        },
    ) {
        Err(DandiError::CorruptArchive(msg)) => assert!(msg.contains("vol.7z.002"), "{msg}"),
        other => panic!("expected missing-volume error, got {other:?}"),
    }
}

#[cfg(unix)]
#[test]
fn pack_7z_keeps_exec_bits_and_relative_symlinks() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let tmp = TempDir::new().unwrap();
    let app = tmp.path().join("src/Tool.app");
    fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
    let bin = app.join("Contents/MacOS/tool");
    fs::write(&bin, b"#!/bin/sh\necho hi\n").unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    symlink("MacOS/tool", app.join("Contents/launcher")).unwrap();

    let out = tmp.path().join("app.7z");
    pack_7z(&app, &out, None, None);
    let summary = inspect(&out, &InspectOptions::default()).unwrap();
    let link = summary
        .entries
        .iter()
        .find(|e| e.path == "Tool.app/Contents/launcher")
        .unwrap();
    assert_eq!(link.kind, EntryKind::Symlink);

    let dest = tmp.path().join("x");
    let report = unpack(&out, &dest, &unpack_opts(None), &NoopProgressObserver).unwrap();
    assert_eq!(report.symlinks_created, 1, "{report:?}");
    let mode = fs::metadata(dest.join("Tool.app/Contents/MacOS/tool"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o111, 0o111, "exec bits lost: {mode:o}");
    let link_path = dest.join("Tool.app/Contents/launcher");
    assert_eq!(
        fs::read_link(&link_path).unwrap(),
        PathBuf::from("MacOS/tool")
    );
}

fn write_7z_with(path: &Path, entries: Vec<(ArchiveEntry, Option<Vec<u8>>)>) {
    let mut writer = ArchiveWriter::create(path).unwrap();
    writer.set_content_methods(vec![sevenz_rust2::EncoderMethod::COPY.into()]);
    for (entry, data) in entries {
        match data {
            Some(bytes) => writer
                .push_archive_entry(entry, Some(bytes.as_slice()))
                .unwrap(),
            None => writer.push_archive_entry::<&[u8]>(entry, None).unwrap(),
        };
    }
    writer.finish().unwrap();
}

#[test]
fn symlink_escaping_destination_is_rejected_before_any_write() {
    let tmp = TempDir::new().unwrap();
    let archive = tmp.path().join("evil.7z");
    let mut link = ArchiveEntry::new_file("bundle/out");
    link.has_windows_attributes = true;
    link.windows_attributes = 0x20 | 0x8000 | (0o120_777 << 16);
    write_7z_with(
        &archive,
        vec![
            (
                ArchiveEntry::new_file("bundle/first.txt"),
                Some(b"first".to_vec()),
            ),
            (link, Some(b"../../outside".to_vec())),
        ],
    );
    let dest = tmp.path().join("dest");
    fs::create_dir_all(&dest).unwrap();
    let err = unpack(&archive, &dest, &unpack_opts(None), &NoopProgressObserver).unwrap_err();
    assert!(matches!(err, DandiError::UnsafeSymlink { .. }), "{err:?}");
    assert!(!dest.join("bundle/first.txt").exists());
    assert!(!tmp.path().join("outside").exists());
}

#[test]
fn corrupt_entry_stops_extraction_and_leaves_no_partial_files() {
    let tmp = TempDir::new().unwrap();
    let archive = tmp.path().join("crc.7z");
    let marker = b"SECOND-ENTRY-PAYLOAD-0123456789".repeat(64);
    write_7z_with(
        &archive,
        vec![
            (
                ArchiveEntry::new_file("a_first.txt"),
                Some(b"first ok".to_vec()),
            ),
            (ArchiveEntry::new_file("b_second.txt"), Some(marker.clone())),
            (
                ArchiveEntry::new_file("c_third.txt"),
                Some(b"third ok".to_vec()),
            ),
        ],
    );
    let mut bytes = fs::read(&archive).unwrap();
    let at = bytes
        .windows(marker.len())
        .position(|w| w == marker.as_slice())
        .unwrap();
    bytes[at + 100] ^= 0xFF;
    fs::write(&archive, &bytes).unwrap();

    let dest = tmp.path().join("dest");
    fs::create_dir_all(&dest).unwrap();
    let err = unpack(&archive, &dest, &unpack_opts(None), &NoopProgressObserver).unwrap_err();
    assert!(
        matches!(err, DandiError::CorruptArchive(_) | DandiError::Io { .. }),
        "{err:?}"
    );
    assert!(!dest.join("b_second.txt").exists(), "partial file kept");
    assert!(
        !dest.join("c_third.txt").exists(),
        "extraction continued after error"
    );
}

#[test]
fn overwrite_false_and_budget_hold_for_7z() {
    let tmp = TempDir::new().unwrap();
    let docs = make_tree(&tmp.path().join("src"));
    let out = tmp.path().join("docs.7z");
    pack_7z(&docs, &out, None, None);

    let dest = tmp.path().join("x");
    unpack(&out, &dest, &unpack_opts(None), &NoopProgressObserver).unwrap();
    let photo = dest.join("docs/photo.jpg");
    fs::write(&photo, b"user edit").unwrap();
    let err = unpack(&out, &dest, &unpack_opts(None), &NoopProgressObserver).unwrap_err();
    assert!(matches!(err, DandiError::AlreadyExists { .. }), "{err:?}");
    assert_eq!(fs::read(&photo).unwrap(), b"user edit");

    let tight = UnpackOptions {
        budget: SafetyBudget::new(50_000, 10_000, 200.0, 10 * 1024 * 1024),
        ..unpack_opts(None)
    };
    let err = unpack(&out, &tmp.path().join("y"), &tight, &NoopProgressObserver).unwrap_err();
    assert!(matches!(err, DandiError::BudgetExceeded { .. }), "{err:?}");
    assert!(!tmp.path().join("y").exists());
}

struct CancelAfterFirstEntry(CancellationToken);

impl ProgressObserver for CancelAfterFirstEntry {
    fn on_progress(&self, event: &ProgressEvent) {
        if event.phase == ProgressPhase::Packing && event.entries_done >= 1 {
            self.0.cancel();
        }
    }
}

#[test]
fn cancelled_7z_pack_leaves_nothing_behind() {
    for split in [None, Some(MIN_SPLIT_SIZE_BYTES)] {
        let tmp = TempDir::new().unwrap();
        let docs = make_tree(&tmp.path().join("src"));
        let out_dir = tmp.path().join("out");
        fs::create_dir_all(&out_dir).unwrap();
        let token = CancellationToken::new();
        let err = pack(
            &[docs],
            &out_dir.join("c.7z"),
            &PackOptions {
                format: PackFormat::SevenZ,
                password: Some(KOREAN_PW.to_string()),
                split_size_bytes: split,
                cancel: token.clone(),
                ..PackOptions::default()
            },
            &CancelAfterFirstEntry(token),
        )
        .unwrap_err();
        assert!(matches!(err, DandiError::Cancelled), "{err:?}");
        let left: Vec<_> = fs::read_dir(&out_dir).unwrap().collect();
        assert!(left.is_empty(), "split={split:?} left {left:?}");
    }
}

/// libarchive (`bsdtar`) is an independent 7z reader: plain Dandi `.7z` output must open there.
#[test]
fn bsdtar_reads_plain_dandi_7z() {
    let Ok(probe) = Command::new("bsdtar").arg("--version").output() else {
        eprintln!("skipping: bsdtar not installed");
        return;
    };
    if !probe.status.success() {
        eprintln!("skipping: bsdtar not usable");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let docs = make_tree(&tmp.path().join("src"));
    let out = tmp.path().join("docs.7z");
    pack_7z(&docs, &out, None, None);
    let dest = tmp.path().join("bsd");
    fs::create_dir_all(&dest).unwrap();
    let status = Command::new("bsdtar")
        .arg("-xf")
        .arg(&out)
        .arg("-C")
        .arg(&dest)
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(hash_tree(&dest.join("docs")), expected_without_junk(&docs));
}

/// Directories and empty files are visited after all data blocks; selection must still pick
/// entries by their archive index.
#[test]
fn selective_7z_extraction_uses_archive_indices() {
    let tmp = TempDir::new().unwrap();
    let docs = make_tree(&tmp.path().join("src"));
    let out = tmp.path().join("docs.7z");
    pack_7z(&docs, &out, None, None);

    let summary = inspect(&out, &InspectOptions::default()).unwrap();
    let pick = |path: &str| {
        summary
            .entries
            .iter()
            .find(|e| e.path == path)
            .and_then(|e| e.index)
            .unwrap()
    };
    let wanted = [pick("docs/photo.jpg"), pick("docs/empty.txt")];
    let dest = tmp.path().join("x");
    unpack(
        &out,
        &dest,
        &UnpackOptions {
            selected_entries: Some(wanted.into_iter().collect()),
            ..unpack_opts(None)
        },
        &NoopProgressObserver,
    )
    .unwrap();
    let got: Vec<String> = hash_tree(&dest).into_iter().map(|(p, _)| p).collect();
    assert_eq!(got, vec!["docs/empty.txt", "docs/photo.jpg"]);
}
