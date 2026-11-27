use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::process::Command;

use dandi_core::platform::set_mtime;
use dandi_core::{pack, NoopProgressObserver, PackOptions};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use unicode_normalization::UnicodeNormalization;
use zip::{CompressionMethod, ZipArchive};

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    let mut out = String::with_capacity(64);
    for b in h.finalize() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn find_extra_field(extra: &[u8], id: u16) -> Option<&[u8]> {
    let mut pos = 0usize;
    while pos + 4 <= extra.len() {
        let field_id = u16::from_le_bytes([extra[pos], extra[pos + 1]]);
        let field_len = u16::from_le_bytes([extra[pos + 2], extra[pos + 3]]) as usize;
        let start = pos + 4;
        let end = start.checked_add(field_len)?;
        if end > extra.len() {
            return None;
        }
        if field_id == id {
            return Some(&extra[start..end]);
        }
        pos = end;
    }
    None
}

fn detect_python3() -> Option<&'static str> {
    for candidate in ["python3", "python"] {
        if let Ok(out) = Command::new(candidate)
            .args(["-c", "import sys, zipfile; print(sys.version_info[0])"])
            .output()
        {
            if out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "3" {
                return Some(candidate);
            }
        }
    }
    None
}

#[test]
fn dandi_packed_zip_verified_by_independent_zip_crate_and_python_zipfile() {
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("verify_bundle");
    fs::create_dir_all(src.join("bin")).unwrap();

    // Fixed UTC mtime: 2025-07-15 12:34:56 UTC
    let expected_ts: i64 = 1_752_582_896;

    // 1. Compressible NFC/NFD multilingual text file (should use Method 8 Deflate)
    let text_nfc = "가나다_보고서_café.txt";
    let text_nfd: String = text_nfc.nfd().collect();
    let text_payload = "Dandi independent verification payload line.\n"
        .repeat(200)
        .into_bytes();
    let text_path = src.join(&text_nfd);
    fs::write(&text_path, &text_payload).unwrap();
    set_mtime(&text_path, expected_ts, false).unwrap();

    // 2. Pre-compressed media file (should use Method 0 Store via Smart Store)
    let media_nfc = "がぎぐ_photo.jpg";
    let media_nfd: String = media_nfc.nfd().collect();
    let media_payload: Vec<u8> = (0..4096u32)
        .map(|i| ((i.wrapping_mul(2654435761)) >> 24) as u8)
        .collect();
    let media_path = src.join(&media_nfd);
    fs::write(&media_path, &media_payload).unwrap();
    set_mtime(&media_path, expected_ts, false).unwrap();

    // 3. Executable script (should preserve +x on Unix and non-zero Unix mode everywhere)
    let script_payload = b"#!/bin/sh\necho ok\n".to_vec();
    let script_path = src.join("bin/run.sh");
    fs::write(&script_path, &script_payload).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    set_mtime(&script_path, expected_ts, false).unwrap();

    // Plant OS junk that must not appear in output ZIP
    fs::write(src.join(".DS_Store"), b"junk").unwrap();

    let zip_path = tmp.path().join("golden.zip");
    let report = pack(
        &[src],
        &zip_path,
        &PackOptions::default(),
        &NoopProgressObserver,
    )
    .unwrap();
    assert_eq!(report.junk_skipped, 1);

    let mut expected_files: BTreeMap<String, (Vec<u8>, CompressionMethod)> = BTreeMap::new();
    expected_files.insert(
        format!("verify_bundle/{text_nfc}"),
        (text_payload.clone(), CompressionMethod::Deflated),
    );
    expected_files.insert(
        format!("verify_bundle/{media_nfc}"),
        (media_payload.clone(), CompressionMethod::Stored),
    );
    expected_files.insert(
        "verify_bundle/bin/run.sh".to_string(),
        (script_payload.clone(), CompressionMethod::Stored),
    );

    // --- Independent Verifier 1: `zip` crate (`zip::ZipArchive`) ---
    {
        let file = File::open(&zip_path).unwrap();
        let mut archive = ZipArchive::new(file).unwrap();
        let mut seen_files = BTreeMap::new();

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i).unwrap();
            let name = entry.name().unwrap().into_owned();

            // Strict NFC UTF-8 filename
            assert_eq!(name, name.nfc().collect::<String>(), "not NFC: {name:?}");
            assert!(!name.contains(".DS_Store"), "OS junk leaked: {name}");

            // Valid non-zero Unix mode bits
            let mode = entry
                .unix_mode()
                .unwrap_or_else(|| panic!("missing unix_mode for {name}"));
            assert_ne!(mode & 0o777, 0, "zero Unix permission bits on {name}");

            #[cfg(unix)]
            if name == "verify_bundle/bin/run.sh" {
                assert_ne!(mode & 0o111, 0, "lost +x on run.sh: mode={mode:o}");
            }

            // Extra fields: 0x5455 UTC present & matches expected_ts, NO redundant 0x7075
            let extra = entry.extra_data().unwrap_or_default();
            assert!(
                find_extra_field(&extra, 0x7075).is_none(),
                "redundant 0x7075 found on {name}"
            );
            let ts_field = find_extra_field(&extra, 0x5455)
                .unwrap_or_else(|| panic!("missing 0x5455 UTC extra on {name}"));
            assert!(ts_field.len() >= 5 && (ts_field[0] & 0x01) != 0);
            let ts =
                i32::from_le_bytes([ts_field[1], ts_field[2], ts_field[3], ts_field[4]]) as i64;

            if !entry.is_dir() {
                assert!(
                    (ts - expected_ts).abs() <= 2,
                    "0x5455 timestamp drift on {name}: expected {expected_ts}, got {ts}"
                );
                let mut content = Vec::new();
                entry.read_to_end(&mut content).unwrap();
                seen_files.insert(name, (content, entry.compression()));
            }
        }

        assert_eq!(seen_files.len(), expected_files.len());
        for (name, (exp_bytes, exp_method)) in &expected_files {
            let (got_bytes, got_method) = seen_files
                .get(name)
                .unwrap_or_else(|| panic!("zip crate missing {name}"));
            assert_eq!(got_bytes, exp_bytes, "content mismatch for {name}");
            // Note: tiny files (like run.sh) may be Stored when Deflate isn't smaller;
            // verify compressible text is Deflated and media .jpg is Stored.
            if name.ends_with(".txt") || name.ends_with(".jpg") {
                assert_eq!(
                    got_method, exp_method,
                    "unexpected compression method for {name}"
                );
            }
        }
    }

    // --- Independent Verifier 2: Python 3 `zipfile` ---
    if let Some(py) = detect_python3() {
        let expected_hashes_json = serde_json::to_string(
            &expected_files
                .iter()
                .map(|(k, (v, _))| (k.clone(), sha256_hex(v)))
                .collect::<BTreeMap<_, _>>(),
        )
        .unwrap();

        let py_script = r#"
import hashlib, json, struct, sys, unicodedata, zipfile

zip_path = sys.argv[1]
expected_ts = int(sys.argv[2])
expected_hashes = json.loads(sys.argv[3])
check_exec = sys.argv[4] == "1"

def parse_extra(extra):
    fields = {}
    pos = 0
    while pos + 4 <= len(extra):
        fid, flen = struct.unpack_from("<HH", extra, pos)
        pos += 4
        if pos + flen > len(extra):
            raise AssertionError(f"truncated extra field 0x{fid:04x}")
        fields[fid] = extra[pos:pos + flen]
        pos += flen
    return fields

seen = {}
with zipfile.ZipFile(zip_path, "r") as zf:
    for info in zf.infolist():
        # Bit 11 UTF-8 flag MUST be set
        assert (info.flag_bits & 0x0800) != 0, f"Bit 11 OFF on {info.filename}"
        # Filename MUST be strict NFC
        assert info.filename == unicodedata.normalize("NFC", info.filename), f"not NFC: {info.filename!r}"
        # Unix mode bits MUST be non-zero
        mode = (info.external_attr >> 16) & 0xFFFF
        assert (mode & 0o777) != 0, f"zero unix mode on {info.filename}"
        if check_exec and info.filename == "verify_bundle/bin/run.sh":
            assert (mode & 0o111) != 0, f"missing +x on {info.filename}: {oct(mode)}"
        # Extra fields: 0x5455 present, 0x7075 absent
        extra = parse_extra(info.extra)
        assert 0x7075 not in extra, f"redundant 0x7075 on {info.filename}"
        assert 0x5455 in extra, f"missing 0x5455 on {info.filename}"
        f5455 = extra[0x5455]
        assert len(f5455) >= 5 and (f5455[0] & 0x01) != 0
        ts = struct.unpack_from("<i", f5455, 1)[0]
        if not info.is_dir():
            assert abs(ts - expected_ts) <= 2, f"0x5455 drift on {info.filename}: {ts} vs {expected_ts}"
            if info.filename.endswith(".txt"):
                assert info.compress_type == zipfile.ZIP_DEFLATED, f"expected Deflate for {info.filename}"
            if info.filename.endswith(".jpg"):
                assert info.compress_type == zipfile.ZIP_STORED, f"expected Store for {info.filename}"
            data = zf.read(info.filename)
            seen[info.filename] = hashlib.sha256(data).hexdigest()

assert seen == expected_hashes, f"mismatch: {seen} != {expected_hashes}"
print("PYTHON_ZIPFILE_OK")
"#;

        let out = Command::new(py)
            .args([
                "-c",
                py_script,
                zip_path.to_str().unwrap(),
                &expected_ts.to_string(),
                &expected_hashes_json,
                if cfg!(unix) { "1" } else { "0" },
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "Python zipfile verification failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("PYTHON_ZIPFILE_OK"));
    }
}
