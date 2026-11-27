use std::fs;
use std::process::Command;

use tempfile::TempDir;

#[test]
fn cli_pack_inspect_list_unpack_fix_roundtrip() {
    let bin = env!("CARGO_BIN_EXE_dandi");
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("sample_proj");
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("가나다_문서.txt"), b"hello dandi cli").unwrap();
    fs::write(src.join("sub/second.txt"), b"second file").unwrap();
    fs::write(src.join(".DS_Store"), b"junk").unwrap();

    let zip_path = tmp.path().join("out.zip");
    let pack_out = Command::new(bin)
        .args(["pack", "--json", "-o"])
        .arg(&zip_path)
        .arg(&src)
        .output()
        .unwrap();
    assert!(
        pack_out.status.success(),
        "pack failed: {}",
        String::from_utf8_lossy(&pack_out.stderr)
    );
    let pack_json: serde_json::Value = serde_json::from_slice(&pack_out.stdout).unwrap();
    assert_eq!(pack_json["junk_skipped"].as_u64(), Some(1));

    let inspect_out = Command::new(bin)
        .args(["inspect", "--json"])
        .arg(&zip_path)
        .output()
        .unwrap();
    assert!(inspect_out.status.success());
    let inspect_json: serde_json::Value = serde_json::from_slice(&inspect_out.stdout).unwrap();
    assert_eq!(inspect_json["format"].as_str(), Some("zip"));

    let list_out = Command::new(bin)
        .args(["list"])
        .arg(&zip_path)
        .output()
        .unwrap();
    assert!(list_out.status.success());
    let list_str = String::from_utf8_lossy(&list_out.stdout);
    assert!(list_str.contains("가나다_문서.txt"));
    assert!(!list_str.contains(".DS_Store"));

    let dest = tmp.path().join("extracted");
    let unpack_out = Command::new(bin)
        .args(["unpack", "--json", "--mode", "smart", "-d"])
        .arg(&dest)
        .arg(&zip_path)
        .output()
        .unwrap();
    assert!(unpack_out.status.success());
    let unpack_json: serde_json::Value = serde_json::from_slice(&unpack_out.stdout).unwrap();
    assert_eq!(unpack_json["symlinks_skipped"].as_u64(), Some(0));
    assert_eq!(unpack_json["warnings"].as_array().map(Vec::len), Some(0));
    assert_eq!(
        fs::read(dest.join("sample_proj/가나다_문서.txt")).unwrap(),
        b"hello dandi cli"
    );

    // Direct mode without --overwrite MUST fail when file already exists
    let clash_out = Command::new(bin)
        .args(["unpack", "--mode", "direct", "-d"])
        .arg(&dest)
        .arg(&zip_path)
        .output()
        .unwrap();
    assert!(
        !clash_out.status.success(),
        "direct unpack without --overwrite should fail on existing files"
    );

    let fixed_zip = tmp.path().join("fixed.zip");
    let fix_out = Command::new(bin)
        .args(["fix", "--json", "-o"])
        .arg(&fixed_zip)
        .arg(&zip_path)
        .output()
        .unwrap();
    assert!(fix_out.status.success());
    assert!(fixed_zip.exists());
}

fn noise(len: usize, seed: u64) -> Vec<u8> {
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

fn run_json(args: &[&std::ffi::OsStr]) -> serde_json::Value {
    let out = Command::new(env!("CARGO_BIN_EXE_dandi"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn cli_split_and_7z_pack_round_trip() {
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("media");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("clip.jpg"), noise(200_000, 1)).unwrap();
    fs::write(src.join("메모.txt"), "단디".repeat(100)).unwrap();

    let os = |s: &str| std::ffi::OsString::from(s);
    let zip_path = tmp.path().join("media.zip");
    let report = run_json(&[
        &os("pack"),
        &os("--json"),
        &os("--split"),
        &os("64K"),
        &os("-o"),
        zip_path.as_os_str(),
        src.as_os_str(),
    ]);
    let volumes = report["output_volumes"].as_array().unwrap();
    assert!(volumes.len() >= 3, "{report}");
    assert!(volumes[0].as_str().unwrap().ends_with("media.z01"));
    assert!(volumes
        .last()
        .unwrap()
        .as_str()
        .unwrap()
        .ends_with("media.zip"));

    let z01 = tmp.path().join("media.z01");
    let listing = run_json(&[&os("list"), &os("--json"), z01.as_os_str()]);
    assert!(listing
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["path"] == "media/메모.txt"));

    let sz_path = tmp.path().join("media.7z");
    let report = run_json(&[
        &os("pack"),
        &os("--json"),
        &os("--format"),
        &os("7z"),
        &os("--split"),
        &os("64K"),
        &os("--password"),
        &os("단디-7z!2026"),
        &os("-o"),
        sz_path.as_os_str(),
        src.as_os_str(),
    ]);
    assert_eq!(report["encrypted"], true);
    let first = report["output_path"].as_str().unwrap().to_string();
    assert!(first.ends_with("media.7z.001"), "{report}");

    let dest = tmp.path().join("out");
    let unpack = run_json(&[
        &os("unpack"),
        &os("--json"),
        &os("--password"),
        &os("단디-7z!2026"),
        &os("-d"),
        dest.as_os_str(),
        &os(&first),
    ]);
    assert_eq!(unpack["format"], "seven_z");
    assert_eq!(
        fs::read(dest.join("media/clip.jpg")).unwrap(),
        noise(200_000, 1)
    );

    let bad = Command::new(env!("CARGO_BIN_EXE_dandi"))
        .args(["pack", "--split", "10X", "-o"])
        .arg(tmp.path().join("bad.zip"))
        .arg(&src)
        .output()
        .unwrap();
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("invalid size"));
}
