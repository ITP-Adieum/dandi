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
