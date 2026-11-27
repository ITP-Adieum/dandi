use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use dandi_core::{
    pack, unpack, DandiError, ExtractMode, NoopProgressObserver, PackOptions, UnpackOptions,
    UnpackWarning,
};
use flate2::write::GzEncoder;
use flate2::Compression;
use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
use tempfile::TempDir;

fn write_tar_gz(path: &Path, files: &[(&str, &[u8])]) {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (name, data) in files {
            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(data.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_mtime(1_735_689_600);
            hdr.set_cksum();
            builder.append_data(&mut hdr, name, *data).unwrap();
        }
        builder.finish().unwrap();
    }
    let file = File::create(path).unwrap();
    let mut enc = GzEncoder::new(file, Compression::default());
    enc.write_all(&tar_bytes).unwrap();
    enc.finish().unwrap();
}

fn write_7z(path: &Path, files: &[(&str, &[u8])]) {
    let mut writer = ArchiveWriter::create(path).unwrap();
    for (name, data) in files {
        writer
            .push_archive_entry(ArchiveEntry::new_file(name), Some(*data))
            .unwrap();
    }
    writer.finish().unwrap();
}

fn assert_direct_overwrite_policy(archive_path: &Path, rel_file: &str, new_bytes: &[u8]) {
    let tmp = TempDir::new().unwrap();
    let dest = tmp.path().join("dest");
    let target = dest.join(rel_file);
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    let original_bytes = b"ORIGINAL_DO_NOT_CLOBBER";
    fs::write(&target, original_bytes).unwrap();

    // 1. Direct + overwrite: false MUST return AlreadyExists and leave original file intact.
    let err = unpack(
        archive_path,
        &dest,
        &UnpackOptions {
            mode: ExtractMode::Direct,
            overwrite: false,
            ..UnpackOptions::default()
        },
        &NoopProgressObserver,
    );
    assert!(
        matches!(err, Err(DandiError::AlreadyExists { .. })),
        "expected AlreadyExists for {} with overwrite=false, got {err:?}",
        archive_path.display()
    );
    assert_eq!(
        fs::read(&target).unwrap(),
        original_bytes,
        "existing file contents were modified when overwrite=false for {}",
        archive_path.display()
    );

    // 2. Direct + overwrite: true MUST succeed and replace file contents cleanly.
    let report = unpack(
        archive_path,
        &dest,
        &UnpackOptions {
            mode: ExtractMode::Direct,
            overwrite: true,
            ..UnpackOptions::default()
        },
        &NoopProgressObserver,
    )
    .unwrap();
    assert_eq!(report.files_extracted, 1);
    assert!(report.warnings.is_empty());
    assert_eq!(fs::read(&target).unwrap(), new_bytes);
}

#[test]
fn direct_mode_enforces_overwrite_false_across_zip_tar_and_7z() {
    let tmp = TempDir::new().unwrap();
    let new_bytes = b"NEW_ARCHIVE_CONTENT";

    // ZIP
    let src_dir = tmp.path().join("pkg");
    fs::create_dir_all(&src_dir).unwrap();
    fs::write(src_dir.join("note.txt"), new_bytes).unwrap();
    let zip_path = tmp.path().join("sample.zip");
    pack(
        &[src_dir],
        &zip_path,
        &PackOptions::default(),
        &NoopProgressObserver,
    )
    .unwrap();
    assert_direct_overwrite_policy(&zip_path, "pkg/note.txt", new_bytes);

    // TAR (.tar.gz)
    let tar_path = tmp.path().join("sample.tar.gz");
    write_tar_gz(&tar_path, &[("pkg/note.txt", new_bytes)]);
    assert_direct_overwrite_policy(&tar_path, "pkg/note.txt", new_bytes);

    // 7z
    let sevenz_path = tmp.path().join("sample.7z");
    write_7z(&sevenz_path, &[("pkg/note.txt", new_bytes)]);
    assert_direct_overwrite_policy(&sevenz_path, "pkg/note.txt", new_bytes);
}

#[cfg(unix)]
#[test]
fn direct_mode_enforces_overwrite_false_for_symlinks_in_zip_and_tar() {
    use std::os::unix::fs::symlink;

    let tmp = TempDir::new().unwrap();

    // Build ZIP containing a regular file and a safe relative symlink
    let src = tmp.path().join("bundle");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("target.txt"), b"target-data").unwrap();
    symlink("target.txt", src.join("link.txt")).unwrap();
    let zip_path = tmp.path().join("sym.zip");
    pack(
        &[src],
        &zip_path,
        &PackOptions::default(),
        &NoopProgressObserver,
    )
    .unwrap();

    // Build TAR containing the same regular file and safe relative symlink
    let tar_path = tmp.path().join("sym.tar.gz");
    {
        let mut tar_bytes = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_bytes);
            let mut h1 = tar::Header::new_gnu();
            h1.set_entry_type(tar::EntryType::Regular);
            h1.set_size(11);
            h1.set_mode(0o644);
            h1.set_mtime(1_735_689_600);
            h1.set_cksum();
            builder
                .append_data(&mut h1, "bundle/target.txt", &b"target-data"[..])
                .unwrap();

            let mut h2 = tar::Header::new_gnu();
            h2.set_entry_type(tar::EntryType::Symlink);
            h2.set_size(0);
            h2.set_mode(0o777);
            h2.set_mtime(1_735_689_600);
            h2.set_cksum();
            builder
                .append_link(&mut h2, "bundle/link.txt", "target.txt")
                .unwrap();
            builder.finish().unwrap();
        }
        let file = File::create(&tar_path).unwrap();
        let mut enc = GzEncoder::new(file, Compression::default());
        enc.write_all(&tar_bytes).unwrap();
        enc.finish().unwrap();
    }

    for archive in [&zip_path, &tar_path] {
        let dest = tmp.path().join(format!(
            "dest_{}",
            archive.file_name().unwrap().to_string_lossy()
        ));
        fs::create_dir_all(dest.join("bundle")).unwrap();
        // Pre-plant a regular file where the symlink wants to go
        fs::write(dest.join("bundle/link.txt"), b"KEEP_ME").unwrap();

        let res = unpack(
            archive,
            &dest,
            &UnpackOptions {
                mode: ExtractMode::Direct,
                overwrite: false,
                ..UnpackOptions::default()
            },
            &NoopProgressObserver,
        );
        assert!(
            matches!(res, Err(DandiError::AlreadyExists { .. })),
            "expected AlreadyExists for symlink collision in {}, got {res:?}",
            archive.display()
        );
        assert_eq!(fs::read(dest.join("bundle/link.txt")).unwrap(), b"KEEP_ME");

        // With overwrite: true, symlink replaces pre-existing file cleanly
        let report = unpack(
            archive,
            &dest,
            &UnpackOptions {
                mode: ExtractMode::Direct,
                overwrite: true,
                ..UnpackOptions::default()
            },
            &NoopProgressObserver,
        )
        .unwrap();
        assert_eq!(report.symlinks_created, 1);
        assert_eq!(report.symlinks_skipped, 0);
        assert!(fs::symlink_metadata(dest.join("bundle/link.txt"))
            .unwrap()
            .file_type()
            .is_symlink());

        // Second unpack onto an EXISTING symlink:
        // Remove target.txt so Phase 1 succeeds and Phase 2 specifically tests existing-symlink leaf behavior.
        fs::remove_file(dest.join("bundle/target.txt")).unwrap();
        let res_existing_sym = unpack(
            archive,
            &dest,
            &UnpackOptions {
                mode: ExtractMode::Direct,
                overwrite: false,
                ..UnpackOptions::default()
            },
            &NoopProgressObserver,
        );
        assert!(
            matches!(res_existing_sym, Err(DandiError::AlreadyExists { .. })),
            "expected AlreadyExists (not UnsafeSymlink) onto existing symlink in {}, got {res_existing_sym:?}",
            archive.display()
        );
        assert!(fs::symlink_metadata(dest.join("bundle/link.txt"))
            .unwrap()
            .file_type()
            .is_symlink());

        // With overwrite: true, re-unpacking onto an existing symlink succeeds cleanly.
        let report2 = unpack(
            archive,
            &dest,
            &UnpackOptions {
                mode: ExtractMode::Direct,
                overwrite: true,
                ..UnpackOptions::default()
            },
            &NoopProgressObserver,
        )
        .unwrap();
        assert_eq!(report2.symlinks_created, 1);
        assert_eq!(report2.symlinks_skipped, 0);
        assert!(fs::symlink_metadata(dest.join("bundle/link.txt"))
            .unwrap()
            .file_type()
            .is_symlink());
    }
}

#[test]
fn unpack_warning_variants_serialize_cleanly() {
    let warnings = vec![
        UnpackWarning::SymlinkSkipped {
            path: "a/link".to_string(),
            target: "../b".to_string(),
            reason: "privilege not held".to_string(),
        },
        UnpackWarning::PermissionApplyFailed {
            path: "a/file.sh".to_string(),
            reason: "operation not permitted".to_string(),
        },
        UnpackWarning::MtimeApplyFailed {
            path: "a/file.txt".to_string(),
            reason: "read-only filesystem".to_string(),
        },
        UnpackWarning::ZoneIdPropagateFailed {
            path: "a/file.exe".to_string(),
            reason: "ADS unsupported".to_string(),
        },
    ];

    let json = serde_json::to_string(&warnings).unwrap();
    let roundtrip: Vec<UnpackWarning> = serde_json::from_str(&json).unwrap();
    assert_eq!(warnings, roundtrip);
    assert!(json.contains("\"kind\":\"symlink_skipped\""));
    assert!(json.contains("\"kind\":\"permission_apply_failed\""));
    assert!(json.contains("\"kind\":\"mtime_apply_failed\""));
    assert!(json.contains("\"kind\":\"zone_id_propagate_failed\""));
}
