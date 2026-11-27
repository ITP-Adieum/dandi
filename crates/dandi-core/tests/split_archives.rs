use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use dandi_core::archive::inspect_zip_raw_headers;
use dandi_core::{
    inspect, pack, unpack, CancellationToken, DandiError, ExtractMode, InspectOptions,
    NoopProgressObserver, PackOptions, PackReport, ProgressEvent, ProgressObserver, ProgressPhase,
    SplitStyle, UnpackOptions, MIN_SPLIT_SIZE_BYTES,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const SPLIT: u64 = MIN_SPLIT_SIZE_BYTES;

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

/// Builds `root/bundle/...` with incompressible payloads so the archive spans several volumes.
fn make_tree(root: &Path, total_kib: usize) -> PathBuf {
    let bundle = root.join("bundle");
    fs::create_dir_all(bundle.join("nested/깊은")).unwrap();
    fs::write(bundle.join("readme.txt"), b"split archive smoke test\n").unwrap();
    fs::write(
        bundle.join("nested/한글_문서.txt"),
        "단디 분할 압축".as_bytes(),
    )
    .unwrap();
    fs::write(bundle.join("empty.dat"), b"").unwrap();
    let chunk = 90 * 1024;
    let mut written = 0usize;
    let mut i = 0u64;
    while written < total_kib * 1024 {
        let len = chunk.min(total_kib * 1024 - written);
        let name = if i.is_multiple_of(2) {
            format!("nested/깊은/blob_{i:03}.bin")
        } else {
            format!("photo_{i:03}.jpg")
        };
        fs::write(bundle.join(name), pseudo_random(len, 0x9E37_79B9 + i)).unwrap();
        written += len;
        i += 1;
    }
    bundle
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
            out.push((rel, format!("{digest:x}")));
        }
    }
    out
}

fn pack_split(
    input: &Path,
    out: &Path,
    style: SplitStyle,
    split: u64,
    password: Option<&str>,
) -> PackReport {
    pack(
        &[input.to_path_buf()],
        out,
        &PackOptions {
            split_size_bytes: Some(split),
            split_style: style,
            password: password.map(str::to_string),
            ..PackOptions::default()
        },
        &NoopProgressObserver,
    )
    .unwrap()
}

fn unpack_direct(archive: &Path, dest: &Path, password: Option<&str>) {
    unpack(
        archive,
        dest,
        &UnpackOptions {
            mode: ExtractMode::Direct,
            password: password.map(str::to_string),
            ..UnpackOptions::default()
        },
        &NoopProgressObserver,
    )
    .unwrap();
}

fn listed_paths(archive: &Path) -> Vec<String> {
    inspect(archive, &InspectOptions::default())
        .unwrap()
        .entries
        .into_iter()
        .map(|e| e.path)
        .collect()
}

fn dir_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn read_u16(buf: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([buf[at], buf[at + 1]])
}

#[test]
fn pkware_split_round_trips_from_any_volume() {
    let tmp = TempDir::new().unwrap();
    let bundle = make_tree(&tmp.path().join("src"), 600);
    let out_dir = tmp.path().join("out");
    let zip_path = out_dir.join("bundle.zip");

    let report = pack_split(&bundle, &zip_path, SplitStyle::PkwareZip, SPLIT, None);
    let volumes = &report.output_volumes;
    assert!(volumes.len() >= 9, "expected many volumes, got {volumes:?}");
    assert_eq!(report.output_path, zip_path);
    assert_eq!(volumes.last(), Some(&zip_path));
    for (i, vol) in volumes[..volumes.len() - 1].iter().enumerate() {
        assert_eq!(
            vol.file_name().unwrap().to_string_lossy(),
            format!("bundle.z{:02}", i + 1)
        );
        assert!(fs::metadata(vol).unwrap().len() <= SPLIT);
    }
    let total: u64 = volumes.iter().map(|v| fs::metadata(v).unwrap().len()).sum();
    assert_eq!(total, report.output_bytes);

    let expected = hash_tree(&bundle);
    let listing = listed_paths(&zip_path);
    for opener in [&volumes[0], &volumes[3], &zip_path] {
        assert_eq!(listed_paths(opener), listing, "listing via {opener:?}");
        let dest = tmp.path().join(format!(
            "x_{}",
            opener.file_name().unwrap().to_string_lossy()
        ));
        unpack_direct(opener, &dest, None);
        assert_eq!(hash_tree(&dest.join("bundle")), expected, "via {opener:?}");
    }
}

#[test]
fn pkware_split_layout_matches_appnote() {
    let tmp = TempDir::new().unwrap();
    let bundle = make_tree(&tmp.path().join("src"), 400);
    let zip_path = tmp.path().join("layout.zip");
    let report = pack_split(&bundle, &zip_path, SplitStyle::PkwareZip, SPLIT, None);
    let volumes = &report.output_volumes;
    let last_disk = (volumes.len() - 1) as u16;

    // Disk 0 begins with the split signature 0x08074b50.
    let mut sig = [0u8; 4];
    File::open(&volumes[0])
        .unwrap()
        .read_exact(&mut sig)
        .unwrap();
    assert_eq!(u32::from_le_bytes(sig), 0x0807_4b50);

    // EOCD on the final volume names the final disk and the disk holding the CD start.
    let tail = fs::read(&zip_path).unwrap();
    let eocd = tail.len() - 22;
    assert_eq!(&tail[eocd..eocd + 4], b"PK\x05\x06");
    assert_eq!(read_u16(&tail, eocd + 4), last_disk);
    let cd_disk = read_u16(&tail, eocd + 6);
    assert!(cd_disk <= last_disk);

    // Every CD record points at a local header on the disk and offset it declares.
    let headers = inspect_zip_raw_headers(&zip_path).unwrap();
    assert!(!headers.is_empty());
    let mut disks_used = std::collections::BTreeSet::new();
    for h in &headers {
        disks_used.insert(h.disk_number_start);
        let mut vol = File::open(&volumes[h.disk_number_start as usize]).unwrap();
        let vol_len = vol.metadata().unwrap().len();
        let mut fixed = [0u8; 30];
        vol.seek(SeekFrom::Start(h.local_header_offset)).unwrap();
        vol.read_exact(&mut fixed).unwrap();
        assert_eq!(&fixed[..4], b"PK\x03\x04", "LFH of entry {}", h.index);
        let header_len = 30 + read_u16(&fixed, 26) as u64 + read_u16(&fixed, 28) as u64;
        assert!(
            h.local_header_offset + header_len <= vol_len,
            "local header of entry {} straddles a volume boundary",
            h.index
        );
    }
    assert!(
        disks_used.len() > 1,
        "entries should start on several disks"
    );
}

#[test]
fn pkware_split_that_fits_one_volume_is_a_plain_zip() {
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("small");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"tiny").unwrap();
    let zip_path = tmp.path().join("small.zip");

    let report = pack_split(&src, &zip_path, SplitStyle::PkwareZip, 1 << 20, None);
    assert_eq!(report.output_volumes, vec![zip_path.clone()]);
    let bytes = fs::read(&zip_path).unwrap();
    assert_eq!(&bytes[..4], b"PK\x03\x04");
    assert_eq!(dir_names(tmp.path()), vec!["small", "small.zip"]);
    let dest = tmp.path().join("x");
    unpack_direct(&zip_path, &dest, None);
    assert_eq!(fs::read(dest.join("small/a.txt")).unwrap(), b"tiny");
}

#[test]
fn numeric_zip_split_round_trips_from_middle_part() {
    let tmp = TempDir::new().unwrap();
    let bundle = make_tree(&tmp.path().join("src"), 300);
    let zip_path = tmp.path().join("num.zip");
    let report = pack_split(&bundle, &zip_path, SplitStyle::Numeric, SPLIT, None);

    assert!(report.output_volumes.len() >= 4);
    for (i, vol) in report.output_volumes.iter().enumerate() {
        assert_eq!(
            vol.file_name().unwrap().to_string_lossy(),
            format!("num.zip.{:03}", i + 1)
        );
    }
    assert_eq!(report.output_path, report.output_volumes[0]);
    assert!(!zip_path.exists());

    let dest = tmp.path().join("x");
    unpack_direct(&report.output_volumes[1], &dest, None);
    assert_eq!(hash_tree(&dest.join("bundle")), hash_tree(&bundle));
}

#[test]
fn numeric_split_with_hundreds_of_volumes_keeps_handles_bounded() {
    // ~300 volumes: the old writer kept one descriptor per volume and hit the default
    // macOS limit of 256 open files.
    let tmp = TempDir::new().unwrap();
    let bundle = make_tree(&tmp.path().join("src"), 300 * 64);
    let zip_path = tmp.path().join("many.zip");
    let report = pack_split(&bundle, &zip_path, SplitStyle::Numeric, SPLIT, None);
    assert!(
        report.output_volumes.len() >= 290,
        "{}",
        report.output_volumes.len()
    );
    let dest = tmp.path().join("x");
    unpack_direct(&report.output_volumes[0], &dest, None);
    assert_eq!(hash_tree(&dest.join("bundle")), hash_tree(&bundle));
}

#[test]
fn missing_middle_volume_is_named_in_the_error() {
    let tmp = TempDir::new().unwrap();
    let bundle = make_tree(&tmp.path().join("src"), 300);

    let pk_dir = tmp.path().join("pk");
    let pk = pack_split(
        &bundle,
        &pk_dir.join("set.zip"),
        SplitStyle::PkwareZip,
        SPLIT,
        None,
    );
    fs::remove_file(&pk.output_volumes[1]).unwrap();
    for opener in [&pk.output_volumes[0], pk.output_volumes.last().unwrap()] {
        match inspect(opener, &InspectOptions::default()) {
            Err(DandiError::CorruptArchive(msg)) => assert!(msg.contains("set.z02"), "{msg}"),
            other => panic!("expected CorruptArchive naming set.z02, got {other:?}"),
        }
    }

    let num_dir = tmp.path().join("num");
    let num = pack_split(
        &bundle,
        &num_dir.join("set.zip"),
        SplitStyle::Numeric,
        SPLIT,
        None,
    );
    fs::remove_file(&num.output_volumes[1]).unwrap();
    let dest = tmp.path().join("x");
    match unpack(
        &num.output_volumes[0],
        &dest,
        &UnpackOptions::default(),
        &NoopProgressObserver,
    ) {
        Err(DandiError::CorruptArchive(msg)) => assert!(msg.contains("set.zip.002"), "{msg}"),
        other => panic!("expected CorruptArchive naming set.zip.002, got {other:?}"),
    }
    assert!(
        !dest.exists(),
        "nothing may be extracted from an incomplete set"
    );
}

#[test]
fn split_size_below_minimum_is_rejected_before_writing() {
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"x").unwrap();
    for style in [SplitStyle::PkwareZip, SplitStyle::Numeric] {
        let err = pack(
            std::slice::from_ref(&src),
            &tmp.path().join("out.zip"),
            &PackOptions {
                split_size_bytes: Some(MIN_SPLIT_SIZE_BYTES - 1),
                split_style: style,
                ..PackOptions::default()
            },
            &NoopProgressObserver,
        )
        .unwrap_err();
        assert!(matches!(err, DandiError::InvalidInput(_)), "{err:?}");
    }
    assert_eq!(dir_names(tmp.path()), vec!["src"]);
}

#[test]
fn pkware_split_requires_zip_extension() {
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("a.txt"), b"x").unwrap();
    let err = pack(
        &[src],
        &tmp.path().join("out.bin"),
        &PackOptions {
            split_size_bytes: Some(SPLIT),
            ..PackOptions::default()
        },
        &NoopProgressObserver,
    )
    .unwrap_err();
    assert!(matches!(err, DandiError::InvalidInput(_)), "{err:?}");
}

struct CancelWhilePacking {
    token: CancellationToken,
    after: usize,
}

impl ProgressObserver for CancelWhilePacking {
    fn on_progress(&self, event: &ProgressEvent) {
        if event.phase == ProgressPhase::Packing && event.entries_done >= self.after {
            self.token.cancel();
        }
    }
}

#[test]
fn cancel_mid_split_pack_leaves_no_volumes_or_temps() {
    for style in [SplitStyle::PkwareZip, SplitStyle::Numeric] {
        for password in [None, Some("pw")] {
            let tmp = TempDir::new().unwrap();
            let bundle = make_tree(&tmp.path().join("src"), 600);
            let out_dir = tmp.path().join("out");
            fs::create_dir_all(&out_dir).unwrap();
            let token = CancellationToken::new();
            let err = pack(
                &[bundle],
                &out_dir.join("c.zip"),
                &PackOptions {
                    split_size_bytes: Some(SPLIT),
                    split_style: style,
                    password: password.map(str::to_string),
                    cancel: token.clone(),
                    ..PackOptions::default()
                },
                &CancelWhilePacking { token, after: 3 },
            )
            .unwrap_err();
            assert!(matches!(err, DandiError::Cancelled), "{style:?}: {err:?}");
            assert!(
                dir_names(&out_dir).is_empty(),
                "{style:?}/{password:?} left {:?}",
                dir_names(&out_dir)
            );
        }
    }
}

#[test]
fn repacking_into_fewer_volumes_replaces_the_whole_old_set() {
    let tmp = TempDir::new().unwrap();
    let big = make_tree(&tmp.path().join("big"), 400);
    let small = make_tree(&tmp.path().join("small"), 80);
    let out_dir = tmp.path().join("out");

    for style in [SplitStyle::Numeric, SplitStyle::PkwareZip] {
        let zip_path = out_dir.join(format!("{style:?}.zip"));
        let first = pack_split(&big, &zip_path, style, SPLIT, None);
        let second = pack_split(&small, &zip_path, style, SPLIT, None);
        assert!(second.output_volumes.len() < first.output_volumes.len());
        for old in &first.output_volumes {
            if !second.output_volumes.contains(old) {
                assert!(!old.exists(), "{style:?}: stale volume {old:?} survived");
            }
        }
        let dest = tmp.path().join(format!("x_{style:?}"));
        unpack_direct(&second.output_volumes[0], &dest, None);
        assert_eq!(hash_tree(&dest.join("bundle")), hash_tree(&small));

        let err = pack(
            std::slice::from_ref(&small),
            &zip_path,
            &PackOptions {
                split_size_bytes: Some(SPLIT),
                split_style: style,
                overwrite: false,
                ..PackOptions::default()
            },
            &NoopProgressObserver,
        )
        .unwrap_err();
        assert!(matches!(err, DandiError::AlreadyExists { .. }), "{err:?}");
    }
}

#[test]
fn encrypted_split_zip_round_trips_and_rejects_wrong_password() {
    let tmp = TempDir::new().unwrap();
    let bundle = make_tree(&tmp.path().join("src"), 300);
    let pw = "단디-Split!2026";
    for style in [SplitStyle::PkwareZip, SplitStyle::Numeric] {
        let zip_path = tmp.path().join(format!("enc_{style:?}.zip"));
        let report = pack_split(&bundle, &zip_path, style, SPLIT, Some(pw));
        assert!(report.encrypted);
        assert!(report.output_volumes.len() > 1);

        let bad = unpack(
            &report.output_volumes[0],
            &tmp.path().join(format!("bad_{style:?}")),
            &UnpackOptions {
                password: Some("wrong".to_string()),
                ..UnpackOptions::default()
            },
            &NoopProgressObserver,
        );
        assert!(matches!(bad, Err(DandiError::InvalidPassword)), "{bad:?}");

        let dest = tmp.path().join(format!("ok_{style:?}"));
        unpack_direct(&report.output_volumes[0], &dest, Some(pw));
        assert_eq!(hash_tree(&dest.join("bundle")), hash_tree(&bundle));
    }
}

#[test]
fn overwrite_false_holds_for_split_sets() {
    let tmp = TempDir::new().unwrap();
    let bundle = make_tree(&tmp.path().join("src"), 200);
    let zip_path = tmp.path().join("ow.zip");
    let report = pack_split(&bundle, &zip_path, SplitStyle::PkwareZip, SPLIT, None);
    let dest = tmp.path().join("x");
    unpack_direct(&zip_path, &dest, None);
    let marker = dest.join("bundle/readme.txt");
    fs::write(&marker, b"user edit").unwrap();
    let err = unpack(
        &report.output_volumes[0],
        &dest,
        &UnpackOptions {
            mode: ExtractMode::Direct,
            overwrite: false,
            ..UnpackOptions::default()
        },
        &NoopProgressObserver,
    )
    .unwrap_err();
    assert!(matches!(err, DandiError::AlreadyExists { .. }), "{err:?}");
    assert_eq!(fs::read(&marker).unwrap(), b"user edit");
}

#[test]
fn numeric_split_tar_gz_is_read_through_the_split_reader() {
    let tmp = TempDir::new().unwrap();
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        for (i, len) in [70_000usize, 150_000, 5].iter().enumerate() {
            let data = pseudo_random(*len, i as u64 + 7);
            let mut hdr = tar::Header::new_gnu();
            hdr.set_size(data.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_mtime(1_735_689_600);
            hdr.set_cksum();
            builder
                .append_data(&mut hdr, format!("logs/part_{i}.bin"), data.as_slice())
                .unwrap();
        }
        builder.finish().unwrap();
    }
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&tar_bytes).unwrap();
    let gz_bytes = gz.finish().unwrap();
    let parts: Vec<PathBuf> = gz_bytes
        .chunks(64 * 1024)
        .enumerate()
        .map(|(i, chunk)| {
            let p = tmp.path().join(format!("logs.tar.gz.{:03}", i + 1));
            fs::write(&p, chunk).unwrap();
            p
        })
        .collect();
    assert!(parts.len() >= 3);

    let dest = tmp.path().join("x");
    unpack_direct(&parts[2], &dest, None);
    assert_eq!(
        fs::read(dest.join("logs/part_1.bin")).unwrap(),
        pseudo_random(150_000, 8)
    );
}

/// Cross-check with Info-ZIP: `zip -s 0` only merges spec-valid split sets.
///
/// Entries stay below one volume because Info-ZIP 3.0 mis-merges entries spanning three or
/// more volumes even in split sets it wrote itself (`zip -s 64k` then `zip -s 0`).
#[test]
fn info_zip_merges_pkware_split_set() {
    let Ok(probe) = Command::new("zip").arg("-v").output() else {
        eprintln!("skipping: Info-ZIP `zip` not installed");
        return;
    };
    if !String::from_utf8_lossy(&probe.stdout).contains("Info-ZIP") {
        eprintln!("skipping: `zip` is not Info-ZIP");
        return;
    }
    let tmp = TempDir::new().unwrap();
    let bundle = tmp.path().join("src/bundle");
    fs::create_dir_all(bundle.join("한글")).unwrap();
    for i in 0..12u64 {
        let name = format!("한글/part_{i:02}.bin");
        fs::write(bundle.join(name), pseudo_random(30_000, i + 1)).unwrap();
    }
    let zip_path = tmp.path().join("set.zip");
    let report = pack_split(&bundle, &zip_path, SplitStyle::PkwareZip, SPLIT, None);
    assert!(report.output_volumes.len() > 3);

    let merged = tmp.path().join("merged.zip");
    let status = Command::new("zip")
        .args(["-q", "-s", "0"])
        .arg(&zip_path)
        .arg("--out")
        .arg(&merged)
        .status()
        .unwrap();
    assert!(status.success(), "zip -s 0 rejected the split set");
    let test = Command::new("unzip")
        .args(["-tq"])
        .arg(&merged)
        .output()
        .unwrap();
    assert!(
        test.status.success(),
        "unzip -t failed: {}",
        String::from_utf8_lossy(&test.stdout)
    );
}

/// Only the consecutive run after the new set is "an older set"; look-alike names are user files.
#[test]
fn unrelated_numbered_siblings_survive_and_standalone_numbered_zip_opens() {
    let tmp = TempDir::new().unwrap();
    let bundle = make_tree(&tmp.path().join("src"), 200);
    let out_dir = tmp.path().join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let yearly = out_dir.join("out.zip.2024");
    pack(
        &[bundle.join("readme.txt")],
        &yearly,
        &PackOptions::default(),
        &NoopProgressObserver,
    )
    .unwrap();
    let lone_z99 = out_dir.join("out.z99");
    fs::write(&lone_z99, b"not part of any set").unwrap();

    for style in [SplitStyle::Numeric, SplitStyle::PkwareZip] {
        let report = pack_split(&bundle, &out_dir.join("out.zip"), style, SPLIT, None);
        assert!(report.output_volumes.len() > 1);
        assert!(yearly.exists(), "{style:?} deleted out.zip.2024");
        assert!(lone_z99.exists(), "{style:?} deleted out.z99");
        let dest = tmp.path().join(format!("x_{style:?}"));
        unpack_direct(&report.output_volumes[0], &dest, None);
        assert_eq!(hash_tree(&dest.join("bundle")), hash_tree(&bundle));
    }

    assert_eq!(listed_paths(&yearly), vec!["readme.txt"]);
}
