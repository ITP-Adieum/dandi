use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use dandi_core::archive::inspect_zip_raw_headers;
use dandi_core::{
    inspect, pack, repack_nfc, unpack, CancellationToken, DandiError, EncodingId, EntryKind,
    ExtractMode, InspectOptions, NoopProgressObserver, PackOptions, PathPolicy, RepackOptions,
    SafetyBudget, UnpackOptions,
};
use flate2::write::DeflateEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use unicode_normalization::UnicodeNormalization;

use crate::fixtures::{
    build_0x7075_block, fill_pseudo_random, hash_directory, sha256_file, sha256_hex,
    write_7z_fixture, write_raw_zip, write_tar_fixture, RawZipSpec,
};
use crate::windows_bridge::{generate_real_windows_zips, verify_zip_on_windows};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckResult {
    pub id: String,
    pub category: String,
    pub name: String,
    pub max_points: u32,
    pub earned_points: u32,
    pub passed: bool,
    pub duration_ms: u64,
    pub details: String,
}

#[derive(Clone, Debug)]
pub struct EvalContext {
    pub windows_ssh: Option<String>,
}

impl EvalContext {
    fn has_real_windows(&self) -> bool {
        cfg!(windows) || self.windows_ssh.is_some()
    }
}

pub fn run_all_checks(ctx: &EvalContext) -> Vec<CheckResult> {
    let mut results = Vec::with_capacity(27);

    // Pre-generate real Windows ZIPs once if Windows is reachable (used by COMPAT-02 & I18N-02).
    let shared_tmp = TempDir::new().ok();
    let win_generated = if ctx.has_real_windows() {
        shared_tmp.as_ref().map(|tmp| {
            let ps_zip = tmp.path().join("win_ps.zip");
            let cp_zip = tmp.path().join("win_cp949.zip");
            let res = generate_real_windows_zips(&ps_zip, &cp_zip, ctx.windows_ssh.as_deref());
            (ps_zip, cp_zip, res)
        })
    } else {
        None
    };

    // Category A — Cross-OS Native Compatibility (30 pts)
    results.push(run_check(
        "COMPAT-01",
        "Compatibility",
        "Mac -> Windows Native Explorer Round-Trip",
        8,
        || check_compat_01(ctx),
    ));
    results.push(run_check(
        "COMPAT-02",
        "Compatibility",
        "Windows -> Mac Native Archive Utility Round-Trip",
        6,
        || check_compat_02(win_generated.as_ref()),
    ));
    results.push(run_check(
        "COMPAT-03",
        "Compatibility",
        "macOS .app-like Executable & Symlink Round-Trip",
        5,
        check_compat_03,
    ));
    results.push(run_check(
        "COMPAT-04",
        "Compatibility",
        "UTC Timestamp Fidelity (0x5455)",
        4,
        check_compat_04,
    ));
    results.push(run_check(
        "COMPAT-05",
        "Compatibility",
        "ZIP64 & Large Entry Count",
        3,
        check_compat_05,
    ));
    results.push(run_check(
        "COMPAT-06",
        "Compatibility",
        "WinZip AES-256 + Unicode Password",
        2,
        check_compat_06,
    ));
    results.push(run_check(
        "COMPAT-07",
        "Compatibility",
        "Extended Format Reading (.7z, .tar.gz/zst/bz2/xz)",
        2,
        check_compat_07,
    ));

    // Category B — Multilingual & Encoding Fidelity (25 pts)
    results.push(run_check(
        "I18N-01",
        "Multilingual",
        "All-Script NFD -> NFC Pack Verification",
        6,
        check_i18n_01,
    ));
    results.push(run_check(
        "I18N-02",
        "Multilingual",
        "Legacy Korean CP949 (Real Windows & Synthetic)",
        5,
        || check_i18n_02(win_generated.as_ref()),
    ));
    results.push(run_check(
        "I18N-03",
        "Multilingual",
        "Legacy Japanese Shift_JIS incl. 0x5C Bytes",
        4,
        check_i18n_03,
    ));
    results.push(run_check(
        "I18N-04",
        "Multilingual",
        "Legacy Simplified (GB18030) & Traditional (Big5) Chinese",
        3,
        check_i18n_04,
    ));
    results.push(run_check(
        "I18N-05",
        "Multilingual",
        "Cyrillic (IBM866/Win-1251) + Western (Win-1252) + Non-ASCII Path",
        3,
        check_i18n_05,
    ));
    results.push(run_check(
        "I18N-06",
        "Multilingual",
        "Manual Encoding Override & repack_nfc",
        2,
        check_i18n_06,
    ));
    results.push(run_check(
        "I18N-07",
        "Multilingual",
        "Mixed-Script 5-Level Deep Nesting",
        1,
        check_i18n_07,
    ));
    results.push(run_check(
        "I18N-08",
        "Multilingual",
        "Info-ZIP 0x7075 Valid vs Tampered CRC32",
        1,
        check_i18n_08,
    ));

    // Category C — Security & Filesystem Edge Cases (20 pts)
    results.push(run_check(
        "SEC-01",
        "Security",
        "Zip Slip Path Traversal Defense",
        5,
        check_sec_01,
    ));
    results.push(run_check(
        "SEC-02",
        "Security",
        "Symlink Escape Defense",
        5,
        check_sec_02,
    ));
    results.push(run_check(
        "SEC-03",
        "Security",
        "Zip Bomb SafetyBudget Defense",
        4,
        check_sec_03,
    ));
    results.push(run_check(
        "SEC-04",
        "Security",
        "Windows Illegal Chars, Reserved Names & >260 Long Paths",
        3,
        check_sec_04,
    ));
    results.push(run_check(
        "SEC-05",
        "Security",
        "Case-Insensitive Collision Disambiguation",
        2,
        check_sec_05,
    ));
    results.push(run_check(
        "SEC-06",
        "Security",
        "Corrupt & Truncated Archive Handling",
        1,
        check_sec_06,
    ));

    // Category D — Performance & Efficiency (15 pts)
    results.push(run_check(
        "PERF-01",
        "Performance",
        "Multi-File Parallel Deflate Throughput",
        6,
        check_perf_01,
    ));
    results.push(run_check(
        "PERF-02",
        "Performance",
        "Smart Store (Pre-Compressed Media)",
        5,
        check_perf_02,
    ));
    results.push(run_check(
        "PERF-03",
        "Performance",
        "Extraction Throughput & Streaming Memory",
        4,
        check_perf_03,
    ));

    // Category E — Reliability & Smart UX (10 pts)
    results.push(run_check(
        "UX-01",
        "UX",
        "Smart Extraction (Single-Root vs Tarbomb & Collision)",
        4,
        check_ux_01,
    ));
    results.push(run_check(
        "UX-02",
        "UX",
        "Cooperative Cancellation & Clean Rollback",
        3,
        check_ux_02,
    ));
    results.push(run_check(
        "UX-03",
        "UX",
        "Implicit Directory Synthesis & Selective Extraction",
        3,
        check_ux_03,
    ));

    results
}

fn run_check<F>(id: &str, category: &str, name: &str, max_points: u32, f: F) -> CheckResult
where
    F: FnOnce() -> Result<String, String>,
{
    let start = Instant::now();
    match f() {
        Ok(details) => CheckResult {
            id: id.to_string(),
            category: category.to_string(),
            name: name.to_string(),
            max_points,
            earned_points: max_points,
            passed: true,
            duration_ms: start.elapsed().as_millis() as u64,
            details,
        },
        Err(err) => CheckResult {
            id: id.to_string(),
            category: category.to_string(),
            name: name.to_string(),
            max_points,
            earned_points: 0,
            passed: false,
            duration_ms: start.elapsed().as_millis() as u64,
            details: err,
        },
    }
}

type WinGenTriple = (
    PathBuf,
    PathBuf,
    Result<crate::windows_bridge::WinGeneratedArchive, String>,
);

fn check_compat_01(ctx: &EvalContext) -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;
    let root_name_nfc = "단디_호환성_테스트";
    let root_name_nfd: String = root_name_nfc.nfd().collect();
    let src_dir = tmp.path().join(&root_name_nfd);
    fs::create_dir_all(&src_dir).map_err(|e| e.to_string())?;

    let expected_specs: Vec<(&str, &[u8])> = vec![
        (
            "가나다라_보고서.txt",
            b"Korean Hangul NFC roundtrip payload",
        ),
        (
            "がぎぐげご_ぱぴぷ.txt",
            b"Japanese dakuten NFC roundtrip payload",
        ),
        (
            "café_über_niño_Ångström.md",
            b"European accents NFC payload",
        ),
        ("🎉_최종_v2.txt", b"Emoji + Hangul payload"),
        (
            "하위폴더/Tiếng_Việt.txt",
            b"Vietnamese tone marks nested payload",
        ),
    ];

    let mut expected_hashes: BTreeMap<String, String> = BTreeMap::new();
    for (rel_nfc, data) in &expected_specs {
        let rel_nfd: String = rel_nfc.nfd().collect();
        let file_path = src_dir.join(&rel_nfd);
        if let Some(p) = file_path.parent() {
            fs::create_dir_all(p).map_err(|e| e.to_string())?;
        }
        fs::write(&file_path, data).map_err(|e| e.to_string())?;
        expected_hashes.insert(format!("{root_name_nfc}/{rel_nfc}"), sha256_hex(data));
    }

    // Plant OS junk that MUST be excluded from the Golden ZIP.
    fs::write(src_dir.join(".DS_Store"), b"junk-ds").map_err(|e| e.to_string())?;
    fs::write(src_dir.join("._가나다라_보고서.txt"), b"junk-appledouble")
        .map_err(|e| e.to_string())?;
    fs::write(src_dir.join("Thumbs.db"), b"junk-thumbs").map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        fs::write(src_dir.join("Icon\r"), b"junk-icon").map_err(|e| e.to_string())?;
    }

    let zip_path = tmp.path().join("compat01.zip");
    let report = pack(
        &[src_dir],
        &zip_path,
        &PackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;

    if report.junk_skipped < 3 {
        return Err(format!(
            "expected >= 3 OS junk files skipped, got {}",
            report.junk_skipped
        ));
    }

    // Verify raw ZIP headers: Bit 11 ON, strict NFC, 0x5455 present, no 0x7075, no junk.
    let headers = inspect_zip_raw_headers(&zip_path).map_err(|e| e.to_string())?;
    for h in &headers {
        if !h.utf8_bit11() {
            return Err("raw header missing UTF-8 Bit 11".to_string());
        }
        if h.has_0x7075 {
            return Err("raw header unexpectedly wrote redundant 0x7075".to_string());
        }
        if !h.has_0x5455 {
            return Err("raw header missing 0x5455 UTC timestamp".to_string());
        }
        let s = std::str::from_utf8(&h.raw_name).map_err(|_| "header not valid UTF-8")?;
        if s != s.nfc().collect::<String>() {
            return Err(format!("header is not Unicode NFC: {s:?}"));
        }
        if dandi_core::is_os_junk(s) {
            return Err(format!("OS junk leaked into ZIP: {s}"));
        }
    }

    if ctx.has_real_windows() {
        let win_res =
            verify_zip_on_windows(&zip_path, expected_hashes.len(), ctx.windows_ssh.as_deref())?;

        if win_res.explorer_junk_count != 0 || win_res.expand_archive_junk_count != 0 {
            return Err(format!(
                "junk detected on Windows: explorer={}, expand_archive={}",
                win_res.explorer_junk_count, win_res.expand_archive_junk_count
            ));
        }

        for (label, extracted) in [
            ("Explorer COM", &win_res.explorer_files),
            ("Expand-Archive", &win_res.expand_archive_files),
        ] {
            if extracted.len() != expected_hashes.len() {
                return Err(format!(
                    "{label}: expected {} files, got {} (keys={:?})",
                    expected_hashes.len(),
                    extracted.len(),
                    extracted.keys().collect::<Vec<_>>()
                ));
            }
            for (rel, exp_hash) in &expected_hashes {
                let info = extracted
                    .get(rel)
                    .ok_or_else(|| format!("{label}: missing NFC file '{rel}'"))?;
                if !info.is_nfc {
                    return Err(format!("{label}: filename not NFC on Windows: '{rel}'"));
                }
                if &info.sha256 != exp_hash {
                    return Err(format!("{label}: SHA-256 mismatch for '{rel}'"));
                }
            }
        }
        let via = if ctx.windows_ssh.is_some() {
            "remote Windows SSH"
        } else {
            "native Windows"
        };
        Ok(format!(
            "verified {} NFC files via Explorer COM + Expand-Archive ({via}), {} junk skipped",
            expected_hashes.len(),
            report.junk_skipped
        ))
    } else {
        // Local verification on macOS/Linux without remote Windows target.
        let out = tmp.path().join("local_out");
        let urep = unpack(
            &zip_path,
            &out,
            &UnpackOptions::default(),
            &NoopProgressObserver,
        )
        .map_err(|e| e.to_string())?;
        let actual = hash_directory(&out)?;
        for (rel, exp_hash) in &expected_hashes {
            let got = actual
                .get(rel)
                .ok_or_else(|| format!("missing unpacked file '{rel}'"))?;
            if got != exp_hash {
                return Err(format!("SHA-256 mismatch for '{rel}'"));
            }
        }
        Ok(format!(
            "verified {} NFC files & raw Golden ZIP headers locally ({} extracted; pass --windows-ssh for remote Explorer COM check)",
            expected_hashes.len(),
            urep.files_extracted
        ))
    }
}

fn check_compat_02(win_gen: Option<&WinGenTriple>) -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;
    let src_dir = tmp.path().join("win_roundtrip");
    fs::create_dir_all(src_dir.join("sub")).map_err(|e| e.to_string())?;
    let f1 = b"Cross-OS payload one for ditto/unzip verification";
    let f2 = b"Cross-OS Korean payload \xED\x95\x9C\xEA\xB8\x80";
    fs::write(src_dir.join("readme.txt"), f1).map_err(|e| e.to_string())?;
    fs::write(src_dir.join("sub/한글_문서.txt"), f2).map_err(|e| e.to_string())?;

    let dandi_zip = tmp.path().join("dandi_out.zip");
    pack(
        &[src_dir],
        &dandi_zip,
        &PackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;

    // Check Bit 11 ON and 0 redundant 0x7075.
    let headers = inspect_zip_raw_headers(&dandi_zip).map_err(|e| e.to_string())?;
    if headers.is_empty() {
        return Err("packed ZIP has 0 headers".to_string());
    }
    for h in &headers {
        if !h.utf8_bit11() {
            return Err("Bit 11 not set on dandi-packed ZIP".to_string());
        }
        if h.has_0x7075 {
            return Err("redundant 0x7075 written alongside Bit 11".to_string());
        }
    }

    let mut verified_tools = Vec::new();

    #[cfg(target_os = "macos")]
    {
        let ditto_dir = tmp.path().join("ditto_out");
        fs::create_dir_all(&ditto_dir).map_err(|e| e.to_string())?;
        let st = Command::new("/usr/bin/ditto")
            .args(["-x", "-k"])
            .arg(&dandi_zip)
            .arg(&ditto_dir)
            .status()
            .map_err(|e| format!("failed to run ditto: {e}"))?;
        if !st.success() {
            return Err(format!("ditto failed with {:?}", st.code()));
        }
        let h1 = sha256_file(&ditto_dir.join("win_roundtrip/readme.txt"))?;
        let h2 = sha256_file(&ditto_dir.join("win_roundtrip/sub/한글_문서.txt"))?;
        if h1 != sha256_hex(f1) || h2 != sha256_hex(f2) {
            return Err("ditto extracted SHA-256 mismatch".to_string());
        }
        verified_tools.push("macOS ditto");

        let unzip_dir = tmp.path().join("unzip_out");
        fs::create_dir_all(&unzip_dir).map_err(|e| e.to_string())?;
        let st2 = Command::new("/usr/bin/unzip")
            .args(["-qq", "-o"])
            .arg(&dandi_zip)
            .arg("-d")
            .arg(&unzip_dir)
            .status()
            .map_err(|e| format!("failed to run unzip: {e}"))?;
        if !st2.success() {
            return Err(format!("unzip failed with {:?}", st2.code()));
        }
        let uh1 = sha256_file(&unzip_dir.join("win_roundtrip/readme.txt"))?;
        let uh2 = sha256_file(&unzip_dir.join("win_roundtrip/sub/한글_문서.txt"))?;
        if uh1 != sha256_hex(f1) || uh2 != sha256_hex(f2) {
            return Err("unzip extracted SHA-256 mismatch".to_string());
        }
        verified_tools.push("macOS unzip");
    }

    // If we also generated a real Windows PowerShell ZIP, unpack it with dandi (and ditto on macOS).
    if let Some((ps_zip, _cp_zip, res)) = win_gen {
        let meta = res
            .as_ref()
            .map_err(|e| format!("real Windows ZIP generation failed: {e}"))?;
        let ps_out = tmp.path().join("win_ps_unpack");
        let urep = unpack(
            ps_zip,
            &ps_out,
            &UnpackOptions {
                mode: ExtractMode::Direct,
                ..UnpackOptions::default()
            },
            &NoopProgressObserver,
        )
        .map_err(|e| e.to_string())?;
        let actual = hash_directory(&ps_out)?;
        for (rel, exp_hash) in &meta.files {
            let rel_nfc: String = rel.nfc().collect();
            let found = actual
                .iter()
                .find(|(k, _)| k.nfc().collect::<String>() == rel_nfc)
                .map(|(_, v)| v);
            match found {
                Some(got) if got == exp_hash => {}
                Some(_) => return Err(format!("PowerShell ZIP hash mismatch for {rel_nfc}")),
                None => {
                    return Err(format!(
                        "PowerShell ZIP missing {rel_nfc} (got {:?})",
                        actual.keys().collect::<Vec<_>>()
                    ))
                }
            }
        }
        let _ = urep;
        verified_tools.push("Windows PowerShell Compress-Archive -> dandi");
    }

    if verified_tools.is_empty() {
        // Fallback on Linux/Windows without macOS ditto
        let out = tmp.path().join("dandi_unpack");
        unpack(
            &dandi_zip,
            &out,
            &UnpackOptions::default(),
            &NoopProgressObserver,
        )
        .map_err(|e| e.to_string())?;
        let h1 = sha256_file(&out.join("win_roundtrip/readme.txt"))?;
        let h2 = sha256_file(&out.join("win_roundtrip/sub/한글_문서.txt"))?;
        if h1 != sha256_hex(f1) || h2 != sha256_hex(f2) {
            return Err("dandi unpack SHA-256 mismatch".to_string());
        }
        verified_tools.push("dandi roundtrip + raw header audit");
    }

    Ok(format!(
        "verified via [{}], Bit 11 ON, 0 redundant 0x7075",
        verified_tools.join(", ")
    ))
}

fn check_compat_03() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;
    let zip_path = tmp.path().join("demo_app.zip");

    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let app_root = tmp.path().join("Demo.app");
        let macos_dir = app_root.join("Contents/MacOS");
        let res_dir = app_root.join("Contents/Resources");
        fs::create_dir_all(&macos_dir).map_err(|e| e.to_string())?;
        fs::create_dir_all(&res_dir).map_err(|e| e.to_string())?;

        let bin_path = macos_dir.join("run.sh");
        let script = b"#!/bin/sh\necho dandi-ok\n";
        fs::write(&bin_path, script).map_err(|e| e.to_string())?;
        fs::set_permissions(&bin_path, fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;

        let link_path = res_dir.join("run_link");
        symlink("../MacOS/run.sh", &link_path).map_err(|e| e.to_string())?;

        pack(
            &[app_root],
            &zip_path,
            &PackOptions::default(),
            &NoopProgressObserver,
        )
        .map_err(|e| e.to_string())?;

        let out_dir = tmp.path().join("out");
        let urep = unpack(
            &zip_path,
            &out_dir,
            &UnpackOptions::default(),
            &NoopProgressObserver,
        )
        .map_err(|e| e.to_string())?;

        let extracted_bin = out_dir.join("Demo.app/Contents/MacOS/run.sh");
        let bin_mode = fs::metadata(&extracted_bin)
            .map_err(|e| e.to_string())?
            .permissions()
            .mode()
            & 0o777;
        if (bin_mode & 0o111) == 0 {
            return Err(format!("+x bit lost on run.sh (mode={bin_mode:o})"));
        }

        let extracted_link = out_dir.join("Demo.app/Contents/Resources/run_link");
        let link_meta = fs::symlink_metadata(&extracted_link).map_err(|e| e.to_string())?;
        if !link_meta.file_type().is_symlink() {
            return Err("relative symlink was not preserved as a symlink".to_string());
        }
        let target = fs::read_link(&extracted_link).map_err(|e| e.to_string())?;
        if target != std::path::Path::new("../MacOS/run.sh") {
            return Err(format!("unexpected symlink target: {}", target.display()));
        }
        if sha256_file(&extracted_link)? != sha256_hex(script) {
            return Err("symlink does not resolve to target script content".to_string());
        }
        Ok(format!(
            "+x preserved (0o{bin_mode:o}) & relative symlink intact ({} symlinks)",
            urep.symlinks_created
        ))
    }

    #[cfg(windows)]
    {
        // On Windows, verify Unix mode metadata and safe relative symlink handling cleanly.
        let mut exec = RawZipSpec::file(
            b"Demo.app/Contents/MacOS/run.sh".to_vec(),
            b"#!/bin/sh\necho dandi-ok\n".to_vec(),
        );
        exec.flags = 0x0800;
        exec.external_attrs = 0o100755 << 16;
        let sym = RawZipSpec::symlink(
            b"Demo.app/Contents/Resources/run_link".to_vec(),
            "../MacOS/run.sh",
        );
        write_raw_zip(&zip_path, &[exec, sym])?;

        let summary = inspect(&zip_path, &InspectOptions::default()).map_err(|e| e.to_string())?;
        let has_exec = summary
            .entries
            .iter()
            .any(|e| e.path.ends_with("run.sh") && e.unix_mode == Some(0o100755));
        let has_sym = summary
            .entries
            .iter()
            .any(|e| e.path.ends_with("run_link") && e.kind == EntryKind::Symlink);
        if !has_exec || !has_sym {
            return Err("inspect failed to detect Unix +x mode or symlink entry".to_string());
        }
        let out_dir = tmp.path().join("out");
        unpack(
            &zip_path,
            &out_dir,
            &UnpackOptions::default(),
            &NoopProgressObserver,
        )
        .map_err(|e| e.to_string())?;
        Ok("verified Unix +x metadata & safe relative symlink unpack on Windows".to_string())
    }
}

fn check_compat_04() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;
    let src_file = tmp.path().join("timestamp_test.txt");
    fs::write(&src_file, b"utc timestamp payload").map_err(|e| e.to_string())?;

    // Explicit UTC timestamp: 2025-07-15 12:34:56 UTC
    let expected_ts: i64 = 1_752_582_896;
    dandi_core::platform::set_mtime(&src_file, expected_ts, false).map_err(|e| e.to_string())?;

    let zip_path = tmp.path().join("ts.zip");
    pack(
        &[src_file],
        &zip_path,
        &PackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;

    let headers = inspect_zip_raw_headers(&zip_path).map_err(|e| e.to_string())?;
    let h = headers
        .first()
        .ok_or_else(|| "missing header in ts.zip".to_string())?;
    if !h.has_0x5455 {
        return Err("0x5455 Extended Timestamp extra field missing".to_string());
    }
    let header_ts = h
        .mtime_unix_secs
        .ok_or_else(|| "mtime_unix_secs missing".to_string())?;
    if (header_ts - expected_ts).abs() > 2 {
        return Err(format!(
            "header UTC timestamp drift: expected {expected_ts}, got {header_ts}"
        ));
    }

    let out_dir = tmp.path().join("out");
    unpack(
        &zip_path,
        &out_dir,
        &UnpackOptions {
            mode: ExtractMode::Direct,
            ..UnpackOptions::default()
        },
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;

    let unpacked_meta =
        fs::metadata(out_dir.join("timestamp_test.txt")).map_err(|e| e.to_string())?;
    let actual_ts = unpacked_meta
        .modified()
        .map_err(|e| e.to_string())?
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs() as i64;
    let drift = (actual_ts - expected_ts).abs();
    if drift > 2 {
        return Err(format!(
            "unpacked mtime drift {drift}s > 2s (expected {expected_ts}, got {actual_ts})"
        ));
    }

    Ok(format!("0x5455 UTC present, unpack mtime drift = {drift}s"))
}

fn check_compat_05() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;
    let many_dir = tmp.path().join("many_files");
    fs::create_dir_all(&many_dir).map_err(|e| e.to_string())?;

    let count = 1_050usize;
    let mut expected = BTreeMap::new();
    for i in 0..count {
        let name = format!("item_{i:04}.txt");
        let content = format!("payload-{i:04}-dandi-zip64-test");
        fs::write(many_dir.join(&name), content.as_bytes()).map_err(|e| e.to_string())?;
        expected.insert(format!("many_files/{name}"), sha256_hex(content.as_bytes()));
    }

    let many_zip = tmp.path().join("many.zip");
    let prep = pack(
        &[many_dir],
        &many_zip,
        &PackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;
    if prep.used_zip64 {
        return Err("small archive (<4GB, <65535 entries) should NOT emit ZIP64".to_string());
    }

    let out_many = tmp.path().join("out_many");
    unpack(
        &many_zip,
        &out_many,
        &UnpackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;
    let got_many = hash_directory(&out_many)?;
    if got_many != expected {
        return Err(format!(
            "1050-file roundtrip mismatch: expected {}, got {}",
            expected.len(),
            got_many.len()
        ));
    }

    // External ZIP64 fixture (explicit ZIP64 extra + ZIP64 EOCD/Locator).
    let z64_zip = tmp.path().join("ext_zip64.zip");
    let mut spec = RawZipSpec::file(
        b"zip64_dir/hello_zip64.txt".to_vec(),
        b"verified external ZIP64 payload".to_vec(),
    );
    spec.flags = 0x0800;
    spec.force_zip64 = true;
    write_raw_zip(&z64_zip, &[spec])?;

    let z64_headers = inspect_zip_raw_headers(&z64_zip).map_err(|e| e.to_string())?;
    if !z64_headers
        .first()
        .map(|h| h.has_zip64_extra)
        .unwrap_or(false)
    {
        return Err("external ZIP64 extra field was not recognized".to_string());
    }

    let out_z64 = tmp.path().join("out_z64");
    unpack(
        &z64_zip,
        &out_z64,
        &UnpackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;
    let got_z64 = fs::read(out_z64.join("zip64_dir/hello_zip64.txt")).map_err(|e| e.to_string())?;
    if got_z64 != b"verified external ZIP64 payload" {
        return Err("external ZIP64 extracted bytes mismatch".to_string());
    }

    Ok(
        "1,050 files round-tripped (ZIP64 omitted on small archive) + external ZIP64 verified"
            .to_string(),
    )
}

fn check_compat_06() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;
    let secret_file = tmp.path().join("비밀_문서.txt");
    let secret_bytes = b"Top-secret AES-256 Unicode password payload 2026!";
    fs::write(&secret_file, secret_bytes).map_err(|e| e.to_string())?;

    let pw = "단디-Pass!2026";
    let zip_path = tmp.path().join("aes256.zip");
    let prep = pack(
        &[secret_file],
        &zip_path,
        &PackOptions {
            password: Some(pw.to_string()),
            ..PackOptions::default()
        },
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;
    if !prep.encrypted {
        return Err("PackReport.encrypted was false".to_string());
    }

    // Wrong password MUST return DandiError::InvalidPassword.
    let bad_dir = tmp.path().join("bad_pw");
    let bad_res = unpack(
        &zip_path,
        &bad_dir,
        &UnpackOptions {
            password: Some("wrong-pass".to_string()),
            ..UnpackOptions::default()
        },
        &NoopProgressObserver,
    );
    if !matches!(bad_res, Err(DandiError::InvalidPassword)) {
        return Err(format!("expected InvalidPassword, got {bad_res:?}"));
    }

    // Correct Unicode password (even passed as NFD!) MUST succeed with exact bytes.
    let pw_nfd: String = pw.nfd().collect();
    let ok_dir = tmp.path().join("ok_pw");
    unpack(
        &zip_path,
        &ok_dir,
        &UnpackOptions {
            mode: ExtractMode::Direct,
            password: Some(pw_nfd),
            ..UnpackOptions::default()
        },
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;

    let recovered = fs::read(ok_dir.join("비밀_문서.txt")).map_err(|e| e.to_string())?;
    if recovered != secret_bytes {
        return Err("decrypted bytes mismatch".to_string());
    }

    Ok(
        "WinZip AES-256 Unicode password decrypts cleanly; wrong password returns InvalidPassword"
            .to_string(),
    )
}

fn check_compat_07() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;
    let payload1 = b"Extended format file 1: Korean \xED\x95\x9C\xEA\xB8\x80";
    let payload2 = b"Extended format file 2: nested content";
    let files: Vec<(&str, &[u8])> = vec![
        ("bundle/hello.txt", payload1),
        ("bundle/nested/문서.txt", payload2),
    ];

    let formats = [
        ("sample.7z", "7z"),
        ("sample.tar.gz", "tar.gz"),
        ("sample.tar.zst", "tar.zst"),
        ("sample.tar.bz2", "tar.bz2"),
        ("sample.tar.xz", "tar.xz"),
    ];

    for (fname, kind) in formats {
        let archive = tmp.path().join(fname);
        if kind == "7z" {
            write_7z_fixture(&archive, &files)?;
        } else {
            write_tar_fixture(&archive, kind, &files)?;
        }

        let summary = inspect(&archive, &InspectOptions::default())
            .map_err(|e| format!("{kind} inspect: {e}"))?;
        if summary.entries.is_empty() {
            return Err(format!("{kind} inspect returned 0 entries"));
        }

        let out = tmp.path().join(format!("out_{kind}"));
        unpack(
            &archive,
            &out,
            &UnpackOptions::default(),
            &NoopProgressObserver,
        )
        .map_err(|e| format!("{kind} unpack: {e}"))?;

        let h1 = sha256_file(&out.join("bundle/hello.txt"))?;
        let h2 = sha256_file(&out.join("bundle/nested/문서.txt"))?;
        if h1 != sha256_hex(payload1) || h2 != sha256_hex(payload2) {
            return Err(format!("{kind}: SHA-256 mismatch after unpack"));
        }
    }

    Ok("100% SHA-256 match across .7z, .tar.gz, .tar.zst, .tar.bz2, .tar.xz".to_string())
}

fn check_i18n_01() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;
    let src = tmp.path().join("all_scripts");
    fs::create_dir_all(&src).map_err(|e| e.to_string())?;

    let names = [
        "가나다라_보고서.pdf",
        "がぎぐげご_ぱぴぷ.txt",
        "café_über_niño_Ångström.md",
        "Tiếng_Việt.txt",
        "🎉_최종_v2.xlsx",
    ];

    for nfc_name in names {
        let nfd_name: String = nfc_name.nfd().collect();
        fs::write(src.join(&nfd_name), nfc_name.as_bytes()).map_err(|e| e.to_string())?;
    }

    let zip_path = tmp.path().join("i18n01.zip");
    pack(
        &[src],
        &zip_path,
        &PackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;

    let headers = inspect_zip_raw_headers(&zip_path).map_err(|e| e.to_string())?;
    let mut found = HashSet::new();
    for h in &headers {
        if !h.utf8_bit11() {
            return Err("Bit 11 OFF in I18N-01 ZIP".to_string());
        }
        let s = std::str::from_utf8(&h.raw_name).map_err(|_| "invalid UTF-8 raw header")?;
        if s != s.nfc().collect::<String>() {
            return Err(format!("header not NFC: {s:?}"));
        }
        if let Some(base) = s.strip_prefix("all_scripts/") {
            if !base.is_empty() {
                found.insert(base.to_string());
            }
        }
    }

    for nfc_name in names {
        if !found.contains(nfc_name) {
            return Err(format!("missing NFC entry '{nfc_name}' (found={found:?})"));
        }
    }

    Ok(format!(
        "all {} scripts packed with Bit 11 ON & strict NFC bytes",
        names.len()
    ))
}

fn check_i18n_02(win_gen: Option<&WinGenTriple>) -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;

    // 1. Synthetic multi-file CP949 ZIP (Bit 11 OFF).
    let expected = [
        ("프로젝트/보고서_최종.txt", b"cp949-1".as_slice()),
        ("프로젝트/가나다라_회의록.md", b"cp949-2".as_slice()),
        ("프로젝트/하위폴더/단디_테스트.csv", b"cp949-3".as_slice()),
    ];
    let specs: Vec<RawZipSpec> = expected
        .iter()
        .map(|(name, data)| {
            let (raw, had_err) = EncodingId::Cp949.encode_str(name);
            assert!(!had_err);
            RawZipSpec::file(raw, data.to_vec())
        })
        .collect();
    let syn_zip = tmp.path().join("legacy_cp949.zip");
    write_raw_zip(&syn_zip, &specs)?;

    let summary = inspect(&syn_zip, &InspectOptions::default()).map_err(|e| e.to_string())?;
    if summary.applied_encoding != EncodingId::Cp949 {
        return Err(format!(
            "synthetic CP949 detected as {:?}",
            summary.applied_encoding
        ));
    }
    let out = tmp.path().join("out_syn");
    unpack(
        &syn_zip,
        &out,
        &UnpackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;
    for (name, data) in expected {
        let got = fs::read(out.join(name)).map_err(|e| format!("missing {name}: {e}"))?;
        if got != data {
            return Err(format!("content mismatch for {name}"));
        }
    }

    // 2. Real Windows-generated CP949 ZIP if available.
    if let Some((_ps_zip, cp_zip, res)) = win_gen {
        let meta = res
            .as_ref()
            .map_err(|e| format!("real Windows CP949 generation failed: {e}"))?;
        let wsum = inspect(cp_zip, &InspectOptions::default()).map_err(|e| e.to_string())?;
        if wsum.applied_encoding != EncodingId::Cp949 {
            return Err(format!(
                "real Windows CP949 ZIP detected as {:?}",
                wsum.applied_encoding
            ));
        }
        let wout = tmp.path().join("out_real_win_cp949");
        unpack(
            cp_zip,
            &wout,
            &UnpackOptions {
                mode: ExtractMode::Direct,
                ..UnpackOptions::default()
            },
            &NoopProgressObserver,
        )
        .map_err(|e| e.to_string())?;
        let actual = hash_directory(&wout)?;
        for (rel, exp_hash) in &meta.files {
            let rel_nfc: String = rel.nfc().collect();
            let got = actual
                .iter()
                .find(|(k, _)| k.nfc().collect::<String>() == rel_nfc)
                .map(|(_, v)| v)
                .ok_or_else(|| {
                    format!(
                        "real Windows CP949 missing '{rel_nfc}' (got {:?})",
                        actual.keys().collect::<Vec<_>>()
                    )
                })?;
            if got != exp_hash {
                return Err(format!("real Windows CP949 hash mismatch for '{rel_nfc}'"));
            }
        }
        return Ok(format!(
            "auto-detected CP949 on BOTH synthetic & real Windows-generated CP949 ZIP ({} files, 0 mojibake)",
            meta.files.len()
        ));
    }

    Ok("auto-detected CP949 on synthetic multi-file CP949 ZIP (0 mojibake)".to_string())
}

fn check_i18n_03() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;
    let expected = [
        ("日本語/一覧表_機能一覧.txt", b"sjis-1".as_slice()),
        ("日本語/ソフト設計書/能力確認.md", b"sjis-2".as_slice()),
        ("日本語/予定表_ソース.txt", b"sjis-3".as_slice()),
    ];
    let specs: Vec<RawZipSpec> = expected
        .iter()
        .map(|(name, data)| {
            let (raw, had_err) = EncodingId::ShiftJis.encode_str(name);
            assert!(!had_err);
            // Sanity check that our test genuinely exercises Shift_JIS 0x5C trail bytes!
            RawZipSpec::file(raw, data.to_vec())
        })
        .collect();
    let has_5c = specs.iter().any(|s| s.raw_name.contains(&0x5C));
    if !has_5c {
        return Err("Shift_JIS fixture failed to include 0x5C trail bytes".to_string());
    }

    let zip_path = tmp.path().join("legacy_sjis.zip");
    write_raw_zip(&zip_path, &specs)?;

    let summary = inspect(&zip_path, &InspectOptions::default()).map_err(|e| e.to_string())?;
    if summary.applied_encoding != EncodingId::ShiftJis {
        return Err(format!(
            "Shift_JIS detected as {:?}",
            summary.applied_encoding
        ));
    }

    let out = tmp.path().join("out");
    unpack(
        &zip_path,
        &out,
        &UnpackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;
    for (name, data) in expected {
        let got = fs::read(out.join(name)).map_err(|e| format!("missing {name}: {e}"))?;
        if got != data {
            return Err(format!("content mismatch for {name}"));
        }
    }

    Ok(
        "Shift_JIS auto-detected; 表/能/ソ 0x5C trail bytes preserved without path splitting"
            .to_string(),
    )
}

fn check_i18n_04() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;

    // Simplified Chinese (GB18030/GBK)
    let sc = [
        ("中文资料/项目报告_最终版.txt", b"gb-1".as_slice()),
        ("中文资料/数据分析_年度总结.md", b"gb-2".as_slice()),
        ("中文资料/系统说明文档.txt", b"gb-3".as_slice()),
    ];
    let sc_specs: Vec<RawZipSpec> = sc
        .iter()
        .map(|(n, d)| RawZipSpec::file(EncodingId::Gb18030.encode_str(n).0, d.to_vec()))
        .collect();
    let sc_zip = tmp.path().join("legacy_gb18030.zip");
    write_raw_zip(&sc_zip, &sc_specs)?;
    let sc_sum = inspect(&sc_zip, &InspectOptions::default()).map_err(|e| e.to_string())?;
    if sc_sum.applied_encoding != EncodingId::Gb18030 {
        return Err(format!("GB18030 detected as {:?}", sc_sum.applied_encoding));
    }
    let sc_out = tmp.path().join("sc_out");
    unpack(
        &sc_zip,
        &sc_out,
        &UnpackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;
    for (n, d) in sc {
        if fs::read(sc_out.join(n)).map_err(|e| e.to_string())? != d {
            return Err(format!("GB18030 mismatch for {n}"));
        }
    }

    // Traditional Chinese (Big5)
    let tc = [
        ("繁體資料/專案報告_最終版.txt", b"big5-1".as_slice()),
        ("繁體資料/資料分析_年度總結.md", b"big5-2".as_slice()),
        ("繁體資料/系統說明文件.txt", b"big5-3".as_slice()),
    ];
    let tc_specs: Vec<RawZipSpec> = tc
        .iter()
        .map(|(n, d)| RawZipSpec::file(EncodingId::Big5.encode_str(n).0, d.to_vec()))
        .collect();
    let tc_zip = tmp.path().join("legacy_big5.zip");
    write_raw_zip(&tc_zip, &tc_specs)?;
    let tc_sum = inspect(&tc_zip, &InspectOptions::default()).map_err(|e| e.to_string())?;
    if tc_sum.applied_encoding != EncodingId::Big5 {
        return Err(format!("Big5 detected as {:?}", tc_sum.applied_encoding));
    }
    let tc_out = tmp.path().join("tc_out");
    unpack(
        &tc_zip,
        &tc_out,
        &UnpackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;
    for (n, d) in tc {
        if fs::read(tc_out.join(n)).map_err(|e| e.to_string())? != d {
            return Err(format!("Big5 mismatch for {n}"));
        }
    }

    Ok("GB18030 & Big5 both auto-detected and recovered 100% cleanly".to_string())
}

fn check_i18n_05() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;

    // Archive whose OWN filename is Cyrillic + Korean (MacPacker#107).
    let ru_files = [
        ("документы/Отчет_финал.txt", b"ru-1".as_slice()),
        ("документы/Проверка_данных.md", b"ru-2".as_slice()),
    ];
    let w1251_specs: Vec<RawZipSpec> = ru_files
        .iter()
        .map(|(n, d)| RawZipSpec::file(EncodingId::Windows1251.encode_str(n).0, d.to_vec()))
        .collect();
    let w1251_zip = tmp.path().join("Архив_보고서_1251.zip");
    write_raw_zip(&w1251_zip, &w1251_specs)?;
    let s1 = inspect(&w1251_zip, &InspectOptions::default()).map_err(|e| e.to_string())?;
    if s1.applied_encoding != EncodingId::Windows1251 || s1.entries.is_empty() {
        return Err(format!(
            "Windows-1251 failed: enc={:?}",
            s1.applied_encoding
        ));
    }

    let cp866_specs: Vec<RawZipSpec> = ru_files
        .iter()
        .map(|(n, d)| RawZipSpec::file(EncodingId::Ibm866.encode_str(n).0, d.to_vec()))
        .collect();
    let cp866_zip = tmp.path().join("Архив_866.zip");
    write_raw_zip(&cp866_zip, &cp866_specs)?;
    let s2 = inspect(&cp866_zip, &InspectOptions::default()).map_err(|e| e.to_string())?;
    if s2.applied_encoding != EncodingId::Ibm866 {
        return Err(format!("IBM866 failed: enc={:?}", s2.applied_encoding));
    }

    let west_files = [
        ("europe/café_résumé.txt", b"west-1".as_slice()),
        ("europe/über_niño_Ångström.md", b"west-2".as_slice()),
    ];
    let w1252_specs: Vec<RawZipSpec> = west_files
        .iter()
        .map(|(n, d)| RawZipSpec::file(EncodingId::Windows1252.encode_str(n).0, d.to_vec()))
        .collect();
    let w1252_zip = tmp.path().join("résumé_1252.zip");
    write_raw_zip(&w1252_zip, &w1252_specs)?;
    let s3 = inspect(&w1252_zip, &InspectOptions::default()).map_err(|e| e.to_string())?;
    if s3.applied_encoding != EncodingId::Windows1252 {
        return Err(format!(
            "Windows-1252 failed: enc={:?}",
            s3.applied_encoding
        ));
    }

    let out = tmp.path().join("out_w1251");
    unpack(
        &w1251_zip,
        &out,
        &UnpackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;
    for (n, d) in ru_files {
        if fs::read(out.join(n)).map_err(|e| e.to_string())? != d {
            return Err(format!("Cyrillic unpack mismatch for {n}"));
        }
    }

    Ok("Windows-1251, IBM866, Windows-1252 & Cyrillic/Korean archive paths verified".to_string())
}

fn check_i18n_06() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;
    let single_name = "단.txt";
    let (raw, _) = EncodingId::Cp949.encode_str(single_name);
    let legacy_zip = tmp.path().join("ambiguous_single.zip");
    write_raw_zip(
        &legacy_zip,
        &[RawZipSpec::file(raw, b"repacked content".to_vec())],
    )?;

    let fixed_zip = tmp.path().join("fixed_nfc.zip");
    let rrep = repack_nfc(
        &legacy_zip,
        &fixed_zip,
        &RepackOptions {
            encoding_override: Some(EncodingId::Cp949),
            ..RepackOptions::default()
        },
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;
    if rrep.entries_repacked != 1 {
        return Err(format!(
            "expected 1 entry repacked, got {}",
            rrep.entries_repacked
        ));
    }

    let headers = inspect_zip_raw_headers(&fixed_zip).map_err(|e| e.to_string())?;
    let h = headers
        .first()
        .ok_or_else(|| "missing header".to_string())?;
    if !h.utf8_bit11() {
        return Err("repacked ZIP missing Bit 11".to_string());
    }
    let name = std::str::from_utf8(&h.raw_name).map_err(|_| "repacked name not UTF-8")?;
    if name != single_name {
        return Err(format!("expected '{single_name}', got '{name}'"));
    }

    let out = tmp.path().join("out");
    unpack(
        &fixed_zip,
        &out,
        &UnpackOptions {
            mode: ExtractMode::Direct,
            ..UnpackOptions::default()
        },
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;
    if fs::read(out.join(single_name)).map_err(|e| e.to_string())? != b"repacked content" {
        return Err("repacked content mismatch".to_string());
    }

    Ok("manual --encoding cp949 override + repack_nfc produced Bit-11 NFC ZIP".to_string())
}

fn check_i18n_07() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;
    let deep = tmp.path().join("한국어_1/日本語_2/العربية_3/café_4/🎉_5");
    fs::create_dir_all(&deep).map_err(|e| e.to_string())?;
    let payload = b"5-level mixed script payload";
    fs::write(deep.join("최종_最終_نهائي.txt"), payload).map_err(|e| e.to_string())?;

    let zip_path = tmp.path().join("deep.zip");
    pack(
        &[tmp.path().join("한국어_1")],
        &zip_path,
        &PackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;

    let out = tmp.path().join("out");
    unpack(
        &zip_path,
        &out,
        &UnpackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;
    let recovered =
        fs::read(out.join("한국어_1/日本語_2/العربية_3/café_4/🎉_5/최종_最終_نهائي.txt"))
            .map_err(|e| e.to_string())?;
    if recovered != payload {
        return Err("5-level deep nested payload mismatch".to_string());
    }

    Ok("5-level Korean/Japanese/Arabic/Latin/Emoji path round-tripped cleanly".to_string())
}

fn check_i18n_08() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;
    let raw1 = EncodingId::Cp949.encode_str("구형_이름.txt").0;
    let raw2 = EncodingId::Cp949.encode_str("변조_이름.txt").0;

    let mut e1 = RawZipSpec::file(raw1.clone(), b"valid-7075".to_vec());
    e1.extra = build_0x7075_block(&raw1, "유니코드_정상.txt", false);

    let mut e2 = RawZipSpec::file(raw2.clone(), b"tampered-7075".to_vec());
    e2.extra = build_0x7075_block(&raw2, "위조된_이름.txt", true);

    let zip_path = tmp.path().join("extra7075.zip");
    write_raw_zip(&zip_path, &[e1, e2])?;

    let summary = inspect(
        &zip_path,
        &InspectOptions {
            encoding_override: Some(EncodingId::Cp949),
            ..InspectOptions::default()
        },
    )
    .map_err(|e| e.to_string())?;
    let paths: Vec<&str> = summary.entries.iter().map(|e| e.path.as_str()).collect();
    if !paths.contains(&"유니코드_정상.txt") {
        return Err(format!("valid 0x7075 not honored: {paths:?}"));
    }
    if paths.contains(&"위조된_이름.txt") || !paths.contains(&"변조_이름.txt") {
        return Err(format!("tampered 0x7075 was not safely ignored: {paths:?}"));
    }

    Ok("valid 0x7075 honored; tampered CRC32 safely ignored".to_string())
}

fn check_sec_01() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;
    let vectors = [
        "../evil.txt",
        "a/../../evil.txt",
        "/etc/evil",
        r"C:\Windows\evil.dll",
        r"..\evil.txt",
    ];

    for (i, vec_path) in vectors.iter().enumerate() {
        let zip_path = tmp.path().join(format!("slip_{i}.zip"));
        let mut spec = RawZipSpec::file(vec_path.as_bytes().to_vec(), b"pwned".to_vec());
        spec.flags = 0x0800;
        write_raw_zip(&zip_path, &[spec])?;

        let dest = tmp.path().join(format!("dest_{i}"));
        let res = unpack(
            &zip_path,
            &dest,
            &UnpackOptions::default(),
            &NoopProgressObserver,
        );
        if !matches!(res, Err(DandiError::UnsafePath { .. })) {
            return Err(format!(
                "Zip Slip vector '{vec_path}' was NOT rejected: {res:?}"
            ));
        }
        if tmp.path().join("evil.txt").exists() {
            return Err(format!(
                "Zip Slip escaped outside destination for '{vec_path}'"
            ));
        }
    }

    Ok(format!(
        "all {} Zip Slip vectors rejected with UnsafePath",
        vectors.len()
    ))
}

fn check_sec_02() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;

    // Attack 1: symlink `out -> /tmp` followed by `out/pwned.txt`
    let zip1 = tmp.path().join("sym_escape_1.zip");
    let s1 = RawZipSpec::symlink(b"out".to_vec(), "/tmp");
    let mut f1 = RawZipSpec::file(b"out/pwned.txt".to_vec(), b"pwned".to_vec());
    f1.flags = 0x0800;
    write_raw_zip(&zip1, &[s1, f1])?;
    let r1 = unpack(
        &zip1,
        &tmp.path().join("d1"),
        &UnpackOptions::default(),
        &NoopProgressObserver,
    );
    if !matches!(r1, Err(DandiError::UnsafeSymlink { .. })) {
        return Err(format!("symlink escape 1 not rejected: {r1:?}"));
    }

    // Attack 2: absolute symlink to `/etc/passwd`
    let zip2 = tmp.path().join("sym_escape_2.zip");
    let s2 = RawZipSpec::symlink(b"passwd_link".to_vec(), "/etc/passwd");
    write_raw_zip(&zip2, &[s2])?;
    let r2 = unpack(
        &zip2,
        &tmp.path().join("d2"),
        &UnpackOptions::default(),
        &NoopProgressObserver,
    );
    if !matches!(r2, Err(DandiError::UnsafeSymlink { .. })) {
        return Err(format!("absolute symlink not rejected: {r2:?}"));
    }

    // Attack 3: relative symlink escaping via `../../escape`
    let zip3 = tmp.path().join("sym_escape_3.zip");
    let s3 = RawZipSpec::symlink(b"a/escape_link".to_vec(), "../../outside");
    write_raw_zip(&zip3, &[s3])?;
    let r3 = unpack(
        &zip3,
        &tmp.path().join("d3"),
        &UnpackOptions::default(),
        &NoopProgressObserver,
    );
    if !matches!(r3, Err(DandiError::UnsafeSymlink { .. })) {
        return Err(format!("relative symlink escape not rejected: {r3:?}"));
    }

    Ok("all symlink escape & absolute symlink attacks rejected with UnsafeSymlink".to_string())
}

fn check_sec_03() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;
    // 100 MB all-zeros compresses to ~100 KB (~1000x ratio)
    let bomb_data = vec![0u8; 100 * 1024 * 1024];
    let mut spec = RawZipSpec::file(b"bomb.bin".to_vec(), bomb_data);
    spec.flags = 0x0800;
    let bomb_zip = tmp.path().join("bomb.zip");
    write_raw_zip(&bomb_zip, &[spec])?;

    let dest = tmp.path().join("bomb_out");
    let tight_budget = SafetyBudget::new(20 * 1024 * 1024, 1000, 100.0, 5 * 1024 * 1024);

    let res = unpack(
        &bomb_zip,
        &dest,
        &UnpackOptions {
            budget: tight_budget,
            ..UnpackOptions::default()
        },
        &NoopProgressObserver,
    );
    if !matches!(res, Err(DandiError::BudgetExceeded { .. })) {
        return Err(format!(
            "Zip Bomb was NOT rejected with BudgetExceeded: {res:?}"
        ));
    }
    if dest.exists() {
        return Err("partial output directory was not cleaned up after BudgetExceeded".to_string());
    }

    Ok(
        "100 MB (~1000x) Zip Bomb blocked with BudgetExceeded & partial output cleaned up"
            .to_string(),
    )
}

fn check_sec_04() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;
    let long_seg = "a".repeat(60);
    let long_path = format!("{long_seg}/{long_seg}/{long_seg}/{long_seg}/{long_seg}.txt");
    assert!(long_path.len() > 280);

    let entries = [
        ("hazards/a:b*c?.txt", b"illegal-chars".as_slice()),
        ("hazards/CON.txt", b"reserved-con".as_slice()),
        ("hazards/NUL", b"reserved-nul".as_slice()),
        ("hazards/trailing. ", b"trailing-dot-space".as_slice()),
        (long_path.as_str(), b"long-path-ok".as_slice()),
    ];
    let specs: Vec<RawZipSpec> = entries
        .iter()
        .map(|(n, d)| {
            let mut s = RawZipSpec::file(n.as_bytes().to_vec(), d.to_vec());
            s.flags = 0x0800;
            s
        })
        .collect();
    let zip_path = tmp.path().join("win_hazards.zip");
    write_raw_zip(&zip_path, &specs)?;

    let out = tmp.path().join("out");
    let urep = unpack(
        &zip_path,
        &out,
        &UnpackOptions {
            mode: ExtractMode::Direct,
            path_policy: PathPolicy::WindowsCompat,
            ..UnpackOptions::default()
        },
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;

    if urep.files_extracted != entries.len() {
        return Err(format!(
            "expected {} sanitized files extracted, got {}",
            entries.len(),
            urep.files_extracted
        ));
    }
    if urep.sanitized_paths < 4 {
        return Err(format!(
            "expected >= 4 sanitized paths, got {}",
            urep.sanitized_paths
        ));
    }

    // Verify exact deterministic sanitized filenames exist.
    let checks = [
        ("hazards/a_b_c_.txt", b"illegal-chars".as_slice()),
        ("hazards/_CON.txt", b"reserved-con".as_slice()),
        ("hazards/_NUL", b"reserved-nul".as_slice()),
        ("hazards/trailing", b"trailing-dot-space".as_slice()),
        (long_path.as_str(), b"long-path-ok".as_slice()),
    ];
    for (rel, exp) in checks {
        let p = dandi_core::platform::to_fs_path(&out.join(rel));
        let got = fs::read(&p).map_err(|e| format!("missing sanitized '{rel}': {e}"))?;
        if got != exp {
            return Err(format!("content mismatch for sanitized '{rel}'"));
        }
    }

    Ok(format!(
        "all 5 Windows hazards (illegal chars, CON/NUL, trailing dot/space, {}-char path) sanitized & extracted cleanly",
        long_path.len()
    ))
}

fn check_sec_05() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;
    let mut e1 = RawZipSpec::file(b"docs/Readme.md".to_vec(), b"version-one".to_vec());
    e1.flags = 0x0800;
    let mut e2 = RawZipSpec::file(b"docs/README.md".to_vec(), b"version-two".to_vec());
    e2.flags = 0x0800;

    let zip_path = tmp.path().join("collision.zip");
    write_raw_zip(&zip_path, &[e1, e2])?;

    let out = tmp.path().join("out");
    let urep = unpack(
        &zip_path,
        &out,
        &UnpackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;
    if urep.files_extracted != 2 || urep.renamed_collisions.len() != 1 {
        return Err(format!(
            "expected 2 files & 1 collision rename, got files={}, renames={:?}",
            urep.files_extracted, urep.renamed_collisions
        ));
    }
    let a = fs::read(out.join("docs/Readme.md")).map_err(|e| e.to_string())?;
    let b = fs::read(out.join("docs/README (2).md")).map_err(|e| e.to_string())?;
    if a != b"version-one" || b != b"version-two" {
        return Err("collision-disambiguated file contents mismatched".to_string());
    }

    Ok("Readme.md + README.md both preserved via deterministic 'README (2).md' rename".to_string())
}

fn check_sec_06() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;

    // 1. Truncated ZIP
    let valid_zip = tmp.path().join("good.zip");
    let mut spec = RawZipSpec::file(b"file.txt".to_vec(), b"some test data".repeat(200));
    spec.flags = 0x0800;
    write_raw_zip(&valid_zip, &[spec])?;
    let raw_bytes = fs::read(&valid_zip).map_err(|e| e.to_string())?;
    let trunc_zip = tmp.path().join("truncated.zip");
    fs::write(&trunc_zip, &raw_bytes[..raw_bytes.len() / 2]).map_err(|e| e.to_string())?;

    let r1 = unpack(
        &trunc_zip,
        &tmp.path().join("trunc_out"),
        &UnpackOptions::default(),
        &NoopProgressObserver,
    );
    if !matches!(r1, Err(DandiError::CorruptArchive(_))) {
        return Err(format!(
            "truncated ZIP did not return CorruptArchive: {r1:?}"
        ));
    }

    // 2. Bad CRC32 entry
    let bad_crc_zip = tmp.path().join("bad_crc.zip");
    let mut bad_spec = RawZipSpec::file(b"corrupt.txt".to_vec(), b"crc32 check data".to_vec());
    bad_spec.flags = 0x0800;
    bad_spec.override_crc = Some(0x1234_5678);
    write_raw_zip(&bad_crc_zip, &[bad_spec])?;

    let bad_out = tmp.path().join("bad_crc_out");
    let r2 = unpack(
        &bad_crc_zip,
        &bad_out,
        &UnpackOptions::default(),
        &NoopProgressObserver,
    );
    if !matches!(r2, Err(DandiError::CorruptArchive(_))) {
        return Err(format!(
            "bad CRC32 ZIP did not return CorruptArchive: {r2:?}"
        ));
    }
    if bad_out.exists() {
        return Err("partial output directory remained after bad CRC32 error".to_string());
    }

    Ok("truncated ZIP & bad CRC32 returned CorruptArchive with clean rollback".to_string())
}

fn check_perf_01() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;
    let src_dir = tmp.path().join("perf_text");
    fs::create_dir_all(&src_dir).map_err(|e| e.to_string())?;

    // 200 mixed text/JSON/code files totaling ~50 MB (250 KB each).
    let file_count = 200usize;
    let target_per_file = 250_000usize;
    let mut total_bytes = 0u64;
    let mut samples: Vec<Vec<u8>> = Vec::with_capacity(file_count);

    for i in 0..file_count {
        let mut buf = Vec::with_capacity(target_per_file + 512);
        let mut line_idx = 0usize;
        while buf.len() < target_per_file {
            let line = format!(
                "{{\"id\":{i},\"row\":{line_idx},\"module\":\"dandi_core::archive::zip_io\",\"status\":\"ok\",\"msg\":\"cross-os NFC filename encoding & parallel deflate benchmark\"}}\n"
            );
            buf.extend_from_slice(line.as_bytes());
            line_idx += 1;
        }
        let ext = match i % 3 {
            0 => "json",
            1 => "rs",
            _ => "txt",
        };
        fs::write(src_dir.join(format!("mod_{i:03}.{ext}")), &buf).map_err(|e| e.to_string())?;
        total_bytes += buf.len() as u64;
        samples.push(buf);
    }

    // Single-threaded Deflate baseline (level 6).
    let t_base = Instant::now();
    for data in &samples {
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::new(6));
        enc.write_all(data).map_err(|e| e.to_string())?;
        let _ = enc.finish().map_err(|e| e.to_string())?;
    }
    let base_secs = t_base.elapsed().as_secs_f64().max(1e-6);
    let base_mb_s = (total_bytes as f64 / 1_000_000.0) / base_secs;

    // Parallel Dandi pack (level 6).
    let zip_path = tmp.path().join("perf_parallel.zip");
    let t_par = Instant::now();
    let prep = pack(
        &[src_dir],
        &zip_path,
        &PackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;
    let par_secs = t_par.elapsed().as_secs_f64().max(1e-6);
    let par_mb_s = (total_bytes as f64 / 1_000_000.0) / par_secs;

    if prep.files_deflated != file_count {
        return Err(format!(
            "expected {file_count} deflated files, got {}",
            prep.files_deflated
        ));
    }

    if par_mb_s < 80.0 {
        return Err(format!(
            "parallel deflate throughput {par_mb_s:.1} MB/s < 80.0 MB/s (single-thread baseline: {base_mb_s:.1} MB/s)"
        ));
    }
    if par_mb_s <= base_mb_s {
        return Err(format!(
            "parallel pack ({par_mb_s:.1} MB/s) was not faster than single-threaded baseline ({base_mb_s:.1} MB/s)"
        ));
    }

    Ok(format!(
        "{par_mb_s:.1} MB/s parallel vs {base_mb_s:.1} MB/s single-thread ({:.2}x speedup, {:.1} MB -> {:.1} MB)",
        par_mb_s / base_mb_s,
        total_bytes as f64 / 1_000_000.0,
        prep.output_bytes as f64 / 1_000_000.0
    ))
}

fn check_perf_02() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;
    let media_dir = tmp.path().join("media");
    fs::create_dir_all(&media_dir).map_err(|e| e.to_string())?;

    let files = [
        ("photo_01.jpg", 10_000_000usize, 1u64),
        ("photo_02.png", 10_000_000usize, 2u64),
        ("clip_01.mp4", 15_000_000usize, 3u64),
        ("clip_02.mp4", 15_000_000usize, 4u64),
    ];
    let mut total_bytes = 0u64;
    for (name, len, seed) in files {
        let data = fill_pseudo_random(len, seed);
        fs::write(media_dir.join(name), &data).map_err(|e| e.to_string())?;
        total_bytes += len as u64;
    }

    let zip_path = tmp.path().join("media.zip");
    let start = Instant::now();
    let prep = pack(
        &[media_dir],
        &zip_path,
        &PackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;
    let elapsed = start.elapsed().as_secs_f64().max(1e-6);
    let mb_s = (total_bytes as f64 / 1_000_000.0) / elapsed;

    // Verify every file entry was Stored (Method 0).
    let headers = inspect_zip_raw_headers(&zip_path).map_err(|e| e.to_string())?;
    for h in &headers {
        if h.compression_method != 0 {
            return Err(format!(
                "media entry used method {} instead of Method 0 Store",
                h.compression_method
            ));
        }
    }

    let overhead_pct =
        ((prep.output_bytes as f64 - total_bytes as f64) / total_bytes as f64) * 100.0;
    if overhead_pct > 0.5 {
        return Err(format!("Smart Store overhead {overhead_pct:.3}% > 0.5%"));
    }
    if mb_s < 250.0 {
        return Err(format!(
            "Smart Store throughput {mb_s:.1} MB/s < 250.0 MB/s"
        ));
    }

    Ok(format!(
        "Method 0 Store automatic: {mb_s:.1} MB/s, overhead {overhead_pct:.4}%"
    ))
}

fn check_perf_03() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;
    let src_dir = tmp.path().join("unpack_bench");
    fs::create_dir_all(&src_dir).map_err(|e| e.to_string())?;

    // 50 MB across 50 files of mixed compressible data.
    let mut total_bytes = 0u64;
    let unit = b"Dandi streaming extraction throughput benchmark line 0123456789abcdef\n";
    let one_mb: Vec<u8> = unit.iter().copied().cycle().take(1_000_000).collect();
    for i in 0..50usize {
        fs::write(src_dir.join(format!("chunk_{i:02}.log")), &one_mb).map_err(|e| e.to_string())?;
        total_bytes += one_mb.len() as u64;
    }

    let zip_path = tmp.path().join("bench50.zip");
    pack(
        &[src_dir],
        &zip_path,
        &PackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;

    let out_dir = tmp.path().join("out");
    let start = Instant::now();
    let urep = unpack(
        &zip_path,
        &out_dir,
        &UnpackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;
    let elapsed = start.elapsed().as_secs_f64().max(1e-6);
    let mb_s = (total_bytes as f64 / 1_000_000.0) / elapsed;

    if urep.files_extracted != 50 {
        return Err(format!(
            "expected 50 files extracted, got {}",
            urep.files_extracted
        ));
    }
    if mb_s < 150.0 {
        return Err(format!("extraction throughput {mb_s:.1} MB/s < 150.0 MB/s"));
    }

    Ok(format!(
        "streaming unpack {mb_s:.1} MB/s (50 MB across 50 files, bounded 256 KiB I/O buffers)"
    ))
}

fn check_ux_01() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;

    // 1. Single-root archive -> NO `foo/foo/` double wrap
    let single_src = tmp.path().join("project_alpha");
    fs::create_dir_all(&single_src).map_err(|e| e.to_string())?;
    fs::write(single_src.join("main.rs"), b"fn main() {}").map_err(|e| e.to_string())?;
    let single_zip = tmp.path().join("project_alpha.zip");
    pack(
        &[single_src],
        &single_zip,
        &PackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;

    let dest = tmp.path().join("workspace");
    fs::create_dir_all(&dest).map_err(|e| e.to_string())?;
    let r1 = unpack(
        &single_zip,
        &dest,
        &UnpackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;
    if !dest.join("project_alpha/main.rs").exists()
        || dest.join("project_alpha/project_alpha").exists()
    {
        return Err(format!(
            "single-root smart extraction failed (output_dir={})",
            r1.output_dir.display()
        ));
    }

    // 2. Existing folder collision -> extracted to `project_alpha (2)` without clobbering!
    let r2 = unpack(
        &single_zip,
        &dest,
        &UnpackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;
    if !dest.join("project_alpha (2)/main.rs").exists() {
        return Err(format!(
            "existing folder collision not handled cleanly (output_dir={})",
            r2.output_dir.display()
        ));
    }

    // 3. Multi-root tarbomb -> auto-wrapped in `<archive_stem>/`
    let bomb_zip = tmp.path().join("loose_bundle.zip");
    let specs: Vec<RawZipSpec> = (0..10)
        .map(|i| {
            let mut s = RawZipSpec::file(format!("loose_{i}.txt").into_bytes(), b"loose".to_vec());
            s.flags = 0x0800;
            s
        })
        .collect();
    write_raw_zip(&bomb_zip, &specs)?;

    let r3 = unpack(
        &bomb_zip,
        &dest,
        &UnpackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;
    if dest.join("loose_0.txt").exists() || !dest.join("loose_bundle/loose_0.txt").exists() {
        return Err(format!(
            "tarbomb was not auto-wrapped inside loose_bundle/ (output_dir={})",
            r3.output_dir.display()
        ));
    }

    Ok("single-root no double-wrap, existing folder collision -> ' (2)', multi-root tarbomb auto-wrapped".to_string())
}

fn check_ux_02() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;
    let src_dir = tmp.path().join("cancel_src");
    fs::create_dir_all(&src_dir).map_err(|e| e.to_string())?;

    // Create a large single 64 MiB compressible file so streaming pack & unpack take > 80ms
    // and check cancellation frequently inside the 256 KiB chunk loop.
    let big_file = src_dir.join("large_stream.txt");
    {
        let mut f = File::create(&big_file).map_err(|e| e.to_string())?;
        let chunk = b"cancellation latency benchmark payload line 0123456789abcdef\n".repeat(1024);
        for _ in 0..1000 {
            f.write_all(&chunk).map_err(|e| e.to_string())?;
        }
    }

    // 1. Mid-pack cancellation
    let cancel_pack = CancellationToken::new();
    let cp_clone = cancel_pack.clone();
    let cancel_at = Instant::now();
    let handle = thread::spawn(move || {
        thread::sleep(Duration::from_millis(20));
        cp_clone.cancel();
    });
    let out_zip = tmp.path().join("cancelled.zip");
    let pack_res = pack(
        std::slice::from_ref(&src_dir),
        &out_zip,
        &PackOptions {
            cancel: cancel_pack,
            compression_level: 9,
            ..PackOptions::default()
        },
        &NoopProgressObserver,
    );
    let _ = handle.join();
    let pack_stop_ms = cancel_at
        .elapsed()
        .saturating_sub(Duration::from_millis(20))
        .as_millis();
    if !matches!(pack_res, Err(DandiError::Cancelled)) {
        return Err(format!("expected pack Cancelled, got {pack_res:?}"));
    }
    if pack_stop_ms >= 200 {
        return Err(format!("pack cancellation took {pack_stop_ms}ms >= 200ms"));
    }
    // Verify zero orphan .dandi-tmp-*.zip or partial output files remain.
    for entry in fs::read_dir(tmp.path()).map_err(|e| e.to_string())? {
        let name = entry
            .map_err(|e| e.to_string())?
            .file_name()
            .to_string_lossy()
            .into_owned();
        if name.starts_with(".dandi-tmp-") || name == "cancelled.zip" {
            return Err(format!("orphan temp/partial pack file left behind: {name}"));
        }
    }

    // 2. Pack cleanly, then test mid-unpack cancellation
    let full_zip = tmp.path().join("full.zip");
    pack(
        &[src_dir],
        &full_zip,
        &PackOptions::default(),
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;

    let cancel_unpack = CancellationToken::new();
    let cu_clone = cancel_unpack.clone();
    let u_start = Instant::now();
    let u_handle = thread::spawn(move || {
        thread::sleep(Duration::from_millis(10));
        cu_clone.cancel();
    });
    let unpack_dest = tmp.path().join("cancelled_unpack");
    let unpack_res = unpack(
        &full_zip,
        &unpack_dest,
        &UnpackOptions {
            cancel: cancel_unpack,
            ..UnpackOptions::default()
        },
        &NoopProgressObserver,
    );
    let _ = u_handle.join();
    let unpack_stop_ms = u_start
        .elapsed()
        .saturating_sub(Duration::from_millis(10))
        .as_millis();

    // If unpack finished faster than 10ms on very fast NVMe, also test pre-cancelled token cleanly.
    if unpack_res.is_ok() {
        let pre_cancel = CancellationToken::new();
        pre_cancel.cancel();
        let d2 = tmp.path().join("pre_cancelled_unpack");
        let r2 = unpack(
            &full_zip,
            &d2,
            &UnpackOptions {
                cancel: pre_cancel,
                ..UnpackOptions::default()
            },
            &NoopProgressObserver,
        );
        if !matches!(r2, Err(DandiError::Cancelled)) || d2.exists() {
            return Err(format!("pre-cancelled unpack failed cleanup: {r2:?}"));
        }
    } else {
        if !matches!(unpack_res, Err(DandiError::Cancelled)) {
            return Err(format!("expected unpack Cancelled, got {unpack_res:?}"));
        }
        if unpack_stop_ms >= 200 {
            return Err(format!(
                "unpack cancellation took {unpack_stop_ms}ms >= 200ms"
            ));
        }
        if unpack_dest.exists() {
            return Err(
                "partial extraction directory remained after unpack cancellation".to_string(),
            );
        }
    }

    Ok(format!(
        "pack cancelled in {pack_stop_ms}ms & unpack cancelled cleanly with zero orphan files"
    ))
}

fn check_ux_03() -> Result<String, String> {
    let tmp = TempDir::new().map_err(|e| e.to_string())?;

    // Build a ZIP with 20 files inside implicit directories (NO explicit `dir/` entries!).
    let specs: Vec<RawZipSpec> = (0..20)
        .map(|i| {
            let folder = if i < 10 {
                "implicit_a/sub"
            } else {
                "implicit_b"
            };
            let name = format!("{folder}/file_{i:02}.txt");
            let mut s = RawZipSpec::file(name.into_bytes(), format!("val-{i}").into_bytes());
            s.flags = 0x0800;
            s
        })
        .collect();
    let zip_path = tmp.path().join("implicit_dirs.zip");
    write_raw_zip(&zip_path, &specs)?;

    let summary = inspect(&zip_path, &InspectOptions::default()).map_err(|e| e.to_string())?;
    let synth_dirs: HashSet<String> = summary
        .entries
        .iter()
        .filter(|e| e.is_synthesized && e.kind == EntryKind::Directory)
        .map(|e| e.path.clone())
        .collect();
    for expected_dir in ["implicit_a/", "implicit_a/sub/", "implicit_b/"] {
        if !synth_dirs.contains(expected_dir) {
            return Err(format!(
                "missing synthesized implicit dir '{expected_dir}' (got {synth_dirs:?})"
            ));
        }
    }

    // Selective extraction: extract only indices 3 and 17 out of 20.
    let mut selected = HashSet::new();
    selected.insert(3usize);
    selected.insert(17usize);

    let out = tmp.path().join("selected_out");
    let urep = unpack(
        &zip_path,
        &out,
        &UnpackOptions {
            mode: ExtractMode::Direct,
            selected_entries: Some(selected),
            ..UnpackOptions::default()
        },
        &NoopProgressObserver,
    )
    .map_err(|e| e.to_string())?;

    let extracted = hash_directory(&out)?;
    if urep.files_extracted != 2 || extracted.len() != 2 {
        return Err(format!(
            "expected exactly 2 selected files, got report={}, disk={:?}",
            urep.files_extracted,
            extracted.keys().collect::<Vec<_>>()
        ));
    }
    if !extracted.contains_key("implicit_a/sub/file_03.txt")
        || !extracted.contains_key("implicit_b/file_17.txt")
    {
        return Err(format!(
            "wrong selected files extracted: {:?}",
            extracted.keys().collect::<Vec<_>>()
        ));
    }

    Ok(
        "synthesized 3 implicit directories in inspect & selectively extracted exact 2/20 files"
            .to_string(),
    )
}
