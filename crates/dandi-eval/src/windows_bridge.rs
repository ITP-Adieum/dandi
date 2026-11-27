use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct WinExtractVerification {
    pub explorer_files: BTreeMap<String, WinFileInfo>,
    pub expand_archive_files: BTreeMap<String, WinFileInfo>,
    pub explorer_junk_count: usize,
    pub expand_archive_junk_count: usize,
}

#[derive(Debug, Deserialize)]
pub struct WinFileInfo {
    pub sha256: String,
    pub is_nfc: bool,
}

#[derive(Debug, Deserialize)]
pub struct WinGeneratedArchive {
    pub files: BTreeMap<String, String>,
}

/// Encodes a PowerShell script as UTF-16LE Base64 for `-EncodedCommand` (immune to SSH quoting/CP949 console issues).
fn encode_ps_command(script: &str) -> String {
    let utf16: Vec<u8> = script
        .encode_utf16()
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    base64_encode(&utf16)
}

fn run_powershell(windows_ssh: Option<&str>, script: &str) -> Result<String, String> {
    let encoded = encode_ps_command(script);
    let output = match windows_ssh {
        Some(host) => Command::new("ssh")
            .args([
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=15",
                host,
                &format!("powershell -NoProfile -NonInteractive -EncodedCommand {encoded}"),
            ])
            .output()
            .map_err(|e| format!("failed to invoke ssh: {e}"))?,
        None => Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
            .output()
            .map_err(|e| format!("failed to invoke local powershell: {e}"))?,
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!(
            "PowerShell failed (exit {:?}): stderr={stderr} stdout={stdout}",
            output.status.code()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn rand_tag() -> String {
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("dandi-eval-{pid}-{nanos}")
}

/// Verifies a `dandi`-packed ZIP on REAL Windows using BOTH Windows Explorer COM (`Shell.Application`)
/// and PowerShell `Expand-Archive`, either locally (on Windows) or over SSH (`--windows-ssh <alias>`).
pub fn verify_zip_on_windows(
    local_zip: &Path,
    expected_file_count: usize,
    windows_ssh: Option<&str>,
) -> Result<WinExtractVerification, String> {
    let tag = rand_tag();
    let (remote_dir_ps, zip_path_ps) = if let Some(host) = windows_ssh {
        // Resolve remote %TEMP% path cleanly first.
        let remote_temp =
            run_powershell(Some(host), "[System.IO.Path]::GetTempPath().TrimEnd('\\')")?;
        let remote_dir = format!("{remote_temp}\\{tag}");
        run_powershell(
            Some(host),
            &format!("New-Item -ItemType Directory -Path '{remote_dir}' -Force | Out-Null"),
        )?;

        let remote_zip = format!("{remote_dir}\\payload.zip");
        let scp_target = format!("{host}:{}", remote_zip.replace('\\', "/"));
        let status = Command::new("scp")
            .args(["-q", "-o", "BatchMode=yes"])
            .arg(local_zip)
            .arg(&scp_target)
            .status()
            .map_err(|e| format!("failed to invoke scp: {e}"))?;
        if !status.success() {
            let _ = run_powershell(
                Some(host),
                &format!("Remove-Item -LiteralPath '{remote_dir}' -Recurse -Force -ErrorAction SilentlyContinue"),
            );
            return Err(format!(
                "scp upload failed with exit code {:?}",
                status.code()
            ));
        }
        (remote_dir, remote_zip)
    } else {
        let temp_dir = std::env::temp_dir().join(&tag);
        std::fs::create_dir_all(&temp_dir).map_err(|e| e.to_string())?;
        let zip_dst = temp_dir.join("payload.zip");
        std::fs::copy(local_zip, &zip_dst).map_err(|e| e.to_string())?;
        (
            temp_dir.to_string_lossy().into_owned(),
            zip_dst.to_string_lossy().into_owned(),
        )
    };

    let ps_script = format!(
        r#"
$ErrorActionPreference = 'Stop'
$workDir = '{remote_dir_ps}'
$zipPath = '{zip_path_ps}'
$expDir  = Join-Path $workDir 'explorer'
$psDir   = Join-Path $workDir 'expand_archive'
$expectedCount = {expected_file_count}

try {{
    New-Item -ItemType Directory -Path $expDir -Force | Out-Null
    New-Item -ItemType Directory -Path $psDir -Force | Out-Null

    # 1. PowerShell Expand-Archive
    Expand-Archive -LiteralPath $zipPath -DestinationPath $psDir -Force

    # 2. Real Windows Explorer COM (Shell.Application)
    $shell = New-Object -ComObject Shell.Application
    $zipNs = $shell.NameSpace($zipPath)
    $dstNs = $shell.NameSpace($expDir)
    if ($null -eq $zipNs -or $null -eq $dstNs) {{
        throw "Shell.Application NameSpace returned null"
    }}
    $dstNs.CopyHere($zipNs.Items(), 0x14)

    # Shell.Application CopyHere can finalize asynchronously; poll briefly until files land.
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {{
        $cnt = @(Get-ChildItem -LiteralPath $expDir -Recurse -File -Force -ErrorAction SilentlyContinue).Count
        if ($cnt -ge $expectedCount) {{
            Start-Sleep -Milliseconds 250
            break
        }}
        Start-Sleep -Milliseconds 150
    }}

    function Scan-Tree([string]$root) {{
        $files = @{{}}
        $junk = 0
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {{
            $items = Get-ChildItem -LiteralPath $root -Recurse -File -Force
            foreach ($it in $items) {{
                $rel = $it.FullName.Substring($root.Length).TrimStart('\').Replace('\', '/')
                $name = $it.Name
                if ($rel -match '(^|/)__MACOSX(/|$)' -or $name -eq '.DS_Store' -or $name.StartsWith('._') -or $name -ieq 'Thumbs.db' -or $name -ieq 'desktop.ini') {{
                    $junk++
                }}
                $bytes = [System.IO.File]::ReadAllBytes($it.FullName)
                $hashBytes = $sha.ComputeHash($bytes)
                $hashHex = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '').ToLowerInvariant()
                $isNfc = $rel.IsNormalized([System.Text.NormalizationForm]::FormC)
                $files[$rel] = @{{ sha256 = $hashHex; is_nfc = $isNfc }}
            }}
        }} finally {{
            $sha.Dispose()
        }}
        return @{{ files = $files; junk = $junk }}
    }}

    $expRes = Scan-Tree $expDir
    $psRes  = Scan-Tree $psDir
    $payload = @{{
        explorer_files = $expRes.files
        expand_archive_files = $psRes.files
        explorer_junk_count = $expRes.junk
        expand_archive_junk_count = $psRes.junk
    }} | ConvertTo-Json -Depth 6 -Compress

    $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
    [Console]::Out.WriteLine([System.Convert]::ToBase64String($utf8Bytes))
}} finally {{
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}}
"#
    );

    let b64 = run_powershell(windows_ssh, &ps_script)?;
    let json_bytes = base64_decode(&b64)?;
    let json_str = String::from_utf8(json_bytes).map_err(|e| e.to_string())?;
    serde_json::from_str(&json_str)
        .map_err(|e| format!("failed to parse Windows verification JSON: {e} (raw={json_str})"))
}

/// Generates a REAL Windows PowerShell ZIP (UTF-8 / Compress-Archive) AND a REAL Korean CP949 ZIP
/// on Windows, downloads them to `local_ps_zip` and `local_cp949_zip`, and cleans up remote temp dir.
pub fn generate_real_windows_zips(
    local_ps_zip: &Path,
    local_cp949_zip: &Path,
    windows_ssh: Option<&str>,
) -> Result<WinGeneratedArchive, String> {
    let tag = rand_tag();
    let remote_dir = if let Some(host) = windows_ssh {
        let remote_temp =
            run_powershell(Some(host), "[System.IO.Path]::GetTempPath().TrimEnd('\\')")?;
        format!("{remote_temp}\\{tag}")
    } else {
        std::env::temp_dir()
            .join(&tag)
            .to_string_lossy()
            .into_owned()
    };

    // Create sample files with Korean + ASCII names on Windows, pack with Compress-Archive AND CP949 .NET ZipFile.
    let ps_script = format!(
        r##"
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$workDir = '{remote_dir}'
$srcDir  = Join-Path $workDir 'src'
$psZip   = Join-Path $workDir 'win_ps.zip'
$cpZip   = Join-Path $workDir 'win_cp949.zip'

New-Item -ItemType Directory -Path $srcDir -Force | Out-Null
$subDir = Join-Path $srcDir ([string]::Concat([char]0xBCF4, [char]0xACE0, [char]0xC11C, '_', [char]0xBAA8, [char]0xC74C))
New-Item -ItemType Directory -Path $subDir -Force | Out-Null

$f1Name = [string]::Concat([char]0xCD5C, [char]0xC885, '_', [char]0xACC4, [char]0xD68D, [char]0xC11C, '.txt')
$f2Name = [string]::Concat([char]0xAC00, [char]0xB098, [char]0xB2E4, [char]0xB77C, '_', [char]0xD68C, [char]0xC758, [char]0xB85D, '.md')
$f3Name = [string]::Concat([char]0xB2E8, [char]0xB514, '_', [char]0xD14C, [char]0xC2A4, [char]0xD2B8, '.json')

$p1 = Join-Path $subDir $f1Name
$p2 = Join-Path $subDir $f2Name
$p3 = Join-Path $srcDir $f3Name

[System.IO.File]::WriteAllText($p1, "Windows CP949 roundtrip content 1`n", [System.Text.Encoding]::UTF8)
[System.IO.File]::WriteAllText($p2, "# Korean meeting notes from real Windows`n", [System.Text.Encoding]::UTF8)
[System.IO.File]::WriteAllText($p3, '{{"origin":"windows","ok":true}}', [System.Text.Encoding]::UTF8)

# 1. PowerShell Compress-Archive (standard Windows PowerShell ZIP)
Compress-Archive -Path (Join-Path $srcDir '*') -DestinationPath $psZip -Force

# 2. Legacy Korean CP949 ZIP (Bit 11 OFF, exact Windows codepage 949 bytes!)
$cp949 = [System.Text.Encoding]::GetEncoding(949)
[System.IO.Compression.ZipFile]::CreateFromDirectory($srcDir, $cpZip, [System.IO.Compression.CompressionLevel]::Optimal, $false, $cp949)

$sha = [System.Security.Cryptography.SHA256]::Create()
$map = @{{}}
try {{
    foreach ($it in (Get-ChildItem -LiteralPath $srcDir -Recurse -File)) {{
        $rel = $it.FullName.Substring($srcDir.Length).TrimStart('\').Replace('\', '/')
        $bytes = [System.IO.File]::ReadAllBytes($it.FullName)
        $hashHex = ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
        $map[$rel] = $hashHex
    }}
}} finally {{
    $sha.Dispose()
}}

$payload = @{{ files = $map }} | ConvertTo-Json -Depth 4 -Compress
[Console]::Out.WriteLine([System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)))
"##
    );

    let b64 = run_powershell(windows_ssh, &ps_script)?;
    let cleanup = || {
        let _ = run_powershell(
            windows_ssh,
            &format!("Remove-Item -LiteralPath '{remote_dir}' -Recurse -Force -ErrorAction SilentlyContinue"),
        );
    };

    if let Some(host) = windows_ssh {
        let remote_ps_zip = format!("{host}:{}/win_ps.zip", remote_dir.replace('\\', "/"));
        let remote_cp_zip = format!("{host}:{}/win_cp949.zip", remote_dir.replace('\\', "/"));

        let s1 = Command::new("scp")
            .args(["-q", "-o", "BatchMode=yes", &remote_ps_zip])
            .arg(local_ps_zip)
            .status();
        let s2 = Command::new("scp")
            .args(["-q", "-o", "BatchMode=yes", &remote_cp_zip])
            .arg(local_cp949_zip)
            .status();
        cleanup();

        if !s1.map(|s| s.success()).unwrap_or(false) || !s2.map(|s| s.success()).unwrap_or(false) {
            return Err("scp download of Windows-generated ZIPs failed".to_string());
        }
    } else {
        let res1 = std::fs::copy(format!("{remote_dir}\\win_ps.zip"), local_ps_zip);
        let res2 = std::fs::copy(format!("{remote_dir}\\win_cp949.zip"), local_cp949_zip);
        cleanup();
        res1.map_err(|e| e.to_string())?;
        res2.map_err(|e| e.to_string())?;
    }

    let json_bytes = base64_decode(&b64)?;
    let json_str = String::from_utf8(json_bytes).map_err(|e| e.to_string())?;
    serde_json::from_str(&json_str)
        .map_err(|e| format!("failed to parse Windows generated archive JSON: {e}"))
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = [0u8; 4];
    let mut count = 0usize;

    for b in input.bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        let val = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => 64,
            _ => return Err(format!("invalid base64 byte: {b}")),
        };
        buf[count] = val;
        count += 1;
        if count == 4 {
            let v0 = buf[0] as u32;
            let v1 = buf[1] as u32;
            out.push(((v0 << 2) | (v1 >> 4)) as u8);
            if buf[2] != 64 {
                let v2 = buf[2] as u32;
                out.push((((v1 & 0x0F) << 4) | (v2 >> 2)) as u8);
                if buf[3] != 64 {
                    let v3 = buf[3] as u32;
                    out.push((((v2 & 0x03) << 6) | v3) as u8);
                }
            }
            count = 0;
        }
    }
    Ok(out)
}
