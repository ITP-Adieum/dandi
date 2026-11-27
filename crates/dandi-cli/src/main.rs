use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use dandi_core::{
    inspect, pack, repack_nfc, unpack, DandiError, EncodingId, EntryKind, ExtractMode,
    InspectOptions, NoopProgressObserver, PackOptions, RepackOptions, UnpackOptions, UnpackWarning,
};

#[derive(Parser)]
#[command(
    name = "dandi",
    version,
    about = "Fast, cross-OS archiver that never breaks filenames"
)]
struct Cli {
    /// Emit machine-readable JSON output
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CliExtractMode {
    Smart,
    Direct,
    Wrap,
}

impl From<CliExtractMode> for ExtractMode {
    fn from(m: CliExtractMode) -> Self {
        match m {
            CliExtractMode::Smart => ExtractMode::Smart,
            CliExtractMode::Direct => ExtractMode::Direct,
            CliExtractMode::Wrap => ExtractMode::Wrap,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Pack files or directories into a cross-OS NFC UTF-8 Golden ZIP
    Pack {
        /// Files or directories to pack
        #[arg(required = true)]
        inputs: Vec<PathBuf>,

        /// Output .zip path
        #[arg(short, long)]
        output: PathBuf,

        /// Deflate compression level (0-9)
        #[arg(short, long, default_value_t = 6)]
        level: u32,

        /// Optional password for WinZip AES-256 encryption
        #[arg(short, long)]
        password: Option<String>,

        /// Keep OS metadata junk (.DS_Store, ._*, Thumbs.db, etc.)
        #[arg(long)]
        keep_junk: bool,
    },

    /// Unpack a ZIP, 7z, or TAR archive safely
    Unpack {
        /// Archive path
        archive: PathBuf,

        /// Destination directory (defaults to current directory)
        #[arg(short, long, default_value = ".")]
        dest: PathBuf,

        /// Extraction layout mode
        #[arg(short, long, value_enum, default_value_t = CliExtractMode::Smart)]
        mode: CliExtractMode,

        /// Override detected filename encoding (e.g. cp949, shift_jis, gb18030, big5)
        #[arg(short, long)]
        encoding: Option<String>,

        /// Password for encrypted archives
        #[arg(short, long)]
        password: Option<String>,

        /// Keep OS metadata junk entries
        #[arg(long)]
        keep_junk: bool,

        /// Selective extraction: comma-separated entry indices or exact entry paths
        #[arg(long, value_delimiter = ',')]
        select: Option<Vec<String>>,

        /// Overwrite existing target folders/files
        #[arg(long)]
        overwrite: bool,
    },

    /// List archive entries
    List {
        /// Archive path
        archive: PathBuf,

        /// Override detected filename encoding
        #[arg(short, long)]
        encoding: Option<String>,

        /// Password for encrypted archives
        #[arg(short, long)]
        password: Option<String>,

        /// Include OS metadata junk entries
        #[arg(long)]
        keep_junk: bool,
    },

    /// Inspect archive metadata, format, encoding detection, and entry tree
    Inspect {
        /// Archive path
        archive: PathBuf,

        /// Override detected filename encoding
        #[arg(short, long)]
        encoding: Option<String>,

        /// Password for encrypted archives
        #[arg(short, long)]
        password: Option<String>,

        /// Include OS metadata junk entries
        #[arg(long)]
        keep_junk: bool,
    },

    /// Repair a legacy CP949/Shift_JIS/GBK or macOS NFD ZIP into a clean NFC UTF-8 ZIP
    Fix {
        /// Source ZIP archive
        source: PathBuf,

        /// Destination repaired ZIP archive
        #[arg(short, long)]
        output: PathBuf,

        /// Override detected source filename encoding
        #[arg(short, long)]
        encoding: Option<String>,

        /// Password if source ZIP is encrypted
        #[arg(short, long)]
        password: Option<String>,

        /// Keep OS metadata junk entries
        #[arg(long)]
        keep_junk: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn parse_encoding(opt: Option<String>) -> Result<Option<EncodingId>, DandiError> {
    opt.map(|s| EncodingId::from_name(&s)).transpose()
}

fn run(cli: Cli) -> Result<(), DandiError> {
    let observer = NoopProgressObserver;

    match cli.command {
        Commands::Pack {
            inputs,
            output,
            level,
            password,
            keep_junk,
        } => {
            let opts = PackOptions {
                compression_level: level,
                exclude_os_junk: !keep_junk,
                password,
                overwrite: true,
                ..PackOptions::default()
            };
            let report = pack(&inputs, &output, &opts, &observer)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "Packed {} entries ({} deflated, {} stored, {} junk skipped) -> {} ({} bytes)",
                    report.entries_written,
                    report.files_deflated,
                    report.files_stored,
                    report.junk_skipped,
                    report.output_path.display(),
                    report.output_bytes
                );
            }
        }
        Commands::Unpack {
            archive,
            dest,
            mode,
            encoding,
            password,
            keep_junk,
            select,
            overwrite,
        } => {
            let enc = parse_encoding(encoding)?;
            let selected_entries = match select {
                Some(items) => Some(resolve_selection(
                    &archive,
                    enc,
                    password.as_deref(),
                    &items,
                )?),
                None => None,
            };
            let opts = UnpackOptions {
                mode: mode.into(),
                encoding_override: enc,
                password,
                selected_entries,
                exclude_os_junk: !keep_junk,
                overwrite,
                ..UnpackOptions::default()
            };
            let report = unpack(&archive, &dest, &opts, &observer)?;
            if cli.json {
                print_json(&report)?;
            } else {
                let mut extras = Vec::new();
                if report.symlinks_skipped > 0 {
                    extras.push(format!("{} symlinks skipped", report.symlinks_skipped));
                }
                if !report.warnings.is_empty() {
                    extras.push(format!("{} warning(s)", report.warnings.len()));
                }
                let extra_suffix = if extras.is_empty() {
                    String::new()
                } else {
                    format!(", {}", extras.join(", "))
                };
                println!(
                    "Unpacked {} files, {} dirs, {} symlinks{} (encoding: {}) -> {}",
                    report.files_extracted,
                    report.dirs_created,
                    report.symlinks_created,
                    extra_suffix,
                    report.applied_encoding.canonical_name(),
                    report.output_dir.display()
                );
                for w in &report.warnings {
                    match w {
                        UnpackWarning::SymlinkSkipped {
                            path,
                            target,
                            reason,
                        } => eprintln!("warning: skipped symlink '{path}' -> '{target}': {reason}"),
                        UnpackWarning::PermissionApplyFailed { path, reason } => {
                            eprintln!("warning: failed to apply permissions on '{path}': {reason}")
                        }
                        UnpackWarning::MtimeApplyFailed { path, reason } => {
                            eprintln!("warning: failed to set mtime on '{path}': {reason}")
                        }
                        UnpackWarning::ZoneIdPropagateFailed { path, reason } => {
                            eprintln!(
                                "warning: failed to propagate Zone.Identifier on '{path}': {reason}"
                            )
                        }
                    }
                }
            }
        }
        Commands::List {
            archive,
            encoding,
            password,
            keep_junk,
        } => {
            let opts = InspectOptions {
                encoding_override: parse_encoding(encoding)?,
                password,
                include_os_junk: keep_junk,
                ..InspectOptions::default()
            };
            let summary = inspect(&archive, &opts)?;
            if cli.json {
                print_json(&summary.entries)?;
            } else {
                for entry in &summary.entries {
                    let kind = match entry.kind {
                        EntryKind::Directory => "d",
                        EntryKind::Symlink => "l",
                        EntryKind::File => "-",
                    };
                    let idx = entry
                        .index
                        .map(|i| format!("{i:>5}"))
                        .unwrap_or_else(|| "    -".to_string());
                    println!(
                        "{idx} {kind} {:>10}  {}",
                        entry.uncompressed_size, entry.path
                    );
                }
            }
        }
        Commands::Inspect {
            archive,
            encoding,
            password,
            keep_junk,
        } => {
            let opts = InspectOptions {
                encoding_override: parse_encoding(encoding)?,
                password,
                include_os_junk: keep_junk,
                ..InspectOptions::default()
            };
            let summary = inspect(&archive, &opts)?;
            if cli.json {
                print_json(&summary)?;
            } else {
                println!("Format:   {}", summary.format.display_name());
                println!(
                    "Encoding: {} (detected {} @ {:.0}%)",
                    summary.applied_encoding.canonical_name(),
                    summary.encoding.encoding.canonical_name(),
                    summary.encoding.confidence * 100.0
                );
                println!("Entries:  {}", summary.total_entries);
                println!("Size:     {} bytes", summary.total_uncompressed_bytes);
                for entry in &summary.entries {
                    let tag = if entry.is_synthesized { " [dir]" } else { "" };
                    println!("  {}{}", entry.path, tag);
                }
            }
        }
        Commands::Fix {
            source,
            output,
            encoding,
            password,
            keep_junk,
        } => {
            let opts = RepackOptions {
                encoding_override: parse_encoding(encoding)?,
                password,
                exclude_os_junk: !keep_junk,
                overwrite: true,
                ..RepackOptions::default()
            };
            let report = repack_nfc(&source, &output, &opts, &observer)?;
            if cli.json {
                print_json(&report)?;
            } else {
                println!(
                    "Repacked {} entries (source encoding: {}, {} junk skipped) -> {}",
                    report.entries_repacked,
                    report.source_encoding.canonical_name(),
                    report.junk_skipped,
                    report.output_path.display()
                );
            }
        }
    }

    Ok(())
}

fn resolve_selection(
    archive: &Path,
    encoding: Option<EncodingId>,
    password: Option<&str>,
    selectors: &[String],
) -> Result<HashSet<usize>, DandiError> {
    let mut selected = HashSet::new();
    let mut name_selectors: HashSet<String> = HashSet::new();

    for item in selectors {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(idx) = trimmed.parse::<usize>() {
            selected.insert(idx);
        } else {
            name_selectors.insert(trimmed.trim_end_matches('/').to_string());
        }
    }

    if !name_selectors.is_empty() {
        let summary = inspect(
            archive,
            &InspectOptions {
                encoding_override: encoding,
                password: password.map(ToString::to_string),
                include_os_junk: true,
                ..InspectOptions::default()
            },
        )?;
        for entry in summary.entries {
            if let Some(idx) = entry.index {
                let norm = entry.path.trim_end_matches('/');
                if name_selectors.contains(norm) {
                    selected.insert(idx);
                }
            }
        }
    }

    Ok(selected)
}

fn print_json<T: serde::Serialize>(val: &T) -> Result<(), DandiError> {
    let text =
        serde_json::to_string_pretty(val).map_err(|e| DandiError::ArchiveEngine(e.to_string()))?;
    println!("{text}");
    Ok(())
}
