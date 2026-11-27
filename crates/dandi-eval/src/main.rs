mod checks;
mod fixtures;
mod windows_bridge;

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use serde::Serialize;

use crate::checks::{run_all_checks, CheckResult, EvalContext};

#[derive(Parser)]
#[command(
    name = "dandi-eval",
    about = "Autonomous 100-point cross-OS evaluation harness for Dandi"
)]
struct Args {
    /// Optional SSH host alias for remote real-Windows verification (also via DANDI_EVAL_WINDOWS_SSH)
    #[arg(long, env = "DANDI_EVAL_WINDOWS_SSH")]
    windows_ssh: Option<String>,

    /// Path to write machine-readable JSON report
    #[arg(long, default_value = "eval-report.json")]
    json_out: PathBuf,

    /// Path to write human-readable Markdown scorecard
    #[arg(long, default_value = "eval-report.md")]
    md_out: PathBuf,

    /// Minimum passing total score (default 95)
    #[arg(long, default_value_t = 95)]
    min_score: u32,
}

#[derive(Serialize)]
struct EvalReport {
    os: String,
    arch: String,
    remote_windows_enabled: bool,
    total_earned: u32,
    total_max: u32,
    category_scores: BTreeMap<String, CategoryScore>,
    gate_passed: bool,
    checks: Vec<CheckResult>,
}

#[derive(Serialize)]
struct CategoryScore {
    earned: u32,
    max: u32,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let ctx = EvalContext {
        windows_ssh: args.windows_ssh.clone(),
    };

    let checks = run_all_checks(&ctx);

    let mut category_scores: BTreeMap<String, CategoryScore> = BTreeMap::new();
    let mut total_earned = 0u32;
    let mut total_max = 0u32;

    for c in &checks {
        total_earned += c.earned_points;
        total_max += c.max_points;
        let entry = category_scores
            .entry(c.category.clone())
            .or_insert(CategoryScore { earned: 0, max: 0 });
        entry.earned += c.earned_points;
        entry.max += c.max_points;
    }

    let sec_ok = category_scores
        .get("Security")
        .map(|s| s.earned == s.max)
        .unwrap_or(false);
    let compat_ok = category_scores
        .get("Compatibility")
        .map(|s| s.earned == s.max)
        .unwrap_or(false);
    let gate_passed = sec_ok && compat_ok && total_earned >= args.min_score;

    let report = EvalReport {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        remote_windows_enabled: args.windows_ssh.is_some(),
        total_earned,
        total_max,
        category_scores,
        gate_passed,
        checks,
    };

    let md = render_markdown(&report);
    if let Ok(json) = serde_json::to_string_pretty(&report) {
        if let Err(e) = fs::write(&args.json_out, json) {
            eprintln!("warning: failed to write {}: {e}", args.json_out.display());
        }
    }
    if let Err(e) = fs::write(&args.md_out, &md) {
        eprintln!("warning: failed to write {}: {e}", args.md_out.display());
    }

    println!("{md}");

    if report.gate_passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn render_markdown(report: &EvalReport) -> String {
    let mut out = String::new();
    out.push_str("# Dandi 100-Point Cross-OS Evaluation Scorecard\n\n");
    out.push_str(&format!(
        "- **Runner**: `{}/{}` | **Remote Windows SSH**: `{}`\n",
        report.os,
        report.arch,
        if report.remote_windows_enabled {
            "enabled"
        } else {
            "disabled"
        }
    ));
    out.push_str(&format!(
        "- **Total Score**: **{} / {}** ({})\n\n",
        report.total_earned,
        report.total_max,
        if report.gate_passed { "PASS" } else { "FAIL" }
    ));

    out.push_str("## Category Breakdown\n\n");
    out.push_str("| Category | Earned | Max |\n");
    out.push_str("|---|---:|---:|\n");
    for (cat, score) in &report.category_scores {
        out.push_str(&format!("| {cat} | {} | {} |\n", score.earned, score.max));
    }

    out.push_str("\n## Detailed Results\n\n");
    out.push_str("| ID | Category | Test | Score | Status | Time (ms) | Details |\n");
    out.push_str("|---|---|---|---:|---|---:|---|\n");
    for c in &report.checks {
        let status = if c.passed { "PASS" } else { "FAIL" };
        let clean_details = c.details.replace('|', "\\|").replace('\n', " ");
        out.push_str(&format!(
            "| `{}` | {} | {} | {}/{} | {} | {} | {} |\n",
            c.id,
            c.category,
            c.name,
            c.earned_points,
            c.max_points,
            status,
            c.duration_ms,
            clean_details
        ));
    }

    out
}
