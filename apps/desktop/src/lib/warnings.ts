import type { Dictionary } from "../i18n";
import type { ErrorKind, UnpackReport, UnpackWarning } from "../types";
import type { BannerNotice, FormattedWarningItem } from "./state";

export function formatUnpackWarning(
  warning: UnpackWarning,
  t: Dictionary
): FormattedWarningItem {
  return {
    kind: warning.kind,
    label: t.warningKinds[warning.kind],
    path: warning.path,
    target: warning.kind === "symlink_skipped" ? warning.target : undefined,
    reason: warning.reason,
  };
}

export function buildUnpackNotice(report: UnpackReport, t: Dictionary): BannerNotice {
  const rawWarnings = report.warnings ?? [];
  const symlinksSkipped = report.symlinks_skipped ?? 0;
  const formattedWarnings = rawWarnings.map((w) => formatUnpackWarning(w, t));

  const detailParts: string[] = [];
  if (report.renamed_collisions.length > 0) {
    detailParts.push(t.collisionsRenamed(report.renamed_collisions.length));
  }
  if (symlinksSkipped > 0) {
    detailParts.push(t.symlinksSkippedSummary(symlinksSkipped));
  }
  const detail = detailParts.length > 0 ? detailParts.join(" · ") : undefined;

  const hasWarnings = formattedWarnings.length > 0 || symlinksSkipped > 0;
  if (hasWarnings) {
    const warningCount = Math.max(formattedWarnings.length, symlinksSkipped);
    return {
      tone: "warning",
      title: t.unpackSuccessWithWarnings(report.files_extracted, report.output_dir, warningCount),
      detail,
      revealPath: report.output_dir,
      warnings: formattedWarnings.length > 0 ? formattedWarnings : undefined,
    };
  }

  return {
    tone: "success",
    title: t.unpackSuccess(report.files_extracted, report.output_dir),
    detail,
    revealPath: report.output_dir,
  };
}

export function buildErrorNotice(
  kind: ErrorKind,
  detail: string,
  t: Dictionary
): BannerNotice {
  if (kind === "cancelled") {
    return {
      tone: "info",
      title: t.errors.cancelled,
    };
  }

  return {
    tone: "error",
    title: t.errors[kind] ?? detail,
    detail,
    guidance: kind === "already_exists" ? t.alreadyExistsGuidance : undefined,
  };
}
