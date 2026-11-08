export function timeAgo(iso?: string | null): string {
  if (!iso) return "-";
  const t = new Date(iso.replace(" ", "T") + (iso.includes("Z") ? "" : "Z")).getTime();
  if (Number.isNaN(t)) return iso;
  const s = Math.floor((Date.now() - t) / 1000);
  if (s < 0) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export const OUTCOME_META: Record<string, { label: string; cls: string; dot: string }> = {
  confirmed: { label: "Confirmed", cls: "border-crit/40 text-crit bg-crit/10", dot: "bg-crit" },
  possible: { label: "Possible", cls: "border-warn/40 text-warn bg-warn/10", dot: "bg-warn" },
  attempted: { label: "Attempted", cls: "border-line-strong text-ink-dim bg-bg-inset", dot: "bg-ink-faint" },
  blocked: { label: "Blocked", cls: "border-ok/30 text-ok bg-ok/10", dot: "bg-ok" },
};

export const SEVERITY_META: Record<string, string> = {
  critical: "border-crit/40 text-crit bg-crit/10",
  high: "border-bad/40 text-bad bg-bad/10",
  medium: "border-warn/40 text-warn bg-warn/10",
  low: "border-line-strong text-ink-dim bg-bg-inset",
};

export const CONFIDENCE_META: Record<string, { label: string; cls: string }> = {
  strong: { label: "Strongly supported", cls: "border-bad/40 text-bad bg-bad/10" },
  potential: { label: "Potential", cls: "border-warn/40 text-warn bg-warn/10" },
  needs_context: { label: "Needs context", cls: "border-accent/40 text-accent bg-accent/10" },
  none: { label: "No match", cls: "border-line-strong text-ink-dim" },
};

export const TECHNIQUE_LABEL: Record<string, string> = {
  sql_injection: "SQL Injection",
  command_injection: "Command Injection",
  path_traversal: "Path Traversal",
  xss: "Cross-Site Scripting",
  ssti: "Template Injection",
  ssrf: "Server-Side Request Forgery",
  lfi_rfi: "File Inclusion",
  deserialization: "Unsafe Deserialization",
  scanner: "Scanner / Recon",
  ids_alert: "IDS Alert",
  other: "Other",
};

export const tech = (c?: string) => (c ? TECHNIQUE_LABEL[c] ?? c : "-");
