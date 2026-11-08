import { ReactNode, useState } from "react";
import { Check, Copy, Loader2 } from "lucide-react";

export function Badge({ className = "", children }: { className?: string; children: ReactNode }) {
  return <span className={`tag ${className}`}>{children}</span>;
}

export function Dot({ className = "" }: { className?: string }) {
  return <span className={`inline-block h-2 w-2 rounded-full ${className}`} />;
}

export function Spinner({ className = "" }: { className?: string }) {
  return <Loader2 className={`h-4 w-4 animate-spin text-ink-faint ${className}`} />;
}

export function Panel({ title, actions, children, className = "", bodyClass = "" }: {
  title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; bodyClass?: string;
}) {
  return (
    <section className={`panel flex flex-col min-h-0 ${className}`}>
      {(title || actions) && (
        <header className="flex items-center justify-between px-3 h-10 border-b border-line shrink-0">
          <h2 className="text-sm font-semibold text-ink">{title}</h2>
          <div className="flex items-center gap-1.5">{actions}</div>
        </header>
      )}
      <div className={`min-h-0 ${bodyClass}`}>{children}</div>
    </section>
  );
}

export function EmptyState({ icon, title, hint, action }: {
  icon?: ReactNode; title: string; hint?: ReactNode; action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-14 px-6 gap-2">
      {icon && <div className="text-ink-faint mb-1">{icon}</div>}
      <div className="text-sm font-medium text-ink">{title}</div>
      {hint && <div className="text-xs text-ink-dim max-w-md leading-relaxed">{hint}</div>}
      {action && <div className="mt-3">{action}</div>}
    </div>
  );
}

export function CopyButton({ text, label }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      className="btn btn-ghost btn-sm text-ink-dim"
      title="Copy"
      onClick={() => {
        navigator.clipboard.writeText(text).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        });
      }}
    >
      {done ? <Check className="h-3.5 w-3.5 text-ok" /> : <Copy className="h-3.5 w-3.5" />}
      {label && <span>{done ? "Copied" : label}</span>}
    </button>
  );
}

// A snippet line carries its TRUE source line number (`n`) and whether it is part
// of the matched span (`hit`). When `sourceLines` is given the gutter shows real
// source numbers; otherwise CodeBlock falls back to numbering a plain string 1..N.
export type SnippetLine = { n: number; text: string; hit?: boolean };

export function CodeBlock({ code, sourceLines, className = "", highlightLines = [], wrap = false, noGutter = false }: {
  code?: string; sourceLines?: SnippetLine[]; className?: string; highlightLines?: number[]; wrap?: boolean; noGutter?: boolean;
}) {
  const rows: SnippetLine[] = sourceLines && sourceLines.length
    ? sourceLines
    : (code ?? "").split("\n").map((text, i) => ({ n: i + 1, text, hit: highlightLines.includes(i + 1) }));
  // Keep the gutter width in step with the largest line number.
  const gw = Math.max(2, String(rows.length ? rows[rows.length - 1].n : 1).length);
  return (
    <pre className={`well mono overflow-auto p-0 text-ink ${className}`}>
      <code className="block">
        {rows.map((r, i) => (
          <div key={i} className={`flex ${r.hit ? "bg-bad/10" : ""}`}>
            {!noGutter && (
              <span className="select-none text-right pr-3 pl-2 text-ink-faint shrink-0 border-r border-line/60"
                style={{ minWidth: `${gw + 1.5}ch` }}>
                {r.n}
              </span>
            )}
            <span className={`pl-3 pr-4 ${wrap ? "whitespace-pre-wrap break-words" : "whitespace-pre"} ${r.hit ? "text-bad" : ""}`}>{r.text || " "}</span>
          </div>
        ))}
      </code>
    </pre>
  );
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <div>
      <label className="label">{label}</label>
      {children}
      {hint && <p className="text-2xs text-ink-faint mt-1">{hint}</p>}
    </div>
  );
}

export function Tabs({ tabs, active, onChange }: {
  tabs: { id: string; label: ReactNode }[]; active: string; onChange: (id: string) => void;
}) {
  return (
    <div className="flex items-center gap-1 border-b border-line px-1">
      {tabs.map((t) => (
        <button
          key={t.id}
          onClick={() => onChange(t.id)}
          className={`px-3 h-9 text-sm font-medium border-b-2 -mb-px transition-colors ${
            active === t.id
              ? "border-accent text-ink"
              : "border-transparent text-ink-dim hover:text-ink"
          }`}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}
