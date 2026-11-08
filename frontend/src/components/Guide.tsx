import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { BookOpen, AlertTriangle, ChevronRight } from "lucide-react";
import { get } from "../lib/api";
import { Panel, CopyButton } from "./ui";

// Reusable operational-guide browser: lists guides for a workspace, opens one,
// renders sections with copyable parameterized commands and warning callouts.
export function GuideBrowser({ workspace }: { workspace: string }) {
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<string | null>(null);
  const list = useQuery({ queryKey: ["guides", q], queryFn: () => get(`/ops/guides?q=${encodeURIComponent(q)}`) });
  const items = (list.data?.items || []).filter((g: any) => g.workspace === workspace);

  if (sel) return <GuideView id={sel} onBack={() => setSel(null)} />;

  return (
    <Panel title="Operational guides" actions={
      <input className="input h-7 w-48 text-xs" placeholder="Search guides…" value={q} onChange={(e) => setQ(e.target.value)} />
    }>
      {items.length === 0
        ? <div className="p-4 text-sm text-ink-faint">No guides match.</div>
        : <div className="divide-y divide-line">
            {items.map((g: any) => (
              <button key={g.id} className="w-full text-left p-3 row-hover flex items-start gap-2" onClick={() => setSel(g.id)}>
                <BookOpen className="h-4 w-4 text-ink-faint mt-0.5 shrink-0" />
                <span className="min-w-0">
                  <span className="text-sm font-medium flex items-center gap-1">{g.title}<ChevronRight className="h-3.5 w-3.5 text-ink-faint" /></span>
                  <span className="text-xs text-ink-dim">{g.summary}</span>
                </span>
              </button>
            ))}
          </div>}
    </Panel>
  );
}

export function GuideView({ id, onBack }: { id: string; onBack?: () => void }) {
  const { data: g } = useQuery({ queryKey: ["guide", id], queryFn: () => get(`/ops/guides/${id}`) });
  if (!g) return <div className="p-4 text-sm text-ink-faint">Loading…</div>;
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        {onBack && <button className="btn btn-sm" onClick={onBack}>← Guides</button>}
        <h2 className="text-sm font-semibold">{g.title}</h2>
      </div>
      <p className="text-sm text-ink-dim">{g.summary}</p>
      {(g.warnings || []).length > 0 && (
        <div className="rounded-md border border-warn/30 bg-warn/5 p-3 space-y-1">
          {g.warnings.map((w: string, i: number) => (
            <div key={i} className="flex gap-2 text-xs text-ink-dim"><AlertTriangle className="h-3.5 w-3.5 text-warn shrink-0 mt-0.5" /><span>{w}</span></div>
          ))}
        </div>
      )}
      {g.sections.map((s: any, i: number) => (
        <Panel key={i} title={s.heading}>
          <div className="p-3 space-y-2">
            {s.body && <p className="text-sm text-ink-dim leading-relaxed">{s.body}</p>}
            {(s.commands || []).map((c: any, j: number) => (
              <div key={j} className={`well rounded-md p-2 ${c.danger ? "border border-bad/30" : ""}`}>
                <div className="flex items-start gap-2">
                  <code className="mono text-xs text-ink flex-1 whitespace-pre-wrap break-words">{c.cmd}</code>
                  <CopyButton text={c.cmd} />
                </div>
                {c.note && <div className="text-2xs text-ink-faint mt-1">{c.danger && <span className="text-bad font-semibold">Destructive. </span>}{c.note}</div>}
              </div>
            ))}
          </div>
        </Panel>
      ))}
    </div>
  );
}
