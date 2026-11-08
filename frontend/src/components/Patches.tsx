import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { GitCompare, Download, Pencil, Trash2 } from "lucide-react";
import { get, post, put, del } from "../lib/api";
import { useToast } from "../lib/toast";
import { Badge, EmptyState, Panel, Spinner } from "./ui";
import { CodeEditor } from "./CodeEditor";

const STATUS_META: Record<string, string> = {
  suggested: "border-line-strong text-ink-dim", reviewed: "border-accent/40 text-accent bg-accent/10",
  tested: "border-warn/40 text-warn bg-warn/10", applied: "border-accent/40 text-accent bg-accent/10",
  verified: "border-ok/30 text-ok bg-ok/10", rejected: "border-bad/40 text-bad bg-bad/10",
  failed: "border-bad/40 text-bad bg-bad/10", rolled_back: "border-warn/40 text-warn bg-warn/10",
};
const VAL_META: Record<string, string> = {
  pass: "border-ok/30 text-ok bg-ok/10", fail: "border-bad/40 text-bad bg-bad/10",
  na: "border-line-strong text-ink-faint", pending: "border-line-strong text-ink-faint",
};

export function Patches() {
  const [sel, setSel] = useState<number | null>(null);
  const qc = useQueryClient();
  const toast = useToast();
  const list = useQuery({ queryKey: ["patches"], queryFn: () => get("/patches") });
  const [nw, setNw] = useState<any>(null);
  const create = useMutation({
    mutationFn: () => post("/patches", nw),
    onSuccess: (r: any) => { setNw(null); qc.invalidateQueries({ queryKey: ["patches"] }); setSel(r.id); toast("ok", "Patch created"); },
    onError: (e: any) => toast("error", e.message),
  });
  const remove = useMutation({
    mutationFn: (pid: number) => del(`/patches/${pid}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["patches"] }); toast("ok", "Patch deleted"); },
    onError: (e: any) => toast("error", e.message),
  });

  if (sel != null) return <div className="p-5 max-w-5xl"><PatchDetail id={sel} onBack={() => { setSel(null); qc.invalidateQueries({ queryKey: ["patches"] }); }} /></div>;

  return (
    <div className="p-5 max-w-4xl space-y-3">
      <div className="flex items-center gap-2">
        <h2 className="text-sm font-semibold">Patch history</h2>
        <button className="btn btn-sm btn-primary ml-auto" onClick={() => setNw({ title: "", cwe: "", filename: "", original_code: "", patched_code: "" })}>
          <GitCompare className="h-3.5 w-3.5" />New patch
        </button>
      </div>
      {nw && (
        <Panel title="New patch">
          <div className="p-3 grid grid-cols-2 gap-2">
            <input className="input col-span-2" placeholder="Title" value={nw.title} onChange={(e) => setNw({ ...nw, title: e.target.value })} />
            <input className="input" placeholder="CWE (optional)" value={nw.cwe} onChange={(e) => setNw({ ...nw, cwe: e.target.value })} />
            <input className="input mono" placeholder="filename (optional)" value={nw.filename} onChange={(e) => setNw({ ...nw, filename: e.target.value })} />
            <div className="col-span-2 grid grid-cols-2 gap-2">
              <div><label className="label">Original (vulnerable)</label><CodeEditor value={nw.original_code} onChange={(v) => setNw({ ...nw, original_code: v })} minRows={8} /></div>
              <div><label className="label">Patched</label><CodeEditor value={nw.patched_code} onChange={(v) => setNw({ ...nw, patched_code: v })} minRows={8} /></div>
            </div>
            <div className="col-span-2 flex gap-2">
              <button className="btn btn-primary" disabled={!nw.title || create.isPending} onClick={() => create.mutate()}>Create</button>
              <button className="btn" onClick={() => setNw(null)}>Cancel</button>
            </div>
          </div>
        </Panel>
      )}
      <Panel>
        {(list.data?.items || []).length === 0 ? <EmptyState title="No patches" hint="Create a patch, or use 'Save as patch' on an Analyze finding." /> : (
          <table className="w-full row-hover">
            <thead><tr><th className="th">Title</th><th className="th">CWE</th><th className="th">Status</th><th className="th">Security</th><th className="th">Functional</th><th className="th">By</th><th className="th"></th></tr></thead>
            <tbody>{list.data.items.map((p: any) => (
              <tr key={p.id} className="cursor-pointer" onClick={() => setSel(p.id)}>
                <td className="td font-medium">{p.title}</td><td className="td mono text-xs">{p.cwe || "-"}</td>
                <td className="td"><Badge className={STATUS_META[p.status]}>{p.status}</Badge></td>
                <td className="td"><Badge className={VAL_META[p.security_status]}>{p.security_status}</Badge></td>
                <td className="td"><Badge className={VAL_META[p.functional_status]}>{p.functional_status}</Badge></td>
                <td className="td text-2xs text-ink-faint">{p.label}</td>
                <td className="td text-right"><button className="btn btn-ghost btn-sm text-bad" title="Delete patch"
                  onClick={(e) => { e.stopPropagation(); if (confirm(`Delete patch "${p.title}"?`)) remove.mutate(p.id); }}><Trash2 className="h-3.5 w-3.5" /></button></td>
              </tr>
            ))}</tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}

function PatchDetail({ id, onBack }: { id: number; onBack: () => void }) {
  const toast = useToast();
  const qc = useQueryClient();
  const [mode, setMode] = useState<"split" | "unified">("split");
  const [draft, setDraft] = useState<{ original_code: string; patched_code: string } | null>(null);
  const { data: p } = useQuery({ queryKey: ["patch", id], queryFn: () => get(`/patches/${id}`) });
  const refresh = () => qc.invalidateQueries({ queryKey: ["patch", id] });

  const status = useMutation({
    mutationFn: (to: string) => post(`/patches/${id}/status`, { version: p.version, to_status: to }),
    onSuccess: refresh, onError: (e: any) => { toast("error", e.message); refresh(); },
  });
  const valid = useMutation({
    mutationFn: (a: { kind: string; result: string; notes: string | null }) => post(`/patches/${id}/validation`, { version: p.version, ...a }),
    onSuccess: refresh, onError: (e: any) => { toast("error", e.message); refresh(); },
  });
  const save = useMutation({
    mutationFn: () => put(`/patches/${id}`, { version: p.version, original_code: draft!.original_code, patched_code: draft!.patched_code }),
    onSuccess: () => { setDraft(null); refresh(); toast("ok", "Patch saved"); },
    onError: (e: any) => { toast("error", e.message); refresh(); },
  });
  const remove = useMutation({
    mutationFn: () => del(`/patches/${id}`),
    onSuccess: () => { toast("ok", "Patch deleted"); onBack(); },
    onError: (e: any) => toast("error", e.message),
  });

  function setVal(kind: string, result: string) {
    const notes = window.prompt(`${kind} ${result} note (optional)`) || null;
    valid.mutate({ kind, result, notes });
  }

  if (!p) return <div className="p-4"><Spinner /></div>;
  const noChange = p.diff_stats.added === 0 && p.diff_stats.removed === 0 && p.diff_stats.modified === 0;
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 flex-wrap">
        <button className="btn btn-sm" onClick={onBack}>← Patches</button>
        <h2 className="text-sm font-semibold">{p.title}</h2>
        <Badge className={STATUS_META[p.status]}>{p.status}</Badge>
        {p.cwe && <Badge className="border-line-strong text-ink-dim mono">{p.cwe}</Badge>}
        <span className="text-2xs text-ink-faint">+{p.diff_stats.added} / -{p.diff_stats.removed} / ~{p.diff_stats.modified}</span>
        <a className="btn btn-sm ml-auto" href={`/api/patches/${id}/export`} target="_blank" rel="noreferrer"><Download className="h-3.5 w-3.5" />Export .diff</a>
        <button className="btn btn-sm text-bad" title="Delete patch" onClick={() => { if (confirm("Delete this patch?")) remove.mutate(); }}><Trash2 className="h-3.5 w-3.5" />Delete</button>
      </div>

      {p.notes && (
        <div className="rounded-md border border-accent/30 bg-accent/5 p-3 text-xs text-ink-dim whitespace-pre-wrap">
          <span className="text-accent font-semibold">Guidance (from the finding). </span>{p.notes}
        </div>
      )}

      <Panel
        title={draft ? "Edit patch: Original (vulnerable) vs Your fix" : "Diff: Original (vulnerable) vs Patched"}
        actions={draft ? (
          <div className="flex gap-1">
            <button className="btn btn-sm btn-primary" disabled={save.isPending} onClick={() => save.mutate()}>Save</button>
            <button className="btn btn-sm" onClick={() => setDraft(null)}>Cancel</button>
          </div>
        ) : (
          <div className="flex gap-1">
            <button className="btn btn-sm" onClick={() => setDraft({ original_code: p.original_code, patched_code: p.patched_code })}><Pencil className="h-3.5 w-3.5" />Edit code</button>
            <button className={`btn btn-sm ${mode === "split" ? "btn-primary" : ""}`} onClick={() => setMode("split")}>Side by side</button>
            <button className={`btn btn-sm ${mode === "unified" ? "btn-primary" : ""}`} onClick={() => setMode("unified")}>Unified</button>
          </div>
        )}
      >
        <div className="p-3 overflow-auto max-h-[60vh]">
          {draft ? (
            <div className="grid grid-cols-2 gap-3">
              <div><label className="label">Original (vulnerable code)</label><CodeEditor value={draft.original_code} onChange={(v) => setDraft({ ...draft, original_code: v })} minRows={12} /></div>
              <div><label className="label">Your patched version</label><CodeEditor value={draft.patched_code} onChange={(v) => setDraft({ ...draft, patched_code: v })} minRows={12} /></div>
            </div>
          ) : noChange ? (
            <EmptyState title="No changes yet" hint="This patch's two versions are identical. Click 'Edit code' to write the fix on the right side; the diff appears here." />
          ) : mode === "split" ? (
            <div>
              <div className="flex text-2xs font-semibold uppercase tracking-wider text-ink-faint mb-1"><span className="flex-1 pl-12">Original (vulnerable)</span><span className="flex-1 pl-12">Patched</span></div>
              <SplitDiff rows={p.side_by_side} />
            </div>
          ) : <UnifiedDiff text={p.unified_diff} />}
        </div>
      </Panel>

      <div className="grid md:grid-cols-2 gap-3">
        <Panel title="Lifecycle">
          <div className="p-3 space-y-2">
            <p className="text-2xs text-ink-faint">Suggested, Reviewed, Tested, Applied, Verified. Transitions are validated server-side; Verified needs both checks to pass.</p>
            <div className="flex flex-wrap gap-1.5">
              {(p.allowed_transitions || []).map((s: string) => (
                <button key={s} className="btn btn-sm" disabled={status.isPending} onClick={() => status.mutate(s)}>→ {s}</button>
              ))}
              {(p.allowed_transitions || []).length === 0 && <span className="text-xs text-ink-faint">Terminal state.</span>}
            </div>
            <div className="text-2xs text-ink-faint">Deployment: {p.deployment_status}{p.reviewer ? ` · reviewer ${p.reviewer}` : ""}</div>
          </div>
        </Panel>
        <Panel title="Validation (security is not functional)">
          <div className="p-3 space-y-2 text-sm">
            <ValRow label="Security regression" status={p.security_status} notes={p.security_notes} onSet={(r: string) => setVal("security", r)} />
            <ValRow label="Service functional" status={p.functional_status} notes={p.functional_notes} onSet={(r: string) => setVal("functional", r)} />
            <p className="text-2xs text-ink-faint">Record real results. A passing security check does NOT mean the service still works. Run your local checks and set each here.</p>
          </div>
        </Panel>
      </div>

      <Panel title="Timeline">
        <div className="p-3 space-y-1 text-xs">
          {(p.events || []).map((e: any, i: number) => (
            <div key={i} className="flex gap-2"><span className="text-ink-faint w-32 shrink-0 mono">{e.at}</span><span className="text-ink-faint">{e.label}</span><span className="text-ink-dim">{e.kind}: {e.detail}</span></div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function ValRow({ label, status, notes, onSet }: { label: string; status: string; notes?: string; onSet: (r: string) => void }) {
  return (
    <div className="flex items-center gap-2">
      <span className="w-40 text-ink-dim">{label}</span>
      <Badge className={VAL_META[status]}>{status}</Badge>
      {notes && <span className="text-2xs text-ink-faint truncate max-w-[12rem]" title={notes}>{notes}</span>}
      <span className="ml-auto flex gap-1">
        {["pass", "fail", "na"].map((r) => <button key={r} className="btn btn-ghost btn-sm" onClick={() => onSet(r)}>{r}</button>)}
      </span>
    </div>
  );
}

function SplitDiff({ rows }: { rows: any[] }) {
  const bg: Record<string, string> = { add: "bg-ok/10", del: "bg-bad/10", mod: "bg-warn/10", equal: "" };
  return (
    <table className="w-full mono text-xs border-collapse">
      <tbody>{rows.map((r, i) => (
        <tr key={i}>
          <td className="text-right pr-2 text-ink-faint select-none w-10 align-top">{r.left_no ?? ""}</td>
          <td className={`px-2 whitespace-pre-wrap break-words align-top ${r.type === "del" || r.type === "mod" ? bg[r.type] : ""}`}>{r.left ?? ""}</td>
          <td className="text-right pr-2 text-ink-faint select-none w-10 align-top border-l border-line">{r.right_no ?? ""}</td>
          <td className={`px-2 whitespace-pre-wrap break-words align-top ${r.type === "add" || r.type === "mod" ? bg[r.type] : ""}`}>{r.right ?? ""}</td>
        </tr>
      ))}</tbody>
    </table>
  );
}

function UnifiedDiff({ text }: { text: string }) {
  const lines = (text || "").split("\n");
  return (
    <pre className="mono text-xs whitespace-pre-wrap break-words">{lines.map((ln, i) => {
      const cls = ln.startsWith("+") && !ln.startsWith("+++") ? "text-ok"
        : ln.startsWith("-") && !ln.startsWith("---") ? "text-bad"
        : ln.startsWith("@@") ? "text-accent" : "text-ink-dim";
      return <div key={i} className={cls}>{ln || " "}</div>;
    })}</pre>
  );
}
