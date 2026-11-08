import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Terminal, Wrench, HeartPulse, Plus, Download, Copy as CopyIcon, Trash2, Save, Play, Lock } from "lucide-react";
import { del, get, post, put } from "../lib/api";
import { useToast } from "../lib/toast";
import { PageBody, PageHeader } from "../components/Page";
import { HowToUse } from "../components/HowToUse";
import { Badge, CodeBlock, EmptyState, Panel, Spinner, Tabs } from "../components/ui";
import { CodeEditor } from "../components/CodeEditor";

export function Automation() {
  const [tab, setTab] = useState("scripts");
  return (
    <>
      <PageHeader title="Automation" subtitle="Script library · utilities · service health" />
      <div className="px-5 pt-3 bg-bg-raised/40 border-b border-line flex items-end justify-between gap-3">
        <Tabs active={tab} onChange={setTab} tabs={[
          { id: "scripts", label: <span className="flex items-center gap-1.5"><Terminal className="h-3.5 w-3.5" />Scripts</span> },
          { id: "utils", label: <span className="flex items-center gap-1.5"><Wrench className="h-3.5 w-3.5" />Utilities</span> },
          { id: "runner", label: <span className="flex items-center gap-1.5"><Play className="h-3.5 w-3.5" />Runner</span> },
          { id: "health", label: <span className="flex items-center gap-1.5"><HeartPulse className="h-3.5 w-3.5" />Health</span> },
        ]} />
        <HowToUse page="automation" className="mb-1.5" />
      </div>
      <PageBody className="p-0">
        {tab === "scripts" && <Scripts />}
        {tab === "utils" && <Utils />}
        {tab === "runner" && <Runner />}
        {tab === "health" && <Health />}
      </PageBody>
    </>
  );
}

function Scripts() {
  const qc = useQueryClient();
  const toast = useToast();
  const { data } = useQuery({ queryKey: ["scripts"], queryFn: () => get("/automation/scripts") });
  const [selId, setSelId] = useState<number | null>(null);
  const { data: sel } = useQuery({ queryKey: ["scripts", selId], queryFn: () => get(`/automation/scripts/${selId}`), enabled: !!selId });
  const [draft, setDraft] = useState<any>(null);

  const edit = draft ?? sel;
  const items = data?.items || [];

  const saveM = useMutation({
    mutationFn: () => {
      const body = { name: edit.name, language: edit.language, category: edit.category, body: edit.body, notes: edit.notes, tags: edit.tags || [], kind: edit.kind || "script" };
      return edit.id ? put(`/automation/scripts/${edit.id}`, body) : post("/automation/scripts", body);
    },
    onSuccess: (r: any) => { qc.invalidateQueries({ queryKey: ["scripts"] }); if (r?.id) setSelId(r.id); setDraft(null); toast("ok", "Saved"); },
    onError: (e: any) => toast("error", e.message),
  });
  const delM = useMutation({ mutationFn: (id: number) => del(`/automation/scripts/${id}`), onSuccess: () => { qc.invalidateQueries({ queryKey: ["scripts"] }); setSelId(null); } });
  const dupM = useMutation({ mutationFn: (id: number) => post(`/automation/scripts/${id}/duplicate`), onSuccess: (r: any) => { qc.invalidateQueries({ queryKey: ["scripts"] }); setSelId(r.id); } });

  const newScript = () => { setSelId(null); setDraft({ name: "untitled.py", language: "python", category: "general", body: "", kind: "script", tags: [] }); };

  return (
    <div className="grid grid-cols-[18rem_1fr] h-full min-h-0">
      <div className="border-r border-line flex flex-col min-h-0">
        <div className="h-11 flex items-center justify-between px-3 border-b border-line">
          <span className="text-xs font-semibold text-ink-dim">{items.length} scripts</span>
          <button className="btn btn-sm btn-primary" onClick={newScript}><Plus className="h-3.5 w-3.5" />New</button>
        </div>
        <div className="overflow-auto flex-1">
          {items.map((s: any) => (
            <button key={s.id} onClick={() => { setSelId(s.id); setDraft(null); }}
              className={`w-full text-left px-3 py-2 border-b border-line/60 hover:bg-bg-hover ${selId === s.id ? "bg-accent/10" : ""}`}>
              <div className="text-sm font-medium truncate">{s.name}</div>
              <div className="flex items-center gap-1.5 mt-0.5">
                <Badge className="border-line-strong text-ink-faint">{s.language}</Badge>
                <span className="text-2xs text-ink-faint">{s.category}</span>
                {s.kind === "exploit_template" && <Badge className="border-warn/40 text-warn bg-warn/10">template</Badge>}
              </div>
            </button>
          ))}
          {items.length === 0 && <div className="p-6 text-center text-xs text-ink-faint">Library empty. Run <span className="mono">python -m app.admin seed-library</span> or add one.</div>}
        </div>
      </div>

      <div className="min-h-0 flex flex-col">
        {!edit ? <EmptyState title="Select or create a script" hint="Store real, reusable scripts and exploit templates. Previewing never executes them." /> : (
          <>
            <div className="h-11 flex items-center gap-2 px-3 border-b border-line">
              <input className="input w-56" value={edit.name} onChange={(e) => setDraft({ ...edit, name: e.target.value })} />
              <select className="input w-32" value={edit.language} onChange={(e) => setDraft({ ...edit, language: e.target.value })}>
                {["python", "bash", "javascript", "sql", "text"].map((l) => <option key={l}>{l}</option>)}
              </select>
              <select className="input w-40" value={edit.category} onChange={(e) => setDraft({ ...edit, category: e.target.value })}>
                {["reconnaissance", "exploitation_templates", "patch_testing", "networking", "log_processing", "encoding", "service_monitoring", "flag_submission", "general"].map((c) => <option key={c}>{c}</option>)}
              </select>
              <div className="ml-auto flex items-center gap-1">
                <button className="btn btn-sm" onClick={() => saveM.mutate()} disabled={saveM.isPending}><Save className="h-3.5 w-3.5" />Save</button>
                {edit.id && <button className="btn btn-sm" onClick={() => dupM.mutate(edit.id)}><CopyIcon className="h-3.5 w-3.5" /></button>}
                <button className="btn btn-sm" onClick={() => { const b = new Blob([edit.body], { type: "text/plain" }); const a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = edit.name; a.click(); }}><Download className="h-3.5 w-3.5" /></button>
                {edit.id && <button className="btn btn-sm text-bad" onClick={() => delM.mutate(edit.id)}><Trash2 className="h-3.5 w-3.5" /></button>}
              </div>
            </div>
            <div className="flex-1 min-h-0 p-3">
              <CodeEditor value={edit.body} onChange={(v) => setDraft({ ...edit, body: v })} minRows={20} />
            </div>
            {edit.revisions?.length > 0 && (
              <div className="px-3 py-2 border-t border-line text-2xs text-ink-faint">{edit.revisions.length} revision(s) stored</div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

const OPS = [
  ["b64_encode", "Base64 encode"], ["b64_decode", "Base64 decode"], ["url_encode", "URL encode"], ["url_decode", "URL decode"],
  ["hex_encode", "Hex encode"], ["hex_decode", "Hex decode"], ["hashes", "Hashes (md5…sha512)"], ["jwt_decode", "JWT decode (no verify)"],
  ["json_pretty", "JSON prettify"], ["timestamp", "Timestamp convert"],
];
function Utils() {
  const toast = useToast();
  const [op, setOp] = useState("b64_decode");
  const [input, setInput] = useState("");
  const [out, setOut] = useState<any>(null);
  const runM = useMutation({
    mutationFn: () => post("/automation/utils", { op, text: input }),
    onSuccess: (r: any) => setOut(r),
    onError: (e: any) => toast("error", e.message),
  });
  return (
    <div className="p-5 grid lg:grid-cols-2 gap-4 max-w-5xl">
      <Panel title="Input">
        <div className="p-3 space-y-2">
          <select className="input" value={op} onChange={(e) => setOp(e.target.value)}>
            {OPS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
          <textarea className="input h-48 py-2 mono resize-none" value={input} onChange={(e) => setInput(e.target.value)} placeholder="Paste input…" />
          <button className="btn btn-primary w-full" onClick={() => runM.mutate()}>Run</button>
        </div>
      </Panel>
      <Panel title="Output">
        <div className="p-3">
          {out === null ? <EmptyState title="No output" /> :
            out.ok === false ? <div className="text-sm text-bad bg-bad/10 border border-bad/30 rounded p-2">{out.error}</div> :
              <CodeBlock code={typeof out.result === "string" ? out.result : JSON.stringify(out.result, null, 2)} className="max-h-[55vh]" />}
          {op === "jwt_decode" && out?.ok && <p className="text-2xs text-warn mt-2">Signature is NOT verified, claims only.</p>}
        </div>
      </Panel>
    </div>
  );
}

function Runner() {
  const toast = useToast();
  const { data: status } = useQuery({ queryKey: ["exec-status"], queryFn: () => get("/automation/execution-status") });
  const { data: tasks } = useQuery({ queryKey: ["runner-tasks"], queryFn: () => get("/automation/runner/tasks") });
  const enabled = !!status?.task_execution_enabled;

  return (
    <div className="p-5 max-w-4xl space-y-4">
      <div className={`well p-3 flex items-start gap-2.5 ${enabled ? "" : "border-warn/30"}`}>
        <Lock className={`h-4 w-4 mt-0.5 shrink-0 ${enabled ? "text-ok" : "text-warn"}`} />
        <div className="text-xs">
          <div className="font-medium text-ink mb-0.5">
            Local-utility runner is {enabled ? "ENABLED" : "DISABLED"}
            {!status?.https && enabled && <span className="text-warn"> · running without HTTPS</span>}
          </div>
          <p className="text-ink-dim leading-relaxed">{status?.reason}</p>
        </div>
      </div>
      <div className="grid md:grid-cols-2 gap-4">
        {(tasks?.tasks || []).map((t: any) => <TaskCard key={t.id} task={t} enabled={enabled} onError={(m: string) => toast("error", m)} />)}
      </div>
    </div>
  );
}

function TaskCard({ task, enabled, onError }: { task: any; enabled: boolean; onError: (m: string) => void }) {
  const [args, setArgs] = useState<Record<string, any>>(() => {
    const init: Record<string, any> = {};
    task.params.forEach((p: any) => { init[p.name] = p.default ?? (p.type === "bool" ? false : ""); });
    return init;
  });
  const [result, setResult] = useState<any>(null);
  const run = useMutation({
    mutationFn: () => post("/automation/runner/run", { task_id: task.id, args: cleanArgs(task, args) }),
    onSuccess: (r) => setResult(r),
    onError: (e: any) => { setResult(null); onError(e.message); },
  });
  function cleanArgs(t: any, a: Record<string, any>) {
    const out: Record<string, any> = {};
    t.params.forEach((p: any) => { if (a[p.name] !== "" && a[p.name] != null) out[p.name] = a[p.name]; });
    return out;
  }
  let parsed: any = null;
  try { parsed = result ? JSON.parse(result.stdout || "null") : null; } catch { parsed = null; }

  return (
    <Panel title={task.title}>
      <div className="p-3 space-y-2">
        <p className="text-2xs text-ink-faint">{task.description}</p>
        {task.params.map((p: any) => (
          <div key={p.name}>
            <label className="label">{p.name}{p.required && <span className="text-bad"> *</span>}</label>
            {p.type === "bool" ? (
              <label className="flex items-center gap-2 text-sm h-8"><input type="checkbox" checked={!!args[p.name]} onChange={(e) => setArgs({ ...args, [p.name]: e.target.checked })} /> enable</label>
            ) : p.type === "enum" ? (
              <select className="input" value={args[p.name]} onChange={(e) => setArgs({ ...args, [p.name]: e.target.value })}>
                {p.choices.map((c: string) => <option key={c}>{c}</option>)}
              </select>
            ) : p.max_len > 200 ? (
              <textarea className="input h-20 py-1.5 mono resize-none" value={args[p.name]} onChange={(e) => setArgs({ ...args, [p.name]: e.target.value })} />
            ) : (
              <input className="input mono" value={args[p.name]} onChange={(e) => setArgs({ ...args, [p.name]: e.target.value })} />
            )}
          </div>
        ))}
        <button className="btn btn-primary w-full" disabled={!enabled || run.isPending} onClick={() => run.mutate()}>
          {enabled ? <Play className="h-4 w-4" /> : <Lock className="h-4 w-4" />} {enabled ? "Run" : "Disabled"}
        </button>
        {result && (
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-2xs">
              <Badge className={result.status === "done" ? "border-ok/30 text-ok bg-ok/10" : result.status === "timeout" ? "border-warn/40 text-warn bg-warn/10" : "border-bad/40 text-bad bg-bad/10"}>{result.status}</Badge>
              <span className="text-ink-faint">{result.duration_ms} ms</span>
            </div>
            <CodeBlock code={parsed ? JSON.stringify(parsed, null, 2) : (result.stdout || result.stderr || "(no output)")} className="max-h-48" />
          </div>
        )}
      </div>
    </Panel>
  );
}

function Health() {
  const qc = useQueryClient();
  const { data } = useQuery({ queryKey: ["services"], queryFn: () => get("/services") });
  const checkAll = useMutation({ mutationFn: () => post("/automation/health/check-all"), onSuccess: () => qc.invalidateQueries({ queryKey: ["services"] }) });
  const items = data?.items || [];
  return (
    <div className="p-5 max-w-4xl space-y-3">
      <div className="flex justify-end">
        <button className="btn btn-primary" onClick={() => checkAll.mutate()} disabled={checkAll.isPending}>
          {checkAll.isPending ? <Spinner className="text-white" /> : <HeartPulse className="h-4 w-4" />} Check all
        </button>
      </div>
      <Panel>
        {items.length === 0 ? <EmptyState title="No services" hint="Add services in the Attack › Targets tab." /> :
          <table className="w-full row-hover">
            <thead><tr><th className="th">Service</th><th className="th">Endpoint</th><th className="th">Status</th><th className="th">Latency</th><th className="th">Checked</th></tr></thead>
            <tbody>{items.map((s: any) => (
              <tr key={s.id}>
                <td className="td font-medium">{s.name}</td>
                <td className="td mono">{s.host}{s.port ? `:${s.port}` : ""}</td>
                <td className="td">{s.last_health ? <span className="flex items-center gap-1.5"><span className={`h-2 w-2 rounded-full ${s.last_health.status === "online" ? "bg-ok" : s.last_health.status === "offline" ? "bg-bad" : "bg-ink-faint"}`} />{s.last_health.status}</span> : <span className="text-ink-faint">unknown</span>}</td>
                <td className="td mono">{s.last_health?.latency_ms != null ? `${s.last_health.latency_ms} ms` : "-"}</td>
                <td className="td text-ink-faint">{s.last_health?.checked_at ?? "-"}</td>
              </tr>
            ))}</tbody>
          </table>}
      </Panel>
    </div>
  );
}
