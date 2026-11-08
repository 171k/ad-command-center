import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, FileSearch, Trash2 } from "lucide-react";
import { get, post, put, del } from "../lib/api";
import { useToast } from "../lib/toast";
import { PageBody, PageHeader } from "../components/Page";
import { HowToUse } from "../components/HowToUse";
import { Badge, EmptyState, Panel } from "../components/ui";
import { Drawer, Dialog } from "../components/overlay";
import { SEVERITY_META, timeAgo } from "../lib/format";

const NEW = { title: "", description: "", category: "attack", severity: "medium", status: "open" };

export function Findings() {
  const qc = useQueryClient();
  const toast = useToast();
  const [status, setStatus] = useState("");
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<number | null>(null);
  const [create, setCreate] = useState(false);
  const [form, setForm] = useState<any>(NEW);

  const { data } = useQuery({
    queryKey: ["findings", status, q],
    queryFn: () => get(`/findings?${status ? `status=${status}&` : ""}${q ? `q=${encodeURIComponent(q)}` : ""}`),
  });
  const createM = useMutation({
    mutationFn: () => post("/findings", form),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["findings"] }); setCreate(false); setForm(NEW); toast("ok", "Finding created"); },
    onError: (e: any) => toast("error", e.message),
  });
  const deleteM = useMutation({
    mutationFn: (id: number) => del(`/findings/${id}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["findings"] }); toast("ok", "Finding deleted"); },
    onError: (e: any) => toast("error", e.message),
  });
  const items = data?.items || [];
  return (
    <>
      <PageHeader title="Findings" subtitle="Shared across all sessions · synced live"
        actions={<><button className="btn btn-primary" onClick={() => setCreate(true)}><Plus className="h-4 w-4" />New finding</button><HowToUse page="findings" /></>} />
      <PageBody>
        <div className="flex gap-2 mb-3">
          <input className="input w-56" placeholder="Search…" value={q} onChange={(e) => setQ(e.target.value)} />
          <select className="input w-40" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All statuses</option><option value="open">Open</option><option value="investigating">Investigating</option><option value="resolved">Resolved</option>
          </select>
          <span className="ml-auto self-center text-xs text-ink-faint">{data?.total ?? 0} findings</span>
        </div>
        <Panel>
          {items.length === 0 ? <EmptyState icon={<FileSearch className="h-7 w-7" />} title="No findings" hint="Create a finding or send one from an SOC offense." /> : (
            <table className="w-full row-hover">
              <thead><tr><th className="th">Title</th><th className="th">Source</th><th className="th">Severity</th><th className="th">Status</th><th className="th">By</th><th className="th">Updated</th><th className="th"></th></tr></thead>
              <tbody>{items.map((f: any) => (
                <tr key={f.id} className="cursor-pointer" onClick={() => setSel(f.id)}>
                  <td className="td font-medium">{f.title}</td>
                  <td className="td text-ink-dim">{f.source ?? f.category ?? "-"}</td>
                  <td className="td"><Badge className={SEVERITY_META[f.severity]}>{f.severity}</Badge></td>
                  <td className="td text-ink-dim">{f.status}</td>
                  <td className="td text-ink-faint">{f.label ?? "-"}</td>
                  <td className="td text-ink-faint">{timeAgo(f.updated_at)}</td>
                  <td className="td text-right"><button className="btn btn-ghost btn-sm text-bad" title="Delete finding"
                    onClick={(e) => { e.stopPropagation(); if (confirm(`Delete finding "${f.title}"?`)) deleteM.mutate(f.id); }}><Trash2 className="h-3.5 w-3.5" /></button></td>
                </tr>
              ))}</tbody>
            </table>
          )}
        </Panel>
      </PageBody>

      <Dialog open={create} onClose={() => setCreate(false)} title="New finding"
        footer={<><button className="btn" onClick={() => setCreate(false)}>Cancel</button><button className="btn btn-primary" disabled={!form.title} onClick={() => createM.mutate()}>Create</button></>}>
        <div className="space-y-3">
          <div><label className="label">Title</label><input className="input" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} /></div>
          <div><label className="label">Description</label><textarea className="input h-24 py-2 resize-none" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></div>
          <div className="grid grid-cols-3 gap-2">
            <div><label className="label">Source</label><select className="input" value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })}>
              {["attack", "defense", "automation", "soc"].map((c) => <option key={c}>{c}</option>)}</select></div>
            <div><label className="label">Severity</label><select className="input" value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
              {["low", "medium", "high", "critical"].map((c) => <option key={c}>{c}</option>)}</select></div>
            <div><label className="label">Status</label><select className="input" value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value })}>
              {["open", "investigating", "resolved"].map((c) => <option key={c}>{c}</option>)}</select></div>
          </div>
        </div>
      </Dialog>

      {sel && <FindingDetail id={sel} onClose={() => setSel(null)} />}
    </>
  );
}

function FindingDetail({ id, onClose }: { id: number; onClose: () => void }) {
  const qc = useQueryClient();
  const { data: f } = useQuery({ queryKey: ["finding", id], queryFn: () => get(`/findings/${id}`) });
  const [note, setNote] = useState("");
  const noteM = useMutation({ mutationFn: () => post(`/findings/${id}/notes`, { body: note }), onSuccess: () => { setNote(""); qc.invalidateQueries({ queryKey: ["finding", id] }); } });
  const statusM = useMutation({ mutationFn: (s: string) => put(`/findings/${id}`, { ...f, status: s }), onSuccess: () => { qc.invalidateQueries({ queryKey: ["finding", id] }); qc.invalidateQueries({ queryKey: ["findings"] }); } });
  const deleteM = useMutation({ mutationFn: () => del(`/findings/${id}`), onSuccess: () => { qc.invalidateQueries({ queryKey: ["findings"] }); onClose(); } });
  return (
    <Drawer open onClose={onClose} title={f?.title || "Finding"} width="max-w-xl">
      {!f ? null : (
        <div className="p-4 space-y-3">
          <div className="flex gap-2">
            <Badge className={SEVERITY_META[f.severity]}>{f.severity}</Badge>
            {["open", "investigating", "resolved"].map((s) => (
              <button key={s} className={`btn btn-sm ${f.status === s ? "btn-primary" : ""}`} onClick={() => statusM.mutate(s)}>{s}</button>
            ))}
            <button className="btn btn-sm text-bad ml-auto" title="Delete finding" onClick={() => { if (confirm("Delete this finding?")) deleteM.mutate(); }}><Trash2 className="h-3.5 w-3.5" />Delete</button>
          </div>
          {f.description && <p className="text-sm text-ink-dim whitespace-pre-wrap">{f.description}</p>}
          {f.refs?.offense_id && <div className="text-xs text-ink-faint">Linked SOC offense #{f.refs.offense_id}</div>}
          <Panel title="Notes">
            <div className="p-3 space-y-2">
              {(f.notes || []).map((n: any) => (
                <div key={n.id} className="text-sm border-l-2 border-line pl-2"><div className="text-ink-dim">{n.body}</div><div className="text-2xs text-ink-faint">{n.label ?? "-"} · {n.created_at}</div></div>
              ))}
              <div className="flex gap-2"><input className="input flex-1" placeholder="Add note…" value={note} onChange={(e) => setNote(e.target.value)} onKeyDown={(e) => e.key === "Enter" && note && noteM.mutate()} /><button className="btn" disabled={!note} onClick={() => noteM.mutate()}>Add</button></div>
            </div>
          </Panel>
        </div>
      )}
    </Drawer>
  );
}
