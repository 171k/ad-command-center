import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Crosshair, Plus, Radio, Flag, BookOpen, Trash2, Activity, ChevronDown, ChevronRight, Code2, Download } from "lucide-react";
import { del, get, post, put } from "../lib/api";
import { useToast } from "../lib/toast";
import { PageBody, PageHeader } from "../components/Page";
import { Badge, CodeBlock, EmptyState, Panel, Spinner, Tabs } from "../components/ui";
import { Dialog } from "../components/overlay";
import { HowToUse } from "../components/HowToUse";

export function Attack() {
  const [tab, setTab] = useState("targets");
  return (
    <>
      <PageHeader title="Attack" subtitle="Authorized targets · recon · exploit knowledge · flags" />
      <div className="px-5 pt-3 bg-bg-raised/40 border-b border-line flex items-end justify-between gap-3">
        <Tabs active={tab} onChange={setTab} tabs={[
          { id: "targets", label: <Tl icon={Crosshair}>Targets</Tl> },
          { id: "recon", label: <Tl icon={Radio}>Recon</Tl> },
          { id: "knowledge", label: <Tl icon={BookOpen}>Knowledge</Tl> },
          { id: "rce", label: <Tl icon={Code2}>RCE Gen</Tl> },
          { id: "flags", label: <Tl icon={Flag}>Flags</Tl> },
        ]} />
        <HowToUse page="attack" className="mb-1.5" />
      </div>
      <PageBody>
        {tab === "targets" && <Targets />}
        {tab === "recon" && <Recon />}
        {tab === "knowledge" && <Knowledge />}
        {tab === "rce" && <RceGen />}
        {tab === "flags" && <Flags />}
      </PageBody>
    </>
  );
}
const Tl = ({ icon: I, children }: any) => <span className="flex items-center gap-1.5"><I className="h-3.5 w-3.5" />{children}</span>;

const EMPTY = { name: "", host: "", port: "" as any, protocol: "tcp", owner: "opponent", description: "", authorized: false };

function Targets() {
  const qc = useQueryClient();
  const toast = useToast();
  const { data } = useQuery({ queryKey: ["services"], queryFn: () => get("/services") });
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<any>(EMPTY);
  const [editId, setEditId] = useState<number | null>(null);

  const saveM = useMutation({
    mutationFn: () => {
      const body = { ...form, port: form.port ? Number(form.port) : null };
      return editId ? put(`/services/${editId}`, body) : post("/services", body);
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["services"] }); setOpen(false); toast("ok", "Saved"); },
    onError: (e: any) => toast("error", e.message),
  });
  const delM = useMutation({
    mutationFn: (id: number) => del(`/services/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["services"] }),
  });
  const checkM = useMutation({
    mutationFn: (id: number) => post(`/services/${id}/check`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["services"] }),
  });

  const items = data?.items || [];
  const ours = items.filter((s: any) => s.owner === "ours");
  const opp = items.filter((s: any) => s.owner === "opponent");

  return (
    <div className="space-y-4 max-w-5xl">
      <div className="flex justify-end">
        <button className="btn btn-primary" onClick={() => { setForm(EMPTY); setEditId(null); setOpen(true); }}>
          <Plus className="h-4 w-4" /> Add target
        </button>
      </div>
      {[["Our services", ours], ["Opponent targets", opp]].map(([title, list]: any) => (
        <Panel key={title} title={title}>
          {list.length === 0 ? (
            <EmptyState title="None configured" hint="Add a service to define the authorized scope. Probing anything not listed is rejected server-side." />
          ) : (
            <table className="w-full row-hover">
              <thead><tr>
                <th className="th">Name</th><th className="th">Endpoint</th><th className="th">Proto</th>
                <th className="th">Authorized</th><th className="th">Health</th><th className="th"></th>
              </tr></thead>
              <tbody>
                {list.map((s: any) => (
                  <tr key={s.id}>
                    <td className="td font-medium">{s.name}</td>
                    <td className="td mono">{s.host}{s.port ? `:${s.port}` : ""}</td>
                    <td className="td">{s.protocol}</td>
                    <td className="td">{s.authorized
                      ? <Badge className="border-ok/30 text-ok bg-ok/10">yes</Badge>
                      : <Badge className="border-line-strong text-ink-faint">no</Badge>}</td>
                    <td className="td">
                      {s.last_health
                        ? <span className="flex items-center gap-1.5"><span className={`h-2 w-2 rounded-full ${s.last_health.status === "online" ? "bg-ok" : s.last_health.status === "offline" ? "bg-bad" : "bg-ink-faint"}`} />{s.last_health.status}</span>
                        : <span className="text-ink-faint">-</span>}
                    </td>
                    <td className="td text-right whitespace-nowrap">
                      <button className="btn btn-ghost btn-sm" onClick={() => checkM.mutate(s.id)} title="Check now"><Activity className="h-3.5 w-3.5" /></button>
                      <button className="btn btn-ghost btn-sm" onClick={() => { setForm({ ...s, port: s.port ?? "" }); setEditId(s.id); setOpen(true); }}>Edit</button>
                      <button className="btn btn-ghost btn-sm text-bad" onClick={() => delM.mutate(s.id)}><Trash2 className="h-3.5 w-3.5" /></button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      ))}

      <Dialog open={open} onClose={() => setOpen(false)} title={editId ? "Edit target" : "Add target"}
        footer={<><button className="btn" onClick={() => setOpen(false)}>Cancel</button>
          <button className="btn btn-primary" onClick={() => saveM.mutate()} disabled={!form.name || !form.host}>Save</button></>}>
        <div className="grid grid-cols-2 gap-3">
          <L label="Name"><input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></L>
          <L label="Host / IP"><input className="input mono" value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} /></L>
          <L label="Port"><input className="input mono" value={form.port} onChange={(e) => setForm({ ...form, port: e.target.value })} /></L>
          <L label="Protocol"><select className="input" value={form.protocol} onChange={(e) => setForm({ ...form, protocol: e.target.value })}>
            <option>tcp</option><option>http</option><option>https</option></select></L>
          <L label="Owner"><select className="input" value={form.owner} onChange={(e) => setForm({ ...form, owner: e.target.value })}>
            <option value="ours">ours</option><option value="opponent">opponent</option></select></L>
          <L label="Authorized for probing">
            <label className="flex items-center gap-2 h-8 text-sm"><input type="checkbox" checked={form.authorized} onChange={(e) => setForm({ ...form, authorized: e.target.checked })} /> allow active recon</label>
          </L>
          <div className="col-span-2"><L label="Description"><input className="input" value={form.description || ""} onChange={(e) => setForm({ ...form, description: e.target.value })} /></L></div>
        </div>
        <p className="text-2xs text-ink-faint mt-3">Active recon is rejected unless the target is registered and marked authorized.</p>
      </Dialog>
    </div>
  );
}
const L = ({ label, children }: any) => <div><label className="label">{label}</label>{children}</div>;

function Recon() {
  const toast = useToast();
  const { data } = useQuery({ queryKey: ["services"], queryFn: () => get("/services") });
  const targets = (data?.items || []).filter((s: any) => s.port);
  const [sel, setSel] = useState<string>("");
  const [path, setPath] = useState("/");
  const [out, setOut] = useState<any>(null);
  const [kind, setKind] = useState("");

  const target = targets.find((t: any) => String(t.id) === sel);
  const runM = useMutation({
    mutationFn: async (k: string) => {
      setKind(k);
      if (!target) throw new Error("Select a target");
      if (k === "http") return post("/attack/recon/http", { host: target.host, port: target.port, path, tls: target.protocol === "https" });
      if (k === "banner") return post("/attack/recon/banner", { host: target.host, port: target.port });
      return post("/attack/recon/tcp", { host: target.host, port: target.port });
    },
    onSuccess: (r) => setOut(r),
    onError: (e: any) => { setOut(null); toast("error", e.message); },
  });

  return (
    <div className="grid lg:grid-cols-2 gap-4 max-w-5xl">
      <Panel title="Probe">
        <div className="p-3 space-y-3">
          <L label="Target (registered scope only)">
            <select className="input" value={sel} onChange={(e) => setSel(e.target.value)}>
              <option value="">Select target…</option>
              {targets.map((t: any) => <option key={t.id} value={t.id}>{t.name} · {t.host}:{t.port} {t.authorized ? "" : "(not authorized)"}</option>)}
            </select>
          </L>
          <L label="HTTP path"><input className="input mono" value={path} onChange={(e) => setPath(e.target.value)} /></L>
          <div className="flex gap-2">
            <button className="btn" disabled={!sel || runM.isPending} onClick={() => runM.mutate("tcp")}>TCP connect</button>
            <button className="btn" disabled={!sel || runM.isPending} onClick={() => runM.mutate("banner")}>Banner</button>
            <button className="btn" disabled={!sel || runM.isPending} onClick={() => runM.mutate("http")}>HTTP inspect</button>
            {runM.isPending && <Spinner className="self-center" />}
          </div>
          <p className="text-2xs text-ink-faint">Bounded timeouts; no Internet-wide scanning. Out-of-scope hosts are refused by the server.</p>
        </div>
      </Panel>
      <Panel title={`Result${kind ? ` · ${kind}` : ""}`}>
        <div className="p-3">
          {!out ? <EmptyState title="No probe run" hint="Pick a target and run a probe." /> :
            <ReconResult kind={kind} out={out} />}
        </div>
      </Panel>
    </div>
  );
}

const Rlabel = ({ children }: any) => <div className="text-2xs font-semibold uppercase tracking-wider text-ink-faint mb-1">{children}</div>;

function ReconResult({ kind, out }: { kind: string; out: any }) {
  return (
    <div className="space-y-3 max-h-[62vh] overflow-auto">
      {kind === "http" && (
        <>
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <Badge className={(out.status_code ?? 0) < 400 ? "border-ok/30 text-ok bg-ok/10" : "border-warn/40 text-warn bg-warn/10"}>HTTP {out.status_code}</Badge>
            {out.latency_ms != null && <Badge className="border-line-strong text-ink-dim">{out.latency_ms} ms</Badge>}
            {out.content_type && <Badge className="border-line-strong text-ink-dim">{out.content_type}</Badge>}
          </div>
          {out.tech_fingerprint?.length > 0 && (
            <div><Rlabel>Tech fingerprint</Rlabel>
              <div className="flex flex-wrap gap-1.5">{out.tech_fingerprint.map((t: string, i: number) => <Badge key={i} className="border-accent/40 text-accent bg-accent/10">{t}</Badge>)}</div></div>
          )}
          {out.headers && (
            <div><Rlabel>Response headers</Rlabel>
              <div className="well rounded-md divide-y divide-line/60 text-xs">
                {Object.entries(out.headers).map(([k, v]: any) => (
                  <div key={k} className="flex gap-3 px-2.5 py-1.5"><span className="mono text-ink-faint w-36 shrink-0 break-all">{k}</span><span className="mono text-ink-dim break-all min-w-0">{String(v)}</span></div>
                ))}
              </div></div>
          )}
          {out.body_preview && (
            <div><Rlabel>Body preview</Rlabel><CodeBlock code={out.body_preview} className="max-h-72" wrap /></div>
          )}
        </>
      )}
      {kind === "banner" && (
        out.banner ? <CodeBlock code={out.banner} wrap /> : <p className="text-sm text-ink-faint">No banner. This port did not return a plaintext service banner (normal for HTTPS).</p>
      )}
      {kind === "tcp" && (
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <Badge className={out.status === "online" ? "border-ok/30 text-ok bg-ok/10" : "border-bad/40 text-bad bg-bad/10"}>{out.status}</Badge>
          {out.latency_ms != null && <span className="text-ink-dim">{out.latency_ms} ms</span>}
          {out.detail && <span className="text-ink-faint">{out.detail}</span>}
        </div>
      )}
      <details className="text-2xs text-ink-faint">
        <summary className="cursor-pointer select-none">Raw JSON</summary>
        <CodeBlock code={JSON.stringify(out, null, 2)} className="max-h-72 mt-1" wrap />
      </details>
    </div>
  );
}

function Knowledge() {
  const { data } = useQuery({ queryKey: ["knowledge"], queryFn: () => get("/attack/knowledge") });
  const [q, setQ] = useState("");
  const groups = data?.groups || [];
  return (
    <div className="max-w-4xl space-y-3">
      <input className="input max-w-sm" placeholder="Search techniques…" value={q} onChange={(e) => setQ(e.target.value)} />
      {groups.map((g: any) => (
        <Panel key={g.cwe} title={<span className="flex items-center gap-2">{g.cwe}</span>}>
          <div className="divide-y divide-line">
            {g.entries.filter((e: any) => !q || (e.name + e.description).toLowerCase().includes(q.toLowerCase())).map((e: any) => <KnowEntry key={e.id} e={e} />)}
          </div>
        </Panel>
      ))}
    </div>
  );
}
function KnowEntry({ e }: { e: any }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="p-3">
      <button className="w-full flex items-center gap-2 text-left" onClick={() => setOpen(!open)}>
        {open ? <ChevronDown className="h-4 w-4 text-ink-faint" /> : <ChevronRight className="h-4 w-4 text-ink-faint" />}
        <span className="text-sm font-medium">{e.name}</span>
        <span className="ml-auto text-2xs text-ink-faint">{e.languages.join(", ")}</span>
      </button>
      {open && (
        <div className="mt-2 pl-6 space-y-2 text-sm text-ink-dim">
          <p>{e.description}</p>
          <p><span className="text-ink-faint text-2xs uppercase">Preconditions:</span> {e.preconditions}</p>
          <p><span className="text-ink-faint text-2xs uppercase">Safe test:</span> {e.test_procedure}</p>
          {e.exploit_template && <CodeBlock code={e.exploit_template} className="max-h-32" />}
          <p className="text-2xs text-ink-faint">{e.limitations}</p>
        </div>
      )}
    </div>
  );
}

function Flags() {
  const qc = useQueryClient();
  const toast = useToast();
  const { data } = useQuery({ queryKey: ["flags"], queryFn: () => get("/attack/flags") });
  const [val, setVal] = useState("");
  const addM = useMutation({
    mutationFn: () => post("/attack/flags", { value: val }),
    onSuccess: (r: any) => { setVal(""); qc.invalidateQueries({ queryKey: ["flags"] }); toast(r.duplicate ? "info" : "ok", r.duplicate ? "Duplicate flag" : "Flag added"); },
    onError: (e: any) => toast("error", e.message),
  });
  const subM = useMutation({
    mutationFn: () => post("/attack/flags/submit"),
    onSuccess: (r: any) => { qc.invalidateQueries({ queryKey: ["flags"] }); toast("ok", `Submitted ${r.results?.length ?? 0}`); },
    onError: (e: any) => toast("info", e.message),
  });
  const s = data?.summary || { accepted: 0, rejected: 0, pending: 0 };
  return (
    <div className="max-w-3xl space-y-4">
      <Panel title="Capture flag">
        <div className="p-3 flex gap-2">
          <input className="input mono flex-1" placeholder="FLAG{...}" value={val} onChange={(e) => setVal(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && val && addM.mutate()} />
          <button className="btn btn-primary" disabled={!val} onClick={() => addM.mutate()}>Add</button>
          <button className="btn" onClick={() => subM.mutate()} disabled={subM.isPending}>Submit pending</button>
        </div>
        <div className="px-3 pb-3 flex gap-2 text-xs">
          <Badge className="border-ok/30 text-ok bg-ok/10">accepted {s.accepted}</Badge>
          <Badge className="border-bad/30 text-bad bg-bad/10">rejected {s.rejected}</Badge>
          <Badge className="border-line-strong text-ink-dim">pending {s.pending}</Badge>
          <span className="text-ink-faint ml-auto self-center">Raw flags are never written to logs or git.</span>
        </div>
      </Panel>
      <Panel title="Submissions">
        {(data?.items || []).length === 0 ? <EmptyState title="No flags yet" /> :
          <table className="w-full row-hover">
            <thead><tr><th className="th">#</th><th className="th">Status</th><th className="th">Service</th><th className="th">By</th><th className="th">Added</th></tr></thead>
            <tbody>{data.items.map((f: any) => (
              <tr key={f.id}><td className="td mono">{f.id}</td>
                <td className="td"><Badge className={f.status === "accepted" ? "border-ok/30 text-ok bg-ok/10" : f.status === "rejected" ? "border-bad/30 text-bad bg-bad/10" : "border-line-strong text-ink-dim"}>{f.status}</Badge></td>
                <td className="td">{f.service_id ?? "-"}</td><td className="td">{f.label ?? "-"}</td><td className="td text-ink-faint">{f.created_at}</td></tr>
            ))}</tbody>
          </table>}
      </Panel>
    </div>
  );
}

const PROTOCOLS = ["requests", "http", "tcp", "pwntools"];

function RceGen() {
  const toast = useToast();
  const { data } = useQuery({ queryKey: ["services"], queryFn: () => get("/services") });
  const targets = (data?.items || []).filter((s: any) => s.authorized && s.port);
  const [f, setF] = useState<any>({ protocol: "requests", host: "", port: 443, tls: true, method: "GET", path: "/", params: "", headers: "", body: "", payload: "", expected: "", timeout: 10, name: "exploit" });
  const [result, setResult] = useState<any>(null);

  function pickTarget(id: string) {
    const t = targets.find((x: any) => String(x.id) === id);
    if (t) setF({ ...f, host: t.host, port: t.port, tls: t.protocol === "https" });
  }
  function kvLines(s: string): Record<string, string> {
    const out: Record<string, string> = {};
    (s || "").split("\n").forEach((ln) => { const i = ln.indexOf(":"); if (i > 0) out[ln.slice(0, i).trim()] = ln.slice(i + 1).trim(); });
    return out;
  }

  const gen = useMutation({
    mutationFn: () => post("/ops/rce-template", {
      ...f, port: Number(f.port) || null, timeout: Number(f.timeout) || 10,
      headers: kvLines(f.headers), params: kvLines(f.params),
    }),
    onSuccess: (r) => setResult(r),
    onError: (e: any) => toast("error", e.message),
  });

  function download() {
    if (!result) return;
    const blob = new Blob([result.script], { type: "text/x-python" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = result.filename; a.click();
    URL.revokeObjectURL(a.href);
  }

  return (
    <div className="grid lg:grid-cols-2 gap-4 max-w-6xl">
      <Panel title="RCE script generator">
        <div className="p-3 space-y-3">
          <p className="text-2xs text-ink-faint">Turn a verified vulnerability into a reusable, editable script. Generation only, no execution. The target must be a registered, authorised service. Run the exported script from your own box.</p>
          <div className="grid grid-cols-2 gap-3">
            <L label="Protocol"><select className="input" value={f.protocol} onChange={(e) => setF({ ...f, protocol: e.target.value })}>{PROTOCOLS.map((p) => <option key={p}>{p}</option>)}</select></L>
            <L label="Authorised target"><select className="input" onChange={(e) => pickTarget(e.target.value)}><option value="">Select…</option>{targets.map((t: any) => <option key={t.id} value={t.id}>{t.name} — {t.host}:{t.port}</option>)}</select></L>
            <L label="Host"><input className="input mono" value={f.host} onChange={(e) => setF({ ...f, host: e.target.value })} /></L>
            <L label="Port"><input className="input mono" value={f.port} onChange={(e) => setF({ ...f, port: e.target.value })} /></L>
            <L label="Method"><select className="input" value={f.method} onChange={(e) => setF({ ...f, method: e.target.value })}><option>GET</option><option>POST</option></select></L>
            <L label="TLS"><label className="flex items-center gap-2 h-8 text-sm"><input type="checkbox" checked={f.tls} onChange={(e) => setF({ ...f, tls: e.target.checked })} /> https / wrap TLS</label></L>
            <div className="col-span-2"><L label="Path"><input className="input mono" value={f.path} onChange={(e) => setF({ ...f, path: e.target.value })} /></L></div>
            <div className="col-span-2"><L label="Query params (key: value per line)"><textarea className="input mono h-16" value={f.params} onChange={(e) => setF({ ...f, params: e.target.value })} placeholder={"page: {{PAYLOAD}}"} /></L></div>
            <div className="col-span-2"><L label="Headers (key: value per line)"><textarea className="input mono h-16" value={f.headers} onChange={(e) => setF({ ...f, headers: e.target.value })} placeholder={"User-Agent: okhttp/4"} /></L></div>
            {f.method === "POST" && <div className="col-span-2"><L label="Body (use {{PAYLOAD}})"><textarea className="input mono h-16" value={f.body} onChange={(e) => setF({ ...f, body: e.target.value })} /></L></div>}
            <div className="col-span-2"><L label="Payload / test input"><input className="input mono" value={f.payload} onChange={(e) => setF({ ...f, payload: e.target.value })} placeholder="../../../../etc/passwd" /></L></div>
            <L label="Expected marker"><input className="input mono" value={f.expected} onChange={(e) => setF({ ...f, expected: e.target.value })} placeholder="root:x:" /></L>
            <L label="Timeout (s)"><input className="input mono" value={f.timeout} onChange={(e) => setF({ ...f, timeout: e.target.value })} /></L>
          </div>
          <button className="btn btn-primary" disabled={!f.host || gen.isPending} onClick={() => gen.mutate()}>{gen.isPending ? <Spinner className="text-white" /> : <Code2 className="h-4 w-4" />} Generate</button>
        </div>
      </Panel>
      <Panel title={result ? `Script · ${result.filename}` : "Script"} actions={result && <button className="btn btn-sm" onClick={download}><Download className="h-3.5 w-3.5" />Export .py</button>}>
        <div className="p-3">
          {!result ? <EmptyState title="No script yet" hint="Configure the request and click Generate. The script is deterministic and editable." /> :
            <CodeBlock code={result.script} className="max-h-[70vh]" wrap />}
        </div>
      </Panel>
    </div>
  );
}
