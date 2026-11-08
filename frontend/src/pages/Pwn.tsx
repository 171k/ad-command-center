import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Binary, Upload, Cpu, Wrench, Trash2, Save, Lock } from "lucide-react";
import { get, post, del } from "../lib/api";
import { useToast } from "../lib/toast";
import { PageBody, PageHeader } from "../components/Page";
import { HowToUse } from "../components/HowToUse";
import { Badge, CodeBlock, EmptyState, Panel, Spinner, Tabs } from "../components/ui";
import { CodeEditor } from "../components/CodeEditor";

export function Pwn() {
  const [sel, setSel] = useState<number | null>(null);
  const [tab, setTab] = useState("cases");
  return (
    <>
      <PageHeader title="Pwn Solver" subtitle="ELF analysis · checksec · ROP/cyclic · exploit scripts (static; execution is sandboxed locally)" />
      <div className="px-5 pt-3 bg-bg-raised/40 border-b border-line flex items-end justify-between gap-3">
        <Tabs active={tab} onChange={setTab} tabs={[
          { id: "cases", label: <span className="flex items-center gap-1.5"><Binary className="h-3.5 w-3.5" />Binaries</span> },
          { id: "utils", label: <span className="flex items-center gap-1.5"><Wrench className="h-3.5 w-3.5" />Utilities</span> },
        ]} />
        <HowToUse page="pwn" className="mb-1.5" />
      </div>
      <PageBody className="p-0">
        {tab === "cases" && <Cases sel={sel} setSel={setSel} />}
        {tab === "utils" && <Utilities />}
      </PageBody>
    </>
  );
}

function Cases({ sel, setSel }: { sel: number | null; setSel: (n: number | null) => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const { data } = useQuery({ queryKey: ["pwn-cases"], queryFn: () => get("/pwn/cases") });
  async function upload(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0]; if (!f) return;
    const fd = new FormData(); fd.append("file", f); fd.append("name", f.name);
    const m = document.cookie.match(/(?:^|;\s*)adcc_csrf=([^;]+)/);
    const res = await fetch("/api/pwn/cases", { method: "POST", credentials: "include", body: fd, headers: { "X-CSRF-Token": m ? decodeURIComponent(m[1]) : "" } });
    const j = await res.json();
    if (res.ok) { qc.invalidateQueries({ queryKey: ["pwn-cases"] }); setSel(j.id); toast("ok", `Analyzed ${f.name}`); }
    else toast("error", j.detail || "upload failed");
  }
  const items = data?.items || [];
  return (
    <div className="grid grid-cols-[18rem_1fr] h-full min-h-0">
      <div className="border-r border-line flex flex-col min-h-0">
        <div className="h-11 flex items-center justify-between px-3 border-b border-line">
          <span className="text-xs font-semibold text-ink-dim">{items.length} binaries</span>
          <label className="btn btn-sm btn-primary cursor-pointer"><Upload className="h-3.5 w-3.5" />Upload<input type="file" className="hidden" onChange={upload} /></label>
        </div>
        <div className="overflow-auto flex-1">
          {items.map((c: any) => (
            <button key={c.id} onClick={() => setSel(c.id)} className={`w-full text-left px-3 py-2 border-b border-line/60 hover:bg-bg-hover ${sel === c.id ? "bg-accent/10" : ""}`}>
              <div className="text-sm font-medium truncate">{c.name}</div>
              <div className="text-2xs text-ink-faint">{c.arch || "?"} · {(c.size_bytes / 1024).toFixed(0)}KB · {c.label}</div>
            </button>
          ))}
          {items.length === 0 && <div className="p-6 text-center text-xs text-ink-faint">Upload an ELF challenge binary to analyze it. It is parsed, never executed.</div>}
        </div>
      </div>
      <div className="min-h-0 overflow-auto">
        {sel ? <CaseDetail cid={sel} onDelete={() => { setSel(null); qc.invalidateQueries({ queryKey: ["pwn-cases"] }); }} /> :
          <EmptyState icon={<Binary className="h-7 w-7" />} title="Select or upload a binary" hint="Static analysis: format, arch, NX/PIE/RELRO/canary, symbols, strings, ROP gadgets, exploit template." />}
      </div>
    </div>
  );
}

function Prot({ label, on, goodWhenOn = true }: { label: string; on: boolean; goodWhenOn?: boolean }) {
  const good = goodWhenOn ? on : !on;
  return <Badge className={good ? "border-ok/30 text-ok bg-ok/10" : "border-bad/40 text-bad bg-bad/10"}>{label}: {on ? "on" : "off"}</Badge>;
}

function CaseDetail({ cid, onDelete }: { cid: number; onDelete: () => void }) {
  const toast = useToast();
  const qc = useQueryClient();
  const { data: c } = useQuery({ queryKey: ["pwn-case", cid], queryFn: () => get(`/pwn/cases/${cid}`) });
  const { data: gadgets } = useQuery({ queryKey: ["pwn-gadgets", cid], queryFn: () => get(`/pwn/cases/${cid}/gadgets`) });
  const { data: tmpl } = useQuery({ queryKey: ["pwn-tmpl", cid], queryFn: () => get(`/pwn/cases/${cid}/template`) });
  const [script, setScript] = useState("");
  const saveScript = useMutation({
    mutationFn: () => post(`/pwn/cases/${cid}/scripts`, { name: "exploit.py", body: script || tmpl?.template || "" }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["pwn-case", cid] }); toast("ok", "Script saved"); },
  });
  const delCase = useMutation({ mutationFn: () => del(`/pwn/cases/${cid}`), onSuccess: onDelete });

  if (!c) return <div className="p-6"><Spinner /></div>;
  const cs = c.analysis?.checksec;
  return (
    <div className="p-5 space-y-3 max-w-4xl">
      <div className="flex items-center gap-2">
        <h2 className="text-sm font-semibold">{c.name}</h2>
        <span className="mono text-2xs text-ink-faint">{c.sha256?.slice(0, 24)}…</span>
        <button className="btn btn-ghost btn-sm text-bad ml-auto" onClick={() => delCase.mutate()}><Trash2 className="h-3.5 w-3.5" /></button>
      </div>

      <Panel title="Security protections (checksec)">
        <div className="p-3">
          {cs ? (
            <div className="flex flex-wrap gap-2">
              <Badge className="border-line-strong text-ink-dim">{cs.arch} {cs.bits}-bit {cs.endian}</Badge>
              <Badge className="border-line-strong text-ink-dim">{cs.type}</Badge>
              <Prot label="NX" on={cs.nx} />
              <Prot label="PIE" on={cs.pie} />
              <Badge className={cs.relro === "Full" ? "border-ok/30 text-ok bg-ok/10" : cs.relro === "Partial" ? "border-warn/40 text-warn bg-warn/10" : "border-bad/40 text-bad bg-bad/10"}>RELRO: {cs.relro}</Badge>
              <Prot label="Canary" on={cs.canary} />
              <Prot label="Fortify" on={cs.fortify} />
              <Badge className={cs.stripped ? "border-warn/40 text-warn bg-warn/10" : "border-line-strong text-ink-dim"}>{cs.stripped ? "stripped" : "not stripped"}</Badge>
            </div>
          ) : <div className="text-xs text-ink-faint">{c.analysis?.note || "Not an ELF."}</div>}
          {cs?.libc_needed?.length > 0 && <div className="text-2xs text-ink-faint mt-2">Needs: {cs.libc_needed.join(", ")}</div>}
        </div>
      </Panel>

      <div className="grid md:grid-cols-2 gap-3">
        <Panel title="Interesting strings">
          <div className="p-3"><CodeBlock code={(c.analysis?.interesting_strings || []).join("\n") || "(none flagged)"} className="max-h-40" /></div>
        </Panel>
        <Panel title={`Symbols (${(c.analysis?.symbols || []).length})`}>
          <div className="p-3"><CodeBlock code={(c.analysis?.symbols || []).join("\n") || "(none / stripped)"} className="max-h-40" /></div>
        </Panel>
      </div>

      <Panel title="ROP gadgets">
        <div className="p-3 space-y-1.5">
          {gadgets ? Object.entries(gadgets.gadgets || {}).map(([k, v]: any) => (
            <div key={k} className="flex items-start gap-2 text-xs">
              <span className="mono text-accent w-40 shrink-0">{k}</span>
              <span className="mono text-ink-dim flex-1 break-all">{v.slice(0, 6).join("  ")}{v.length > 6 ? ` …(+${v.length - 6})` : ""}</span>
            </div>
          )) : <Spinner />}
          {gadgets && Object.keys(gadgets.gadgets || {}).length === 0 && <div className="text-xs text-ink-faint">No common gadgets found.</div>}
          {gadgets?.pie && <div className="text-2xs text-warn">PIE — addresses are offsets; add the runtime base.</div>}
        </div>
      </Panel>

      <Panel title="Exploit script (pwntools)" actions={<button className="btn btn-sm" onClick={() => saveScript.mutate()}><Save className="h-3.5 w-3.5" />Save</button>}>
        <div className="p-3">
          <CodeEditor value={script || tmpl?.template || ""} onChange={setScript} minRows={16} />
          <p className="text-2xs text-ink-faint mt-2 flex items-center gap-1.5"><Lock className="h-3.5 w-3.5" />Run crash/exploit tests in the local sandbox: <span className="mono">python3 scripts/pwn_sandbox.py exploit ./{c.filename} ./exploit.py</span></p>
        </div>
      </Panel>
      {c.scripts?.length > 0 && <div className="text-2xs text-ink-faint">{c.scripts.length} saved script(s)</div>}
    </div>
  );
}

const OPS = [["cyclic", "Cyclic pattern"], ["cyclic-find", "Find offset"], ["pack", "Pack int"], ["unpack", "Unpack hex"]];
function Utilities() {
  const toast = useToast();
  const [op, setOp] = useState("cyclic");
  const [val, setVal] = useState("");
  const [bits, setBits] = useState(64);
  const [out, setOut] = useState<any>(null);
  const run = useMutation({
    mutationFn: async () => {
      if (op === "cyclic") return post("/pwn/cyclic", { length: parseInt(val) || 100 });
      if (op === "cyclic-find") return post("/pwn/cyclic-find", { value: val });
      if (op === "pack") return post("/pwn/pack", { value: val, bits });
      return post("/pwn/unpack", { value: val, bits });
    },
    onSuccess: (r) => setOut(r), onError: (e: any) => toast("error", e.message),
  });
  return (
    <div className="p-5 grid lg:grid-cols-2 gap-4 max-w-4xl">
      <Panel title="Input">
        <div className="p-3 space-y-2">
          <select className="input" value={op} onChange={(e) => { setOp(e.target.value); setOut(null); }}>{OPS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select>
          <input className="input mono" value={val} onChange={(e) => setVal(e.target.value)}
            placeholder={op === "cyclic" ? "length e.g. 200" : op === "cyclic-find" ? "leaked value (0xdeadbeef or text)" : op === "pack" ? "integer e.g. 0x400000" : "hex e.g. efbeadde"} />
          {(op === "pack" || op === "unpack") && (
            <select className="input w-32" value={bits} onChange={(e) => setBits(parseInt(e.target.value))}><option value={32}>32-bit</option><option value={64}>64-bit</option></select>
          )}
          <button className="btn btn-primary w-full" onClick={() => run.mutate()}><Cpu className="h-4 w-4" />Run</button>
        </div>
      </Panel>
      <Panel title="Output">
        <div className="p-3">{out === null ? <EmptyState title="No output" /> : <CodeBlock code={JSON.stringify(out, null, 2)} className="max-h-[50vh]" />}</div>
      </Panel>
    </div>
  );
}
