import { useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Play, Save, BookOpen, FileCode2, ChevronDown, ChevronRight, Upload, FolderArchive } from "lucide-react";
import { get, post, upload } from "../lib/api";
import { useToast } from "../lib/toast";
import { PageBody, PageHeader } from "../components/Page";
import { HowToUse } from "../components/HowToUse";
import { CodeEditor } from "../components/CodeEditor";
import { Badge, CodeBlock, CopyButton, EmptyState, Panel, Spinner, Tabs } from "../components/ui";
import { CONFIDENCE_META } from "../lib/format";

const LANGS = ["auto", "python", "php", "javascript", "typescript", "java", "go", "ruby", "c", "cpp", "shell"];

const SAMPLE = `# Paste code to analyze. Example (Flask):
import subprocess
def ping(host):
    return subprocess.run("ping -c1 " + host, shell=True)

query = "SELECT * FROM users WHERE id = " + request.args.get("id")
cur.execute(query)`;

export function Defense() {
  const [tab, setTab] = useState("analyze");
  return (
    <>
      <PageHeader title="Defense" subtitle="Code review: paste or upload · built-in rules + Semgrep · exploit, payload, patch (no AI)" />
      <div className="px-5 pt-3 bg-bg-raised/40 border-b border-line flex items-end justify-between gap-3">
        <Tabs
          active={tab}
          onChange={setTab}
          tabs={[
            { id: "analyze", label: <span className="flex items-center gap-1.5"><Play className="h-3.5 w-3.5" />Analyze</span> },
            { id: "project", label: <span className="flex items-center gap-1.5"><FolderArchive className="h-3.5 w-3.5" />Project (zip)</span> },
            { id: "rules", label: <span className="flex items-center gap-1.5"><BookOpen className="h-3.5 w-3.5" />Rule library</span> },
            { id: "saved", label: <span className="flex items-center gap-1.5"><FileCode2 className="h-3.5 w-3.5" />Saved</span> },
          ]}
        />
        <HowToUse page="defense" className="mb-1.5" />
      </div>
      <PageBody className="p-0">
        {tab === "analyze" && <Analyze onUseProject={() => setTab("project")} />}
        {tab === "project" && <ProjectScan />}
        {tab === "rules" && <RuleLibrary />}
        {tab === "saved" && <Saved />}
      </PageBody>
    </>
  );
}

function Analyze({ onUseProject }: { onUseProject: () => void }) {
  const toast = useToast();
  const [code, setCode] = useState(SAMPLE);
  const [lang, setLang] = useState("auto");
  const [result, setResult] = useState<any>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const run = useMutation({
    mutationFn: () => post("/defense/analyze", { code, language: lang === "auto" ? null : lang, use_semgrep: true }),
    onSuccess: (r) => setResult(r),
    onError: (e: any) => toast("error", e.message),
  });

  const uploadM = useMutation({
    mutationFn: async (file: File) => {
      const text = await file.text();
      if (text.includes("\u0000")) {
        throw new Error("That looks like a binary file. Upload a text source file, or use the Project (zip) tab for a whole project.");
      }
      setCode(text);
      const q = lang === "auto" ? "" : `&language=${lang}`;
      const fd = new FormData();
      fd.append("file", file);
      return upload(`/defense/analyze-file?use_semgrep=true${q}`, fd);
    },
    onSuccess: (r) => setResult(r),
    onError: (e: any) => toast("error", e.message),
  });

  const ARCHIVE = /\.(zip|tar|gz|tgz|tar\.gz|rar|7z|jar|war|bz2|xz)$/i;

  function onPickFile(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    e.target.value = ""; // allow re-selecting the same file
    if (!f) return;
    if (ARCHIVE.test(f.name)) {
      toast("info", "That is an archive. Opening the Project (zip) tab to scan the whole project.");
      onUseProject();
      return;
    }
    uploadM.mutate(f);
  }

  const save = useMutation({
    mutationFn: () => post("/defense/save", { title: `Analysis (${result.language})`, language: result.language, code, result }),
    onSuccess: () => toast("ok", "Analysis saved"),
    onError: (e: any) => toast("error", e.message),
  });

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 p-5 h-full min-h-0">
      <div className="flex flex-col min-h-0 gap-3">
        <div className="flex items-center gap-2">
          <select className="input w-40" value={lang} onChange={(e) => setLang(e.target.value)}>
            {LANGS.map((l) => <option key={l} value={l}>{l === "auto" ? "Auto-detect" : l}</option>)}
          </select>
          <button className="btn btn-primary" disabled={run.isPending || uploadM.isPending || !code.trim()} onClick={() => run.mutate()}>
            {run.isPending ? <Spinner className="text-white" /> : <Play className="h-4 w-4" />} Analyze
          </button>
          <input ref={fileRef} type="file" className="hidden"
            accept=".py,.js,.jsx,.mjs,.ts,.tsx,.php,.java,.go,.c,.h,.cc,.cpp,.hpp,.rb,.sh,.bash,.txt,text/*"
            onChange={onPickFile} />
          <button className="btn" disabled={uploadM.isPending} onClick={() => fileRef.current?.click()} title="Upload a source file to analyze">
            {uploadM.isPending ? <Spinner /> : <Upload className="h-4 w-4" />} Upload file
          </button>
          {result && (
            <button className="btn" onClick={() => save.mutate()} disabled={save.isPending}>
              <Save className="h-4 w-4" /> Save
            </button>
          )}
          <div className="ml-auto"><CopyButton text={code} label="Copy" /></div>
        </div>
        <div className="flex-1 min-h-0">
          <CodeEditor value={code} onChange={setCode} placeholder="Paste source code…" minRows={22} />
        </div>
      </div>

      <div className="min-h-0 overflow-auto">
        {!result ? (
          <Panel className="h-full"><EmptyState icon={<Shield2 />} title="No analysis yet"
            hint="Paste code or upload a file, then run Analyze. Each finding shows the line, the possible exploit, an example payload and how to patch it. Built-in curated rules run alongside Semgrep. 'No match' never means the code is proven safe." /></Panel>
        ) : (
          <Results result={result} />
        )}
      </div>
    </div>
  );
}

function Shield2() {
  return <FileCode2 className="h-7 w-7" />;
}

function Results({ result }: { result: any }) {
  return (
    <div className="space-y-3">
      <Panel bodyClass="p-3">
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {result.filename && <Badge className="border-accent/40 text-accent bg-accent/10">{result.filename}</Badge>}
          <Badge className="border-line-strong text-ink-dim">lang: {result.language}</Badge>
          <Badge className="border-line-strong text-ink-dim">engine: {result.engine}</Badge>
          <span className="text-ink-faint">{result.finding_count} finding(s)</span>
          {Object.entries(result.category_counts || {}).filter(([, v]: any) => v > 0).map(([k, v]: any) => (
            <Badge key={k} className={CONFIDENCE_META[k]?.cls || "border-line-strong"}>{CONFIDENCE_META[k]?.label || k}: {v}</Badge>
          ))}
        </div>
        {result.semgrep_note && <p className="text-2xs text-ink-faint mt-2">{result.semgrep_note}</p>}
        {result.no_match_notice && (
          <p className="text-xs text-accent bg-accent/10 border border-accent/30 rounded px-2.5 py-2 mt-2">{result.no_match_notice}</p>
        )}
      </Panel>
      {result.findings.map((f: any, i: number) => <Finding key={i} f={f} />)}
      <p className="text-2xs text-ink-faint px-1">{result.disclaimer}</p>
    </div>
  );
}

function Finding({ f }: { f: any }) {
  const [open, setOpen] = useState(true);
  const meta = CONFIDENCE_META[f.confidence] || CONFIDENCE_META.potential;
  return (
    <Panel>
      <button className="w-full flex items-center gap-2 px-3 h-11 text-left" onClick={() => setOpen(!open)}>
        {open ? <ChevronDown className="h-4 w-4 text-ink-faint" /> : <ChevronRight className="h-4 w-4 text-ink-faint" />}
        <span className="text-sm font-medium">{f.name}</span>
        <Badge className={`${meta.cls} ml-1`}>{meta.label}</Badge>
        <span className="ml-auto flex items-center gap-2 text-2xs text-ink-faint">
          {f.engine && <Badge className="border-line-strong text-ink-faint uppercase">{f.engine}</Badge>}
          {f.cwe && <span className="mono">{f.cwe}</span>}
          <span>line {f.line}</span>
        </span>
      </button>
      {open && (
        <div className="px-3 pb-3 space-y-3 border-t border-line pt-3">
          {f.snippet?.length > 0 && (
            <CodeBlock
              code={f.snippet.map((s: any) => s.text).join("\n")}
              highlightLines={f.snippet.reduce((acc: number[], s: any, idx: number) => (s.hit ? [...acc, idx + 1] : acc), [])}
            />
          )}
          <Info label="What it is" text={f.description} />
          {f.why_dangerous && <Info label="Possible exploit" text={f.why_dangerous} />}
          {f.preconditions && <Info label="Preconditions" text={f.preconditions} />}
          {f.taint_evidence && <Info label="Input source detected" text={f.taint_evidence} mono />}
          {f.test_procedure && <Info label="Safe test (authorized only)" text={f.test_procedure} />}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {f.exploit_template && <Labeled label="Example payload"><CodeBlock code={f.exploit_template} className="max-h-40" /></Labeled>}
            {f.remediation && <Labeled label="How to patch"><CodeBlock code={f.remediation} className="max-h-40" /></Labeled>}
          </div>
          {f.why_patch_works && <Info label="Why the patch works" text={f.why_patch_works} />}
          {f.regression_test && <Labeled label="Regression test"><CodeBlock code={f.regression_test} className="max-h-40" /></Labeled>}
          {f.limitations && <Info label="Limitations of this analysis" text={f.limitations} />}
          {f.references?.length > 0 && (
            <div className="text-2xs text-ink-faint">
              References: {f.references.map((r: string, i: number) => (
                <a key={i} href={r} target="_blank" rel="noreferrer" className="text-accent hover:underline mr-2">{new URL(r).hostname}</a>
              ))}
            </div>
          )}
        </div>
      )}
    </Panel>
  );
}

function Info({ label, text, mono }: { label: string; text: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-2xs font-semibold uppercase tracking-wider text-ink-faint">{label}</div>
      <div className={`text-sm text-ink-dim ${mono ? "mono" : ""}`}>{text}</div>
    </div>
  );
}
function Labeled({ label, children }: { label: string; children: any }) {
  return (
    <div>
      <div className="text-2xs font-semibold uppercase tracking-wider text-ink-faint mb-1 flex items-center justify-between">
        {label}
      </div>
      {children}
    </div>
  );
}

function ProjectScan() {
  const toast = useToast();
  const [jobId, setJobId] = useState<number | null>(null);
  const [sev, setSev] = useState("all");
  const fileRef = useRef<HTMLInputElement>(null);

  const scans = useQuery({ queryKey: ["scans"], queryFn: () => get("/defense/scans") });

  const startM = useMutation({
    mutationFn: async (file: File) => {
      const fd = new FormData();
      fd.append("file", file);
      return upload("/defense/scan", fd);
    },
    onSuccess: (r: any) => { setJobId(r.job_id); scans.refetch(); },
    onError: (e: any) => toast("error", e.message),
  });

  const job = useQuery({
    queryKey: ["scan", jobId],
    queryFn: () => get(`/defense/scan/${jobId}`),
    enabled: jobId != null,
    refetchInterval: (q: any) => {
      const s = q.state.data?.status;
      return s === "done" || s === "error" ? false : 1500;
    },
  });

  function onPick(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    if (f) startM.mutate(f);
    e.target.value = "";
  }

  const d: any = job.data;
  const running = d && (d.status === "queued" || d.status === "running");
  const res = d?.result;

  return (
    <div className="p-5 space-y-4 max-w-5xl">
      <div className="flex flex-wrap items-center gap-2">
        <input ref={fileRef} type="file" accept=".zip,application/zip" className="hidden" onChange={onPick} />
        <button className="btn btn-primary" disabled={startM.isPending || running} onClick={() => fileRef.current?.click()}>
          {startM.isPending ? <Spinner className="text-white" /> : <FolderArchive className="h-4 w-4" />} Upload project zip
        </button>
        {(d || startM.isPending) && <button className="btn" onClick={() => setJobId(null)}>New scan</button>}
        <span className="text-2xs text-ink-faint">Extracted and statically analyzed, never executed. Up to 200 MB. node_modules, vendor and .git are skipped.</span>
      </div>

      {running && (
        <Panel bodyClass="p-4">
          <div className="flex items-center gap-3">
            <Spinner />
            <div>
              <div className="text-sm">{d.phase || "Scanning…"}</div>
              <div className="text-2xs text-ink-faint">{d.filename} · {d.scanned_files}/{d.total_files || "…"} files</div>
            </div>
          </div>
        </Panel>
      )}

      {d?.status === "error" && (
        <Panel bodyClass="p-4"><p className="text-sm text-bad">Scan failed: {d.error}</p></Panel>
      )}

      {res && (
        <>
          <Panel bodyClass="p-3">
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <Badge className="border-accent/40 text-accent bg-accent/10">{d.filename}</Badge>
              <span className="text-ink-faint">{res.files_with_findings} file(s) with findings · {d.finding_count} total · {res.files_scanned} scanned</span>
              {Object.entries(res.totals || {}).filter(([, v]: any) => v > 0).map(([k, v]: any) => (
                <Badge key={k} className={CONFIDENCE_META[k]?.cls || "border-line-strong"}>{CONFIDENCE_META[k]?.label || k}: {v}</Badge>
              ))}
              <select className="input ml-auto w-44" value={sev} onChange={(e) => setSev(e.target.value)}>
                <option value="all">All severities</option>
                <option value="potential">Potential and up</option>
                <option value="strong">Strong only</option>
              </select>
            </div>
            {!res.semgrep_ran && <p className="text-2xs text-ink-faint mt-2">Semgrep not available on this server; built-in rules only.</p>}
          </Panel>
          {res.files.length === 0
            ? <EmptyState title="No findings" hint="No curated or Semgrep pattern fired across the project. This does not prove it is secure." />
            : res.files.map((fe: any) => <ProjectFile key={fe.path} fe={fe} sev={sev} />)}
          <p className="text-2xs text-ink-faint px-1">{res.disclaimer}</p>
        </>
      )}

      {!d && !startM.isPending && (
        <Panel title="Recent scans">
          {(scans.data?.items || []).length === 0
            ? <div className="p-4 text-sm text-ink-faint">No scans yet. Upload a project zip to start.</div>
            : <div className="divide-y divide-line">
                {scans.data.items.map((s: any) => (
                  <button key={s.id} className="w-full text-left p-3 flex items-center gap-2 text-sm row-hover" onClick={() => setJobId(s.id)}>
                    <FolderArchive className="h-4 w-4 text-ink-faint" />
                    <span className="font-medium">{s.filename || `scan #${s.id}`}</span>
                    <Badge className="border-line-strong text-ink-dim">{s.status}</Badge>
                    <span className="ml-auto text-2xs text-ink-faint">{s.finding_count} findings · {s.created_at} · {s.label}</span>
                  </button>
                ))}
              </div>}
        </Panel>
      )}
    </div>
  );
}

function ProjectFile({ fe, sev }: { fe: any; sev: string }) {
  const [open, setOpen] = useState(false);
  const order: any = { strong: 2, potential: 1, needs_context: 0 };
  const min = sev === "strong" ? 2 : sev === "potential" ? 1 : 0;
  const findings = fe.findings.filter((f: any) => (order[f.confidence] ?? 0) >= min);
  if (findings.length === 0) return null;
  return (
    <Panel>
      <button className="w-full flex items-center gap-2 px-3 h-11 text-left" onClick={() => setOpen(!open)}>
        {open ? <ChevronDown className="h-4 w-4 text-ink-faint" /> : <ChevronRight className="h-4 w-4 text-ink-faint" />}
        <span className="text-sm font-medium mono truncate">{fe.path}</span>
        <span className="ml-auto flex items-center gap-1.5 shrink-0">
          {fe.counts.strong > 0 && <Badge className={CONFIDENCE_META.strong.cls}>{fe.counts.strong}</Badge>}
          {fe.counts.potential > 0 && <Badge className={CONFIDENCE_META.potential.cls}>{fe.counts.potential}</Badge>}
          {fe.counts.needs_context > 0 && <Badge className="border-line-strong text-ink-faint">{fe.counts.needs_context}</Badge>}
        </span>
      </button>
      {open && <div className="px-3 pb-3 space-y-3 border-t border-line pt-3">{findings.map((f: any, i: number) => <Finding key={i} f={f} />)}</div>}
    </Panel>
  );
}

function RuleLibrary() {
  const [q, setQ] = useState("");
  const { data } = useQuery({ queryKey: ["rules", q], queryFn: () => get(`/defense/rules?q=${encodeURIComponent(q)}`) });
  return (
    <div className="p-5 max-w-4xl">
      <input className="input mb-3 max-w-sm" placeholder="Search rules (name, CWE)…" value={q} onChange={(e) => setQ(e.target.value)} />
      <div className="panel divide-y divide-line">
        {(data?.items || []).map((r: any) => (
          <div key={r.id} className="p-3">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">{r.name}</span>
              <Badge className="border-line-strong text-ink-dim mono">{r.cwe}</Badge>
              <span className="ml-auto text-2xs text-ink-faint">{r.languages.join(", ")}</span>
            </div>
            <p className="text-xs text-ink-dim mt-1">{r.description}</p>
          </div>
        ))}
        {data?.items?.length === 0 && <div className="p-6 text-center text-sm text-ink-faint">No rules match.</div>}
      </div>
    </div>
  );
}

function Saved() {
  const { data } = useQuery({ queryKey: ["analyses"], queryFn: () => get("/defense/analyses") });
  const items = data?.items || [];
  if (items.length === 0) return <Panel className="m-5"><EmptyState title="No saved analyses" hint="Run an analysis and click Save to keep it here." /></Panel>;
  return (
    <div className="p-5">
      <div className="panel divide-y divide-line">
        {items.map((a: any) => (
          <div key={a.id} className="p-3 flex items-center gap-2 text-sm">
            <FileCode2 className="h-4 w-4 text-ink-faint" />
            <span className="font-medium">{a.title || `Analysis #${a.id}`}</span>
            <Badge className="border-line-strong text-ink-dim">{a.language}</Badge>
            <span className="ml-auto text-2xs text-ink-faint">{a.created_at} · {a.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
