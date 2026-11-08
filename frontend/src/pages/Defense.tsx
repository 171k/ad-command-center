import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Play, Save, BookOpen, FileCode2, ChevronDown, ChevronRight } from "lucide-react";
import { get, post } from "../lib/api";
import { useToast } from "../lib/toast";
import { PageBody, PageHeader } from "../components/Page";
import { HowToUse } from "../components/HowToUse";
import { CodeEditor } from "../components/CodeEditor";
import { Badge, CodeBlock, CopyButton, EmptyState, Panel, Spinner, Tabs } from "../components/ui";
import { CONFIDENCE_META } from "../lib/format";

const LANGS = ["auto", "python", "php", "javascript", "java", "c", "cpp", "shell"];

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
      <PageHeader title="Defense" subtitle="Deterministic code analysis · patches · regression tests (no AI)" />
      <div className="px-5 pt-3 bg-bg-raised/40 border-b border-line flex items-end justify-between gap-3">
        <Tabs
          active={tab}
          onChange={setTab}
          tabs={[
            { id: "analyze", label: <span className="flex items-center gap-1.5"><Play className="h-3.5 w-3.5" />Analyze</span> },
            { id: "rules", label: <span className="flex items-center gap-1.5"><BookOpen className="h-3.5 w-3.5" />Rule library</span> },
            { id: "saved", label: <span className="flex items-center gap-1.5"><FileCode2 className="h-3.5 w-3.5" />Saved</span> },
          ]}
        />
        <HowToUse page="defense" className="mb-1.5" />
      </div>
      <PageBody className="p-0">
        {tab === "analyze" && <Analyze />}
        {tab === "rules" && <RuleLibrary />}
        {tab === "saved" && <Saved />}
      </PageBody>
    </>
  );
}

function Analyze() {
  const toast = useToast();
  const [code, setCode] = useState(SAMPLE);
  const [lang, setLang] = useState("auto");
  const [result, setResult] = useState<any>(null);

  const run = useMutation({
    mutationFn: () => post("/defense/analyze", { code, language: lang === "auto" ? null : lang, use_semgrep: true }),
    onSuccess: (r) => setResult(r),
    onError: (e: any) => toast("error", e.message),
  });

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
          <button className="btn btn-primary" disabled={run.isPending || !code.trim()} onClick={() => run.mutate()}>
            {run.isPending ? <Spinner className="text-white" /> : <Play className="h-4 w-4" />} Analyze
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
            hint="Paste code and run Analyze. Findings show matched lines, why the pattern is dangerous, a patch, and a regression test. 'No match' never means the code is proven safe." /></Panel>
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
          <span className="mono">{f.cwe}</span>
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
          <Info label="Why it's dangerous" text={f.why_dangerous} />
          {f.preconditions && <Info label="Preconditions" text={f.preconditions} />}
          {f.taint_evidence && <Info label="Input source detected" text={f.taint_evidence} mono />}
          {f.test_procedure && <Info label="Safe test (authorized only)" text={f.test_procedure} />}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {f.exploit_template && <Labeled label="Verification template"><CodeBlock code={f.exploit_template} className="max-h-40" /></Labeled>}
            {f.remediation && <Labeled label="Suggested patch"><CodeBlock code={f.remediation} className="max-h-40" /></Labeled>}
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
