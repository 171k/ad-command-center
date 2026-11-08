import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Package, Search, Download, Upload, ShieldCheck, Boxes, RefreshCw } from "lucide-react";
import { get, post } from "../lib/api";
import { useToast } from "../lib/toast";
import { PageBody, PageHeader } from "../components/Page";
import { HowToUse } from "../components/HowToUse";
import { Badge, CodeBlock, CopyButton, EmptyState, Panel, Spinner } from "../components/ui";
import { Drawer } from "../components/overlay";

export function Tools() {
  const toast = useToast();
  const qc = useQueryClient();
  const [q, setQ] = useState("");
  const [cat, setCat] = useState("");
  const [sel, setSel] = useState<string | null>(null);
  const { data, isLoading } = useQuery({ queryKey: ["tools", q, cat], queryFn: () => get(`/tools?${q ? `q=${encodeURIComponent(q)}&` : ""}${cat ? `category=${encodeURIComponent(cat)}` : ""}`) });

  const seedM = useMutation({ mutationFn: () => post("/tools/seed"), onSuccess: (r: any) => { qc.invalidateQueries({ queryKey: ["tools"] }); toast("ok", `Catalog seeded (+${r.seeded})`); } });
  async function downloadBundle() {
    try {
      const res = await fetch("/api/tools/export/bundle", { credentials: "include" });
      if (!res.ok) throw new Error("export failed");
      const blob = await res.blob();
      const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = "adcc-tool-bundle.zip"; a.click();
      toast("ok", `Offline bundle downloaded (${(blob.size / 1e6).toFixed(1)} MB)`);
    } catch (e: any) { toast("error", e.message); }
  }

  const items = data?.items || [];
  const cats = data?.categories || [];
  return (
    <>
      <PageHeader title="Tool Repository" subtitle="Self-hosted tool catalog · no GitHub needed at competition time"
        actions={<>
          <button className="btn btn-sm" onClick={() => seedM.mutate()} title="Load/refresh catalog metadata"><RefreshCw className="h-3.5 w-3.5" />Seed</button>
          <button className="btn btn-sm btn-primary" onClick={downloadBundle}><Boxes className="h-3.5 w-3.5" />Offline bundle</button>
          <HowToUse page="tools" />
        </>} />
      <PageBody>
        <div className="flex flex-wrap gap-2 mb-3">
          <div className="relative">
            <Search className="h-3.5 w-3.5 absolute left-2.5 top-2.5 text-ink-faint" />
            <input className="input pl-8 w-64" placeholder="Search tools…" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <select className="input w-52" value={cat} onChange={(e) => setCat(e.target.value)}>
            <option value="">All categories</option>
            {cats.map((c: string) => <option key={c}>{c}</option>)}
          </select>
          <span className="ml-auto self-center text-xs text-ink-faint">{data?.total ?? 0} tools</span>
        </div>
        {isLoading ? <Spinner /> : items.length === 0 ? (
          <Panel><EmptyState icon={<Package className="h-7 w-7" />} title="Catalog empty" hint="Click Seed to load the curated tool catalog." /></Panel>
        ) : (
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-3">
            {items.map((t: any) => (
              <button key={t.slug} onClick={() => setSel(t.slug)} className="panel p-3 text-left hover:bg-bg-hover transition-colors">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium">{t.name}</span>
                  {t.artifact_count > 0 && <Badge className="border-ok/30 text-ok bg-ok/10"><Download className="h-3 w-3" />{t.artifact_count}</Badge>}
                </div>
                <div className="text-2xs text-ink-faint mt-0.5">{t.category} · {t.license || "-"}{t.version ? ` · v${t.version}` : ""}</div>
                <p className="text-xs text-ink-dim mt-1.5 line-clamp-2">{t.description}</p>
              </button>
            ))}
          </div>
        )}
      </PageBody>
      {sel && <ToolDetail slug={sel} onClose={() => setSel(null)} />}
    </>
  );
}

function ToolDetail({ slug, onClose }: { slug: string; onClose: () => void }) {
  const toast = useToast();
  const qc = useQueryClient();
  const { data: t } = useQuery({ queryKey: ["tool", slug], queryFn: () => get(`/tools/${slug}`) });
  const [os, setOs] = useState("ubuntu");

  async function dl(aid: number, filename: string, sha: string) {
    try {
      const res = await fetch(`/api/tools/${slug}/artifacts/${aid}/download`, { credentials: "include" });
      if (!res.ok) throw new Error("download failed");
      const hdr = res.headers.get("X-Checksum-SHA256");
      const blob = await res.blob();
      const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = filename; a.click();
      toast(hdr === sha ? "ok" : "error", hdr === sha ? `Downloaded ${filename} (checksum OK)` : "Checksum header mismatch!");
    } catch (e: any) { toast("error", e.message); }
  }
  async function upload(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0]; if (!f) return;
    const fd = new FormData(); fd.append("file", f); fd.append("os", os);
    const m = document.cookie.match(/(?:^|;\s*)adcc_csrf=([^;]+)/);
    const res = await fetch(`/api/tools/${slug}/artifacts`, { method: "POST", credentials: "include", body: fd, headers: { "X-CSRF-Token": m ? decodeURIComponent(m[1]) : "" } });
    const j = await res.json();
    if (res.ok) { toast("ok", `Uploaded ${j.filename} · sha256 ${j.sha256.slice(0, 12)}…`); qc.invalidateQueries({ queryKey: ["tool", slug] }); }
    else toast("error", j.detail || "upload failed");
  }

  return (
    <Drawer open onClose={onClose} title={t?.name || slug} width="max-w-xl">
      {!t ? <div className="p-6"><Spinner /></div> : (
        <div className="p-4 space-y-3">
          <div className="flex flex-wrap gap-2 text-xs">
            <Badge className="border-line-strong text-ink-dim">{t.category}</Badge>
            {t.version && <Badge className="border-line-strong text-ink-dim">v{t.version}</Badge>}
            {t.license && <Badge className="border-accent/40 text-accent bg-accent/10">{t.license}</Badge>}
          </div>
          <p className="text-sm text-ink-dim">{t.description}</p>
          {t.provenance && <div className="text-2xs text-ink-faint">Source: <span className="mono">{t.provenance}</span></div>}
          <div className="text-2xs text-ink-faint">OS: {(t.os_support || []).join(", ") || "-"} · Deps: {(t.dependencies || []).join(", ") || "none"}</div>

          <Panel title="Hosted artifacts">
            {(t.artifacts || []).length === 0 ? <div className="p-3 text-xs text-ink-faint">No hosted files yet. Upload one below or follow the install instructions.</div> : (
              <table className="w-full"><tbody>
                {t.artifacts.map((a: any) => (
                  <tr key={a.id} className="border-b border-line/60">
                    <td className="td"><div className="text-sm">{a.filename}</div><div className="text-2xs text-ink-faint mono">{a.sha256.slice(0, 24)}… · {a.os}/{a.arch} · {(a.size_bytes / 1024).toFixed(0)}KB</div></td>
                    <td className="td text-right whitespace-nowrap">
                      <CopyButton text={a.sha256} /><button className="btn btn-ghost btn-sm" onClick={() => dl(a.id, a.filename, a.sha256)}><Download className="h-3.5 w-3.5" /></button>
                    </td>
                  </tr>
                ))}
              </tbody></table>
            )}
            <div className="p-3 flex items-center gap-2">
              <select className="input w-32" value={os} onChange={(e) => setOs(e.target.value)}>{["any", "ubuntu", "kali", "wsl2", "windows"].map((o) => <option key={o}>{o}</option>)}</select>
              <label className="btn btn-sm cursor-pointer"><Upload className="h-3.5 w-3.5" />Upload artifact<input type="file" className="hidden" onChange={upload} /></label>
              <span className="text-2xs text-ink-faint">SHA-256 computed on upload</span>
            </div>
          </Panel>

          {t.install && Object.keys(t.install).length > 0 && (
            <Panel title="Install instructions">
              <div className="p-3 space-y-2">
                {Object.entries(t.install).map(([k, v]: any) => (
                  <div key={k}><div className="text-2xs font-semibold uppercase text-ink-faint">{k}</div><CodeBlock code={String(v)} /></div>
                ))}
              </div>
            </Panel>
          )}

          <div className="well p-3 text-2xs text-ink-faint flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-ok shrink-0" />
            Downloads are TLS-protected and checksum-verified. Use <span className="mono">adtools</span> for CLI install:
            <span className="mono">adtools install {slug}</span>
          </div>
        </div>
      )}
    </Drawer>
  );
}
