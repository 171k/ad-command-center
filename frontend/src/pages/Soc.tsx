import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  LayoutDashboard, ShieldAlert, ListFilter, RadioTower, BookOpen, Upload, Send,
} from "lucide-react";
import { get, post } from "../lib/api";
import { useToast } from "../lib/toast";
import { PageBody, PageHeader } from "../components/Page";
import { Badge, CodeBlock, CopyButton, EmptyState, Panel, Spinner, Tabs } from "../components/ui";
import { Drawer } from "../components/overlay";
import { OUTCOME_META, tech, timeAgo } from "../lib/format";
import { GUIDES } from "../lib/setupGuides";

export function Soc() {
  const [tab, setTab] = useState("dashboard");
  return (
    <>
      <PageHeader title="Network / SOC" subtitle="Offense correlation · evidence-based outcomes · traffic" />
      <div className="px-5 pt-3 bg-bg-raised/40 border-b border-line">
        <Tabs active={tab} onChange={setTab} tabs={[
          { id: "dashboard", label: <T i={LayoutDashboard}>Dashboard</T> },
          { id: "offenses", label: <T i={ShieldAlert}>Offenses</T> },
          { id: "events", label: <T i={ListFilter}>Events</T> },
          { id: "sensors", label: <T i={RadioTower}>Sensors</T> },
          { id: "setup", label: <T i={BookOpen}>Setup</T> },
        ]} />
      </div>
      <PageBody>
        {tab === "dashboard" && <Dashboard go={setTab} />}
        {tab === "offenses" && <Offenses />}
        {tab === "events" && <Events />}
        {tab === "sensors" && <Sensors />}
        {tab === "setup" && <Setup />}
      </PageBody>
    </>
  );
}
const T = ({ i: I, children }: any) => <span className="flex items-center gap-1.5"><I className="h-3.5 w-3.5" />{children}</span>;

function Tile({ label, value, cls = "" }: { label: string; value: any; cls?: string }) {
  return (
    <div className="panel p-3">
      <div className="text-2xs uppercase tracking-wider text-ink-faint">{label}</div>
      <div className={`text-2xl font-semibold mt-1 ${cls}`}>{value}</div>
    </div>
  );
}

function Dashboard({ go }: { go: (t: string) => void }) {
  const toast = useToast();
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ["soc-dashboard"], queryFn: () => get("/soc/dashboard") });
  const demoM = useMutation({
    mutationFn: () => post("/soc/ingest", demoPayload()),
    onSuccess: () => { qc.invalidateQueries(); toast("ok", "Sample traffic ingested (demo)"); },
    onError: (e: any) => toast("error", e.message),
  });

  if (isLoading) return <Spinner />;
  const d = data || {};
  return (
    <div className="space-y-4 max-w-6xl">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Tile label="Confirmed" value={d.confirmed ?? 0} cls="text-crit" />
        <Tile label="Possible" value={d.possible ?? 0} cls="text-warn" />
        <Tile label="Active offenses" value={d.active_offenses ?? 0} />
        <Tile label="Blocked" value={d.blocked ?? 0} cls="text-ok" />
        <Tile label="Events" value={d.events_total ?? 0} />
      </div>
      <div className="text-2xs text-ink-faint">
        Last ingest: {d.last_ingest_at ? timeAgo(d.last_ingest_at) : "never"} · counts of blocked/routine attempts are de-emphasized by design.
      </div>

      {d.empty ? (
        <Panel><EmptyState icon={<Upload className="h-7 w-7" />} title="No events yet"
          hint={d.empty_hint}
          action={<button className="btn btn-primary" onClick={() => demoM.mutate()} disabled={demoM.isPending}>Load demo traffic</button>} />
        </Panel>
      ) : (
        <div className="grid lg:grid-cols-2 gap-4">
          <Panel title="Recent activity (1h)">
            <div className="p-3 space-y-1.5">
              {(d.recent_activity || []).map((r: any) => (
                <div key={r.category} className="flex items-center gap-2 text-sm">
                  <span className="w-40 truncate">{tech(r.category)}</span>
                  <div className="flex-1 h-2 bg-bg-inset rounded overflow-hidden">
                    <div className="h-full bg-accent/60" style={{ width: `${Math.min(100, r.c)}%` }} />
                  </div>
                  <span className="mono text-ink-dim w-10 text-right">{r.c}</span>
                </div>
              ))}
              {(d.recent_activity || []).length === 0 && <div className="text-xs text-ink-faint">No activity in the last hour.</div>}
            </div>
          </Panel>
          <Panel title="Monitored services" actions={<button className="btn btn-sm" onClick={() => go("offenses")}>View offenses</button>}>
            <div className="p-3 space-y-1.5">
              {(d.service_health || []).map((s: any, i: number) => (
                <div key={i} className="flex items-center gap-2 text-sm">
                  <span className={`h-2 w-2 rounded-full ${s.status === "online" ? "bg-ok" : s.status === "offline" ? "bg-bad" : "bg-ink-faint"}`} />
                  <span>{s.name}</span><span className="ml-auto text-2xs text-ink-faint">{s.status ?? "unknown"}</span>
                </div>
              ))}
              {(d.service_health || []).length === 0 && <div className="text-xs text-ink-faint">No services configured.</div>}
            </div>
          </Panel>
        </div>
      )}
    </div>
  );
}

function Offenses() {
  const [outcome, setOutcome] = useState("");
  const [noise, setNoise] = useState(false);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<number | null>(null);
  const { data, isLoading } = useQuery({
    queryKey: ["offenses", outcome, noise, q],
    queryFn: () => get(`/soc/offenses?include_noise=${noise}${outcome ? `&outcome=${outcome}` : ""}${q ? `&q=${encodeURIComponent(q)}` : ""}`),
  });
  const items = data?.items || [];
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <select className="input w-40" value={outcome} onChange={(e) => setOutcome(e.target.value)}>
          <option value="">All outcomes</option>
          {Object.keys(OUTCOME_META).map((o) => <option key={o} value={o}>{OUTCOME_META[o].label}</option>)}
        </select>
        <input className="input w-56" placeholder="Search IP / technique…" value={q} onChange={(e) => setQ(e.target.value)} />
        <label className="flex items-center gap-1.5 text-xs text-ink-dim ml-auto">
          <input type="checkbox" checked={noise} onChange={(e) => setNoise(e.target.checked)} /> show blocked / routine noise
        </label>
      </div>
      <Panel>
        {isLoading ? <div className="p-6"><Spinner /></div> : items.length === 0 ? (
          <EmptyState icon={<ShieldAlert className="h-7 w-7" />} title="No offenses match"
            hint="Confirmed compromises and possibly-successful attacks appear first. Enable noise to see blocked/routine attempts." />
        ) : (
          <table className="w-full row-hover">
            <thead><tr>
              <th className="th">Outcome</th><th className="th">Technique</th><th className="th">Attacker → Target</th>
              <th className="th text-right">Events</th><th className="th text-right">Payloads</th><th className="th">Last seen</th><th className="th">Status</th>
            </tr></thead>
            <tbody>
              {items.map((o: any) => {
                const m = OUTCOME_META[o.outcome] || OUTCOME_META.attempted;
                return (
                  <tr key={o.id} className="cursor-pointer" onClick={() => setSel(o.id)}>
                    <td className="td"><Badge className={m.cls}><span className={`h-1.5 w-1.5 rounded-full ${m.dot}`} />{m.label}</Badge></td>
                    <td className="td font-medium">{tech(o.category)}</td>
                    <td className="td mono text-xs">{o.src_ip ?? "?"} <span className="text-ink-faint">→</span> {o.dest_ip}{o.dest_port ? `:${o.dest_port}` : ""}</td>
                    <td className="td text-right mono">{o.event_count}</td>
                    <td className="td text-right mono">{o.distinct_payloads}</td>
                    <td className="td text-ink-dim">{timeAgo(o.last_seen)}</td>
                    <td className="td"><span className="text-xs text-ink-dim">{o.status}</span></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Panel>
      {sel && <OffenseDetail id={sel} onClose={() => setSel(null)} />}
    </div>
  );
}

function OffenseDetail({ id, onClose }: { id: number; onClose: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const { data: o } = useQuery({ queryKey: ["offense", id], queryFn: () => get(`/soc/offenses/${id}`) });
  const [note, setNote] = useState("");
  const act = useMutation({
    mutationFn: (body: any) => post(`/soc/offenses/${id}/action`, body),
    onSuccess: (_r, body: any) => {
      qc.invalidateQueries({ queryKey: ["offense", id] });
      qc.invalidateQueries({ queryKey: ["offenses"] });
      if (body.action === "send_to_defense") toast("ok", "Sent to Defense as a finding");
      if (body.action === "note") setNote("");
    },
    onError: (e: any) => toast("error", e.message),
  });

  const m = o ? (OUTCOME_META[o.outcome] || OUTCOME_META.attempted) : null;
  return (
    <Drawer open onClose={onClose} title={o ? `${tech(o.category)} · offense #${id}` : "Offense"}>
      {!o ? <div className="p-6"><Spinner /></div> : (
        <div className="p-4 space-y-4">
          <div className="flex items-center gap-2">
            <Badge className={m!.cls}><span className={`h-1.5 w-1.5 rounded-full ${m!.dot}`} />{m!.label}</Badge>
            <Badge className="border-line-strong text-ink-dim">{o.event_count} events</Badge>
            <Badge className="border-line-strong text-ink-dim">{o.distinct_payloads} distinct payloads</Badge>
          </div>

          {/* Beginner-friendly plain-language summary */}
          <div className="well p-3 space-y-2">
            <Q q="What happened?" a={o.explanation?.what_happened} />
            <Q q="Who / where?" a={<span className="mono text-xs">{o.src_ip} → {o.dest_ip}{o.dest_port ? `:${o.dest_port}` : ""} · first {o.first_seen} · last {o.last_seen}</span>} />
            <Q q="Did it work?" a={o.explanation?.did_it_work} />
            <Q q="What should we do?" a={o.explanation?.what_to_do} />
          </div>

          {/* Strongest evidence event */}
          {o.top_event && <EventCard title="Strongest evidence request" ev={o.top_event} />}

          {/* Evidence signals */}
          {o.evidence?.signals?.length > 0 && (
            <Panel title="Why this outcome">
              <div className="p-3 space-y-1.5">
                {o.evidence.signals.map((s: any, i: number) => (
                  <div key={i} className="text-xs"><span className="mono text-accent">{s.signal}</span> — <span className="text-ink-dim">{s.detail}</span></div>
                ))}
              </div>
            </Panel>
          )}

          {/* Actions */}
          <div className="flex flex-wrap gap-1.5">
            <button className="btn btn-sm" onClick={() => act.mutate({ action: "investigate" })}>Investigate</button>
            <button className="btn btn-sm" onClick={() => act.mutate({ action: "resolve" })}>Resolve</button>
            <button className="btn btn-sm" onClick={() => act.mutate({ action: "suppress", reason: "routine noise" })}>Suppress</button>
            <button className="btn btn-sm btn-primary" onClick={() => act.mutate({ action: "send_to_defense" })}><Send className="h-3.5 w-3.5" />Send to Defense</button>
          </div>

          {/* Notes */}
          <Panel title="Investigation notes">
            <div className="p-3 space-y-2">
              {(o.notes || []).map((n: any) => (
                <div key={n.id} className="text-sm border-l-2 border-line pl-2">
                  <div className="text-ink-dim">{n.body}</div>
                  <div className="text-2xs text-ink-faint">{n.label ?? "—"} · {n.created_at}</div>
                </div>
              ))}
              <div className="flex gap-2">
                <input className="input flex-1" placeholder="Add a note…" value={note} onChange={(e) => setNote(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && note && act.mutate({ action: "note", note })} />
                <button className="btn" disabled={!note} onClick={() => act.mutate({ action: "note", note })}>Add</button>
              </div>
            </div>
          </Panel>

          {/* Related requests */}
          <Panel title={`Related requests (${o.sample_events?.length || 0} shown)`}>
            <table className="w-full row-hover">
              <thead><tr><th className="th">Time</th><th className="th">Method</th><th className="th">URL</th><th className="th">Status</th><th className="th">Outcome</th></tr></thead>
              <tbody>{(o.sample_events || []).map((e: any) => (
                <tr key={e.id}><td className="td text-ink-faint">{e.ts}</td><td className="td mono">{e.http_method ?? "—"}</td>
                  <td className="td mono text-xs truncate max-w-[16rem]">{e.http_url ?? "—"}</td>
                  <td className="td mono">{e.http_status ?? "—"}</td><td className="td">{e.outcome}</td></tr>
              ))}</tbody>
            </table>
          </Panel>
        </div>
      )}
    </Drawer>
  );
}
const Q = ({ q, a }: { q: string; a: any }) => (
  <div><div className="text-2xs font-semibold uppercase tracking-wider text-ink-faint">{q}</div><div className="text-sm text-ink">{a ?? "—"}</div></div>
);

function EventCard({ title, ev }: { title: string; ev: any }) {
  const pi = ev.payload_inspector;
  return (
    <Panel title={title}>
      <div className="p-3 space-y-3">
        <div className="grid grid-cols-2 gap-2 text-xs">
          <KV k="Method" v={ev.http_method} /><KV k="Status" v={ev.http_status} />
          <KV k="URL" v={ev.http_url} mono /><KV k="Signature" v={ev.signature} />
        </div>
        {!pi?.available ? (
          <div className="text-xs text-warn bg-warn/10 border border-warn/30 rounded px-2.5 py-2">{pi?.message || "Payload unavailable."}</div>
        ) : (
          <PayloadInspector pi={pi} />
        )}
      </div>
    </Panel>
  );
}
const KV = ({ k, v, mono }: any) => (
  <div><span className="text-ink-faint">{k}: </span><span className={mono ? "mono" : ""}>{v ?? "—"}</span></div>
);

function PayloadInspector({ pi }: { pi: any }) {
  const [view, setView] = useState<"raw" | "url" | "hex">("raw");
  const text = view === "raw" ? pi.raw : view === "url" ? (pi.url_decoded ?? pi.raw) : pi.hex;
  return (
    <div>
      <div className="flex items-center gap-1 mb-1.5">
        {(["raw", "url", "hex"] as const).map((v) => (
          <button key={v} onClick={() => setView(v)} className={`btn btn-sm ${view === v ? "btn-primary" : ""}`}>
            {v === "raw" ? "Raw" : v === "url" ? "URL-decoded" : "Hex"}
          </button>
        ))}
        <div className="ml-auto"><CopyButton text={text || ""} label="Copy" /></div>
      </div>
      <CodeBlock code={text || "(empty)"} className="max-h-48" />
      {pi.suspicious?.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {pi.suspicious.map((s: any, i: number) => (
            <Badge key={i} className="border-bad/40 text-bad bg-bad/10" >{tech(s.technique)}: <span className="mono">{s.match}</span></Badge>
          ))}
        </div>
      )}
      {pi.truncated && <p className="text-2xs text-warn mt-1">Payload truncated for display.</p>}
      <p className="text-2xs text-ink-faint mt-1">{pi.note}</p>
    </div>
  );
}

function Events() {
  const [filters, setFilters] = useState<any>({ q: "", category: "", outcome: "" });
  const [sel, setSel] = useState<number | null>(null);
  const qs = Object.entries(filters).filter(([, v]) => v).map(([k, v]) => `${k}=${encodeURIComponent(v as string)}`).join("&");
  const { data } = useQuery({ queryKey: ["events", qs], queryFn: () => get(`/soc/events?${qs}`) });
  const items = data?.items || [];
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2">
        <input className="input w-56" placeholder="Search URL / payload / signature…" value={filters.q} onChange={(e) => setFilters({ ...filters, q: e.target.value })} />
        <select className="input w-44" value={filters.category} onChange={(e) => setFilters({ ...filters, category: e.target.value })}>
          <option value="">All techniques</option>
          {["sql_injection", "command_injection", "path_traversal", "xss", "ssti", "ssrf", "scanner", "ids_alert"].map((c) => <option key={c} value={c}>{tech(c)}</option>)}
        </select>
        <select className="input w-36" value={filters.outcome} onChange={(e) => setFilters({ ...filters, outcome: e.target.value })}>
          <option value="">All outcomes</option>
          {Object.keys(OUTCOME_META).map((o) => <option key={o} value={o}>{OUTCOME_META[o].label}</option>)}
        </select>
        <span className="text-xs text-ink-faint self-center ml-auto">{data?.total ?? 0} events</span>
      </div>
      <Panel>
        {items.length === 0 ? <EmptyState title="No events" hint="Ingest Suricata EVE or access logs. No SQL needed — use the filters above." /> : (
          <table className="w-full row-hover">
            <thead><tr><th className="th">Time</th><th className="th">Src</th><th className="th">Dst</th><th className="th">Technique</th><th className="th">Method</th><th className="th">Status</th><th className="th">Outcome</th></tr></thead>
            <tbody>{items.map((e: any) => (
              <tr key={e.id} className="cursor-pointer" onClick={() => setSel(e.id)}>
                <td className="td text-ink-faint whitespace-nowrap">{e.ts}</td>
                <td className="td mono text-xs">{e.src_ip}</td>
                <td className="td mono text-xs">{e.dest_ip}{e.dest_port ? `:${e.dest_port}` : ""}</td>
                <td className="td">{tech(e.category)}</td>
                <td className="td mono">{e.http_method ?? "—"}</td>
                <td className="td mono">{e.http_status ?? "—"}</td>
                <td className="td"><Badge className={(OUTCOME_META[e.outcome] || OUTCOME_META.attempted).cls}>{(OUTCOME_META[e.outcome] || OUTCOME_META.attempted).label}</Badge></td>
              </tr>
            ))}</tbody>
          </table>
        )}
      </Panel>
      {sel && <EventDrawer id={sel} onClose={() => setSel(null)} />}
    </div>
  );
}

function EventDrawer({ id, onClose }: { id: number; onClose: () => void }) {
  const { data: e } = useQuery({ queryKey: ["event", id], queryFn: () => get(`/soc/events/${id}`) });
  return (
    <Drawer open onClose={onClose} title={`Event #${id}`} width="max-w-xl">
      {!e ? <div className="p-6"><Spinner /></div> : (
        <div className="p-4 space-y-3">
          <EventCard title="Request" ev={e} />
          <Panel title="Outcome">
            <div className="p-3 space-y-1.5">
              <Badge className={(OUTCOME_META[e.outcome_detail?.outcome] || OUTCOME_META.attempted).cls}>{(OUTCOME_META[e.outcome_detail?.outcome] || OUTCOME_META.attempted).label}</Badge>
              {(e.outcome_detail?.evidence || []).map((s: any, i: number) => (
                <div key={i} className="text-xs"><span className="mono text-accent">{s.signal}</span> — <span className="text-ink-dim">{s.detail}</span></div>
              ))}
            </div>
          </Panel>
          <Panel title="Raw record"><div className="p-3"><CodeBlock code={e.raw ? JSON.stringify(JSON.parse(e.raw), null, 2) : "(none)"} className="max-h-72" /></div></Panel>
        </div>
      )}
    </Drawer>
  );
}

function Sensors() {
  const qc = useQueryClient();
  const toast = useToast();
  const { data } = useQuery({ queryKey: ["sensors"], queryFn: () => get("/soc/sensors") });
  const { data: health } = useQuery({ queryKey: ["ingest-health"], queryFn: () => get("/soc/ingest/health") });
  const [name, setName] = useState("");
  const [token, setToken] = useState<string | null>(null);
  const addM = useMutation({
    mutationFn: () => post("/soc/sensors", { name, kind: "suricata" }),
    onSuccess: (r: any) => { setToken(r.token); setName(""); qc.invalidateQueries({ queryKey: ["sensors"] }); },
    onError: (e: any) => toast("error", e.message),
  });
  return (
    <div className="max-w-3xl space-y-4">
      <Panel title="Register sensor">
        <div className="p-3 flex gap-2">
          <input className="input flex-1" placeholder="e.g. edge-suricata-1" value={name} onChange={(e) => setName(e.target.value)} />
          <button className="btn btn-primary" disabled={!name} onClick={() => addM.mutate()}>Create token</button>
        </div>
        {token && (
          <div className="mx-3 mb-3 well p-3">
            <div className="text-xs text-warn mb-1">Copy this token now — it is shown only once.</div>
            <div className="flex items-center gap-2"><code className="mono text-xs break-all flex-1">{token}</code><CopyButton text={token} /></div>
          </div>
        )}
      </Panel>
      <Panel title="Sensors">
        {(data?.items || []).length === 0 ? <EmptyState title="No sensors" hint="Register a collector, then point the EVE forwarder at /api/soc/ingest/sensor." /> : (
          <table className="w-full row-hover">
            <thead><tr><th className="th">Name</th><th className="th">Kind</th><th className="th">Last seen</th><th className="th">Enabled</th></tr></thead>
            <tbody>{data.items.map((s: any) => (
              <tr key={s.id}><td className="td font-medium">{s.name}</td><td className="td">{s.kind}</td>
                <td className="td text-ink-dim">{s.last_seen ? timeAgo(s.last_seen) : "never"}</td>
                <td className="td">{s.enabled ? <Badge className="border-ok/30 text-ok bg-ok/10">yes</Badge> : <Badge className="border-line-strong text-ink-faint">no</Badge>}</td></tr>
            ))}</tbody>
          </table>
        )}
      </Panel>
      <Panel title="Ingestion health">
        <div className="p-3 text-sm text-ink-dim space-y-1">
          <div>Last ingest: <span className="text-ink">{health?.last_ingest ? timeAgo(health.last_ingest) : "never"}</span></div>
          <div>Events stored: <span className="mono">{health?.events_total ?? 0}</span></div>
        </div>
      </Panel>
    </div>
  );
}

function Setup() {
  const [open, setOpen] = useState<string>("suricata");
  return (
    <div className="max-w-4xl space-y-3">
      <div className="well p-3 text-xs text-ink-dim">
        <span className="text-warn font-medium">TLS note:</span> passive PCAP cannot reveal encrypted HTTPS bodies without TLS-termination or app-level logging.
        Capture at the reverse proxy / app layer for full payload visibility.
      </div>
      {GUIDES.map((g) => (
        <Panel key={g.id} title={<button className="text-left" onClick={() => setOpen(open === g.id ? "" : g.id)}>{g.tool}</button>}
          actions={<span className="text-2xs text-ink-faint">{g.platforms}</span>}>
          {open === g.id && (
            <div className="p-3 space-y-3">
              <p className="text-sm text-ink-dim">{g.purpose}</p>
              {g.steps.map((s, i) => (
                <div key={i}>
                  <div className="text-xs font-medium text-ink mb-1">{i + 1}. {s.label}</div>
                  {s.cmd && (
                    <div className="flex items-start gap-2">
                      <CodeBlock code={s.cmd} className="flex-1" />
                      <CopyButton text={s.cmd} />
                    </div>
                  )}
                  {s.note && <p className="text-2xs text-ink-faint mt-1">{s.note}</p>}
                </div>
              ))}
              {g.verify && <div><div className="text-xs font-medium text-ink mb-1">Verify</div><CodeBlock code={g.verify} /></div>}
              {g.troubleshoot?.map((t, i) => (
                <div key={i} className="text-xs"><span className="text-warn">{t.problem}:</span> <span className="text-ink-dim">{t.fix}</span></div>
              ))}
            </div>
          )}
        </Panel>
      ))}
    </div>
  );
}

function demoPayload() {
  // Minimal in-UI demo ingest (mirrors backend seed demo set shape).
  const atk = "10.13.37.9", dst = "10.10.0.5", port = 8080;
  const events: any[] = [];
  for (let i = 0; i < 40; i++) {
    events.push({ timestamp: `2026-11-07T10:00:${String(i % 60).padStart(2, "0")}`, event_type: "http", src_ip: atk, dest_ip: dst, dest_port: port, proto: "TCP",
      http: { url: "/item?id=1' OR '1'='1", http_method: "GET", status: 200 }, payload_printable: "id=1' OR '1'='1", alert: { signature: "ET SQL Injection", signature_id: 1, severity: 1 } });
  }
  events.push({ timestamp: "2026-11-07T10:05:00", event_type: "http", src_ip: atk, dest_ip: dst, dest_port: port, proto: "TCP",
    http: { url: "/item?id=1' OR '1'='1", http_method: "GET", status: 500 }, payload_printable: "id=1' OR '1'='1", response_body: "You have an error in your SQL syntax" });
  events.push({ timestamp: "2026-11-07T10:07:00", event_type: "http", src_ip: "10.20.0.7", dest_ip: dst, dest_port: port, proto: "TCP",
    http: { url: "/ping", http_method: "POST", status: 200 }, payload_printable: "host=127.0.0.1; id", response_body: "uid=0(root) gid=0(root)", app_proof: "shell exec recorded" });
  return { events };
}
