import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, Hammer, RefreshCw, Flower2 } from "lucide-react";
import { get, post } from "../lib/api";
import { useToast } from "../lib/toast";
import { useAuth } from "../lib/auth";
import { Badge, Panel, Spinner } from "./ui";

type Svc = { name: string; ip: string; port: number | string };
type Cfg = {
  tick_start: string; tick_length: number | string; flag_regex: string;
  vm_ip: string; team_id: number | string; services: Svc[];
};

const STATE_META: Record<string, { cls: string; label: string }> = {
  queued: { cls: "border-warn/40 text-warn bg-warn/10", label: "Queued" },
  applying: { cls: "border-accent/40 text-accent bg-accent/10", label: "Rebuilding…" },
  done: { cls: "border-ok/40 text-ok bg-ok/10", label: "Done" },
  error: { cls: "border-bad/50 text-bad bg-bad/10", label: "Error" },
  unknown: { cls: "border-line-strong text-ink-faint", label: "Idle" },
};

export function TulipConfig() {
  const qc = useQueryClient();
  const toast = useToast();
  const { isAdmin } = useAuth();
  const [cfg, setCfg] = useState<Cfg | null>(null);

  const { data } = useQuery({ queryKey: ["tulip-config"], queryFn: () => get("/tulip/config") });
  useEffect(() => { if (data?.config && !cfg) setCfg(data.config); }, [data]); // eslint-disable-line

  const status = useQuery({
    queryKey: ["tulip-status"],
    queryFn: () => get("/tulip/status"),
    refetchInterval: (q: any) => (["queued", "applying"].includes(q.state.data?.state) ? 2500 : false),
  });

  const save = useMutation({
    mutationFn: () => post("/tulip/config", cfg),
    onSuccess: () => { toast("ok", "Rebuild requested"); qc.invalidateQueries({ queryKey: ["tulip-status"] }); setTimeout(() => status.refetch(), 500); },
    onError: (e: any) => toast("error", e.message),
  });

  if (!cfg) return <div className="p-6"><Spinner /></div>;

  const set = (k: keyof Cfg, v: any) => setCfg({ ...cfg, [k]: v });
  const setSvc = (i: number, k: keyof Svc, v: any) => {
    const s = cfg.services.slice(); s[i] = { ...s[i], [k]: v }; set("services", s);
  };
  const st = status.data || { state: "unknown" };
  const meta = STATE_META[st.state] || STATE_META.unknown;
  const busy = ["queued", "applying"].includes(st.state);

  return (
    <div className="max-w-3xl space-y-4 p-1">
      <Panel>
        <div className="px-3 h-11 flex items-center gap-2 border-b border-line">
          <Flower2 className="h-4 w-4 text-accent" />
          <span className="text-sm font-medium">Tulip configuration</span>
          <a href="https://tulip.itikad.site" target="_blank" rel="noreferrer" className="text-2xs text-accent hover:underline ml-1">open dashboard</a>
          <span className="ml-auto flex items-center gap-2">
            <Badge className={meta.cls}>{meta.label}</Badge>
            <button className="btn btn-ghost btn-sm" title="Refresh status" onClick={() => status.refetch()}><RefreshCw className={`h-3.5 w-3.5 ${busy ? "animate-spin" : ""}`} /></button>
          </span>
        </div>
        <div className="p-3 space-y-3">
          <p className="text-2xs text-ink-faint">Set the competition values, then Save &amp; Rebuild. A host agent renders Tulip's config and rebuilds it — no SSH, no manual file editing. These are safe to set now with placeholders; confirm the real values with organisers on game day.</p>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div><label className="label">Tick start (ISO-8601 UTC)</label>
              <input className="input mono" value={cfg.tick_start} onChange={(e) => set("tick_start", e.target.value)} placeholder="2026-11-17T09:00:00Z" /></div>
            <div><label className="label">Tick length (ms)</label>
              <input className="input mono" value={cfg.tick_length} onChange={(e) => set("tick_length", e.target.value)} placeholder="120000" /></div>
            <div><label className="label">Flag regex</label>
              <input className="input mono" value={cfg.flag_regex} onChange={(e) => set("flag_regex", e.target.value)} placeholder="[A-Z0-9]{31}=" /></div>
            <div className="grid grid-cols-2 gap-2">
              <div><label className="label">Your VM IP</label>
                <input className="input mono" value={cfg.vm_ip} onChange={(e) => set("vm_ip", e.target.value)} placeholder="10.0.0.1" /></div>
              <div><label className="label">Team ID</label>
                <input className="input mono" value={cfg.team_id} onChange={(e) => set("team_id", e.target.value)} placeholder="1" /></div>
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="label mb-0">Services</label>
              <button className="btn btn-ghost btn-sm" onClick={() => set("services", [...cfg.services, { name: "", ip: cfg.vm_ip, port: "" }])}><Plus className="h-3.5 w-3.5" />Add</button>
            </div>
            <div className="space-y-2">
              {cfg.services.map((s, i) => (
                <div key={i} className="flex gap-2">
                  <input className="input flex-1" placeholder="name" value={s.name} onChange={(e) => setSvc(i, "name", e.target.value)} />
                  <input className="input w-40 mono" placeholder="ip" value={s.ip} onChange={(e) => setSvc(i, "ip", e.target.value)} />
                  <input className="input w-24 mono" placeholder="port" value={s.port} onChange={(e) => setSvc(i, "port", e.target.value)} />
                  <button className="btn btn-ghost btn-sm text-bad" title="Remove" disabled={cfg.services.length <= 1} onClick={() => set("services", cfg.services.filter((_, j) => j !== i))}><Trash2 className="h-3.5 w-3.5" /></button>
                </div>
              ))}
            </div>
          </div>

          {st.message && (
            <div className={`text-xs rounded px-2.5 py-2 border ${meta.cls} whitespace-pre-wrap break-words`}>{st.message}</div>
          )}

          <div className="flex items-center gap-2 pt-1">
            {isAdmin ? (
              <button className="btn btn-primary" disabled={save.isPending || busy} onClick={() => save.mutate()}>
                <Hammer className="h-4 w-4" />{busy ? "Rebuilding…" : "Save & Rebuild"}
              </button>
            ) : (
              <span className="text-2xs text-ink-faint">Saving/rebuilding is admin-only. Ask itik to apply changes.</span>
            )}
            {st.updated_at && <span className="text-2xs text-ink-faint ml-auto">updated {timeago(st.updated_at)}</span>}
          </div>
        </div>
      </Panel>
    </div>
  );
}

function timeago(ts: number): string {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}
