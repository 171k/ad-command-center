import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { get, post } from "../lib/api";
import { useToast } from "../lib/toast";
import { PageBody, PageHeader } from "../components/Page";
import { Badge, EmptyState, Panel } from "../components/ui";
import { timeAgo } from "../lib/format";

export function Settings() {
  const qc = useQueryClient();
  const toast = useToast();
  const { data: sessions } = useQuery({ queryKey: ["sessions"], queryFn: () => get("/auth/sessions") });
  const { data: cfg } = useQuery({ queryKey: ["config"], queryFn: () => get("/system/config") });
  const { data: audit } = useQuery({ queryKey: ["audit"], queryFn: () => get("/system/audit?limit=40") });

  const [cur, setCur] = useState(""); const [nw, setNw] = useState("");
  const revokeAll = useMutation({ mutationFn: () => post("/auth/sessions/revoke-all"), onSuccess: () => { qc.invalidateQueries({ queryKey: ["sessions"] }); toast("ok", "Other sessions revoked"); } });
  const rotate = useMutation({
    mutationFn: () => post("/auth/password", { current_password: cur, new_password: nw }),
    onSuccess: () => { toast("ok", "Password changed — all sessions signed out"); location.reload(); },
    onError: (e: any) => toast("error", e.message),
  });

  return (
    <>
      <PageHeader title="Settings" subtitle="Sessions · security · audit" />
      <PageBody className="max-w-4xl space-y-4">
        <Panel title="Active sessions" actions={<button className="btn btn-sm btn-danger" onClick={() => revokeAll.mutate()}>Revoke all others</button>}>
          <table className="w-full row-hover">
            <thead><tr><th className="th">Label</th><th className="th">Fingerprint</th><th className="th">IP</th><th className="th">Last seen</th></tr></thead>
            <tbody>{(sessions?.sessions || []).map((s: any) => (
              <tr key={s.fingerprint}><td className="td">{s.label ?? "—"} {s.fingerprint === sessions.current && <Badge className="border-accent/40 text-accent bg-accent/10">this</Badge>}</td>
                <td className="td mono text-xs">{s.fingerprint}</td><td className="td mono text-xs">{s.ip ?? "—"}</td><td className="td text-ink-faint">{timeAgo(s.last_seen_at)}</td></tr>
            ))}</tbody>
          </table>
          <p className="text-2xs text-ink-faint p-3">Session labels are attribution hints only — all sessions share one credential, so individual identity is not guaranteed.</p>
        </Panel>

        <Panel title="Change password">
          <div className="p-3 grid grid-cols-2 gap-3 max-w-lg">
            <div><label className="label">Current</label><input className="input" type="password" value={cur} onChange={(e) => setCur(e.target.value)} /></div>
            <div><label className="label">New (min 10)</label><input className="input" type="password" value={nw} onChange={(e) => setNw(e.target.value)} /></div>
            <div className="col-span-2"><button className="btn btn-primary" disabled={!cur || nw.length < 10} onClick={() => rotate.mutate()}>Change password</button>
              <span className="text-2xs text-ink-faint ml-2">All sessions are signed out after a change.</span></div>
          </div>
        </Panel>

        <Panel title="Feature gates">
          <div className="p-3 grid grid-cols-2 gap-2 text-sm">
            {cfg && Object.entries(cfg.features).map(([k, v]: any) => (
              <div key={k} className="flex items-center justify-between well px-2.5 py-1.5">
                <span className="text-ink-dim">{k.replace(/_/g, " ")}</span>
                <Badge className={v ? "border-ok/30 text-ok bg-ok/10" : "border-line-strong text-ink-faint"}>{v ? "enabled" : "disabled"}</Badge>
              </div>
            ))}
          </div>
          <p className="text-2xs text-ink-faint px-3 pb-3">Execution features are off by default and require setting the matching env var and a sandboxed runner.</p>
        </Panel>

        <Panel title="Audit log">
          {(audit?.items || []).length === 0 ? <EmptyState title="No audit entries" /> : (
            <table className="w-full row-hover">
              <thead><tr><th className="th">Time</th><th className="th">By</th><th className="th">Action</th><th className="th">Detail</th></tr></thead>
              <tbody>{audit.items.map((a: any, i: number) => (
                <tr key={i}><td className="td text-ink-faint whitespace-nowrap">{a.at}</td><td className="td">{a.label ?? "—"}</td>
                  <td className="td mono text-xs">{a.action}</td><td className="td text-ink-dim">{a.detail ?? ""}</td></tr>
              ))}</tbody>
            </table>
          )}
        </Panel>
      </PageBody>
    </>
  );
}
