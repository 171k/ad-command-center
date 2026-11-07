import { useState } from "react";
import { useAuth } from "../lib/auth";
import { ApiError } from "../lib/api";
import { Field } from "../components/ui";

export function Login() {
  const { status, login, setup } = useAuth();
  const isSetup = status?.configured === false;
  const users = status?.users ?? ["itik", "mejik", "gha", "namia"];
  const [username, setUsername] = useState(localStorage.getItem("adcc_user") || users[0]);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [totp, setTotp] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      if (isSetup) {
        if (password.length < 10) throw new Error("Password must be at least 10 characters.");
        if (password !== confirm) throw new Error("Passwords do not match.");
        await setup(password);
        await login(username, password);
      } else {
        await login(username, password, totp || undefined);
      }
    } catch (e: any) {
      setErr(e instanceof ApiError ? e.message : e.message || "Login failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="h-full grid place-items-center p-4 bg-[radial-gradient(ellipse_at_top,#111722,#0b0e14)]">
      <div className="w-full max-w-sm">
        <div className="flex items-center gap-2.5 mb-6 justify-center">
          <div className="h-9 w-9 rounded-lg bg-accent/15 border border-accent/30 grid place-items-center overflow-hidden">
            <img src="/favicon-64.png" alt="" className="h-9 w-9 object-cover" onError={(e) => ((e.target as HTMLImageElement).style.display = "none")} />
          </div>
          <div>
            <div className="text-base font-semibold">A&amp;D Command Center</div>
            <div className="text-2xs text-ink-faint">Attack &amp; Defense Operations</div>
          </div>
        </div>

        <form onSubmit={submit} className="panel p-5 space-y-4">
          <div>
            <h1 className="text-sm font-semibold">{isSetup ? "Create team password" : "Sign in"}</h1>
            <p className="text-2xs text-ink-faint mt-0.5">
              {isSetup
                ? "One-time setup. Sets an initial password for all four accounts; each person can change their own afterward."
                : "Pick your account and sign in. Everyone shares the same findings, offenses and SIEM data."}
            </p>
          </div>

          <Field label={isSetup ? "Accounts" : "Account"}>
            <div className="grid grid-cols-4 gap-1.5">
              {users.map((u) => (
                <button
                  type="button"
                  key={u}
                  onClick={() => setUsername(u)}
                  disabled={isSetup}
                  className={`btn btn-sm ${username === u && !isSetup ? "btn-primary" : ""} ${isSetup ? "opacity-70" : ""}`}
                >
                  {u}
                </button>
              ))}
            </div>
          </Field>

          <Field label={isSetup ? "Initial password" : "Password"}>
            <input className="input" type="password" value={password} autoFocus
              onChange={(e) => setPassword(e.target.value)} placeholder="••••••••••" />
          </Field>

          {isSetup && (
            <Field label="Confirm password">
              <input className="input" type="password" value={confirm}
                onChange={(e) => setConfirm(e.target.value)} placeholder="••••••••••" />
            </Field>
          )}

          {!isSetup && status?.totp_enabled && (
            <Field label="Authenticator code (TOTP)">
              <input className="input mono" value={totp} inputMode="numeric" maxLength={6}
                onChange={(e) => setTotp(e.target.value)} placeholder="123456" />
            </Field>
          )}

          {err && <div className="text-xs text-bad bg-bad/10 border border-bad/30 rounded px-2.5 py-2">{err}</div>}

          <button className="btn btn-primary w-full h-9" disabled={busy}>
            {busy ? "…" : isSetup ? "Create & sign in" : `Sign in as ${username}`}
          </button>
        </form>
        <p className="text-2xs text-ink-faint text-center mt-3">
          Self-hosted · No runtime AI · Individual accounts, shared operational data.
        </p>
      </div>
    </div>
  );
}
