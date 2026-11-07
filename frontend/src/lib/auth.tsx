import { createContext, ReactNode, useContext, useEffect, useState } from "react";
import { get, post } from "./api";

type Status = {
  account_setup: boolean;
  authenticated: boolean;
  totp_enabled: boolean;
  app_name: string;
};

type AuthCtx = {
  status: Status | null;
  loading: boolean;
  label: string | null;
  refresh: () => Promise<void>;
  login: (password: string, label?: string, totp?: string) => Promise<void>;
  setup: (password: string) => Promise<void>;
  logout: () => Promise<void>;
};

const Ctx = createContext<AuthCtx>(null as any);
export const useAuth = () => useContext(Ctx);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status | null>(null);
  const [loading, setLoading] = useState(true);
  const [label, setLabel] = useState<string | null>(localStorage.getItem("adcc_label"));

  const refresh = async () => {
    try {
      setStatus(await get<Status>("/auth/status"));
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    refresh();
  }, []);

  const login = async (password: string, lbl?: string, totp?: string) => {
    const r = await post<{ label?: string }>("/auth/login", { password, label: lbl, totp });
    if (r.label) {
      setLabel(r.label);
      localStorage.setItem("adcc_label", r.label);
    }
    await refresh();
  };
  const setup = async (password: string) => {
    await post("/auth/setup", { password });
    await refresh();
  };
  const logout = async () => {
    await post("/auth/logout");
    await refresh();
  };

  return (
    <Ctx.Provider value={{ status, loading, label, refresh, login, setup, logout }}>
      {children}
    </Ctx.Provider>
  );
}
