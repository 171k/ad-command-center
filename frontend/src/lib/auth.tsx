import { createContext, ReactNode, useContext, useEffect, useState } from "react";
import { get, post } from "./api";

type Status = {
  configured: boolean;
  authenticated: boolean;
  username: string | null;
  is_admin: boolean;
  totp_enabled: boolean;
  users: string[];
  app_name: string;
};

type AuthCtx = {
  status: Status | null;
  loading: boolean;
  username: string | null;
  isAdmin: boolean;
  refresh: () => Promise<void>;
  login: (username: string, password: string, totp?: string) => Promise<void>;
  setup: (password: string) => Promise<void>;
  logout: () => Promise<void>;
};

const Ctx = createContext<AuthCtx>(null as any);
export const useAuth = () => useContext(Ctx);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status | null>(null);
  const [loading, setLoading] = useState(true);
  const [username, setUsername] = useState<string | null>(null);

  const refresh = async () => {
    try {
      const st = await get<Status>("/auth/status");
      setStatus(st);
      setUsername(st.username);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    refresh();
  }, []);

  const login = async (user: string, password: string, totp?: string) => {
    const r = await post<{ username?: string }>("/auth/login", { username: user, password, totp });
    if (r.username) {
      setUsername(r.username);
      localStorage.setItem("adcc_user", r.username);
    }
    await refresh();
  };
  const setup = async (password: string) => {
    await post("/auth/setup", { password });
    await refresh();
  };
  const logout = async () => {
    await post("/auth/logout");
    setUsername(null);
    await refresh();
  };

  return (
    <Ctx.Provider value={{ status, loading, username, isAdmin: !!status?.is_admin, refresh, login, setup, logout }}>
      {children}
    </Ctx.Provider>
  );
}
