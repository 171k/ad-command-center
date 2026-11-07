import { createContext, ReactNode, useCallback, useContext, useState } from "react";
import { CheckCircle2, AlertTriangle, Info, X } from "lucide-react";

type Kind = "ok" | "error" | "info";
type Toast = { id: number; kind: Kind; msg: string };

const Ctx = createContext<(kind: Kind, msg: string) => void>(() => {});
export const useToast = () => useContext(Ctx);

const ICON = { ok: CheckCircle2, error: AlertTriangle, info: Info };
const COLOR = { ok: "text-ok", error: "text-bad", info: "text-accent" };

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]);
  const push = useCallback((kind: Kind, msg: string) => {
    const id = Date.now() + Math.random();
    setItems((x) => [...x, { id, kind, msg }]);
    setTimeout(() => setItems((x) => x.filter((t) => t.id !== id)), 4500);
  }, []);
  return (
    <Ctx.Provider value={push}>
      {children}
      <div className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2 w-80">
        {items.map((t) => {
          const Icon = ICON[t.kind];
          return (
            <div key={t.id} className="panel shadow-xl px-3 py-2.5 flex items-start gap-2 text-sm">
              <Icon className={`h-4 w-4 mt-0.5 shrink-0 ${COLOR[t.kind]}`} />
              <span className="flex-1 text-ink-dim break-words">{t.msg}</span>
              <button className="text-ink-faint hover:text-ink" onClick={() => setItems((x) => x.filter((i) => i.id !== t.id))}>
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          );
        })}
      </div>
    </Ctx.Provider>
  );
}
