import { ReactNode, useEffect } from "react";
import { X } from "lucide-react";

function useEscape(onClose: () => void) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);
}

export function Dialog({ open, onClose, title, children, footer, wide }: {
  open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; footer?: ReactNode; wide?: boolean;
}) {
  useEscape(onClose);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center p-4 sm:p-8 bg-black/60" onMouseDown={onClose}>
      <div
        className={`panel w-full ${wide ? "max-w-3xl" : "max-w-lg"} mt-[6vh] shadow-2xl flex flex-col max-h-[85vh]`}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <header className="flex items-center justify-between px-4 h-11 border-b border-line shrink-0">
          <h3 className="text-sm font-semibold">{title}</h3>
          <button className="btn btn-ghost btn-sm" onClick={onClose}><X className="h-4 w-4" /></button>
        </header>
        <div className="p-4 overflow-auto">{children}</div>
        {footer && <footer className="flex justify-end gap-2 px-4 h-14 items-center border-t border-line shrink-0">{footer}</footer>}
      </div>
    </div>
  );
}

export function Drawer({ open, onClose, title, children, width = "max-w-2xl" }: {
  open: boolean; onClose: () => void; title: ReactNode; children: ReactNode; width?: string;
}) {
  useEscape(onClose);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/50" onMouseDown={onClose}>
      <div
        className={`bg-bg-raised border-l border-line w-full ${width} h-full flex flex-col shadow-2xl`}
        onMouseDown={(e) => e.stopPropagation()}
      >
        <header className="flex items-center justify-between px-4 h-12 border-b border-line shrink-0">
          <div className="text-sm font-semibold min-w-0 truncate">{title}</div>
          <button className="btn btn-ghost btn-sm" onClick={onClose}><X className="h-4 w-4" /></button>
        </header>
        <div className="flex-1 overflow-auto">{children}</div>
      </div>
    </div>
  );
}
