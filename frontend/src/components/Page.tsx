import { ReactNode } from "react";

export function PageHeader({ title, subtitle, actions }: {
  title: string; subtitle?: string; actions?: ReactNode;
}) {
  return (
    <header className="h-14 shrink-0 border-b border-line flex items-center justify-between px-5 bg-bg-raised/40">
      <div>
        <h1 className="text-sm font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="text-2xs text-ink-faint">{subtitle}</p>}
      </div>
      <div className="flex items-center gap-2">{actions}</div>
    </header>
  );
}

export function PageBody({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`flex-1 min-h-0 overflow-auto p-5 ${className}`}>{children}</div>;
}
