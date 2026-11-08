import { useState } from "react";
import { HelpCircle, Lightbulb } from "lucide-react";
import { Drawer } from "./overlay";
import { HELP } from "../lib/help";

export function HowToUse({ page, className = "" }: { page: string; className?: string }) {
  const [open, setOpen] = useState(false);
  const doc = HELP[page];
  if (!doc) return null;
  return (
    <>
      <button
        className={`btn btn-ghost btn-sm text-ink-dim gap-1.5 shrink-0 ${className}`}
        onClick={() => setOpen(true)}
        title="How to use this workspace"
      >
        <HelpCircle className="h-3.5 w-3.5" />
        How to use
      </button>
      <Drawer
        open={open}
        onClose={() => setOpen(false)}
        title={
          <span className="flex items-center gap-2">
            <HelpCircle className="h-4 w-4 text-accent" />
            How to use · {doc.title}
          </span>
        }
      >
        <div className="p-4 space-y-5 text-sm leading-relaxed">
          {doc.intro && <p className="text-ink-dim">{doc.intro}</p>}
          {doc.sections.map((s) => (
            <div key={s.heading} className="space-y-1.5">
              <h4 className="text-ink font-semibold text-2xs uppercase tracking-wide">{s.heading}</h4>
              <ul className="space-y-1.5 text-ink-dim">
                {s.steps.map((st, i) => (
                  <li key={i} className="flex gap-2">
                    <span className="text-accent shrink-0 select-none">{s.ordered ? `${i + 1}.` : "•"}</span>
                    <span>{st}</span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
          {doc.tip && (
            <div className="rounded-md border border-accent/30 bg-accent/5 p-3 text-xs text-ink-dim flex gap-2">
              <Lightbulb className="h-4 w-4 text-accent shrink-0 mt-0.5" />
              <span>
                <span className="text-accent font-semibold">Tip for beginners — </span>
                {doc.tip}
              </span>
            </div>
          )}
        </div>
      </Drawer>
    </>
  );
}
