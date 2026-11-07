import { useRef } from "react";

// Lightweight, fully-offline code editor: a monospace textarea with a synced
// line-number gutter and tab-key handling. Chosen over a heavy embedded editor
// to keep the bundle small and work without any CDN (see docs/THIRD_PARTY.md).
export function CodeEditor({ value, onChange, placeholder, minRows = 14 }: {
  value: string; onChange: (v: string) => void; placeholder?: string; minRows?: number;
}) {
  const ta = useRef<HTMLTextAreaElement>(null);
  const gutter = useRef<HTMLDivElement>(null);
  const lineCount = Math.max(value.split("\n").length, minRows);

  return (
    <div className="well flex min-h-0 overflow-hidden font-mono text-[0.8125rem]">
      <div
        ref={gutter}
        className="select-none text-right py-2 pl-2 pr-2 text-ink-faint bg-bg-inset border-r border-line/60 overflow-hidden shrink-0"
        style={{ minWidth: "2.5rem" }}
      >
        {Array.from({ length: lineCount }, (_, i) => (
          <div key={i} className="leading-5 h-5">{i + 1}</div>
        ))}
      </div>
      <textarea
        ref={ta}
        value={value}
        placeholder={placeholder}
        spellCheck={false}
        onScroll={() => {
          if (gutter.current && ta.current) gutter.current.scrollTop = ta.current.scrollTop;
        }}
        onKeyDown={(e) => {
          if (e.key === "Tab") {
            e.preventDefault();
            const el = e.currentTarget;
            const s = el.selectionStart, en = el.selectionEnd;
            const next = value.slice(0, s) + "  " + value.slice(en);
            onChange(next);
            requestAnimationFrame(() => { el.selectionStart = el.selectionEnd = s + 2; });
          }
        }}
        onChange={(e) => onChange(e.target.value)}
        className="flex-1 bg-transparent text-ink p-2 leading-5 resize-none outline-none placeholder:text-ink-faint whitespace-pre overflow-auto"
        style={{ minHeight: `${minRows * 1.25}rem`, tabSize: 2 }}
      />
    </div>
  );
}
