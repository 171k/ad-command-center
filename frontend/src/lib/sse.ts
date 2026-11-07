import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";

// Maps backend SSE topics to the query keys they should invalidate, so an edit
// in one browser session refreshes the others without a manual reload.
const TOPIC_KEYS: Record<string, string[]> = {
  "findings.changed": ["findings", "activity", "stats"],
  "offenses.changed": ["offenses", "soc-dashboard", "stats"],
  "soc.ingest": ["offenses", "soc-dashboard", "events", "stats", "ingest-health"],
  "services.changed": ["services", "stats"],
  "services.health": ["services", "soc-dashboard"],
  "scripts.changed": ["scripts", "activity"],
  "flags.changed": ["flags"],
  "defense.saved": ["analyses"],
};

export function useLiveSync() {
  const qc = useQueryClient();
  useEffect(() => {
    const es = new EventSource("/api/stream", { withCredentials: true });
    es.onmessage = (e) => {
      try {
        const { topic } = JSON.parse(e.data);
        for (const key of TOPIC_KEYS[topic] ?? []) {
          qc.invalidateQueries({ queryKey: [key] });
        }
      } catch {
        /* ignore keep-alive pings */
      }
    };
    es.onerror = () => {
      /* EventSource auto-reconnects; nothing to do */
    };
    return () => es.close();
  }, [qc]);
}
