/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Charcoal/slate operational palette (dark-first).
        bg: {
          DEFAULT: "#0b0e14", // app background
          raised: "#111722", // panels
          inset: "#0d1219", // wells / inputs
          hover: "#161d2b",
        },
        line: {
          DEFAULT: "#1e2735", // borders
          strong: "#2a3647",
        },
        ink: {
          DEFAULT: "#e6edf5", // primary text
          dim: "#9aa7b8", // secondary
          faint: "#64718a", // tertiary
        },
        accent: {
          DEFAULT: "#4f8cff", // restrained blue
          dim: "#2d4a7a",
        },
        ok: "#3fb950",
        warn: "#d29922",
        bad: "#f85149",
        crit: "#ff6b6b",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ["'JetBrains Mono'", "'SFMono-Regular'", "Consolas", "monospace"],
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem" }],
      },
      borderRadius: { DEFAULT: "6px", md: "6px", lg: "8px" },
    },
  },
  plugins: [],
};
