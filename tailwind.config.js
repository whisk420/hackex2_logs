/** Tailwind build config. Rebuild style.css after changing classes: npm run build:css */
module.exports = {
  content: ["./index.html", "./app.js", "./kb.js"],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#0b1120",
          card: "#050811",
          well: "#03050a",
          border: "#1e293b",
          ip: "#38bdf8",
          ident: "#f8fafc",
          header: "#64748b",
          accent: "#0ea5e9"
        }
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
        mono: ['"JetBrains Mono"', '"Fira Code"', "ui-monospace", "Menlo", "monospace"]
      },
      keyframes: {
        fadeIn: { from: { opacity: "0", transform: "translateY(6px)" }, to: { opacity: "1", transform: "translateY(0)" } },
        pulseGlow: { "0%, 100%": { boxShadow: "0 0 4px rgba(251,191,36,.25)" }, "50%": { boxShadow: "0 0 12px rgba(251,191,36,.55)" } },
        toastIn: { from: { opacity: "0", transform: "translate(-50%, 8px)" }, to: { opacity: "1", transform: "translate(-50%, 0)" } }
      },
      animation: {
        "fade-in": "fadeIn .3s cubic-bezier(.16,1,.3,1) both",
        "pulse-glow": "pulseGlow 2s ease-in-out infinite",
        "toast-in": "toastIn .2s ease-out both"
      }
    }
  },
  plugins: []
};
