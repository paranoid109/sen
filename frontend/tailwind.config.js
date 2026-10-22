/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#090d16",
          surface: "#0f172a",
          card: "#1e293b",
          border: "#334155",
          primary: "#38bdf8",
          accent: "#22d3ee",
          success: "#34d399",
          warning: "#fbbf24",
          danger: "#f87171",
          critical: "#ef4444",
        },
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
    },
  },
  plugins: [],
};
