/** ForensicAI dashboard — dark charcoal + neon-dark-pink theme.
 *  Single accent hue (pink); severity differentiates by intensity, never by
 *  switching to amber/red/green. See docs/PHASE6_HANDOFF.md §Visual spec.
 */
module.exports = {
  content: ["./ui/templates/**/*.html", "./ui/static/js/**/*.js"],
  theme: {
    extend: {
      colors: {
        // Dark charcoal surfaces — NOT pure black.
        ink: {
          900: "#0d0d0f", // page base
          800: "#121216",
          700: "#16161a", // card base
          600: "#1d1d23", // raised
          500: "#26262e", // borders / hairlines
        },
        // The only neon: pink. 400 = general accent, 300 = critical glow,
        // 500 = hover/pressed.
        pink: {
          300: "#ff0080", // critical-severity glow
          400: "#ec4899", // general accent
          500: "#d6336c", // hover state
          600: "#9d2455", // dim / desaturated (low severity)
          700: "#5c1733", // deepest dim
        },
        // Neutral text ramp.
        mist: {
          100: "#f5f5f7",
          300: "#c7c7d1",
          400: "#9a9aa8",
          500: "#6e6e7c",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "sans-serif"],
        mono: ['"JetBrains Mono"', '"Fira Code"', "ui-monospace", "monospace"],
      },
      boxShadow: {
        "pink-sm": "0 0 0 1px rgba(236,72,153,0.18)",
        "pink-glow": "0 0 24px -4px rgba(236,72,153,0.45)",
        "pink-glow-strong": "0 0 36px -2px rgba(255,0,128,0.55)",
      },
      borderRadius: {
        xl2: "1.125rem",
      },
      transitionTimingFunction: {
        "out-cubic": "cubic-bezier(0.22, 1, 0.36, 1)",
      },
    },
  },
  plugins: [],
};
