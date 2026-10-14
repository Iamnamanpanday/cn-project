/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    colors: {
      transparent: 'transparent',
      current: 'currentColor',
      black: '#000000',
      white: '#ffffff',
      bg: 'var(--bg)',
      panel: 'var(--panel)',
      line: 'var(--line)',
      text: 'var(--text)',
      dim: 'var(--dim)',
      ok: 'var(--ok)',
      warn: 'var(--warn)',
      threat: 'var(--threat)',
      'threat-dim': 'var(--threat-dim)',
    },
    fontFamily: {
      mono: ['"IBM Plex Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      condensed: ['"Barlow Condensed"', 'sans-serif'],
    },
    borderRadius: {
      none: '0px',
      DEFAULT: '0px',
      sm: '0px',
      md: '0px',
      lg: '0px',
      xl: '0px',
      full: '9999px',
    },
    extend: {
      fontSize: {
        '2xs': '10px',
        xs: '11px',
        sm: '12px',
        base: '12px',
        lg: '14px',
        xl: '16px',
        '2xl': '20px',
        '3xl': '24px',
        '4xl': '32px',
      },
    },
  },
  plugins: [],
}
