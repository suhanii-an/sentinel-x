/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Dark-first SOC surface ramp. Four steps, not ten: an analyst needs to
        // tell "page", "panel" and "row" apart at a glance, and more steps than
        // that stop being distinguishable on the monitors these run on.
        base: '#0a0e14',
        surface: '#111722',
        elevated: '#161d2b',
        raised: '#1c2536',
        line: '#243047',
        'line-strong': '#334158',

        ink: '#e8eef7',
        'ink-muted': '#93a1b8',
        'ink-faint': '#64748b',

        // Severity is a semantic scale, never decoration. Every use of these is
        // paired with a text label or an icon, because colour alone fails for
        // the ~8% of analysts with colour vision deficiency.
        critical: '#f43f5e',
        high: '#fb7c3c',
        medium: '#fbbf24',
        low: '#38bdf8',
        info: '#64748b',
        healthy: '#34d399',
        accent: '#22d3ee',
      },
      fontFamily: {
        // System fonts only. See index.html for why there is no web font here.
        sans: [
          'system-ui',
          '-apple-system',
          'Segoe UI',
          'Roboto',
          'Helvetica Neue',
          'Arial',
          'sans-serif',
        ],
        mono: [
          'ui-monospace',
          'SFMono-Regular',
          'Menlo',
          'Consolas',
          'Liberation Mono',
          'monospace',
        ],
      },
      fontSize: {
        '2xs': ['0.6875rem', { lineHeight: '1rem' }],
      },
      boxShadow: {
        panel: '0 1px 2px rgba(0,0,0,0.4), 0 0 0 1px rgba(36,48,71,0.6)',
        pop: '0 12px 32px -8px rgba(0,0,0,0.7), 0 0 0 1px rgba(51,65,88,0.8)',
      },
      keyframes: {
        'fade-in': { from: { opacity: '0' }, to: { opacity: '1' } },
        'slide-up': {
          from: { opacity: '0', transform: 'translateY(4px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        shimmer: { '100%': { transform: 'translateX(100%)' } },
      },
      animation: {
        // Short and non-repeating. Analysts stare at these screens for hours;
        // anything that loops is a distraction, not a delight.
        'fade-in': 'fade-in 140ms ease-out',
        'slide-up': 'slide-up 160ms ease-out',
        shimmer: 'shimmer 1.6s infinite',
      },
    },
  },
  plugins: [],
}
