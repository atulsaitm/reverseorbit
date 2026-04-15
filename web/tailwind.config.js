/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        orbit: {
          950: '#08080a',
          900: '#0d0d11',
          800: '#141418',
          700: '#1a1b20',
        },
        metal: {
          chrome: '#c0c0c0',
          steel: '#8a8d93',
          gunmetal: '#2a3439',
        },
        accent: {
          warm: '#d4a574',
          amber: '#f59e0b',
          rose: '#e8b4b8',
          sage: '#9caf88',
          ice: '#a8d8ea',
        },
        threat: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#3b82f6',
          info: '#6b7280',
        },
      },
      boxShadow: {
        glass: '0 8px 32px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255,255,255,0.05)',
        key: '0 1px 0 rgba(255,255,255,0.05), 0 4px 6px rgba(0,0,0,0.4), 0 1px 3px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.08)',
        'glow-warm': '0 0 20px rgba(212,165,116,0.15)',
      },
      animation: {
        float: 'float 6s ease-in-out infinite',
        shimmer: 'shimmer 3s ease-in-out infinite',
      },
      keyframes: {
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-4px)' },
        },
        shimmer: {
          '0%, 100%': { opacity: '0.5' },
          '50%': { opacity: '1' },
        },
      },
    },
  },
  plugins: [require('@tailwindcss/typography')],
};

