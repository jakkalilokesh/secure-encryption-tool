/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyberBlack: "#020204",
        cyberGray: "#07120a",
        cyberGreen: "#0aff0a",
        cyberBlue: "#00eaff",
        cyberPurple: "#b967ff",
        cyberRed: "#ff3232",
        cyberYellow: "#ffff00",
      },
      animation: {
        'flicker': 'flicker 2s infinite',
      },
      keyframes: {
        flicker: {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: 0.8 },
        },
      },
      boxShadow: {
        'neonGreen': '0 0 8px #0aff0a',
        'neonBlue': '0 0 8px #00eaff',
        'neonPurple': '0 0 8px #b967ff',
      },
    },
  },
  plugins: [],
}