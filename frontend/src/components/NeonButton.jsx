export default function NeonButton({ children, onClick, color = "green", disabled = false }) {
  const colorClass = color === "blue"
    ? "shadow-neonBlue text-cyberBlue border-cyberBlue"
    : color === "purple"
      ? "shadow-neonPurple text-cyberPurple border-cyberPurple"
      : "shadow-neonGreen text-cyberGreen border-cyberGreen";

  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`
        px-5 py-2 border ${colorClass} rounded-md 
        transition duration-300 
        ${disabled
          ? 'opacity-50 cursor-not-allowed'
          : 'hover:scale-105 active:scale-95 hover:opacity-90'
        }
      `}
    >
      {children}
    </button>
  );
}