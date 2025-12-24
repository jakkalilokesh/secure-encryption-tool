export default function CyberGrid() {
  return (
    <div
      className="fixed inset-0 -z-10 opacity-20 pointer-events-none"
      style={{
        backgroundImage: `
          linear-gradient(#0aff0a15 1px, transparent 1px),
          linear-gradient(90deg, #0aff0a15 1px, transparent 1px)
        `,
        backgroundSize: "50px 50px",
      }}
    />
  );
}