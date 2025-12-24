import { Link } from "react-router-dom";

export default function NavBar() {
  return (
    <nav className="flex items-center justify-between px-10 py-4 border-b border-cyberGreen shadow-neonGreen">
      <h1 className="text-cyberGreen text-2xl font-bold">Secure Encryption Tool</h1>

      <div className="flex gap-6">
        <Link className="hover:text-cyberBlue transition" to="/">Dashboard</Link>
        <Link className="hover:text-cyberBlue transition" to="/encrypt">Encrypt</Link>
        <Link className="hover:text-cyberBlue transition" to="/decrypt">Decrypt</Link>
        <Link className="hover:text-cyberBlue transition" to="/keys">Keys</Link>
        <Link className="hover:text-cyberBlue transition" to="/steg">Steganography</Link>
        <Link className="hover:text-cyberBlue transition" to="/vault">Key Vault</Link>
      </div>
    </nav>
  );
}