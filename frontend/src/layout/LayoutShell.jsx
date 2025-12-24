import NavBar from "./NavBar";
import Footer from "./Footer";
import CyberGrid from "../components/CyberGrid";

export default function LayoutShell({ children }) {
  return (
    <div className="min-h-screen bg-cyberBlack text-white">
      <CyberGrid />
      <NavBar />
      <main className="main-container">{children}</main>
      <Footer />
    </div>
  );
}