import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./lib/auth";
import { Spinner } from "./components/ui";
import { Login } from "./pages/Login";
import { Layout } from "./components/Layout";
import { Attack } from "./pages/Attack";
import { Defense } from "./pages/Defense";
import { Automation } from "./pages/Automation";
import { Soc } from "./pages/Soc";
import { Pwn } from "./pages/Pwn";
import { Findings } from "./pages/Findings";
import { Tools } from "./pages/Tools";
import { Settings } from "./pages/Settings";

export default function App() {
  const { status, loading } = useAuth();

  if (loading) {
    return (
      <div className="h-full grid place-items-center">
        <Spinner className="h-6 w-6" />
      </div>
    );
  }
  if (!status?.authenticated) {
    return <Login />;
  }

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/soc" replace />} />
        <Route path="/attack" element={<Attack />} />
        <Route path="/defense" element={<Defense />} />
        <Route path="/automation" element={<Automation />} />
        <Route path="/soc/*" element={<Soc />} />
        <Route path="/pwn" element={<Pwn />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/tools" element={<Tools />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/soc" replace />} />
      </Routes>
    </Layout>
  );
}
