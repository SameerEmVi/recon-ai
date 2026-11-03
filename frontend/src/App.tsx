import { Routes, Route } from "react-router-dom";
import { TokenGate } from "@/components/TokenGate";
import { Layout } from "@/components/Layout";
import Overview from "@/pages/Overview";
import Scans from "@/pages/Scans";
import Monitor from "@/pages/Monitor";
import Assets from "@/pages/Assets";
import Vulnerabilities from "@/pages/Vulnerabilities";
import Diagnostics from "@/pages/Diagnostics";
import Settings from "@/pages/Settings";

export default function App() {
  return (
    <TokenGate>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Overview />} />
          <Route path="scans" element={<Scans />} />
          <Route path="monitor" element={<Monitor />} />
          <Route path="assets" element={<Assets />} />
          <Route path="vulnerabilities" element={<Vulnerabilities />} />
          <Route path="diagnostics" element={<Diagnostics />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </TokenGate>
  );
}
