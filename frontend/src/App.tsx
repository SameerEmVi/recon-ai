import { Suspense, lazy } from "react";
import { Routes, Route } from "react-router-dom";
import { TokenGate } from "@/components/TokenGate";
import { Layout } from "@/components/Layout";
import Overview from "@/pages/Overview";
import Scans from "@/pages/Scans";
import Monitor from "@/pages/Monitor";
import Plan from "@/pages/Plan";
import Assets from "@/pages/Assets";
import Traffic from "@/pages/Traffic";

// Code-split the Asset Map so its graph library (cytoscape) loads only when the
// route is opened, keeping the main bundle lean.
const Map = lazy(() => import("@/pages/Map"));
const ToolMap = lazy(() => import("@/pages/ToolMap"));
const Exploration = lazy(() => import("@/pages/Exploration"));
import Vulnerabilities from "@/pages/Vulnerabilities";
import Findings from "@/pages/Findings";
import Pentest from "@/pages/Pentest";
import Skills from "@/pages/Skills";
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
          <Route path="plan" element={<Plan />} />
          <Route
            path="map"
            element={
              <Suspense fallback={<div className="text-sm text-muted-foreground">Loading map…</div>}>
                <Map />
              </Suspense>
            }
          />
          <Route
            path="execmap"
            element={
              <Suspense fallback={<div className="text-sm text-muted-foreground">Loading…</div>}>
                <ToolMap />
              </Suspense>
            }
          />
          <Route
            path="exploration"
            element={
              <Suspense fallback={<div className="text-sm text-muted-foreground">Loading…</div>}>
                <Exploration />
              </Suspense>
            }
          />
          <Route path="traffic" element={<Traffic />} />
          <Route path="assets" element={<Assets />} />
          <Route path="vulnerabilities" element={<Vulnerabilities />} />
          <Route path="findings" element={<Findings />} />
          <Route path="pentest" element={<Pentest />} />
          <Route path="skills" element={<Skills />} />
          <Route path="diagnostics" element={<Diagnostics />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </TokenGate>
  );
}
