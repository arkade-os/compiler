import { useEffect } from "react";
import { useStore } from "./state/store";
import { Header } from "./components/Header";
import { SpotBar } from "./components/SpotBar";
import { TradeFlow } from "./components/TradeFlow";
import { Positions } from "./components/Positions";
import { ActivityLog } from "./components/ActivityLog";
import { AboutCard } from "./components/InfoCards";

function Toast() {
  const { toast, clearToast } = useStore();
  useEffect(() => {
    if (toast) {
      const t = setTimeout(clearToast, 3200);
      return () => clearTimeout(t);
    }
  }, [toast, clearToast]);
  if (!toast) return null;
  return <div className={`ark-toast ${toast.kind}`}>{toast.text}</div>;
}

export function App() {
  return (
    <div className="ark-shell">
      <Header />
      <SpotBar />

      <div className="main-grid">
        <TradeFlow />
        <Positions />
      </div>

      <div className="split-grid" style={{ marginTop: 16 }}>
        <ActivityLog />
        <AboutCard />
      </div>

      <Toast />

      <footer className="faint" style={{ marginTop: 28, textAlign: "center", fontSize: 11.5 }}>
        Arkade · BTC Covered Calls — emulator. Compiler-sourced vault · embedded wallet · no
        real funds. Educational use.
      </footer>
    </div>
  );
}
