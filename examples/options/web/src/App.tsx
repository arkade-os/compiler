import { useEffect } from "react";
import { useStore } from "./state/store";
import { Header } from "./components/Header";
import { MarketBar } from "./components/MarketBar";
import { TradePanel } from "./components/TradePanel";
import { Positions } from "./components/Positions";
import { ActivityLog, MempoolCard } from "./components/ActivityLog";
import { CounterpartiesCard, AboutCard } from "./components/InfoCards";

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
      <MarketBar />

      <div className="main-grid">
        <div className="col">
          <TradePanel />
          <CounterpartiesCard />
        </div>
        <div className="col">
          <Positions />
        </div>
      </div>

      <div className="tri-grid">
        <ActivityLog />
        <MempoolCard />
        <AboutCard />
      </div>

      <Toast />

      <footer className="faint" style={{ marginTop: 28, textAlign: "center", fontSize: 11.5 }}>
        Arkade · Covered Call — emulator build. Compiler-sourced ABI · embedded wallet ·
        dual-chain (onchain L1 + virtual Ark). No real funds. Educational use.
      </footer>
    </div>
  );
}
