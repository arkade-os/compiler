// Global app state (zustand) for the simplified BTC covered-call flow.
//
// One ledger (Arkade settles UTXO and vUTXO the same way — no chain choice),
// one product (sell a call on your BTC), an RFQ step, and settlement. Components
// read `snapshot` + `ladder`/`positions` and call actions.
import { create } from "zustand";
import { Emulator, EmulatorSnapshot, Owner } from "../lib/emulator";
import {
  loadUserWallet,
  makeCounterparties,
  resetUserWallet,
  type Wallet,
} from "../lib/wallet";
import {
  writeCall,
  settleCall,
  strikeLadder,
  STRIKE_OFFSETS,
  type Position,
  type Ctx,
} from "../lib/options";
import { runRfq, bestQuote, type Quote } from "../lib/rfq";
import { btcToSats, satsToBtc } from "../lib/pricing";

export interface LadderRow {
  strikeUsd: number;
  offsetPct: number;
  quotes: Quote[];
  best: Quote;
}

interface AppState {
  user: Wallet;
  maker: Wallet;
  operator: Wallet;
  emu: Emulator;
  snapshot: EmulatorSnapshot;
  positions: Position[];

  spot: number;
  deposit: number; // BTC
  expiryDays: number;

  quoting: boolean;
  ladder: LadderRow[] | null;
  selectedStrike: number | null;

  toast: { kind: "ok" | "err"; text: string } | null;

  ctx: () => Ctx;
  setSpot: (n: number) => void;
  setDeposit: (n: number) => void;
  setExpiry: (d: number) => void;
  requestQuotes: () => void;
  selectStrike: (s: number) => void;
  clearQuotes: () => void;
  accept: (row: LadderRow) => void;
  settle: (id: string) => void;
  mine: (n: number) => void;
  faucet: () => void;
  reset: () => void;
  clearToast: () => void;
}

function keyOwner(w: Wallet): Owner {
  return { kind: "key", pubkey: w.pubkey, label: w.label };
}

function seed(emu: Emulator, user: Wallet) {
  emu.credit("virtual", keyOwner(user), btcToSats(1), undefined);
  emu.events.length = 0;
}

export const useStore = create<AppState>((set, get) => {
  const user = loadUserWallet();
  const { maker, operator } = makeCounterparties();
  const emu = new Emulator();
  seed(emu, user);

  return {
    user,
    maker,
    operator,
    emu,
    snapshot: emu.snapshot(),
    positions: [],
    spot: 100_000,
    deposit: 0.1,
    expiryDays: 14,
    quoting: false,
    ladder: null,
    selectedStrike: null,
    toast: null,

    ctx: () => ({ emu: get().emu, user: get().user, maker: get().maker, operator: get().operator }),
    setSpot: (n) => set({ spot: Math.max(1, Math.round(n)) }),
    setDeposit: (n) => set({ deposit: Math.max(0, n), ladder: null, selectedStrike: null }),
    setExpiry: (d) => set({ expiryDays: d, ladder: null, selectedStrike: null }),
    clearQuotes: () => set({ ladder: null, selectedStrike: null }),
    clearToast: () => set({ toast: null }),

    requestQuotes: () => {
      const { deposit, spot } = get();
      if (!(deposit > 0)) {
        set({ toast: { kind: "err", text: "Enter a BTC amount first" } });
        return;
      }
      set({ quoting: true, ladder: null, selectedStrike: null });
      // brief delay to evoke makers streaming quotes back to the desk
      setTimeout(() => {
        const { expiryDays } = get();
        const rows: LadderRow[] = strikeLadder(spot).map((strikeUsd, i) => {
          const quotes = runRfq({ spot, strikeUsd, depositBtc: deposit, days: expiryDays });
          return { strikeUsd, offsetPct: STRIKE_OFFSETS[i], quotes, best: bestQuote(quotes) };
        });
        // default-select the richest-yield rung
        const top = rows.reduce((a, b) => (b.best.apyPct > a.best.apyPct ? b : a));
        set({ ladder: rows, quoting: false, selectedStrike: top.strikeUsd });
      }, 850);
    },

    selectStrike: (s) => set({ selectedStrike: s }),

    accept: (row) => {
      try {
        const { deposit, expiryDays, spot } = get();
        const q = row.best;
        const { position } = writeCall(get().ctx(), {
          depositSats: btcToSats(deposit),
          strikeUsd: row.strikeUsd,
          expiryDays,
          premiumSats: q.premiumSats,
          makerName: q.maker,
          apyPct: q.apyPct,
          spot,
        });
        set({
          positions: [position, ...get().positions],
          snapshot: get().emu.snapshot(),
          ladder: null,
          selectedStrike: null,
          toast: { kind: "ok", text: `Sold $${row.strikeUsd.toLocaleString()} call · earned ${satsToBtc(q.premiumSats).toFixed(6)} BTC` },
        });
      } catch (e) {
        set({ toast: { kind: "err", text: (e as Error).message } });
      }
    },

    settle: (id) => {
      try {
        const pos = get().positions.find((p) => p.id === id);
        if (!pos) return;
        settleCall(get().ctx(), pos, get().spot);
        set({
          positions: [...get().positions],
          snapshot: get().emu.snapshot(),
          toast: { kind: "ok", text: "Position settled" },
        });
      } catch (e) {
        set({ toast: { kind: "err", text: (e as Error).message } });
      }
    },

    mine: (n) => {
      get().emu.mine(n);
      set({ snapshot: get().emu.snapshot() });
    },

    faucet: () => {
      const { emu, user } = get();
      emu.credit("virtual", keyOwner(user), btcToSats(0.5), undefined, "Faucet: +0.5 BTC");
      set({ snapshot: emu.snapshot(), toast: { kind: "ok", text: "Faucet: +0.5 BTC" } });
    },

    reset: () => {
      const w = resetUserWallet();
      const emu2 = new Emulator();
      seed(emu2, w);
      set({
        user: w,
        emu: emu2,
        snapshot: emu2.snapshot(),
        positions: [],
        ladder: null,
        selectedStrike: null,
        toast: { kind: "ok", text: "New wallet" },
      });
    },
  };
});
