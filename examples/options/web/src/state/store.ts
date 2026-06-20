// Global app state (zustand).
//
// Owns the singleton emulator, the embedded wallet + simulated counterparties,
// the market (spot/vol), and the open positions. UI components read the
// `snapshot` and call actions; every action mutates the emulator then republishes
// a fresh snapshot so React re-renders.
import { create } from "zustand";
import { Emulator, EmulatorSnapshot, Owner } from "../lib/emulator";
import {
  loadUserWallet,
  makeCounterparties,
  resetUserWallet,
  type Wallet,
} from "../lib/wallet";
import {
  writeCoveredCall,
  exercise,
  reclaim,
  transferLeg,
  STABLE,
  type Position,
  type PositionTerms,
  type Side,
  type Ctx,
} from "../lib/coveredCall";
import { TapleafPath } from "../lib/arkadeScript";
import { btcToSats, usdToStableUnits } from "../lib/pricing";

export interface OpenForm {
  side: Side; // user's side
  notionalBtc: number;
  strikeUsd: number;
  premiumUsd: number;
  volPct: number;
  expiryInBlocks: number;
  graceBlocks: number;
  exitBlocks: number;
  chain: "onchain" | "virtual";
}

interface AppState {
  user: Wallet;
  maker: Wallet;
  operator: Wallet;
  emu: Emulator;
  snapshot: EmulatorSnapshot;
  positions: Position[];
  spot: number;
  vol: number;
  selectedChain: "onchain" | "virtual";
  toast: { kind: "ok" | "err"; text: string } | null;

  refresh: () => void;
  ctx: () => Ctx;
  setSpot: (n: number) => void;
  setVol: (n: number) => void;
  selectChain: (c: "onchain" | "virtual") => void;
  mine: (n: number) => void;
  faucet: () => void;
  resetWallet: () => void;
  openPosition: (f: OpenForm) => void;
  exercisePosition: (id: string, path: TapleafPath) => void;
  reclaimPosition: (id: string, path: TapleafPath) => void;
  transferPosition: (id: string, leg: Side) => void;
  clearToast: () => void;
}

function keyOwner(w: Wallet): Owner {
  return { kind: "key", pubkey: w.pubkey, label: w.label };
}

function seed(emu: Emulator, user: Wallet, maker: Wallet) {
  for (const chain of ["onchain", "virtual"] as const) {
    emu.credit(chain, keyOwner(user), btcToSats(1), undefined);
    emu.credit(chain, keyOwner(user), 0, {
      id: STABLE.id,
      amount: usdToStableUnits(250_000),
    });
    emu.credit(chain, keyOwner(maker), btcToSats(20), undefined);
    emu.credit(chain, keyOwner(maker), 0, {
      id: STABLE.id,
      amount: usdToStableUnits(5_000_000),
    });
  }
  emu.events.length = 0; // keep the seed quiet
}

export const useStore = create<AppState>((set, get) => {
  const user = loadUserWallet();
  const { maker, operator } = makeCounterparties();
  const emu = new Emulator();
  seed(emu, user, maker);

  const resolve = (pubkey: string): Wallet => {
    const { user: u, maker: m, operator: o } = get();
    for (const w of [u, m, o]) if (w.pubkey === pubkey) return w;
    throw new Error(`no wallet for ${pubkey.slice(0, 8)}…`);
  };

  return {
    user,
    maker,
    operator,
    emu,
    snapshot: emu.snapshot(),
    positions: [],
    spot: 100_000,
    vol: 0.6,
    selectedChain: "virtual",
    toast: null,

    refresh: () => set({ snapshot: get().emu.snapshot() }),
    ctx: () => ({ emu: get().emu, operator: get().operator, resolve }),
    setSpot: (n) => set({ spot: Math.max(1, n) }),
    setVol: (n) => set({ vol: Math.max(0.01, n) }),
    selectChain: (c) => set({ selectedChain: c }),
    clearToast: () => set({ toast: null }),

    mine: (n) => {
      get().emu.mine(n);
      set({ snapshot: get().emu.snapshot() });
    },

    faucet: () => {
      const { emu, user, selectedChain } = get();
      emu.credit(selectedChain, keyOwner(user), btcToSats(0.5), undefined, "Faucet: +0.5 BTC");
      emu.credit(
        selectedChain,
        keyOwner(user),
        0,
        { id: STABLE.id, amount: usdToStableUnits(100_000) },
        "Faucet: +100,000 aUSD",
      );
      set({ snapshot: emu.snapshot(), toast: { kind: "ok", text: "Faucet delivered" } });
    },

    resetWallet: () => {
      const w = resetUserWallet();
      const emu2 = new Emulator();
      seed(emu2, w, get().maker);
      set({
        user: w,
        emu: emu2,
        snapshot: emu2.snapshot(),
        positions: [],
        toast: { kind: "ok", text: "New wallet generated" },
      });
    },

    openPosition: (f) => {
      try {
        const { user, maker } = get();
        const userParty = { pubkey: user.pubkey, label: "You" };
        const makerParty = { pubkey: maker.pubkey, label: "Arkade MM" };
        const seller = f.side === "seller" ? userParty : makerParty;
        const buyer = f.side === "seller" ? makerParty : userParty;
        const terms: PositionTerms = {
          notionalBtc: f.notionalBtc,
          strikeUsd: f.strikeUsd,
          premiumUsd: f.premiumUsd,
          volPct: f.volPct,
          expiryHeight: get().emu.height + f.expiryInBlocks,
          graceBlocks: f.graceBlocks,
          exit: f.exitBlocks,
        };
        const { position } = writeCoveredCall(get().ctx(), {
          seller,
          buyer,
          userSide: f.side,
          terms,
          chain: f.chain,
        });
        set({
          positions: [position, ...get().positions],
          snapshot: get().emu.snapshot(),
          toast: { kind: "ok", text: `Covered call opened on ${f.chain}` },
        });
      } catch (e) {
        set({ toast: { kind: "err", text: (e as Error).message } });
      }
    },

    exercisePosition: (id, path) => {
      try {
        const pos = get().positions.find((p) => p.id === id);
        if (!pos) return;
        exercise(get().ctx(), pos, path);
        set({
          positions: [...get().positions],
          snapshot: get().emu.snapshot(),
          toast: { kind: "ok", text: "Exercised" },
        });
      } catch (e) {
        set({ toast: { kind: "err", text: (e as Error).message } });
      }
    },

    reclaimPosition: (id, path) => {
      try {
        const pos = get().positions.find((p) => p.id === id);
        if (!pos) return;
        reclaim(get().ctx(), pos, path);
        set({
          positions: [...get().positions],
          snapshot: get().emu.snapshot(),
          toast: { kind: "ok", text: "Reclaimed" },
        });
      } catch (e) {
        set({ toast: { kind: "err", text: (e as Error).message } });
      }
    },

    transferPosition: (id, leg) => {
      try {
        const pos = get().positions.find((p) => p.id === id);
        if (!pos) return;
        // Transfer to a fresh deterministic "new party" — reuse the MM as the
        // demo counterparty to swap into.
        const { maker, user } = get();
        const target =
          leg === "seller" && pos.sellerPk === user.pubkey
            ? { pubkey: maker.pubkey, label: "Arkade MM" }
            : { pubkey: user.pubkey, label: "You" };
        transferLeg(get().ctx(), pos, leg, target);
        set({
          positions: [...get().positions],
          snapshot: get().emu.snapshot(),
          toast: { kind: "ok", text: `${leg} leg transferred` },
        });
      } catch (e) {
        set({ toast: { kind: "err", text: (e as Error).message } });
      }
    },
  };
});
