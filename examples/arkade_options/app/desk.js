import { bestQuote, deskQuotes } from "./quote.js";
import {
  DUST,
  PRICE_MAX,
  Q_MAX,
  Q_MIN,
  holderPayoff,
  settle,
  windows,
} from "./settle-math.js";

const ORACLES = ["Chainlink", "DIA", "Pyth", "Stork", "Band"];
const STORE = "arkade-options-desk-v1";

const state = {
  spotCents: null,
  spotSource: "Loading",
  side: 0,
  kind: 0,
  days: 30,
  strikeIndex: 2,
  miss: false,
  quotes: null,
  quoting: false,
  positions: loadPositions(),
  selected: null,
  settleText: "",
  spike: false,
};

let quoteGen = 0;
let quoteTimer = 0;

const $ = (id) => document.getElementById(id);

function loadPositions() {
  try {
    const raw = JSON.parse(localStorage.getItem(STORE) || "[]");
    return raw.map(revive);
  } catch {
    return [];
  }
}

function revive(row) {
  const position = {
    ...row,
    collateral: BigInt(row.collateral),
    premiumSats: BigInt(row.premiumSats),
    strike: BigInt(row.strike),
    expiry: BigInt(row.expiry),
  };
  if (position.settlement) {
    position.settlement = {
      twap: BigInt(position.settlement.twap),
      holder: BigInt(position.settlement.holder),
      writer: BigInt(position.settlement.writer),
      mode: position.settlement.mode,
    };
  }
  return position;
}

function persist() {
  const rows = state.positions.map((p) => ({
    id: p.id,
    side: p.side,
    kind: p.kind,
    strike: p.strike.toString(),
    expiry: p.expiry.toString(),
    collateral: p.collateral.toString(),
    premiumSats: p.premiumSats.toString(),
    premiumUsd: p.premiumUsd,
    solver: p.solver,
    miss: p.miss,
    status: p.status,
    deadline: p.deadline,
    commitment: p.commitment,
    settlement: p.settlement && {
      twap: p.settlement.twap.toString(),
      holder: p.settlement.holder.toString(),
      writer: p.settlement.writer.toString(),
      mode: p.settlement.mode,
    },
  }));
  localStorage.setItem(STORE, JSON.stringify(rows));
}

function fmtUsdFromCents(cents) {
  const neg = cents < 0n;
  const v = neg ? -cents : cents;
  const whole = (v / 100n).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  const frac = (v % 100n).toString().padStart(2, "0");
  return `${neg ? "-" : ""}${whole}.${frac}`;
}

function fmtBtc(sats) {
  const neg = sats < 0n;
  const v = neg ? -sats : sats;
  const whole = (v / 100_000_000n).toString();
  const frac = (v % 100_000_000n).toString().padStart(8, "0").replace(/0+$/, "");
  return `${neg ? "-" : ""}${whole}${frac ? `.${frac}` : ""}`;
}

function fmtWhen(unix) {
  return `${new Date(Number(unix) * 1000).toLocaleString("en-GB", {
    timeZone: "UTC",
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  })} UTC`;
}

function btcToSats(text) {
  const s = text.trim();
  if (!/^\d+(\.\d{0,8})?$/.test(s)) return null;
  const [whole, frac = ""] = s.split(".");
  return BigInt(whole) * 100_000_000n + BigInt((frac + "00000000").slice(0, 8));
}

function usdToCents(text) {
  const s = text.trim().replaceAll(",", "");
  if (!/^\d+(\.\d{0,2})?$/.test(s)) return null;
  const [whole, frac = ""] = s.split(".");
  return BigInt(whole) * 100n + BigInt((frac + "00").slice(0, 2));
}

function expiryUnix(days) {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + days);
  d.setUTCHours(8, 0, 0, 0);
  return BigInt(Math.floor(d.getTime() / 1000));
}

function ladder() {
  const steps = state.kind === 0 ? [105n, 110n, 115n, 125n, 140n] : [95n, 90n, 85n, 75n, 60n];
  const grid = state.spotCents >= 10_000_000n ? 100_000n : 50_000n;
  const seen = new Set();
  return steps.map((step) => {
    let cents = ((state.spotCents * step) / 100n + grid / 2n) / grid * grid;
    const bump = state.kind === 0 ? grid : -grid;
    while (seen.has(cents.toString())) cents += bump;
    seen.add(cents.toString());
    return cents;
  });
}

function strike() {
  return ladder()[state.strikeIndex] ?? ladder()[0];
}

function sizeSats() {
  return btcToSats($("size").value);
}

function sizeError(sats) {
  if (sats == null) return "Use a BTC amount with up to 8 decimals.";
  if (sats < Q_MIN) return "Minimum size is 0.0001 BTC.";
  if (sats > Q_MAX) return "Maximum size is 10 BTC.";
  return "";
}

function copy() {
  if (state.side === 0 && state.kind === 0) {
    return "You lock BTC. At expiry the holder is paid only the fraction of that collateral by which the TWAP finishes above the strike.";
  }
  if (state.side === 0) {
    return "You lock BTC. The holder is paid the fraction the TWAP finishes below the strike, and the claim stops at the collateral.";
  }
  if (state.kind === 0) {
    return "You lock the premium. A desk locks the BTC, and you are paid the fraction that finishes above the strike.";
  }
  return "You lock the premium. A desk locks the BTC, and you are paid if the TWAP finishes below the strike, up to that collateral.";
}

function productName() {
  return state.kind === 0 ? "Covered call" : "Limited put";
}

let strikeKey = "";

function renderStrikes() {
  const host = $("strikes");
  if (state.spotCents == null) return;
  const rows = ladder();
  if (state.strikeIndex >= rows.length) state.strikeIndex = 2;
  const key = rows.join(",");
  if (key !== strikeKey) {
    strikeKey = key;
    host.replaceChildren();
    rows.forEach((cents, index) => {
      const delta = Number((cents - state.spotCents) * 10000n / state.spotCents) / 100;
      const sign = delta > 0 ? "+" : "";
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "strike";
      btn.role = "radio";
      btn.dataset.index = String(index);
      const d = document.createElement("span");
      d.className = "delta";
      d.textContent = `${sign}${delta.toFixed(1)}%`;
      const px = document.createElement("span");
      px.className = "px";
      px.textContent = fmtUsdFromCents(cents);
      btn.append(d, px);
      host.append(btn);
    });
  }
  for (const btn of host.querySelectorAll(".strike")) {
    btn.setAttribute("aria-checked", String(Number(btn.dataset.index) === state.strikeIndex));
  }
}

function renderPayoff() {
  const host = $("payoff");
  const sats = sizeSats();
  if (state.spotCents == null || sats == null || sizeError(sats)) {
    host.replaceChildren();
    return;
  }
  const k = strike();
  const q = sats;
  const lo = state.kind === 0 ? k * 70n / 100n : k * 30n / 100n;
  const hi = state.kind === 0 ? k * 160n / 100n : k * 130n / 100n;
  const points = [];
  for (let i = 0; i <= 48; i += 1) {
    const px = lo + (hi - lo) * BigInt(i) / 48n;
    const y = holderPayoff(state.kind, px === 0n ? 1n : px, k, q);
    points.push([px, y]);
  }
  const w = 320;
  const h = 96;
  const pad = 8;
  const sx = (px) => pad + Number(px - lo) / Number(hi - lo) * (w - pad * 2);
  const sy = (y) => h - pad - Number(y) / Number(q) * (h - pad * 2);
  const line = points.map(([px, y], i) => `${i ? "L" : "M"}${sx(px).toFixed(1)},${sy(y).toFixed(1)}`).join(" ");
  const strikeX = sx(k);
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", `Holder payoff from ${fmtUsdFromCents(lo)} to ${fmtUsdFromCents(hi)}`);
  svg.innerHTML = `<path d="${line}" fill="none" stroke="#dff25a" stroke-width="1.5"/>
    <line x1="${strikeX.toFixed(1)}" y1="${pad}" x2="${strikeX.toFixed(1)}" y2="${h - pad}" stroke="#9a947f" stroke-dasharray="2 3"/>`;
  host.replaceChildren(svg);
}

function renderTicket() {
  $("kind-copy").textContent = copy();
  $("expiry-when").textContent = state.spotCents == null ? "" : fmtWhen(expiryUnix(state.days));
  $("ticket-kicker").textContent = `${state.side === 0 ? "Sell" : "Buy"} · ${productName()}`;
  const sats = sizeSats();
  const err = state.spotCents == null ? "" : sizeError(sats);
  $("size-error").textContent = err;
  const best = state.quotes && bestQuote(state.quotes, state.side);
  const host = $("quotes");
  host.replaceChildren();
  if (state.quoting) {
    const p = document.createElement("p");
    p.className = "lock-note";
    p.textContent = "Asking Northbridge, Harbor, and Kestrel.";
    host.append(p);
  } else if (best) {
    state.quotes.forEach((row, index) => {
      const line = document.createElement("div");
      line.className = `quote-row${row.name === best.name ? " best" : ""}`;
      line.style.animationDelay = `${index * 40}ms`;
      const name = document.createElement("span");
      name.textContent = row.name;
      const prem = document.createElement("span");
      prem.textContent = `${fmtBtc(row.sats)} BTC`;
      const flag = document.createElement("span");
      if (row.name === best.name) {
        flag.className = "mark";
        flag.textContent = "Best";
      }
      line.append(name, prem, flag);
      host.append(line);
    });
  }
  if (!best || err) {
    $("premium").textContent = "—";
    $("premium-meta").textContent = err ? "" : "Enter a size. The desks answer with a premium.";
    $("lock-note").textContent = "";
  } else {
    $("premium").textContent = `${fmtBtc(best.sats)} BTC`;
    const notionalUsd = Number(sats) / 1e8 * Number(state.spotCents) / 100;
    const ann = notionalUsd > 0 ? best.usd / notionalUsd * (365 / state.days) * 100 : 0;
    $("premium-meta").textContent = `$${best.usd.toLocaleString("en-US", { maximumFractionDigits: 2 })} · ${ann.toFixed(1)}% annualized · ${best.name}`;
    if (state.side === 0) {
      $("lock-note").textContent = `You lock ${fmtBtc(sats)} BTC. ${best.name} pays the premium if it funds within 30 seconds.`;
    } else {
      $("lock-note").textContent = `You lock ${fmtBtc(best.sats)} BTC of premium. ${best.name} locks ${fmtBtc(sats)} BTC of collateral.`;
    }
  }
  const locking = state.positions.some((p) => p.status === "locking");
  const tooSmall = best && best.sats <= DUST;
  $("lock").disabled = !best || Boolean(err) || state.quoting || locking || tooSmall;
  $("lock").textContent = state.side === 0 ? "Lock collateral" : "Lock premium";
  if (tooSmall) $("status").textContent = "Premium is at or below dust. The intent cannot enforce it.";
  else if (!locking) $("status").textContent = "";
}

function renderBlotter() {
  const host = $("blotter");
  host.replaceChildren();
  $("blotter-count").textContent = state.positions.length ? `${state.positions.length} on the desk` : "";
  if (!state.positions.length) {
    const p = document.createElement("p");
    p.className = "empty";
    p.textContent = "Nothing locked. A quote you accept shows up here, then settles from three oracle slices.";
    host.append(p);
    return;
  }
  const columns = document.createElement("div");
  columns.className = "position-head tag";
  for (const label of ["Contract", "Strike", "Expiry", "Notional", "Status"]) {
    columns.append(textCell(label));
  }
  host.append(columns);
  for (const position of state.positions) {
    const wrap = document.createElement("article");
    wrap.className = "position";
    const head = document.createElement("button");
    head.type = "button";
    head.className = "position-head";
    head.addEventListener("click", () => {
      if (state.selected === position.id) return;
      state.selected = position.id;
      state.settleText = fmtUsdFromCents(state.spotCents);
      state.spike = false;
      renderBlotter();
    });
    const kind = document.createElement("span");
    kind.className = `tag ${position.kind === 0 ? "call" : "put"}`;
    kind.textContent = `${position.side === 0 ? "Sell" : "Buy"} ${position.kind === 0 ? "covered call" : "limited put"}`;
    const cells = [
      kind,
      textCell(fmtUsdFromCents(position.strike)),
      textCell(fmtWhen(position.expiry)),
      textCell(`${fmtBtc(position.collateral)} BTC`),
      statusCell(position),
    ];
    head.append(...cells);
    wrap.append(head);
    if (state.selected === position.id) wrap.append(detail(position));
    host.append(wrap);
  }
}

function textCell(value) {
  const span = document.createElement("span");
  span.textContent = value;
  return span;
}

function statusCell(position) {
  const span = document.createElement("span");
  if (position.status === "locking") {
    span.dataset.deadline = String(position.deadline);
    span.textContent = countdown(position.deadline);
    return span;
  }
  span.textContent = statusLabel(position);
  return span;
}

function statusLabel(position) {
  if (position.status === "locking") return countdown(position.deadline);
  if (position.status === "refunded") return "Refunded";
  if (position.status === "settled") return "Settled";
  return "Open";
}

function countdown(deadline) {
  const left = Math.max(0, deadline - Math.floor(Date.now() / 1000));
  const m = Math.floor(left / 60);
  const s = left % 60;
  return `Fills in ${m}:${s.toString().padStart(2, "0")}`;
}

function detail(position) {
  const box = document.createElement("div");
  box.className = "lab";
  if (position.status === "locking") {
    const p = document.createElement("p");
    p.className = "lock-note";
    p.textContent = position.miss
      ? "The desk has not funded the option. Cancel is locked until the 30-second clock passes, then the collateral returns."
      : `${position.solver} is funding the option script committed at ${position.commitment.slice(0, 16)}.`;
    box.append(p);
    return box;
  }
  if (position.status === "refunded") {
    const p = document.createElement("p");
    p.textContent = "Deadline passed before finalize. The intent refunded the locked coins to you.";
    box.append(p);
    return box;
  }
  if (position.status === "settled") {
    box.append(resultLine(position.settlement));
    return box;
  }
  box.append(settleLab(position));
  return box;
}

function resultLine(settlement) {
  const row = document.createElement("div");
  row.className = "result";
  row.append(stat("TWAP", `$${fmtUsdFromCents(settlement.twap)}`), stat("Holder", `${fmtBtc(settlement.holder)} BTC`), stat("Writer", `${fmtBtc(settlement.writer)} BTC`));
  return row;
}

function stat(label, value) {
  const wrap = document.createElement("div");
  const name = document.createElement("span");
  name.className = "tag";
  name.textContent = label;
  const strong = document.createElement("strong");
  strong.textContent = value;
  wrap.append(name, strong);
  return wrap;
}

function settleLab(position) {
  const box = document.createDocumentFragment();
  const who = document.createElement("p");
  who.className = "lock-note";
  who.textContent = position.side === 0
    ? `You are the writer. ${position.solver} paid ${fmtBtc(position.premiumSats)} BTC for the option.`
    : `You are the holder. You paid ${fmtBtc(position.premiumSats)} BTC. ${position.solver} locked the collateral.`;
  const controls = document.createElement("div");
  controls.className = "lab-controls";
  const label = document.createElement("label");
  label.textContent = "Settlement spot";
  const input = document.createElement("input");
  input.type = "text";
  input.inputMode = "decimal";
  input.value = state.settleText || fmtUsdFromCents(state.spotCents);
  input.addEventListener("input", () => {
    state.settleText = input.value;
    renderPreview(position, previewHost, button);
  });
  label.append(input);
  const spike = document.createElement("label");
  spike.className = "miss";
  const check = document.createElement("input");
  check.type = "checkbox";
  check.checked = state.spike;
  check.addEventListener("change", () => {
    state.spike = check.checked;
    renderPreview(position, previewHost, button);
  });
  spike.append(check, document.createTextNode("Pyth spikes the midpoint"));
  controls.append(label, spike);
  const previewHost = document.createElement("div");
  const button = document.createElement("button");
  button.type = "button";
  button.className = "settle";
  button.textContent = "Settle";
  button.addEventListener("click", () => commitSettle(position));
  const note = document.createElement("p");
  note.className = "lock-note";
  note.textContent = "ST = (900·open + 900·mid + 60·settle) / 1860. Each print is the median of three oracles inside a one-minute slice. A spiked print loses the median.";
  box.append(who, controls, previewHost, button, note);
  renderPreview(position, previewHost, button);
  return box;
}

function slicesFor(expiry, settleCents, spike) {
  const bounds = windows(expiry);
  const bases = [settleCents * 995n / 1000n, settleCents, settleCents];
  const who = [[0n, 1n, 2n], [1n, 2n, 3n], [2n, 3n, 4n]];
  const time = [bounds.open, bounds.mid, bounds.close].map(([lo]) => [lo + 20n, lo + 30n, lo + 40n]);
  return bases.map((base, i) => {
    const price = [base > 5n ? base - 5n : base, base, base + 5n];
    if (spike && i === 1) {
      const pyth = who[i].findIndex((id) => id === 2n);
      price[pyth] = base * 3n > PRICE_MAX ? PRICE_MAX : base * 3n;
    }
    return { price, time: time[i], who: who[i] };
  });
}

function renderPreview(position, host, button) {
  host.replaceChildren();
  const cents = usdToCents(state.settleText || fmtUsdFromCents(state.spotCents));
  if (cents == null || cents <= 0n) {
    button.disabled = true;
    const p = document.createElement("p");
    p.className = "error";
    p.textContent = "Enter a settlement spot in dollars.";
    host.append(p);
    return;
  }
  const slices = slicesFor(position.expiry, cents, state.spike);
  const names = ["Open, 30m prior", "Mid, 15m prior", "Settle, at expiry"];
  slices.forEach((slice, i) => {
    const row = document.createElement("div");
    row.className = "slice";
    const title = document.createElement("span");
    title.textContent = names[i];
    const prints = document.createElement("span");
    prints.textContent = slice.who.map((id, n) => `${ORACLES[Number(id)]} ${fmtUsdFromCents(slice.price[n])}`).join("  ·  ");
    const med = document.createElement("b");
    const ordered = [...slice.price].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    med.textContent = fmtUsdFromCents(ordered[1]);
    row.append(title, prints, med);
    host.append(row);
  });
  const result = settle(position, slices);
  if (result.error) {
    button.disabled = true;
    const p = document.createElement("p");
    p.className = "error";
    p.textContent = result.error;
    host.append(p);
    return;
  }
  button.disabled = false;
  host.append(resultLine({
    twap: result.settlement,
    holder: result.outputs.holder,
    writer: result.outputs.writer,
  }));
  position.preview = result;
}

function commitSettle(position) {
  if (!position.preview || position.preview.error) return;
  position.status = "settled";
  position.settlement = {
    twap: position.preview.settlement,
    holder: position.preview.outputs.holder,
    writer: position.preview.outputs.writer,
    mode: position.preview.outputs.mode,
  };
  delete position.preview;
  persist();
  renderBlotter();
}

function onTermsChanged() {
  state.quotes = null;
  const sats = sizeSats();
  const ready = state.spotCents != null && !sizeError(sats);
  state.quoting = ready;
  renderStrikes();
  renderPayoff();
  renderTicket();
  clearTimeout(quoteTimer);
  if (!ready) return;
  const gen = ++quoteGen;
  quoteTimer = setTimeout(() => ask(gen), 900);
}

async function ask(gen) {
  const sats = sizeSats();
  if (gen !== quoteGen || sats == null) return;
  const years = state.days / 365;
  state.quotes = deskQuotes({
    kind: state.kind,
    spotCents: Number(state.spotCents),
    strikeCents: Number(strike()),
    years,
    collateralSats: sats,
  });
  state.quoting = false;
  if (gen === quoteGen) renderTicket();
}

async function lock() {
  const sats = sizeSats();
  const err = sizeError(sats);
  const best = state.quotes && bestQuote(state.quotes, state.side);
  if (err || !best || best.sats <= DUST) return;
  const terms = {
    kind: state.kind,
    side: state.side,
    strike: strike().toString(),
    collateral: sats.toString(),
    premium: best.sats.toString(),
    expiry: expiryUnix(state.days).toString(),
    solver: best.name,
  };
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(JSON.stringify(terms)));
  const commitment = [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  const position = {
    id: crypto.randomUUID(),
    side: state.side,
    kind: state.kind,
    strike: strike(),
    expiry: expiryUnix(state.days),
    collateral: sats,
    premiumSats: best.sats,
    premiumUsd: best.usd,
    solver: best.name,
    status: "locking",
    miss: state.miss,
    deadline: Math.floor(Date.now() / 1000) + 30,
    commitment,
  };
  state.positions.unshift(position);
  state.selected = position.id;
  state.settleText = fmtUsdFromCents(state.spotCents);
  persist();
  renderTicket();
  renderBlotter();
  if (!position.miss) {
    setTimeout(() => {
      if (position.status !== "locking") return;
      position.status = "open";
      persist();
      renderTicket();
      renderBlotter();
    }, 1600);
  }
}

function tick() {
  const now = Math.floor(Date.now() / 1000);
  let changed = false;
  for (const position of state.positions) {
    if (position.status === "locking" && now >= position.deadline) {
      position.status = "refunded";
      changed = true;
    }
  }
  if (changed) {
    persist();
    renderTicket();
    renderBlotter();
    return;
  }
  for (const node of document.querySelectorAll("[data-deadline]")) {
    node.textContent = countdown(Number(node.dataset.deadline));
  }
  const locking = state.positions.find((p) => p.status === "locking");
  if (!locking) return;
  const left = countdown(locking.deadline).replace("Fills in ", "");
  $("status").textContent = locking.miss
    ? `Refund unlocks in ${left}. The intent cannot cancel before then.`
    : "Desk is funding the vault.";
}

function reconcileLocks() {
  const now = Math.floor(Date.now() / 1000);
  let changed = false;
  for (const position of state.positions) {
    if (position.status !== "locking") continue;
    if (now >= position.deadline) position.status = "refunded";
    else if (!position.miss) position.status = "open";
    changed = true;
  }
  if (changed) persist();
}

function press(id, pressed) {
  $(id).setAttribute("aria-pressed", String(pressed));
}

function bind() {
  $("side-sell").addEventListener("click", () => {
    state.side = 0;
    press("side-sell", true);
    press("side-buy", false);
    onTermsChanged();
  });
  $("side-buy").addEventListener("click", () => {
    state.side = 1;
    press("side-sell", false);
    press("side-buy", true);
    onTermsChanged();
  });
  $("kind-call").addEventListener("click", () => {
    state.kind = 0;
    press("kind-call", true);
    press("kind-put", false);
    onTermsChanged();
  });
  $("kind-put").addEventListener("click", () => {
    state.kind = 1;
    press("kind-call", false);
    press("kind-put", true);
    onTermsChanged();
  });
  document.querySelectorAll("[data-days]").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.days = Number(btn.dataset.days);
      document.querySelectorAll("[data-days]").forEach((other) => {
        other.setAttribute("aria-pressed", String(other === btn));
      });
      onTermsChanged();
    });
  });
  $("strikes").addEventListener("click", (event) => {
    const btn = event.target.closest("button");
    if (!btn) return;
    state.strikeIndex = Number(btn.dataset.index);
    onTermsChanged();
  });
  $("size").addEventListener("input", onTermsChanged);
  $("miss").addEventListener("change", () => {
    state.miss = $("miss").checked;
  });
  $("lock").addEventListener("click", lock);
}

async function loadSpot() {
  const sources = [
    ["Coinbase", "https://api.coinbase.com/v2/prices/BTC-USD/spot", (body) => body.data.amount],
    ["Binance", "https://api.binance.com/api/v3/ticker/price?symbol=BTCUSDT", (body) => body.price],
  ];
  for (const [name, url, pick] of sources) {
    try {
      const res = await fetch(url);
      if (!res.ok) continue;
      const price = Number(pick(await res.json()));
      if (price > 1000 && price < 10_000_000) {
        state.spotCents = BigInt(Math.round(price * 100));
        state.spotSource = name;
        return;
      }
    } catch {
      // try the next source, then the labeled fallback
    }
  }
  state.spotCents = 10_000_000n;
  state.spotSource = "Simulated spot";
}

async function loadArtifact() {
  const node = $("artifact");
  try {
    const [vaultRes, intentRes] = await Promise.all([
      fetch(new URL("../artifacts/option_vault.json", import.meta.url)),
      fetch(new URL("../artifacts/option_intent.json", import.meta.url)),
    ]);
    if (!vaultRes.ok || !intentRes.ok) throw new Error("missing artifact");
    const vault = await vaultRes.json();
    const intent = await intentRes.json();
    const asm = vault.functions.find((fn) => fn.name === "settle").arkade.asm;
    const count = (op) => asm.filter((tok) => tok === op).length;
    const finalize = intent.functions.find((fn) => fn.name === "finalize").arkade.asm.join(" ");
    node.textContent = `OptionVault settle · ${count("OP_CHECKSIGFROMSTACK")} oracle signatures · ${count("OP_MUL")} multiplies · ${count("OP_DIV")} divides · ${count("OP_SHA256")} hashes. OptionIntent ${finalize.includes("OP_CHECKTIME") ? "gates the fill on the 30-second clock." : "is loaded."}`;
  } catch {
    node.textContent = "Compile the two contracts into artifacts/ to show the covenant opcodes.";
  }
}

bind();
reconcileLocks();
renderTicket();
renderBlotter();
loadSpot().then(() => {
  $("spot-source").textContent = state.spotSource;
  $("spot-px").textContent = fmtUsdFromCents(state.spotCents);
  state.settleText = fmtUsdFromCents(state.spotCents);
  onTermsChanged();
  renderBlotter();
});
loadArtifact();
setInterval(tick, 250);
