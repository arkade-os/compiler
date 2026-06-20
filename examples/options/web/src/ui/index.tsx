// Arkade UI primitives — thin, typed wrappers over theme.css classes so the app
// composes from one consistent, branded component set.
import React from "react";

type Div = React.HTMLAttributes<HTMLDivElement>;

export function Card({
  title,
  children,
  tight,
  className = "",
  ...rest
}: Div & { title?: React.ReactNode; tight?: boolean }) {
  return (
    <div className={`ark-card ${tight ? "tight" : ""} ${className}`} {...rest}>
      {title && <div className="ark-card-title">{title}</div>}
      {children}
    </div>
  );
}

export function Button({
  variant = "default",
  size,
  className = "",
  ...rest
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "default" | "primary" | "ghost" | "danger";
  size?: "sm";
}) {
  const v = variant === "default" ? "" : variant;
  return <button className={`ark-btn ${v} ${size ?? ""} ${className}`} {...rest} />;
}

export type BadgeTone = "default" | "lime" | "cyan" | "green" | "red" | "amber";
export function Badge({
  tone = "default",
  dot,
  children,
}: {
  tone?: BadgeTone;
  dot?: boolean;
  children: React.ReactNode;
}) {
  return (
    <span className={`ark-badge ${tone === "default" ? "" : tone}`}>
      {dot && <span className="dot" />}
      {children}
    </span>
  );
}

export function Stat({ k, v, sub }: { k: string; v: React.ReactNode; sub?: React.ReactNode }) {
  return (
    <div className="ark-stat">
      <span className="k">{k}</span>
      <span className="v">{v}</span>
      {sub && <span className="faint" style={{ fontSize: 12 }}>{sub}</span>}
    </div>
  );
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="ark-field">
      <span className="ark-label">{label}</span>
      {children}
      {hint && <span className="faint" style={{ fontSize: 11 }}>{hint}</span>}
    </label>
  );
}

export function NumberInput({
  value,
  onChange,
  step = 1,
  min,
  ...rest
}: {
  value: number;
  onChange: (n: number) => void;
  step?: number;
  min?: number;
} & Omit<React.InputHTMLAttributes<HTMLInputElement>, "value" | "onChange">) {
  return (
    <input
      className="ark-input"
      type="number"
      value={Number.isFinite(value) ? value : ""}
      step={step}
      min={min}
      onChange={(e) => onChange(parseFloat(e.target.value))}
      {...rest}
    />
  );
}

export function Segmented<T extends string>({
  value,
  onChange,
  options,
  tone = "lime",
}: {
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: React.ReactNode }[];
  tone?: "lime" | "cyan";
}) {
  return (
    <div className="ark-seg">
      {options.map((o) => (
        <button
          key={o.value}
          className={value === o.value ? `active ${tone}` : ""}
          onClick={() => onChange(o.value)}
          type="button"
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Modal({
  title,
  onClose,
  children,
  footer,
}: {
  title: React.ReactNode;
  onClose: () => void;
  children: React.ReactNode;
  footer?: React.ReactNode;
}) {
  return (
    <div className="ark-modal-backdrop" onClick={onClose}>
      <div className="ark-modal" onClick={(e) => e.stopPropagation()}>
        <div className="row between center" style={{ marginBottom: 14 }}>
          <h3>{title}</h3>
          <Button size="sm" variant="ghost" onClick={onClose}>
            ✕
          </Button>
        </div>
        {children}
        {footer && (
          <>
            <div className="divider" style={{ margin: "16px 0" }} />
            <div className="row between center">{footer}</div>
          </>
        )}
      </div>
    </div>
  );
}

export function Logo() {
  return (
    <div className="ark-brand">
      <div className="ark-logo">▲</div>
      <div className="ark-wordmark">
        ARKADE <span className="dim">/ OPTIONS</span>
      </div>
    </div>
  );
}
