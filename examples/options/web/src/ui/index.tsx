// Arkade UI primitives — thin, typed wrappers over theme.css classes so the app
// composes from one consistent, branded component set.
import React from "react";

type Div = React.HTMLAttributes<HTMLDivElement>;

/** Bordered surface with an optional uppercase title. */
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

/** Themed button with primary / ghost / danger variants. */
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

export type BadgeTone = "default" | "lime" | "cyan" | "green" | "red" | "amber" | "violet";

/** Small status pill. */
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

/** Arkade wordmark + logo. */
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
