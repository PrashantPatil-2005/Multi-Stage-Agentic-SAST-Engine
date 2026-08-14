import type { HTMLAttributes } from "react";

import "./ui.css";

type Tone = "neutral" | "success" | "warning" | "danger" | "info";

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: Tone;
}

export function Badge({ tone = "neutral", className = "", ...rest }: BadgeProps) {
  return (
    <span className={`ui-badge ui-badge--${tone} ${className}`} {...rest} />
  );
}