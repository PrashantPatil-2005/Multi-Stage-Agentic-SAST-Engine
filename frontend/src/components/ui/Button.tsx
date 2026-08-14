import { forwardRef, type ButtonHTMLAttributes } from "react";

import "./ui.css";

type Variant = "primary" | "secondary" | "ghost" | "danger";
type Size = "sm" | "md";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = "secondary", size = "md", className = "", ...rest }, ref) => (
    <button
      ref={ref}
      className={`ui-button ui-button--${variant} ui-button--${size} ${className}`}
      {...rest}
    />
  ),
);

Button.displayName = "Button";