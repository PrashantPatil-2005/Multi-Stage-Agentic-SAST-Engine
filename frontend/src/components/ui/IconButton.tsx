import { forwardRef, type ButtonHTMLAttributes } from "react";

import "./ui.css";

export interface IconButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement> {
  label: string;
}

export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(
  ({ label, className = "", children, ...rest }, ref) => (
    <button
      ref={ref}
      type="button"
      aria-label={label}
      title={label}
      className={`ui-icon-button ${className}`}
      {...rest}
    >
      {children}
    </button>
  ),
);

IconButton.displayName = "IconButton";