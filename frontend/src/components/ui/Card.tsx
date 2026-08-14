import type { HTMLAttributes } from "react";

import "./ui.css";

export interface CardProps extends HTMLAttributes<HTMLDivElement> {
  title?: string;
}

export function Card({ title, className = "", children, ...rest }: CardProps) {
  return (
    <section className={`ui-card ${className}`} {...rest}>
      {title ? (
        <header className="ui-card__header">
          <h3 className="ui-card__title">{title}</h3>
        </header>
      ) : null}
      <div className="ui-card__body">{children}</div>
    </section>
  );
}