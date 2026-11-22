import type { ReactNode } from "react";

/** Decorative wave for a polaroid's "photo"; purely ornamental. */
function Wave({ variant }: { variant: number }) {
  const paths = [
    "M0 40 L20 34 40 46 60 38 80 50 100 44 120 54 140 46 160 56 180 48 200 52",
    "M0 36 L40 30 80 40 120 28 160 38 200 32",
    "M0 48 L30 44 60 52 90 38 120 46 150 34 180 42 200 36",
  ];
  const d = paths[variant % paths.length] ?? paths[0];
  return (
    <svg viewBox="0 0 200 64" preserveAspectRatio="none" aria-hidden="true">
      <path d={`${d ?? ""} V64 H0Z`} fill="currentColor" opacity="0.22" />
      <path d={d} fill="none" stroke="currentColor" strokeWidth="2" />
    </svg>
  );
}

/** A slightly tilted polaroid with tape: a big handwritten number under a decorative photo. */
export function Polaroid({ index, caption, value, unit, meta, pink }: {
  index: number;
  caption: string;
  value: ReactNode;
  unit?: string;
  meta?: ReactNode;
  pink?: boolean;
}) {
  return (
    <div className={`paper polaroid tilt-${String((index % 4) + 1)}`}>
      <span className={index % 2 ? "tape blue" : "tape"} aria-hidden="true" />
      <div className={pink ? "photo pink" : "photo"} style={{ color: pink ? "var(--blossom)" : "var(--sky-deep)" }}>
        <Wave variant={index} />
      </div>
      <div className="cap">
        <b>{caption}</b>
        <span className="num">{value}{unit && <i>{unit}</i>}</span>
      </div>
      {meta && <div className="meta">{meta}</div>}
    </div>
  );
}

/** A pill-shaped label in script, tilted like a sticker. quiet uses sky instead of blossom. */
export function Sticker({ children, quiet }: { children: ReactNode; quiet?: boolean }) {
  return <span className={quiet ? "sticker quiet" : "sticker"}>{children}</span>;
}

/** A dashed ticket stub of label/value pairs. */
export function Ticket({ items }: { items: { label: string; value: ReactNode; unit?: string }[] }) {
  return (
    <div className="ticket">
      {items.map((it) => (
        <div key={it.label}>
          <div className="label">{it.label}</div>
          <div className="value">{it.value}{it.unit && <i>{it.unit}</i>}</div>
        </div>
      ))}
    </div>
  );
}
