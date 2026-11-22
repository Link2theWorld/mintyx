/** The M mark on an ink square, with a blossom dot like a sticker. */
export function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true" focusable="false">
      <rect width="32" height="32" rx="7" fill="var(--ink)" />
      <path d="M9 22V10l7 7 7-7v12" stroke="var(--paper)" strokeWidth="3" fill="none" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="26" cy="6" r="3.2" fill="var(--blossom)" />
    </svg>
  );
}
