export const deviceOSes = ["ios", "android", "windows", "macos"] as const;
export type DeviceOS = (typeof deviceOSes)[number];

/** Best guess at the device's OS from the user agent; null when it is none of the four we advise on. */
export function detectOS(userAgent: string, maxTouchPoints = 0): DeviceOS | null {
  // Android first: its user agent also says "Linux".
  if (/Android/i.test(userAgent)) return "android";
  if (/iPhone|iPad|iPod/.test(userAgent)) return "ios";
  if (/Windows/.test(userAgent)) return "windows";
  // iPadOS in desktop mode sends a Mac user agent; no Mac has a touchscreen.
  if (/Macintosh/.test(userAgent)) return maxTouchPoints > 1 ? "ios" : "macos";
  return null;
}

export interface ClientApp {
  name: string;
  /** Which of the panel's subscription formats this app imports. */
  format: "links" | "mihomo";
}

// Only apps whose core handles all three line types the panel emits
// (VLESS+REALITY, VLESS+XHTTP, Hysteria2). Download details live in the guide.
export const clientApps: Record<DeviceOS, readonly ClientApp[]> = {
  ios: [
    { name: "Shadowrocket", format: "links" },
    { name: "Streisand", format: "links" },
  ],
  android: [
    { name: "v2rayNG", format: "links" },
    { name: "FlClash", format: "mihomo" },
  ],
  windows: [
    { name: "v2rayN", format: "links" },
    { name: "Clash Verge Rev", format: "mihomo" },
  ],
  macos: [
    { name: "v2rayN", format: "links" },
    { name: "Clash Verge Rev", format: "mihomo" },
  ],
};
