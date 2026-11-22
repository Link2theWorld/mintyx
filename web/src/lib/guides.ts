// The owner's how-to guides. This is the only file that may name the site: the panel
// links to it with plain anchors and must never request it (no fetch, image or prefetch).
const guideBase = "https://fand.dev/go/";

const guideSlugs = {
  maintain: "mintyx-maintain",
  care: "mintyx-care",
  security: "mintyx-security",
  blocked: "mintyx-blocked",
  sshKey: "mintyx-ssh-key",
  clients: "mintyx-clients",
} as const;

export type GuideId = keyof typeof guideSlugs;
export const guideIds = Object.keys(guideSlugs) as GuideId[];

export function guideUrl(id: GuideId): string {
  return guideBase + guideSlugs[id];
}

/** New tab, no opener handle and no Referer, so the site never learns the panel's address. */
export const guideLinkProps = { target: "_blank", rel: "noopener noreferrer" } as const;
