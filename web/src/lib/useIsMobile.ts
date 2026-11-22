import { useMediaQuery } from "./useMediaQuery";

export const MOBILE_QUERY = "(max-width: 767.98px)";

export function useIsMobile(): boolean {
  return useMediaQuery(MOBILE_QUERY);
}
